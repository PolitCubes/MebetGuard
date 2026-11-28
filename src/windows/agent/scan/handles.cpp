// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "scan/handles.hpp"

#include "nt.hpp"

#include <cstdio>
#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/watchdog.hpp"
#include "core/win_util.hpp"
#include "json_writer.hpp"
#include "report/cards.hpp"
#include "strings.hpp"
#include "trust/engine.hpp"

namespace mebet::handles {

namespace {

constexpr int kSystemProcessInformation = 5;
constexpr int kSystemExtendedHandleInformation = 64;

// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (phnt).
struct HandleEntry {
    PVOID object;
    ULONG_PTR pid;
    ULONG_PTR handle;
    ULONG access;
    USHORT creator_back_trace_index;
    USHORT type_index;
    ULONG attributes;
    ULONG reserved;
};
struct HandleTable {
    ULONG_PTR count;
    ULONG_PTR reserved;
    HandleEntry entries[1];
};

// What lets a program see or change the game from outside.
constexpr ULONG kDangerous = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;

// One query of a system table, into a buffer kept between sweeps (the handle table of a busy desktop
// is several megabytes: grown once, not every five seconds).
bool query(int cls, std::vector<unsigned char>& buf) {
    const auto f = nt::api().NtQuerySystemInformation;
    if (!f) return false;
    if (buf.size() < (1u << 20)) buf.resize(1u << 20);
    for (int attempt = 0; attempt < 8; ++attempt) {
        ULONG need = 0;
        const NTSTATUS s = f(cls, buf.data(), static_cast<ULONG>(buf.size()), &need);
        if (nt::ok(s)) return true;
        if (s != nt::kStatusInfoLengthMismatch && s != nt::kStatusBufferTooSmall) return false;
        std::size_t next = need > buf.size() ? need + need / 4 : buf.size() * 2;
        if (next > (256u << 20)) return false;
        buf.resize(next);
    }
    return false;
}

struct ProcessFacts {
    bool listed = false;
    ULONG session = 0;
    ULONG_PTR parent = 0;
    std::uint64_t created = 0;
    std::wstring name;  // image file name from the process list
};

// pid → facts, from one walk of the process list (no process is opened for it).
std::map<ULONG_PTR, ProcessFacts> process_list() {
    static std::vector<unsigned char> buf;
    std::map<ULONG_PTR, ProcessFacts> out;
    if (!query(kSystemProcessInformation, buf)) return out;
    std::size_t off = 0;
    for (int guard_count = 0; guard_count < 65536; ++guard_count) {
        if (off + sizeof(SYSTEM_PROCESS_INFORMATION) > buf.size()) break;
        const auto* p = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(buf.data() + off);
        ProcessFacts f;
        f.listed = true;
        f.session = p->SessionId;
        f.parent = reinterpret_cast<ULONG_PTR>(p->Reserved2);  // InheritedFromUniqueProcessId
        // CreateTime: after WorkingSetPrivateSize (8), HardFaultCount (4), NumberOfThreadsHighWatermark
        // (4) and CycleTime (8) at the start of Reserved1.
        f.created = *reinterpret_cast<const std::uint64_t*>(p->Reserved1 + 24);
        if (p->ImageName.Buffer && p->ImageName.Length)
            f.name.assign(p->ImageName.Buffer, p->ImageName.Length / sizeof(wchar_t));
        out[reinterpret_cast<ULONG_PTR>(p->UniqueProcessId)] = f;
        if (!p->NextEntryOffset) break;
        off += p->NextEntryOffset;
    }
    return out;
}

// A handle of our own on this process, to find this process's object in the table.
HANDLE self_handle() {
    static HANDLE h = [] {
        HANDLE d = nullptr;
        DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &d,
                        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0);
        return d;
    }();
    return h;
}

enum class Holder { allowed, foreign, unknown };

struct Judged {
    Holder holder = Holder::unknown;
    std::wstring path;  // the holder's executable, when it could be read
    trust::Decision decision;
    bool decided = false;
};

Judged judge_holder(ULONG_PTR pid, const std::map<ULONG_PTR, ProcessFacts>& procs) {
    Judged j;
    if (pid == 0 || pid == 4) {  // idle, the kernel
        j.holder = Holder::allowed;
        return j;
    }
    const DWORD me = GetCurrentProcessId();
    const auto self = procs.find(me);
    const auto it = procs.find(pid);
    if (it == procs.end()) return j;  // gone meanwhile: nothing to judge
    const ProcessFacts& f = it->second;
    // The launcher that started the game holds the handle CreateProcess gave it. Proven by the time:
    // a parent id taken over by a later process (the launcher exited, its id reused) is not the parent.
    if (self != procs.end() && self->second.parent == pid && f.created && f.created <= self->second.created) {
        j.holder = Holder::allowed;
        return j;
    }
    const ULONG own_session = self != procs.end() ? self->second.session : 0;
    // Services (session 0: the system's own, antivirus) beside a game in the player's session. A game
    // that runs in session 0 itself (a CI runner as a service) has its neighbours judged like any other.
    if (f.session == 0 && own_session != 0) {
        j.holder = Holder::allowed;
        return j;
    }
    const HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        if (f.session == 0) {  // a service the game may not look at: cannot be told, let be
            j.holder = Holder::allowed;
            return j;
        }
        // In the player's session and closed even to a query of its name: an elevated program that
        // keeps itself from being looked at.
        j.holder = Holder::foreign;
        j.path = f.name;
        return j;
    }
    wchar_t path[MAX_PATH * 4];
    DWORD n = MAX_PATH * 4;
    const bool named = QueryFullProcessImageNameW(h, 0, path, &n) != 0;
    CloseHandle(h);
    if (!named) {
        j.holder = Holder::foreign;
        j.path = f.name;
        return j;
    }
    j.path.assign(path, n);
    {
        watchdog::SlowWork slow;  // a signature check of an unseen executable can take a while
        j.decision = trust::decide_path(j.path);
    }
    j.decided = true;
    j.holder = j.decision.verdict.allowed ? Holder::allowed : Holder::foreign;
    return j;
}

std::string access_hex(ULONG a) {
    char b[16];
    std::snprintf(b, sizeof(b), "0x%lx", static_cast<unsigned long>(a));
    return b;
}

void close_foreign_handle(ULONG_PTR pid, ULONG access, const Judged& j, const char* tied_by) {
    report::Event ev;
    ev.type = "close.foreign_handle";
    ev.level = report::Level::error;
    const std::wstring name = win::file_name_of(j.path);
    ev.title = "Closed: another program holds the game open for its memory: " + to_utf8(name);
    JsonWriter w;
    w.begin_object();
    w.field("holder_pid", static_cast<std::uint64_t>(pid));
    w.field("access", access_hex(access));
    w.field("tied_by", tied_by);
    if (j.decided) {
        w.key("holder").raw(cards::file_card_json(j.decision));
    } else {
        w.field("holder_name", to_utf8(name));
        w.field("holder_readable", false);
    }
    w.end_object();
    ev.extra_json = w.take();
    const std::string group = j.decided && j.decision.facts.hashed ? j.decision.facts.sha256.hex()
                                                                 : to_utf8(lower_ascii(name));
    ev.fingerprint = {"close.foreign_handle", group.empty() ? std::string("unnamed") : group};
    guard::signal(config::Module::foreign_handles, config::Reason::foreign_handle, name, std::move(ev));
}

// A handle another process holds is on this process: duplicated from its owner and compared.
// Only where the owner may be opened for that; false when it cannot be told.
bool duplicate_is_self(ULONG_PTR pid, ULONG_PTR value, std::map<ULONG_PTR, HANDLE>& owners) {
    auto it = owners.find(pid);
    if (it == owners.end())
        it = owners.emplace(pid, OpenProcess(PROCESS_DUP_HANDLE, FALSE, static_cast<DWORD>(pid))).first;
    if (!it->second) return false;
    HANDLE dup = nullptr;
    if (!DuplicateHandle(it->second, reinterpret_cast<HANDLE>(value), GetCurrentProcess(), &dup,
                         PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
        return false;
    const bool self = GetProcessId(dup) == GetCurrentProcessId();
    CloseHandle(dup);
    return self;
}

}  // namespace

void sweep() {
    if (!config::enabled(config::Module::foreign_handles)) return;
    const HANDLE mine = self_handle();
    if (!mine) return;
    static std::vector<unsigned char> buf;
    if (!query(kSystemExtendedHandleInformation, buf)) return;
    watchdog::worker_beat();
    const auto* table = reinterpret_cast<const HandleTable*>(buf.data());
    const std::size_t max_count = (buf.size() - offsetof(HandleTable, entries)) / sizeof(HandleEntry);
    const std::size_t count = table->count < max_count ? static_cast<std::size_t>(table->count) : max_count;
    const ULONG_PTR me = GetCurrentProcessId();

    // This process's object and the type index of process objects, from our own handle.
    PVOID self_object = nullptr;
    USHORT process_type = 0;
    bool found = false;
    for (std::size_t i = 0; i < count; ++i) {
        const HandleEntry& e = table->entries[i];
        if (e.pid == me && e.handle == reinterpret_cast<ULONG_PTR>(mine)) {
            self_object = e.object;
            process_type = e.type_index;
            found = true;
            break;
        }
    }
    if (!found) return;

    std::map<ULONG_PTR, ProcessFacts> procs;
    std::map<ULONG_PTR, HANDLE> owners;  // for duplicating, when object addresses are hidden
    // Holders already judged allowed, kept across sweeps by pid and creation time (a judged launcher
    // or csrss is not judged again every five seconds; a reused id is a new process).
    static std::map<ULONG_PTR, std::uint64_t> allowed_holders;
    for (std::size_t i = 0; i < count && !guard::closing(); ++i) {
        const HandleEntry& e = table->entries[i];
        if (e.type_index != process_type || e.pid == me || !(e.access & kDangerous)) continue;
        const char* tied_by = "object";
        if (self_object) {
            if (e.object != self_object) continue;
        } else {
            if (!duplicate_is_self(e.pid, e.handle, owners)) continue;
            tied_by = "duplicate";
        }
        if (procs.empty()) procs = process_list();
        const auto p = procs.find(e.pid);
        const std::uint64_t created = p != procs.end() ? p->second.created : 0;
        const auto known = allowed_holders.find(e.pid);
        if (known != allowed_holders.end() && known->second == created) continue;
        const Judged j = judge_holder(e.pid, procs);
        if (j.holder == Holder::allowed) {
            allowed_holders[e.pid] = created;
            continue;
        }
        if (j.holder == Holder::foreign) {
            close_foreign_handle(e.pid, e.access, j, tied_by);
            if (config::closes(config::Module::foreign_handles)) break;
            allowed_holders[e.pid] = created;  // report mode: reported once per holder process
        }
    }
    for (auto& [pid, h] : owners)
        if (h) CloseHandle(h);
}

}  // namespace mebet::handles
