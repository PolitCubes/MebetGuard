// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/module_table.hpp"

#include <atomic>
#include <cstring>
#include <map>

#include "core/range_set.hpp"
#include "core/win_util.hpp"

namespace mebet::modules {

namespace {

struct Payload {
    trust::Trust trust;
    std::uintptr_t base;
    bool operator==(const Payload& o) const { return trust == o.trust && base == o.base; }
};

// No function-local statics here: every use of one reads the TLS block of the thread, and the
// hooks look modules up and forget them on threads that have none (nt_hooks.cpp). Leaked on purpose.
template <typename T>
T& once(std::atomic<T*>& slot) {
    T* v = slot.load(std::memory_order_acquire);
    if (v) return *v;
    T* fresh = new T();
    if (slot.compare_exchange_strong(v, fresh, std::memory_order_acq_rel)) return *fresh;
    delete fresh;
    return *v;
}

std::atomic<RangeSet<Payload>*> g_ranges{nullptr};
RangeSet<Payload>& ranges() { return once(g_ranges); }

// What the loader has just unloaded: a library leaves the table at the loader's notification a
// moment before its image is unmapped, and the sweep may find it in between (scans.cpp).
struct Unloaded {
    std::uintptr_t base = 0;
    std::uint64_t at_ms = 0;
    bool trusted = false;
    std::wstring path;  // the file the record named
    trust::FileIdentity id{};
    bool id_known = false;
};
constexpr std::size_t kUnloadedKept = 32;

struct Names {
    SRWLOCK lock = SRWLOCK_INIT;
    std::map<std::uintptr_t, Record> records;
    std::map<std::uintptr_t, std::uint64_t> pending;  // base → when its judging started (ms)
    Unloaded unloaded[kUnloadedKept] = {};
    std::size_t unloaded_next = 0;
};

std::atomic<Names*> g_names{nullptr};
Names& names() { return once(g_names); }
std::atomic<std::uint64_t> g_serial{0};

struct Span {
    std::uintptr_t begin = 0, end = 0;
    bool contains(std::uintptr_t a) const { return a >= begin && a < end; }
};

Span g_ntdll, g_kernelbase, g_kernel32, g_self;

Span span_of(HMODULE m) {
    Span s;
    if (!m) return s;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m);
    const auto* nth = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const char*>(m) + dos->e_lfanew);
    s.begin = reinterpret_cast<std::uintptr_t>(m);
    s.end = s.begin + nth->OptionalHeader.SizeOfImage;
    return s;
}

HMODULE self_module() {
    HMODULE m = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&self_module), &m);
    return m;
}

}  // namespace

void init() {
    g_ntdll = span_of(GetModuleHandleW(L"ntdll.dll"));
    g_kernelbase = span_of(GetModuleHandleW(L"kernelbase.dll"));
    g_kernel32 = span_of(GetModuleHandleW(L"kernel32.dll"));
    g_self = span_of(self_module());
}

// The range and the record of a module change together, under the lock of the names: with the
// two steps apart, a record removed by one thread and added again by another could end up
// without its range (or with the range of the one that is gone).
void add(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path, const trust::FileIdentity* id) {
    if (!base || !size) return;
    // Before the lock: a syscall must not be held across it (the sweep's swap check reads this later).
    std::wstring kernel_name = win::mapped_file_name(reinterpret_cast<void*>(base));
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    // A stale bigger record at the same base: only its own range goes — modules mapped inside it
    // since then keep theirs.
    if (it != n.records.end() && it->second.size > size)
        ranges().remove_where(base, base + it->second.size, [base](const Payload& p) { return p.base == base; });
    ranges().add(base, base + size, Payload{t, base}, false);
    Record rec{base, size, t, path, g_serial.fetch_add(1, std::memory_order_relaxed) + 1,
               id ? *id : trust::FileIdentity{}, id != nullptr};
    rec.kernel_name = std::move(kernel_name);  // for the sweep's swap check
    n.records[base] = std::move(rec);
    n.pending.erase(base);
    ReleaseSRWLockExclusive(&n.lock);
}

void add_pending(std::uintptr_t base) {
    if (!base) return;
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    n.pending[base] = GetTickCount64();
    ReleaseSRWLockExclusive(&n.lock);
}

bool pending_within(std::uintptr_t base, std::uint64_t max_ms) {
    Names& n = names();
    AcquireSRWLockShared(&n.lock);
    const std::uint64_t now = GetTickCount64();  // under the lock: never older than a tick stored meanwhile
    auto it = n.pending.find(base);
    const bool fresh = it != n.pending.end() && (now <= it->second || now - it->second < max_ms);
    ReleaseSRWLockShared(&n.lock);
    return fresh;
}

std::uint64_t add_if_absent(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path,
                            const trust::FileIdentity* id) {
    if (!base || !size) return 0;
    Names& n = names();
    std::uint64_t serial = 0;
    AcquireSRWLockExclusive(&n.lock);
    // Never over another module: a range of its own inside [base, base + size) means the image the
    // sweep judged is gone and another one sits there now — recorded by its own hook.
    bool others = false;
    for (const auto& e : ranges().entries()) {
        if (e.begin < base + size && e.end > base && e.payload.base != base) {
            others = true;
            break;
        }
    }
    if (!others && n.records.find(base) == n.records.end()) {
        serial = g_serial.fetch_add(1, std::memory_order_relaxed) + 1;
        ranges().add(base, base + size, Payload{t, base}, false);
        n.records[base] = Record{base, size, t, path, serial, id ? *id : trust::FileIdentity{}, id != nullptr};
    }
    ReleaseSRWLockExclusive(&n.lock);
    return serial;
}

namespace {
void remove_locked(Names& n, std::map<std::uintptr_t, Record>::iterator it) {
    const std::uintptr_t base = it->second.base;
    const std::size_t size = it->second.size;
    n.records.erase(it);
    if (size) ranges().remove_where(base, base + size, [base](const Payload& p) { return p.base == base; });
}
}  // namespace

void remove_unloading(std::uintptr_t base) {
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    if (it != n.records.end()) {
        // One entry per base (a library loaded and unloaded over and over keeps one), else the oldest:
        // round-robin, a burst of unloads elsewhere pushed out the one a sweep was about to ask for,
        // and a library caught between its unload notification and its unmap was closed as hidden.
        std::size_t slot = 0;
        for (std::size_t i = 0; i < kUnloadedKept; ++i) {
            if (n.unloaded[i].base == base) {
                slot = i;
                break;
            }
            if (n.unloaded[i].at_ms < n.unloaded[slot].at_ms) slot = i;
        }
        n.unloaded[slot] = Unloaded{base, GetTickCount64(), it->second.trust != trust::Trust::unknown, it->second.path,
                                    it->second.id, it->second.id_known};
        remove_locked(n, it);
    }
    ReleaseSRWLockExclusive(&n.lock);
}

namespace {
// The newest unload from `base` within `max_age_ms`, copied out of the lock.
bool newest_unload(std::uintptr_t base, std::uint64_t max_age_ms, Unloaded* out) {
    Names& n = names();
    bool found = false;
    AcquireSRWLockShared(&n.lock);
    const std::uint64_t now = GetTickCount64();
    for (const Unloaded& u : n.unloaded) {
        if (u.base == base && u.at_ms && now - u.at_ms <= max_age_ms && (!found || u.at_ms >= out->at_ms)) {
            *out = u;
            found = true;
        }
    }
    ReleaseSRWLockShared(&n.lock);
    return found;
}
}  // namespace

bool unloaded_recently(std::uintptr_t base, std::uint64_t max_age_ms) {
    Unloaded u;
    return newest_unload(base, max_age_ms, &u) && u.trusted;
}

bool unloaded_recently_file(std::uintptr_t base, std::uint64_t max_age_ms, const std::wstring& path) {
    Unloaded u;
    if (path.empty() || !newest_unload(base, max_age_ms, &u) || !u.trusted) return false;
    // Outside the lock: an open can take a while.
    auto id_of = [](const std::wstring& p, trust::FileIdentity& out) {
        const HANDLE h = p.empty() ? INVALID_HANDLE_VALUE : trust::open_read(p);
        if (h == INVALID_HANDLE_VALUE) return false;
        const bool ok = trust::identity_of(h, out);
        CloseHandle(h);
        return ok;
    };
    trust::FileIdentity now{};
    if (!id_of(path, now)) return false;
    trust::FileIdentity was = u.id;
    // A record without an id (Windows 7, a volume without file ids): the file under its own name, by
    // id too. Its name and the kernel's never compare: the record has the long normalized form, the
    // kernel's keeps 8.3 components ("JOHNDO~1"), and the same file did not match itself.
    if (!u.id_known && !id_of(u.path, was)) return false;
    return now.volume == was.volume && std::memcmp(now.file_id, was.file_id, sizeof(now.file_id)) == 0;
}

void prove_identity(std::uintptr_t base, std::uint64_t serial, const trust::FileIdentity& id) {
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    if (it != n.records.end() && it->second.serial == serial && !it->second.id_known) {
        it->second.id = id;
        it->second.id_known = true;
    }
    ReleaseSRWLockExclusive(&n.lock);
}

bool record_at(std::uintptr_t base, Record* out) {
    Names& n = names();
    AcquireSRWLockShared(&n.lock);
    auto it = n.records.find(base);
    const bool found = it != n.records.end();
    if (found && out) *out = it->second;
    ReleaseSRWLockShared(&n.lock);
    return found;
}

void remove(std::uintptr_t base) {
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    if (it != n.records.end()) remove_locked(n, it);
    n.pending.erase(base);
    ReleaseSRWLockExclusive(&n.lock);
}

void remove_if(std::uintptr_t base, std::uint64_t serial) {
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    if (it != n.records.end() && it->second.serial == serial) remove_locked(n, it);
    ReleaseSRWLockExclusive(&n.lock);
}

bool find(std::uintptr_t addr, trust::Trust* t, std::uintptr_t* base) {
    RangeSet<Payload>::Entry e{};
    if (!ranges().find(addr, &e)) return false;
    if (t) *t = e.payload.trust;
    if (base) *base = e.payload.base;
    return true;
}

bool is_system_frame(std::uintptr_t addr) {
    return g_ntdll.contains(addr) || g_kernelbase.contains(addr) || g_kernel32.contains(addr);
}

bool in_self(std::uintptr_t addr) { return g_self.contains(addr); }

std::uintptr_t self_base() { return g_self.begin; }

std::wstring path_of(std::uintptr_t base) {
    Names& n = names();
    AcquireSRWLockShared(&n.lock);
    auto it = n.records.find(base);
    std::wstring p = it != n.records.end() ? it->second.path : std::wstring();
    ReleaseSRWLockShared(&n.lock);
    return p;
}

std::vector<Record> all() {
    Names& n = names();
    std::vector<Record> out;
    AcquireSRWLockShared(&n.lock);
    out.reserve(n.records.size());
    for (const auto& kv : n.records) out.push_back(kv.second);
    ReleaseSRWLockShared(&n.lock);
    return out;
}

}  // namespace mebet::modules
