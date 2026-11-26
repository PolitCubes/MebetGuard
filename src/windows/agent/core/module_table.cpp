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
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    // A stale bigger record at the same base: only its own range goes — modules mapped inside it
    // since then keep theirs.
    if (it != n.records.end() && it->second.size > size)
        ranges().remove_where(base, base + it->second.size, [base](const Payload& p) { return p.base == base; });
    ranges().add(base, base + size, Payload{t, base}, false);
    n.records[base] = Record{base, size, t, path, g_serial.fetch_add(1, std::memory_order_relaxed) + 1,
                             id ? *id : trust::FileIdentity{}, id != nullptr};
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
        n.unloaded[n.unloaded_next++ % kUnloadedKept] = Unloaded{base, GetTickCount64(), it->second.trust != trust::Trust::unknown,
                                                                 it->second.path, it->second.id, it->second.id_known};
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
    if (!u.id_known) return !u.path.empty() && win::name_equals(u.path, path);
    const HANDLE h = trust::open_read(path);  // outside the lock: an open can take a while
    if (h == INVALID_HANDLE_VALUE) return false;
    trust::FileIdentity now{};
    const bool ok = trust::identity_of(h, now);
    CloseHandle(h);
    return ok && now.volume == u.id.volume && std::memcmp(now.file_id, u.id.file_id, sizeof(now.file_id)) == 0;
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
