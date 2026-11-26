// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/module_table.hpp"

#include <atomic>
#include <map>

#include "core/range_set.hpp"

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

struct Names {
    SRWLOCK lock = SRWLOCK_INIT;
    std::map<std::uintptr_t, Record> records;
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
void add(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path) {
    if (!base || !size) return;
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    if (it != n.records.end() && it->second.size > size) ranges().remove(base, base + it->second.size);
    ranges().add(base, base + size, Payload{t, base}, false);
    n.records[base] = Record{base, size, t, path, g_serial.fetch_add(1, std::memory_order_relaxed) + 1};
    ReleaseSRWLockExclusive(&n.lock);
}

std::uint64_t add_if_absent(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path) {
    if (!base || !size) return 0;
    Names& n = names();
    std::uint64_t serial = 0;
    AcquireSRWLockExclusive(&n.lock);
    if (n.records.find(base) == n.records.end()) {
        serial = g_serial.fetch_add(1, std::memory_order_relaxed) + 1;
        ranges().add(base, base + size, Payload{t, base}, false);
        n.records[base] = Record{base, size, t, path, serial};
    }
    ReleaseSRWLockExclusive(&n.lock);
    return serial;
}

namespace {
void remove_locked(Names& n, std::map<std::uintptr_t, Record>::iterator it) {
    const std::uintptr_t base = it->second.base;
    const std::size_t size = it->second.size;
    n.records.erase(it);
    if (size) ranges().remove(base, base + size);
}
}  // namespace

void remove(std::uintptr_t base) {
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    if (it != n.records.end()) remove_locked(n, it);
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
