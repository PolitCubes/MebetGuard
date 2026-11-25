// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/module_table.hpp"

#include <map>

#include "core/range_set.hpp"

namespace mebet::modules {

namespace {

struct Payload {
    trust::Trust trust;
    std::uintptr_t base;
    bool operator==(const Payload& o) const { return trust == o.trust && base == o.base; }
};

RangeSet<Payload>& ranges() {
    static RangeSet<Payload>* r = new RangeSet<Payload>();
    return *r;
}

struct Names {
    SRWLOCK lock = SRWLOCK_INIT;
    std::map<std::uintptr_t, Record> records;
};

Names& names() {
    static Names* n = new Names();
    return *n;
}

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

void add(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path) {
    if (!base || !size) return;
    ranges().add(base, base + size, Payload{t, base}, false);
    Names& n = names();
    AcquireSRWLockExclusive(&n.lock);
    n.records[base] = Record{base, size, t, path};
    ReleaseSRWLockExclusive(&n.lock);
}

void remove(std::uintptr_t base) {
    Names& n = names();
    std::size_t size = 0;
    AcquireSRWLockExclusive(&n.lock);
    auto it = n.records.find(base);
    if (it != n.records.end()) {
        size = it->second.size;
        n.records.erase(it);
    }
    ReleaseSRWLockExclusive(&n.lock);
    if (size) ranges().remove(base, base + size);
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
