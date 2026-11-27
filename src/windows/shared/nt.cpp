// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "nt.hpp"

namespace mebet::nt {

namespace {

template <typename T>
void resolve(HMODULE m, T& out, const char* name) {
    out = reinterpret_cast<T>(reinterpret_cast<void*>(GetProcAddress(m, name)));
}

Api load() {
    Api a;
    a.ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!a.ntdll) return a;
    resolve(a.ntdll, a.NtCreateSection, "NtCreateSection");
    resolve(a.ntdll, a.NtMapViewOfSection, "NtMapViewOfSection");
    resolve(a.ntdll, a.NtUnmapViewOfSection, "NtUnmapViewOfSection");
    resolve(a.ntdll, a.NtAllocateVirtualMemory, "NtAllocateVirtualMemory");
    resolve(a.ntdll, a.NtProtectVirtualMemory, "NtProtectVirtualMemory");
    resolve(a.ntdll, a.NtFreeVirtualMemory, "NtFreeVirtualMemory");
    resolve(a.ntdll, a.NtCreateSectionEx, "NtCreateSectionEx");
    resolve(a.ntdll, a.NtMapViewOfSectionEx, "NtMapViewOfSectionEx");
    resolve(a.ntdll, a.NtUnmapViewOfSectionEx, "NtUnmapViewOfSectionEx");
    resolve(a.ntdll, a.NtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx");
    resolve(a.ntdll, a.NtQueryVirtualMemory, "NtQueryVirtualMemory");
    resolve(a.ntdll, a.NtQuerySection, "NtQuerySection");
    resolve(a.ntdll, a.NtQuerySystemInformation, "NtQuerySystemInformation");
    resolve(a.ntdll, a.NtQueryInformationProcess, "NtQueryInformationProcess");
    resolve(a.ntdll, a.NtQueryInformationThread, "NtQueryInformationThread");
    resolve(a.ntdll, a.NtGetNextThread, "NtGetNextThread");
    resolve(a.ntdll, a.NtSetSecurityObject, "NtSetSecurityObject");
    resolve(a.ntdll, a.NtTerminateProcess, "NtTerminateProcess");
    resolve(a.ntdll, a.NtQueryObject, "NtQueryObject");
    resolve(a.ntdll, a.LdrRegisterDllNotification, "LdrRegisterDllNotification");
    resolve(a.ntdll, a.RtlGetVersion, "RtlGetVersion");
    resolve(a.ntdll, a.wine_get_version, "wine_get_version");
    return a;
}

}  // namespace

const Api& api() {
    static const Api a = load();
    return a;
}

}  // namespace mebet::nt
