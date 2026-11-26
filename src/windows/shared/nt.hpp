// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Native API declarations used by the wrapper and the agent.
//
// Everything is resolved at runtime with GetProcAddress, so a function missing on an
// older Windows only switches the dependent module off (ТЗ §2 pillar 3) instead of
// breaking the import table. Structure layouts follow the public Windows SDK/WDK and the
// System Informer (phnt) headers.
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>

namespace mebet::nt {

constexpr NTSTATUS kStatusSuccess = 0x00000000L;
constexpr NTSTATUS kStatusAccessDenied = static_cast<NTSTATUS>(0xC0000022L);
constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
constexpr NTSTATUS kStatusNoMoreEntries = static_cast<NTSTATUS>(0x8000001AL);
inline bool ok(NTSTATUS s) { return s >= 0; }

inline HANDLE current_process() { return reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)); }
inline HANDLE current_thread() { return reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-2)); }

// Section attributes (wdm.h).
constexpr ULONG kSecImage = 0x01000000;
constexpr ULONG kSecImageNoExecute = 0x11000000;

// Information classes.
constexpr int kMemoryBasicInformation = 0;
constexpr int kMemoryMappedFilenameInformation = 2;
constexpr int kSectionBasicInformation = 0;
constexpr int kThreadQuerySetWin32StartAddress = 9;
constexpr int kProcessDebugPort = 7;
constexpr int kProcessDebugObjectHandle = 30;
constexpr int kSystemModuleInformation = 11;
constexpr int kSystemKernelDebuggerInformation = 35;
constexpr int kSystemCodeIntegrityInformation = 103;
constexpr int kSystemSecureBootInformation = 145;
constexpr int kSystemKernelDebuggerInformationEx = 149;
constexpr int kSystemHypervisorDetailInformation = 159;

// CodeIntegrityOptions bits (ntddk.h / phnt).
constexpr ULONG kCiEnabled = 0x01;
constexpr ULONG kCiTestSign = 0x02;
constexpr ULONG kCiUmciEnabled = 0x04;
constexpr ULONG kCiDebugModeEnabled = 0x80;
constexpr ULONG kCiFlightBuild = 0x200;
constexpr ULONG kCiHvciKmciEnabled = 0x400;
constexpr ULONG kCiHvciKmciAuditMode = 0x800;
constexpr ULONG kCiHvciKmciStrictMode = 0x1000;
constexpr ULONG kCiHvciIumEnabled = 0x2000;

struct SectionBasicInformation {
    PVOID BaseAddress;
    ULONG AllocationAttributes;
    LARGE_INTEGER MaximumSize;
};

struct CodeIntegrityInformation {
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

struct KernelDebuggerInformation {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};

struct KernelDebuggerInformationEx {
    BOOLEAN DebuggerAllowed;
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerPresent;
};

struct SecureBootInformation {
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootCapable;
};

// SystemHypervisorDetailInformation (0x9F): the hypervisor CPUID leaves 0x40000000–6 as
// Windows saw them; the only way to read them on ARM64, where there is no CPUID.
struct HvDetails {
    ULONG Data[4];  // EAX, EBX, ECX, EDX
};
struct HypervisorDetailInformation {
    HvDetails HvVendorAndMaxFunction;  // 0x40000000
    HvDetails HypervisorInterface;     // 0x40000001
    HvDetails HypervisorVersion;       // 0x40000002
    HvDetails HvFeatures;              // 0x40000003
    HvDetails HwFeatures;              // 0x40000006
    HvDetails EnlightenmentInfo;       // 0x40000004
    HvDetails ImplementationLimits;    // 0x40000005
};

struct ProcessModuleInformation {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};
struct ProcessModules {
    ULONG NumberOfModules;
    ProcessModuleInformation Modules[1];
};

// LdrRegisterDllNotification.
constexpr ULONG kLdrDllNotificationLoaded = 1;
constexpr ULONG kLdrDllNotificationUnloaded = 2;
struct LdrDllNotificationData {
    ULONG Flags;
    const UNICODE_STRING* FullDllName;
    const UNICODE_STRING* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
};
using LdrDllNotificationFn = VOID(NTAPI*)(ULONG reason, const LdrDllNotificationData* data, PVOID context);

// Hooked functions. ТЗ §5 named six; their Ex variants (below) are hooked too where ntdll has them:
// without them an image could be mapped, a view unmapped and executable memory allocated past
// the hooks, and only the periodic sweep (every 5 s) saw it.
using NtCreateSectionFn = NTSTATUS(NTAPI*)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                           POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                           ULONG SectionPageProtection, ULONG AllocationAttributes,
                                           HANDLE FileHandle);
using NtMapViewOfSectionFn = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
                                              ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
                                              PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
                                              ULONG Win32Protect);
using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress);
using NtAllocateVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                                   PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
using NtProtectVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                                                  ULONG NewProtect, PULONG OldProtect);
using NtFreeVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                                               ULONG FreeType);
// The Ex variants (Windows 8 for the unmap, Windows 10 1803/1809 for the others; nullptr where absent).
// MEM_EXTENDED_PARAMETER is passed through untouched, so it is a plain pointer here.
using NtCreateSectionExFn = NTSTATUS(NTAPI*)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                             POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                             ULONG SectionPageProtection, ULONG AllocationAttributes,
                                             HANDLE FileHandle, PVOID ExtendedParameters, ULONG ExtendedParameterCount);
using NtMapViewOfSectionExFn = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
                                                PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
                                                ULONG PageProtection, PVOID ExtendedParameters,
                                                ULONG ExtendedParameterCount);
using NtUnmapViewOfSectionExFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags);
using NtAllocateVirtualMemoryExFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                                                     ULONG AllocationType, ULONG PageProtection,
                                                     PVOID ExtendedParameters, ULONG ExtendedParameterCount);

// Queries.
using NtQueryVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, int InformationClass,
                                                PVOID Buffer, SIZE_T Length, PSIZE_T ReturnLength);
using NtQuerySectionFn = NTSTATUS(NTAPI*)(HANDLE SectionHandle, int InformationClass, PVOID Buffer, SIZE_T Length,
                                          PSIZE_T ReturnLength);
using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(int InformationClass, PVOID Buffer, ULONG Length,
                                                    PULONG ReturnLength);
using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, int InformationClass, PVOID Buffer,
                                                     ULONG Length, PULONG ReturnLength);
using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, int InformationClass, PVOID Buffer,
                                                    ULONG Length, PULONG ReturnLength);
using NtGetNextThreadFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                           ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);
using NtSetSecurityObjectFn = NTSTATUS(NTAPI*)(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                               PSECURITY_DESCRIPTOR SecurityDescriptor);
using NtTerminateProcessFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE Handle, int InformationClass, PVOID Buffer, ULONG Length,
                                         PULONG ReturnLength);
constexpr int kObjectNameInformation = 1;
using LdrRegisterDllNotificationFn = NTSTATUS(NTAPI*)(ULONG Flags, LdrDllNotificationFn Callback, PVOID Context,
                                                      PVOID* Cookie);
using RtlGetVersionFn = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW Info);
using WineGetVersionFn = const char*(__cdecl*)();

// All ntdll entry points the guard uses, resolved once.
struct Api {
    HMODULE ntdll = nullptr;
    NtCreateSectionFn NtCreateSection = nullptr;
    NtMapViewOfSectionFn NtMapViewOfSection = nullptr;
    NtUnmapViewOfSectionFn NtUnmapViewOfSection = nullptr;
    NtAllocateVirtualMemoryFn NtAllocateVirtualMemory = nullptr;
    NtProtectVirtualMemoryFn NtProtectVirtualMemory = nullptr;
    NtFreeVirtualMemoryFn NtFreeVirtualMemory = nullptr;
    NtCreateSectionExFn NtCreateSectionEx = nullptr;
    NtMapViewOfSectionExFn NtMapViewOfSectionEx = nullptr;
    NtUnmapViewOfSectionExFn NtUnmapViewOfSectionEx = nullptr;
    NtAllocateVirtualMemoryExFn NtAllocateVirtualMemoryEx = nullptr;
    NtQueryVirtualMemoryFn NtQueryVirtualMemory = nullptr;
    NtQuerySectionFn NtQuerySection = nullptr;
    NtQuerySystemInformationFn NtQuerySystemInformation = nullptr;
    NtQueryInformationProcessFn NtQueryInformationProcess = nullptr;
    NtQueryInformationThreadFn NtQueryInformationThread = nullptr;
    NtGetNextThreadFn NtGetNextThread = nullptr;
    NtSetSecurityObjectFn NtSetSecurityObject = nullptr;
    NtTerminateProcessFn NtTerminateProcess = nullptr;
    NtQueryObjectFn NtQueryObject = nullptr;
    LdrRegisterDllNotificationFn LdrRegisterDllNotification = nullptr;
    RtlGetVersionFn RtlGetVersion = nullptr;
    WineGetVersionFn wine_get_version = nullptr;
};

// Resolves the table on first use; never fails (missing entries stay nullptr).
const Api& api();

}  // namespace mebet::nt
