// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "hardening.hpp"

#include "env_list.hpp"
#include "config.hpp"
#include "nt.hpp"

namespace mebet::win {

namespace {

// Declared here because the SDK hides them below _WIN32_WINNT 0x0602.
constexpr DWORD kLoadLibrarySearchUserDirs = 0x00000400;
constexpr DWORD kLoadLibrarySearchSystem32 = 0x00000800;
constexpr int kProcessExtensionPointDisablePolicy = 6;
struct ExtensionPointDisablePolicy {
    DWORD Flags;  // bit 0: DisableExtensionPoints
};

using SetDefaultDllDirectoriesFn = BOOL(WINAPI*)(DWORD);
using SetProcessMitigationPolicyFn = BOOL(WINAPI*)(int, PVOID, SIZE_T);
using GetProcessMitigationPolicyFn = BOOL(WINAPI*)(HANDLE, int, PVOID, SIZE_T);

// Static storage: the agent reads the cleared values through BootInfo pointers.
char g_names[kMaxClearedEnv][40];
char g_values[kMaxClearedEnv][2048];  // 512 characters of UTF-8 at most 4 bytes each

FARPROC kernel32_proc(const char* name) {
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    return k ? GetProcAddress(k, name) : nullptr;
}

void copy_ascii(char* dst, std::size_t cap, const char* src) {
    std::size_t i = 0;
    for (; src[i] && i + 1 < cap; ++i) dst[i] = src[i];
    dst[i] = 0;
}

// Cuts to 512 UTF-16 units and converts to UTF-8 (ТЗ §12: value ≤ 512 characters).
void to_utf8_cut(const wchar_t* w, char* out, int cap) {
    wchar_t cut[513];
    int n = 0;
    for (; w[n] && n < 512; ++n) cut[n] = w[n];
    if (n > 0 && cut[n - 1] >= 0xD800 && cut[n - 1] <= 0xDBFF) --n;  // do not split a surrogate pair
    cut[n] = 0;
    if (WideCharToMultiByte(CP_UTF8, 0, cut, -1, out, cap, nullptr, nullptr) == 0) out[0] = 0;
}

void clear_var(BootInfo& boot, const char* name) {
    wchar_t wname[64];
    int i = 0;
    for (; name[i] && i < 63; ++i) wname[i] = static_cast<wchar_t>(name[i]);
    wname[i] = 0;
    // Most values are short; a long one is read into a heap buffer.
    wchar_t small[1024];
    DWORD len = GetEnvironmentVariableW(wname, small, 1024);
    if (len == 0) return;  // not set
    wchar_t* value = small;
    wchar_t* big = nullptr;
    if (len >= 1024) {
        big = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, (static_cast<SIZE_T>(len) + 1) * sizeof(wchar_t)));
        if (big && GetEnvironmentVariableW(wname, big, len + 1) != 0) value = big;
        else value = small;
    }
    if (boot.cleared_count < kMaxClearedEnv) {
        const unsigned k = boot.cleared_count++;
        copy_ascii(g_names[k], sizeof(g_names[k]), name);
        to_utf8_cut(value, g_values[k], sizeof(g_values[k]));
        boot.cleared_names[k] = g_names[k];
        boot.cleared_values[k] = g_values[k];
    }
    SetEnvironmentVariableW(wname, nullptr);
    if (big) HeapFree(GetProcessHeap(), 0, big);
}

void set_var(const char* name, const char* value) {
    wchar_t wn[64], wv[512];
    int i = 0;
    for (; name[i] && i < 63; ++i) wn[i] = static_cast<wchar_t>(name[i]);
    wn[i] = 0;
    for (i = 0; value[i] && i < 511; ++i) wv[i] = static_cast<wchar_t>(value[i]);
    wv[i] = 0;
    SetEnvironmentVariableW(wn, wv);
}

}  // namespace

void harden_process(BootInfo& boot) {
    // 1. DLL search order. Without KB2533623 Windows 7 has no SetDefaultDllDirectories;
    //    SetDllDirectoryW("") still removes the current directory from the search.
    if (auto set_default = reinterpret_cast<SetDefaultDllDirectoriesFn>(kernel32_proc("SetDefaultDllDirectories"))) {
        if (set_default(kLoadLibrarySearchSystem32 | kLoadLibrarySearchUserDirs)) boot.hardening |= kBootDllDirsDefault;
    }
    if (SetDllDirectoryW(L"")) boot.hardening |= kBootDllDirsNoCwd;

    // 2. Extension points (Windows 8+): AppInit_DLLs, legacy IME, global window hooks,
    //    Winsock LSP. Must happen before user32 is loaded — the wrapper delay-loads it.
    if (config::enabled(config::Module::extension_point_disable)) {
        if (auto set_policy =
                reinterpret_cast<SetProcessMitigationPolicyFn>(kernel32_proc("SetProcessMitigationPolicy"))) {
            ExtensionPointDisablePolicy p{1};
            if (set_policy(kProcessExtensionPointDisablePolicy, &p, sizeof(p))) boot.hardening |= kBootExtPointsDisabled;
        }
    }

    // 3. Environment.
    if (config::enabled(config::Module::env_hardening)) {
        for (const char* v : kJavaEnvVars) clear_var(boot, v);
        for (const char* v : kVulkanEnvVars) clear_var(boot, v);
        set_var("VK_LOADER_LAYERS_DISABLE", kVulkanLayersDisable);
        set_var("VK_LOADER_LAYERS_ALLOW", kVulkanLayersAllow);
        boot.hardening |= kBootEnvCleared | kBootVulkanFiltered;
        if (config::opt::nvidia_shim_mccompat) set_var(kShimMcCompatName, kShimMcCompatValue);
    }
}

bool extension_points_disabled() {
    auto get_policy = reinterpret_cast<GetProcessMitigationPolicyFn>(kernel32_proc("GetProcessMitigationPolicy"));
    if (!get_policy) return false;
    ExtensionPointDisablePolicy p{0};
    if (!get_policy(GetCurrentProcess(), kProcessExtensionPointDisablePolicy, &p, sizeof(p))) return false;
    return (p.Flags & 1) != 0;
}


// ---- The DACL, as early as the process can have it -------------------------------------------
// The agent sets the process and thread DACL at step 6 — after the hooks, the start-up scan and
// jli.dll: hundreds of milliseconds in which a program of the player's own user that waits for the
// game could open it for its memory, and keep that handle for good (a DACL takes back no handle).
// The same rights here, first thing in the wrapper, through ntdll only (the wrapper imports nothing
// but kernel32). The agent sets them again later; this only closes the window before.
namespace {

using NtOpenProcessTokenFn = NTSTATUS(NTAPI*)(HANDLE, ACCESS_MASK, PHANDLE);
using NtQueryInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
using RtlLengthSidFn = ULONG(NTAPI*)(PSID);
using RtlCreateAclFn = NTSTATUS(NTAPI*)(PACL, ULONG, ULONG);
using RtlAddAccessAllowedAceFn = NTSTATUS(NTAPI*)(PACL, ULONG, ACCESS_MASK, PSID);
using RtlCreateSecurityDescriptorFn = NTSTATUS(NTAPI*)(PSECURITY_DESCRIPTOR, ULONG);
using RtlSetDaclSecurityDescriptorFn = NTSTATUS(NTAPI*)(PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN);
using RtlSetControlSecurityDescriptorFn = NTSTATUS(NTAPI*)(PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL,
                                                           SECURITY_DESCRIPTOR_CONTROL);
using NtSetSecurityObjectFn2 = NTSTATUS(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
using NtCloseFn = NTSTATUS(NTAPI*)(HANDLE);

template <typename T>
T ntdll_proc(const char* name) {
    return reinterpret_cast<T>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name)));
}

bool set_dacl(HANDLE object, PSID user, ACCESS_MASK user_rights) {
    const auto length_sid = ntdll_proc<RtlLengthSidFn>("RtlLengthSid");
    const auto create_acl = ntdll_proc<RtlCreateAclFn>("RtlCreateAcl");
    const auto add_ace = ntdll_proc<RtlAddAccessAllowedAceFn>("RtlAddAccessAllowedAce");
    const auto create_sd = ntdll_proc<RtlCreateSecurityDescriptorFn>("RtlCreateSecurityDescriptor");
    const auto set_sd_dacl = ntdll_proc<RtlSetDaclSecurityDescriptorFn>("RtlSetDaclSecurityDescriptor");
    const auto set_control = ntdll_proc<RtlSetControlSecurityDescriptorFn>("RtlSetControlSecurityDescriptor");
    const auto set_security = ntdll_proc<NtSetSecurityObjectFn2>("NtSetSecurityObject");
    if (!length_sid || !create_acl || !add_ace || !create_sd || !set_sd_dacl || !set_control || !set_security)
        return false;
    // OWNER RIGHTS (S-1-3-4): the owner keeps only READ_CONTROL, not the implicit WRITE_DAC.
    struct {
        BYTE revision = 1, count = 1;
        BYTE authority[6] = {0, 0, 0, 0, 0, 3};
        DWORD sub = 4;
    } owner_rights;
    PSID owner = &owner_rights;
    alignas(8) unsigned char acl_buf[512];
    const ULONG size = sizeof(ACL) + 2 * sizeof(ACCESS_ALLOWED_ACE) + length_sid(user) + length_sid(owner);
    if (size > sizeof(acl_buf)) return false;
    auto* acl = reinterpret_cast<PACL>(acl_buf);
    SECURITY_DESCRIPTOR sd{};
    return nt::ok(create_acl(acl, size, ACL_REVISION)) && nt::ok(add_ace(acl, ACL_REVISION, user_rights, user)) &&
           nt::ok(add_ace(acl, ACL_REVISION, READ_CONTROL, owner)) &&
           nt::ok(create_sd(&sd, SECURITY_DESCRIPTOR_REVISION)) && nt::ok(set_sd_dacl(&sd, TRUE, acl, FALSE)) &&
           nt::ok(set_control(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) &&
           nt::ok(set_security(object, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &sd));
}

}  // namespace

void protect_process_early() {
    if (!config::enabled(config::Module::process_dacl)) return;
    const auto open_token = ntdll_proc<NtOpenProcessTokenFn>("NtOpenProcessToken");
    const auto query_token = ntdll_proc<NtQueryInformationTokenFn>("NtQueryInformationToken");
    const auto close = ntdll_proc<NtCloseFn>("NtClose");
    if (!open_token || !query_token || !close) return;
    HANDLE token = nullptr;
    if (!nt::ok(open_token(nt::current_process(), TOKEN_QUERY, &token))) return;
    alignas(8) unsigned char buf[256];
    ULONG got = 0;
    const bool have = nt::ok(query_token(token, 1 /* TokenUser */, buf, sizeof(buf), &got));
    close(token);
    if (!have) return;
    PSID user = reinterpret_cast<TOKEN_USER*>(buf)->User.Sid;
    // As the agent's (process/dacl.cpp): OBS opens the game with QUERY_INFORMATION | SYNCHRONIZE, Task
    // Manager needs TERMINATE. No memory rights, no thread rights. Not the main thread here: its DACL
    // would take WRITE_DAC from the agent too, which sets every thread's DACL itself at step 6.
    set_dacl(nt::current_process(), user,
             PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE);
}

}  // namespace mebet::win
