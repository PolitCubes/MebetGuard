// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/win_util.hpp"

#include <cwchar>
#include <utility>

#include "strings.hpp"

namespace mebet::win {

const OsVersion& os_version() {
    static const OsVersion v = [] {
        OsVersion r;
        RTL_OSVERSIONINFOW info{};
        info.dwOSVersionInfoSize = sizeof(info);
        if (nt::api().RtlGetVersion && nt::ok(nt::api().RtlGetVersion(&info))) {
            r.major = info.dwMajorVersion;
            r.minor = info.dwMinorVersion;
            r.build = info.dwBuildNumber;
        }
        return r;
    }();
    return v;
}

bool is_windows8_or_later() { return os_version().at_least(6, 2); }

bool is_wow64() {
    BOOL wow = FALSE;
    using Fn = BOOL(WINAPI*)(HANDLE, PBOOL);
    static const Fn fn = reinterpret_cast<Fn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process")));
    return fn && fn(GetCurrentProcess(), &wow) && wow;
}

bool is_native_x86_os() {
#if defined(_M_IX86)
    return !is_wow64();
#else
    return false;
#endif
}

USHORT wow64_native_machine() {
    if (!is_wow64()) return IMAGE_FILE_MACHINE_UNKNOWN;
    using Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    static const Fn fn = reinterpret_cast<Fn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2")));
    USHORT process = IMAGE_FILE_MACHINE_UNKNOWN, native = IMAGE_FILE_MACHINE_UNKNOWN;
    if (fn && fn(GetCurrentProcess(), &process, &native) && native != IMAGE_FILE_MACHINE_UNKNOWN) return native;
    return IMAGE_FILE_MACHINE_AMD64;  // IsWow64Process2 is Windows 10+; before it WOW64 ran only on x64
}

std::string utf8(const std::wstring& w) { return to_utf8(w); }
std::wstring wide(const std::string& s) { return from_utf8(s); }

std::wstring from_ansi(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

std::string to_ansi(const std::wstring& w, bool* lossless) {
    if (lossless) *lossless = true;
    if (w.empty()) return std::string();
    BOOL used_default = FALSE;
    const int n = WideCharToMultiByte(CP_ACP, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_ACP, 0, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr, &used_default);
    if (lossless) *lossless = n > 0 && !used_default;
    return s;
}

std::wstring module_path(HMODULE m) {
    std::wstring buf(MAX_PATH, L'\0');
    for (int i = 0; i < 6; ++i) {
        const DWORD n = GetModuleFileNameW(m, &buf[0], static_cast<DWORD>(buf.size()));
        if (n == 0) return std::wstring();
        if (n < buf.size()) {
            buf.resize(n);
            return buf;
        }
        buf.resize(buf.size() * 2);
    }
    return std::wstring();
}

std::wstring system_dir() {
    wchar_t buf[MAX_PATH];
    const UINT n = GetSystemDirectoryW(buf, MAX_PATH);
    return n && n < MAX_PATH ? std::wstring(buf, n) : std::wstring(L"C:\\Windows\\System32");
}

std::wstring image_system_dir() {
    return is_wow64() ? windows_dir() + L"\\SysWOW64" : system_dir();
}

std::wstring windows_dir() {
    wchar_t buf[MAX_PATH];
    const UINT n = GetSystemWindowsDirectoryW(buf, MAX_PATH);
    return n && n < MAX_PATH ? std::wstring(buf, n) : std::wstring(L"C:\\Windows");
}

std::wstring env(const wchar_t* name) {
    wchar_t small[512];
    DWORD n = GetEnvironmentVariableW(name, small, 512);
    if (n == 0) return std::wstring();
    if (n < 512) return std::wstring(small, n);
    std::wstring big(n, L'\0');
    n = GetEnvironmentVariableW(name, &big[0], n);
    big.resize(n);
    return big;
}

std::wstring dir_of(const std::wstring& path) {
    const auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? std::wstring() : path.substr(0, pos);
}

std::wstring file_name_of(const std::wstring& path) {
    const auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

std::wstring full_path(const std::wstring& path) {
    if (path.empty()) return path;
    DWORD n = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (n == 0) return path;
    std::wstring out(n, L'\0');
    n = GetFullPathNameW(path.c_str(), n, &out[0], nullptr);
    out.resize(n);
    while (out.size() > 3 && (out.back() == L'\\' || out.back() == L'/')) out.pop_back();
    return out;
}

namespace {
std::wstring strip_long_prefix(const std::wstring& p) {
    if (p.compare(0, 8, L"\\\\?\\UNC\\") == 0) return L"\\\\" + p.substr(8);
    if (p.compare(0, 4, L"\\\\?\\") == 0) return p.substr(4);
    return p;
}
}  // namespace

bool path_under(const std::wstring& path, const std::wstring& dir) {
    const std::wstring p = strip_long_prefix(path);
    std::wstring d = strip_long_prefix(dir);
    while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
    if (d.empty() || p.size() <= d.size()) return false;
    if (!istarts_with(p, d)) return false;
    return p[d.size()] == L'\\' || p[d.size()] == L'/';
}

bool same_path(const std::wstring& a, const std::wstring& b) {
    return iequals_ascii(strip_long_prefix(full_path(a)), strip_long_prefix(full_path(b)));
}

bool file_exists(const std::wstring& path) {
    const DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool dir_exists(const std::wstring& path) {
    const DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

std::vector<std::wstring> list_dir(const std::wstring& dir, bool* had_subdirs) {
    std::vector<std::wstring> out;
    if (had_subdirs) *had_subdirs = false;
    WIN32_FIND_DATAW fd;
    const HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    if (h == INVALID_HANDLE_VALUE) return out;
    do {
        const std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (had_subdirs) *had_subdirs = true;
            out.push_back(name + L"\\");
        } else {
            out.push_back(name);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return out;
}

namespace {

// GetFinalPathNameByHandleW into a string of any length; empty on failure.
std::wstring final_name(HANDLE h, DWORD flags) {
    wchar_t small[MAX_PATH + 8];
    DWORD n = GetFinalPathNameByHandleW(h, small, MAX_PATH + 8, flags);
    if (n == 0) return std::wstring();
    if (n < MAX_PATH + 8) return std::wstring(small, n);
    std::wstring big(n, L'\0');  // n counts the terminating zero here
    n = GetFinalPathNameByHandleW(h, &big[0], n, flags);
    if (n == 0 || n >= big.size()) return std::wstring();
    big.resize(n);
    return big;
}

// A file or folder opened only to ask for its name: no data access, so share modes do not stand
// in the way of a file the loader has mapped.
HANDLE open_for_name(const std::wstring& path) {
    return CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS, nullptr);
}

// The DOS root of a volume ("\Device\HarddiskVolume3") from the mount manager: "C:", or
// "C:\Mount\Data" for a volume mounted only into a folder; empty when it has none. Asked through
// the volume's root folder, so WOW64 never redirects it.
std::wstring ask_dos_root_of_volume(const std::wstring& device) {
    const HANDLE h = open_for_name(L"\\\\?\\GLOBALROOT" + device + L"\\");
    if (h == INVALID_HANDLE_VALUE) return std::wstring();
    std::wstring root = strip_long_prefix(final_name(h, FILE_NAME_OPENED | VOLUME_NAME_DOS));
    CloseHandle(h);
    while (!root.empty() && (root.back() == L'\\' || root.back() == L'/')) root.pop_back();
    return root;
}

// Devices that are not volumes: their "root folder" is a server or a pipe namespace. Opening it
// can wait on the network, and this runs inside the load hook; a path on them has no DOS root to
// find anyway.
bool not_a_volume(const std::wstring& device) {
    static const wchar_t* const kNames[] = {L"\\Device\\Mup",              L"\\Device\\LanmanRedirector",
                                            L"\\Device\\WebDavRedirector", L"\\Device\\NamedPipe",
                                            L"\\Device\\Mailslot",         L"\\Device\\Afd",
                                            L"\\Device\\Null",             L"\\Device\\ConDrv"};
    for (const wchar_t* n : kNames)
        if (iequals_ascii(device, n)) return true;
    return false;
}

// Asked once per volume: the answer does not change while the volume is mounted, and the question
// opens a handle — it used to be asked again for every module path, inside the load hook too.
struct VolumeRoots {
    SRWLOCK lock = SRWLOCK_INIT;
    std::vector<std::pair<std::wstring, std::wstring>> known;  // device → DOS root ("" = none)
};

std::wstring dos_root_of_volume(const std::wstring& device) {
    static VolumeRoots* const roots = new VolumeRoots();  // leaked: hooks use it while the process exits
    VolumeRoots& v = *roots;
    AcquireSRWLockShared(&v.lock);
    for (const auto& kv : v.known) {
        if (iequals_ascii(kv.first, device)) {
            const std::wstring root = kv.second;
            ReleaseSRWLockShared(&v.lock);
            return root;
        }
    }
    ReleaseSRWLockShared(&v.lock);
    const std::wstring root = ask_dos_root_of_volume(device);
    AcquireSRWLockExclusive(&v.lock);
    if (v.known.size() < 64) v.known.emplace_back(device, root);
    ReleaseSRWLockExclusive(&v.lock);
    return root;
}

}  // namespace

std::wstring nt_to_dos(const std::wstring& nt_path) {
    // Drive letters, refreshed on every call: a game can mount a drive while running.
    wchar_t drives[512];
    const DWORD n = GetLogicalDriveStringsW(511, drives);
    if (n > 0 && n < 511) {
        for (const wchar_t* d = drives; *d; d += wcslen(d) + 1) {
            const wchar_t letter[3] = {d[0], L':', 0};
            wchar_t device[MAX_PATH];
            if (!QueryDosDeviceW(letter, device, MAX_PATH)) continue;
            const std::wstring dev = device;
            if (nt_path.size() > dev.size() && istarts_with(nt_path, dev) && nt_path[dev.size()] == L'\\') {
                return std::wstring(letter) + nt_path.substr(dev.size());
            }
        }
    }
    if (istarts_with(nt_path, L"\\Device\\Mup\\")) return L"\\\\" + nt_path.substr(12);
    if (istarts_with(nt_path, L"\\Device\\")) {
        // No letter matched. QueryDosDeviceW must query the logon session's \?? folder, and its DACL
        // lets in only SYSTEM, Administrators and its owner — Administrators again when an elevated
        // token created it. A standard-user token made from an elevated one (`runas /trustlevel`, a
        // launcher dropping its rights, the CI "game as a user") has Administrators deny-only: every
        // lookup is refused, C: too. The raw NT path cannot be opened (the guard refused its own exe,
        // 212), and a GLOBALROOT path compares unequal to every DOS folder (jvm.dll "outside the
        // client Java", 209; the WOW64 layer "hidden", 214). The mount manager answers any token —
        // and also names a volume mounted only into a folder.
        const std::size_t end = nt_path.find(L'\\', 8);
        const std::wstring device = nt_path.substr(0, end);
        if (not_a_volume(device)) return nt_path;  // a redirector, a pipe: as the kernel names it
        if (end != std::wstring::npos) {
            const std::wstring root = dos_root_of_volume(device);
            if (!root.empty()) return root + nt_path.substr(end);
        }
        // A volume with no DOS name at all: the GLOBALROOT form still opens with every Win32 file API.
        return L"\\\\?\\GLOBALROOT" + nt_path;
    }
    return nt_path;
}

std::wstring canonical_path(const std::wstring& path) {
    if (path.empty()) return std::wstring();
    const HANDLE h = open_for_name(path);
    if (h == INVALID_HANDLE_VALUE) return std::wstring();
    std::wstring out = strip_long_prefix(final_name(h, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));
    if (out.empty()) {
        const std::wstring nt = final_name(h, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
        if (!nt.empty()) out = L"\\\\?\\GLOBALROOT" + nt;
    }
    CloseHandle(h);
    return out;
}

std::wstring mapped_file_name(const void* address) {
    const auto& a = nt::api();
    if (!a.NtQueryVirtualMemory) return std::wstring();
    alignas(8) unsigned char buf[sizeof(UNICODE_STRING) + 2 * 4096];
    SIZE_T ret = 0;
    if (!nt::ok(a.NtQueryVirtualMemory(nt::current_process(), const_cast<void*>(address),
                                       nt::kMemoryMappedFilenameInformation, buf, sizeof(buf), &ret)))
        return std::wstring();
    const auto* us = reinterpret_cast<const UNICODE_STRING*>(buf);
    if (!us->Buffer || !us->Length) return std::wstring();
    return nt_to_dos(std::wstring(us->Buffer, us->Length / sizeof(wchar_t)));
}

std::wstring reg_string(HKEY root, const wchar_t* subkey, const wchar_t* value, REGSAM extra) {
    HKEY k;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | extra, &k) != ERROR_SUCCESS) return std::wstring();
    DWORD type = 0, size = 0;
    std::wstring out;
    if (RegQueryValueExW(k, value, nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ) && size > 0) {
        std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
        if (RegQueryValueExW(k, value, nullptr, &type, reinterpret_cast<BYTE*>(&buf[0]), &size) == ERROR_SUCCESS) {
            buf.resize(wcsnlen(buf.c_str(), buf.size()));
            out = buf;
        }
    }
    RegCloseKey(k);
    return out;
}

std::vector<std::wstring> reg_multi_string(HKEY root, const wchar_t* subkey, const wchar_t* value, REGSAM extra) {
    std::vector<std::wstring> out;
    HKEY k;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | extra, &k) != ERROR_SUCCESS) return out;
    DWORD type = 0, size = 0;
    if (RegQueryValueExW(k, value, nullptr, &type, nullptr, &size) == ERROR_SUCCESS && size > 0) {
        std::wstring buf(size / sizeof(wchar_t) + 2, L'\0');
        if (RegQueryValueExW(k, value, nullptr, &type, reinterpret_cast<BYTE*>(&buf[0]), &size) == ERROR_SUCCESS) {
            if (type == REG_MULTI_SZ) {
                for (const wchar_t* p = buf.c_str(); *p; p += wcslen(p) + 1) out.emplace_back(p);
            } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
                out.emplace_back(buf.c_str());
            }
        }
    }
    RegCloseKey(k);
    return out;
}

DWORD reg_dword(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD fallback, REGSAM extra) {
    HKEY k;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | extra, &k) != ERROR_SUCCESS) return fallback;
    DWORD type = 0, data = 0, size = sizeof(data);
    const LONG r = RegQueryValueExW(k, value, nullptr, &type, reinterpret_cast<BYTE*>(&data), &size);
    RegCloseKey(k);
    return r == ERROR_SUCCESS && type == REG_DWORD ? data : fallback;
}

std::vector<std::wstring> reg_subkeys(HKEY root, const wchar_t* subkey, REGSAM extra) {
    std::vector<std::wstring> out;
    HKEY k;
    if (RegOpenKeyExW(root, subkey, 0, KEY_ENUMERATE_SUB_KEYS | extra, &k) != ERROR_SUCCESS) return out;
    wchar_t name[256];
    for (DWORD i = 0;; ++i) {
        DWORD len = 256;
        if (RegEnumKeyExW(k, i, name, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        out.emplace_back(name, len);
    }
    RegCloseKey(k);
    return out;
}

std::vector<std::wstring> reg_value_names(HKEY root, const wchar_t* subkey, REGSAM extra) {
    std::vector<std::wstring> out;
    HKEY k;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | extra, &k) != ERROR_SUCCESS) return out;
    wchar_t name[512];
    for (DWORD i = 0;; ++i) {
        DWORD len = 512;
        if (RegEnumValueW(k, i, name, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        out.emplace_back(name, len);
    }
    RegCloseKey(k);
    return out;
}

std::uint64_t now_ms() { return GetTickCount64(); }

}  // namespace mebet::win
