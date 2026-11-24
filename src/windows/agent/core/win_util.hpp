// Small Windows helpers shared by the agent's modules.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nt.hpp"

namespace mebet::win {

struct OsVersion {
    DWORD major = 0, minor = 0, build = 0;
    bool at_least(DWORD ma, DWORD mi) const { return major > ma || (major == ma && minor >= mi); }
};
const OsVersion& os_version();  // RtlGetVersion: not affected by compatibility shims
bool is_windows8_or_later();
bool is_wow64();
bool is_native_x86_os();  // 32-bit Windows (not WOW64)

std::string utf8(const std::wstring& w);
std::wstring wide(const std::string& s);       // from UTF-8
std::wstring from_ansi(const std::string& s);  // JLI arguments are in the ANSI code page
std::string to_ansi(const std::wstring& w, bool* lossless);

std::wstring module_path(HMODULE m);
std::wstring system_dir();   // System32 (SysWOW64 for a 32-bit process on 64-bit Windows)
std::wstring windows_dir();
std::wstring env(const wchar_t* name);
std::wstring dir_of(const std::wstring& path);
std::wstring file_name_of(const std::wstring& path);
std::wstring full_path(const std::wstring& path);  // GetFullPathNameW, no trailing separator
bool path_under(const std::wstring& path, const std::wstring& dir);  // case-insensitive
bool same_path(const std::wstring& a, const std::wstring& b);
bool file_exists(const std::wstring& path);
bool dir_exists(const std::wstring& path);
std::vector<std::wstring> list_dir(const std::wstring& dir, bool* had_subdirs = nullptr);

// "\Device\HarddiskVolume3\…" → "C:\…" (kernel paths from MemoryMappedFilenameInformation).
std::wstring nt_to_dos(const std::wstring& nt_path);
// Kernel path of the image/file mapped at an address (ТЗ §6: identity from the kernel, not the PEB).
std::wstring mapped_file_name(const void* address);

std::wstring reg_string(HKEY root, const wchar_t* subkey, const wchar_t* value, REGSAM extra = 0);
std::vector<std::wstring> reg_multi_string(HKEY root, const wchar_t* subkey, const wchar_t* value, REGSAM extra = 0);
DWORD reg_dword(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD fallback, REGSAM extra = 0);
std::vector<std::wstring> reg_subkeys(HKEY root, const wchar_t* subkey, REGSAM extra = 0);
std::vector<std::wstring> reg_value_names(HKEY root, const wchar_t* subkey, REGSAM extra = 0);

std::uint64_t now_ms();  // GetTickCount64

}  // namespace mebet::win
