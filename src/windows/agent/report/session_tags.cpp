// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "report/session_tags.hpp"

#include <string>

#include "config.hpp"
#include "core/win_util.hpp"
#include "report.hpp"
#include "strings.hpp"

namespace mebet::tags {

namespace {

const char* arch() {
#if defined(_M_ARM64)
    return "arm64";
#elif defined(_M_X64)
    return "x64";
#elif defined(_M_IX86)
    return "x86";
#else
    return "other";
#endif
}

std::string language() {
    using Fn = int(WINAPI*)(LCID, LPWSTR, int, DWORD);
    static const auto fn = reinterpret_cast<Fn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LCIDToLocaleName")));
    wchar_t buf[85];
    if (fn && fn(MAKELCID(GetUserDefaultUILanguage(), SORT_DEFAULT), buf, 85, 0) > 0) return to_utf8(buf);
    return std::to_string(GetUserDefaultUILanguage());
}

// First active display adapter: provider and driver version (ТЗ §12 «Видеокарта»).
void gpu(std::string& vendor, std::string& driver) {
    const wchar_t* cls = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
    for (const auto& sub : win::reg_subkeys(HKEY_LOCAL_MACHINE, cls)) {
        if (sub.size() != 4) continue;
        const std::wstring key = std::wstring(cls) + L"\\" + sub;
        const std::wstring provider = win::reg_string(HKEY_LOCAL_MACHINE, key.c_str(), L"ProviderName");
        const std::wstring version = win::reg_string(HKEY_LOCAL_MACHINE, key.c_str(), L"DriverVersion");
        if (provider.empty() && version.empty()) continue;
        if (!vendor.empty()) vendor += ", ";
        vendor += to_utf8(provider);
        if (!driver.empty()) driver += ", ";
        driver += to_utf8(version);
    }
}

}  // namespace

void init() {
    auto& r = report::Reporter::instance();
    r.set_tag("guard_version", config::kVersion);
    r.set_tag("arch", arch());
    if (win::is_wow64()) r.set_tag("wow64", "yes");
    const auto& v = win::os_version();
    r.set_tag("os_version", std::to_string(v.major) + "." + std::to_string(v.minor) + "." + std::to_string(v.build));
    const wchar_t* nt = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    r.set_tag("os_edition", to_utf8(win::reg_string(HKEY_LOCAL_MACHINE, nt, L"EditionID", KEY_WOW64_64KEY)));
    r.set_tag("language", language());
    std::string vendor, driver;
    gpu(vendor, driver);
    r.set_tag("gpu_vendor", vendor.empty() ? "unknown" : vendor);
    r.set_tag("gpu_driver", driver.empty() ? "unknown" : driver);
}

}  // namespace mebet::tags
