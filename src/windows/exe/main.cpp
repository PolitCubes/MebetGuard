// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Mebet wrapper (ТЗ §4). Replaces javaw.exe: the launcher starts this executable with the
// usual Java command line and JAVA_HOME pointing to the client Java.
//
// This file does only what has to happen before any other DLL is in the process:
//   1. DLL search order, extension points, environment (harden_process);
//   2. verify the agent by the hash embedded at build time and load it by full path;
//   3. hand over to the agent (MebetGuardMain), which runs every other step.
// Imports are kernel32 only; user32 is delay-loaded for the single error box below, so
// AppInit_DLLs and global hooks cannot get in before the policy is set (ТЗ §4).

#include <cstring>
#include <string>

#include "agent_hash.hpp"
#include "boot_info.hpp"
#include "config.hpp"
#include "hardening.hpp"
#include "nt.hpp"
#include "pe_hash.hpp"

// Discrete GPU on hybrid laptops (ТЗ §4): drivers read these exports from the exe only.
extern "C" {
__declspec(dllexport) DWORD NvOptimusEnablement = 0x00000001;
__declspec(dllexport) int AmdPowerXpressRequestHighPerformance = 1;
}

namespace {

using mebet::config::Reason;

bool russian_ui() {
    const WORD lang = PRIMARYLANGID(GetUserDefaultUILanguage());
    return lang == LANG_RUSSIAN || lang == LANG_UKRAINIAN || lang == LANG_BELARUSIAN || lang == LANG_KAZAK;
}

std::string utf8(const std::wstring& w);

struct FailBox {
    std::wstring title, text;
};

DWORD WINAPI fail_box_main(void* p) {
    const auto* box = static_cast<const FailBox*>(p);
    MessageBoxW(nullptr, box->text.c_str(), box->title.c_str(), MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
    return 0;
}

// The wrapper's own close, before the agent exists: the same rules as the agent's (guard.cpp).
// The reason goes to the launcher log first; the window is skipped in test builds with
// MEBET_TEST_NO_UI (a damaged-files close in a test hung on it), and it waits for the player at most
// close_window_max_ms — a window nobody dismisses no longer keeps the process alive for good.
[[noreturn]] void fail(Reason r, const std::wstring& detail) {
    const auto& d = mebet::config::reason(r);
    const std::string line = std::string("[Mebet] closed: ") + d.id + " (code " + std::to_string(d.exit_code) + ") " +
                             utf8(detail) + "\n";
    DWORD written = 0;
    const HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    if (err && err != INVALID_HANDLE_VALUE) WriteFile(err, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);

    wchar_t no_ui[2] = {};
    const bool skip_ui = mebet::config::kTestBuild && GetEnvironmentVariableW(L"MEBET_TEST_NO_UI", no_ui, 2) > 0;
    if (!skip_ui) {
        const bool ru = russian_ui();
        static FailBox box;  // lives until the process ends: the window thread is not waited for to the end
        box.text = ru ? d.text_ru : d.text_en;
        const auto pos = box.text.find(L"{file}");
        if (pos != std::wstring::npos) box.text.replace(pos, 6, detail);
        box.text += ru ? L"\n\nКод: " : L"\n\nCode: ";
        box.text += std::to_wstring(d.exit_code);
        box.title = L"Mebet Anticheat — ";
        box.title += ru ? d.title_ru : d.title_en;
        if (HANDLE t = CreateThread(nullptr, 0, &fail_box_main, &box, 0, nullptr)) {
            WaitForSingleObject(t, mebet::config::opt::close_window_max_ms);
            CloseHandle(t);
        } else {
            fail_box_main(&box);
        }
    }
    ExitProcess(static_cast<UINT>(d.exit_code));
}

std::wstring module_path(HMODULE m) {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(m, &buf[0], static_cast<DWORD>(buf.size()));
        if (n == 0) return std::wstring();
        if (n < buf.size()) {
            buf.resize(n);
            return buf;
        }
        buf.resize(buf.size() * 2);
    }
}

std::string utf8(const std::wstring& w) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
}

// Reads the whole file through an already open handle (the handle stays open while the
// agent is loaded, so the file cannot be swapped between the check and the load).
bool read_all(HANDLE f, std::string& out) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 0 || size.QuadPart > (256ll << 20)) return false;
    out.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t done = 0;
    while (done < out.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(out.size() - done > (1u << 20) ? (1u << 20) : out.size() - done);
        if (!ReadFile(f, &out[done], want, &got, nullptr) || got == 0) return false;
        done += got;
    }
    return true;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    static mebet::BootInfo boot{};
    boot.size = sizeof(boot);
    boot.version = mebet::kBootInfoVersion;
    boot.exe_module = instance;
    boot.start_ms = GetTickCount64();

    // Step 1 — before anything else.
    mebet::win::harden_process(boot);

    const std::wstring exe = module_path(nullptr);
    const std::wstring dir = exe.substr(0, exe.find_last_of(L"\\/"));
    const std::wstring agent = dir + L"\\" + mebet::generated::kAgentFileNameW;

    // Step 2 — the agent must be byte-for-byte the one this wrapper was built with.
    const HANDLE f = CreateFileW(agent.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) fail(Reason::agent_integrity, agent);
    std::string bytes;
    mebet::Sha256Digest digest{};
    if (!read_all(f, bytes) ||
        !mebet::win::pe_image_hash(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest) ||
        std::memcmp(digest.bytes, mebet::generated::kAgentHash, 32) != 0) {
        CloseHandle(f);
        fail(Reason::agent_integrity, agent);
    }
    std::string().swap(bytes);

    const HMODULE module = LoadLibraryExW(agent.c_str(), nullptr, 0);
    CloseHandle(f);
    if (!module) fail(Reason::agent_integrity, agent);
    const auto entry = reinterpret_cast<mebet::MebetGuardMainFn>(
        reinterpret_cast<void*>(GetProcAddress(module, mebet::kAgentEntryName)));
    if (!entry) fail(Reason::agent_integrity, agent);

    static std::string exe_utf8 = utf8(exe);
    boot.exe_path = exe_utf8.c_str();

    // Step 3 — the agent runs the rest of ТЗ §4 and starts the JVM.
    return entry(&boot);
}
