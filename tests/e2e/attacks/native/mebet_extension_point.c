/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * The library the OS itself brings into every new process through an extension point
 * (tests/e2e, layer extension_point_disable). Built twice by the harness, once per define:
 *
 *   -DAPPCERT  AppCertDlls — the kernel loads it into every CreateProcess of the session.
 *   -DAPPINIT  AppInit_DLLs — user32 loads it into every process that loads user32 (Windows 8+
 *              only while Secure Boot is off; the CI runners have it off).
 *
 * Nothing but one line on the process's stdout, which the harness reads, and the program that got
 * it. Plain Win32, no CRT, so it behaves the same however the system brought it in. */

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

/* The same file is linked as an exe (the helper) and as the DLL the system loads. In the exe nothing
 * calls DllMain, so the linker drops it and its line with it; the DLL it is the entry and must stay. */
#pragma comment(linker, "/include:DllMain")

static void say(const char *how) {
    char line[512];
    int n = 0;
    const char *head = "ATTACK injected library loaded (";
    for (const char *p = head; *p; ++p) line[n++] = *p;
    for (const char *p = how; *p && n < 120; ++p) line[n++] = *p;
    const char *mid = ") in ";
    for (const char *p = mid; *p; ++p) line[n++] = *p;
    /* The program that got the library, never the full path: the line has to stay one line. */
    const wchar_t *w = GetCommandLineW();
    if (w && *w == L'"') ++w;
    while (w && *w && *w != L'"' && *w != L' ' && n < 500) {
        const wchar_t c = *w++;
        line[n++] = (char)(c < 128 ? c : '?');
    }
    line[n++] = '\n';
    DWORD done = 0;
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out && out != INVALID_HANDLE_VALUE) WriteFile(out, line, (DWORD)n, &done, NULL);
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    (void)self;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    /* AppCertDlls is run before the process' own start-up: the environment block may not be usable
     * yet, so the value is not read and the line just says what this library is. */
    say("an extension point");
    return TRUE;
}

/* ---- the helper side: register the mode, run a game under it, unregister ---------------------- */

/* The game's own environment was inherited by the injector, so the library also lands in the
 * injector; the helper's pid is handed on to skip that line. */
#define APPINIT_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define APPCERT_KEY L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"

static DWORD old_init = 0;
static wchar_t old_init_value[1024];
static int appinit_set = 0;

static int read_value(const wchar_t *key, const wchar_t *name, wchar_t *buf, DWORD *len) {
    DWORD type = 0;
    *len = 0;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, key, name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, &type, buf, len) !=
        ERROR_SUCCESS) {
        buf[0] = 0;
        return 0;
    }
    return 1;
}

static int register_appinit(const wchar_t *dll) {
    /* Secure Boot off is the one condition of AppInit on Windows 8+: a signed copy is not required
     * here, the list is checked by name only. */
    DWORD len = sizeof(old_init_value);
    read_value(APPINIT_KEY, L"AppInit_DLLs", old_init_value, &len);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, APPINIT_KEY, L"LoadAppInit_DLLs", RRF_RT_REG_DWORD, NULL, &old_init,
                     &(DWORD){sizeof(old_init)}) != ERROR_SUCCESS)
        old_init = 0;
    /* One entry at a time (the app's own value first would keep the running processes' copy). */
    if (RegSetKeyValueW(HKEY_LOCAL_MACHINE, APPINIT_KEY, L"AppInit_DLLs", REG_SZ, dll,
                        (DWORD)((wcslen(dll) + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
        return 0;
    if (RegSetKeyValueW(HKEY_LOCAL_MACHINE, APPINIT_KEY, L"LoadAppInit_DLLs", REG_DWORD, &(DWORD){1},
                        sizeof(DWORD)) != ERROR_SUCCESS)
        return 0;
    appinit_set = 1;
    return 1;
}

static void unregister_appinit(void) {
    if (!appinit_set) return;
    RegSetKeyValueW(HKEY_LOCAL_MACHINE, APPINIT_KEY, L"AppInit_DLLs", REG_SZ, old_init_value,
                    (DWORD)((wcslen(old_init_value) + 1) * sizeof(wchar_t)));
    RegSetKeyValueW(HKEY_LOCAL_MACHINE, APPINIT_KEY, L"LoadAppInit_DLLs", REG_DWORD, &old_init, sizeof(DWORD));
    appinit_set = 0;
}

/* AppCertDlls: one value per library, kept by name so the helper removes exactly its own. */
static const wchar_t *APPCERT_NAME = L"MebetE2e";

static int register_appcert(const wchar_t *dll) {
    HKEY k = NULL;
    const LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, APPCERT_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
    if (rc != ERROR_SUCCESS) {
        printf("INJECTOR extension: AppCertDlls key open failed (%ld)\n", (long)rc);
        return 0;
    }
    const LONG ok = RegSetValueExW(k, APPCERT_NAME, 0, REG_SZ, (const BYTE *)dll,
                                   (DWORD)((wcslen(dll) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    if (ok != ERROR_SUCCESS) printf("INJECTOR extension: AppCertDlls value set failed (%ld)\n", (long)ok);
    return ok == ERROR_SUCCESS;
}

static void unregister_appcert(void) {
    RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, APPCERT_KEY, APPCERT_NAME);
}

int wmain(int argc, wchar_t **argv) {
    /* extension <mode> <pidfile> <dll> <arg0> [args...] — register <dll>, run arg0.. (the whole
     * command line, quoted here exactly as the child's CreateProcess sees it), wait for the game,
     * unregister again. The game's stdout is the harness's own (inherited), so its lines land where it
     * reads them; the echo below is the start signal. */
    if (argc < 2) return 2;
    const int appinit = wcscmp(argv[1], L"appinit") == 0;
    const int appcert = wcscmp(argv[1], L"appcert") == 0;
    if (!appinit && !appcert) return 2;
    if (argc < 5) {
        wchar_t buf[1024];
        DWORD len = sizeof(buf);
        buf[0] = 0;
        if (appinit) {
            if (!read_value(APPINIT_KEY, L"AppInit_DLLs", buf, &len)) buf[0] = 0;
        } else if (!read_value(APPCERT_KEY, APPCERT_NAME, buf, &len)) {
            buf[0] = 0;
        }
        printf("INJECTOR extension value %ls\n", buf);
        return 0;
    }
    const wchar_t *pidfile = argv[2];
    wchar_t cmd[8192];
    int used = 0;
    cmd[0] = 0;
    for (int i = 4; i < argc && used < 8000; ++i)
        used += _snwprintf_s(cmd + used, 8192 - used, _TRUNCATE, L"\"%ls\" ", argv[i]);
    wchar_t full[8256];
    _snwprintf_s(full, 8256, _TRUNCATE, L"cmd /c echo TARGET started && %ls", cmd);
    if (!(appinit ? register_appinit(argv[3]) : register_appcert(argv[3]))) return 1;
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    const BOOL made = CreateProcessW(NULL, full, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (made) {
        wchar_t text[32];
        _snwprintf_s(text, 32, _TRUNCATE, L"%lu", pi.dwProcessId);
        const HANDLE f = CreateFileW(pidfile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD done = 0;
            WriteFile(f, text, (DWORD)(wcslen(text) * sizeof(wchar_t)), &done, NULL);
            CloseHandle(f);
        }
        WaitForSingleObject(pi.hProcess, 120000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        printf("INJECTOR extension start failed: error %lu\n", GetLastError());
    }
    if (appinit) unregister_appinit(); else unregister_appcert();
    return made ? 0 : 1;
}
