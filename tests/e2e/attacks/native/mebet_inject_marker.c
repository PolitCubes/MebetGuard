/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * The library the injection scenarios place into the test game process (tests/e2e). It does
 * nothing but say where it ended up: one line on the process's stdout, which the harness reads.
 * Plain Win32, no CRT, so it behaves the same however it was brought in. */

#include <windows.h>

static void say(const char *how) {
    char line[128];
    const char *head = "ATTACK injected ";
    int n = 0;
    for (const char *p = head; *p && n < 100; ++p) line[n++] = *p;
    for (const char *p = how; *p && n < 120; ++p) line[n++] = *p;
    line[n++] = '\n';
    DWORD done = 0;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out && out != INVALID_HANDLE_VALUE) WriteFile(out, line, (DWORD)n, &done, NULL);
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    (void)self;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) say("library loaded");
    return TRUE;
}
