/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * A stand-in for a cheat DLL that gets injected into the game process from the outside. It
 * is NOT a cheat: on load it only appends one line to the file named by the MEBET_MARK
 * environment variable, so the e2e oracle can tell the DLL actually ran inside the target.
 * Everything a real cheat would do (read game memory, draw an overlay, drive input) is absent.
 *
 * Without the guard the injection must succeed and the marker line appears; with the guard in
 * the process the load must be refused and the client closed before DllMain returns, so no
 * marker is written. The runner builds this in CI with MSVC. */

#include <windows.h>
#include <stdio.h>

static void write_marker(void) {
    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("MEBET_MARK", path, sizeof(path));
    if (n == 0 || n >= sizeof(path)) return;
    FILE *f = fopen(path, "ab");
    if (!f) return;
    fputs("ATTACK injected dll loaded\n", f);
    fclose(f);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        write_marker();
    }
    return TRUE;
}
