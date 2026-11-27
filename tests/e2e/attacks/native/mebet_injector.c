/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * Test fixture for tests/e2e: brings mebet_inject_marker.dll into the harness's own test game
 * process by one technique at a time, so each scenario can show it works without the guard and
 * is caught with it. Built for the test Java's architecture by the harness, run by its probes.
 *
 *   mebet_injector remote-thread <pid> <dll>
 *
 * Prints one "INJECTOR ..." line and exits 0 when the technique was carried out. */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static int fail(const char *what) {
    printf("INJECTOR failed: %s (error %lu)\n", what, GetLastError());
    return 1;
}

/* The DLL's path written into the target, then LoadLibraryW started there on a new thread. */
static int remote_thread(DWORD pid, const wchar_t *dll) {
    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    const SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    void *remote = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return fail("VirtualAllocEx");
    if (!WriteProcessMemory(proc, remote, dll, bytes, NULL)) return fail("WriteProcessMemory");
    LPTHREAD_START_ROUTINE load =
        (LPTHREAD_START_ROUTINE)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE t = CreateRemoteThread(proc, NULL, 0, load, remote, 0, NULL);
    if (!t) return fail("CreateRemoteThread");
    WaitForSingleObject(t, 10000);
    DWORD code = 0;
    GetExitCodeThread(t, &code);
    printf("INJECTOR remote-thread done (LoadLibraryW returned %s)\n", code ? "a module" : "null");
    CloseHandle(t);
    CloseHandle(proc);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 4) {
        printf("INJECTOR usage: mebet_injector <technique> <pid> <dll>\n");
        return 2;
    }
    const DWORD pid = (DWORD)wcstoul(argv[2], NULL, 10);
    if (wcscmp(argv[1], L"remote-thread") == 0) return remote_thread(pid, argv[3]);
    printf("INJECTOR unknown technique\n");
    return 2;
}
