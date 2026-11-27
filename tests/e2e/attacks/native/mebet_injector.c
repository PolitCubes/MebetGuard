/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * Test fixture for tests/e2e: brings mebet_inject_marker.dll into the harness's own test game
 * process by one technique at a time, so each scenario can show it works without the guard and
 * is caught with it. Built for the test Java's architecture by the harness, run by its probes.
 *
 *   mebet_injector remote-thread <pid> <dll>
 *   mebet_injector apc <pid> <dll>
 *
 * Prints one "INJECTOR ..." line and exits 0 when the technique was carried out. */

#include <windows.h>
#include <tlhelp32.h>
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

/* The DLL's path written into the target (shared by the techniques that call a loader there). */
static void *write_path(HANDLE proc, const wchar_t *dll) {
    const SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    void *remote = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote && !WriteProcessMemory(proc, remote, dll, bytes, NULL)) return NULL;
    return remote;
}

typedef LONG(NTAPI *NtQueueApcThreadExFn)(HANDLE, HANDLE, void *, void *, void *, void *);

/* LoadLibraryExW(path, NULL, 0) queued to the target's threads as a special user APC, which runs
 * without the thread having to enter an alertable wait (Windows 10 1809+). LoadLibraryExW takes three
 * arguments — what an APC routine receives — so the call is balanced on 32-bit x86 too. */
static int apc(DWORD pid, const wchar_t *dll) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!proc) return fail("OpenProcess");
    void *remote = write_path(proc, dll);
    if (!remote) return fail("write the path");
    NtQueueApcThreadExFn queue =
        (NtQueueApcThreadExFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThreadEx");
    if (!queue) return fail("NtQueueApcThreadEx missing");
    void *load = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryExW");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = {sizeof(te)};
    int queued = 0;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE t = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
        if (!t) continue;
        if (queue(t, (HANDLE)1 /* QUEUE_USER_APC_SPECIAL_USER_APC */, load, remote, NULL, NULL) >= 0) queued++;
        CloseHandle(t);
    }
    CloseHandle(snap);
    CloseHandle(proc);
    if (!queued) return fail("no thread took the APC");
    printf("INJECTOR apc done (queued to %d threads)\n", queued);
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
    if (wcscmp(argv[1], L"apc") == 0) return apc(pid, argv[3]);
    printf("INJECTOR unknown technique\n");
    return 2;
}
