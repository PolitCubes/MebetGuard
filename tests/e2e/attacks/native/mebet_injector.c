/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * Test fixture for tests/e2e: brings mebet_inject_marker.dll into the harness's own test game
 * process by one technique at a time, so each scenario can show it works without the guard and
 * is caught with it. Built for the test Java's architecture by the harness, run by its probes.
 *
 *   mebet_injector remote-thread <pid> <dll>
 *   mebet_injector apc <pid> <dll>
 *   mebet_injector exec-thread <pid> <unused>
 *   mebet_injector manual-map <pid> <dll>
 *
 * Prints one "INJECTOR ..." line and exits 0 when the technique was carried out. */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

typedef LONG(NTAPI *NtCreateSectionFn)(HANDLE *, ACCESS_MASK, void *, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef LONG(NTAPI *NtMapViewOfSectionFn)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T, PLARGE_INTEGER, SIZE_T *, ULONG,
                                          ULONG, ULONG);
#define SEC_IMAGE_FLAG 0x1000000u
#define VIEW_UNMAP 2u

/* An export's RVA, read from the headers already placed at `base` in the target. */
static DWORD export_rva(HANDLE proc, BYTE *base, const char *want) {
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(proc, base, &dos, sizeof(dos), NULL)) return 0;
    if (!ReadProcessMemory(proc, base + dos.e_lfanew, &nt, sizeof(nt), NULL)) return 0;
    IMAGE_DATA_DIRECTORY d = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!d.Size) return 0;
    IMAGE_EXPORT_DIRECTORY ex;
    if (!ReadProcessMemory(proc, base + d.VirtualAddress, &ex, sizeof(ex), NULL)) return 0;
    for (DWORD i = 0; i < ex.NumberOfNames; ++i) {
        DWORD name_rva = 0;
        WORD ordinal = 0;
        DWORD fn_rva = 0;
        char name[64] = {0};
        if (!ReadProcessMemory(proc, base + ex.AddressOfNames + i * sizeof(DWORD), &name_rva, sizeof(name_rva), NULL) ||
            !ReadProcessMemory(proc, base + name_rva, name, sizeof(name) - 1, NULL))
            continue;
        if (strcmp(name, want) != 0) continue;
        if (!ReadProcessMemory(proc, base + ex.AddressOfNameOrdinals + i * sizeof(WORD), &ordinal, sizeof(ordinal), NULL) ||
            !ReadProcessMemory(proc, base + ex.AddressOfFunctions + ordinal * sizeof(DWORD), &fn_rva, sizeof(fn_rva), NULL))
            return 0;
        return fn_rva;
    }
    return 0;
}

/* A few bytes of code written into the target and a thread started on them — no library, no loader:
 * what is left of any injection once the loader is out of the picture. The code only returns a known
 * value, read back as the thread's exit code: it ran, or it was stopped before its first instruction. */
#define EXEC_THREAD_VALUE 0x4D42u
static int exec_thread(DWORD pid) {
#if defined(_M_X64) || defined(__x86_64__)
    static const unsigned char stub[] = {0xB8, 0x42, 0x4D, 0x00, 0x00, 0xC3}; /* mov eax, 0x4d42; ret */
#elif defined(_M_IX86) || defined(__i386__)
    static const unsigned char stub[] = {0xB8, 0x42, 0x4D, 0x00, 0x00, 0xC2, 0x04, 0x00}; /* ...; ret 4 */
#elif defined(_M_ARM64) || defined(__aarch64__)
    static const unsigned char stub[] = {0x40, 0xA8, 0x89, 0x52, 0xC0, 0x03, 0x5F, 0xD6}; /* movz w0, #0x4d42; ret */
#else
#error "unknown architecture"
#endif
    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    void *code = VirtualAllocEx(proc, NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!code) return fail("VirtualAllocEx");
    if (!WriteProcessMemory(proc, code, stub, sizeof(stub), NULL)) return fail("WriteProcessMemory");
    DWORD old = 0;
    if (!VirtualProtectEx(proc, code, sizeof(stub), PAGE_EXECUTE_READ, &old)) return fail("VirtualProtectEx");
    FlushInstructionCache(proc, code, sizeof(stub));
    HANDLE t = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)code, NULL, 0, NULL);
    if (!t) return fail("CreateRemoteThread");
    const DWORD waited = WaitForSingleObject(t, 10000);
    DWORD rc = 0;
    GetExitCodeThread(t, &rc);
    if (waited == WAIT_OBJECT_0 && rc == EXEC_THREAD_VALUE)
        printf("INJECTOR exec-thread done: ran\n");
    else
        printf("INJECTOR exec-thread done: stopped (%s, exit code 0x%lx)\n",
               waited == WAIT_OBJECT_0 ? "ended" : "still parked", (unsigned long)rc);
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
    if (wcscmp(argv[1], L"apc") == 0) return apc(pid, argv[3]);
    if (wcscmp(argv[1], L"exec-thread") == 0) return exec_thread(pid);
    printf("INJECTOR unknown technique\n");
    return 2;
}
