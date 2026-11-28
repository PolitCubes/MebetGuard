/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * Test fixture for tests/e2e: brings mebet_inject_marker.dll into the harness's own test game
 * process by one technique at a time, so each scenario can show it works without the guard and
 * is caught with it. Built for the test Java's architecture by the harness, run by its probes.
 *
 *   mebet_injector remote-thread <pid> <dll>   VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW)
 *   mebet_injector hijack <pid> <dll>          a sleeping thread's context redirected to LoadLibraryExW
 *   mebet_injector apc <pid> <dll>             QueueUserAPC(LoadLibraryExW) to the first thread (classic APC)
 *   mebet_injector apc-all <pid> <dll>         the same, to every thread
 *   mebet_injector apc-special <pid> <dll>     NtQueueApcThreadEx(SEM_SPECIAL_USER_APC) — runs at any wait
 *   mebet_injector apc-special-all <pid> <dll> the same, to every thread
 *   mebet_injector exec-thread <pid> <unused>  a page of code + CreateRemoteThread on it
 *   mebet_injector manual-map <pid> <dll>      the image mapped from the file by the kernel, no loader
 *   mebet_injector manual-run <pid> <dll>      loaded by the kernel, then its export started off-loader
 *
 * One command per technique. Prints one "INJECTOR ..." line and exits 0 when the technique was
 * carried out. */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* The section calls, by hand: no nt headers and no ntdll in the import table. */
typedef LONG(NTAPI *NtCreateSectionFn)(HANDLE *, ACCESS_MASK, void *, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef LONG(NTAPI *NtMapViewOfSectionFn)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG,
                                          ULONG, ULONG);
typedef LONG(NTAPI *NtUnmapViewOfSectionFn)(HANDLE, PVOID);
typedef LONG(NTAPI *NtQueueApcThreadExFn)(HANDLE, HANDLE, void *, void *, void *, void *);
typedef LONG(NTAPI *NtSetContextThreadFn)(HANDLE, void *);
typedef LONG(NTAPI *NtGetContextThreadFn)(HANDLE, void *);

static DWORD module_base(HANDLE proc, const wchar_t *dll);

/* Thread ids of a process into out (up to cap), the count into *n. False when there are none. */
static int all_tids(HANDLE snap, DWORD pid, DWORD *out, size_t *n, size_t cap) {
    *n = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = {sizeof(te)};
    for (BOOL ok = Thread32First(snap, &te); ok && *n < cap; ok = Thread32Next(snap, &te))
        if (te.th32OwnerProcessID == pid) out[(*n)++] = te.th32ThreadID;
    return *n > 0;
}

/* Logging: everything is a one-line message under one lock. MSVC's printf with an unbuffered stdout
 * is not safe to call from several threads at once (it crashed while a thread of the target was being
 * traced), and the injector does log from two places. */
static CRITICAL_SECTION g_log;
static void log_line(const char *text) {
    EnterCriticalSection(&g_log);
    fputs(text, stdout);
    fflush(stdout);
    LeaveCriticalSection(&g_log);
}

static int fail(const char *what) {
    printf("INJECTOR failed: %s (error %lu)\n", what, GetLastError());
    return 1;
}

/* The DLL's path written into the target (shared by the techniques that call a loader there). */
static void *write_path(HANDLE proc, const wchar_t *dll) {
    const SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    void *remote = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote && !WriteProcessMemory(proc, remote, dll, bytes, NULL)) return NULL;
    return remote;
}

/* ---- 1. VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW) ----------------- */

static int remote_thread(DWORD pid, const wchar_t *dll) {
    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    void *remote = write_path(proc, dll);
    if (!remote) return fail("write the path");
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

/* ---- 2. thread hijack: a sleeping thread's context redirected ---------------------------------- */

/* Which threads of the target sleep in the kernel. NtDelayExecution is reached through
 * NtWaitForSingleObject in the same ntdll image; the code between NtDelayExecution and the next
 * export is its delay routine, and a thread standing there is in a timed sleep: it comes back to user
 * mode on its own and takes the changed context. A thread parked for ever (a JVM thread on an event)
 * never comes back and is only a fallback. */
typedef struct ThreadState {
    DWORD tid;
    ULONG_PTR rip;
    int moved; /* the pointer moved between two looks: it really came out of the wait */
} ThreadState;

static int sleepers(HANDLE proc, DWORD pid, ThreadState **out) {
    HMODULE mods[1024];
    DWORD needed = 0;
    ULONG_PTR target_ntdll = 0;
    if (EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, 3)) {
        WCHAR name[64];
        for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i)
            if (GetModuleBaseNameW(proc, mods[i], name, 64) && _wcsicmp(name, L"ntdll.dll") == 0) {
                target_ntdll = (ULONG_PTR)mods[i];
                break;
            }
    }
    if (!target_ntdll) return 0;
    size_t n = 0;
    ThreadState *list = malloc(sizeof(*list));
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    /* Threads that are openable (rights checked by OpenThread), one look each; the second round only
     * notes whether the instruction pointer moved (a timed wait ends and goes round again, a park
     * does not). Nothing is filtered out here: the passes of hijack() take what stands in user mode. */
    for (int round = 0; round < 2; ++round) {
        THREADENTRY32 te = {sizeof(te)};
        for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!t) continue;
            CONTEXT c;
            memset(&c, 0, sizeof(c));
            c.ContextFlags = CONTEXT_CONTROL;
            ULONG_PTR rip = 0;
            if (GetThreadContext(t, &c)) {
#if defined(_M_X64) || defined(__x86_64__)
                rip = (ULONG_PTR)c.Rip;
#elif defined(_M_IX86) || defined(__i386__)
                rip = (ULONG_PTR)c.Eip;
#else
                rip = (ULONG_PTR)c.Pc;
#endif
            }
            CloseHandle(t);
            if (round == 0) {
                list = realloc(list, (n + 1) * sizeof(*list));
                list[n].tid = te.th32ThreadID;
                list[n].rip = rip;
                list[n].moved = 0;
                n++;
            } else {
                for (size_t i = 0; i < n; ++i)
                    if (list[i].tid == te.th32ThreadID) list[i].moved = rip != list[i].rip;
            }
        }
        if (round == 0) Sleep(120);
    }
    const ULONG_PTR ntdll_hi = target_ntdll + 0x200000;
    (void)ntdll_hi;
    CloseHandle(snap);
    /* Threads that moved go first: they come back from a wait by themselves. */
    size_t w = 0;
    for (size_t i = 0; i < n; ++i)
        if (list[i].moved) {
            const ThreadState tmp = list[w];
            list[w++] = list[i];
            list[i] = tmp;
        }
    printf("INJECTOR hijack: %d thread(s), %d of them moving\n", (int)n, (int)w);
    *out = list;
    return (int)n;
}

/* The stub: it announces the end of the loader call by taking one off the done flag, then spins —
 * there the injector stops the thread and puts the found register file back. */
static void stub_bytes(BYTE *s, size_t *n, ULONG_PTR flag) {
#if defined(_M_X64) || defined(__x86_64__)
    if (getenv("MEBET_SPIN_ONLY")) {
        s[(*n)++] = 0xEB;
        s[(*n)++] = 0xFE;
        return;
    }
    s[(*n)++] = 0x48; /* mov rdx, flag */
    s[(*n)++] = 0xBA;
    const ULONG_PTR f = flag;
    memcpy(s + *n, &f, 8);
    *n += 8;
    s[(*n)++] = 0xF0; /* lock dec dword [rdx] */
    s[(*n)++] = 0xFF;
    s[(*n)++] = 0x0A;
    s[(*n)++] = 0xEB; /* jmp $ */
    s[(*n)++] = 0xFE;
#elif defined(_M_IX86) || defined(__i386__)
    s[(*n)++] = 0xBA; /* mov edx, flag */
    const DWORD f = (DWORD)flag;
    memcpy(s + *n, &f, 4);
    *n += 4;
    s[(*n)++] = 0xF0;
    s[(*n)++] = 0xFF;
    s[(*n)++] = 0x0A;
    s[(*n)++] = 0xEB;
    s[(*n)++] = 0xFE;
#elif defined(_M_ARM64) || defined(__aarch64__)
    /* ldr w2, [x1]; subs w2, w2, #1; str w2, [x1]; b .  — x1 is set by the context */
    const unsigned insns[] = {0xB9400022u, 0x71000442u, 0xB9000022u, 0x14000000u};
    memcpy(s + *n, insns, sizeof(insns));
    *n += sizeof(insns);
#else
#error "unknown architecture"
#endif
}

#define CTX_FLAGS (CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
#define STUB_LEN 0x80
#define FRAME_LEN 0x20

/* Build the context the thread will run with: the loader, its arguments, a frame it returns from
 * into the stub. The stack is the section's own (several free pages under the entry point), and the
 * return address the stub is placed at [rsp], where the callee's `ret` reads it. Each architecture's
 * own calling convention. */
static void shape_context(CONTEXT *c, BYTE *frame, ULONG_PTR remote_frame, ULONG_PTR remote_stack, ULONG_PTR remote_stub, ULONG_PTR stub, void *path, ULONG_PTR flag) {
    (void)flag;
    (void)frame;
    c->ContextFlags = CTX_FLAGS;
#if defined(_M_X64) || defined(__x86_64__)
    c->Rip = (DWORD64)(ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    c->Rcx = (DWORD64)(ULONG_PTR)path;
    c->Rdx = 0;
    c->R8 = 0;
    c->Rsp = (DWORD64)((ULONG_PTR)remote_stack);
    /* The return slot is in the target's view and holds the target's stub address. */
    *(ULONG_PTR *)((BYTE *)frame + ((ULONG_PTR)remote_stack - (ULONG_PTR)remote_frame)) = remote_stub;
#elif defined(_M_IX86) || defined(__i386__)
    c->Eip = (DWORD)(ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    ((DWORD *)frame)[0] = (DWORD)stub; /* the return address: where `ret 0x0C` lands */
    ((DWORD *)frame)[1] = (DWORD)(ULONG_PTR)path;
    ((DWORD *)frame)[2] = 0;
    ((DWORD *)frame)[3] = 0;
    c->Esp = (DWORD)remote_frame + 4; /* the arguments, as the callee reads them */
    (void)remote_stack;
    (void)remote_stub;
#else
    c->Pc = (DWORD64)(ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    c->X0 = (DWORD64)(ULONG_PTR)path;
    c->X1 = (DWORD64)flag; /* what the stub decrements */
    c->X2 = 0;
    c->Lr = (DWORD64)stub;
    c->Sp = (DWORD64)remote_frame;
    (void)remote_stack;
    (void)remote_stub;
#endif
}

/* The section with the stub, the frame, the path and the flag, mapped into this process and the
 * target: every value the target needs is known before a byte is written there. */
typedef struct HijackCtx {
    HANDLE proc, section;
    BYTE *own, *remote, *remote_stack;
    SIZE_T frame_off, path_off, flag_off, stack_size;
} HijackCtx;

static int hijack_setup(HijackCtx *h, HANDLE proc, const wchar_t *dll) {
    const SIZE_T path_bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    h->frame_off = STUB_LEN;
    h->path_off = h->frame_off + FRAME_LEN;
    h->flag_off = h->path_off + path_bytes;
    const SIZE_T pages = (h->flag_off + 16 + 0xFFF) & ~(SIZE_T)0xFFF;
    /* The stack for the call goes at the end of the section: the call itself may push below it, so
     * several pages are kept free under the entry point. */
    h->stack_size = 0x4000;
    const SIZE_T total = pages + h->stack_size;
    NtCreateSectionFn create =
        (NtCreateSectionFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection");
    NtMapViewOfSectionFn map =
        (NtMapViewOfSectionFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection");
    if (!create || !map) return fail("ntdll section calls missing");
    LARGE_INTEGER size = {.QuadPart = (LONGLONG)total};
    if (create(&h->section, SECTION_ALL_ACCESS, NULL, &size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL))
        return fail("NtCreateSection");
    SIZE_T view = 0;
    if (map(h->section, GetCurrentProcess(), (PVOID *)&h->own, 0, 0, NULL, &view, 2, 0, PAGE_EXECUTE_READWRITE) ||
        map(h->section, proc, (PVOID *)&h->remote, 0, 0, NULL, &view, 2, 0, PAGE_EXECUTE_READWRITE))
        return fail("NtMapViewOfSection");
    size_t sn = 0;
    stub_bytes(h->own, &sn, (ULONG_PTR)(h->remote + h->flag_off));
    memcpy(h->own + h->path_off, dll, path_bytes);
    /* The entry stack: the end of the last page, 16-aligned. */
    h->remote_stack = h->remote + total - 0x0F0;
    h->proc = proc;
    return 0;
}

static void hijack_teardown(HijackCtx *h) {
    NtUnmapViewOfSectionFn unmap =
        (NtUnmapViewOfSectionFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection");
    if (unmap) {
        if (h->remote) unmap(h->proc, h->remote);
        if (h->own) unmap(GetCurrentProcess(), h->own);
    }
    if (h->section) CloseHandle(h->section);
}

/* Run the loader on one thread and put it back: true when the call came back through the stub. */
static int try_thread(HijackCtx *h, DWORD tid, int moved, int strict) {
    HANDLE t = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!t) return 0;
    volatile LONG *flag = (volatile LONG *)(h->own + h->flag_off);
    InterlockedExchange(flag, 1);
    CONTEXT found;
    memset(&found, 0, sizeof(found));
    found.ContextFlags = CTX_FLAGS;
    if (SuspendThread(t) == (DWORD)-1 || !GetThreadContext(t, &found)) {
        CloseHandle(t);
        return 0;
    }
#if defined(_M_X64) || defined(__x86_64__)
    const ULONG_PTR caught = (ULONG_PTR)found.Rip;
#elif defined(_M_IX86) || defined(__i386__)
    const ULONG_PTR caught = (ULONG_PTR)found.Eip;
#else
    const ULONG_PTR caught = (ULONG_PTR)found.Pc;
#endif
    /* A context written to a thread standing in a syscall is thrown away when the syscall returns:
     * the change only sticks for a thread caught in user mode. Checked for every attempt now; the
     * passes of hijack() take a thread as soon as one is out of the kernel. */
    ULONG_PTR ntdll_lo = 0;
    if (h->proc) {
        HMODULE mods[1024];
        DWORD needed = 0;
        if (EnumProcessModulesEx(h->proc, mods, sizeof(mods), &needed, 3)) {
            WCHAR name[64];
            for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i)
                if (GetModuleBaseNameW(h->proc, mods[i], name, 64) && _wcsicmp(name, L"ntdll.dll") == 0) {
                    ntdll_lo = (ULONG_PTR)mods[i];
                    break;
                }
        }
    }
    (void)strict;
    if (ntdll_lo && caught >= ntdll_lo && caught < ntdll_lo + 0x200000) {
        ResumeThread(t);
        CloseHandle(t);
        return 0;
    }
    CONTEXT start = found;
    /* The stub sits at the start of the section, the stack at its end, the frame right after the stub:
     * the loader returns into the stub, which publishes and spins. */
    shape_context(&start, h->own + h->frame_off, (ULONG_PTR)(h->remote + h->frame_off),
                  (ULONG_PTR)h->remote_stack, (ULONG_PTR)h->remote, (ULONG_PTR)h->remote, h->own + h->path_off,
                  (ULONG_PTR)(h->remote + h->flag_off));
    if (getenv("MEBET_SAMPLE")) {
        FILETIME c, e, k, u;
        GetThreadTimes(t, &c, &e, &k, &u);
        printf("INJECTOR sample: k=%lu u=%lu\n", k.dwLowDateTime, u.dwLowDateTime);
    }
    const CONTEXT after = found;
    /* The stack goes in our section (under several free pages): a thread's own stack top is close to
     * a guard page, and the loader deep down needs far more than those few bytes. */
#if defined(_M_X64) || defined(__x86_64__)
    start.Rsp = (DWORD64)(ULONG_PTR)h->remote_stack;
    start.Rip = (DWORD64)(ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    start.Rcx = (DWORD64)(ULONG_PTR)(h->own + h->path_off);
    start.Rdx = 0;
    start.R8 = 0;
    *(ULONG_PTR *)(h->own + (h->remote_stack - h->remote)) = (ULONG_PTR)h->remote; /* [rsp]: the stub */
#elif defined(_M_IX86) || defined(__i386__)
    start.Esp = (DWORD)(ULONG_PTR)h->remote_stack;
    start.Eip = (DWORD)(ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    *(DWORD *)(h->own + (h->remote_stack - h->remote)) = (DWORD)(ULONG_PTR)h->remote; /* [esp]: the stub */
#else
    start.Sp = (DWORD64)(ULONG_PTR)h->remote_stack;
    start.Pc = (DWORD64)(ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    start.X0 = (DWORD64)(ULONG_PTR)(h->own + h->path_off);
    start.Lr = (DWORD64)(ULONG_PTR)h->remote; /* the return goes to the stub */
#endif
    NtSetContextThreadFn nt_set = (NtSetContextThreadFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                                               "NtSetContextThread");
    const BOOL set_ok = nt_set ? nt_set(t, &start) == 0 : SetThreadContext(t, &start);
    if (getenv("MEBET_TRACE")) {
        printf("INJECTOR try tid %lu caught %p set %d\n", (unsigned long)tid, (void *)(ULONG_PTR)caught, (int)set_ok);
        fflush(stdout);
    }    if (!set_ok || ResumeThread(t) == (DWORD)-1) {
        ResumeThread(t);
        CloseHandle(t);
        return 0;
    }
    /* Wait for the stub, then stop the thread in its spin there and put the found register file back.
     * A thread may carry extra suspensions of its own (the JVM parks threads that way). */
    const DWORD end = GetTickCount() + (moved ? 2000 : 4000);
    while (*flag && GetTickCount() < end) Sleep(5);
    SuspendThread(t);
    CONTEXT back = after;
#if defined(_M_X64) || defined(__x86_64__)
    back.Rsp = start.Rsp;
#elif defined(_M_IX86) || defined(__i386__)
    back.Esp = start.Esp;
#else
    back.Sp = start.Sp;
#endif
    SetThreadContext(t, &back);
    ResumeThread(t);
    CloseHandle(t);
    if (getenv("MEBET_TRACE")) {
        printf("INJECTOR try tid %lu flag %ld\n", (unsigned long)tid, (long)*flag);
        fflush(stdout);
    }
    return *flag == 0;
}

/* The same, on one named thread: the game prints its own sleeping main thread, so the caller can
 * hand it in and nothing has to be guessed. */
static int hijack_one(DWORD pid, const wchar_t *dll, DWORD tid) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                  PROCESS_VM_READ | PROCESS_SUSPEND_RESUME,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    HijackCtx h;
    memset(&h, 0, sizeof(h));
    const int setup = hijack_setup(&h, proc, dll);
    CloseHandle(proc);
    if (setup) return 1;
    const int ok = try_thread(&h, tid, 1, 1);
    hijack_teardown(&h);
    if (!ok) return fail("the thread did not take the call");
    printf("INJECTOR hijack done (thread %lu moved to LoadLibraryExW and put back)\n", (unsigned long)tid);
    return 0;
}

static int hijack(DWORD pid, const wchar_t *dll) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                  PROCESS_VM_READ | PROCESS_SUSPEND_RESUME,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    ThreadState *list = NULL;
    const int n = sleepers(proc, pid, &list);
    if (n <= 0) {
        free(list);
        CloseHandle(proc);
        return fail("no thread waiting in the kernel");
    }
    HijackCtx h;
    memset(&h, 0, sizeof(h));
    if (hijack_setup(&h, proc, dll)) {
        free(list);
        CloseHandle(proc);
        return 1;
    }
    printf("INJECTOR hijack: %d candidate thread(s)\n", n);
    int rc = 1;
    DWORD done = 0;
    /* A context only sticks on a thread caught in user mode, and the threads are in the kernel most
     * of the time. Several passes: the JDK's own safepoint polls bring a thread out into user code
     * every so often, and that moment is taken. Between passes the thread is suspended and resumed
     * once more, which also lets the JVM move on. */
    for (int pass = 0; pass < 60 && rc; ++pass) {
        for (int i = 0; i < n && rc; ++i)
            if (try_thread(&h, list[i].tid, 0, 0)) {
                rc = 0;
                done = list[i].tid;
            }
        if (rc) Sleep(10);
    }
    hijack_teardown(&h);
    printf("INJECTOR hijack: teardown ok\n");
    fflush(stdout);
    free(list);
    if (rc) {
        CloseHandle(proc);
        return fail("no thread of the game took the call");
    }
    /* The stub said the call came back — but the stub runs before the loader's own work: only the
     * library in the module list means the loader really got in. */
    int loaded = 0;
    for (int i = 0; i < 500 && !loaded; ++i) {
        loaded = module_base(proc, dll) != 0;
        if (!loaded) Sleep(10);
    }
    CloseHandle(proc);
    printf("INJECTOR hijack done (thread %lu moved to LoadLibraryExW and put back%s)\n", (unsigned long)done,
           loaded ? "" : ", library not in the list");
    return 0;
}

/* ---- 3. APC: QueueUserAPC and the special user APC --------------------------------------------- */

/* LoadLibraryExW(path, NULL, 0) queued as an APC, by one of two mechanisms:
 *
 *   normal    QueueUserAPC. It runs when the thread next enters an alertable wait (SleepEx,
 *             WaitForSingleObjectEx, ...) — the classic APC injection, seen by an exported function
 *             the guard could hook (and does).
 *   special   NtQueueApcThreadEx with SEM_SPECIAL_USER_APC: the kernel queues a user-mode APC when
 *             the thread waits at all, alertable or not (Windows 10 1809+), and no exported function
 *             is between — only the thread it lands in says so.
 *
 * "one" targets the first thread that takes it, "all" queues to every thread. LoadLibraryExW takes
 * three arguments — what an APC routine receives — so the call is balanced on 32-bit x86 too. */
/* Set the context of one thread straight at the alertable `SleepEx(1, TRUE)` and resume it from a
 * suspend: the thread wakes into the alertable check and runs its APC there. */
static void kick_alertable(HANDLE proc, DWORD tid) {
    (void)proc;
    HANDLE t = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!t) return;
    CONTEXT c;
    memset(&c, 0, sizeof(c));
    c.ContextFlags = CTX_FLAGS;
    if (SuspendThread(t) != (DWORD)-1 && GetThreadContext(t, &c)) {
        CONTEXT s = c;
        const ULONG_PTR entry = (ULONG_PTR)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SleepEx");
#if defined(_M_X64) || defined(__x86_64__)
        s.Rip = entry;
        s.Rcx = 1; /* ms */
        s.Rdx = 1; /* TRUE, alertable */
        s.Rsp = (c.Rsp & ~(DWORD64)0xF) - 0x30; /* room under the original stack, 16-aligned */
        *(ULONG_PTR *)(ULONG_PTR)s.Rsp = (ULONG_PTR)c.Rip; /* return to where it was */
#elif defined(_M_IX86) || defined(__i386__)
        s.Eip = (DWORD)entry;
        s.Esp = (c.Esp & ~(DWORD)3) - 0x10;
        ((DWORD *)(ULONG_PTR)s.Esp)[0] = 1;
        ((DWORD *)(ULONG_PTR)s.Esp)[1] = 1;
        ((DWORD *)(ULONG_PTR)s.Esp)[2] = 0;
        ((DWORD *)(ULONG_PTR)s.Esp)[3] = (DWORD)c.Eip;
        s.Esp += 4;
#else
        s.Pc = entry;
        s.X0 = 1;
        s.X1 = 1;
        s.Lr = c.Pc;
        s.Sp = c.Sp & ~(DWORD64)0xF;
#endif
        SetThreadContext(t, &s);
    }
    ResumeThread(t);
    CloseHandle(t);
}

static int apc(DWORD pid, const wchar_t *dll, int special, int all) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                  PROCESS_SUSPEND_RESUME,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    void *remote = write_path(proc, dll);
    if (!remote) return fail("write the path");
    NtQueueApcThreadExFn special_queue = special
        ? (NtQueueApcThreadExFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThreadEx")
        : NULL;
    if (special && !special_queue) return fail("NtQueueApcThreadEx missing");
    void *load = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryExW");
    /* Both kinds queue the loader itself, on a fresh thread snapshot, one thread at a time. */
    void *entry = load;
    const ULONG_PTR arg = (ULONG_PTR)remote;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = {sizeof(te)};
    int queued = 0;
    LONG last = 0;
    for (BOOL ok = Thread32First(snap, &te); ok && (all || !queued); ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE t = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
        if (!t) continue;
        const LONG st = special
            ? special_queue(t, (HANDLE)1 /* QUEUE_USER_APC_SPECIAL_USER_APC */, entry, remote, NULL, NULL)
            : QueueUserAPC((PAPCFUNC)entry, t, arg);
        /* NtQueueApcThreadEx answers an NTSTATUS (0 is success), QueueUserAPC a BOOL (0 is failure). */
        if (special ? st == 0 : st != 0) queued++;
        else last = st;
        CloseHandle(t);
    }
    CloseHandle(snap);
    CloseHandle(proc);
    if (!queued) {
        printf("INJECTOR failed: no thread took the APC (status 0x%lx)\n", (unsigned long)(last & 0xFFFFFFFFu));
        return 1;
    }
    /* A normal APC runs only in an alertable wait, which a JVM thread may not enter at all: the
     * threads are woken here by resuming them (a spurious resume is harmless and takes one off the
     * count), and the library is waited for — the queue alone proves nothing. A special APC needs no
     * such wait, but the wait is harmless there too. */
    int loaded = 0;
    {
        HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, pid);
        for (int round = 0; p && !special && round < 3 && !loaded; ++round) {
            size_t n = 0;
            DWORD *tids = malloc(sizeof(DWORD) * 256);
            HANDLE wsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (all_tids(wsnap, pid, tids, &n, 256))
                for (size_t i = 0; i < n && !loaded; ++i) {
                    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tids[i]);
                    if (!t) continue;
                    const DWORD count = SuspendThread(t);
                    if (count != (DWORD)-1) ResumeThread(t);
                    CloseHandle(t);
                    loaded = module_base(p, dll) != 0;
                }
            if (wsnap) CloseHandle(wsnap);
            free(tids);
            for (int i = 0; p && i < 600 && !loaded; ++i) {
                Sleep(10);
                loaded = module_base(p, dll) != 0;
            }
        }
        if (p) CloseHandle(p);
    }
    printf("INJECTOR %s done (queued to %d thread%s, %s)\n",
           special ? (all ? "apc-special-all" : "apc-special") : (all ? "apc-all" : "apc"), queued,
           queued == 1 ? "" : "s", loaded ? "library in the game" : "library not seen in the game");
    return 0;
}

/* ---- 4. a code page and a thread on it --------------------------------------------------------- */

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

/* ---- the export of the library that takes one pointer, read out of the file -------------------- */

static int rva_to_off(const IMAGE_NT_HEADERS *nt, DWORD size, DWORD rva, DWORD span, DWORD *out) {
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD k = 0; k < nt->FileHeader.NumberOfSections; ++k, ++sec) {
        if (rva < sec->VirtualAddress || rva - sec->VirtualAddress + span > sec->SizeOfRawData) continue;
        const DWORD off = rva - sec->VirtualAddress + sec->PointerToRawData;
        if (off + span > size) return 0;
        *out = off;
        return 1;
    }
    return 0;
}

/* The export's RVA: the same number in the file's tables and in a view the kernel maps from them. */
static int export_offset(const BYTE *img, DWORD size, const char *want, DWORD *out) {
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)img;
    if (size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) return 0;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const IMAGE_DATA_DIRECTORY d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    DWORD ex_off = 0;
    if (!d.Size || !rva_to_off(nt, size, d.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), &ex_off)) return 0;
    const IMAGE_EXPORT_DIRECTORY *ex = (const IMAGE_EXPORT_DIRECTORY *)(img + ex_off);
    DWORD names_off = 0, ords_off = 0, fns_off = 0;
    if (!rva_to_off(nt, size, ex->AddressOfNames, ex->NumberOfNames * sizeof(DWORD), &names_off) ||
        !rva_to_off(nt, size, ex->AddressOfNameOrdinals, ex->NumberOfNames * sizeof(WORD), &ords_off) ||
        !rva_to_off(nt, size, ex->AddressOfFunctions, ex->NumberOfFunctions * sizeof(DWORD), &fns_off))
        return 0;
    const DWORD *names = (const DWORD *)(img + names_off);
    const WORD *ords = (const WORD *)(img + ords_off);
    const DWORD *fns = (const DWORD *)(img + fns_off);
    for (DWORD i = 0; i < ex->NumberOfNames; ++i) {
        DWORD name_off = 0;
        if (ords[i] >= ex->NumberOfFunctions) continue;
        if (!rva_to_off(nt, size, names[i], 1, &name_off)) continue;
        DWORD end = name_off;
        while (end < size && img[end]) ++end;
        if (end >= size || strcmp((const char *)img + name_off, want) != 0) continue;
        *out = fns[ords[i]];
        return 1;
    }
    return 0;
}

static BYTE *read_image(const wchar_t *dll, DWORD *size) {
    const HANDLE f = CreateFileW(dll, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    *size = GetFileSize(f, NULL);
    BYTE *img = *size && *size < (128u << 20) ? malloc(*size) : NULL;
    SIZE_T read = 0;
    const BOOL ok = img && ReadFile(f, img, *size, &read, NULL) && read == *size;
    CloseHandle(f);
    if (!ok) {
        free(img);
        return NULL;
    }
    return img;
}

static DWORD module_base(HANDLE proc, const wchar_t *dll) {
    HMODULE mods[2048];
    DWORD needed = 0;
    const wchar_t *name = wcsrchr(dll, L'\\') ? wcsrchr(dll, L'\\') + 1 : dll;
    if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, 3)) return 0;
    WCHAR got[64];
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i)
        if (GetModuleBaseNameW(proc, mods[i], got, 64) && _wcsicmp(got, name) == 0) return (DWORD)(ULONG_PTR)mods[i];
    return 0;
}

/* ---- 5. load, then start the library's export off any loader ----------------------------------- */

static int load_and_run(DWORD pid, const wchar_t *dll) {
    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE | PROCESS_VM_READ,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    void *remote = write_path(proc, dll);
    if (!remote) return fail("write the path");
    void *load = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE t = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)load, remote, 0, NULL);
    if (!t) return fail("CreateRemoteThread(load)");
    WaitForSingleObject(t, 10000);
    CloseHandle(t);
    DWORD size = 0, off = 0;
    BYTE *img = read_image(dll, &size);
    const int exported = img && export_offset(img, size, "MebetMarkerAttach", &off);
    free(img);
    if (!exported) {
        CloseHandle(proc);
        return fail("no MebetMarkerAttach export");
    }
    const DWORD base = module_base(proc, dll);
    if (!base) {
        CloseHandle(proc);
        return fail("the library did not load");
    }
    t = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)((ULONG_PTR)base + off), (void *)(ULONG_PTR)base, 0,
                           NULL);
    if (!t) {
        CloseHandle(proc);
        return fail("CreateRemoteThread(MebetMarkerAttach)");
    }
    WaitForSingleObject(t, 10000);
    DWORD tc = 0;
    GetExitCodeThread(t, &tc);
    CloseHandle(t);
    CloseHandle(proc);
    printf("INJECTOR manual-run done (MebetMarkerThread started from outside a loader, thread 0x%lx)\n",
           (unsigned long)tc);
    return 0;
}

/* ---- 6. the image mapped from the file by the kernel, no loader -------------------------------- */

/* Every call is made from here, on the target's handle: no code of the injector runs inside the
 * target, so nothing of its imports means anything there. The kernel maps the image from the file
 * and the marker export is called on a thread. Nothing of the loader runs: no module list entry, no
 * load notification. x64 only — an x86 image is mapped by WOW64 in another address space. */
static int manual_map(DWORD pid, const wchar_t *dll) {
#if !defined(_M_X64) && !defined(__x86_64__)
    (void)pid;
    (void)dll;
    printf("INJECTOR manual-map skipped (x64 only)\n");
    return 3;
#else
    static const ACCESS_MASK section_all = 0x000F001F; /* SECTION_ALL_ACCESS */
    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE | PROCESS_VM_READ,
                              FALSE, pid);
    if (!proc) return fail("OpenProcess");
    DWORD size = 0, off = 0;
    BYTE *img = read_image(dll, &size);
    int rc = 1;
    if (!img) {
        CloseHandle(proc);
        return fail("read the dll");
    }
    if (!export_offset(img, size, "MebetMarkerAttach", &off)) {
        fail("no MebetMarkerThread export in the dll");
        goto out;
    }
    {
        NtCreateSectionFn create =
            (NtCreateSectionFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection");
        NtMapViewOfSectionFn map =
            (NtMapViewOfSectionFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection");
        if (!create || !map) {
            fail("ntdll section calls missing");
            goto out;
        }
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)img;
        const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
        /* A reservation of the image's size makes the address space ready and is given back at once,
         * so the view lands in a hole the kernel chooses. */
        void *scratch = VirtualAllocEx(proc, NULL, nt->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
        if (scratch) VirtualFreeEx(proc, scratch, 0, MEM_RELEASE);
        const HANDLE f =
            CreateFileW(dll, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) {
            fail("open the dll");
            goto out;
        }
        HANDLE section = NULL;
        const LONG made = create(&section, section_all, NULL, NULL, PAGE_READONLY, SEC_IMAGE, f);
        CloseHandle(f);
        if (made || !section) {
            printf("INJECTOR failed: NtCreateSection(SEC_IMAGE) 0x%lx (step 1)\n",
                   (unsigned long)(made & 0xFFFFFFFFu));
            if (section) CloseHandle(section);
            goto out;
        }
        void *base = NULL;
        SIZE_T view = (SIZE_T)nt->OptionalHeader.SizeOfImage; /* exactly the image, or INVALID_VIEW_SIZE */
        const LONG mapped = map(section, proc, &base, 0, 0, NULL, &view, 2 /* ViewUnmap */, 0, PAGE_READONLY);
        CloseHandle(section);
        if (mapped || !base) {
            printf("INJECTOR failed: NtMapViewOfSection 0x%lx (step 2)\n", (unsigned long)(mapped & 0xFFFFFFFFu));
            goto out;
        }
        HANDLE t = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)((BYTE *)base + off), base, 0, NULL);
        if (!t) {
            fail("CreateRemoteThread(marker)");
            goto out;
        }
        /* The marker thread says its line and then stays: a little wait is enough for the line. */
        const DWORD waited = WaitForSingleObject(t, 5000);
        CloseHandle(t);
        (void)waited;
        printf("INJECTOR manual-map done (image mapped from the file by the kernel, no loader)\n");
        rc = 0;
    }
out:
    free(img);
    CloseHandle(proc);
    return rc;
#endif
}

int wmain(int argc, wchar_t **argv) {
    InitializeCriticalSection(&g_log);
    if (argc < 4) {
        printf("INJECTOR usage: mebet_injector <technique> <pid> <dll>\n");
        return 2;
    }
    const DWORD pid = (DWORD)wcstoul(argv[2], NULL, 10);
    if (!pid) {
        printf("INJECTOR usage: mebet_injector <technique> <pid> <dll>\n");
        return 2;
    }
    const wchar_t *dll = argv[3];
    if (wcscmp(argv[1], L"remote-thread") == 0) return remote_thread(pid, dll);
    if (wcscmp(argv[1], L"hijack") == 0) return hijack(pid, dll);
    if (wcscmp(argv[1], L"hijack-one") == 0) return hijack_one(pid, dll, (DWORD)wcstoul(argv[4], NULL, 10));
    if (wcscmp(argv[1], L"apc") == 0) return apc(pid, dll, 0, 0);
    if (wcscmp(argv[1], L"apc-all") == 0) return apc(pid, dll, 0, 1);
    if (wcscmp(argv[1], L"apc-special") == 0) return apc(pid, dll, 1, 0);
    if (wcscmp(argv[1], L"apc-special-all") == 0) return apc(pid, dll, 1, 1);
    if (wcscmp(argv[1], L"exec-thread") == 0) return exec_thread(pid);
    if (wcscmp(argv[1], L"manual-map") == 0) return manual_map(pid, dll);
    if (wcscmp(argv[1], L"manual-run") == 0) return load_and_run(pid, dll);
    printf("INJECTOR unknown technique\n");
    return 2;
}
