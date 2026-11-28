/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * The library the injection scenarios place into the test game process (tests/e2e). It does
 * nothing but say where it ended up: one line on the process's stdout, which the harness reads.
 *
 * It has no import table at all — not even kernel32: the two calls it needs (GetStdHandle /
 * WriteFile) are found by walking the PEB's module list and parsing kernel32's exports. That is
 * what lets the image run when nothing has resolved its imports the way a loader would: mapped by
 * the kernel from the file (manual mapping), or called as a plain function by a foreign thread. */

#include <windows.h>

/* strlen by hand: the file has no imports at all, not even the CRT's. */
static unsigned long len_of(const char *s) {
    unsigned long n = 0;
    while (s[n]) ++n;
    return n;
}

/* ---- kernel32 by hand: no imports ------------------------------------------------------------- */

typedef struct Unic {
    USHORT Length;
    USHORT Max;
    const wchar_t *Buffer;
} Unic;

typedef struct LdrEntry {
    LIST_ENTRY InLoadOrder, InMemoryOrder, InInitOrder;
    ULONG_PTR DllBase;
    ULONG_PTR EntryPoint;
    ULONG SizeOfImage;
    Unic FullDllName, BaseDllName;
} LdrEntry;

typedef struct PebLdrData {
    ULONG Length;
    ULONG Initialized;
    ULONG_PTR SsHandle;
    LIST_ENTRY InLoadOrder, InMemoryOrder, InInitOrder;
} PebLdrData;

static int lower(wchar_t c) { return (c >= L'A' && c <= L'Z') ? c + 32 : c; }

static int name_is(const Unic *u, const char *want) {
    if (u->Length / sizeof(wchar_t) != 12) return 0;
    for (int i = 0; i < 12; ++i)
        if (lower(u->Buffer[i]) != want[i]) return 0;
    return 1;
}

/* kernel32.dll's base, from the loader's in-memory list (this process here). */
static BYTE *kernel32_base(void) {
#if defined(_M_X64) || defined(__x86_64__)
    const BYTE *teb = (const BYTE *)__readgsqword(0x30);
#elif defined(_M_IX86) || defined(__i386__)
    const BYTE *teb = (const BYTE *)__readfsdword(0x18);
#elif defined(_M_ARM64) || defined(__aarch64__)
    const BYTE *teb = (const BYTE *)__getReg(18);
#endif
    const BYTE *peb = *(const BYTE *const *)(teb + 0x60);
    const PebLdrData *ldr = *(const PebLdrData *const *)(peb + 0x18);
    for (const LIST_ENTRY *e = ldr->InMemoryOrder.Flink; e != &ldr->InMemoryOrder; e = e->Flink) {
        /* InMemoryOrderLinks is the second field of the entry: back off two pointers to its start. */
        const LdrEntry *m = (const LdrEntry *)((const BYTE *)e - 2 * sizeof(void *));
        if (name_is(&m->BaseDllName, "kernel32.dll")) return (BYTE *)m->DllBase;
    }
    return 0;
}

static void *proc_address(BYTE *base, const char *want) {
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!d.Size) return 0;
    const IMAGE_EXPORT_DIRECTORY *ex = (const IMAGE_EXPORT_DIRECTORY *)(base + d.VirtualAddress);
    const DWORD *names = (const DWORD *)(base + ex->AddressOfNames);
    const WORD *ords = (const WORD *)(base + ex->AddressOfNameOrdinals);
    const DWORD *fns = (const DWORD *)(base + ex->AddressOfFunctions);
    const CHAR *n = (const CHAR *)base + ex->Name;
    (void)n;
    for (DWORD i = 0; i < ex->NumberOfNames; ++i) {
        const char *got = (const char *)base + names[i];
        const char *a = got, *b = want;
        while (*a && *a == *b) {
            ++a;
            ++b;
        }
        if (*a || *b) continue;
        return (void *)(base + fns[ords[i]]);
    }
    return 0;
}

/* ---- the line --------------------------------------------------------------------------------- */

static void marker_log(const char *text);

static void say(const char *how) {
    char line[128];
    const char *head = "ATTACK injected ";
    int n = 0;
    for (const char *p = head; *p && n < 100; ++p) line[n++] = *p;
    for (const char *p = how; *p && n < 120; ++p) line[n++] = *p;
    line[n++] = '\n';
    BYTE *k32 = kernel32_base();
    if (!k32) {
        marker_log("marker: no kernel32\n");
        return;
    }
    typedef HANDLE(WINAPI * GetStdHandleFn)(DWORD);
    typedef BOOL(WINAPI * WriteFileFn)(HANDLE, const void *, DWORD, DWORD *, void *);
    GetStdHandleFn get_out = (GetStdHandleFn)proc_address(k32, "GetStdHandle");
    WriteFileFn write_file = (WriteFileFn)proc_address(k32, "WriteFile");
    if (!get_out || !write_file) {
        marker_log("marker: no kernel32 exports\n");
        return;
    }
    DWORD done = 0;
    const HANDLE out = get_out(STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE) {
        marker_log("marker: no stdout\n");
        return;
    }
    if (!write_file(out, line, (DWORD)n, &done, NULL)) marker_log("marker: write failed\n");
}

/* A debug channel that needs nothing resolved: a line into the injector's log file (a named pipe
 * or a plain file), written with the kernel32 found by hand. Used when the ordinary stdout says
 * nothing. */
static void marker_log(const char *text) {
    BYTE *k32 = kernel32_base();
    if (!k32) return;
    typedef HANDLE(WINAPI * CreateFileAFn)(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
    typedef BOOL(WINAPI * WriteFileFn)(HANDLE, const void *, DWORD, DWORD *, void *);
    CreateFileAFn open = (CreateFileAFn)proc_address(k32, "CreateFileA");
    WriteFileFn write_file = (WriteFileFn)proc_address(k32, "WriteFile");
    if (!open || !write_file) return;
    const HANDLE f = open("C:\\Users\\Public\\mebet-marker.log", 4 /* GENERIC_WRITE */, 3, NULL,
                          4 /* OPEN_ALWAYS */, 0x80, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD done = 0;
    write_file(f, text, (DWORD)len_of(text), &done, NULL);
    typedef BOOL(WINAPI * CloseFn)(HANDLE);
    CloseFn close = (CloseFn)proc_address(k32, "CloseHandle");
    if (close) close(f);
}

/* Exported as well: a hand-placed image runs no DllMain, and the scenario that starts the export on
 * its own thread can call the very same entry (with DLL_PROCESS_ATTACH) instead. */
__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    (void)self;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) say("library loaded");
    return TRUE;
}

/* A plain thread entry (one argument, so it is called correctly however the image was placed).
 * The scenario that maps this image without the loader starts a thread here: DllMain does not run
 * for a hand-placed image, and calling it as a thread entry would pass the wrong "reason". */
__declspec(dllexport) DWORD WINAPI MebetMarkerThread(LPVOID arg) {
    (void)arg;
    marker_log("entered MebetMarkerThread\n");
    say("manually-mapped image");
    marker_log("said it\n");
    return 0;
}

/* The same one-pointer thread entry, but through DllMain's own path (a hand-placed image runs none). */
__declspec(dllexport) DWORD WINAPI MebetMarkerAttach(LPVOID base) {
    DllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    return 0;
}
