// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
//
// What a cheat mod can do from pure Java 22+ through the Foreign Function & Memory API: call
// the OS directly, with no DLL of its own, so the load gate never sees a module. Each action
// models one attack on the guard from inside the game process. MebetTarget calls run()
// reflectively, so the target itself still builds on older Java (32-bit Windows has no FFM
// linker at all: there these attacks do not exist).
//
// Progress goes out as "TARGET ..." lines; run() returns the "TARGET did ..." marker only when
// the attack fully worked, and throws when a step was refused.

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_INT_UNALIGNED;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

public final class MebetFfm {
    private static final Linker LINKER = Linker.nativeLinker();
    private static final Arena ARENA = Arena.global();
    private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase().startsWith("windows");
    private static final boolean ARM64 = "aarch64".equals(System.getProperty("os.arch"));

    private static final int MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
    private static final int PAGE_READWRITE = 0x04, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40;
    private static final int THREAD_TERMINATE = 0x0001, THREAD_SUSPEND_RESUME = 0x0002, THREAD_QUERY_INFORMATION = 0x0040;
    private static final String GUARD_DLL = "MebetGuard.dll";

    private MebetFfm() {}

    public static String run(String action) throws Throwable {
        String[] p = action.split(" ", 2);
        String arg = p.length > 1 ? p[1].trim() : "";
        switch (p[0]) {
            case "ffm-benign": return benign();
            case "ffm-load-churn": return loadChurn(arg);
            case "ffm-exec-alloc": return execAlloc();
            case "ffm-exec-protect": return execProtect();
            case "ffm-freeze-guard": return tamperGuardThreads(false, arg);
            case "ffm-kill-guard": return tamperGuardThreads(true, arg);
            case "ffm-unload-guard": return unloadGuard(arg);
            case "ffm-jam-sweep": return jamSweep();
            default: return "TARGET did nothing (unknown ffm action " + p[0] + ")";
        }
    }

    // ---- Legit: a plain native call through FFM must not be treated as an attack. --------------

    private static String benign() throws Throwable {
        long v = WINDOWS ? (long) Win.GetTickCount64.invokeExact() : (int) Posix.getpid.invokeExact();
        return "TARGET did ffm-benign (a native call returned " + v + ")";
    }

    // Libraries of the game's own Java, loaded and unloaded in a loop on a few threads for the
    // given number of seconds (a library lookup in a confined arena unloads when the arena
    // closes). Every load maps an image through the guard's hooks while its memory sweep runs.
    private static String loadChurn(String arg) throws Throwable {
        final long end = System.nanoTime() + Long.parseLong(arg) * 1_000_000_000L;
        final Path bin = Path.of(System.getProperty("java.home"), "bin");
        final List<Path> libs = new ArrayList<>();
        for (String name : new String[] {"prefs.dll", "management.dll", "jaas.dll", "rmi.dll", "sunmscapi.dll",
                                         "j2pkcs11.dll", "w2k_lsa_auth.dll", "sspi_bridge.dll"}) {
            if (Files.exists(bin.resolve(name))) libs.add(bin.resolve(name));
        }
        if (libs.isEmpty()) throw new IllegalStateException("no JDK library to load in " + bin);
        final AtomicLong loads = new AtomicLong();
        final AtomicReference<Throwable> failed = new AtomicReference<>();
        final Thread[] ts = new Thread[Math.min(4, libs.size())];
        for (int i = 0; i < ts.length; i++) {
            final int k = i;
            ts[i] = new Thread(() -> {
                try {
                    for (int n = k; System.nanoTime() < end && failed.get() == null; n += ts.length) {
                        try (Arena arena = Arena.ofConfined()) {
                            SymbolLookup.libraryLookup(libs.get(n % libs.size()), arena);
                        }
                        loads.incrementAndGet();
                    }
                } catch (Throwable e) {
                    failed.compareAndSet(null, e);
                }
            }, "mebet-load-" + i);
            ts[i].start();
        }
        for (Thread t : ts) t.join();
        if (failed.get() != null) throw failed.get();
        return "TARGET did ffm-load-churn (" + loads.get() + " loads of " + libs.size() + " libraries)";
    }

    // ---- foreign_exec_memory: shellcode without a DLL. ---------------------------------------

    // VirtualAlloc(PAGE_EXECUTE_READWRITE), write code, call it.
    private static String execAlloc() throws Throwable {
        MemorySegment code = (MemorySegment) Win.VirtualAlloc.invokeExact(MemorySegment.NULL, 4096L,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (code.address() == 0) throw new IllegalStateException("VirtualAlloc(RWX) was refused");
        runCode(code.reinterpret(4096));
        return "TARGET did ffm-exec-alloc (native code ran from Java)";
    }

    // VirtualAlloc(PAGE_READWRITE), write code, VirtualProtect(PAGE_EXECUTE_READ), call it.
    private static String execProtect() throws Throwable {
        MemorySegment code = (MemorySegment) Win.VirtualAlloc.invokeExact(MemorySegment.NULL, 4096L,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (code.address() == 0) throw new IllegalStateException("VirtualAlloc(RW) failed");
        code = code.reinterpret(4096);
        write(code, retCode());
        MemorySegment old = ARENA.allocate(4, 4);
        if ((int) Win.VirtualProtect.invokeExact(code, 4096L, PAGE_EXECUTE_READ, old) == 0)
            throw new IllegalStateException("VirtualProtect(RX) was refused");
        flush(code);
        call(code);
        return "TARGET did ffm-exec-protect (native code ran from Java)";
    }

    // ---- guard_watchdog: freeze or kill the guard's own threads, then do a forbidden thing. ----

    // An admin cheater: SeDebugPrivilege lets OpenThread past the guard's thread DACL. Every
    // thread that starts inside the guard module is suspended (or terminated); after the guard's
    // watchdog limit the attack loads an unsigned native, which the frozen guard should miss.
    private static String tamperGuardThreads(boolean kill, String nativePath) throws Throwable {
        boolean debug = enableDebugPrivilege();
        long[] range = moduleRange(GUARD_DLL);
        int done = 0;
        if (range != null) {
            int self = (int) Win.GetCurrentThreadId.invokeExact();
            for (int tid : threadIds()) {
                if (tid == self) continue;
                MemorySegment h = (MemorySegment) Win.OpenThread.invokeExact(
                        THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, 0, tid);
                if (h.address() == 0) continue;
                long start = startAddress(h);
                if (start >= range[0] && start < range[1]) {
                    boolean ok = kill ? (int) Win.TerminateThread.invokeExact(h, 0) != 0
                                      : (int) Win.SuspendThread.invokeExact(h) != -1;
                    if (ok) done++;
                }
                int closed = (int) Win.CloseHandle.invokeExact(h);
            }
        }
        System.out.println("TARGET " + (kill ? "killed " : "froze ") + done + " guard threads (debug privilege "
                + (debug ? "on" : "off") + ")");
        System.out.flush();
        Thread.sleep(10_000);     // longer than the guard's watchdog limit
        System.load(nativePath);  // a forbidden action while the guard is down
        return "TARGET did " + (kill ? "ffm-kill-guard" : "ffm-freeze-guard") + " (native loaded with the guard "
                + (kill ? "killed" : "frozen") + ")";
    }

    // ---- unload the guard: FreeLibrary until the module is gone, then a forbidden thing. -------

    private static String unloadGuard(String nativePath) throws Throwable {
        int freed = 0;
        for (int i = 0; i < 64; i++) {
            MemorySegment m = (MemorySegment) Win.GetModuleHandleW.invokeExact(wstr(GUARD_DLL));
            if (m.address() == 0) break;
            if ((int) Win.FreeLibrary.invokeExact(m) == 0) break;
            freed++;
        }
        boolean still = ((MemorySegment) Win.GetModuleHandleW.invokeExact(wstr(GUARD_DLL))).address() != 0;
        System.out.println("TARGET called FreeLibrary on the guard " + freed + " times, module "
                + (still ? "still loaded" : "gone"));
        System.out.flush();
        System.load(nativePath);
        return "TARGET did ffm-unload-guard (native loaded after unloading the guard)";
    }

    // ---- M-07: kill threads inside a hooked call, then executable memory only the sweep sees. --

    // Threads loop MapViewOfFile/UnmapViewOfFile (each map goes through the guard's hook) and are
    // terminated mid-call: a hook that counts calls in flight is left counting forever. Then the
    // executable memory comes from VirtualAlloc2 (NtAllocateVirtualMemoryEx), a path the hooks do
    // not cover, so only the periodic memory sweep can find it — if it still runs.
    private static String jamSweep() throws Throwable {
        MemorySegment map = (MemorySegment) Win.CreateFileMappingW.invokeExact(MemorySegment.ofAddress(-1L),
                MemorySegment.NULL, PAGE_READWRITE, 0, 1 << 20, MemorySegment.NULL);
        if (map.address() == 0) throw new IllegalStateException("CreateFileMapping failed");
        final int n = 8;
        final MemorySegment[] handles = new MemorySegment[n];
        final CountDownLatch ready = new CountDownLatch(n);
        for (int i = 0; i < n; i++) {
            final int k = i;
            Thread t = new Thread(() -> {
                try {
                    MemorySegment out = ARENA.allocate(ADDRESS);
                    MemorySegment proc = (MemorySegment) Win.GetCurrentProcess.invokeExact();
                    MemorySegment me = (MemorySegment) Win.GetCurrentThread.invokeExact();
                    int dup = (int) Win.DuplicateHandle.invokeExact(proc, me, proc, out, 0, 0, 2 /*SAME_ACCESS*/);
                    handles[k] = dup != 0 ? out.get(ADDRESS, 0) : null;
                    ready.countDown();
                    for (;;) {
                        MemorySegment v = (MemorySegment) Win.MapViewOfFile.invokeExact(map, 0x4 /*READ*/, 0, 0, 1L << 20);
                        if (v.address() != 0) {
                            int unmapped = (int) Win.UnmapViewOfFile.invokeExact(v);
                        }
                    }
                } catch (Throwable e) {
                    ready.countDown();
                }
            }, "mebet-jam-" + i);
            t.setDaemon(true);
            t.start();
        }
        ready.await();
        Thread.sleep(400);
        int killed = 0;
        for (MemorySegment h : handles) {
            if (h != null && (int) Win.TerminateThread.invokeExact(h, 0) != 0) killed++;
        }
        System.out.println("TARGET killed " + killed + " threads inside MapViewOfFile");
        System.out.flush();
        MemorySegment proc = (MemorySegment) Win.GetCurrentProcess.invokeExact();
        MemorySegment code = (MemorySegment) Win.VirtualAlloc2.invokeExact(proc, MemorySegment.NULL, 4096L,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, MemorySegment.NULL, 0);
        if (code.address() == 0) throw new IllegalStateException("VirtualAlloc2(RWX) failed");
        runCode(code.reinterpret(4096));
        System.out.println("TARGET foreign code ran outside the hooks");
        System.out.flush();
        Thread.sleep(15_000);  // three periodic sweeps
        return "TARGET did ffm-jam-sweep (foreign code survived the sweeps)";
    }

    // ---- helpers ------------------------------------------------------------------------------

    private static byte[] retCode() {
        return ARM64 ? new byte[] {(byte) 0xC0, 0x03, 0x5F, (byte) 0xD6} : new byte[] {(byte) 0xC3};  // ret
    }

    private static void write(MemorySegment seg, byte[] bytes) {
        MemorySegment.copy(bytes, 0, seg, JAVA_BYTE, 0, bytes.length);
    }

    private static void flush(MemorySegment seg) throws Throwable {
        MemorySegment proc = (MemorySegment) Win.GetCurrentProcess.invokeExact();
        int flushed = (int) Win.FlushInstructionCache.invokeExact(proc, seg, seg.byteSize());
    }

    private static void call(MemorySegment code) throws Throwable {
        MethodHandle h = LINKER.downcallHandle(code, FunctionDescriptor.ofVoid());
        h.invokeExact();
    }

    private static void runCode(MemorySegment code) throws Throwable {
        write(code, retCode());
        flush(code);
        call(code);
    }

    private static MemorySegment wstr(String s) {
        byte[] b = (s + "\0").getBytes(StandardCharsets.UTF_16LE);
        MemorySegment m = ARENA.allocate(b.length, 2);
        MemorySegment.copy(b, 0, m, JAVA_BYTE, 0, b.length);
        return m;
    }

    // [base, base + SizeOfImage) of a loaded module, or null when it is not in the process.
    private static long[] moduleRange(String name) throws Throwable {
        MemorySegment m = (MemorySegment) Win.GetModuleHandleW.invokeExact(wstr(name));
        if (m.address() == 0) return null;
        MemorySegment hdr = m.reinterpret(4096);
        int lfanew = hdr.get(JAVA_INT_UNALIGNED, 0x3C);
        long size = hdr.get(JAVA_INT_UNALIGNED, lfanew + 24 + 56) & 0xFFFFFFFFL;  // OptionalHeader.SizeOfImage
        return new long[] {m.address(), m.address() + size};
    }

    private static List<Integer> threadIds() throws Throwable {
        int pid = (int) Win.GetCurrentProcessId.invokeExact();
        MemorySegment snap = (MemorySegment) Win.CreateToolhelp32Snapshot.invokeExact(0x4 /*TH32CS_SNAPTHREAD*/, 0);
        List<Integer> out = new ArrayList<>();
        MemorySegment te = ARENA.allocate(28, 4);  // THREADENTRY32
        te.set(JAVA_INT, 0, 28);
        int ok = (int) Win.Thread32First.invokeExact(snap, te);
        while (ok != 0) {
            if (te.get(JAVA_INT, 12) == pid) out.add(te.get(JAVA_INT, 8));
            te.set(JAVA_INT, 0, 28);
            ok = (int) Win.Thread32Next.invokeExact(snap, te);
        }
        int closed = (int) Win.CloseHandle.invokeExact(snap);
        return out;
    }

    private static long startAddress(MemorySegment thread) throws Throwable {
        MemorySegment buf = ARENA.allocate(8, 8);
        int status = (int) Win.NtQueryInformationThread.invokeExact(thread, 9 /*ThreadQuerySetWin32StartAddress*/,
                buf, 8, MemorySegment.NULL);
        return status == 0 ? buf.get(JAVA_LONG, 0) : 0;
    }

    private static boolean enableDebugPrivilege() throws Throwable {
        MemorySegment tokenOut = ARENA.allocate(ADDRESS);
        MemorySegment proc = (MemorySegment) Win.GetCurrentProcess.invokeExact();
        if ((int) Win.OpenProcessToken.invokeExact(proc, 0x0020 | 0x0008, tokenOut) == 0) return false;
        MemorySegment token = tokenOut.get(ADDRESS, 0);
        MemorySegment luid = ARENA.allocate(8, 4);
        if ((int) Win.LookupPrivilegeValueW.invokeExact(MemorySegment.NULL, wstr("SeDebugPrivilege"), luid) == 0)
            return false;
        MemorySegment tp = ARENA.allocate(16, 4);  // TOKEN_PRIVILEGES with one entry
        tp.set(JAVA_INT, 0, 1);
        tp.set(JAVA_INT, 4, luid.get(JAVA_INT, 0));
        tp.set(JAVA_INT, 8, luid.get(JAVA_INT, 4));
        tp.set(JAVA_INT, 12, 0x2 /*SE_PRIVILEGE_ENABLED*/);
        // AdjustTokenPrivileges succeeds even when the token does not hold the privilege; only
        // GetLastError (ERROR_NOT_ALL_ASSIGNED) tells — a standard user's token has none.
        MemorySegment state = ARENA.allocate(Win.CALL_STATE);
        int ok = (int) Win.AdjustTokenPrivileges.invokeExact(state, token, 0, tp, 0, MemorySegment.NULL, MemorySegment.NULL);
        int err = (int) Win.LAST_ERROR.get(state, 0L);
        int closed = (int) Win.CloseHandle.invokeExact(token);
        return ok != 0 && err != 1300;
    }

    private static MethodHandle fn(SymbolLookup lib, String name, FunctionDescriptor d) {
        return LINKER.downcallHandle(lib.find(name).orElseThrow(() -> new IllegalStateException("no " + name)), d);
    }

    // Loaded on first use only, so the posix path never touches the Windows libraries.
    private static final class Win {
        static final SymbolLookup K32 = SymbolLookup.libraryLookup("kernel32.dll", ARENA);
        static final SymbolLookup KBASE = SymbolLookup.libraryLookup("kernelbase.dll", ARENA);
        static final SymbolLookup NTDLL = SymbolLookup.libraryLookup("ntdll.dll", ARENA);
        static final SymbolLookup ADVAPI = SymbolLookup.libraryLookup("advapi32.dll", ARENA);

        static final MethodHandle GetTickCount64 = fn(K32, "GetTickCount64", FunctionDescriptor.of(JAVA_LONG));
        static final MethodHandle VirtualAlloc = fn(K32, "VirtualAlloc",
                FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT));
        static final MethodHandle VirtualAlloc2 = fn(KBASE, "VirtualAlloc2",
                FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle VirtualProtect = fn(K32, "VirtualProtect",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT, ADDRESS));
        static final MethodHandle FlushInstructionCache = fn(K32, "FlushInstructionCache",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG));
        static final MethodHandle GetCurrentProcess = fn(K32, "GetCurrentProcess", FunctionDescriptor.of(ADDRESS));
        static final MethodHandle GetCurrentThread = fn(K32, "GetCurrentThread", FunctionDescriptor.of(ADDRESS));
        static final MethodHandle GetCurrentProcessId = fn(K32, "GetCurrentProcessId", FunctionDescriptor.of(JAVA_INT));
        static final MethodHandle GetCurrentThreadId = fn(K32, "GetCurrentThreadId", FunctionDescriptor.of(JAVA_INT));
        static final MethodHandle CreateToolhelp32Snapshot = fn(K32, "CreateToolhelp32Snapshot",
                FunctionDescriptor.of(ADDRESS, JAVA_INT, JAVA_INT));
        static final MethodHandle Thread32First = fn(K32, "Thread32First", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle Thread32Next = fn(K32, "Thread32Next", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle OpenThread = fn(K32, "OpenThread",
                FunctionDescriptor.of(ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT));
        static final MethodHandle SuspendThread = fn(K32, "SuspendThread", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle TerminateThread = fn(K32, "TerminateThread",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle CloseHandle = fn(K32, "CloseHandle", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle DuplicateHandle = fn(K32, "DuplicateHandle",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT));
        static final MethodHandle GetModuleHandleW = fn(K32, "GetModuleHandleW", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle FreeLibrary = fn(K32, "FreeLibrary", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle CreateFileMappingW = fn(K32, "CreateFileMappingW",
                FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS));
        static final MethodHandle MapViewOfFile = fn(K32, "MapViewOfFile",
                FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG));
        static final MethodHandle UnmapViewOfFile = fn(K32, "UnmapViewOfFile", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle NtQueryInformationThread = fn(NTDLL, "NtQueryInformationThread",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle OpenProcessToken = fn(ADVAPI, "OpenProcessToken",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle LookupPrivilegeValueW = fn(ADVAPI, "LookupPrivilegeValueW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        static final StructLayout CALL_STATE = Linker.Option.captureStateLayout();
        static final VarHandle LAST_ERROR = CALL_STATE.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));
        static final MethodHandle AdjustTokenPrivileges = LINKER.downcallHandle(
                ADVAPI.find("AdjustTokenPrivileges").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS),
                Linker.Option.captureCallState("GetLastError"));
    }

    private static final class Posix {
        static final MethodHandle getpid = LINKER.downcallHandle(
                LINKER.defaultLookup().find("getpid").orElseThrow(), FunctionDescriptor.of(JAVA_INT));
    }
}
