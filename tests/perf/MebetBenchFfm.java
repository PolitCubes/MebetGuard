// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
//
// Benchmarks that need the final Foreign Function & Memory API (Java 22+); built only there.
//   native_alloc  1 MB native blocks allocated and freed (on Windows each one is VirtualAlloc +
//                 VirtualFree — straight through the guard's memory hooks)
//   file_mmap     a 4 MB file region mapped and unmapped (the guard's section hooks)
//   ffm_downcall  plain native calls — a control: the guard is not on this path

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

public final class MebetBenchFfm {
    private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase().startsWith("windows");
    private static Path file;

    private MebetBenchFfm() {}

    public static MebetBench.Round round(String name) throws Throwable {
        switch (name) {
            case "native_alloc": return MebetBenchFfm::nativeAlloc;
            case "file_mmap": return MebetBenchFfm::fileMmap;
            case "ffm_downcall": return downcall();
            default: throw new IllegalArgumentException("unknown benchmark " + name);
        }
    }

    static void nativeAlloc() {
        long s = 0;
        for (int i = 0; i < 1000; i++) {
            try (Arena a = Arena.ofConfined()) {
                MemorySegment m = a.allocate(1 << 20, 16);
                m.set(JAVA_BYTE, 0, (byte) i);
                m.set(JAVA_BYTE, (1 << 20) - 1, (byte) 1);
                s += m.get(JAVA_BYTE, 0);
            }
        }
        MebetBench.SINK += s;
    }

    static void fileMmap() throws IOException {
        if (file == null) {
            file = Files.createTempFile("mebet-bench", ".bin");
            file.toFile().deleteOnExit();
            Files.write(file, new byte[8 << 20]);
        }
        long s = 0;
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            for (int i = 0; i < 2000; i++) {
                try (Arena a = Arena.ofConfined()) {
                    MemorySegment m = ch.map(FileChannel.MapMode.READ_ONLY, 0, 4 << 20, a);
                    for (long off = 0; off < m.byteSize(); off += 65536) s += m.get(JAVA_BYTE, off);
                }
            }
        }
        MebetBench.SINK += s;
    }

    static MebetBench.Round downcall() {
        Linker linker = Linker.nativeLinker();
        if (WINDOWS) {
            MethodHandle h = linker.downcallHandle(
                    SymbolLookup.libraryLookup("kernel32.dll", Arena.global()).find("GetTickCount64").orElseThrow(),
                    FunctionDescriptor.of(JAVA_LONG));
            return () -> {
                long s = 0;
                for (int i = 0; i < 30_000_000; i++) s += (long) h.invokeExact();
                MebetBench.SINK += s;
            };
        }
        MethodHandle h = linker.downcallHandle(linker.defaultLookup().find("getpid").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT));
        return () -> {
            long s = 0;
            for (int i = 0; i < 30_000_000; i++) s += (int) h.invokeExact();
            MebetBench.SINK += s;
        };
    }
}
