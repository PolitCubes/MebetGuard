// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
//
// Workloads for measuring what the guard costs: the same JVM work timed without the guard and
// through it (tests/perf/bench.py runs both and prints the difference in %).
//
// Each benchmark stresses one thing the guard touches, or must not touch:
//   cpu_hash, cpu_sort, cpu_math  pure Java compute (JIT code): the guard should cost nothing
//   alloc_young                   short-lived objects: young GC
//   alloc_huge                    8 MB arrays: humongous allocation, heap commit (memory hooks)
//   threads                       thread start and exit: the guard's thread checks, DACL per thread
//   class_load                    classes defined at run time: the JVMTI side of the guard
//   jni_deflate                   JNI-heavy JDK code (zip)
//   game_tick                     a game-like frame loop: math, garbage, a spatial grid, parallel work
//   native_alloc   (Java 22+)     1 MB native blocks: VirtualAlloc / VirtualFree through the hooks
//   file_mmap      (Java 22+)     map and unmap a file: the section hooks
//   ffm_downcall   (Java 22+)     plain native calls (control: the guard is not on this path)
//
// Timing is by wall clock, not by a round count: rounds repeat through a warm-up window (JIT),
// then through a measured window of at least 10 s, and the result is the mean round time over
// that window — GC pauses and everything else the JVM does included, as in a real game.
//
// Usage: java MebetBench <name> [warmup_s] [measure_s]  → one "BENCH {json}" line (3 s, 10 s)
//        java MebetBench list                          → the names this JDK can run
//        java MebetBench startup                       → exits at once (start-up is timed outside)

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;
import java.util.zip.Deflater;

public final class MebetBench {
    static volatile long SINK;
    static final AtomicLong COUNTER = new AtomicLong();

    interface Round {
        void run() throws Throwable;
    }

    public static void main(String[] args) throws Throwable {
        String name = args.length > 0 ? args[0] : "list";
        if (name.equals("startup")) return;
        if (name.equals("list")) {
            List<String> names = new ArrayList<>(List.of("cpu_hash", "cpu_sort", "cpu_math", "alloc_young",
                    "alloc_huge", "threads", "class_load", "jni_deflate", "game_tick", "frame_pacing"));
            if (ffm() != null) names.addAll(List.of("native_alloc", "file_mmap", "ffm_downcall"));
            System.out.println("BENCHES " + String.join(" ", names));
            return;
        }
        double warmupS = args.length > 1 ? Double.parseDouble(args[1]) : 3;
        double measureS = args.length > 2 ? Double.parseDouble(args[2]) : 10;
        if (name.equals("frame_pacing")) {
            framePacing(warmupS, measureS);
            return;
        }
        Round r = round(name);
        long end = System.nanoTime() + (long) (warmupS * 1e9);
        do {
            r.run();
        } while (System.nanoTime() < end);
        List<Double> ms = new ArrayList<>();
        final long start = System.nanoTime(), stop = start + (long) (measureS * 1e9);
        for (;;) {
            long t0 = System.nanoTime();
            r.run();
            long t1 = System.nanoTime();
            ms.add((t1 - t0) / 1e6);
            if (t1 >= stop && ms.size() >= 3) break;
        }
        final double totalMs = (System.nanoTime() - start) / 1e6;
        double[] sorted = ms.stream().mapToDouble(Double::doubleValue).sorted().toArray();
        StringBuilder sb = new StringBuilder();
        sb.append("BENCH {\"name\":\"").append(name).append("\",\"rounds\":").append(ms.size())
          .append(",\"total_ms\":").append(fmt(totalMs))
          .append(",\"mean_ms\":").append(fmt(totalMs / ms.size()))
          .append(",\"median_ms\":").append(fmt(sorted[sorted.length / 2]))
          .append(",\"min_ms\":").append(fmt(sorted[0]))
          .append(",\"max_ms\":").append(fmt(sorted[sorted.length - 1]))
          .append(",\"sink\":").append(SINK & 1).append('}');
        System.out.println(sb);
    }

    static String fmt(double v) {
        return String.format(java.util.Locale.ROOT, "%.3f", v);
    }

    static Round round(String name) throws Throwable {
        switch (name) {
            case "cpu_hash": return MebetBench::cpuHash;
            case "cpu_sort": return MebetBench::cpuSort;
            case "cpu_math": return MebetBench::cpuMath;
            case "alloc_young": return MebetBench::allocYoung;
            case "alloc_huge": return MebetBench::allocHuge;
            case "threads": return MebetBench::threads;
            case "class_load": return MebetBench::classLoad;
            case "jni_deflate": return MebetBench::jniDeflate;
            case "game_tick": return new Game()::round;
            default:
                Class<?> f = ffm();
                if (f == null) throw new IllegalArgumentException("unknown or unavailable benchmark " + name);
                Object r = f.getMethod("round", String.class).invoke(null, name);
                return (Round) r;
        }
    }

    // MebetBenchFfm is built only on Java 22+ (the final Foreign Function & Memory API).
    static Class<?> ffm() {
        try {
            return Class.forName("MebetBenchFfm");
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    // ---- pure compute ---------------------------------------------------------------------------

    static final class Data {
        static final byte[] BYTES = new byte[16 << 20];
        static final long[] LONGS = new long[2_000_000];
        static {
            Random rnd = new Random(1);
            rnd.nextBytes(BYTES);
            for (int i = 0; i < LONGS.length; i++) LONGS[i] = rnd.nextLong();
        }
    }

    static void cpuHash() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 12; i++) md.update(Data.BYTES);
        SINK += md.digest()[0];
    }

    static void cpuSort() {
        long[] a = Data.LONGS.clone();
        Arrays.sort(a);
        SINK += a[a.length / 2];
    }

    static void cpuMath() {
        final int w = 1280, h = 960;
        long count = 0;
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                double cr = x * 3.0 / w - 2.0, ci = y * 2.0 / h - 1.0, zr = 0, zi = 0;
                int k = 0;
                while (k < 256 && zr * zr + zi * zi < 4) {
                    double t = zr * zr - zi * zi + cr;
                    zi = 2 * zr * zi + ci;
                    zr = t;
                    k++;
                }
                count += k;
            }
        }
        SINK += count;
    }

    // ---- allocation and GC ----------------------------------------------------------------------

    static final Object[] RING = new Object[4096];
    static final byte[][] KEEP = new byte[4][];

    static void allocYoung() {
        for (int i = 0; i < 32_000_000; i++) {
            long[] o = new long[3];
            o[0] = i;
            RING[i & 4095] = o;
        }
        SINK += ((long[]) RING[7])[0];
    }

    static void allocHuge() {
        for (int i = 0; i < 256; i++) {
            byte[] b = new byte[8 << 20];
            b[0] = (byte) i;
            b[b.length - 1] = 1;
            KEEP[i & 3] = b;
        }
        SINK += KEEP[1][0];
    }

    // ---- threads --------------------------------------------------------------------------------

    static void threads() throws InterruptedException {
        for (int done = 0; done < 4000; done += 50) {
            Thread[] ts = new Thread[50];
            for (int i = 0; i < ts.length; i++) {
                ts[i] = new Thread(COUNTER::incrementAndGet);
                ts[i].start();
            }
            for (Thread t : ts) t.join();
        }
        SINK += COUNTER.get();
    }

    // ---- classes defined at run time -----------------------------------------------------------

    static byte[] payload;

    static final class Loader extends ClassLoader {
        Loader() {
            super(null);
        }

        Class<?> define(byte[] b) {
            return defineClass("MebetBenchPayload", b, 0, b.length);
        }
    }

    static void classLoad() throws Exception {
        if (payload == null) {
            try (InputStream in = MebetBench.class.getResourceAsStream("/MebetBenchPayload.class")) {
                payload = in.readAllBytes();
            }
        }
        for (int i = 0; i < 4000; i++) {
            Class<?> c = new Loader().define(payload);
            Object o = c.getDeclaredConstructor().newInstance();
            SINK += o.hashCode() & 1;
        }
    }

    // ---- JNI-heavy JDK code ---------------------------------------------------------------------

    static final byte[] TEXT;
    static {
        StringBuilder sb = new StringBuilder();
        String[] words = {"chunk", "block", "entity", "player", "server", "redstone", "creeper", "village"};
        Random rnd = new Random(2);
        while (sb.length() < 256 * 1024) sb.append(words[rnd.nextInt(words.length)]).append(' ').append(rnd.nextInt(1000));
        TEXT = sb.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    static void jniDeflate() {
        byte[] out = new byte[64 << 10];
        for (int i = 0; i < 30; i++) {
            Deflater d = new Deflater(6);
            d.setInput(TEXT);
            d.finish();
            long n = 0;
            while (!d.finished()) n += d.deflate(out);
            d.end();
            SINK += n;
        }
    }

    // ---- a game-like frame loop ------------------------------------------------------------------

    static final class Vec {
        final double x, y;

        Vec(double x, double y) {
            this.x = x;
            this.y = y;
        }

        Vec add(Vec o) {
            return new Vec(x + o.x, y + o.y);
        }

        Vec scale(double k) {
            return new Vec(x * k, y * k);
        }
    }

    static final class Game {
        static final int N = 4000;
        final double[] x = new double[N], y = new double[N], vx = new double[N], vy = new double[N];

        Game() {
            Random rnd = new Random(3);
            for (int i = 0; i < N; i++) {
                x[i] = rnd.nextDouble() * 1000;
                y[i] = rnd.nextDouble() * 1000;
                vx[i] = rnd.nextDouble() * 10 - 5;
                vy[i] = rnd.nextDouble() * 10 - 5;
            }
        }

        // 360 ticks (6 s of a 60 FPS game).
        void round() {
            for (int t = 0; t < 360; t++) tick();
        }

        // One tick: parallel physics, a spatial grid rebuilt from scratch, collisions per cell,
        // and temporary vector objects — the garbage a real game makes every frame.
        void tick() {
            final double dt = 1.0 / 60;
            IntStream.range(0, N).parallel().forEach(i -> {
                vy[i] -= 9.8 * dt;
                x[i] += vx[i] * dt;
                y[i] += vy[i] * dt;
                if (x[i] < 0 || x[i] > 1000) vx[i] = -vx[i];
                if (y[i] < 0) { y[i] = 0; vy[i] = -vy[i] * 0.9; }
                if (y[i] > 1000) vy[i] = -Math.abs(vy[i]);
            });
            HashMap<Long, ArrayList<Integer>> grid = new HashMap<>();
            for (int i = 0; i < N; i++) {
                long key = ((long) (x[i] / 25) << 32) ^ (long) (y[i] / 25);
                grid.computeIfAbsent(key, k -> new ArrayList<>()).add(i);
            }
            long hits = 0;
            for (ArrayList<Integer> cell : grid.values()) {
                for (int a = 0; a < cell.size(); a++) {
                    for (int b = a + 1; b < cell.size(); b++) {
                        int i = cell.get(a), j = cell.get(b);
                        double dx = x[i] - x[j], dy = y[i] - y[j];
                        if (dx * dx + dy * dy < 4) hits++;
                    }
                }
            }
            for (int i = 0; i < N; i++) {
                Vec v = new Vec(x[i], y[i]).add(new Vec(vx[i], vy[i]).scale(dt));
                hits += (long) v.x & 1;
            }
            SINK += hits;
        }
    }

    // ---- frame pacing: a 144 FPS loop, every frame timed ------------------------------------------

    // Each frame: a game tick, software rendering of every entity into a 1280×720 framebuffer, a
    // little garbage — then it waits for its 6.94 ms slot. The work time of every frame is kept, so
    // a hitch (a frame that missed its slot) shows up even if the average does not move: that is
    // where the guard's periodic checks (every 5 s) would hurt a game, if they did. The window is
    // 30 s at least — six rounds of those checks.
    static void framePacing(double warmupS, double measureS) {
        final int w = 1280, h = 720;
        final long budget = 1_000_000_000L / 144;
        final int[] fb = new int[w * h];
        final Game game = new Game();
        Runnable frame = () -> {
            game.tick();
            for (int i = 0; i < fb.length; i += 4) fb[i] = 0xFF202830 + (i & 0xFF);  // clear
            for (int i = 0; i < Game.N; i++) {                                       // draw sprites
                int px = (int) (game.x[i] * (w - 8) / 1000), py = (int) (game.y[i] * (h - 8) / 1000);
                if (px < 0 || py < 0 || px >= w - 8 || py >= h - 8) continue;
                for (int dy = 0; dy < 8; dy++) {
                    int row = (py + dy) * w + px;
                    for (int dx = 0; dx < 8; dx++) fb[row + dx] = 0xFFE0A040 ^ (i << 4);
                }
            }
            StringBuilder hud = new StringBuilder();                                 // per-frame garbage
            for (int i = 0; i < 32; i++) hud.append("fps ").append(i).append(' ');
            SINK += hud.length() + fb[(int) (SINK & 0xFFFF)];
        };
        long end = System.nanoTime() + (long) (warmupS * 1e9);
        while (System.nanoTime() < end) frame.run();
        final long window = (long) (Math.max(measureS, 30) * 1e9);
        long[] work = new long[(int) (window / budget) + 1024];
        int n = 0, over = 0;
        final long start = System.nanoTime(), stop = start + window;
        long next = start;
        while (System.nanoTime() < stop && n < work.length) {
            // From the moment the frame was due, not from the moment it started: a stall that
            // begins while waiting for the next frame delays that frame just the same.
            frame.run();
            long dt = System.nanoTime() - next;
            work[n++] = dt;
            if (dt > budget) over++;
            next += budget;
            long wait = next - System.nanoTime();
            if (wait <= 0) {
                next = System.nanoTime();  // behind schedule: start the next frame at once
                continue;
            }
            if (wait > 300_000) java.util.concurrent.locks.LockSupport.parkNanos(wait - 300_000);
            while (System.nanoTime() < next) Thread.onSpinWait();
        }
        long[] s = Arrays.copyOf(work, n);
        Arrays.sort(s);
        long sum = 0;
        for (long v : s) sum += v;
        StringBuilder sb = new StringBuilder();
        sb.append("BENCH {\"name\":\"frame_pacing\",\"frames\":").append(n)
          .append(",\"budget_ms\":").append(fmt(budget / 1e6))
          .append(",\"mean_ms\":").append(fmt(sum / 1e6 / n))
          .append(",\"p50_ms\":").append(fmt(s[n / 2] / 1e6))
          .append(",\"p99_ms\":").append(fmt(s[(int) (n * 0.99)] / 1e6))
          .append(",\"p999_ms\":").append(fmt(s[Math.min(n - 1, (int) (n * 0.999))] / 1e6))
          .append(",\"max_ms\":").append(fmt(s[n - 1] / 1e6))
          .append(",\"over_budget\":").append(over)
          .append(",\"sink\":").append(SINK & 1).append('}');
        System.out.println(sb);
    }
}
