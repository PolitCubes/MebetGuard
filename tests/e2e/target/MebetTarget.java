// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
//
// The target JVM application the guard protects in the e2e tests. It stands in for the
// game client: a process that starts, prints a heartbeat for a while, then exits cleanly.
// The wrapper (MebetGuard.exe / MebetGuard) launches it exactly as it launches the real
// client; the baseline launches the same class with plain `java`, so the two runs differ
// only in whether the guard is in the process.
//
// Observability the oracle in run.py relies on (every line flushed):
//   "TARGET up pid=<n>"      — the JVM reached main()
//   "TARGET alive <i>"       — heartbeat i (the app is still running)
//   "TARGET action: <a>"     — the in-process action is about to run: the game got that far.
//                              A close before this line was not about the action at all.
//   "TARGET did <marker>"    — an in-process action asked for by -Dmebet.cmd ran. For an
//                              attack (what a cheat mod does from inside the JVM) its
//                              presence is the proof the attack worked, and with the guard in
//                              the process it must be closed before this prints. For a legit
//                              action (threads, JIT, a JDK library) it must print in both runs.
//   "TARGET exit"            — the loop finished without the guard closing the process.
//
// Properties:
//   -Dmebet.iters=<n>    heartbeats before a clean exit (default 8, ~2s at 250ms)
//   -Dmebet.cmd=<file>   optional file whose first line is an in-process action
//   -Dmebet.stop=<file>  optional flag file; when it appears the loop stops early

import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MebetTarget {
    public static void main(String[] args) throws Exception {
        long pid = ProcessHandle.current().pid();
        System.out.println("TARGET up pid=" + pid);
        System.out.flush();

        String cmdFile = System.getProperty("mebet.cmd", "");
        if (!cmdFile.isEmpty() && Files.exists(Paths.get(cmdFile))) {
            String action = Files.readAllLines(Paths.get(cmdFile)).get(0).trim();
            System.out.println("TARGET action: " + action);
            System.out.flush();
            runAction(action);  // models what a cheat jar does from inside the JVM
        }

        int iters = Integer.getInteger("mebet.iters", 8);
        String stop = System.getProperty("mebet.stop", "");
        for (int i = 0; i < iters; i++) {
            if (!stop.isEmpty() && Files.exists(Paths.get(stop))) break;
            System.out.println("TARGET alive " + i);
            System.out.flush();
            Thread.sleep(250);
        }
        System.out.println("TARGET exit");
        System.out.flush();
    }

    // Prints "TARGET did ..." only if the action actually succeeded, so the guard closing the
    // process mid-action leaves no marker.
    private static void runAction(String action) {
        try {
            if (action.equals("none")) {
                System.out.println("TARGET did none");
            } else if (action.startsWith("load-native ")) {
                String path = action.substring("load-native ".length()).trim();
                System.load(path);                       // a native library into the game by path
                System.out.println("TARGET did load-native " + path);
            } else if (action.startsWith("load-library ")) {
                String name = action.substring("load-library ".length()).trim();
                System.loadLibrary(name);                // a JDK library by name (java.library.path)
                System.out.println("TARGET did load-library " + name);
            } else if (action.startsWith("thread-churn ")) {
                int n = Integer.parseInt(action.substring("thread-churn ".length()).trim());
                System.out.println("TARGET did thread-churn " + threadChurn(n));
            } else if (action.startsWith("jit-hot ")) {
                long ms = Long.parseLong(action.substring("jit-hot ".length()).trim());
                System.out.println("TARGET did jit-hot " + jitHot(ms));
            } else if (action.startsWith("ffm-")) {
                // Java 22+ only: the class is built only when the JDK has the FFM API.
                Class<?> ffm = Class.forName("MebetFfm");
                System.out.println((String) ffm.getMethod("run", String.class).invoke(null, action));
            } else {
                System.out.println("TARGET did nothing (unknown action " + action + ")");
            }
        } catch (InvocationTargetException e) {
            System.out.println("TARGET action-failed " + e.getCause());
        } catch (Throwable t) {
            System.out.println("TARGET action-failed " + t);
        }
        System.out.flush();
    }

    // Many short-lived threads, 50 at a time: every start and exit goes through the guard's
    // thread checks and, at exit, through its memory hooks on a thread that is going away.
    private static int threadChurn(int n) throws InterruptedException {
        int done = 0;
        while (done < n) {
            int batch = Math.min(50, n - done);
            Thread[] ts = new Thread[batch];
            for (int i = 0; i < batch; i++) {
                ts[i] = new Thread(() -> { byte[] b = new byte[64 * 1024]; b[0] = 1; });
                ts[i].start();
            }
            for (Thread t : ts) t.join();
            done += batch;
        }
        return done;
    }

    // A hot loop: the JIT compiles it (C1, then C2) into executable memory the JVM owns.
    private static long jitHot(long ms) {
        long end = System.nanoTime() + ms * 1_000_000L, x = 1, rounds = 0;
        while (System.nanoTime() < end) {
            for (int i = 0; i < 100_000; i++) x = mix(x, i);
            rounds++;
        }
        return rounds + (x == 42 ? 1 : 0);
    }

    private static long mix(long x, int i) {
        x ^= x << 13;
        x ^= x >>> 7;
        return x * 0x9E3779B97F4A7C15L + i;
    }
}
