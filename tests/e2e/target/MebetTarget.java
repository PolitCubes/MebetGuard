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
//   "TARGET env <NAME> set|unset" — whether JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS reached the game.
//                              The proof of env_hardening: through the guard they must be gone,
//                              whether or not this launch path would have read them.
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
        for (String name : new String[] {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"}) {
            System.out.println("TARGET env " + name + (System.getenv(name) != null ? " set" : " unset"));
        }
        System.out.flush();

        String cmdFile = System.getProperty("mebet.cmd", "");
        String cmdAction = "";
        if (!cmdFile.isEmpty() && Files.exists(Paths.get(cmdFile))) {
            String action = Files.readAllLines(Paths.get(cmdFile)).get(0).trim();
            cmdAction = action;
            System.out.println("TARGET action: " + action);
            System.out.flush();
            runAction(action);  // models what a cheat jar does from inside the JVM
            // Threads killed by TerminateThread (ffm-jam-sweep) leave the JVM's own bookkeeping broken,
            // and any work after that — the heartbeat loop, a normal shutdown — can end with exit code 1,
            // the attack's doing, not the app's. By the time this action returns the attack is over (the
            // probe has written its code), so the game exits at once, cleanly, before the damage shows.
            if (cmdAction.startsWith("ffm-jam-sweep")) {
                System.out.println("TARGET exit");
                System.out.flush();
                Runtime.getRuntime().halt(0);
            }
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
            } else if (action.startsWith("unreadable-module ")) {
                String src = action.substring("unreadable-module ".length()).trim();
                System.out.println("TARGET did unreadable-module " + unreadableModule(src));
            } else if (action.startsWith("thread-churn ")) {
                int n = Integer.parseInt(action.substring("thread-churn ".length()).trim());
                System.out.println("TARGET did thread-churn " + threadChurn(n));
            } else if (action.startsWith("jit-hot ")) {
                long ms = Long.parseLong(action.substring("jit-hot ".length()).trim());
                System.out.println("TARGET did jit-hot " + jitHot(ms));
            } else if (action.startsWith("ffm-")) {
                // Java 22+ only: the class is built only when the JDK has the FFM API.
                Class<?> ffm = Class.forName("MebetFfm");
                String did = (String) ffm.getMethod("run", String.class).invoke(null, action);
                System.out.println(did);
                if (action.startsWith("ffm-quick-") && did.startsWith("TARGET did")) {
                    // Done before the next periodic sweep could see it: the game ends right here, so
                    // only a hook that refused at the call could have stopped it.
                    System.out.println("TARGET exit");
                    System.out.flush();
                    Runtime.getRuntime().halt(0);
                }
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

    // A library loaded fine (a copy of a JDK one, made by the game itself), whose file then cannot be
    // opened any more — its permissions changed, as when a share drops or a folder is locked: it was
    // judged when it loaded, and the game must go on. Its permissions are put back afterwards.
    private static String unreadableModule(String src) throws Exception {
        java.nio.file.Path dir = Paths.get("unreadable-" + ProcessHandle.current().pid()).toAbsolutePath();
        Files.createDirectories(dir);
        java.nio.file.Path dll = dir.resolve(Paths.get(src).getFileName());
        Files.copy(Paths.get(src), dll, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        System.load(dll.toString());
        icacls(dll, "/deny", "*S-1-1-0:(R)");
        try {
            try (java.io.InputStream in = Files.newInputStream(dll)) {
                throw new IllegalStateException("the file still reads after the deny: the check proves nothing");
            } catch (java.io.IOException expected) {
                // denied, as wanted
            }
            System.out.println("TARGET module file made unreadable");
            System.out.flush();
            Thread.sleep(16_000);  // three periodic sweeps
        } finally {
            icacls(dll, "/remove:d", "*S-1-1-0");
        }
        return dll.toString();
    }

    private static void icacls(java.nio.file.Path file, String... args) throws Exception {
        java.util.List<String> cmd = new java.util.ArrayList<>(java.util.List.of("icacls", file.toString()));
        cmd.addAll(java.util.List.of(args));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new IllegalStateException("icacls " + String.join(" ", args) + " failed: " + out);
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
