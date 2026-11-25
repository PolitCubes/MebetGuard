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
//   "TARGET did <marker>"    — an in-process action asked for by -Dmebet.cmd ran: a "cheat"
//                              a mod would do from inside the JVM (load a native library).
//                              Its presence is the proof the attack worked; with the guard
//                              in the process it must be closed before this prints.
//   "TARGET exit"            — the loop finished without the guard closing the process.
//
// Properties:
//   -Dmebet.iters=<n>    heartbeats before a clean exit (default 8, ~2s at 250ms)
//   -Dmebet.cmd=<file>   optional file whose first line is an in-process action
//   -Dmebet.stop=<file>  optional flag file; when it appears the loop stops early

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
            if (action.startsWith("load-native ")) {
                String path = action.substring("load-native ".length()).trim();
                System.load(path);                       // foreign native library into the game
                System.out.println("TARGET did load-native " + path);
            } else {
                System.out.println("TARGET did nothing (unknown action " + action + ")");
            }
        } catch (Throwable t) {
            System.out.println("TARGET action-failed " + t);
        }
        System.out.flush();
    }
}
