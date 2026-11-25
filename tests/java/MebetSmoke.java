// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Smoke test of the wrapper on CI: the JVM must start through MebetGuard, run Java code
// and exit with the code it chose. Started with "load <dll>" it loads a native library,
// which lets CI check that an unsigned, unlisted DLL closes the client (exit code 210).
public final class MebetSmoke {
    public static void main(String[] args) throws Exception {
        System.out.println("mebet-smoke: java " + System.getProperty("java.version")
                + " " + System.getProperty("os.arch"));
        if (args.length == 2 && args[0].equals("load")) {
            try {
                System.load(args[1]);
                System.out.println("mebet-smoke: library loaded");
            } catch (UnsatisfiedLinkError e) {
                System.out.println("mebet-smoke: load refused: " + e.getMessage());
            }
            // The guard closes the client from its worker thread; give it time.
            Thread.sleep(15000);
            System.out.println("mebet-smoke: still running");
            System.exit(3);
        }
        Thread t = new Thread(() -> System.out.println("mebet-smoke: thread ok"));
        t.start();
        t.join();
        System.out.println("mebet-smoke-ok");
        System.exit(0);
    }
}
