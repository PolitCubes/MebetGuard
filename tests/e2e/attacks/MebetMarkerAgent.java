// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
//
// A harmless Java agent that stands in for an injected cheat agent. It only prints a marker
// so the oracle can tell whether the JVM loaded a foreign -javaagent (jvm_agents) or picked
// one up from the environment (env_hardening). The runner packs it into mebet-marker.jar
// with "Premain-Class" / "Agent-Class" manifest entries.
//
// A real cheat agent would use java.lang.instrument to rewrite game classes; this one does
// nothing but announce that an external agent was allowed to run — which is exactly what the
// guard must prevent.

import java.lang.instrument.Instrumentation;

public class MebetMarkerAgent {
    public static void premain(String args, Instrumentation inst) {
        System.out.println("ATTACK agent premain ran (args=" + args + ")");
        System.out.flush();
    }

    public static void agentmain(String args, Instrumentation inst) {
        System.out.println("ATTACK agent agentmain ran (args=" + args + ")");
        System.out.flush();
    }
}
