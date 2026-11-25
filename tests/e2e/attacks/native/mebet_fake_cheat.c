/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * A tiny unsigned native library that stands in for a cheat's native module. It is NOT a
 * cheat: it only writes a marker so the oracle can tell it was mapped into the game process.
 * Because it is unsigned and lives outside the Java folder, the guard must refuse to load it
 * (ТЗ §6, §10); without the guard it loads and the marker proves the attack worked.
 *
 * It exports three entry points so one file covers several layers:
 *   JNI_OnLoad     — called by System.load() (module_trust: a mod loads a foreign native).
 *   Agent_OnLoad   — called by -agentpath (jvm_agents: a foreign JVMTI agent at start).
 *   Agent_OnAttach — called by a late attach (jvm_agents: a foreign agent attached at runtime).
 * The runner builds it with whatever toolchain is present (cl / clang / gcc). */

#include <stdio.h>

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

static void mark(const char *how) {
    fprintf(stderr, "ATTACK native %s in the game process\n", how);
    fflush(stderr);
}

/* jint JNI_OnLoad(JavaVM*, void*) without pulling in jni.h: the JVM only needs the symbol
 * and a JNI version return value. */
EXPORT int JNI_OnLoad(void *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    mark("System.load");
    return 0x00010008; /* JNI_VERSION_1_8 */
}

/* jint Agent_OnLoad(JavaVM*, char* options, void* reserved): a JVMTI agent started with
 * -agentpath. Returning 0 is success, so the JVM keeps running (baseline). */
EXPORT int Agent_OnLoad(void *vm, char *options, void *reserved) {
    (void)vm;
    (void)options;
    (void)reserved;
    mark("Agent_OnLoad");
    return 0;
}

EXPORT int Agent_OnAttach(void *vm, char *options, void *reserved) {
    (void)vm;
    (void)options;
    (void)reserved;
    mark("Agent_OnAttach");
    return 0;
}
