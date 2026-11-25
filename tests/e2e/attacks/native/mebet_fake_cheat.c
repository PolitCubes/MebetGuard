/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 PolitCubes
 *
 * A tiny unsigned native library that stands in for a cheat's native module. It is NOT a
 * cheat: it only writes a marker so the oracle can tell it was mapped into the game process.
 * Because it is unsigned and lives outside the Java folder, the guard's module-trust gate
 * (ТЗ §6) must refuse to map it and close the client; without the guard it loads and the
 * marker proves the attack worked.
 *
 * Exports JNI_OnLoad so System.load() accepts it on every platform. The runner builds it
 * with whatever toolchain is present (cl / clang / gcc). */

#include <stdio.h>

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/* jint JNI_OnLoad(JavaVM*, void*) without pulling in jni.h: the JVM only needs the symbol
 * and a JNI version return value. */
EXPORT int JNI_OnLoad(void *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    fprintf(stderr, "ATTACK native mapped into the game process\n");
    fflush(stderr);
    return 0x00010008; /* JNI_VERSION_1_8 */
}
