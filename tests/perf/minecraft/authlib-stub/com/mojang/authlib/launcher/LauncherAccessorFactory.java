// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Benchmark-only stand-in: the client's authlib asks the running launcher for profiles and
// skins; without a launcher every lookup simply fails and the game uses the default skin.
package com.mojang.authlib.launcher;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class LauncherAccessorFactory {
    public static LauncherAccessor create() {
        return new LauncherAccessor() {
            public void selfTest() {}

            public void error(Throwable t) {}

            public void debug(String s, Object... args) {}

            public CompletableFuture<GenericGameProfile> findByUsername(String name) {
                return failed();
            }

            public CompletableFuture<GenericGameProfile> findByUUID(UUID id) {
                return failed();
            }

            public CompletableFuture<Boolean> joinServerAsync(String a, String b, String c) {
                return CompletableFuture.completedFuture(Boolean.FALSE);
            }

            public CompletableFuture<Boolean> joinServerAsync(UUID a, String b, String c) {
                return CompletableFuture.completedFuture(Boolean.FALSE);
            }

            public CompletableFuture<GenericGameProfile> checkServerAsync(String a, String b, String c) {
                return failed();
            }
        };
    }

    static <T> CompletableFuture<T> failed() {
        CompletableFuture<T> f = new CompletableFuture<>();
        f.completeExceptionally(new java.io.IOException("benchmark: no launcher"));
        return f;
    }
}
