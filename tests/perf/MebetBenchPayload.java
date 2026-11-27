// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
//
// The class MebetBench defines over and over in fresh class loaders (the class_load benchmark):
// a few fields and methods, so parsing, verification and linking have something to chew on.

public class MebetBenchPayload {
    private int a = 1;
    private long b = 2;
    private final String name = "payload";
    private final int[] table = new int[16];

    public MebetBenchPayload() {
        for (int i = 0; i < table.length; i++) table[i] = i * a + (int) b;
    }

    public int sum() {
        int s = 0;
        for (int v : table) s += v;
        return s;
    }

    public String describe() {
        return name + ":" + sum();
    }

    @Override
    public int hashCode() {
        return sum() ^ name.hashCode();
    }
}
