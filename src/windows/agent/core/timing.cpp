// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/timing.hpp"

#include <cstdio>

#include "json_writer.hpp"

namespace mebet::timing {

namespace {
Counter g_counters[static_cast<int>(config::Module::count_)];
}

Counter& counter(config::Module m) { return g_counters[static_cast<int>(m)]; }

double frequency_per_ms() {
    static const double f = [] {
        LARGE_INTEGER q;
        QueryPerformanceFrequency(&q);
        return static_cast<double>(q.QuadPart) / 1000.0;
    }();
    return f;
}

std::string summary() {
    std::string out;
    char buf[96];
    for (int i = 0; i < static_cast<int>(config::Module::count_); ++i) {
        const auto calls = g_counters[i].calls.load(std::memory_order_relaxed);
        if (!calls) continue;
        const double ms = static_cast<double>(g_counters[i].ticks.load(std::memory_order_relaxed)) / frequency_per_ms();
        std::snprintf(buf, sizeof(buf), "%s%s=%.1fms/%llu", out.empty() ? "" : " ", config::kModules[i].id, ms,
                      static_cast<unsigned long long>(calls));
        out += buf;
    }
    return out;
}

std::string summary_json() {
    JsonWriter w;
    w.begin_object();
    for (int i = 0; i < static_cast<int>(config::Module::count_); ++i) {
        const auto calls = g_counters[i].calls.load(std::memory_order_relaxed);
        if (!calls) continue;
        const double ms = static_cast<double>(g_counters[i].ticks.load(std::memory_order_relaxed)) / frequency_per_ms();
        w.key(config::kModules[i].id).begin_object();
        w.key("ms").value_double(ms);
        w.field("calls", static_cast<std::uint64_t>(calls));
        w.end_object();
    }
    w.end_object();
    return w.take();
}

}  // namespace mebet::timing
