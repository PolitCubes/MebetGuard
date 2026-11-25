// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Own-time counter of every module (ТЗ §5: «счётчик собственного времени», §14 замеры).
// One QueryPerformanceCounter pair per measured block; never used on the fast path of a hook.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include "config.hpp"
#include "nt.hpp"

namespace mebet::timing {

struct Counter {
    std::atomic<std::uint64_t> ticks{0};
    std::atomic<std::uint64_t> calls{0};
};

Counter& counter(config::Module m);
double frequency_per_ms();

class Scope {
public:
    explicit Scope(config::Module m) : m_(m) { QueryPerformanceCounter(&start_); }
    ~Scope() {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        Counter& c = counter(m_);
        c.ticks.fetch_add(static_cast<std::uint64_t>(now.QuadPart - start_.QuadPart), std::memory_order_relaxed);
        c.calls.fetch_add(1, std::memory_order_relaxed);
    }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

private:
    config::Module m_;
    LARGE_INTEGER start_;
};

// "module=12.3ms/45 …" for the exit summary and the reports.
std::string summary();
// JSON object {"module": {"ms": 12.3, "calls": 45}, …}
std::string summary_json();

}  // namespace mebet::timing
