// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/exec_table.hpp"

#include <atomic>

#include "core/range_set.hpp"

namespace mebet::exec {

namespace {

// Not a function-local static: every use of one reads the TLS block of the thread, and the hooks
// look regions up on threads that have none (nt_hooks.cpp). Leaked on purpose.
std::atomic<RangeSet<Owner>*> g_table{nullptr};

RangeSet<Owner>& table() {
    RangeSet<Owner>* t = g_table.load(std::memory_order_acquire);
    if (t) return *t;
    auto* fresh = new RangeSet<Owner>();
    if (g_table.compare_exchange_strong(t, fresh, std::memory_order_acq_rel)) return *fresh;
    delete fresh;
    return *t;
}

std::atomic<long> g_in_flight{0};

}  // namespace

void allow(std::uintptr_t begin, std::uintptr_t end, const Owner& owner) {
    // Merging keeps the JIT code cache (committed piece by piece by jvm.dll) one entry.
    table().add(begin, end, owner, true);
}

void forget(std::uintptr_t begin, std::uintptr_t end) { table().remove(begin, end); }

bool find(std::uintptr_t addr, Owner* out) {
    RangeSet<Owner>::Entry e{};
    if (!table().find(addr, &e)) return false;
    if (out) *out = e.payload;
    return true;
}

bool covers(std::uintptr_t begin, std::uintptr_t end) { return table().covers(begin, end); }
bool overlaps(std::uintptr_t begin, std::uintptr_t end) { return table().overlaps(begin, end); }

void op_begin() { g_in_flight.fetch_add(1, std::memory_order_acq_rel); }
void op_end() { g_in_flight.fetch_sub(1, std::memory_order_acq_rel); }
bool ops_in_flight() { return g_in_flight.load(std::memory_order_acquire) != 0; }

}  // namespace mebet::exec
