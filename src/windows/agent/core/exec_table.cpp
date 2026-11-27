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

struct OpSlot {
    std::atomic<DWORD> tid{0};
    std::atomic<std::uint64_t> since_ms{0};
};
constexpr int kOpSlots = 64;
OpSlot g_ops[kOpSlots];

}  // namespace

void allow(std::uintptr_t begin, std::uintptr_t end, const Owner& owner) {
    // Merging keeps the JIT code cache (committed piece by piece by jvm.dll) one entry.
    table().add(begin, end, owner, true);
}

namespace {
struct Forgotten {
    std::uintptr_t begin, end;
    std::uint64_t generation;
};
constexpr std::size_t kForgottenKept = 256;
struct ForgottenRing {
    SRWLOCK lock = SRWLOCK_INIT;
    Forgotten items[kForgottenKept] = {};
    std::uint64_t generation = 0;
};
ForgottenRing* const g_forgotten = new ForgottenRing();  // leaked: hooks use it while the process exits
}  // namespace

void forget(std::uintptr_t begin, std::uintptr_t end) {
    table().remove(begin, end);
    ForgottenRing& r = *g_forgotten;
    AcquireSRWLockExclusive(&r.lock);
    ++r.generation;
    r.items[r.generation % kForgottenKept] = Forgotten{begin, end, r.generation};
    ReleaseSRWLockExclusive(&r.lock);
}

std::uint64_t forget_generation() {
    ForgottenRing& r = *g_forgotten;
    AcquireSRWLockShared(&r.lock);
    const std::uint64_t g = r.generation;
    ReleaseSRWLockShared(&r.lock);
    return g;
}

bool forgotten_since(std::uintptr_t begin, std::uintptr_t end, std::uint64_t generation) {
    ForgottenRing& r = *g_forgotten;
    bool hit = false;
    AcquireSRWLockShared(&r.lock);
    // More forgets since than the history keeps: those it lost could be the one asked about, and none
    // is taken for it (the caller looks at the memory itself) — an overflow a cheat could cause on
    // purpose must not count as "forgotten".
    if (r.generation - generation < kForgottenKept) {
        for (const Forgotten& f : r.items)
            if (f.generation > generation && f.begin < end && f.end > begin) hit = true;
    }
    ReleaseSRWLockShared(&r.lock);
    return hit;
}

bool find(std::uintptr_t addr, Owner* out) {
    RangeSet<Owner>::Entry e{};
    if (!table().find(addr, &e)) return false;
    if (out) *out = e.payload;
    return true;
}

bool covers(std::uintptr_t begin, std::uintptr_t end) { return table().covers(begin, end); }
bool overlaps(std::uintptr_t begin, std::uintptr_t end) { return table().overlaps(begin, end); }

int op_begin() {
    const DWORD me = GetCurrentThreadId();
    const std::uint64_t now = GetTickCount64();
    for (int i = 0; i < kOpSlots; ++i) {
        DWORD free_slot = 0;
        if (g_ops[i].tid.load(std::memory_order_relaxed) == 0 &&
            g_ops[i].tid.compare_exchange_strong(free_slot, me, std::memory_order_acq_rel)) {
            g_ops[i].since_ms.store(now, std::memory_order_release);
            return i;
        }
    }
    return -1;  // 64 calls at once: this one is not waited for — the sweep looks again anyway
}

void op_end(int slot) {
    if (slot < 0 || slot >= kOpSlots) return;
    g_ops[slot].since_ms.store(0, std::memory_order_release);
    g_ops[slot].tid.store(0, std::memory_order_release);
}

bool live_op_within(std::uint64_t max_ms) {
    const std::uint64_t now = GetTickCount64();
    for (OpSlot& s : g_ops) {
        const DWORD tid = s.tid.load(std::memory_order_acquire);
        const std::uint64_t since = s.since_ms.load(std::memory_order_acquire);
        if (!tid || !since || now - since >= max_ms) continue;
        // A thread killed inside a hook leaves its slot taken for good: not a call in flight.
        const HANDLE h = OpenThread(SYNCHRONIZE, FALSE, tid);
        if (!h) continue;
        const bool alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
        CloseHandle(h);
        if (alive) return true;
    }
    return false;
}

}  // namespace mebet::exec
