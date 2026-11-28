// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/foreign_stop.hpp"

#include <atomic>

#include "core/exec_table.hpp"
#include "nt.hpp"

namespace mebet::stop {

namespace {

// Ranges made non-executable. Fixed, never freed: the handler reads them on any thread, the
// writers run inside DllMain. A writer claims a slot, stores the end, then publishes the begin.
struct Slot {
    std::atomic<std::uintptr_t> begin{0};
    std::atomic<std::uintptr_t> end{0};
};
constexpr unsigned kSlots = 512;
Slot g_slots[kSlots];
std::atomic<unsigned> g_used{0};
std::atomic<bool> g_overflow{false};

void remember(std::uintptr_t begin, std::uintptr_t end) {
    const unsigned i = g_used.fetch_add(1, std::memory_order_acq_rel);
    if (i >= kSlots) {
        g_overflow.store(true, std::memory_order_release);
        return;
    }
    g_slots[i].end.store(end, std::memory_order_release);
    g_slots[i].begin.store(begin, std::memory_order_release);
}

bool executable(const MEMORY_BASIC_INFORMATION& m) {
    return m.State == MEM_COMMIT && (m.Protect & 0xF0) && !(m.Protect & PAGE_GUARD);
}

// Executable memory the table vouches for: recorded with a trust (the JIT, an overlay's thunks,
// the guard's own trampolines). Recorded as unknown (asked for before the start-up scan by code no
// module owns) is foreign, like memory never recorded at all.
bool vouched(std::uintptr_t begin, std::uintptr_t end) {
    if (!exec::overlaps(begin, end)) return false;
    exec::Owner o{};
    return !(exec::find(begin, &o) && o.trust == trust::Trust::unknown);
}

bool make_read_only(const MEMORY_BASIC_INFORMATION& m) {
    DWORD old = 0;
    if (!VirtualProtect(m.BaseAddress, m.RegionSize, PAGE_READONLY, &old)) return false;
    const auto b = reinterpret_cast<std::uintptr_t>(m.BaseAddress);
    remember(b, b + m.RegionSize);
    return true;
}

// The handler keeps a thread that runs into stopped memory from going any further. Only an
// instruction fetched from there counts (the address of the fault is the instruction's own): the
// guard reads that memory for the report, and a fault of its own reading must not park it.
// When more regions were stopped than the slots hold, any execution fault in memory that is
// neither an image nor vouched for is taken for one of them.
LONG CALLBACK on_exception(EXCEPTION_POINTERS* e) {
    if (!e || !e->ExceptionRecord || e->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    const auto pc = reinterpret_cast<std::uintptr_t>(e->ExceptionRecord->ExceptionAddress);
    bool park = stopped(pc);
    if (!park && g_overflow.load(std::memory_order_acquire) && e->ExceptionRecord->NumberParameters >= 1 &&
        e->ExceptionRecord->ExceptionInformation[0] == 8 /* execute */) {
        MEMORY_BASIC_INFORMATION m{};
        park = VirtualQuery(reinterpret_cast<void*>(pc), &m, sizeof(m)) && m.Type != MEM_IMAGE &&
               !vouched(pc, pc + 1);
    }
    if (!park) return EXCEPTION_CONTINUE_SEARCH;
    // Never back into the cheat. The close is already on its way (whoever stopped this memory asked
    // for it); the watchdog ends the process if it is not carried out in time.
    for (;;) SleepEx(INFINITE, FALSE);
}

}  // namespace

namespace {
std::atomic<void*> g_handler{nullptr};
}  // namespace

void install() {
    static std::atomic<bool> done{false};
    if (!done.exchange(true)) g_handler.store(AddVectoredExceptionHandler(1, &on_exception));
}

void move_first() {
    // Added first in the chain, then the JVM added its own first while it started (os::init_2): a
    // Java thread led into stopped memory met HotSpot's handler before ours, and the JVM went down
    // with a crash report instead of the thread being parked. Removed and added again, ours is first.
    void* old = g_handler.exchange(nullptr);
    if (!old) return;
    void* fresh = AddVectoredExceptionHandler(1, &on_exception);
    RemoveVectoredExceptionHandler(old);
    g_handler.store(fresh ? fresh : nullptr);
}

bool stopped(std::uintptr_t address) {
    unsigned n = g_used.load(std::memory_order_acquire);
    if (n > kSlots) n = kSlots;
    for (unsigned i = 0; i < n; ++i) {
        const std::uintptr_t b = g_slots[i].begin.load(std::memory_order_acquire);
        if (!b) continue;  // claimed, not yet published
        if (address >= b && address < g_slots[i].end.load(std::memory_order_acquire)) return true;
    }
    return false;
}

unsigned hidden_image(std::uintptr_t allocation_base) {
    unsigned changed = 0;
    std::uintptr_t pos = allocation_base;
    for (int guard_count = 0; guard_count < 4096; ++guard_count) {
        MEMORY_BASIC_INFORMATION m{};
        if (!VirtualQuery(reinterpret_cast<void*>(pos), &m, sizeof(m)) ||
            reinterpret_cast<std::uintptr_t>(m.AllocationBase) != allocation_base || m.State == MEM_FREE)
            break;
        if (executable(m) && make_read_only(m)) ++changed;
        const std::uintptr_t next = reinterpret_cast<std::uintptr_t>(m.BaseAddress) + m.RegionSize;
        if (next <= pos) break;
        pos = next;
    }
    return changed;
}

unsigned foreign_code(std::uintptr_t address) {
    unsigned changed = 0;
    MEMORY_BASIC_INFORMATION at{};
    if (address && VirtualQuery(reinterpret_cast<void*>(address), &at, sizeof(at)) && at.Type == MEM_IMAGE)
        changed += hidden_image(reinterpret_cast<std::uintptr_t>(at.AllocationBase));

    // Every executable region outside images that nothing vouches for. A manual mapper leaves more
    // than one: the image itself, the stub that relocated it and called its entry, a thunk or two.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto pos = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto max = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    if (pos < 0x10000) pos = 0x10000;
    while (pos < max) {
        MEMORY_BASIC_INFORMATION m{};
        if (!VirtualQuery(reinterpret_cast<void*>(pos), &m, sizeof(m))) break;
        const auto base = reinterpret_cast<std::uintptr_t>(m.BaseAddress);
        const std::uintptr_t next = base + m.RegionSize;
        if (next <= pos) break;
        pos = next;
        if (m.Type == MEM_IMAGE || !executable(m) || vouched(base, next)) continue;
        if (make_read_only(m)) ++changed;
    }
    return changed;
}

}  // namespace mebet::stop
