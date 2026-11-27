// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// The ntdll hooks of the agent (ТЗ §5 «Какие API»): NtCreateSection (the load gate),
// NtMapViewOfSection (safety net, executable mappings), NtUnmapViewOfSection,
// NtAllocateVirtualMemory / NtProtectVirtualMemory / NtFreeVirtualMemory (executable
// memory accounting) — and, beyond the six of the ТЗ, their Ex variants where ntdll has them
// (NtCreateSectionEx, NtMapViewOfSectionEx, NtUnmapViewOfSectionEx, NtAllocateVirtualMemoryEx):
// the same judge behind every door. Every hook has a fast path of one check; LdrLoadDll is not
// hooked.
#pragma once

#include <cstdint>
#include <string>

namespace mebet::hooks {

constexpr int kHookCount = 10;  // the six of the ТЗ, then the four Ex variants

// Installs all of them that ntdll has in one Detours transaction (the six of the ТЗ must be there).
// Returns false and names the failed function.
bool install(std::string* failed);

// The hooks install() put in place, as a bit mask (bit i = hook i).
unsigned installed_mask();

// Canary round for the self-check: calls each installed hook through its ntdll entry with
// arguments only our hook recognizes. Returns the bit mask of hooks that answered (bit i =
// hook i ran); installed_mask() means all of them are in place.
unsigned canary_round();

struct EntryCheck {
    const char* name;
    bool present;              // hooked (an Ex variant ntdll does not have is not)
    bool bytes_same;           // entry bytes equal to what the commit wrote
    std::uintptr_t first_jump; // where the entry jumps now (0 if not a jump)
};
// Reads the current entry bytes of every hooked function.
void check_entries(EntryCheck out[kHookCount]);
std::string entry_bytes_hex(int index, bool expected);

}  // namespace mebet::hooks
