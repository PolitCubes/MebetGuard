// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// The six ntdll hooks of the agent (ТЗ §5 «Какие API»): NtCreateSection (the load gate),
// NtMapViewOfSection (safety net, executable mappings), NtUnmapViewOfSection,
// NtAllocateVirtualMemory / NtProtectVirtualMemory / NtFreeVirtualMemory (executable
// memory accounting). Every hook has a fast path of one check; LdrLoadDll is not hooked.
#pragma once

#include <cstdint>
#include <string>

namespace mebet::hooks {

// Installs all six in one Detours transaction. Returns false and names the failed function.
bool install(std::string* failed);

// Canary round for the self-check: calls each hooked function through its ntdll entry
// with arguments only our hook recognizes. Returns the bit mask of hooks that answered
// (bit i = hook i ran); 0x3F means all six are in place.
unsigned canary_round();

struct EntryCheck {
    const char* name;
    bool bytes_same;           // entry bytes equal to what the commit wrote
    std::uintptr_t first_jump; // where the entry jumps now (0 if not a jump)
};
// Reads the current entry bytes of every hooked function.
void check_entries(EntryCheck out[6]);
std::string entry_bytes_hex(int index, bool expected);

constexpr unsigned kAllHooks = 0x3F;

}  // namespace mebet::hooks
