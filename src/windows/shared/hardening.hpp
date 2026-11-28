// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Step 1 of the wrapper (ТЗ §4): DLL search order, extension points, environment.
// Runs before any DLL other than ntdll/kernel32/kernelbase is in the process, so it may
// use only kernel32 (the wrapper imports nothing else, ТЗ §4 «Импорты exe»).
#pragma once

#include "boot_info.hpp"

namespace mebet::win {

void harden_process(BootInfo& boot);

// The process DACL of the agent (process/dacl.cpp), set first thing in the wrapper:
// no window before step 6 in which a program of the same user opens the game for its memory.
void protect_process_early();

// Windows 8+ policy query used by the agent to confirm step 1 (and to report if not).
bool extension_points_disabled();

}  // namespace mebet::win
