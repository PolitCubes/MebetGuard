// Step 1 of the wrapper (ТЗ §4): DLL search order, extension points, environment.
// Runs before any DLL other than ntdll/kernel32/kernelbase is in the process, so it may
// use only kernel32 (the wrapper imports nothing else, ТЗ §4 «Импорты exe»).
#pragma once

#include "boot_info.hpp"

namespace mebet::win {

void harden_process(BootInfo& boot);

// Windows 8+ policy query used by the agent to confirm step 1 (and to report if not).
bool extension_points_disabled();

}  // namespace mebet::win
