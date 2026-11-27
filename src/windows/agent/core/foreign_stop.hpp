// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Stopping foreign code once it is found (ТЗ §5 «Чужой код в памяти», «Чужие потоки»).
//
// A hand-mapped image (manual map: memory allocated from another process, the sections copied,
// relocated and imports resolved by the injector, a thread started at its entry — no loader, so
// no load gate) was found but not stopped: the new thread's DLL_THREAD_ATTACH saw its start
// outside allowed code and requested the close, then returned — and the thread went on into the
// cheat. The close takes a while (the reason window, the report), and the cheat ran all that time.
// Memory found by the sweep ran on just the same.
//
// Now, when the close is real (the module's level is close, not report), the foreign code is made
// non-executable at once: the allocation it was found in and every other executable region outside
// images that the table does not know (a mapper's loader stub sits in an allocation of its own).
// Made read-only rather than inaccessible, so the report can still hash it. A thread that then runs
// into such memory faults; a vectored handler, first in the chain, keeps it there — parked, never
// returning into the cheat — while the close goes on; the watchdog ends the process if it stalls.
#pragma once

#include <cstdint>

namespace mebet::stop {

// The vectored handler. Installed with the hooks, before anything is judged.
void install();

// Code at `address` is foreign and the client is being closed for it: makes the allocation that
// holds it, and every executable non-image region the exec table does not know, non-executable.
// Allocation-free and lock-free (it runs inside DLL_THREAD_ATTACH). Returns how many regions it
// changed.
unsigned foreign_code(std::uintptr_t address);

// An image mapped around the loader: its executable pages, so a thread in it goes no further.
unsigned hidden_image(std::uintptr_t allocation_base);

// The address lies in memory this module has made non-executable.
bool stopped(std::uintptr_t address);

}  // namespace mebet::stop
