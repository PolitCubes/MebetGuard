// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Watchdog over the guard's own threads.
//
// Every periodic check (memory, threads, debugger, hook self-check) and the controlled close
// run on one worker thread. Frozen (SuspendThread) or killed (TerminateThread), it took the
// whole guard down with it, and a detected cheat no longer even closed the game: the hook
// denied the operation, but nobody was left to carry the close out. Now three parties watch
// each other:
//   - the worker beats on every loop and checks the watchdog thread;
//   - the watchdog thread beats every 250 ms and checks the worker: ended, suspended, or
//     silent for too long;
//   - every NT hook, on whatever thread it runs, compares the two beats: when neither guard
//     thread has beaten for several seconds, both are frozen and the hook ends the process.
// A stalled guard ends the process with guard_stalled (225) without needing the worker.
//
// Silence counts only while the one who watches was running itself: a game paused as a whole
// (Suspend in a task manager) and resumed is not a stalled guard. And the thread that ends the
// process does nothing before the kill that a frozen thread could block.
#pragma once

#include "nt.hpp"

namespace mebet::watchdog {

// Takes the worker's thread handle (keeps a query/synchronize copy) and starts the watchdog.
void start(HANDLE worker);
// The worker, once per loop: heartbeat + checks the watchdog thread.
void worker_tick();
// The worker, inside a task that can run long (file after file on a slow disk): heartbeat only.
void worker_beat();
// Every NT hook: one load and one compare on the fast path; no TLS, no locks, no allocation.
void check_from_hook();

}  // namespace mebet::watchdog
