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

#include <cstdint>

#include "nt.hpp"

namespace mebet::watchdog {

// Takes the worker's thread handle (keeps a query/synchronize copy) and starts the watchdog.
void start(HANDLE worker);
// The worker, as its very first step: the first heartbeat. Until then it has "not started yet",
// which is not silence — so the sooner the better: stopped before its first beat, it would be
// noticed only after the long limit of a start.
void worker_started();
// The worker, once per loop: heartbeat + checks the watchdog thread.
void worker_tick();
// The worker, inside a task that can run long (file after file on a slow disk, a big file chunk
// by chunk): heartbeat only. Does nothing on any other thread, so shared code may call it.
void worker_beat();
// Around one call that can take long and shows nothing meanwhile (a signature check, opening a
// file on a slow disk): on the worker thread its silence gets a much longer limit while the
// scope is open; on any other thread it does nothing. A healthy game on a cold hard disk was
// closed with guard_stalled in the middle of such a call — or with it instead of the code of
// the detection whose file was being hashed.
class SlowWork {
public:
    SlowWork();
    ~SlowWork();
    SlowWork(const SlowWork&) = delete;
    SlowWork& operator=(const SlowWork&) = delete;

private:
    bool on_worker_;
};
// Every NT hook: one load and one compare on the fast path; no TLS, no locks, no allocation.
void check_from_hook();
// A clock that stands still while the whole process is held: the time, in 100 ns units, the
// watchdog thread has seen the process running (it looks every 250 ms; a longer gap counts as
// one second). 0 until the watchdog runs. For limits that must not count a pause of the game.
std::uint64_t witnessed_100ns();

}  // namespace mebet::watchdog
