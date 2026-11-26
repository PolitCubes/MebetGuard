// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Guard core: the controlled close (ТЗ §3 «Как закрываем»), the worker thread and the
// routing of every signal by the level of its module.
//
// Detections never end the process themselves (ТЗ §5): a hook denies the operation and calls
// request_close(); the worker hides the game, shows the reason window, sends the report and
// terminates with the reason's exit code. The one exception is the watchdog (core/watchdog.hpp):
// when the guard's own threads are stopped, or a close is not carried out in time, there is no
// worker left to rely on, and the watchdog — from its thread or from any hook — ends the
// process itself.
#pragma once

#include <functional>
#include <string>

#include "boot_info.hpp"
#include "config.hpp"
#include "nt.hpp"
#include "report.hpp"

namespace mebet::guard {

void init(const BootInfo* boot);
const BootInfo& boot();

bool closing();
// The close itself has started (run_close): the reason window may be on screen.
bool close_running();
// The report of the pending close, for the watchdog when it ends a close that did not run in time.
// Sent at most once, by this or by the close itself.
void send_pending_close_report(unsigned timeout_ms);
bool shutting_down();  // DLL_PROCESS_DETACH: hooks pass everything through
void set_shutting_down();

// The start-up scan is done; before that the memory hooks only record (ТЗ §5: modules
// loaded before the agent are judged once by the start-up check, not by the hooks).
bool armed();
void arm();

void request_close(config::Reason reason, const std::wstring& detail, report::Event ev);
[[noreturn]] void close_now(config::Reason reason, const std::wstring& detail, report::Event ev);

// Report-only events from places that must not send (hooks, loader callbacks).
void defer_event(report::Event ev);
// Work that must not run inside a hook (file cards, sending): runs on the worker thread.
void defer(std::function<void()> fn);

// Routes a detection by the configured level of its module.
void signal(config::Module m, config::Reason reason, const std::wstring& detail, report::Event ev);

using Task = void (*)();
void add_periodic(const char* name, unsigned interval_ms, Task task, config::Module m);
void start_worker();
DWORD worker_thread_id();

// Exit code to force if the process exits while a close is pending.
int pending_exit_code();
// Id of the reason of the pending close ("untrusted_module"), nullptr when none.
const char* pending_reason_id();

// Text of a reason in the player's language with {file} filled in.
std::wstring reason_text(config::Reason reason, const std::wstring& detail, std::wstring* title);

}  // namespace mebet::guard
