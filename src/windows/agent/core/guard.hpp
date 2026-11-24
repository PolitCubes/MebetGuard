// Guard core: the controlled close (ТЗ §3 «Как закрываем»), the worker thread and the
// routing of every signal by the level of its module.
//
// Hooks never end the process (ТЗ §5): they deny the operation and call request_close();
// the worker hides the game, shows the reason window, sends the report and terminates
// with the reason's exit code.
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

// Text of a reason in the player's language with {file} filled in.
std::wstring reason_text(config::Reason reason, const std::wstring& detail, std::wstring* title);

}  // namespace mebet::guard
