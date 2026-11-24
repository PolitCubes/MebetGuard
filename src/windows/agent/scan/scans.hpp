// Sweeps of the process (ТЗ §5): the one-time start-up check of everything that got in
// before the agent, and the periodic sweeps of memory regions and threads.
#pragma once

#include <cstdint>

namespace mebet::scan {

// ТЗ §5 «Проверка при старте агента»: every loader module, then one full pass over
// memory and threads. Runs after the hooks are installed. Closes before the start.
void startup_check();

// Periodic (worker): executable private/mapped memory not in the table, images outside
// the loader list, threads that start outside allowed code.
void memory_sweep();
void thread_sweep();

// Called from DLL_THREAD_ATTACH of the agent: check the start of the new thread and
// restrict its access rights (ТЗ §7 «Права в DACL»).
void on_thread_attach();

// Is this address inside allowed code (a module or an allowed executable region)?
bool allowed_code(std::uintptr_t address);

}  // namespace mebet::scan
