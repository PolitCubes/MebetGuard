// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/watchdog.hpp"

#include <atomic>
#include <cstdint>
#include <thread>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/win_util.hpp"

namespace mebet::watchdog {

namespace {

// Unbiased interrupt time in 100 ns units: sleep and hibernation do not count, so a laptop
// waking up is not a stalled guard.
std::uint64_t now_100ns() {
    ULONGLONG t = 0;
    QueryUnbiasedInterruptTime(&t);
    return t;
}

constexpr std::uint64_t kMs = 10000;
// The watchdog only sleeps 250 ms between checks and runs at high priority: this much silence
// means it is frozen or gone.
constexpr std::uint64_t kWatchdogSilentMax = 8000 * kMs;
// The worker can be busy for a while (a sweep over a big process, a slow disk), so its silence
// alone counts only after this long; suspended or ended is caught at once.
constexpr std::uint64_t kWorkerSilentMax = 30000 * kMs;
constexpr DWORD kTickMs = 250;
constexpr int kThreadSuspendCount = 35;  // THREADINFOCLASS, Windows 8.1+

std::atomic<std::uint64_t> g_beat_worker{0};
std::atomic<std::uint64_t> g_beat_watchdog{0};
// Query/synchronize copies only: code in the process that finds them can wait on them, not
// suspend or end the thread.
HANDLE g_worker = nullptr;
HANDLE g_watchdog = nullptr;
std::atomic<bool> g_ending{false};
std::atomic<bool> g_told{false};  // report level: one report, the game keeps running
using ShutdownFn = BOOLEAN(NTAPI*)();
ShutdownFn g_dll_shutdown = nullptr;  // ntdll!RtlDllShutdownInProgress

// 1 suspended, 0 running, -1 unknown (the information class exists from Windows 8.1).
int suspended(HANDLE t) {
    const auto& a = nt::api();
    if (!a.NtQueryInformationThread) return -1;
    ULONG count = 0;
    if (!nt::ok(a.NtQueryInformationThread(t, kThreadSuspendCount, &count, sizeof(count), nullptr))) return -1;
    return count > 0 ? 1 : 0;
}

bool ended(HANDLE t) { return t && WaitForSingleObject(t, 0) == WAIT_OBJECT_0; }

bool silent(const std::atomic<std::uint64_t>& beat, std::uint64_t now, std::uint64_t max) {
    const std::uint64_t b = beat.load(std::memory_order_relaxed);
    return b && now > b && now - b > max;
}

// "[Mebet] closed: <id> (code <n>) <what>\n" without the CRT: the thread that froze the guard
// may hold the stdio or heap lock.
void write_close_line(const char* id, int code, const char* what) {
    char line[256];
    std::size_t n = 0;
    auto put = [&](const char* s) {
        while (*s && n + 1 < sizeof(line)) line[n++] = *s++;
    };
    put("[Mebet] closed: ");
    put(id);
    put(" (code ");
    char digits[12];
    int d = 0;
    unsigned v = static_cast<unsigned>(code);
    do {
        digits[d++] = static_cast<char>('0' + v % 10);
        v /= 10;
    } while (v && d < 11);
    while (d && n + 1 < sizeof(line)) line[n++] = digits[--d];
    put(") ");
    put(what);
    put("\n");
    DWORD written = 0;
    const HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    if (err && err != INVALID_HANDLE_VALUE) WriteFile(err, line, static_cast<DWORD>(n), &written, nullptr);
}

[[noreturn]] void kill_process(int code) {
    const auto& a = nt::api();
    if (a.NtTerminateProcess) a.NtTerminateProcess(nt::current_process(), static_cast<NTSTATUS>(code));
    TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
    for (;;) Sleep(INFINITE);
}

report::Event stalled_event(const char* what) {
    report::Event ev;
    ev.type = "close.guard_stalled";
    ev.level = report::Level::error;
    ev.title = std::string("Closed: guard thread stopped (") + what + ")";
    ev.fingerprint = {"close.guard_stalled", what};
    ev.tags.emplace_back("reason", "guard_stalled");
    return ev;
}

// Ends the process at once. From the watchdog thread the report gets a short chance first
// (on its own thread: the frozen worker may hold the reporter's lock); from a hook it does not.
[[noreturn]] void end_process(const char* what, bool try_report, int code) {
    bool expected = false;
    if (!g_ending.compare_exchange_strong(expected, true)) {
        for (;;) Sleep(INFINITE);  // another thread is ending the process
    }
    write_close_line(config::reason(config::Reason::guard_stalled).id, code, what);
    if (try_report) {
        std::atomic<bool> sent{false};
        report::Event ev = stalled_event(what);
        std::thread sender([&sent, ev]() mutable {
            report::Reporter::instance().send_now(std::move(ev), 1500);
            sent.store(true);
        });
        for (int i = 0; i < 100 && !sent.load(); ++i) Sleep(20);
        if (sender.joinable()) sender.detach();
    }
    kill_process(code);
}

void on_stall(const char* what, bool try_report) {
    if (config::closes(config::Module::guard_watchdog)) {
        end_process(what, try_report, config::reason(config::Reason::guard_stalled).exit_code);
    }
    if (try_report && !g_told.exchange(true)) guard::defer_event(stalled_event(what));  // report level
}

DWORD WINAPI watchdog_main(void*) {
    for (;;) {
        const std::uint64_t now = now_100ns();
        g_beat_watchdog.store(now, std::memory_order_relaxed);
        if (!guard::closing()) {
            if (ended(g_worker)) on_stall("worker thread ended", true);
            if (suspended(g_worker) == 1) on_stall("worker thread suspended", true);
            if (silent(g_beat_worker, now, kWorkerSilentMax)) on_stall("worker thread silent", true);
        } else if (ended(g_worker) || suspended(g_worker) == 1) {
            // A close is pending and the worker carries it out. Frozen or killed in the middle,
            // it would leave the game running behind that close: end it with the close's code.
            write_close_line("pending_close", guard::pending_exit_code(), "worker thread stopped during the close");
            kill_process(guard::pending_exit_code());
        }
        Sleep(kTickMs);
    }
}

HANDLE query_copy(HANDLE t) {
    HANDLE out = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), t, GetCurrentProcess(), &out,
                         SYNCHRONIZE | THREAD_QUERY_INFORMATION, FALSE, 0))
        out = nullptr;
    return out;
}

}  // namespace

void start(HANDLE worker) {
    if (!worker) return;
    g_dll_shutdown = reinterpret_cast<ShutdownFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDllShutdownInProgress")));
    g_worker = query_copy(worker);
    CloseHandle(worker);
    if (!g_worker || !config::enabled(config::Module::guard_watchdog)) return;
    const std::uint64_t now = now_100ns();
    g_beat_worker.store(now);
    g_beat_watchdog.store(now);
    HANDLE w = CreateThread(nullptr, 0, &watchdog_main, nullptr, CREATE_SUSPENDED, nullptr);
    if (!w) {
        on_stall("watchdog thread could not start", true);
        return;
    }
    SetThreadPriority(w, THREAD_PRIORITY_HIGHEST);
    g_watchdog = query_copy(w);
    ResumeThread(w);
    CloseHandle(w);
}

void worker_tick() {
    const std::uint64_t now = now_100ns();
    g_beat_worker.store(now, std::memory_order_relaxed);
    if (!g_watchdog || guard::closing()) return;
    // The worker is alive, so the regular close runs (window, report, exit code).
    const char* what = nullptr;
    if (ended(g_watchdog)) what = "watchdog thread ended";
    else if (suspended(g_watchdog) == 1) what = "watchdog thread suspended";
    else if (silent(g_beat_watchdog, now, kWatchdogSilentMax)) what = "watchdog thread silent";
    if (what) guard::signal(config::Module::guard_watchdog, config::Reason::guard_stalled, win::wide(what), stalled_event(what));
}

void check_from_hook() {
    if (!g_watchdog) return;
    const std::uint64_t now = now_100ns();
    if (!silent(g_beat_watchdog, now, kWatchdogSilentMax)) return;  // the fast path
    if (!silent(g_beat_worker, now, kWatchdogSilentMax)) return;      // the worker deals with it
    if (guard::shutting_down() || (g_dll_shutdown && g_dll_shutdown())) return;
    if (guard::closing()) {
        // A close is pending, but neither guard thread is left to carry it out.
        write_close_line("pending_close", guard::pending_exit_code(), "guard threads stopped during the close");
        kill_process(guard::pending_exit_code());
    }
    if (config::closes(config::Module::guard_watchdog)) on_stall("both guard threads silent", false);
}

}  // namespace mebet::watchdog
