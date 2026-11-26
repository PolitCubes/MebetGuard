// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/watchdog.hpp"

#include <atomic>
#include <cstdint>

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
// alone counts only after this long; ended is caught at once, suspended within a second.
constexpr std::uint64_t kWorkerSilentMax = 30000 * kMs;
// A guard thread seen suspended on consecutive looks for this long is frozen. One look is not
// enough: while the system suspends or resumes the whole process, thread by thread, one guard
// thread can see the other suspended for an instant.
constexpr std::uint64_t kFrozenMin = 750 * kMs;
// The most one look may add to what its thread has witnessed (see Witness).
constexpr std::uint64_t kWatchdogStep = 1000 * kMs;  // the watchdog looks every 250 ms
constexpr std::uint64_t kWorkerStep = 2000 * kMs;    // the worker at least once a second when idle
constexpr std::uint64_t kHookStep = 1000 * kMs;
constexpr DWORD kTickMs = 250;
constexpr DWORD kHookSecondLookMs = 100;
constexpr DWORD kLastWordsReportMs = 2000;  // the line and the report
constexpr DWORD kLastWordsLineMs = 250;     // the line only
constexpr int kThreadSuspendCount = 35;  // THREADINFOCLASS, Windows 8.1+

std::atomic<std::uint64_t> g_beat_worker{0};
std::atomic<std::uint64_t> g_beat_watchdog{0};
// Query/synchronize copies only: code in the process that finds them can wait on them, not
// suspend or end the thread. Read by the worker and by every hook thread, hence atomic.
std::atomic<HANDLE> g_worker{nullptr};
std::atomic<HANDLE> g_watchdog{nullptr};
std::atomic<bool> g_ending{false};
std::atomic<bool> g_told{false};  // report level: one report, the game keeps running
// Time the watchdog thread has witnessed the process running (see witnessed_100ns); 0 = not started.
std::atomic<std::uint64_t> g_witnessed{0};
// What the hooks have witnessed of both guard threads being silent (see check_from_hook).
std::atomic<std::uint64_t> g_hook_last{0};
std::atomic<std::uint64_t> g_hook_beats{0};
std::atomic<std::uint64_t> g_hook_silent{0};
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

// How long another thread has been stopped, counted only while the observer itself was running.
// The whole process held for a minute (Suspend in a task manager, a dump tool, a machine that
// froze) stops the observer too: afterwards the beat of the other thread is a minute old, yet
// nobody stopped that thread on its own — it beats again as soon as it gets to run. The watchdog
// used to compare the beat with the clock and closed such a game with guard_stalled. So every
// look adds the time since the previous look, but never more than `step`: time the observer did
// not witness proves nothing. One observer thread per Witness, so no lock.
struct Witness {
    std::uint64_t last = 0;    // the previous look
    std::uint64_t beat = 0;    // the beat seen then
    std::uint64_t silent = 0;  // witnessed time without a new beat
    std::uint64_t frozen = 0;  // witnessed time suspended, on consecutive looks
    bool was_suspended = false;

    void look(std::uint64_t now, std::uint64_t current_beat, bool is_suspended, std::uint64_t step) {
        std::uint64_t dt = last && now > last ? now - last : 0;
        if (dt > step) dt = step;
        last = now;
        if (current_beat != beat) {
            beat = current_beat;
            silent = 0;
        } else {
            silent += dt;
        }
        frozen = is_suspended && was_suspended ? frozen + dt : 0;
        was_suspended = is_suspended;
    }
};

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

// The last words of a guard that ends the process itself: the line for the launcher log and,
// when asked, the report. Each of them can block for good — stderr is a console somebody is
// selecting text in, building the report takes the heap lock and sending it the lock of the
// reporter, and the thread that was frozen may hold either. The watchdog used to do all of that
// itself before the kill: blocked there, it never killed, and every other thread that noticed
// the stall then waited for it forever. So the words are said by a thread of their own, started
// together with the watchdog and parked until needed; whoever ends the process only wakes it,
// waits a limited time and kills. Nothing on that path allocates or takes a lock.
struct LastWords {
    const char* id = "";
    const char* what = "";
    int code = 0;
    bool report = false;
};
LastWords g_words;        // written once by the thread that won g_ending, before g_say is set
HANDLE g_say = nullptr;   // wakes the last-words thread
HANDLE g_said = nullptr;  // it has finished

DWORD WINAPI last_words_main(void*) {
    WaitForSingleObject(g_say, INFINITE);
    write_close_line(g_words.id, g_words.code, g_words.what);
    if (g_words.report) report::Reporter::instance().send_now(stalled_event(g_words.what), 1500);
    SetEvent(g_said);
    for (;;) Sleep(INFINITE);  // the caller ends the process
}

[[noreturn]] void end_process(const char* id, const char* what, int code, bool try_report) {
    bool expected = false;
    if (!g_ending.compare_exchange_strong(expected, true)) {
        // Another thread is ending the process — unless it was stopped half-way: give it the
        // time it may take, then finish the job.
        Sleep(kLastWordsReportMs + 1000);
        kill_process(code);
    }
    g_words.id = id;
    g_words.what = what;
    g_words.code = code;
    g_words.report = try_report;
    if (g_say && g_said) {
        SetEvent(g_say);
        WaitForSingleObject(g_said, try_report ? kLastWordsReportMs : kLastWordsLineMs);
    }
    kill_process(code);
}

void on_stall(const char* what, bool try_report) {
    if (config::closes(config::Module::guard_watchdog)) {
        end_process(config::reason(config::Reason::guard_stalled).id, what,
                    config::reason(config::Reason::guard_stalled).exit_code, try_report);
    }
    if (try_report && !g_told.exchange(true)) guard::defer_event(stalled_event(what));  // report level
}

DWORD WINAPI watchdog_main(void*) {
    Witness worker;
    std::uint64_t previous = now_100ns();
    g_witnessed.store(1, std::memory_order_relaxed);
    for (;;) {
        const std::uint64_t now = now_100ns();
        g_beat_watchdog.store(now, std::memory_order_relaxed);
        g_witnessed.fetch_add(now - previous > kWatchdogStep ? kWatchdogStep : now - previous, std::memory_order_relaxed);
        previous = now;
        const HANDLE w = g_worker.load(std::memory_order_acquire);
        worker.look(now, g_beat_worker.load(std::memory_order_relaxed), suspended(w) == 1, kWatchdogStep);
        if (!guard::closing()) {
            if (ended(w)) on_stall("worker thread ended", true);
            if (worker.frozen >= kFrozenMin) on_stall("worker thread suspended", true);
            if (worker.silent > kWorkerSilentMax) on_stall("worker thread silent", true);
        } else if (ended(w) || worker.frozen >= kFrozenMin) {
            // A close is pending and the worker carries it out. Frozen or killed in the middle,
            // it would leave the game running behind that close: end it with the code of the close.
            end_process("pending_close", "worker thread stopped during the close", guard::pending_exit_code(), false);
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
    const HANDLE worker_copy = query_copy(worker);
    CloseHandle(worker);
    if (!worker_copy || !config::enabled(config::Module::guard_watchdog)) return;
    g_worker.store(worker_copy, std::memory_order_release);
    const std::uint64_t now = now_100ns();
    g_beat_worker.store(now);
    g_beat_watchdog.store(now);
    // The last-words thread first: a stall found a moment later already has it.
    g_say = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_said = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_say && g_said) {
        if (HANDLE t = CreateThread(nullptr, 0, &last_words_main, nullptr, 0, nullptr)) CloseHandle(t);
    }
    // Started running, and its handle published only after that. Created suspended and published
    // first, it could be found "suspended" by the worker — already running — before it had ever
    // run, and a clean launch was closed with guard_stalled.
    HANDLE w = CreateThread(nullptr, 0, &watchdog_main, nullptr, 0, nullptr);
    if (!w) {
        on_stall("watchdog thread could not start", true);
        return;
    }
    SetThreadPriority(w, THREAD_PRIORITY_HIGHEST);
    g_watchdog.store(query_copy(w), std::memory_order_release);
    CloseHandle(w);
}

void worker_beat() { g_beat_worker.store(now_100ns(), std::memory_order_relaxed); }

std::uint64_t witnessed_100ns() { return g_witnessed.load(std::memory_order_relaxed); }

void worker_tick() {
    static Witness watchdog;  // the worker thread only
    const std::uint64_t now = now_100ns();
    g_beat_worker.store(now, std::memory_order_relaxed);
    const HANDLE w = g_watchdog.load(std::memory_order_acquire);
    if (!w) return;
    watchdog.look(now, g_beat_watchdog.load(std::memory_order_relaxed), suspended(w) == 1, kWorkerStep);
    if (guard::closing()) return;
    // The worker is alive, so the regular close runs (window, report, exit code).
    const char* what = nullptr;
    if (ended(w)) what = "watchdog thread ended";
    else if (watchdog.frozen >= kFrozenMin) what = "watchdog thread suspended";
    else if (watchdog.silent > kWatchdogSilentMax) what = "watchdog thread silent";
    if (!what) return;
    // Report level: one report, not one on every loop (each of them wakes this loop again).
    if (!config::closes(config::Module::guard_watchdog) && g_told.exchange(true)) return;
    guard::signal(config::Module::guard_watchdog, config::Reason::guard_stalled, win::wide(what), stalled_event(what));
}

void check_from_hook() {
    const HANDLE watchdog = g_watchdog.load(std::memory_order_acquire);
    if (!watchdog) return;
    const std::uint64_t now = now_100ns();
    if (!silent(g_beat_watchdog, now, kWatchdogSilentMax)) return;  // the fast path
    if (!silent(g_beat_worker, now, kWatchdogSilentMax)) return;      // the worker deals with it
    if (guard::shutting_down() || (g_dll_shutdown && g_dll_shutdown())) return;
    if (guard::closing()) {
        // A close is pending, but neither guard thread is left to carry it out.
        end_process("pending_close", "guard threads stopped during the close", guard::pending_exit_code(), false);
    }
    if (!config::closes(config::Module::guard_watchdog)) return;
    // Both beats are old. They are just as old right after the whole process was held (Suspend
    // in a task manager), when this thread happens to run before the guard threads do — and
    // those beat again within a moment. Threads somebody stopped stay stopped: look twice.
    const HANDLE worker = g_worker.load(std::memory_order_acquire);
    auto beats = [] {
        return g_beat_worker.load(std::memory_order_relaxed) + g_beat_watchdog.load(std::memory_order_relaxed);
    };
    auto stopped = [](HANDLE t) { return ended(t) || suspended(t) == 1; };
    const std::uint64_t seen = beats();
    if (stopped(worker) && stopped(watchdog)) {
        Sleep(kHookSecondLookMs);
        if (stopped(worker) && stopped(watchdog) && beats() == seen) on_stall("both guard threads silent", false);
        return;
    }
    // Neither ended nor visibly suspended (before Windows 8.1 the suspend count cannot be asked
    // for; a thread can also be parked without being suspended): silent for as long again, as
    // witnessed by the hooks themselves. Several threads may get here at once; a lost update only
    // delays the verdict.
    const std::uint64_t last = g_hook_last.exchange(now, std::memory_order_relaxed);
    if (g_hook_beats.exchange(seen, std::memory_order_relaxed) != seen || !last) {
        g_hook_silent.store(0, std::memory_order_relaxed);
        return;
    }
    std::uint64_t dt = now > last ? now - last : 0;
    if (dt > kHookStep) dt = kHookStep;
    if (g_hook_silent.fetch_add(dt, std::memory_order_relaxed) + dt > kWatchdogSilentMax)
        on_stall("both guard threads silent", false);
}

}  // namespace mebet::watchdog
