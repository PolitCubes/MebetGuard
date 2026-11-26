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
// The worker inside one call that shows nothing while it runs (a signature check, opening a file
// on a slow disk — see SlowWork): silence gets this long. A big file being hashed beats per
// chunk and does not need it.
constexpr std::uint64_t kWorkerSlowMax = 180000 * kMs;
// A guard thread that was created but never made its first beat (see Witness::unstarted).
constexpr std::uint64_t kStartMax = 60000 * kMs;
// A guard thread seen suspended, its beat standing still, on consecutive looks for this long is
// frozen. One look is not enough: while the system suspends or resumes the whole process, thread
// by thread, one guard thread can see the other suspended for an instant. And one look adds at
// most kFrozenStep, so it takes several.
constexpr std::uint64_t kFrozenMin = 750 * kMs;
constexpr std::uint64_t kFrozenStep = 250 * kMs;
// The most one look may add to what its thread has witnessed (see Witness).
constexpr std::uint64_t kWatchdogStep = 1000 * kMs;  // the watchdog looks every 250 ms
constexpr std::uint64_t kWorkerStep = 2000 * kMs;    // the worker at least once a second when idle
constexpr std::uint64_t kHookStep = 1000 * kMs;
constexpr DWORD kTickMs = 250;
constexpr DWORD kHookSecondLookMs = 100;
constexpr DWORD kLastWordsReportMs = 2000;  // the line and the report
constexpr DWORD kLastWordsLineMs = 250;     // the line only
constexpr int kThreadSuspendCount = 35;  // THREADINFOCLASS, Windows 8.1+

// 0 until the thread has made its first beat: a thread that has not started yet is not silent.
std::atomic<std::uint64_t> g_beat_worker{0};
std::atomic<std::uint64_t> g_beat_watchdog{0};
// Query/synchronize copies only: code in the process that finds them can wait on them, not
// suspend or end the thread. Read by the worker and by every hook thread, hence atomic. The
// one of the watchdog thread is made by its creator (the thread itself cannot: the DACL the guard
// puts on its threads leaves no right to ask for the suspend count) and handed over in
// g_watchdog_own; the thread publishes it in g_watchdog after its first beat.
std::atomic<HANDLE> g_worker{nullptr};
std::atomic<HANDLE> g_watchdog{nullptr};
std::atomic<HANDLE> g_watchdog_own{nullptr};
std::atomic<bool> g_watchdog_created{false};
std::atomic<std::uint64_t> g_created_at{0};  // when start() ran: the clock of threads that have not beaten yet
// Set by the worker on its own thread. Not its thread id: Windows hands the id of a thread that
// has ended to the next new thread, and that thread would then beat for a dead worker.
thread_local bool t_worker = false;
std::atomic<int> g_worker_slow{0};  // SlowWork scopes open on the worker
std::atomic<bool> g_ending{false};
std::atomic<bool> g_told{false};  // report level: one report, the game keeps running
// Time the watchdog thread has witnessed the process running (see witnessed_100ns); 0 = not started.
std::atomic<std::uint64_t> g_witnessed{0};
// What the hooks themselves have witnessed (see hook_witnessed).
std::atomic<std::uint64_t> g_hook_last{0};
std::atomic<std::uint64_t> g_hook_key{0};
std::atomic<std::uint64_t> g_hook_silent{0};
using ShutdownFn = BOOLEAN(NTAPI*)();
ShutdownFn g_dll_shutdown = nullptr;  // ntdll!RtlDllShutdownInProgress

// 1 suspended, 0 running, -1 unknown (the information class exists from Windows 8.1).
int suspended(HANDLE t) {
    const auto& a = nt::api();
    if (!t || !a.NtQueryInformationThread) return -1;
    ULONG count = 0;
    if (!nt::ok(a.NtQueryInformationThread(t, kThreadSuspendCount, &count, sizeof(count), nullptr))) return -1;
    return count > 0 ? 1 : 0;
}

bool ended(HANDLE t) { return t && WaitForSingleObject(t, 0) == WAIT_OBJECT_0; }
bool stopped(HANDLE t) { return ended(t) || suspended(t) == 1; }

// How long another thread has been stopped, counted only while the observer itself was running.
// The whole process held for a minute (Suspend in a task manager, a dump tool, a machine that
// froze) stops the observer too: afterwards the beat of the other thread is a minute old, yet
// nobody stopped that thread on its own — it beats again as soon as it gets to run. The watchdog
// used to compare the beat with the clock and closed such a game with guard_stalled. So every
// look adds the time since the previous look, but never more than `step`: time the observer did
// not witness proves nothing. One observer thread per Witness, so no lock.
struct Witness {
    std::uint64_t last = 0;       // the previous look
    std::uint64_t beat = 0;       // the beat seen then
    std::uint64_t silent = 0;     // witnessed time without a new beat
    std::uint64_t frozen = 0;     // witnessed time suspended with the beat standing still
    std::uint64_t unstarted = 0;  // witnessed time before the first beat
    bool was_suspended = false;

    void look(std::uint64_t now, std::uint64_t current_beat, bool is_suspended, std::uint64_t step) {
        std::uint64_t dt = last && now > last ? now - last : 0;
        if (dt > step) dt = step;
        last = now;
        if (!current_beat) {
            // Created, not running yet: a new thread waits for the loader, and the loader can be
            // busy for seconds with a library on a slow disk. Not silence; it has its own limit.
            unstarted += dt;
            return;
        }
        const bool moved = current_beat != beat;
        beat = current_beat;
        silent = moved ? 0 : silent + dt;
        // A thread that beat between two looks ran between them, whatever its suspend count
        // says at both: a tool that suspends threads one at a time for an instant is not a freeze.
        frozen = is_suspended && was_suspended && !moved ? frozen + (dt < kFrozenStep ? dt : kFrozenStep) : 0;
        was_suspended = is_suspended;
    }
};

// For the hooks. A thread that has not made its first beat is not silent yet — but one that was
// stopped before it could ever beat must not stay invisible for good: it counts from the moment
// the watchdog was started, with the longer limit a start gets.
bool silent(const std::atomic<std::uint64_t>& beat, std::uint64_t now, std::uint64_t max) {
    const std::uint64_t b = beat.load(std::memory_order_relaxed);
    if (b) return now > b && now - b > max;
    const std::uint64_t created = g_created_at.load(std::memory_order_relaxed);
    return created && now > created && now - created > kStartMax;
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

// A close is pending and nobody is left to carry it out, or it was not finished in time: the
// process ends with the code of that close. Never with 0 — a launcher reads 0 as a normal exit.
[[noreturn]] void end_pending_close(const char* what) {
    const int pending = guard::pending_exit_code();
    end_process("pending_close", what, pending ? pending : config::reason(config::Reason::guard_stalled).exit_code, false);
}

// The whole close — the reason window included — may take this long. The worker shows the window
// and waits for the player; the game is hidden but its threads still run behind it, and nothing
// else of the guard works meanwhile. A window nobody dismisses (covered, hidden by code in the
// process, a player who walked away) used to keep that state for good.
std::uint64_t close_max() { return static_cast<std::uint64_t>(config::opt::close_window_max_ms) * kMs; }

HANDLE query_copy(HANDLE t) {
    HANDLE out = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), t, GetCurrentProcess(), &out,
                         SYNCHRONIZE | THREAD_QUERY_INFORMATION, FALSE, 0))
        out = nullptr;
    return out;
}

DWORD WINAPI watchdog_main(void*) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    Witness worker;
    std::uint64_t previous = now_100ns();
    std::uint64_t closing_for = 0;
    g_witnessed.store(1, std::memory_order_relaxed);
    for (;;) {
        const std::uint64_t now = now_100ns();
        const std::uint64_t dt = now - previous > kWatchdogStep ? kWatchdogStep : now - previous;
        previous = now;
        g_witnessed.fetch_add(dt, std::memory_order_relaxed);
        g_beat_watchdog.store(now, std::memory_order_relaxed);
        // Published by the thread itself, after its first beat: until it runs there is nothing
        // for the worker or the hooks to find silent or suspended.
        if (!g_watchdog.load(std::memory_order_relaxed))
            g_watchdog.store(g_watchdog_own.load(std::memory_order_acquire), std::memory_order_release);

        const HANDLE w = g_worker.load(std::memory_order_acquire);
        worker.look(now, g_beat_worker.load(std::memory_order_relaxed), suspended(w) == 1, kWatchdogStep);
        if (!guard::closing()) {
            const bool slow = g_worker_slow.load(std::memory_order_relaxed) > 0;
            if (ended(w)) on_stall("worker thread ended", true);
            if (worker.frozen >= kFrozenMin) on_stall("worker thread suspended", true);
            if (worker.silent > (slow ? kWorkerSlowMax : kWorkerSilentMax)) on_stall("worker thread silent", true);
            if (worker.unstarted > kStartMax) on_stall("worker thread did not start", true);
        } else {
            // A close is pending and the worker carries it out. Frozen or killed in the middle,
            // it would leave the game running behind that close: end it with the code of the
            // close. The same when the close is not finished in time.
            closing_for += dt;
            if (ended(w) || worker.frozen >= kFrozenMin) end_pending_close("worker thread stopped during the close");
            if (closing_for > close_max()) end_pending_close("the close was not finished in time");
        }
        Sleep(kTickMs);
    }
}

// Time the hooks themselves have seen pass while `key` stayed the same; several threads may get
// here at once, and a lost update only delays the verdict. The same rule as Witness: a look
// adds at most kHookStep.
std::uint64_t hook_witnessed(std::uint64_t key, std::uint64_t now) {
    const std::uint64_t last = g_hook_last.exchange(now, std::memory_order_relaxed);
    if (g_hook_key.exchange(key, std::memory_order_relaxed) != key || !last) {
        g_hook_silent.store(0, std::memory_order_relaxed);
        return 0;
    }
    std::uint64_t dt = now > last ? now - last : 0;
    if (dt > kHookStep) dt = kHookStep;
    return g_hook_silent.fetch_add(dt, std::memory_order_relaxed) + dt;
}

// Test builds: what a hook sees while a beat is old or a close is pending, at most once a
// second — a failed e2e run then says what the hooks took the guard threads for. No CRT, no
// allocation.
std::atomic<std::uint64_t> g_trace_last{0};
void trace_hook(std::uint64_t now, HANDLE worker, HANDLE watchdog, bool closing) {
    if (!config::kTestBuild) return;
    if (!closing && !silent(g_beat_worker, now, kWatchdogSilentMax) && !silent(g_beat_watchdog, now, kWatchdogSilentMax))
        return;
    const std::uint64_t last = g_trace_last.load(std::memory_order_relaxed);
    if (last && now - last < 1000 * kMs) return;
    g_trace_last.store(now, std::memory_order_relaxed);
    char line[160];
    std::size_t n = 0;
    auto put = [&](const char* text) {
        while (*text && n + 1 < sizeof(line)) line[n++] = *text++;
    };
    auto num = [&](long long v) {
        if (v < 0) {
            put("-");
            v = -v;
        }
        char digits[24];
        int d = 0;
        do {
            digits[d++] = static_cast<char>('0' + v % 10);
            v /= 10;
        } while (v && d < 23);
        while (d && n + 1 < sizeof(line)) line[n++] = digits[--d];
    };
    put("[Mebet] hook: worker beat ");
    num(static_cast<long long>((now - g_beat_worker.load(std::memory_order_relaxed)) / kMs));
    put(" ms ended=");
    num(ended(worker) ? 1 : 0);
    put(" suspended=");
    num(suspended(worker));
    put(", watchdog beat ");
    num(static_cast<long long>((now - g_beat_watchdog.load(std::memory_order_relaxed)) / kMs));
    put(" ms ended=");
    num(ended(watchdog) ? 1 : 0);
    put(" suspended=");
    num(suspended(watchdog));
    put(closing ? ", closing\n" : "\n");
    DWORD written = 0;
    const HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    if (err && err != INVALID_HANDLE_VALUE) WriteFile(err, line, static_cast<DWORD>(n), &written, nullptr);
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
    g_created_at.store(now_100ns(), std::memory_order_relaxed);
    // The last-words thread first: a stall found a moment later already has it.
    g_say = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_said = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_say && g_said) {
        if (HANDLE t = CreateThread(nullptr, 0, &last_words_main, nullptr, 0, nullptr)) CloseHandle(t);
    }
    // The watchdog thread makes itself known (handle, first beat) once it runs. It used to be
    // created suspended with both published by its creator: the worker — already running — could
    // find it "suspended" before it had ever run, or "silent" while it still waited for the
    // loader behind a library on a slow disk, and a clean launch was closed with guard_stalled.
    // Suspended only until its handle is handed over; nobody can see it meanwhile.
    HANDLE w = CreateThread(nullptr, 0, &watchdog_main, nullptr, CREATE_SUSPENDED, nullptr);
    const HANDLE own = w ? query_copy(w) : nullptr;
    if (!w || !own) {
        if (w) {
            TerminateThread(w, 0);  // never ran
            CloseHandle(w);
        }
        on_stall("watchdog thread could not start", true);
        return;
    }
    g_watchdog_own.store(own, std::memory_order_release);
    g_watchdog_created.store(true, std::memory_order_release);
    ResumeThread(w);
    CloseHandle(w);
}

void worker_started() {
    t_worker = true;
    g_beat_worker.store(now_100ns(), std::memory_order_relaxed);
}

void worker_tick() {
    static Witness watchdog;  // the worker thread only
    t_worker = true;
    const std::uint64_t now = now_100ns();
    g_beat_worker.store(now, std::memory_order_relaxed);
    if (!g_watchdog_created.load(std::memory_order_acquire)) return;
    const HANDLE w = g_watchdog.load(std::memory_order_acquire);
    watchdog.look(now, g_beat_watchdog.load(std::memory_order_relaxed), suspended(w) == 1, kWorkerStep);
    if (guard::closing()) return;
    // The worker is alive, so the regular close runs (window, report, exit code).
    const char* what = nullptr;
    if (ended(w)) what = "watchdog thread ended";
    else if (watchdog.frozen >= kFrozenMin) what = "watchdog thread suspended";
    else if (watchdog.silent > kWatchdogSilentMax) what = "watchdog thread silent";
    else if (watchdog.unstarted > kStartMax) what = "watchdog thread did not start";
    if (!what) return;
    // Report level: one report, not one on every loop (each of them wakes this loop again).
    if (!config::closes(config::Module::guard_watchdog) && g_told.exchange(true)) return;
    guard::signal(config::Module::guard_watchdog, config::Reason::guard_stalled, win::wide(what), stalled_event(what));
}

void worker_beat() {
    if (!t_worker) return;
    g_beat_worker.store(now_100ns(), std::memory_order_relaxed);
}

SlowWork::SlowWork() : on_worker_(t_worker) {
    if (!on_worker_) return;
    g_beat_worker.store(now_100ns(), std::memory_order_relaxed);
    g_worker_slow.fetch_add(1, std::memory_order_relaxed);
}

SlowWork::~SlowWork() {
    if (!on_worker_) return;
    g_beat_worker.store(now_100ns(), std::memory_order_relaxed);
    g_worker_slow.fetch_sub(1, std::memory_order_relaxed);
}

std::uint64_t witnessed_100ns() { return g_witnessed.load(std::memory_order_relaxed); }

void check_from_hook() {
    if (!g_watchdog_created.load(std::memory_order_acquire)) return;
    // Null until the watchdog thread has made its first beat; then nothing below finds it stopped
    // and only its silence counts.
    const HANDLE watchdog = g_watchdog.load(std::memory_order_acquire);
    const std::uint64_t now = now_100ns();
    if (config::kTestBuild) trace_hook(now, g_worker.load(std::memory_order_acquire), watchdog, guard::closing());
    if (!silent(g_beat_watchdog, now, kWatchdogSilentMax)) return;  // the fast path
    if (!silent(g_beat_worker, now, kWatchdogSilentMax)) return;      // the worker deals with it
    if (guard::shutting_down() || (g_dll_shutdown && g_dll_shutdown())) return;
    // Both beats are old. They are just as old right after the whole process was held (Suspend
    // in a task manager), when this thread happens to run before the guard threads do — and
    // those beat again within a moment. Threads somebody stopped stay stopped: look twice.
    const HANDLE worker = g_worker.load(std::memory_order_acquire);
    auto beats = [] {
        return g_beat_worker.load(std::memory_order_relaxed) + g_beat_watchdog.load(std::memory_order_relaxed);
    };
    const std::uint64_t seen = beats();
    if (guard::closing()) {
        // A close is pending and the watchdog thread, which would end a close that hangs, is
        // silent. The worker carries the close out and does not beat while the reason window is
        // open, so its silence says nothing: only a worker that is stopped leaves nobody. (The
        // process used to end here as soon as both beats were 8 s old — the reason window of a
        // close caused by the watchdog thread itself vanished after 8 seconds.) A worker that
        // is alive keeps its time limit, counted by the hooks.
        if (stopped(worker)) {
            Sleep(kHookSecondLookMs);
            if (stopped(worker)) end_pending_close("guard threads stopped during the close");
            return;
        }
        if (hook_witnessed(~seen, now) > close_max()) end_pending_close("the close was not finished in time");
        return;
    }
    if (!config::closes(config::Module::guard_watchdog)) return;
    if (stopped(worker) && stopped(watchdog)) {
        Sleep(kHookSecondLookMs);
        if (stopped(worker) && stopped(watchdog) && beats() == seen) on_stall("both guard threads silent", false);
        return;
    }
    // Neither ended nor visibly suspended (before Windows 8.1 the suspend count cannot be asked
    // for; a thread can also be parked without being suspended): silent for as long again, as
    // witnessed by the hooks themselves.
    if (hook_witnessed(seen, now) > kWatchdogSilentMax) on_stall("both guard threads silent", false);
}

}  // namespace mebet::watchdog
