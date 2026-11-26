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
// The worker's thread id, set by the worker itself. No TLS: SlowWork and worker_beat run on any
// thread, also in a loader callback on a thread that has no TLS block yet or any more. Windows
// may hand the id of a thread that has ended to a new one, which would then beat for a dead
// worker: wherever that matters, an ended worker is told by its handle first.
std::atomic<DWORD> g_worker_tid{0};
std::atomic<int> g_worker_slow{0};  // SlowWork scopes open on the worker
std::atomic<bool> g_ending{false};
// Report level: one report from each side (the watchdog about the worker, the worker about the
// watchdog); the game keeps running.
std::atomic<bool> g_told_by_watchdog{false};
std::atomic<bool> g_told_by_worker{false};
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

// A whole close may take this long once it has started: the reason window (it closes itself
// after close_window_max_ms, guard.cpp), the report, and a margin. Past that the worker is stuck
// somewhere in the close, and the watchdog ends the process with the code of the close.
std::uint64_t close_budget() {
    return (static_cast<std::uint64_t>(config::opt::close_window_max_ms) + config::opt::close_report_wait_ms + 10000) * kMs;
}

// The close line, "[Mebet] closed: <id> (code <n>) <what>\n", without the CRT: the thread that
// froze the guard may hold the stdio or heap lock. Written once, by whoever claims it first.
std::atomic<bool> g_line_claimed{false};

void write_close_line(const char* id, int code, const char* what) {
    if (g_line_claimed.exchange(true)) return;
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

report::Event stalled_event(const char* what, bool closes) {
    report::Event ev;
    ev.type = closes ? "close.guard_stalled" : "report.guard_stalled";
    ev.level = closes ? report::Level::error : report::Level::warning;
    ev.title = std::string(closes ? "Closed: " : "Signal: ") + "guard thread stopped (" + what + ")";
    ev.fingerprint = {ev.type, what};
    ev.tags.emplace_back("reason", "guard_stalled");
    if (!closes) ev.tags.emplace_back("module", config::module(config::Module::guard_watchdog).id);
    return ev;
}

// The last words of a guard that ends the process itself: the line for the launcher log and the
// report. Each of them can block for good — stderr is a console somebody is selecting text in,
// building the report takes the heap lock and sending it the lock of the reporter, and the thread
// that was frozen may hold either. The watchdog used to do all of that itself before the kill:
// blocked there, it never killed, and every other thread that noticed the stall then waited for
// it forever. So the words are said by a thread of their own, started together with the watchdog
// and parked until needed; whoever ends the process only wakes it, waits a limited time and
// kills. Nothing on that path allocates or takes a lock. The same thread sends the one report of
// the report level: given to the worker, it would wait for the very thread that stalled.
enum class Report : unsigned char {
    none,     // the line only
    stalled,  // guard_stalled
    pending,  // the report of the pending close, unless the close has sent it already
};
struct LastWords {
    const char* id = "";
    const char* what = "";
    int code = 0;
    Report report = Report::none;
};
LastWords g_words;        // written once by the thread that won g_ending, before g_say is set
HANDLE g_say = nullptr;   // wakes the last-words thread for the end
HANDLE g_said = nullptr;  // it has finished
HANDLE g_tell = nullptr;  // wakes it for the report of the report level
std::atomic<const char*> g_tell_what{nullptr};

DWORD WINAPI last_words_main(void*) {
    const HANDLE wake[2] = {g_say, g_tell};  // the end first when both are set
    for (;;) {
        const DWORD r = WaitForMultipleObjects(2, wake, FALSE, INFINITE);
        if (r == WAIT_OBJECT_0) {
            const LastWords words = g_words;
            write_close_line(words.id, words.code, words.what);
            if (words.report == Report::stalled) {
                report::Reporter::instance().send_now(stalled_event(words.what, true), 1500);
            } else if (words.report == Report::pending) {
                guard::send_pending_close_report(1500);
            }
            SetEvent(g_said);
            for (;;) Sleep(INFINITE);  // the caller ends the process
        }
        if (r == WAIT_OBJECT_0 + 1) {
            if (const char* what = g_tell_what.exchange(nullptr))
                report::Reporter::instance().send_now(stalled_event(what, false), 1500);
            continue;
        }
        Sleep(1000);  // the wait failed: do not spin
    }
}

[[noreturn]] void end_process(const char* id, const char* what, int code, Report report) {
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
    g_words.report = report;
    bool said = false;
    if (g_say && g_said) {
        SetEvent(g_say);
        said = WaitForSingleObject(g_said, report == Report::none ? kLastWordsLineMs : kLastWordsReportMs) == WAIT_OBJECT_0;
    }
    if (!said) {
        // The last-words thread did not answer. It starts in the guard module, so whoever froze or
        // killed the guard's threads got it too — exactly when the launcher log needs the line.
        // Written from here when stderr is a pipe or a file; a console can be held by a selection
        // and would hold the kill with it.
        const HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
        if (err && err != INVALID_HANDLE_VALUE && GetFileType(err) != FILE_TYPE_CHAR) write_close_line(id, code, what);
    }
    kill_process(code);
}

void on_stall(const char* what, bool try_report) {
    if (config::closes(config::Module::guard_watchdog)) {
        end_process(config::reason(config::Reason::guard_stalled).id, what,
                    config::reason(config::Reason::guard_stalled).exit_code, try_report ? Report::stalled : Report::none);
    }
    // Report level: one report, sent by the last-words thread.
    if (try_report && g_tell && !g_told_by_watchdog.exchange(true)) {
        g_tell_what.store(what);
        SetEvent(g_tell);
    }
}

// A close is pending and nobody is left to carry it out, or it was not finished in time: the
// process ends with the code of that close, and with its report if the close has not sent it.
// Never with 0 — a launcher reads 0 as a normal exit.
[[noreturn]] void end_pending_close(const char* what) {
    const int pending = guard::pending_exit_code();
    end_process("pending_close", what, pending ? pending : config::reason(config::Reason::guard_stalled).exit_code,
                Report::pending);
}

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
    std::uint64_t running_for = 0;  // witnessed time since the close itself started
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
        const bool closing = guard::closing();
        const bool dead = ended(w), frozen = worker.frozen >= kFrozenMin;
        // A close is pending and the worker carries it out. Frozen or killed before or in the
        // middle of it, it would leave the game running behind that close: end it with the code
        // of the close.
        if (closing && (dead || frozen)) end_pending_close("worker thread stopped during the close");
        if (dead) on_stall("worker thread ended", true);
        if (frozen) on_stall("worker thread suspended", true);
        if (guard::close_running()) {
            // The close itself has started. The worker does not beat while the reason window is
            // open, so its silence says nothing now; the close has a time limit instead. It used
            // to start counting when the close was requested — a worker in the middle of a long
            // task reached the close a minute later and was ended before it had sent the report
            // or shown the window.
            running_for += dt;
            if (running_for > close_budget()) end_pending_close("the close was not finished in time");
        } else {
            // Before the close starts the worker beats as always — while it finishes its task.
            const bool slow = g_worker_slow.load(std::memory_order_relaxed) > 0;
            const bool too_silent = worker.silent > (slow ? kWorkerSlowMax : kWorkerSilentMax);
            if (too_silent && closing) end_pending_close("worker thread silent before the close");
            if (too_silent) on_stall("worker thread silent", true);
            if (worker.unstarted > kStartMax) on_stall("worker thread did not start", true);
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
    g_tell = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (g_say && g_said && g_tell) {
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
    g_worker_tid.store(GetCurrentThreadId(), std::memory_order_relaxed);
    g_beat_worker.store(now_100ns(), std::memory_order_relaxed);
}

void worker_tick() {
    static Witness watchdog;  // the worker thread only
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
    if (!config::closes(config::Module::guard_watchdog) && g_told_by_worker.exchange(true)) return;
    guard::signal(config::Module::guard_watchdog, config::Reason::guard_stalled, win::wide(what), stalled_event(what, true));
}

void worker_beat() {
    if (GetCurrentThreadId() != g_worker_tid.load(std::memory_order_relaxed)) return;
    g_beat_worker.store(now_100ns(), std::memory_order_relaxed);
}

SlowWork::SlowWork() : on_worker_(GetCurrentThreadId() == g_worker_tid.load(std::memory_order_relaxed)) {
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
    const HANDLE worker = g_worker.load(std::memory_order_acquire);
    // The worker deals with it — if it is the worker that beats: an ended worker's id may beat
    // for it from a new thread.
    if (!silent(g_beat_worker, now, kWatchdogSilentMax) && !ended(worker)) return;
    if (guard::shutting_down() || (g_dll_shutdown && g_dll_shutdown())) return;
    // Both beats are old. They are just as old right after the whole process was held (Suspend
    // in a task manager), when this thread happens to run before the guard threads do — and
    // those beat again within a moment. Threads somebody stopped stay stopped: look twice.
    auto beats = [] {
        return g_beat_worker.load(std::memory_order_relaxed) + g_beat_watchdog.load(std::memory_order_relaxed);
    };
    const std::uint64_t seen = beats();
    if (guard::closing()) {
        // A close is pending and the watchdog thread, which would end a close that hangs, is
        // silent. A worker that is stopped leaves nobody to carry the close out. A worker that is
        // alive gets the limit the watchdog would give it: the close's own once it has started
        // (the worker does not beat while the reason window is open — the process used to end
        // here as soon as both beats were 8 s old, and the window of a close caused by the
        // watchdog thread itself vanished after 8 seconds), its slow-work limit before that.
        if (stopped(worker)) {
            Sleep(kHookSecondLookMs);
            if (stopped(worker)) end_pending_close("guard threads stopped during the close");
            return;
        }
        const std::uint64_t limit = guard::close_running() ? close_budget() : kWorkerSlowMax;
        if (hook_witnessed(~seen, now) > limit) end_pending_close("the close was not finished in time");
        return;
    }
    if (!config::closes(config::Module::guard_watchdog)) return;
    if (stopped(worker) && (!watchdog || stopped(watchdog))) {
        Sleep(kHookSecondLookMs);
        if (stopped(worker) && (!watchdog || stopped(watchdog)) && beats() == seen)
            on_stall("both guard threads silent", false);
        return;
    }
    // Neither ended nor visibly suspended (before Windows 8.1 the suspend count cannot be asked
    // for; a thread can also be parked without being suspended): silent for as long again, as
    // witnessed by the hooks themselves.
    if (hook_witnessed(seen, now) > kWatchdogSilentMax) on_stall("both guard threads silent", false);
}

}  // namespace mebet::watchdog
