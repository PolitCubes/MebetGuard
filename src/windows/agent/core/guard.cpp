// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "core/guard.hpp"

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

#include "core/timing.hpp"
#include "core/win_util.hpp"
#include "strings.hpp"
#include "window/game_window.hpp"
#include "window/reason_window.hpp"
#include "window/splash.hpp"

namespace mebet::guard {

namespace {

struct CloseRequest {
    config::Reason reason;
    std::wstring detail;
    report::Event event;
};

struct Periodic {
    const char* name;
    unsigned interval_ms;
    Task task;
    config::Module module;
    std::uint64_t next_ms;
};

struct Core {
    const BootInfo* boot = nullptr;
    std::atomic<bool> closing{false};
    std::atomic<bool> shutdown{false};
    std::atomic<bool> armed{false};
    std::atomic<bool> flow_started{false};
    std::atomic<int> exit_code{0};
    std::atomic<CloseRequest*> close{nullptr};
    HANDLE wake = nullptr;
    DWORD worker_tid = 0;
    SRWLOCK deferred_lock = SRWLOCK_INIT;
    std::vector<std::function<void()>> deferred;
    std::vector<Periodic> periodic;
};

Core& core() {
    static Core* c = new Core();  // leaked: hooks may look at it while the process exits
    return *c;
}

bool russian_ui() {
    const WORD lang = PRIMARYLANGID(GetUserDefaultUILanguage());
    return lang == LANG_RUSSIAN || lang == LANG_UKRAINIAN || lang == LANG_BELARUSIAN || lang == LANG_KAZAK;
}

BOOL CALLBACK hide_window(HWND hwnd, LPARAM) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(hwnd)) ShowWindowAsync(hwnd, SW_HIDE);
    return TRUE;
}

void drain_deferred() {
    Core& c = core();
    std::vector<std::function<void()>> items;
    AcquireSRWLockExclusive(&c.deferred_lock);
    items.swap(c.deferred);
    ReleaseSRWLockExclusive(&c.deferred_lock);
    for (auto& fn : items) {
        if (fn) fn();
    }
}

[[noreturn]] void run_close(CloseRequest& r) {
    Core& c = core();
    c.flow_started.store(true);
    const auto& def = config::reason(r.reason);

    // 1. The game disappears at once; the splash gives way to the reason window (ТЗ §4).
    splash::hide_now();
    EnumWindows(&hide_window, 0);

    // 2. The report goes out while the window is on screen (ТЗ §12: send or 3 s).
    const std::uint64_t started = win::now_ms();
    std::atomic<bool> sent{false};
    report::Event ev = std::move(r.event);
    if (ev.type.empty()) ev.type = std::string("close.") + def.id;
    if (ev.title.empty()) ev.title = std::string("Closed: ") + def.id;
    ev.level = report::Level::error;
    ev.tags.emplace_back("reason", def.id);
    ev.tags.emplace_back("exit_code", std::to_string(def.exit_code));
    std::thread sender([&sent, ev]() mutable {
        report::Reporter::instance().send_now(std::move(ev), config::opt::close_report_wait_ms);
        sent.store(true);
    });

    // 3. Reason and code in the launcher log too (no log file, ТЗ §3).
    std::fprintf(stderr, "[Mebet] closed: %s (code %d) %s\n", def.id, def.exit_code, to_utf8(r.detail).c_str());
    std::fflush(stderr);

    // 4. The reason window (draft layout until the mockups are chosen). Test builds on CI
    //    skip it when MEBET_TEST_NO_UI is set, so a smoke test cannot hang on a dialog.
    std::wstring title;
    const std::wstring text = reason_text(r.reason, r.detail, &title);
    const bool no_ui = config::kTestBuild && !win::env(L"MEBET_TEST_NO_UI").empty();
    if (!no_ui) reason_window::show(title, text);

    // 5. Wait for the report at most until 3 s after the close started.
    while (!sent.load() && win::now_ms() - started < config::opt::close_report_wait_ms) Sleep(20);
    if (sender.joinable()) sender.detach();
    const auto& a = nt::api();
    if (a.NtTerminateProcess) a.NtTerminateProcess(nt::current_process(), static_cast<NTSTATUS>(def.exit_code));
    TerminateProcess(GetCurrentProcess(), static_cast<UINT>(def.exit_code));
    for (;;) Sleep(INFINITE);
}

DWORD WINAPI worker_main(void*) {
    Core& c = core();
    game_window::install_in_worker();
    for (;;) {
        std::uint64_t now = win::now_ms();
        DWORD timeout = 1000;
        for (const Periodic& p : c.periodic) {
            const std::uint64_t left = p.next_ms > now ? p.next_ms - now : 0;
            if (left < timeout) timeout = static_cast<DWORD>(left);
        }
        MsgWaitForMultipleObjectsEx(1, &c.wake, timeout, QS_ALLINPUT, MWMO_INPUTAVAILABLE);

        if (CloseRequest* r = c.close.load()) run_close(*r);

        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        drain_deferred();
        if (CloseRequest* r = c.close.load()) run_close(*r);

        now = win::now_ms();
        for (Periodic& p : c.periodic) {
            if (now < p.next_ms) continue;
            {
                timing::Scope scope(p.module);
                p.task();
            }
            p.next_ms = win::now_ms() + p.interval_ms;
            if (CloseRequest* r = c.close.load()) run_close(*r);
        }
    }
}

}  // namespace

void init(const BootInfo* boot) {
    Core& c = core();
    c.boot = boot;
    c.wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

const BootInfo& boot() { return *core().boot; }

bool closing() { return core().closing.load(std::memory_order_acquire); }
bool shutting_down() { return core().shutdown.load(std::memory_order_relaxed); }
void set_shutting_down() { core().shutdown.store(true); }
bool armed() { return core().armed.load(std::memory_order_acquire); }
void arm() { core().armed.store(true, std::memory_order_release); }

void request_close(config::Reason reason, const std::wstring& detail, report::Event ev) {
    Core& c = core();
    bool expected = false;
    if (!c.closing.compare_exchange_strong(expected, true)) return;  // the first reason wins
    c.exit_code.store(config::reason(reason).exit_code);
    c.close.store(new CloseRequest{reason, detail, std::move(ev)});
    if (c.wake) SetEvent(c.wake);
}

void close_now(config::Reason reason, const std::wstring& detail, report::Event ev) {
    request_close(reason, detail, std::move(ev));
    Core& c = core();
    CloseRequest* r = c.close.load();
    if (!r || c.flow_started.load()) {
        for (;;) Sleep(INFINITE);  // another thread is closing
    }
    run_close(*r);
}

void defer(std::function<void()> fn) {
    Core& c = core();
    AcquireSRWLockExclusive(&c.deferred_lock);
    c.deferred.push_back(std::move(fn));
    ReleaseSRWLockExclusive(&c.deferred_lock);
    if (c.wake) SetEvent(c.wake);
}

void defer_event(report::Event ev) {
    defer([ev]() mutable { report::Reporter::instance().submit(std::move(ev)); });
}

void signal(config::Module m, config::Reason reason, const std::wstring& detail, report::Event ev) {
    switch (config::level(m)) {
        case config::Level::close:
            request_close(reason, detail, std::move(ev));
            break;
        case config::Level::report: {
            // Same payload, marked as a report: the game keeps running.
            if (ev.type.compare(0, 6, "close.") == 0) ev.type = "report." + ev.type.substr(6);
            if (ev.title.compare(0, 8, "Closed: ") == 0) ev.title = "Signal: " + ev.title.substr(8);
            ev.level = report::Level::warning;
            ev.tags.emplace_back("module", config::module(m).id);
            if (ev.dedupe_key.empty() && !ev.fingerprint.empty()) {
                ev.dedupe_key = ev.type;
                for (const auto& f : ev.fingerprint) ev.dedupe_key += "|" + f;
            }
            defer_event(std::move(ev));
            break;
        }
        case config::Level::on:
        case config::Level::off:
            break;
    }
}

void add_periodic(const char* name, unsigned interval_ms, Task task, config::Module m) {
    core().periodic.push_back(Periodic{name, interval_ms, task, m, win::now_ms() + interval_ms});
}

void start_worker() {
    Core& c = core();
    HANDLE t = CreateThread(nullptr, 0, &worker_main, nullptr, 0, &c.worker_tid);
    if (t) CloseHandle(t);
}

DWORD worker_thread_id() { return core().worker_tid; }

int pending_exit_code() { return closing() ? core().exit_code.load() : 0; }

std::wstring reason_text(config::Reason reason, const std::wstring& detail, std::wstring* title) {
    const auto& d = config::reason(reason);
    const bool ru = russian_ui();
    std::wstring text = ru ? d.text_ru : d.text_en;
    const auto pos = text.find(L"{file}");
    if (pos != std::wstring::npos) text.replace(pos, 6, detail.empty() ? std::wstring(L"?") : detail);
    text += ru ? L"\n\nКод: " : L"\n\nCode: ";
    text += std::to_wstring(d.exit_code);
    if (title) *title = std::wstring(L"Mebet Anticheat — ") + (ru ? d.title_ru : d.title_en);
    return text;
}

}  // namespace mebet::guard
