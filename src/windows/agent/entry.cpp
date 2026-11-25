// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Agent entry: the whole start sequence of ТЗ §4 and §5 in one readable place.
//
//   wrapper step 1 (env, DLL dirs, extension points) ── done before this DLL was loaded
//   1. splash in its own thread (never waited for)
//   2. Java location, crypto warm-up, trust engine
//   3. hooks first, then everything that was already loaded (ТЗ §5: «сначала хуки»)
//   4. dev mode, virtual machine — close before the start
//   5. jli.dll through the gate, JDK argument parsing, files and agent arguments
//   6. reports of the environment, process DACL, worker thread
//   7. JLI_Launch with our -agentpath; JVMTI takes over inside the JVM
#include <atomic>
#include <cstdio>
#include <string>

#include "boot_info.hpp"
#include "config.hpp"
#include "core/guard.hpp"
#include "core/module_table.hpp"
#include "core/timing.hpp"
#include "core/win_util.hpp"
#include "hardening.hpp"
#include "hooks/hook_check.hpp"
#include "hooks/load_gate.hpp"
#include "hooks/nt_hooks.hpp"
#include "json_writer.hpp"
#include "jvm_args.hpp"
#include "jvm_guard.hpp"
#include "launch/launch.hpp"
#include "process/dacl.hpp"
#include "report/cards.hpp"
#include "report/session_tags.hpp"
#include "scan/scans.hpp"
#include "strings.hpp"
#include "system/environment.hpp"
#include "trust/engine.hpp"
#include "trust/signatures.hpp"
#include "window/game_window.hpp"
#include "window/splash.hpp"

using namespace mebet;

namespace {

std::atomic<bool> g_thread_hooks_ready{false};

HMODULE self_module() {
    HMODULE m = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&self_module), &m);
    return m;
}

// A close requested by a hook on another thread during start-up is carried out here.
void stop_if_closing() {
    if (guard::closing()) guard::close_now(config::Reason::internal_error, std::wstring(), report::Event{});
}

void report_cleared_environment(const BootInfo& boot) {
    for (std::uint32_t i = 0; i < boot.cleared_count && i < kMaxClearedEnv; ++i) {
        report::Event ev;
        ev.type = "report.cleared_env";
        ev.level = report::Level::warning;
        ev.title = std::string("Report: environment variable cleared: ") + boot.cleared_names[i];
        JsonWriter w;
        w.begin_object();
        w.field("name", boot.cleared_names[i]);
        w.field("value", cards::anonymize(win::wide(boot.cleared_values[i])));
        w.end_object();
        ev.extra_json = w.take();
        ev.fingerprint = {"report.cleared_env", boot.cleared_names[i]};
        ev.dedupe_key = std::string("cleared_env|") + boot.cleared_names[i];
        report::Reporter::instance().submit(std::move(ev));
    }
}

void report_hardening(const BootInfo& boot) {
    // Step 1 is "on" (no verdict); a policy that did not apply is worth knowing about.
    const bool want_ext = config::enabled(config::Module::extension_point_disable) && win::is_windows8_or_later();
    const bool ext_ok = !want_ext || (boot.hardening & kBootExtPointsDisabled) || win::extension_points_disabled();
    const bool dirs_ok = (boot.hardening & kBootDllDirsDefault) != 0;
    if (ext_ok && dirs_ok) return;
    report::guard_error("hardening", std::string(ext_ok ? "" : "extension points not disabled; ") +
                                         (dirs_ok ? "" : "SetDefaultDllDirectories unavailable (KB2533623?)"));
}

// JVM hooks of the shared JVMTI code.
bool jvm_thread_allowed(std::string* detail) {
    PVOID start = nullptr;
    const auto& a = nt::api();
    if (a.NtQueryInformationThread)
        a.NtQueryInformationThread(nt::current_thread(), nt::kThreadQuerySetWin32StartAddress, &start, sizeof(start), nullptr);
    const auto s = reinterpret_cast<std::uintptr_t>(start);
    if (!s || scan::allowed_code(s)) return true;
    if (detail) *detail = "{\"start\":" + cards::address_json(s) + "}";
    return false;
}

bool jvm_code_allowed(const void* address) { return scan::allowed_code(reinterpret_cast<std::uintptr_t>(address)); }

void check_jvm_library(const wchar_t* name, const std::wstring& expected_dir) {
    HMODULE m = GetModuleHandleW(name);
    if (!m) return;
    const std::wstring path = win::mapped_file_name(m);
    if (path.empty() || win::path_under(path, expected_dir)) return;
    report::Event ev;
    ev.type = "close.jvm_path";
    ev.level = report::Level::error;
    ev.title = "Closed: JVM library outside the client Java " + to_utf8(name);
    ev.extra_json = "{\"file\":" + cards::file_card_json(path) + "}";
    ev.fingerprint = {"close.jvm_path", to_utf8(name)};
    guard::signal(config::Module::startup_self_check, config::Reason::jvm_path, name, std::move(ev));
}

void jvm_vm_init() {
    gate::set_jvm_started();
    const std::wstring& home = trust::java_home();
    check_jvm_library(L"jvm.dll", home + L"\\bin");
    check_jvm_library(L"java.dll", home + L"\\bin");
}

void jvm_vm_death() {
    game_window::report_input(true);
    const std::string t = timing::summary();
    if (!t.empty()) std::fprintf(stderr, "[Mebet] guard time: %s\n", t.c_str());
    report::Event ev;
    ev.type = "report.session_timing";
    ev.level = report::Level::info;
    ev.title = "Session: guard timing";
    ev.extra_json = timing::summary_json();
    ev.fingerprint = {"report.session_timing"};
    ev.dedupe_key = "report.session_timing";
    if (config::kTestBuild) report::Reporter::instance().submit(std::move(ev));  // stand measurements (ТЗ §14)
    report::Reporter::instance().drain(2000);
}

void jvm_signal(config::Module m, config::Reason r, const std::string& detail, report::Event ev) {
    guard::signal(m, r, win::wide(detail), std::move(ev));
}

}  // namespace

MEBET_EXPORT int MEBET_CALL MebetGuardMain(const BootInfo* boot) {
    static std::atomic<bool> entered{false};
    if (!boot || boot->size < sizeof(BootInfo) || boot->version != kBootInfoVersion || entered.exchange(true)) return 200;
    guard::init(boot);
    nt::api();
    modules::init();

    // Privacy switches before anything can send (JLI parses the full list later).
    bool reports = true, errors = true;
    jvmargs::prescan_switches(GetCommandLineA(), reports, errors);
    report::Reporter::instance().configure(reports, errors);
    tags::init();

    // 1. Splash (ТЗ §4 step 2) — its own thread, after the process policies of step 1.
    splash::start(static_cast<HMODULE>(boot->exe_module));

    // 2. Java location, crypto warm-up before any hook exists (ТЗ §5), trust engine.
    launch::Context ctx;
    ctx.exe_path = win::module_path(nullptr);
    ctx.exe_dir = win::dir_of(ctx.exe_path);
    ctx.agent_path = win::module_path(self_module());
    launch::locate_java(ctx);
    trust::warm_up(ctx.java_home + L"\\bin\\jli.dll", win::system_dir() + L"\\kernel32.dll");
    trust::init_engine(ctx.java_home);
    {
        wchar_t cwd[MAX_PATH * 2];
        const DWORD n = GetCurrentDirectoryW(MAX_PATH * 2, cwd);
        if (n && n < MAX_PATH * 2) cards::set_game_dir(std::wstring(cwd, n));  // the launcher starts us in the client dir
    }

    // 3. Hooks, then the loader notification, then what was loaded before us.
    {
        timing::Scope scope(config::Module::module_trust);
        std::string failed;
        if (!hooks::install(&failed)) {
            report::Event ev;
            ev.type = "close.hardening_failed";
            ev.title = "Closed: hooks could not be installed: " + failed;
            ev.fingerprint = {"close.hardening_failed", failed};
            report::guard_error("hooks_install", failed);
            guard::close_now(config::Reason::hardening_failed, win::wide(failed), std::move(ev));
        }
        gate::register_loader_notifications();
    }

    // 4. Developer mode and virtual machine — before the start (ТЗ §8). Off only in the
    //    unsigned devtest build, so its layers can be tested on a dev-mode CI runner.
    if (config::enabled(config::Module::dev_mode)) env::check_dev_mode();
    if (config::enabled(config::Module::virtual_machine)) env::check_virtual_machine();
    env::tag_kernel_state();

    // Start-up self-check: modules, memory and threads that got in before us (ТЗ §5).
    {
        timing::Scope scope(config::Module::startup_self_check);
        scan::startup_check();
    }
    stop_if_closing();

    // 5. jli.dll through the gate, JDK argument parsing, files next to us, agent options.
    launch::load_jli_and_parse(ctx);
    report::Reporter::instance().configure(ctx.args.reports_enabled, ctx.args.errors_enabled);
    if (!ctx.args.client.empty()) report::Reporter::instance().set_tag("client", ctx.args.client);
    stop_if_closing();
    launch::check_files(ctx);
    stop_if_closing();
    launch::check_agent_args(ctx);
    stop_if_closing();

    // 6. Reports of the environment, DACL, worker thread.
    report_cleared_environment(*boot);
    report_hardening(*boot);
    env::report_extension_points();
    env::report_wine();
    if (dacl::prepare()) {
        dacl::protect_process();
        dacl::protect_existing_threads();
    }
    g_thread_hooks_ready.store(true);
    game_window::configure(win::wide(ctx.args.window_title), win::wide(ctx.args.window_icon), boot->exe_module);

    const unsigned sweep = config::opt::sweep_interval_ms;
    guard::add_periodic("memory", sweep, &scan::memory_sweep, config::Module::foreign_exec_memory);
    guard::add_periodic("threads", sweep, &scan::thread_sweep, config::Module::foreign_threads);
    guard::add_periodic("debugger", sweep, &env::check_debugger, config::Module::debugger);
    guard::add_periodic("hooks", sweep, &hooks::self_check, config::Module::hook_self_check);
    guard::add_periodic("time", 30000, &env::check_time, config::Module::time_check);
    guard::add_periodic("input", config::kLimit_input_report_interval_s * 1000u,
                        [] { game_window::report_input(false); }, config::Module::input_source);
    guard::add_periodic("drivers", 60000, [] {
        static bool done = false;
        if (!done) {
            done = true;
            env::report_drivers();
        }
    }, config::Module::driver_names);
    guard::start_worker();

    jvm::Platform p;
    p.current_thread_allowed = &jvm_thread_allowed;
    p.code_allowed = &jvm_code_allowed;
    p.on_vm_init = &jvm_vm_init;
    p.on_vm_death = &jvm_vm_death;
    p.signal = &jvm_signal;
    jvm::set_platform(p);
    stop_if_closing();

    // 7. The JVM (ТЗ §4 step 10).
    const int code = launch::run_jvm(ctx);
    report::Reporter::instance().drain(2000);
    return code;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_THREAD_ATTACH:
            // Thread checks need the DLL_THREAD_ATTACH of every thread (ТЗ §5), so
            // DisableThreadLibraryCalls is deliberately not used.
            if (g_thread_hooks_ready.load(std::memory_order_acquire)) scan::on_thread_attach();
            break;
        case DLL_PROCESS_DETACH:
            guard::set_shutting_down();
            if (reserved) {
                // The process is exiting (the game called exit while a close was pending):
                // keep the reason's exit code for the launcher.
                const int code = guard::pending_exit_code();
                const auto& a = nt::api();
                if (code && a.NtTerminateProcess) a.NtTerminateProcess(nt::current_process(), static_cast<NTSTATUS>(code));
            }
            break;
        default:
            break;
    }
    return TRUE;
}
