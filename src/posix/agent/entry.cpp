// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Linux / macOS agent (ТЗ §11). Base level: four blocking measures — own wrapper with
// JLI_Launch and our -agentpath, PR_SET_DUMPABLE 0 (Linux) / PT_DENY_ATTACH (macOS),
// -XX:+DisableAttachMechanism from the profile, hashes of our own files — plus WSL2
// closing before the start. LD_PRELOAD / LD_AUDIT / DYLD_INSERT_LIBRARIES and foreign
// libraries are reported, not blocked (Steam overlay, MangoHud, GameMode, OBS capture).
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__linux__)
#include <link.h>
#include <sys/prctl.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/ptrace.h>
#endif

#include <jni.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "boot_info.hpp"
#include "config.hpp"
#include "json_writer.hpp"
#include "jvm_args.hpp"
#include "jvm_guard.hpp"
#include "report.hpp"
#include "strings.hpp"

using namespace mebet;

namespace {

using JliLaunchFn = int (*)(int, char**, int, const char**, int, const char**, const char*, const char*, const char*,
                            const char*, jboolean, jboolean, jboolean, jint);
using JliInitArgProcessingFn = void (*)(jboolean, jboolean);

std::string g_java_home;
std::string g_agent_path;
std::vector<std::string> g_argv;  // final arguments for JLI (kept alive for the JVM)

const char* arch() {
#if defined(__aarch64__) || defined(__arm64__)
    return "arm64";
#elif defined(__x86_64__)
    return "x64";
#elif defined(__i386__)
    return "x86";
#else
    return "other";
#endif
}

[[noreturn]] void close_now(config::Reason r, const std::string& detail, report::Event ev) {
    const auto& d = config::reason(r);
    if (ev.type.empty()) ev.type = std::string("close.") + d.id;
    if (ev.title.empty()) ev.title = std::string("Closed: ") + d.id;
    ev.level = report::Level::error;
    ev.tags.emplace_back("reason", d.id);
    ev.tags.emplace_back("exit_code", std::to_string(d.exit_code));
    std::fprintf(stderr, "[Mebet] closed: %s (code %d) %s\n", d.id, d.exit_code, detail.c_str());
    std::fflush(stderr);
    report::Reporter::instance().send_now(std::move(ev), config::opt::close_report_wait_ms);
    _exit(d.exit_code);
}

void signal(config::Module m, config::Reason r, const std::string& detail, report::Event ev) {
    switch (config::level(m)) {
        case config::Level::close:
            close_now(r, detail, std::move(ev));
        case config::Level::report:
            if (ev.type.compare(0, 6, "close.") == 0) ev.type = "report." + ev.type.substr(6);
            ev.level = report::Level::warning;
            report::Reporter::instance().submit(std::move(ev));
            break;
        default:
            break;
    }
}

std::string read_first_line(const char* path) {
    std::ifstream f(path);
    std::string line;
    std::getline(f, line);
    return line;
}

// ТЗ §11: the Linux client inside WSL2 closes before the start (those players have the
// Windows client); Crostini and Asahi are players and only get a tag.
void check_wsl() {
#if defined(__linux__)
    const std::string release = lower_ascii(read_first_line("/proc/sys/kernel/osrelease"));
    const bool wsl = release.find("microsoft") != std::string::npos || release.find("wsl") != std::string::npos ||
                     access("/proc/sys/fs/binfmt_misc/WSLInterop", F_OK) == 0 || getenv("WSL_DISTRO_NAME") != nullptr;
    if (!wsl) return;
    report::Event ev;
    ev.type = "close.wsl";
    ev.title = "Closed: Linux client in WSL";
    JsonWriter w;
    w.begin_object().field("kernel", truncate_utf8(release, 128)).end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.wsl"};
    signal(config::Module::linux_wsl, config::Reason::wsl, release, std::move(ev));
#endif
}

void deny_debugging() {
#if defined(__linux__)
    // No ptrace, /proc/pid/mem or process_vm_readv for non-root (reset by execve).
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#elif defined(__APPLE__)
    ptrace(PT_DENY_ATTACH, 0, nullptr, 0);
#endif
}

bool system_library(const std::string& path) {
    static const char* const kDirs[] = {"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/local/lib/",
                                        "/System/Library/", "/usr/libexec/", "/nix/store/", "/gnu/store/"};
    for (const char* d : kDirs)
        if (path.compare(0, std::strlen(d), d) == 0) return true;
    return path.empty() || path[0] != '/';
}

// Libraries outside system folders, the JRE and our own files: report only (ТЗ §11, §15).
void report_libraries() {
    if (!config::enabled(config::Module::posix_preload)) return;
    std::vector<std::string> foreign;
    auto consider = [&](const std::string& path) {
        if (system_library(path)) return;
        if (!g_java_home.empty() && path.compare(0, g_java_home.size(), g_java_home) == 0) return;
        if (path == g_agent_path) return;
        if (foreign.size() < config::kLimit_list_items) foreign.push_back(path);
    };
#if defined(__linux__)
    dl_iterate_phdr(
        [](dl_phdr_info* info, size_t, void* data) {
            if (info->dlpi_name && *info->dlpi_name)
                (*static_cast<decltype(consider)*>(data))(info->dlpi_name);
            return 0;
        },
        &consider);
#elif defined(__APPLE__)
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char* n = _dyld_get_image_name(i);
        if (n) consider(n);
    }
#endif
    const char* preload_vars[] = {"LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"};
    JsonWriter w;
    w.begin_object();
    bool any = !foreign.empty();
    for (const char* v : preload_vars) {
        if (const char* val = getenv(v)) {
            w.field(v, truncate_utf8(val, config::kLimit_string_chars));
            any = true;
        }
    }
    w.key("libraries").begin_array();
    for (const auto& f : foreign) w.value(truncate_utf8(f, config::kLimit_string_chars));
    w.end_array();
    w.end_object();
    if (!any) return;
    report::Event ev;
    ev.type = "report.preload";
    ev.level = report::Level::warning;
    ev.title = "Report: preloaded or foreign libraries";
    ev.extra_json = w.take();
    ev.fingerprint = {"report.preload"};
    ev.dedupe_key = "report.preload";
    report::Reporter::instance().submit(std::move(ev));
}

void check_agent_args(const jvmargs::Inspection& in, std::vector<int>& remove) {
    for (const auto& f : in.findings) {
        if (f.kind == jvmargs::Kind::report_only) continue;
        const bool own = (f.kind == jvmargs::Kind::agent_path || f.kind == jvmargs::Kind::agent_lib) &&
                         (f.target == g_agent_path || f.target + ".so" == g_agent_path || f.target + ".dylib" == g_agent_path);
        if (own) {
            remove.push_back(f.index);
            continue;
        }
        report::Event ev;
        const bool location = f.kind == jvmargs::Kind::jvm_location;
        ev.type = location ? "close.jvm_path" : "close.foreign_agent_arg";
        ev.title = location ? "Closed: JVM libraries from another place" : "Closed: foreign Java agent option";
        JsonWriter w;
        w.begin_object().field("kind", jvmargs::kind_name(f.kind)).field("argument", truncate_utf8(f.arg, 512)).end_object();
        ev.extra_json = w.take();
        ev.fingerprint = {ev.type, jvmargs::kind_name(f.kind)};
        signal(config::Module::jvm_agents, location ? config::Reason::jvm_path : config::Reason::foreign_agent_arg, f.arg,
               std::move(ev));
    }
}

void report_cleared_environment(const BootInfo& boot) {
    for (std::uint32_t i = 0; i < boot.cleared_count && i < kMaxClearedEnv; ++i) {
        report::Event ev;
        ev.type = "report.cleared_env";
        ev.level = report::Level::warning;
        ev.title = std::string("Report: environment variable cleared: ") + boot.cleared_names[i];
        JsonWriter w;
        w.begin_object().field("name", boot.cleared_names[i]).field("value", boot.cleared_values[i]).end_object();
        ev.extra_json = w.take();
        ev.fingerprint = {"report.cleared_env", boot.cleared_names[i]};
        ev.dedupe_key = std::string("cleared_env|") + boot.cleared_names[i];
        report::Reporter::instance().submit(std::move(ev));
    }
}

std::string self_library_path() {
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(&self_library_path), &info) && info.dli_fname) {
        char real[4096];
        if (realpath(info.dli_fname, real)) return real;
        return info.dli_fname;
    }
    return std::string();
}

void jvm_vm_death() { report::Reporter::instance().drain(2000); }

void jvm_signal(config::Module m, config::Reason r, const std::string& detail, report::Event ev) {
    signal(m, r, detail, std::move(ev));
}

int run_jli(int argc, char** argv) {
#if defined(__APPLE__)
    const std::string jli = g_java_home + "/lib/libjli.dylib";
#else
    const std::string jli = g_java_home + "/lib/libjli.so";
#endif
    void* lib = dlopen(jli.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!lib) close_now(config::Reason::java_not_found, jli, report::Event{});
    auto launch = reinterpret_cast<JliLaunchFn>(dlsym(lib, "JLI_Launch"));
    auto init_args = reinterpret_cast<JliInitArgProcessingFn>(dlsym(lib, "JLI_InitArgProcessing"));
    if (!launch || !init_args) close_now(config::Reason::java_not_found, jli + " (JLI_* exports)", report::Event{});
    // @argfiles stay off: on these systems the java launcher expands them in main(), which
    // we do not call, and JLI_InitArgProcessing(…, JNI_TRUE) keeps JLI from doing it.
    init_args(JNI_FALSE, JNI_TRUE);
    std::vector<char*> raw;
    for (auto& a : g_argv) raw.push_back(&a[0]);
    raw.push_back(nullptr);
    (void)argc;
    (void)argv;
    return launch(static_cast<int>(g_argv.size()), raw.data(), 0, nullptr, 0, nullptr, "mebet", "mebet", "java",
                  "openjdk", JNI_FALSE, JNI_TRUE, JNI_FALSE, 0);
}

}  // namespace

MEBET_EXPORT int MEBET_CALL MebetGuardMain(const BootInfo* boot) {
    static std::atomic<int> entries{0};
    if (!boot || boot->size < sizeof(BootInfo) || boot->version != kBootInfoVersion) return 200;
    if (entries.fetch_add(1) > 0) {
        // macOS: libjli runs main() again on a new thread; the guard is already up.
        return run_jli(boot->argc, boot->argv);
    }

    std::vector<std::string> argv;
    for (int i = 0; i < boot->argc; ++i) argv.emplace_back(boot->argv[i] ? boot->argv[i] : "");
    jvmargs::Inspection in = jvmargs::inspect(argv);
    report::Reporter::instance().configure(in.reports_enabled, in.errors_enabled);
    auto& r = report::Reporter::instance();
    r.set_tag("guard_version", config::kVersion);
    r.set_tag("arch", arch());
    utsname u{};
    if (uname(&u) == 0) {
        r.set_tag("os", u.sysname);
        r.set_tag("os_version", u.release);
    }
    if (!in.client.empty()) r.set_tag("client", in.client);

    const char* jh = getenv("JAVA_HOME");
    g_java_home = jh ? jh : "";
    while (g_java_home.size() > 1 && g_java_home.back() == '/') g_java_home.pop_back();
    if (g_java_home.empty()) close_now(config::Reason::java_not_found, "JAVA_HOME", report::Event{});
    g_agent_path = self_library_path();

    check_wsl();
    deny_debugging();
    report_cleared_environment(*boot);
    report_libraries();

    std::vector<int> remove;
    check_agent_args(in, remove);
    for (auto it = remove.rbegin(); it != remove.rend(); ++it) argv.erase(argv.begin() + *it);
    argv.insert(argv.begin() + (argv.empty() ? 0 : 1), "-agentpath:" + g_agent_path);
    g_argv = argv;

    jvm::Platform p;
    p.on_vm_death = &jvm_vm_death;
    p.signal = &jvm_signal;
    jvm::set_platform(p);
    const int code = run_jli(boot->argc, boot->argv);
    report::Reporter::instance().drain(2000);
    return code;
}
