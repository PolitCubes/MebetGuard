// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "launch/launch.hpp"

#include <jni.h>

#include <cstdio>
#include <fstream>
#include <string>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/win_util.hpp"
#include "json_writer.hpp"
#include "report/cards.hpp"
#include "strings.hpp"
#include "trust/engine.hpp"

namespace mebet::launch {

// Exports of jli.dll (signatures are the same in Java 21 and 25, ТЗ §4).
struct StdArg {
    char* arg;
    jboolean has_wildcard;
};
using JliLaunchFn = int(JNICALL*)(int argc, char** argv, int jargc, const char** jargv, int appclassc,
                                  const char** appclassv, const char* fullversion, const char* dotversion,
                                  const char* pname, const char* lname, jboolean javaargs, jboolean cpwildcard,
                                  jboolean javaw, jint ergo);
using JliCmdToArgsFn = void(JNICALL*)(char* cmdline);
using JliGetStdArgsFn = StdArg*(JNICALL*)();
using JliGetStdArgcFn = int(JNICALL*)();
using JliInitArgProcessingFn = void(JNICALL*)(jboolean hasJavaArgs, jboolean disableArgFile);

struct Jli {
    HMODULE dll = nullptr;
    JliLaunchFn launch = nullptr;
    JliCmdToArgsFn cmd_to_args = nullptr;
    JliGetStdArgsFn get_args = nullptr;
    JliGetStdArgcFn get_argc = nullptr;
    JliInitArgProcessingFn init_arg_processing = nullptr;
};

namespace {

Jli g_jli;

report::Event event(const char* type, const char* title) {
    report::Event ev;
    ev.type = type;
    ev.title = title;
    ev.level = report::Level::error;
    return ev;
}

[[noreturn]] void close_java_missing(const std::wstring& what) {
    report::Event ev = event("close.java_not_found", "Closed: client Java not found");
    JsonWriter w;
    w.begin_object().field("what", cards::anonymize(what)).end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.java_not_found"};
    guard::close_now(config::Reason::java_not_found, what, std::move(ev));
}

bool system_name(const std::wstring& file) {
    const std::wstring low = lower_ascii(file);
    if (low.size() < 5 || low.compare(low.size() - 4, 4, L".dll") != 0) return false;
    if (istarts_with(low, L"api-ms-win-") || istarts_with(low, L"ext-ms-win-")) {
        // Windows 8+ resolves API set names from the schema, never from a file (ТЗ §6).
        return !win::is_windows8_or_later();
    }
    return win::file_exists(win::system_dir() + L"\\" + file);
}

void check_proxy_dir(const std::wstring& dir, const char* where) {
    if (dir.empty() || !win::dir_exists(dir)) return;
    for (const auto& name : win::list_dir(dir)) {
        if (name.empty() || name.back() == L'\\' || !system_name(name)) continue;
        const std::wstring path = dir + L"\\" + name;
        const trust::Decision d = trust::decide_path(path);
        if (d.verdict.allowed) continue;
        report::Event ev = event("close.proxy_dll", "Closed: system-named DLL next to the game ");
        ev.title += to_utf8(name);
        JsonWriter w;
        w.begin_object();
        w.field("where", where);
        w.key("file").raw(cards::file_card_json(d));
        w.end_object();
        ev.extra_json = w.take();
        ev.fingerprint = {"close.proxy_dll", d.facts.hashed ? d.facts.sha256.hex() : to_utf8(lower_ascii(name))};
        guard::signal(config::Module::proxy_dll, config::Reason::proxy_dll, name, std::move(ev));
        if (guard::closing()) return;
    }
}

std::string read_java_version(const std::wstring& java_home) {
    std::ifstream f(java_home + L"\\release");
    std::string line;
    while (std::getline(f, line)) {
        if (line.compare(0, 13, "JAVA_VERSION=") == 0) {
            std::string v = line.substr(13);
            if (!v.empty() && v.front() == '"') v.erase(0, 1);
            if (!v.empty() && v.back() == '"') v.pop_back();
            return v;
        }
    }
    return std::string();
}

// JLI hands every path to the JVM in the ANSI code page (GetCommandLineA, GetModuleFileNameA), and
// only a path that reads back as itself names the same file: Windows writes "?" for a character the
// code page lacks ("Игры" on a Western-European Windows, an emoji, a Kazakh letter on a Russian one)
// and a look-alike for some others ("Łódź" becomes "Lódz" on CP1252 — another folder).
bool ansi_safe(const std::wstring& path) {
    bool lossless = false;
    win::to_ansi(path, &lossless);
    return lossless;
}

// The 8.3 form of a path, or empty. Many volumes have none (D: by default since Windows 8).
std::wstring short_path(const std::wstring& path) {
    const DWORD n = GetShortPathNameW(path.c_str(), nullptr, 0);
    if (n == 0) return std::wstring();
    std::wstring s(n, L'\0');
    const DWORD m = GetShortPathNameW(path.c_str(), &s[0], n);
    if (m == 0 || m >= n) return std::wstring();
    s.resize(m);
    return s;
}

// The name a folder lists a file under. A launcher may start us by the 8.3 path ("…\MEBETG~1.EXE",
// a usual way around paths the code page cannot express), and our own exe was then closed as a
// foreign file next to itself (207).
std::wstring listed_name_of(const std::wstring& path) {
    const DWORD n = GetLongPathNameW(path.c_str(), nullptr, 0);
    if (n != 0) {
        std::wstring s(n, L'\0');
        const DWORD m = GetLongPathNameW(path.c_str(), &s[0], n);
        if (m != 0 && m < n) {
            s.resize(m);
            return win::file_name_of(s);
        }
    }
    return win::file_name_of(path);
}

// JLI finds the Java folder from the name jli.dll was loaded by, read back in the ANSI code page,
// and loads jvm.dll and java.dll by paths built from it. A folder the code page cannot express is
// loaded by its 8.3 name, which JLI and the JVM then use throughout. Empty when neither works: JLI
// would stop at a message box of its own ("could not find java.dll") and the launcher would get no
// reason at all.
std::wstring jli_dir_for(const std::wstring& bin) {
    if (ansi_safe(bin)) return bin;
    const std::wstring s = short_path(bin);
    return !s.empty() && ansi_safe(s) ? s : std::wstring();
}

[[noreturn]] void close_unsupported_path(const std::wstring& path) {
    report::Event ev = event("close.unsupported_path", "Closed: a path Java cannot be given on this Windows");
    JsonWriter w;
    w.begin_object().field("path", cards::anonymize(path)).field("code_page", static_cast<unsigned>(GetACP())).end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.unsupported_path", std::to_string(GetACP())};
    guard::close_now(config::Reason::unsupported_path, path, std::move(ev));
}

// -Djava.library.path may list several folders.
std::vector<std::wstring> split_paths(const std::wstring& list) {
    std::vector<std::wstring> out;
    std::size_t start = 0;
    while (start <= list.size()) {
        const auto sep = list.find(L';', start);
        const std::wstring piece = list.substr(start, sep == std::wstring::npos ? std::wstring::npos : sep - start);
        if (!piece.empty()) out.push_back(win::full_path(piece));
        if (sep == std::wstring::npos) break;
        start = sep + 1;
    }
    return out;
}

bool is_own_agent(const Context& ctx, jvmargs::Kind kind, const std::string& target) {
    std::wstring p = win::from_ansi(target);
    if (kind == jvmargs::Kind::agent_lib && !iends_with(p, L".dll")) p += L".dll";
    if (p.find(L'\\') == std::wstring::npos && p.find(L'/') == std::wstring::npos) return false;
    if (win::same_path(p, ctx.agent_path)) return true;
    // Same file through another path (8.3 name, junction): compare identities.
    HANDLE a = trust::open_read(p), b = trust::open_read(ctx.agent_path);
    bool same = false;
    if (a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE) {
        trust::FileIdentity ia{}, ib{};
        same = trust::identity_of(a, ia) && trust::identity_of(b, ib) && ia == ib;
    }
    if (a != INVALID_HANDLE_VALUE) CloseHandle(a);
    if (b != INVALID_HANDLE_VALUE) CloseHandle(b);
    return same;
}

}  // namespace

void locate_java(Context& ctx) {
    ctx.java_home = win::full_path(win::env(L"JAVA_HOME"));
    if (ctx.java_home.empty()) close_java_missing(L"JAVA_HOME");
    if (!win::file_exists(ctx.java_home + L"\\bin\\jli.dll")) close_java_missing(ctx.java_home + L"\\bin\\jli.dll");
    ctx.jli_dir = jli_dir_for(ctx.java_home + L"\\bin");
    if (ctx.jli_dir.empty()) close_unsupported_path(ctx.java_home);
    const std::string version = read_java_version(ctx.java_home);
    report::Reporter::instance().set_tag("java", version.empty() ? "unknown" : version);
}

void load_jli_and_parse(Context& ctx) {
    const std::wstring bin = ctx.java_home + L"\\bin";
    // ТЗ §4 step 5: the Java bin folder joins the user directories, then jli.dll by full path —
    // by the name JLI can read back (jli_dir_for).
    using AddDllDirectoryFn = PVOID(WINAPI*)(PCWSTR);  // Windows 7 needs KB2533623
    if (auto add = reinterpret_cast<AddDllDirectoryFn>(
            reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "AddDllDirectory"))))
        add(bin.c_str());
    g_jli.dll = LoadLibraryW((ctx.jli_dir + L"\\jli.dll").c_str());
    if (!g_jli.dll) {
        if (guard::closing()) guard::close_now(config::Reason::untrusted_module, L"jli.dll", report::Event{});
        close_java_missing(bin + L"\\jli.dll");
    }
    // A 32-bit JDK exports these JNICALL (__stdcall) functions decorated, e.g. _JLI_Launch@56
    // (the number is the bytes of arguments on the stack); 64-bit ones use the plain names.
    auto get = [&](const char* name, int stack_bytes) {
        void* p = reinterpret_cast<void*>(GetProcAddress(g_jli.dll, name));
#if defined(_M_IX86)
        if (!p) {
            const std::string decorated = "_" + std::string(name) + "@" + std::to_string(stack_bytes);
            p = reinterpret_cast<void*>(GetProcAddress(g_jli.dll, decorated.c_str()));
        }
#else
        (void)stack_bytes;
#endif
        return p;
    };
    g_jli.launch = reinterpret_cast<JliLaunchFn>(get("JLI_Launch", 56));
    g_jli.cmd_to_args = reinterpret_cast<JliCmdToArgsFn>(get("JLI_CmdToArgs", 4));
    g_jli.get_args = reinterpret_cast<JliGetStdArgsFn>(get("JLI_GetStdArgs", 0));
    g_jli.get_argc = reinterpret_cast<JliGetStdArgcFn>(get("JLI_GetStdArgc", 0));
    g_jli.init_arg_processing = reinterpret_cast<JliInitArgProcessingFn>(get("JLI_InitArgProcessing", 8));
    if (!g_jli.launch || !g_jli.cmd_to_args || !g_jli.get_args || !g_jli.get_argc || !g_jli.init_arg_processing)
        close_java_missing(bin + L"\\jli.dll (JLI_* exports)");

    // ТЗ §4 step 7: the second argument switches @argfiles off.
    g_jli.init_arg_processing(JNI_FALSE, JNI_TRUE);
    // ТЗ §4 step 8: the JDK's own parser, so quoting and order are exactly java's.
    g_jli.cmd_to_args(GetCommandLineA());
    const int argc = g_jli.get_argc();
    const StdArg* args = g_jli.get_args();
    ctx.argv.clear();
    for (int i = 0; i < argc; ++i) ctx.argv.emplace_back(args[i].arg ? args[i].arg : "");
    ctx.args = jvmargs::inspect(ctx.argv);
    ctx.natives_dirs = split_paths(win::from_ansi(ctx.args.library_path));
}

void check_files(const Context& ctx) {
    if (!config::enabled(config::Module::proxy_dll)) return;
    // Only the guard next to the exe (ТЗ §4: «рядом с exe — только файлы стража»).
    const std::wstring exe_name = listed_name_of(ctx.exe_path);
    const std::wstring agent_name = listed_name_of(ctx.agent_path);
    for (const auto& name : win::list_dir(ctx.exe_dir)) {
        if (iequals_ascii(name, exe_name) || iequals_ascii(name, agent_name)) continue;
        report::Event ev = event("close.extra_file", "Closed: foreign file in the guard folder ");
        ev.title += to_utf8(name);
        JsonWriter w;
        w.begin_object();
        const std::wstring path = ctx.exe_dir + L"\\" + name;
        if (!name.empty() && name.back() != L'\\') {
            w.key("file").raw(cards::file_card_json(path));
        } else {
            w.field("directory", cards::anonymize(path));
        }
        w.end_object();
        ev.extra_json = w.take();
        ev.fingerprint = {"close.extra_file", to_utf8(lower_ascii(name))};
        guard::signal(config::Module::proxy_dll, config::Reason::extra_file, name, std::move(ev));
        if (guard::closing()) return;
    }
    check_proxy_dir(ctx.java_home + L"\\bin", "java");
    check_proxy_dir(ctx.java_home + L"\\bin\\server", "java");
    check_proxy_dir(ctx.java_home + L"\\bin\\client", "java");
    for (const auto& d : ctx.natives_dirs) check_proxy_dir(d, "natives");
}

void check_agent_args(Context& ctx) {
    std::vector<int> remove;
    for (const auto& f : ctx.args.findings) {
        if (f.kind == jvmargs::Kind::report_only) {
            report::Event ev = event("report.jvm_option", "Report: notable JVM option");
            ev.level = report::Level::warning;
            JsonWriter w;
            w.begin_object().field("option", truncate_utf8(cards::anonymize(win::from_ansi(f.arg)), 512)).end_object();
            ev.extra_json = w.take();
            ev.fingerprint = {"report.jvm_option", f.arg.substr(0, f.arg.find_first_of(":=") )};
            ev.dedupe_key = ev.fingerprint[1];
            report::Reporter::instance().submit(std::move(ev));
            continue;
        }
        if ((f.kind == jvmargs::Kind::agent_path || f.kind == jvmargs::Kind::agent_lib) && is_own_agent(ctx, f.kind, f.target)) {
            remove.push_back(f.index);  // ours: we add it ourselves, exactly once
            continue;
        }
        const bool location = f.kind == jvmargs::Kind::jvm_location;
        report::Event ev = event(location ? "close.jvm_path" : "close.foreign_agent_arg",
                                 location ? "Closed: JVM libraries from another place" : "Closed: foreign Java agent option");
        JsonWriter w;
        w.begin_object();
        w.field("kind", jvmargs::kind_name(f.kind));
        w.field("argument", truncate_utf8(cards::anonymize(win::from_ansi(f.arg)), 512));
        const std::wstring target = win::from_ansi(f.target);
        if (!target.empty() && win::file_exists(target)) w.key("file").raw(cards::file_card_json(target));
        w.end_object();
        ev.extra_json = w.take();
        ev.fingerprint = {ev.type, jvmargs::kind_name(f.kind), to_utf8(lower_ascii(win::file_name_of(target)))};
        guard::signal(config::Module::jvm_agents, location ? config::Reason::jvm_path : config::Reason::foreign_agent_arg,
                      win::file_name_of(target.empty() ? win::from_ansi(f.arg) : target), std::move(ev));
        if (guard::closing()) return;
    }
    for (auto it = remove.rbegin(); it != remove.rend(); ++it) ctx.argv.erase(ctx.argv.begin() + *it);
}

int run_jvm(Context& ctx) {
    // ТЗ §4 step 9: our -agentpath right after the program name — the JVM calls
    // Agent_OnLoad in the DLL that is already loaded. By its file name only: the JVM's LoadLibraryA
    // finds a loaded module by that name before any search. The full path would go through the
    // ANSI code page (ansi_safe) and the JVM cuts -agentpath:<path>=<options> at the first "=";
    // its 8.3 form, in turn, made the JVM map the agent once more under another name, and the load
    // gate refused that mapping (210). A guard folder "D:\Игры" on a Western-European Windows, or
    // one named "a=b", never started.
    std::vector<std::string> argv = ctx.argv;
    argv.insert(argv.begin() + (argv.empty() ? 0 : 1), "-agentpath:" + win::to_ansi(win::file_name_of(ctx.agent_path), nullptr));
    std::vector<char*> raw;
    raw.reserve(argv.size() + 1);
    for (auto& a : argv) raw.push_back(&a[0]);
    raw.push_back(nullptr);
    static std::string version = read_java_version(ctx.java_home);
    if (version.empty()) version = "unknown";
    // ТЗ §4 step 10: JLI_Launch(appargc, appargv, 0, NULL, 0, NULL, …) as javaw does.
    return g_jli.launch(static_cast<int>(argv.size()), raw.data(), 0, nullptr, 0, nullptr, version.c_str(),
                        version.c_str(), "java", "openjdk", JNI_FALSE, JNI_TRUE, JNI_TRUE, 0);
}

}  // namespace mebet::launch
