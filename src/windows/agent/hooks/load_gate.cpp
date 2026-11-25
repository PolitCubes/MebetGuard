// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "hooks/load_gate.hpp"

#include <atomic>
#include <cstdio>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/module_table.hpp"
#include "core/timing.hpp"
#include "core/win_util.hpp"
#include "json_writer.hpp"
#include "mebet_trust_data.hpp"
#include "report/cards.hpp"
#include "strings.hpp"

namespace mebet::gate {

namespace {

// Per-thread state of the gate. Plain data only: no constructor runs in a hook.
struct ThreadState {
    bool busy;                   // a decision is running on this thread (nested loads)
    HANDLE last_section;         // section the gate just approved on this thread
    trust::Trust last_trust;
    std::wstring* last_path;     // owned
};
thread_local ThreadState t_gate = {false, nullptr, trust::Trust::unknown, nullptr};
thread_local int t_own_read = 0;

std::atomic<bool> g_jvm_started{false};
PVOID g_cookie = nullptr;

void set_last(HANDLE section, trust::Trust t, const std::wstring& path) {
    t_gate.last_section = section;
    t_gate.last_trust = t;
    delete t_gate.last_path;
    t_gate.last_path = new std::wstring(path);
}

void clear_last() {
    t_gate.last_section = nullptr;
    delete t_gate.last_path;
    t_gate.last_path = nullptr;
}

bool system_path(const std::wstring& path) {
    const std::wstring w = win::windows_dir();
    return win::path_under(path, w + L"\\System32") || win::path_under(path, w + L"\\SysWOW64") ||
           win::path_under(path, w + L"\\WinSxS");
}

std::uintptr_t current_thread_start() {
    PVOID start = nullptr;
    const auto& a = nt::api();
    if (a.NtQueryInformationThread)
        a.NtQueryInformationThread(nt::current_thread(), nt::kThreadQuerySetWin32StartAddress, &start, sizeof(start), nullptr);
    return reinterpret_cast<std::uintptr_t>(start);
}

// A remote thread created right at LoadLibrary* is the classic injector pattern.
bool started_at_loadlibrary(std::uintptr_t start) {
    static const char* const names[] = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"};
    for (const wchar_t* mod : {L"kernel32.dll", L"kernelbase.dll"}) {
        HMODULE m = GetModuleHandleW(mod);
        if (!m) continue;
        for (const char* n : names)
            if (reinterpret_cast<std::uintptr_t>(reinterpret_cast<void*>(GetProcAddress(m, n))) == start) return true;
    }
    return false;
}

std::uintptr_t load_requester() {
    void* frames[24];
    const USHORT n = RtlCaptureStackBackTrace(0, 24, frames, nullptr);
    USHORT i = 0;
    while (i < n && modules::in_self(reinterpret_cast<std::uintptr_t>(frames[i]))) ++i;
    while (i < n && modules::is_system_frame(reinterpret_cast<std::uintptr_t>(frames[i]))) ++i;
    return i < n ? reinterpret_cast<std::uintptr_t>(frames[i]) : 0;
}

void report_inventory(const trust::Decision& d) {
    const trust::Verdict& v = d.verdict;
    if (v.trust != trust::Trust::publisher && v.trust != trust::Trust::whql) return;
    const std::string file = to_utf8(lower_ascii(win::file_name_of(d.facts.path)));
    const std::string publisher = v.publisher >= 0 ? config::kPublishers[v.publisher].id : "whql";
    trust::Decision copy = d;
    guard::defer([copy, file, publisher]() {
        report::Event ev;
        ev.type = "inventory.module";
        ev.level = report::Level::info;
        ev.inventory = true;
        ev.title = "Inventory: " + cards::file_label(copy);
        ev.fingerprint = {"inventory.module", publisher, file};
        ev.dedupe_key = "inventory:" + publisher + ":" + file;
        ev.extra_json = "{\"file\":" + cards::file_card_json(copy) + "}";
        report::Reporter::instance().submit(std::move(ev));
    });
    if (v.new_certificate && !d.facts.sigs.signers.empty()) {
        const trust::Signer s = d.facts.sigs.signers.front();
        guard::defer([copy, s, publisher]() {
            report::Event ev;
            ev.type = "report.new_certificate";
            ev.level = report::Level::info;
            ev.title = "New certificate of a known publisher: " + publisher + " serial " + s.serial;
            ev.fingerprint = {"report.new_certificate", publisher, s.serial};
            ev.dedupe_key = "newcert:" + publisher + ":" + s.serial;
            ev.extra_json = "{\"file\":" + cards::file_card_json(copy) + "}";
            report::Reporter::instance().submit(std::move(ev));
        });
    }
}

// ТЗ §10: the JVM's own debugging and instrumentation agents are signed by the Java vendor
// (config/java.json) like the rest of the game Java, so the publisher rule would let them in;
// they never belong in the game.
bool java_agent_module(const std::wstring& path) {
    static const wchar_t* const kNames[] = {L"instrument.dll", L"jdwp.dll", L"attach.dll", L"dt_socket.dll",
                                            L"dt_shmem.dll"};
    const std::wstring name = win::file_name_of(path);
    for (const wchar_t* n : kNames)
        if (iequals_ascii(name, n)) return true;
    return false;
}

void deny_java_agent(const trust::Decision& d) {
    report::Event ev;
    ev.type = "close.jvm_agent_module";
    ev.level = report::Level::error;
    ev.title = "Closed: JVM agent library " + to_utf8(win::file_name_of(d.facts.path));
    JsonWriter w;
    w.begin_object();
    w.key("file").raw(cards::file_card_json(d));
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.jvm_agent_module", to_utf8(lower_ascii(win::file_name_of(d.facts.path)))};
    guard::signal(config::Module::jvm_agents, config::Reason::jvm_agent_module, win::file_name_of(d.facts.path),
                  std::move(ev));
}

bool decide_and_apply(const trust::Decision& d, const char* phase) {
    if (d.verdict.allowed && java_agent_module(d.facts.path) && config::enabled(config::Module::jvm_agents)) {
        deny_java_agent(d);
        return !config::closes(config::Module::jvm_agents);
    }
    if (d.verdict.allowed) {
        report_inventory(d);
        return true;
    }
    deny_module(d, d.verdict.reason, phase);
    return !config::closes(config::Module::module_trust);
}

VOID NTAPI on_loader_event(ULONG reason, const nt::LdrDllNotificationData* data, PVOID) {
    if (!data || guard::shutting_down()) return;
    const auto base = reinterpret_cast<std::uintptr_t>(data->DllBase);
    if (reason == nt::kLdrDllNotificationUnloaded) {
        modules::remove(base);
        return;
    }
    if (reason != nt::kLdrDllNotificationLoaded) return;
    if (modules::find(base)) return;  // mapped through our hook: already decided
    // Mapped by a path the hook does not see (NtMapViewOfSectionEx): decide now. The DLL
    // entry point has not run yet; the close is requested before it can matter much.
    std::wstring path = win::mapped_file_name(data->DllBase);
    if (path.empty() && data->FullDllName && data->FullDllName->Buffer)
        path.assign(data->FullDllName->Buffer, data->FullDllName->Length / sizeof(wchar_t));
    timing::Scope scope(config::Module::module_trust);
    const trust::Decision d = trust::decide_path(path);
    if (d.verdict.allowed) {
        modules::add(base, data->SizeOfImage, d.verdict.trust, d.facts.path);
        report_inventory(d);
    } else {
        deny_module(d, d.verdict.reason, "loader_notification");
    }
}

}  // namespace

OwnReadScope::OwnReadScope() { ++t_own_read; }
OwnReadScope::~OwnReadScope() { --t_own_read; }
bool own_read_on_this_thread() { return t_own_read > 0; }

bool jvm_started() { return g_jvm_started.load(std::memory_order_acquire); }
void set_jvm_started() { g_jvm_started.store(true, std::memory_order_release); }

bool on_image_section(HANDLE file) {
    if (!config::enabled(config::Module::module_trust)) return true;
    if (t_gate.busy) {
        // A load while this thread is verifying another file: the crypto providers were
        // warmed up before the hooks, so this should not happen; when it does, only a
        // system file may pass, and it is verified again by the worker.
        const std::wstring path = trust::final_path(file);
        if (system_path(path)) {
            guard::defer([path]() {
                const trust::Decision d = trust::decide_path(path);
                if (!d.verdict.allowed) deny_module(d, d.verdict.reason, "nested");
            });
            return true;
        }
        trust::Decision d;
        d.facts.path = path;
        d.verdict.rule = "nested_non_system";
        deny_module(d, config::Reason::untrusted_module, "nested");
        return !config::closes(config::Module::module_trust);
    }
    t_gate.busy = true;
    trust::Decision d;
    {
        timing::Scope scope(config::Module::module_trust);
        d = trust::decide(file, std::wstring());
    }
    t_gate.busy = false;
    const bool allow = decide_and_apply(d, jvm_started() ? "game" : "prestart");
    if (allow) set_last(nullptr, d.verdict.allowed ? d.verdict.trust : trust::Trust::unknown, d.facts.path);
    return allow;
}

void on_section_created(HANDLE section) { t_gate.last_section = section; }

bool on_image_view(HANDLE section, void* base, SIZE_T size) {
    const auto b = reinterpret_cast<std::uintptr_t>(base);
    if (t_own_read > 0) {
        // Resource view opened by the guard itself: registered (so the sweep does not call
        // it hidden) but never trusted as code.
        modules::add(b, size, trust::Trust::unknown, std::wstring());
        return true;
    }
    if (section && section == t_gate.last_section) {
        modules::add(b, size, t_gate.last_trust, t_gate.last_path ? *t_gate.last_path : std::wstring());
        clear_last();
        return true;
    }
    // KnownDLLs: sections created by the system at boot from System32.
    const auto& a = nt::api();
    if (a.NtQueryObject && section) {
        alignas(8) unsigned char buf[sizeof(UNICODE_STRING) + 1024];
        ULONG ret = 0;
        if (nt::ok(a.NtQueryObject(section, nt::kObjectNameInformation, buf, sizeof(buf), &ret))) {
            const auto* us = reinterpret_cast<const UNICODE_STRING*>(buf);
            if (us->Buffer && us->Length) {
                const std::wstring name(us->Buffer, us->Length / sizeof(wchar_t));
                if (istarts_with(name, L"\\KnownDlls\\") || istarts_with(name, L"\\KnownDlls32\\")) {
                    modules::add(b, size, trust::Trust::known_dll, win::mapped_file_name(base));
                    return true;
                }
            }
        }
    }
    if (!config::enabled(config::Module::module_trust)) {
        modules::add(b, size, trust::Trust::unknown, std::wstring());
        return true;
    }
    // Any other image section (created before the hooks, by NtCreateSectionEx, or handed
    // over from another process): judge the file that is actually mapped.
    const std::wstring path = win::mapped_file_name(base);
    trust::Decision d;
    {
        timing::Scope scope(config::Module::module_trust);
        d = trust::decide_path(path);
    }
    if (d.verdict.allowed) {
        modules::add(b, size, d.verdict.trust, d.facts.path);
        report_inventory(d);
        return true;
    }
    deny_module(d, d.verdict.reason, "map");
    if (!config::closes(config::Module::module_trust)) {
        modules::add(b, size, trust::Trust::unknown, d.facts.path);
        return true;
    }
    return false;
}

void on_view_unmapped(void* base) { modules::remove(reinterpret_cast<std::uintptr_t>(base)); }

void register_loader_notifications() {
    const auto& a = nt::api();
    if (a.LdrRegisterDllNotification) a.LdrRegisterDllNotification(0, &on_loader_event, nullptr, &g_cookie);
}

trust::Decision decide_loaded_module(std::uintptr_t base, std::size_t, const std::wstring& peb_name) {
    std::wstring path = win::mapped_file_name(reinterpret_cast<void*>(base));
    if (path.empty()) path = peb_name;
    return trust::decide_path(path);
}

void deny_module(const trust::Decision& d, config::Reason reason, const char* phase) {
    const std::wstring file = win::file_name_of(d.facts.path);
    const std::uintptr_t requester = load_requester();
    const std::uintptr_t start = current_thread_start();

    report::Event ev;
    const bool denylisted = reason == config::Reason::denylisted_module;
    ev.type = denylisted ? "close.denylisted_module" : reason == config::Reason::early_module ? "close.early_module"
                                                                                              : "close.untrusted_module";
    ev.level = report::Level::error;
    ev.title = std::string(denylisted ? "Closed: denylisted module " : "Closed: unknown module ") + cards::file_label(d);
    JsonWriter w;
    w.begin_object();
    w.key("file").raw(cards::file_card_json(d));
    w.field("phase", phase);
    w.field("jvm_started", jvm_started());
    w.key("loaded_by").raw(cards::address_json(requester));
    w.key("thread_start").raw(cards::address_json(start));
    w.field("remote_loadlibrary_thread", started_at_loadlibrary(start));
    w.field("reason", config::reason(reason).id);
    w.end_object();
    ev.extra_json = w.take();
    // One GlitchTip issue per file (ТЗ §12): SHA-256 when known, the file name otherwise.
    std::string key = d.facts.hashed ? d.facts.sha256.hex() : std::string();
    if (key.empty()) {
        HANDLE h = trust::open_read(d.facts.path);
        Sha256Digest sha{};
        if (h != INVALID_HANDLE_VALUE) {
            if (trust::sha256_of(h, sha, 512ull << 20)) key = sha.hex();
            CloseHandle(h);
        }
    }
    if (key.empty()) key = to_utf8(lower_ascii(file));
    ev.fingerprint = {ev.type, key};
    guard::signal(config::Module::module_trust, reason, file, std::move(ev));
}

}  // namespace mebet::gate
