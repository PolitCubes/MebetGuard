#include "scan/scans.hpp"

#include "nt.hpp"  // windows.h before detours.h

#include <detours.h>
#include <psapi.h>

#include <atomic>
#include <cstring>
#include <map>
#include <thread>
#include <vector>

#include "config.hpp"
#include "core/exec_table.hpp"
#include "core/guard.hpp"
#include "core/module_table.hpp"
#include "core/win_util.hpp"
#include "hooks/exec_guard.hpp"
#include "hooks/load_gate.hpp"
#include "json_writer.hpp"
#include "process/dacl.hpp"
#include "report/cards.hpp"
#include "strings.hpp"

namespace mebet::scan {

namespace {

// ---- Known threads: id → creation time (a reused id with another creation time is new).
struct Threads {
    SRWLOCK lock = SRWLOCK_INIT;
    std::map<DWORD, std::uint64_t> known;
};

Threads& threads() {
    static Threads* t = new Threads();
    return *t;
}

std::uint64_t creation_time(HANDLE thread) {
    FILETIME c{}, e{}, k{}, u{};
    if (!GetThreadTimes(thread, &c, &e, &k, &u)) return 0;
    return (static_cast<std::uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
}

std::uintptr_t start_address(HANDLE thread) {
    PVOID start = nullptr;
    const auto& a = nt::api();
    if (!a.NtQueryInformationThread ||
        !nt::ok(a.NtQueryInformationThread(thread, nt::kThreadQuerySetWin32StartAddress, &start, sizeof(start), nullptr)))
        return 0;
    return reinterpret_cast<std::uintptr_t>(start);
}

void close_foreign_thread(std::uintptr_t start, DWORD tid, const char* when) {
    report::Event ev;
    ev.type = "close.foreign_thread";
    ev.level = report::Level::error;
    ev.title = "Closed: thread starting outside allowed code";
    JsonWriter w;
    w.begin_object();
    w.field("when", when);
    w.field("thread_id", static_cast<std::uint64_t>(tid));
    w.key("start").raw(cards::address_json(start));
    std::string key;
    w.key("region").raw(cards::region_json(start, &key));
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.foreign_thread", key.empty() ? std::string("no_region") : key};
    guard::signal(config::Module::foreign_threads, config::Reason::foreign_thread, std::wstring(), std::move(ev));
}

void close_hidden_image(std::uintptr_t base) {
    const std::wstring path = win::mapped_file_name(reinterpret_cast<void*>(base));
    report::Event ev;
    ev.type = "close.hidden_image";
    ev.level = report::Level::error;
    ev.title = "Closed: image mapped around the loader " + to_utf8(win::file_name_of(path));
    JsonWriter w;
    w.begin_object();
    w.field("base", cards::address_hex(base));
    std::string group;
    if (!path.empty()) {
        const trust::Decision d = trust::decide_path(path);
        w.key("file").raw(cards::file_card_json(d));
        group = d.facts.hashed ? d.facts.sha256.hex() : to_utf8(lower_ascii(win::file_name_of(path)));
    } else {
        w.key("region").raw(cards::region_json(base, &group));
    }
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.hidden_image", group};
    guard::signal(config::Module::hidden_images, config::Reason::hidden_image, win::file_name_of(path), std::move(ev));
}

void close_foreign_region(const MEMORY_BASIC_INFORMATION& mbi, const char* when) {
    report::Event ev;
    ev.type = "close.foreign_code";
    ev.level = report::Level::error;
    ev.title = std::string("Closed: executable ") + (mbi.Type == MEM_MAPPED ? "mapped" : "private") +
               " memory outside the allowed table";
    std::string key;
    JsonWriter w;
    w.begin_object();
    w.field("when", when);
    w.field("source", "sweep: allocated outside the hooks or from another process");
    w.key("region").raw(cards::region_json(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), &key));
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.foreign_code", key.empty() ? std::string("unreadable") : key};
    guard::signal(config::Module::foreign_exec_memory, config::Reason::foreign_code, std::wstring(), std::move(ev));
}

bool loader_knows(std::uintptr_t addr) {
    HMODULE m = nullptr;
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(addr), &m) != 0;
}

bool committed_exec(std::uintptr_t a) {
    MEMORY_BASIC_INFORMATION m{};
    return VirtualQuery(reinterpret_cast<void*>(a), &m, sizeof(m)) && m.State == MEM_COMMIT && (m.Protect & 0xF0) &&
           !(m.Protect & PAGE_GUARD);
}

bool readable(std::uintptr_t a, std::size_t n) {
    MEMORY_BASIC_INFORMATION m{};
    if (!VirtualQuery(reinterpret_cast<void*>(a), &m, sizeof(m)) || m.State != MEM_COMMIT) return false;
    if (m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    if (!(m.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                       PAGE_EXECUTE_WRITECOPY)))
        return false;
    return a + n <= reinterpret_cast<std::uintptr_t>(m.BaseAddress) + m.RegionSize;
}

// ТЗ §5: executable memory created before the hooks (antivirus trampolines) cannot prove
// who asked for it; it is allowed only if its jumps lead into an allowed module.
bool preexisting_region_ok(std::uintptr_t begin, std::uintptr_t end) {
    int good = 0, bad = 0;
    const std::uintptr_t limit = end - begin > 0x10000 ? begin + 0x10000 : end;
    auto judge = [&](std::uintptr_t t) {
        if (!t || (t >= begin && t < end)) return;
        trust::Trust tr;
        if (modules::find(t, &tr)) {
            if (tr != trust::Trust::unknown) ++good; else ++bad;
        } else if (committed_exec(t)) {
            ++bad;
        }
    };
    __try {
#if defined(_M_ARM64)
        for (std::uintptr_t p = begin; p + 4 <= limit; p += 4) {
            const std::uint32_t op = *reinterpret_cast<const std::uint32_t*>(p);
            if ((op & 0x7C000000u) == 0x14000000u) {  // B / BL imm26
                std::int32_t imm = static_cast<std::int32_t>(op & 0x03FFFFFFu);
                if (imm & 0x02000000) imm -= 0x04000000;
                judge(p + static_cast<std::intptr_t>(imm) * 4);
            } else if ((op & 0xFF000000u) == 0x58000000u) {  // LDR Xt, literal
                std::int32_t imm19 = static_cast<std::int32_t>((op >> 5) & 0x7FFFFu);
                if (imm19 & 0x40000) imm19 -= 0x80000;
                const std::uintptr_t lit = p + static_cast<std::intptr_t>(imm19) * 4;
                if (readable(lit, 8)) judge(*reinterpret_cast<const std::uintptr_t*>(lit));
            }
        }
#else
        std::uintptr_t p = begin;
        while (p < limit) {
            const auto* b = reinterpret_cast<const unsigned char*>(p);
            if (b[0] == 0xFF && b[1] == 0x25) {  // jmp [rip+disp32] / jmp [abs32]
#if defined(_M_X64)
                const std::uintptr_t slot = p + 6 + *reinterpret_cast<const std::int32_t*>(b + 2);
#else
                const std::uintptr_t slot = *reinterpret_cast<const std::uint32_t*>(b + 2);
#endif
                if (readable(slot, sizeof(void*))) judge(*reinterpret_cast<const std::uintptr_t*>(slot));
                p += 6;
                continue;
            }
#if defined(_M_X64)
            if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) {  // mov rax, imm64; jmp rax
                judge(*reinterpret_cast<const std::uintptr_t*>(b + 2));
                p += 12;
                continue;
            }
#endif
            PVOID target = nullptr;
            LONG extra = 0;
            const auto next = reinterpret_cast<std::uintptr_t>(
                DetourCopyInstruction(nullptr, nullptr, reinterpret_cast<PVOID>(p), &target, &extra));
            if (!next || next <= p) {
                ++p;
                continue;
            }
            if (target && target != DETOUR_INSTRUCTION_TARGET_DYNAMIC) judge(reinterpret_cast<std::uintptr_t>(target));
            p = next;
        }
#endif
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // the region changed under us; judge on what we saw
    }
    return good > 0 && bad == 0;
}

enum class SweepMode { startup, periodic };

void sweep_memory(SweepMode mode) {
    if (mode == SweepMode::periodic && exec::ops_in_flight()) return;  // judge next round
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto addr = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto max = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    if (addr < 0x10000) addr = 0x10000;
    std::uintptr_t last_image_base = 0;
    while (addr < max && !guard::closing()) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) break;
        const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uintptr_t next = base + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & 0xF0) || (mbi.Protect & PAGE_GUARD)) continue;
        if (mbi.Type == MEM_IMAGE) {
            const auto alloc = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
            if (alloc == last_image_base) continue;
            last_image_base = alloc;
            if (modules::find(alloc)) continue;
            if (!config::enabled(config::Module::hidden_images)) continue;
            if (loader_knows(alloc)) {
                // Loaded by a path the hooks do not see (NtMapViewOfSectionEx): judge the file now.
                const std::wstring path = win::mapped_file_name(reinterpret_cast<void*>(alloc));
                const trust::Decision d = trust::decide_path(path);
                if (d.verdict.allowed) {
                    MODULEINFO mi{};
                    if (GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(alloc), &mi, sizeof(mi)))
                        modules::add(alloc, mi.SizeOfImage, d.verdict.trust, d.facts.path);
                } else {
                    gate::deny_module(d, d.verdict.reason, mode == SweepMode::startup ? "startup" : "sweep");
                }
                continue;
            }
            close_hidden_image(alloc);
            continue;
        }
        // MEM_PRIVATE / MEM_MAPPED executable.
        if (!config::enabled(config::Module::foreign_exec_memory)) continue;
        if (exec::covers(base, next)) continue;
        if (mode == SweepMode::startup && preexisting_region_ok(base, next)) {
            exec::allow(base, next, exec::Owner{trust::Trust::os, 0, exec::Source::preexisting});
            continue;
        }
        if (mode == SweepMode::periodic && exec::ops_in_flight()) return;
        close_foreign_region(mbi, mode == SweepMode::startup ? "startup" : "sweep");
    }
}

void sweep_threads(SweepMode mode) {
    if (!config::enabled(config::Module::foreign_threads)) return;
    const auto& a = nt::api();
    if (!a.NtGetNextThread) return;
    Threads& t = threads();
    HANDLE prev = nullptr;
    for (int i = 0; i < 8192 && !guard::closing(); ++i) {
        HANDLE next = nullptr;
        if (!nt::ok(a.NtGetNextThread(nt::current_process(), prev, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &next)) || !next) break;
        if (prev) CloseHandle(prev);
        prev = next;
        const DWORD tid = GetThreadId(next);
        const std::uint64_t created = creation_time(next);
        AcquireSRWLockShared(&t.lock);
        auto it = t.known.find(tid);
        const bool known = it != t.known.end() && it->second == created;
        ReleaseSRWLockShared(&t.lock);
        if (known) continue;
        // Not seen yet (SKIP_THREAD_ATTACH, or before the agent): its DACL is still the default.
        HANDLE h = OpenThread(THREAD_QUERY_INFORMATION | WRITE_DAC | READ_CONTROL, FALSE, tid);
        if (!h) continue;
        const std::uintptr_t start = start_address(h);
        dacl::protect_thread(h);
        CloseHandle(h);
        AcquireSRWLockExclusive(&t.lock);
        t.known[tid] = created;
        ReleaseSRWLockExclusive(&t.lock);
        if (start && !allowed_code(start)) close_foreign_thread(start, tid, mode == SweepMode::startup ? "startup" : "sweep");
    }
    if (prev) CloseHandle(prev);
}

}  // namespace

bool allowed_code(std::uintptr_t address) {
    trust::Trust t;
    if (modules::find(address, &t)) return t != trust::Trust::unknown;
    exec::Owner o{};
    if (exec::find(address, &o)) return o.trust != trust::Trust::unknown;
    return false;
}

namespace {

// KnownDLLs: section objects the system builds at boot from System32 (\KnownDlls) or
// SysWOW64 (\KnownDlls32). A module with such a name that sits in that folder came from
// there; only an administrator can change the list or the files.
std::vector<std::wstring> known_dll_names() {
    std::vector<std::wstring> out{L"ntdll.dll"};
    const wchar_t* key = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs";
    for (const auto& value : win::reg_value_names(HKEY_LOCAL_MACHINE, key)) {
        const std::wstring name = lower_ascii(win::reg_string(HKEY_LOCAL_MACHINE, key, value.c_str()));
        if (iends_with(name, L".dll")) out.push_back(name);
    }
    return out;
}

void check_loaded_module(HMODULE m, const std::vector<std::wstring>& known) {
    const auto base = reinterpret_cast<std::uintptr_t>(m);
    if (modules::find(base)) return;  // mapped through the hook already
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof(mi))) return;
    const std::wstring path = win::mapped_file_name(m);  // from the kernel, not the PEB
    const std::wstring name = lower_ascii(win::file_name_of(path));
    if (win::same_path(win::dir_of(path), win::image_system_dir())) {
        for (const auto& k : known) {
            if (name == k) {
                modules::add(base, mi.SizeOfImage, trust::Trust::known_dll, path);
                return;
            }
        }
    }
    const trust::Decision d = gate::decide_loaded_module(base, mi.SizeOfImage, win::module_path(m));
    if (d.verdict.allowed) {
        modules::add(base, mi.SizeOfImage, d.verdict.trust, d.facts.path);
    } else if (config::enabled(config::Module::startup_self_check)) {
        modules::add(base, mi.SizeOfImage, trust::Trust::unknown, d.facts.path);
        gate::deny_module(d, config::Reason::early_module, "startup");
    }
}

}  // namespace

void startup_check() {
    // 1. Every module in the loader list, by the same rule as new loads (ТЗ §5). The
    //    signature checks are independent, so they run on a few threads (ТЗ §2: speed).
    HMODULE mods[1024];
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        const DWORD n = needed / sizeof(HMODULE) < 1024 ? needed / sizeof(HMODULE) : 1024;
        const std::vector<std::wstring> known = known_dll_names();
        std::atomic<DWORD> next{0};
        auto work = [&]() {
            for (DWORD i = next.fetch_add(1); i < n && !guard::closing(); i = next.fetch_add(1))
                check_loaded_module(mods[i], known);
        };
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const unsigned helpers = si.dwNumberOfProcessors > 4 ? 3u : si.dwNumberOfProcessors > 1 ? si.dwNumberOfProcessors - 1 : 0u;
        std::vector<std::thread> pool;
        for (unsigned h = 0; h < helpers; ++h) pool.emplace_back(work);
        work();
        for (auto& t : pool) t.join();
    }
    // 2. One full pass over memory and threads (ТЗ §5): early injections before the agent.
    execguard::judge_pending();
    sweep_memory(SweepMode::startup);
    sweep_threads(SweepMode::startup);
    guard::arm();
}

void memory_sweep() { sweep_memory(SweepMode::periodic); }
void thread_sweep() { sweep_threads(SweepMode::periodic); }

void on_thread_attach() {
    const std::uintptr_t start = start_address(nt::current_thread());
    dacl::protect_current_thread();
    Threads& t = threads();
    const DWORD tid = GetCurrentThreadId();
    const std::uint64_t created = creation_time(GetCurrentThread());
    AcquireSRWLockExclusive(&t.lock);
    t.known[tid] = created;
    ReleaseSRWLockExclusive(&t.lock);
    if (guard::armed() && start && config::enabled(config::Module::foreign_threads) && !allowed_code(start)) {
        // Inside DllMain: keep it light, the worker builds the full report.
        report::Event ev;
        ev.type = "close.foreign_thread";
        ev.level = report::Level::error;
        ev.title = "Closed: thread starting outside allowed code";
        ev.extra_json = "{\"when\":\"thread_attach\",\"start\":\"" + cards::address_hex(start) + "\"}";
        ev.fingerprint = {"close.foreign_thread", "thread_attach"};
        guard::signal(config::Module::foreign_threads, config::Reason::foreign_thread, std::wstring(), std::move(ev));
    }
}

}  // namespace mebet::scan
