// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "scan/scans.hpp"

#include "nt.hpp"  // windows.h before detours.h

#include <detours.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <thread>
#include <vector>

#include "config.hpp"
#include "core/exec_table.hpp"
#include "core/foreign_stop.hpp"
#include "core/guard.hpp"
#include "core/module_table.hpp"
#include "core/watchdog.hpp"
#include "core/win_util.hpp"
#include "hooks/exec_guard.hpp"
#include "hooks/load_gate.hpp"
#include "json_writer.hpp"
#include "process/dacl.hpp"
#include "report/cards.hpp"
#include "strings.hpp"
#include "trust/file_identity.hpp"

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
    // The thread is running in there already: stop its code (core/foreign_stop.hpp). Not before the
    // guard is armed — at start-up the walk would stop regions still to be judged, and the main
    // thread that carries that close out could run into one of them.
    if (guard::armed() && config::closes(config::Module::foreign_threads)) stop::foreign_code(start);
}

// `path`: the file mapped there, read when the image was found (it may be gone by now).
void close_hidden_image(std::uintptr_t base, const std::wstring& path) {
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
    if (guard::armed() && config::closes(config::Module::hidden_images)) stop::hidden_image(base);
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
    // Hashed for the report above; now it stops running (and so does every other unvouched region).
    if (guard::armed() && config::closes(config::Module::foreign_exec_memory))
        stop::foreign_code(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
}

bool loader_knows(std::uintptr_t addr) {
    HMODULE m = nullptr;
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(addr), &m) != 0;
}

// Machine type and SizeOfImage from a mapped image's headers (SizeOfImage sits at the same
// offset in PE32 and PE32+). False when the headers are not readable.
bool image_header(std::uintptr_t base, USHORT* machine, DWORD* size) {
    __try {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || dos->e_lfanew > 0x800) return false;
        const auto* nth = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
        if (nth->Signature != IMAGE_NT_SIGNATURE) return false;
        *machine = nth->FileHeader.Machine;
        *size = nth->OptionalHeader.SizeOfImage;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// M-01. Under WOW64 the system maps its own native images into every 32-bit process before
// any of our code runs: the native ntdll and the WOW64 layer (wow64*.dll; xtajit.dll on ARM64).
// The 32-bit loader list does not have them, so they looked like images mapped around the
// loader and the x86 build closed itself (hidden_image, 214) on every 64-bit Windows. Accept
// exactly those: the OS's native machine type, a WOW64-layer name, mapped from the native
// System32 (the kernel reports the real path) and Microsoft-signed, checked through Sysnative
// because a 32-bit process opening System32 is redirected to SysWOW64.
bool wow64_layer_image(std::uintptr_t base) {
    static const USHORT native = win::wow64_native_machine();
    if (native == IMAGE_FILE_MACHINE_UNKNOWN) return false;
    USHORT machine = 0;
    DWORD size = 0;
    if (!image_header(base, &machine, &size) || machine != native || size == 0) return false;
    // The header is only a hint: the range recorded is what the kernel has mapped, and a header
    // that disagrees with it was rewritten.
    const std::size_t extent = win::image_extent(base);
    if (!extent || ((static_cast<std::size_t>(size) + 0xFFF) & ~static_cast<std::size_t>(0xFFF)) != extent) return false;
    const std::wstring path = win::mapped_file_name(reinterpret_cast<void*>(base));
    const std::wstring name = win::file_name_of(path);
    static const wchar_t* const kLayer[] = {L"ntdll.dll",    L"wow64.dll",    L"wow64base.dll", L"wow64con.dll",
                                            L"wow64win.dll", L"wow64cpu.dll", L"xtajit.dll",    L"wowarmhw.dll"};
    bool layer = false;
    for (const wchar_t* k : kLayer) layer = layer || iequals_ascii(name, k);
    if (!layer || !win::same_path(path, win::windows_dir() + L"\\System32\\" + name)) return false;
    const trust::Decision d = trust::decide_path(win::windows_dir() + L"\\Sysnative\\" + name);
    if (!d.verdict.allowed || d.verdict.trust != trust::Trust::os) return false;
    modules::add(base, extent, trust::Trust::os, path);
    return true;
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

// A hooked call records the memory it has just made a moment after making it; the loader maps an
// image a moment before it lists it and drops it from its list (the guard forgets it then) a
// moment before it unmaps it. The periodic walk can catch any of them in between, and what it
// sees then looks like foreign code or a hidden image: games were closed for only loading or
// unloading a library. So before it judges such a find the walk looks again a few times over a
// quarter of a second — and while a hooked call is still between its real call and its record (a
// thread preempted right there), up to ten seconds longer. What has not settled by then is judged
// in this very sweep; nothing is carried over to the next one.
//
// What counts as settled is narrow on purpose. Executable memory: only a record made meanwhile.
// Memory that turns non-executable or goes away was still seen executable and unrecorded —
// counted as settled, it let shellcode that flips RX/RW slip through every sweep. An image: a
// record, the loader listing it, or the image gone with a file the trust engine allows.
//
// M-07, for the record: the sweep once skipped everything while a call was in flight, and a
// thread killed inside a hook left that count up for good. Now only calls on live threads count.
constexpr DWORD kSettleMs[] = {2, 18, 60, 170};
// A call still between its real call and its record, on a thread that still runs (descheduled
// right there, say) gets this long. A thread killed inside a hook is not waited for at all.
constexpr DWORD kInFlightMaxMs = 10000;
constexpr DWORD kInFlightStepMs = 50;
// A view whose file the load gate is judging: as long as a check may take, and some.
std::uint64_t pending_max_ms() { return static_cast<std::uint64_t>(config::opt::verify_timeout_ms) + 5000; }

// False — "nothing to judge" — as soon as a close is pending: the worker carries the close out
// only once the sweep returns, and the game must not run on for these seconds behind it.
template <typename Settled>
bool still_there(Settled settled) {
    for (const DWORD wait : kSettleMs) {
        if (guard::closing() || settled()) return false;
        Sleep(wait);
        watchdog::worker_beat();
    }
    // By the clock, not by summed sleeps: one settled() can block on a file open (a share that stalls),
    // and the loop must not then keep a whole sweep inside one find while every other check waits.
    const std::uint64_t deadline = GetTickCount64() + kInFlightMaxMs;
    while (GetTickCount64() < deadline && exec::live_op_within(kInFlightMaxMs)) {
        if (guard::closing() || settled()) return false;
        Sleep(kInFlightStepMs);
        watchdog::worker_beat();
    }
    return !guard::closing() && !settled();
}

// No image has its base at `alloc` any more.
bool image_gone(std::uintptr_t alloc) {
    MEMORY_BASIC_INFORMATION m{};
    return !VirtualQuery(reinterpret_cast<void*>(alloc), &m, sizeof(m)) || m.Type != MEM_IMAGE ||
           reinterpret_cast<std::uintptr_t>(m.AllocationBase) != alloc;
}

// Volume and file id of the file mapped at `alloc` (not size and time: those its owner can change
// while the image is mapped). False when it cannot be read.
bool mapped_file_id(std::uintptr_t alloc, trust::FileIdentity& id) {
    const std::wstring path = win::mapped_file_name(reinterpret_cast<void*>(alloc));
    if (path.empty()) return false;
    const HANDLE h = trust::open_read(path);
    if (h == INVALID_HANDLE_VALUE) return false;
    const bool ok = trust::identity_of(h, id);
    CloseHandle(h);
    return ok;
}

// How long the trust of a library the loader has unloaded is remembered for its image (scans).
constexpr std::uint64_t kUnloadedForgetMs = 5000;

bool same_file(const trust::FileIdentity& a, const trust::FileIdentity& b) {
    return a.volume == b.volume && std::memcmp(a.file_id, b.file_id, sizeof(a.file_id)) == 0;
}

// Opens the file mapped as an image at `alloc`, proven to be that very file: opened by the name the
// kernel gives for the mapping, and that name, read again, still leading to the same file.
// INVALID_HANDLE_VALUE when that cannot be proven, for instance because the image or its file
// changed in between.
HANDLE open_mapped_file(std::uintptr_t alloc) {
    const std::wstring name = win::mapped_file_name(reinterpret_cast<void*>(alloc));
    if (name.empty()) return INVALID_HANDLE_VALUE;
    const HANDLE h = trust::open_read(name);
    if (h == INVALID_HANDLE_VALUE) return h;
    // Proven by file id, not by comparing names: the name of the opened file comes back in another
    // form (long instead of 8.3, a volume instead of a mapped drive letter). The mapping's name,
    // read again after the open, must lead to this very file.
    trust::FileIdentity opened{}, mapped{};
    if (!trust::identity_of(h, opened) || !mapped_file_id(alloc, mapped) || !same_file(opened, mapped)) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

// The file of an image the loader lists was refused by the periodic walk. A file that was read and
// judged was there — refused, whatever happens to the image next: one that vanished for an instant
// while it was judged escaped every sweep. Only a refusal without a readable file is looked at
// again: a library unloaded while its file was being judged leaves nothing to read, and another
// library may already sit at its address (a game was closed for an "untrusted module" with no
// name). That one stands unless the image was recorded by a hook or went away — or the file mapped
// there can be read now and is allowed, judged right then. Never let off for being readable alone:
// whoever mapped it decides when its file can be opened, and was let off every sweep.
bool refusal_stands(std::uintptr_t alloc, const trust::Decision& d) {
    if (d.facts.identity_known) return true;
    bool stands = true;
    const bool unsettled = still_there([&] {
        if (modules::find(alloc) || image_gone(alloc)) {
            stands = false;
            return true;
        }
        const HANDLE h = open_mapped_file(alloc);
        if (h == INVALID_HANDLE_VALUE) return false;
        stands = !trust::decide(h, win::mapped_file_name(reinterpret_cast<void*>(alloc))).verdict.allowed;
        CloseHandle(h);
        return true;
    });
    return unsettled || stands;
}

// The record at `alloc` still describes the image mapped there: the very file it was made for, told by
// its id — or, for a record without one (a KnownDLL, a WOW64 image, a file whose id the loader's
// handle could not read), by the kernel's name, and then by the id of the file under the record's own
// name (proven once, kept). Unreadable is not proof: a library on its way out is let go when it is
// gone, but a file kept from the guard by whoever mapped it leaves the record unproven.
bool record_holds(std::uintptr_t alloc, const modules::Record& rec) {
    if (!rec.id_known && rec.path.empty() && rec.kernel_name.empty())
        return true;  // nothing to compare with (the guard's own views)
    bool stale = false;  // set only when a DIFFERENT file is positively seen mapped there
    auto look = [&] {
        if (image_gone(alloc)) return true;  // going: the unmap hook removes the record; hold for now
        // The mapping's name as the kernel gives it now, against the one stored when the record was made
        // — both in the same form, so they compare reliably, and a different file swapped in at this base
        // has a different name even when its own file cannot be opened to compare ids (a cheat unmapping a
        // trusted DLL by a direct syscall, mapping its own there, and keeping that file unreadable).
        if (!rec.kernel_name.empty()) {
            const std::wstring name = win::mapped_file_name(reinterpret_cast<void*>(alloc));
            if (name.empty()) return false;  // cannot read the mapping's name now: not proof, retry
            if (!win::name_equals(name, rec.kernel_name)) {
                stale = true;  // a different file is mapped here
                return true;
            }
            // The same name. An overwrite in place keeps the name, so confirm by id when it can be read.
            trust::FileIdentity now{};
            if (rec.id_known && mapped_file_id(alloc, now)) stale = !same_file(now, rec.id);
            return true;
        }
        trust::FileIdentity now{};
        if (rec.id_known) {
            if (!mapped_file_id(alloc, now)) return false;  // its file cannot be read now: not proof of a swap
            stale = !same_file(now, rec.id);
            return true;
        }
        const std::wstring name = win::mapped_file_name(reinterpret_cast<void*>(alloc));
        if (name.empty()) return false;
        if (win::name_equals(name, rec.path)) {  // the same name: hold, and pin the id if it can be read
            trust::FileIdentity was{};
            const HANDLE h = trust::open_read(rec.path);
            const bool known = h != INVALID_HANDLE_VALUE && trust::identity_of(h, was);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
            if (known && mapped_file_id(alloc, now) && same_file(now, was))
                modules::prove_identity(alloc, rec.serial, now);
            return true;
        }
        // A different name is mapped here. Only a readable, differing id makes the record stale.
        trust::FileIdentity was{};
        const HANDLE h = trust::open_read(rec.path);
        const bool known = h != INVALID_HANDLE_VALUE && trust::identity_of(h, was);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        if (!known || !mapped_file_id(alloc, now)) return false;  // cannot compare: not proof
        stale = !same_file(now, was);
        return true;
    };
    // Never closed for a file that could not be read — whoever mapped it decides when it opens, and
    // an honest module whose file was locked or whose share dropped was closed for it. Stale only on
    // positive evidence; a brief settle window lets a transient read succeed.
    if (!look()) still_there(look);
    return !stale;
}

void sweep_memory(SweepMode mode) {
    const bool periodic = mode == SweepMode::periodic;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto addr = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto max = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    if (addr < 0x10000) addr = 0x10000;
    std::uintptr_t last_image_base = 0;
    while (addr < max && !guard::closing()) {
        const std::uint64_t forgotten_before = exec::forget_generation();  // before the look (exec::forgotten_since)
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) break;
        const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uintptr_t next = base + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
        watchdog::worker_beat();  // a walk over a big process is work, not silence
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & 0xF0) || (mbi.Protect & PAGE_GUARD)) continue;
        if (mbi.Type == MEM_IMAGE) {
            const auto alloc = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
            if (alloc == last_image_base) continue;
            last_image_base = alloc;
            modules::Record rec;
            std::uintptr_t owner = 0;
            if (modules::record_at(alloc, &rec)) {
                // A record holds only while the file mapped there is the one judged. A view unmapped
                // past the hooks (a direct system call, another process) left its record behind, and
                // another image mapped at that base was taken for the old trusted one for good.
                if (record_holds(alloc, rec)) continue;
                modules::remove_if(alloc, rec.serial);  // stale: judged below like any image
            } else if (modules::find(alloc, nullptr, &owner)) {
                // An image starting inside the range of another record: images never overlap, so the
                // one recorded there is gone, and its range lent its trust to whatever is mapped in it
                // now — this image went unjudged for good. That record is stale; this image is judged.
                modules::Record old;
                if (owner == alloc || !modules::record_at(owner, &old)) continue;
                modules::remove_if(owner, old.serial);
            }
            if (!config::enabled(config::Module::hidden_images)) continue;
            if (modules::pending_within(alloc, pending_max_ms())) continue;  // its file is being judged
            if (loader_knows(alloc)) {
                // Loaded past the hooks (a direct system call, another process): judge the file now.
                const std::wstring path = win::mapped_file_name(reinterpret_cast<void*>(alloc));
                const trust::Decision d = trust::decide_path(path);
                if (d.verdict.allowed) {
                    // The verdict is about the file that was mapped when its name was read. The
                    // library may have been unloaded since, and another loaded at its address:
                    // recorded only if that file is still what is mapped, never over a record a
                    // hook has made meanwhile, and taken back if the image went away in between.
                    // The same file — told by its id, as the trust engine judged it: a name says
                    // nothing of the file found under it a moment later.
                    auto still_judged_file = [&] {
                        trust::FileIdentity now{};
                        return d.facts.identity_known && mapped_file_id(alloc, now) && same_file(now, d.facts.identity);
                    };
                    const std::size_t extent = win::image_extent(alloc);
                    if (extent && still_judged_file()) {
                        const std::uint64_t serial = modules::add_if_absent(alloc, extent, d.verdict.trust, d.facts.path,
                                                                            &d.facts.identity);
                        if (serial && !still_judged_file()) modules::remove_if(alloc, serial);
                    }
                } else if (!periodic || refusal_stands(alloc, d)) {
                    gate::deny_module(d, d.verdict.reason, mode == SweepMode::startup ? "startup" : "sweep");
                }
                continue;
            }
            if (wow64_layer_image(alloc)) continue;  // the system's own WOW64 images (M-01)
            const std::wstring found = win::mapped_file_name(reinterpret_cast<void*>(alloc));
            {
                // Neither recorded nor listed (at start-up as well: other threads load meanwhile). A
                // hidden image stays so. A library in the middle of
                // loading or unloading does not: a moment later it is recorded or listed — or gone.
                // Gone is forgiven only for what is known to be harmless: a library the loader has
                // just unloaded (its trust is remembered from its record), or a file proven to be the
                // one that was mapped and allowed by the trust engine. Never by a name alone: the
                // file found under a name a moment later can be another one, and a name can be too
                // long to read.
                const HANDLE mapped = open_mapped_file(alloc);
                bool gone = false;
                const bool stays = still_there([&] {
                    if (modules::find(alloc) || loader_knows(alloc) || modules::pending_within(alloc, pending_max_ms()))
                        return true;
                    gone = image_gone(alloc);
                    return gone;
                });
                bool forgiven = !stays && !gone;
                if (!stays && gone) {
                    // A file proven to be the mapped one and allowed. Or the library the loader has
                    // just unloaded from this base — told by its own record: the very file it named,
                    // still one the trust engine allows (the image was found between the unload
                    // notification and the unmap, and was gone before it could be proven). Or no
                    // name at all, already unreadable when it was found: unmapped right then. Never
                    // by the base alone: a cheat could unload a signed library at that base on
                    // purpose and map its own image there.
                    forgiven = (mapped != INVALID_HANDLE_VALUE && trust::decide(mapped, found).verdict.allowed) ||
                               (found.empty() && modules::unloaded_recently(alloc, kUnloadedForgetMs)) ||
                               (!found.empty() && modules::unloaded_recently_file(alloc, kUnloadedForgetMs, found) &&
                                trust::decide_path(found).verdict.allowed);
                }
                if (mapped != INVALID_HANDLE_VALUE) CloseHandle(mapped);
                if (forgiven) continue;
            }
            close_hidden_image(alloc, found);
            continue;
        }
        // MEM_PRIVATE / MEM_MAPPED executable.
        if (!config::enabled(config::Module::foreign_exec_memory)) continue;
        if (exec::covers(base, next)) continue;
        if (mode == SweepMode::startup && preexisting_region_ok(base, next)) {
            exec::allow(base, next, exec::Owner{trust::Trust::os, 0, exec::Source::preexisting});
            continue;
        }
        if (periodic && !still_there([&] {
                return exec::covers(base, next) || exec::forgotten_since(base, next, forgotten_before);
            }))
            continue;
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
        watchdog::worker_beat();
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
    const std::size_t extent = win::image_extent(base);  // the kernel's, not the loader's entry
    if (!extent) return;
    const std::wstring path = win::mapped_file_name(m);  // from the kernel, not the PEB
    const std::wstring name = lower_ascii(win::file_name_of(path));
    if (win::same_path(win::dir_of(path), win::image_system_dir())) {
        for (const auto& k : known) {
            if (name == k) {
                modules::add(base, extent, trust::Trust::known_dll, path);
                return;
            }
        }
    }
    const trust::Decision d = gate::decide_loaded_module(base, extent, win::module_path(m));
    if (d.verdict.allowed) {
        modules::add(base, extent, d.verdict.trust, d.facts.path, d.facts.identity_known ? &d.facts.identity : nullptr);
    } else if (config::enabled(config::Module::startup_self_check)) {
        modules::add(base, extent, trust::Trust::unknown, d.facts.path);
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
        // The thread has not run one instruction of its own yet. A hand-mapped image (memory written
        // from outside, sections relocated and imports resolved by the injector, a thread started at
        // its entry — no loader, so no load gate) was only reported here, and the thread then went on
        // into the cheat while the close took its time. Its code is made non-executable before this
        // returns: the thread faults on its first instruction and is parked there
        // (core/foreign_stop.hpp). Only when the close is real — in report mode the game runs on.
        const unsigned stopped = config::closes(config::Module::foreign_threads) ? stop::foreign_code(start) : 0u;
        // Inside DllMain: keep it light, the worker builds the full report.
        report::Event ev;
        ev.type = "close.foreign_thread";
        ev.level = report::Level::error;
        ev.title = "Closed: thread starting outside allowed code";
        ev.extra_json = "{\"when\":\"thread_attach\",\"start\":\"" + cards::address_hex(start) +
                        "\",\"stopped_regions\":" + std::to_string(stopped) + "}";
        ev.fingerprint = {"close.foreign_thread", "thread_attach"};
        guard::signal(config::Module::foreign_threads, config::Reason::foreign_thread, std::wstring(), std::move(ev));
    }
}

}  // namespace mebet::scan
