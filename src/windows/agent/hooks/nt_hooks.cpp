// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "hooks/nt_hooks.hpp"

#include "nt.hpp"  // windows.h must come before detours.h

#include <detours.h>

#include <cstring>
#include <vector>

#include "core/exec_table.hpp"
#include "core/guard.hpp"
#include "core/module_table.hpp"
#include "core/watchdog.hpp"
#include "hooks/exec_guard.hpp"
#include "hooks/load_gate.hpp"
#include "strings.hpp"

// The CRT's index of this module's implicit TLS block (tlssup).
extern "C" unsigned long _tls_index;

namespace mebet::hooks {

namespace {

// Originals (Detours replaces them with trampolines on attach).
nt::NtCreateSectionFn real_NtCreateSection = nullptr;
nt::NtMapViewOfSectionFn real_NtMapViewOfSection = nullptr;
nt::NtUnmapViewOfSectionFn real_NtUnmapViewOfSection = nullptr;
nt::NtAllocateVirtualMemoryFn real_NtAllocateVirtualMemory = nullptr;
nt::NtProtectVirtualMemoryFn real_NtProtectVirtualMemory = nullptr;
nt::NtFreeVirtualMemoryFn real_NtFreeVirtualMemory = nullptr;

// Canary tokens: an argument pointer only the self-check passes (ТЗ §7 «канарейка»).
// With our hook in place the call never reaches the kernel; without it the kernel sees
// arguments that fail validation and does nothing.
volatile PVOID g_tokens[6];
volatile LONG g_canary_hits = 0;
inline bool is_token(const volatile void* p, int i) { return p == &g_tokens[i]; }
inline NTSTATUS canary(int i) {
    InterlockedOr(&g_canary_hits, 1 << i);
    return static_cast<NTSTATUS>(0xC00000EFL);  // STATUS_INVALID_PARAMETER_1
}

constexpr NTSTATUS kAccessDenied = nt::kStatusAccessDenied;

// A thread gets our implicit TLS block (thread_local, and the guard MSVC checks on every use of
// a function-local static) only after its early init, and loses it before it is gone; the heap
// still allocates and decommits on such a thread (at exit) and lands in these hooks. Touching
// TLS there reads address 8 * _tls_index and kills the process — seen on Windows ARM64 as
// hook_NtFreeVirtualMemory → guard::shutting_down() → core() while a thread exits. So every
// hook passes such a thread straight through. Direct syscalls skip these hooks anyway; the
// periodic sweep still judges whatever memory the thread ends up with.
inline bool tls_ready() {
    // TEB: NT_TIB (7 pointers), EnvironmentPointer, ClientId (2), ActiveRpcHandle, then
    // ThreadLocalStoragePointer — pointer slot 11 on x86, x64 and ARM64 alike.
    const auto* teb = reinterpret_cast<void* const*>(NtCurrentTeb());
    const auto* slots = static_cast<void* const*>(teb[11]);
    return slots && slots[_tls_index];
}

// ---------------------------------------------------------------------------------------
// 1. NtCreateSection — the load gate.
NTSTATUS NTAPI hook_NtCreateSection(PHANDLE section, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
                                    PLARGE_INTEGER max_size, ULONG page_protection, ULONG allocation, HANDLE file) {
    if (is_token(section, 0)) return canary(0);
    if (!tls_ready()) {
        return real_NtCreateSection(section, access, attributes, max_size, page_protection, allocation, file);
    }
    watchdog::check_from_hook();
    const bool image = (allocation & nt::kSecImage) != 0 && (allocation & nt::kSecImageNoExecute) != nt::kSecImageNoExecute;
    if (!image || !file || guard::shutting_down() || gate::own_read_on_this_thread()) {  // fast path
        return real_NtCreateSection(section, access, attributes, max_size, page_protection, allocation, file);
    }
    if (!gate::on_image_section(file)) return kAccessDenied;
    const NTSTATUS s = real_NtCreateSection(section, access, attributes, max_size, page_protection, allocation, file);
    if (nt::ok(s) && section) gate::on_section_created(*section);
    return s;
}

// ---------------------------------------------------------------------------------------
// 2. NtMapViewOfSection — safety net for images, accounting for executable data views.
bool section_is_image(HANDLE section) {
    nt::SectionBasicInformation info{};
    SIZE_T ret = 0;
    const auto& a = nt::api();
    if (!a.NtQuerySection || !nt::ok(a.NtQuerySection(section, nt::kSectionBasicInformation, &info, sizeof(info), &ret)))
        return false;
    return (info.AllocationAttributes & nt::kSecImage) != 0 &&
           (info.AllocationAttributes & nt::kSecImageNoExecute) != nt::kSecImageNoExecute;
}

NTSTATUS NTAPI hook_NtMapViewOfSection(HANDLE section, HANDLE process, PVOID* base, ULONG_PTR zero_bits,
                                       SIZE_T commit, PLARGE_INTEGER offset, PSIZE_T view_size, ULONG inherit,
                                       ULONG allocation, ULONG protect) {
    if (is_token(base, 1)) return canary(1);
    if (!tls_ready()) {
        return real_NtMapViewOfSection(section, process, base, zero_bits, commit, offset, view_size, inherit,
                                       allocation, protect);
    }
    watchdog::check_from_hook();
    if (guard::shutting_down() || !execguard::is_current_process(process)) {
        return real_NtMapViewOfSection(section, process, base, zero_bits, commit, offset, view_size, inherit,
                                       allocation, protect);
    }
    const bool image = section_is_image(section);
    execguard::Requester req;
    if (!image && execguard::executable(protect)) {
        req = execguard::find_requester();
        if (!execguard::may_create_exec(req, "NtMapViewOfSection", 0, view_size ? *view_size : 0)) return kAccessDenied;
    }
    exec::op_begin();
    const NTSTATUS s =
        real_NtMapViewOfSection(section, process, base, zero_bits, commit, offset, view_size, inherit, allocation, protect);
    if (nt::ok(s) && base && *base && view_size) {
        if (image) {
            if (!gate::on_image_view(section, *base, *view_size)) {
                real_NtUnmapViewOfSection(process, *base);
                *base = nullptr;
                exec::op_end();
                return kAccessDenied;
            }
        } else if (execguard::executable(protect)) {
            execguard::record(reinterpret_cast<std::uintptr_t>(*base), *view_size, req, exec::Source::map);
        }
    }
    exec::op_end();
    return s;
}

// ---------------------------------------------------------------------------------------
// 3. NtUnmapViewOfSection — forget what is gone.
NTSTATUS NTAPI hook_NtUnmapViewOfSection(HANDLE process, PVOID base) {
    if (is_token(base, 2)) return canary(2);
    if (!tls_ready()) {
        return real_NtUnmapViewOfSection(process, base);
    }
    watchdog::check_from_hook();
    if (guard::shutting_down() || !base) return real_NtUnmapViewOfSection(process, base);
    const auto addr = reinterpret_cast<std::uintptr_t>(base);
    const bool tracked = exec::find(addr) || modules::find(addr);
    if (!tracked || !execguard::is_current_process(process)) return real_NtUnmapViewOfSection(process, base);
    std::uintptr_t begin = 0, end = 0;
    const bool range = execguard::allocation_range(addr, &begin, &end);
    const NTSTATUS s = real_NtUnmapViewOfSection(process, base);
    if (nt::ok(s)) {
        if (range) exec::forget(begin, end);
        gate::on_view_unmapped(base);
    }
    return s;
}

// ---------------------------------------------------------------------------------------
// 4. NtAllocateVirtualMemory — fast path: executable protection not requested.
NTSTATUS NTAPI hook_NtAllocateVirtualMemory(HANDLE process, PVOID* base, ULONG_PTR zero_bits, PSIZE_T size,
                                            ULONG type, ULONG protect) {
    if (is_token(base, 3)) return canary(3);
    if (!tls_ready()) {
        return real_NtAllocateVirtualMemory(process, base, zero_bits, size, type, protect);
    }
    watchdog::check_from_hook();
    if (!execguard::executable(protect) || guard::shutting_down() || !execguard::is_current_process(process)) {
        return real_NtAllocateVirtualMemory(process, base, zero_bits, size, type, protect);
    }
    const execguard::Requester req = execguard::find_requester();
    if (!execguard::may_create_exec(req, "NtAllocateVirtualMemory", base && *base ? reinterpret_cast<std::uintptr_t>(*base) : 0,
                                    size ? *size : 0))
        return kAccessDenied;
    exec::op_begin();
    const NTSTATUS s = real_NtAllocateVirtualMemory(process, base, zero_bits, size, type, protect);
    if (nt::ok(s) && base && *base && size) {
        execguard::record(reinterpret_cast<std::uintptr_t>(*base), *size, req, exec::Source::allocate);
    }
    exec::op_end();
    return s;
}

// ---------------------------------------------------------------------------------------
// 5. NtProtectVirtualMemory — fast path: the new protection is not executable.
NTSTATUS NTAPI hook_NtProtectVirtualMemory(HANDLE process, PVOID* base, PSIZE_T size, ULONG protect, PULONG old) {
    if (is_token(base, 4)) return canary(4);
    if (!tls_ready()) {
        return real_NtProtectVirtualMemory(process, base, size, protect, old);
    }
    watchdog::check_from_hook();
    if (!execguard::executable(protect) || guard::shutting_down() || !base || !size ||
        !execguard::is_current_process(process)) {
        return real_NtProtectVirtualMemory(process, base, size, protect, old);
    }
    const auto addr = reinterpret_cast<std::uintptr_t>(*base);
    // Image pages (relocations, import tables, other hooks) belong to the load gate.
    if (modules::find(addr) || exec::covers(addr, addr + (*size ? *size : 1))) {
        return real_NtProtectVirtualMemory(process, base, size, protect, old);
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(*base, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE) {
        return real_NtProtectVirtualMemory(process, base, size, protect, old);
    }
    const execguard::Requester req = execguard::find_requester();
    if (!execguard::may_create_exec(req, "NtProtectVirtualMemory", addr, *size)) return kAccessDenied;
    exec::op_begin();
    const NTSTATUS s = real_NtProtectVirtualMemory(process, base, size, protect, old);
    if (nt::ok(s)) execguard::record(reinterpret_cast<std::uintptr_t>(*base), *size, req, exec::Source::protect);
    exec::op_end();
    return s;
}

// ---------------------------------------------------------------------------------------
// 6. NtFreeVirtualMemory — fast path: nothing recorded at the address (lock-free lookup).
NTSTATUS NTAPI hook_NtFreeVirtualMemory(HANDLE process, PVOID* base, PSIZE_T size, ULONG type) {
    if (is_token(base, 5)) return canary(5);
    if (!tls_ready()) {
        return real_NtFreeVirtualMemory(process, base, size, type);
    }
    watchdog::check_from_hook();
    if (guard::shutting_down() || !base || !*base || !exec::find(reinterpret_cast<std::uintptr_t>(*base))) {
        return real_NtFreeVirtualMemory(process, base, size, type);
    }
    if (!execguard::is_current_process(process)) return real_NtFreeVirtualMemory(process, base, size, type);
    std::uintptr_t begin = 0, end = 0;
    const bool release = (type & MEM_RELEASE) != 0;
    const bool range = release && execguard::allocation_range(reinterpret_cast<std::uintptr_t>(*base), &begin, &end);
    const NTSTATUS s = real_NtFreeVirtualMemory(process, base, size, type);
    if (nt::ok(s)) {
        if (range) {
            exec::forget(begin, end);
        } else if (size) {
            const auto b = reinterpret_cast<std::uintptr_t>(*base);
            exec::forget(b, b + *size);
        }
    }
    return s;
}

// ---------------------------------------------------------------------------------------

struct Target {
    const char* name;
    void** real;
    void* hook;
    void* entry;  // ntdll export (the patched address)
    unsigned char expected[16];
};

Target g_targets[6] = {
    {"NtCreateSection", reinterpret_cast<void**>(&real_NtCreateSection), reinterpret_cast<void*>(&hook_NtCreateSection), nullptr, {}},
    {"NtMapViewOfSection", reinterpret_cast<void**>(&real_NtMapViewOfSection), reinterpret_cast<void*>(&hook_NtMapViewOfSection), nullptr, {}},
    {"NtUnmapViewOfSection", reinterpret_cast<void**>(&real_NtUnmapViewOfSection), reinterpret_cast<void*>(&hook_NtUnmapViewOfSection), nullptr, {}},
    {"NtAllocateVirtualMemory", reinterpret_cast<void**>(&real_NtAllocateVirtualMemory), reinterpret_cast<void*>(&hook_NtAllocateVirtualMemory), nullptr, {}},
    {"NtProtectVirtualMemory", reinterpret_cast<void**>(&real_NtProtectVirtualMemory), reinterpret_cast<void*>(&hook_NtProtectVirtualMemory), nullptr, {}},
    {"NtFreeVirtualMemory", reinterpret_cast<void**>(&real_NtFreeVirtualMemory), reinterpret_cast<void*>(&hook_NtFreeVirtualMemory), nullptr, {}},
};

// Other threads must not run inside the bytes being patched: Detours suspends them.
std::vector<HANDLE> other_threads() {
    std::vector<HANDLE> out;
    const auto& a = nt::api();
    if (!a.NtGetNextThread) return out;
    const DWORD self = GetCurrentThreadId();
    const ACCESS_MASK access =
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION;
    HANDLE prev = nullptr;
    for (int guard_count = 0; guard_count < 4096; ++guard_count) {
        HANDLE next = nullptr;
        if (!nt::ok(a.NtGetNextThread(nt::current_process(), prev, access, 0, 0, &next)) || !next) break;
        // NtGetNextThread does not close the previous handle; keep those Detours needs.
        if (prev && GetThreadId(prev) == self) CloseHandle(prev);
        if (GetThreadId(next) != self) out.push_back(next);
        prev = next;
    }
    if (prev && GetThreadId(prev) == self) CloseHandle(prev);
    return out;
}

void allow_trampoline_regions() {
    for (const Target& tg : g_targets) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (*tg.real && VirtualQuery(*tg.real, &mbi, sizeof(mbi)) && mbi.Type == MEM_PRIVATE) {
            const auto b = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
            std::uintptr_t begin = 0, end = 0;
            if (execguard::allocation_range(b, &begin, &end)) {
                exec::allow(begin, end, exec::Owner{trust::Trust::self, modules::self_base(), exec::Source::hooks});
            }
        }
    }
}

}  // namespace

bool install(std::string* failed) {
    const auto& a = nt::api();
    real_NtCreateSection = a.NtCreateSection;
    real_NtMapViewOfSection = a.NtMapViewOfSection;
    real_NtUnmapViewOfSection = a.NtUnmapViewOfSection;
    real_NtAllocateVirtualMemory = a.NtAllocateVirtualMemory;
    real_NtProtectVirtualMemory = a.NtProtectVirtualMemory;
    real_NtFreeVirtualMemory = a.NtFreeVirtualMemory;
    for (Target& tg : g_targets) {
        tg.entry = *tg.real;
        if (!tg.entry) {
            if (failed) *failed = std::string(tg.name) + " missing";
            return false;
        }
    }

    std::vector<HANDLE> threads = other_threads();
    LONG err = DetourTransactionBegin();
    if (err == NO_ERROR) err = DetourUpdateThread(GetCurrentThread());
    for (HANDLE t : threads) DetourUpdateThread(t);
    int failed_index = -1;
    for (int i = 0; i < 6 && err == NO_ERROR; ++i) {
        err = DetourAttach(g_targets[i].real, g_targets[i].hook);
        if (err != NO_ERROR) failed_index = i;
    }
    if (err == NO_ERROR) {
        err = DetourTransactionCommit();
    } else {
        DetourTransactionAbort();
    }
    for (HANDLE t : threads) CloseHandle(t);
    if (err != NO_ERROR) {
        if (failed) {
            *failed = failed_index >= 0 ? g_targets[failed_index].name : "DetourTransactionCommit";
            *failed += " error " + std::to_string(err);
        }
        return false;
    }
    for (Target& tg : g_targets) std::memcpy(tg.expected, tg.entry, sizeof(tg.expected));
    allow_trampoline_regions();
    return true;
}

unsigned canary_round() {
    InterlockedExchange(&g_canary_hits, 0);
    const auto& a = nt::api();
    SIZE_T zero = 0;
    // Each call is harmless if our hook is gone: invalid handles, zero sizes, zero protections.
    a.NtCreateSection(reinterpret_cast<PHANDLE>(const_cast<PVOID*>(&g_tokens[0])), 0, nullptr, nullptr, 0, 0, nullptr);
    a.NtMapViewOfSection(nullptr, nullptr, const_cast<PVOID*>(&g_tokens[1]), 0, 0, nullptr, &zero, 0, 0, 0);
    a.NtUnmapViewOfSection(nullptr, const_cast<PVOID>(static_cast<const volatile void*>(&g_tokens[2])));
    a.NtAllocateVirtualMemory(nullptr, const_cast<PVOID*>(&g_tokens[3]), 0, &zero, 0, 0);
    a.NtProtectVirtualMemory(nullptr, const_cast<PVOID*>(&g_tokens[4]), &zero, 0, nullptr);
    a.NtFreeVirtualMemory(nullptr, const_cast<PVOID*>(&g_tokens[5]), &zero, 0);
    return static_cast<unsigned>(InterlockedCompareExchange(&g_canary_hits, 0, 0)) & kAllHooks;
}

namespace {

// Follows one jump at a function entry: x86/x64 E9 rel32, EB rel8, FF 25 [mem];
// ARM64 B imm26 and LDR Xn, literal + BR Xn.
std::uintptr_t jump_target(const unsigned char* p) {
#if defined(_M_X64) || defined(_M_IX86)
    if (p[0] == 0xE9) return reinterpret_cast<std::uintptr_t>(p) + 5 + *reinterpret_cast<const std::int32_t*>(p + 1);
    if (p[0] == 0xEB) return reinterpret_cast<std::uintptr_t>(p) + 2 + static_cast<std::int8_t>(p[1]);
    if (p[0] == 0xFF && p[1] == 0x25) {
#if defined(_M_X64)
        const auto* slot = reinterpret_cast<const std::uintptr_t*>(p + 6 + *reinterpret_cast<const std::int32_t*>(p + 2));
#else
        const auto* slot = *reinterpret_cast<const std::uintptr_t* const*>(p + 2);
#endif
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(slot, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) return *slot;
    }
    return 0;
#elif defined(_M_ARM64)
    const std::uint32_t op = *reinterpret_cast<const std::uint32_t*>(p);
    if ((op & 0xFC000000u) == 0x14000000u) {  // B imm26
        std::int32_t imm = static_cast<std::int32_t>(op & 0x03FFFFFFu);
        if (imm & 0x02000000) imm -= 0x04000000;
        return reinterpret_cast<std::uintptr_t>(p) + static_cast<std::intptr_t>(imm) * 4;
    }
    if ((op & 0xFF000000u) == 0x58000000u) {  // LDR Xt, literal
        std::int32_t imm19 = static_cast<std::int32_t>((op >> 5) & 0x7FFFFu);
        if (imm19 & 0x40000) imm19 -= 0x80000;
        const auto* slot = reinterpret_cast<const std::uintptr_t*>(p + static_cast<std::intptr_t>(imm19) * 4);
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(slot, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) return *slot;
    }
    return 0;
#else
    (void)p;
    return 0;
#endif
}

}  // namespace

void check_entries(EntryCheck out[6]) {
    for (int i = 0; i < 6; ++i) {
        const auto* p = static_cast<const unsigned char*>(g_targets[i].entry);
        out[i].name = g_targets[i].name;
        out[i].bytes_same = p && std::memcmp(p, g_targets[i].expected, sizeof(g_targets[i].expected)) == 0;
        out[i].first_jump = p ? jump_target(p) : 0;
    }
}

std::string entry_bytes_hex(int index, bool expected) {
    if (index < 0 || index >= 6 || !g_targets[index].entry) return std::string();
    return expected ? hex(g_targets[index].expected, 16) : hex(g_targets[index].entry, 16);
}

}  // namespace mebet::hooks
