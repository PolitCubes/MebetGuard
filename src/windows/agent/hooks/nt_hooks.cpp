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
nt::NtCreateSectionExFn real_NtCreateSectionEx = nullptr;
nt::NtMapViewOfSectionExFn real_NtMapViewOfSectionEx = nullptr;
nt::NtUnmapViewOfSectionExFn real_NtUnmapViewOfSectionEx = nullptr;
nt::NtAllocateVirtualMemoryExFn real_NtAllocateVirtualMemoryEx = nullptr;

// Canary tokens: an argument pointer only the self-check passes (ТЗ §7 «канарейка»).
// With our hook in place the call never reaches the kernel; without it the kernel sees
// arguments that fail validation and does nothing.
volatile PVOID g_tokens[kHookCount];
unsigned g_installed = 0;  // installed_mask()
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
// hook_NtFreeVirtualMemory → guard::shutting_down() → core() while a thread exits. The hooks
// that judge (section, map, allocate, protect) cannot judge on such a thread: what needs no
// judging passes straight through, and what would — executable memory, an image — is refused.
// A thread really without TLS (being set up or torn down) asks for neither; game code that cleared
// its own TLS pointer around a call to get past the judge gets a refusal instead of a pass.
// The two that only forget (unmap, free) still forget: skipped, a region
// freed by a thread on its way out stayed in the tables as allowed, and whatever was allocated
// at that address later was taken for it. Everything they touch works without TLS (the tables
// and the shutdown flag are plain globals).

// What a view just mapped at `base` is, as the view itself tells: an image that can run code (SEC_IMAGE:
// its allocation protection is PAGE_EXECUTE_WRITECOPY), or something else — data, or an image mapped
// with SEC_IMAGE_NO_EXECUTE (LoadLibraryEx AS_IMAGE_RESOURCE: icons, version info), PAGE_READONLY.
// NtQuerySection cannot tell the last: such a section reads back as a plain image, and every icon
// read from an unsigned file was judged as code and closed the game. TLS-free.
enum class View { unknown, code_image, other };
View view_kind(void* base) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(base, &mbi, sizeof(mbi)) || mbi.AllocationBase != base) return View::unknown;
    return mbi.Type == MEM_IMAGE && execguard::executable(mbi.AllocationProtect) ? View::code_image : View::other;
}

inline bool tls_ready() {
    // TEB: NT_TIB (7 pointers), EnvironmentPointer, ClientId (2), ActiveRpcHandle, then
    // ThreadLocalStoragePointer — pointer slot 11 on x86, x64 and ARM64 alike.
    const auto* teb = reinterpret_cast<void* const*>(NtCurrentTeb());
    const auto* slots = static_cast<void* const*>(teb[11]);
    return slots && slots[_tls_index];
}

// The logic of each hook lives in a template that takes the real call as a lambda: the hook of
// the ТЗ and its Ex variant run the very same judge, only the call behind it differs.

// ---------------------------------------------------------------------------------------
// 1. NtCreateSection / 7. NtCreateSectionEx — the load gate.
bool image_attributes(ULONG allocation) {
    return (allocation & nt::kSecImage) != 0 && (allocation & nt::kSecImageNoExecute) != nt::kSecImageNoExecute;
}

template <typename Real>
NTSTATUS create_section(PHANDLE section, ULONG allocation, HANDLE file, Real real) {
    if (!tls_ready()) {
        if (image_attributes(allocation) && file) return kAccessDenied;  // cannot be judged here (see tls_ready)
        return real();
    }
    watchdog::check_from_hook();
    if (!image_attributes(allocation) || !file || guard::shutting_down() || gate::own_read_on_this_thread()) {
        return real();  // fast path
    }
    if (!gate::on_image_section(file)) return kAccessDenied;
    const NTSTATUS s = real();
    if (nt::ok(s) && section) gate::on_section_created(*section);
    return s;
}

NTSTATUS NTAPI hook_NtCreateSection(PHANDLE section, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
                                    PLARGE_INTEGER max_size, ULONG page_protection, ULONG allocation, HANDLE file) {
    if (is_token(section, 0)) return canary(0);
    return create_section(section, allocation, file, [&] {
        return real_NtCreateSection(section, access, attributes, max_size, page_protection, allocation, file);
    });
}

NTSTATUS NTAPI hook_NtCreateSectionEx(PHANDLE section, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
                                      PLARGE_INTEGER max_size, ULONG page_protection, ULONG allocation, HANDLE file,
                                      PVOID extended, ULONG extended_count) {
    if (is_token(section, 6)) return canary(6);
    return create_section(section, allocation, file, [&] {
        return real_NtCreateSectionEx(section, access, attributes, max_size, page_protection, allocation, file,
                                      extended, extended_count);
    });
}

// ---------------------------------------------------------------------------------------
// 2. NtMapViewOfSection / 8. NtMapViewOfSectionEx — safety net for images, accounting for
//    executable data views.
bool section_is_image(HANDLE section) {
    nt::SectionBasicInformation info{};
    SIZE_T ret = 0;
    const auto& a = nt::api();
    if (!a.NtQuerySection || !nt::ok(a.NtQuerySection(section, nt::kSectionBasicInformation, &info, sizeof(info), &ret)))
        return false;
    return image_attributes(info.AllocationAttributes);
}

template <typename Real>
NTSTATUS map_view(const char* operation, HANDLE section, HANDLE process, PVOID* base, PSIZE_T view_size, ULONG protect,
                  Real real) {
    if (!tls_ready()) {
        if (!execguard::is_current_process(process)) return real();
        if (execguard::executable(protect)) return kAccessDenied;  // cannot be judged here (see tls_ready)
        // Whether it is an image that can run code, only the view tells (view_kind): such a view is
        // taken back, as it cannot be judged here either.
        const NTSTATUS s = real();
        if (nt::ok(s) && base && *base && view_kind(*base) != View::other) {
            real_NtUnmapViewOfSection(process, *base);
            *base = nullptr;
            return kAccessDenied;
        }
        return s;
    }
    watchdog::check_from_hook();
    if (guard::shutting_down() || !execguard::is_current_process(process)) return real();
    bool image = section_is_image(section);
    execguard::Requester req;
    if (!image && execguard::executable(protect)) {
        req = execguard::find_requester();
        if (!execguard::may_create_exec(req, operation, 0, view_size ? *view_size : 0)) return kAccessDenied;
    }
    const int op = exec::op_begin();
    const NTSTATUS s = real();
    bool no_code_image = false;
    if (nt::ok(s) && base && *base && view_size) {
        // The view itself tells what was mapped, whatever the handle allows: a section that could not
        // be asked (no SECTION_QUERY) was taken for data and its image mapped unjudged; and an image
        // mapped for its resources only can run no code, and is no module to judge (view_kind).
        const View k = view_kind(*base);
        if (k != View::unknown) {
            no_code_image = image && k == View::other;
            image = k == View::code_image;
        }
    }
    if (nt::ok(s) && base && *base && view_size && !no_code_image) {
        if (image) {
            if (!gate::on_image_view(section, *base, *view_size)) {
                real_NtUnmapViewOfSection(process, *base);
                *base = nullptr;
                exec::op_end(op);
                return kAccessDenied;
            }
        } else if (execguard::executable(protect)) {
            execguard::record(reinterpret_cast<std::uintptr_t>(*base), *view_size, req, exec::Source::map);
        }
    }
    exec::op_end(op);
    return s;
}

NTSTATUS NTAPI hook_NtMapViewOfSection(HANDLE section, HANDLE process, PVOID* base, ULONG_PTR zero_bits,
                                       SIZE_T commit, PLARGE_INTEGER offset, PSIZE_T view_size, ULONG inherit,
                                       ULONG allocation, ULONG protect) {
    if (is_token(base, 1)) return canary(1);
    return map_view("NtMapViewOfSection", section, process, base, view_size, protect, [&] {
        return real_NtMapViewOfSection(section, process, base, zero_bits, commit, offset, view_size, inherit,
                                       allocation, protect);
    });
}

NTSTATUS NTAPI hook_NtMapViewOfSectionEx(HANDLE section, HANDLE process, PVOID* base, PLARGE_INTEGER offset,
                                         PSIZE_T view_size, ULONG allocation, ULONG protect, PVOID extended,
                                         ULONG extended_count) {
    if (is_token(base, 7)) return canary(7);
    return map_view("NtMapViewOfSectionEx", section, process, base, view_size, protect, [&] {
        return real_NtMapViewOfSectionEx(section, process, base, offset, view_size, allocation, protect, extended,
                                         extended_count);
    });
}

// ---------------------------------------------------------------------------------------
// 3. NtUnmapViewOfSection / 9. NtUnmapViewOfSectionEx — forget what is gone.
template <typename Real>
NTSTATUS unmap_view(HANDLE process, PVOID base, Real real) {
    if (tls_ready()) watchdog::check_from_hook();
    if (guard::shutting_down() || !base) return real();
    const auto addr = reinterpret_cast<std::uintptr_t>(base);
    // The kernel takes any address inside the view, so the module is found by range and
    // forgotten by its own base: forgotten by the address the caller passed, a view unmapped
    // through an address in its middle stayed in the table with its trust.
    std::uintptr_t module_base = 0;
    const bool is_module = modules::find(addr, nullptr, &module_base);
    if ((!is_module && !exec::find(addr)) || !execguard::is_current_process(process)) return real();
    std::uintptr_t begin = 0, end = 0;
    const bool range = execguard::allocation_range(addr, &begin, &end);
    const NTSTATUS s = real();
    if (nt::ok(s)) {
        if (range) exec::forget(begin, end);
        if (is_module) gate::on_view_unmapped(reinterpret_cast<void*>(module_base));
    }
    return s;
}

NTSTATUS NTAPI hook_NtUnmapViewOfSection(HANDLE process, PVOID base) {
    if (is_token(base, 2)) return canary(2);
    return unmap_view(process, base, [&] { return real_NtUnmapViewOfSection(process, base); });
}

NTSTATUS NTAPI hook_NtUnmapViewOfSectionEx(HANDLE process, PVOID base, ULONG flags) {
    if (is_token(base, 8)) return canary(8);
    return unmap_view(process, base, [&] { return real_NtUnmapViewOfSectionEx(process, base, flags); });
}

// ---------------------------------------------------------------------------------------
// 4. NtAllocateVirtualMemory / 10. NtAllocateVirtualMemoryEx — fast path: executable protection
//    not requested.
template <typename Real>
NTSTATUS allocate(const char* operation, HANDLE process, PVOID* base, PSIZE_T size, ULONG protect, Real real) {
    if (!tls_ready()) {
        if (execguard::executable(protect) && execguard::is_current_process(process)) return kAccessDenied;
        return real();
    }
    watchdog::check_from_hook();
    if (!execguard::executable(protect) || guard::shutting_down() || !execguard::is_current_process(process)) {
        return real();
    }
    const execguard::Requester req = execguard::find_requester();
    if (!execguard::may_create_exec(req, operation, base && *base ? reinterpret_cast<std::uintptr_t>(*base) : 0,
                                    size ? *size : 0))
        return kAccessDenied;
    const int op = exec::op_begin();
    const NTSTATUS s = real();
    if (nt::ok(s) && base && *base && size) {
        execguard::record(reinterpret_cast<std::uintptr_t>(*base), *size, req, exec::Source::allocate);
    }
    exec::op_end(op);
    return s;
}

NTSTATUS NTAPI hook_NtAllocateVirtualMemory(HANDLE process, PVOID* base, ULONG_PTR zero_bits, PSIZE_T size,
                                            ULONG type, ULONG protect) {
    if (is_token(base, 3)) return canary(3);
    return allocate("NtAllocateVirtualMemory", process, base, size, protect, [&] {
        return real_NtAllocateVirtualMemory(process, base, zero_bits, size, type, protect);
    });
}

NTSTATUS NTAPI hook_NtAllocateVirtualMemoryEx(HANDLE process, PVOID* base, PSIZE_T size, ULONG type, ULONG protect,
                                              PVOID extended, ULONG extended_count) {
    if (is_token(base, 9)) return canary(9);
    return allocate("NtAllocateVirtualMemoryEx", process, base, size, protect, [&] {
        return real_NtAllocateVirtualMemoryEx(process, base, size, type, protect, extended, extended_count);
    });
}

// ---------------------------------------------------------------------------------------
// 5. NtProtectVirtualMemory — fast path: the new protection is not executable.
NTSTATUS NTAPI hook_NtProtectVirtualMemory(HANDLE process, PVOID* base, PSIZE_T size, ULONG protect, PULONG old) {
    if (is_token(base, 4)) return canary(4);
    if (!tls_ready()) {
        if (execguard::executable(protect) && execguard::is_current_process(process)) return kAccessDenied;
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
    const int op = exec::op_begin();
    const NTSTATUS s = real_NtProtectVirtualMemory(process, base, size, protect, old);
    if (nt::ok(s)) execguard::record(reinterpret_cast<std::uintptr_t>(*base), *size, req, exec::Source::protect);
    exec::op_end(op);
    return s;
}

// ---------------------------------------------------------------------------------------
// 6. NtFreeVirtualMemory — fast path: nothing recorded at the address (lock-free lookup).
NTSTATUS NTAPI hook_NtFreeVirtualMemory(HANDLE process, PVOID* base, PSIZE_T size, ULONG type) {
    if (is_token(base, 5)) return canary(5);
    if (tls_ready()) watchdog::check_from_hook();
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

Target g_targets[kHookCount] = {
    {"NtCreateSection", reinterpret_cast<void**>(&real_NtCreateSection), reinterpret_cast<void*>(&hook_NtCreateSection), nullptr, {}},
    {"NtMapViewOfSection", reinterpret_cast<void**>(&real_NtMapViewOfSection), reinterpret_cast<void*>(&hook_NtMapViewOfSection), nullptr, {}},
    {"NtUnmapViewOfSection", reinterpret_cast<void**>(&real_NtUnmapViewOfSection), reinterpret_cast<void*>(&hook_NtUnmapViewOfSection), nullptr, {}},
    {"NtAllocateVirtualMemory", reinterpret_cast<void**>(&real_NtAllocateVirtualMemory), reinterpret_cast<void*>(&hook_NtAllocateVirtualMemory), nullptr, {}},
    {"NtProtectVirtualMemory", reinterpret_cast<void**>(&real_NtProtectVirtualMemory), reinterpret_cast<void*>(&hook_NtProtectVirtualMemory), nullptr, {}},
    {"NtFreeVirtualMemory", reinterpret_cast<void**>(&real_NtFreeVirtualMemory), reinterpret_cast<void*>(&hook_NtFreeVirtualMemory), nullptr, {}},
    // The Ex variants: hooked where ntdll has them.
    {"NtCreateSectionEx", reinterpret_cast<void**>(&real_NtCreateSectionEx), reinterpret_cast<void*>(&hook_NtCreateSectionEx), nullptr, {}},
    {"NtMapViewOfSectionEx", reinterpret_cast<void**>(&real_NtMapViewOfSectionEx), reinterpret_cast<void*>(&hook_NtMapViewOfSectionEx), nullptr, {}},
    {"NtUnmapViewOfSectionEx", reinterpret_cast<void**>(&real_NtUnmapViewOfSectionEx), reinterpret_cast<void*>(&hook_NtUnmapViewOfSectionEx), nullptr, {}},
    {"NtAllocateVirtualMemoryEx", reinterpret_cast<void**>(&real_NtAllocateVirtualMemoryEx), reinterpret_cast<void*>(&hook_NtAllocateVirtualMemoryEx), nullptr, {}},
};
constexpr int kRequiredHooks = 6;  // the six of the ТЗ; the Ex variants only where ntdll has them

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
    real_NtCreateSectionEx = a.NtCreateSectionEx;
    real_NtMapViewOfSectionEx = a.NtMapViewOfSectionEx;
    real_NtUnmapViewOfSectionEx = a.NtUnmapViewOfSectionEx;
    real_NtAllocateVirtualMemoryEx = a.NtAllocateVirtualMemoryEx;
    for (int i = 0; i < kHookCount; ++i) {
        Target& tg = g_targets[i];
        tg.entry = *tg.real;
        if (!tg.entry && i < kRequiredHooks) {
            if (failed) *failed = std::string(tg.name) + " missing";
            return false;
        }
    }

    std::vector<HANDLE> threads = other_threads();
    LONG err = DetourTransactionBegin();
    if (err == NO_ERROR) err = DetourUpdateThread(GetCurrentThread());
    for (HANDLE t : threads) DetourUpdateThread(t);
    int failed_index = -1;
    for (int i = 0; i < kHookCount && err == NO_ERROR; ++i) {
        if (!g_targets[i].entry) continue;  // an Ex variant this Windows does not have
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
    g_installed = 0;
    for (int i = 0; i < kHookCount; ++i) {
        if (!g_targets[i].entry) continue;
        std::memcpy(g_targets[i].expected, g_targets[i].entry, sizeof(g_targets[i].expected));
        g_installed |= 1u << i;
    }
    allow_trampoline_regions();
    return true;
}

unsigned installed_mask() { return g_installed; }

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
    if (g_installed & (1u << 6))
        a.NtCreateSectionEx(reinterpret_cast<PHANDLE>(const_cast<PVOID*>(&g_tokens[6])), 0, nullptr, nullptr, 0, 0, nullptr,
                            nullptr, 0);
    if (g_installed & (1u << 7))
        a.NtMapViewOfSectionEx(nullptr, nullptr, const_cast<PVOID*>(&g_tokens[7]), nullptr, &zero, 0, 0, nullptr, 0);
    if (g_installed & (1u << 8))
        a.NtUnmapViewOfSectionEx(nullptr, const_cast<PVOID>(static_cast<const volatile void*>(&g_tokens[8])), 0);
    if (g_installed & (1u << 9))
        a.NtAllocateVirtualMemoryEx(nullptr, const_cast<PVOID*>(&g_tokens[9]), &zero, 0, 0, nullptr, 0);
    return static_cast<unsigned>(InterlockedCompareExchange(&g_canary_hits, 0, 0)) & g_installed;
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

void check_entries(EntryCheck out[kHookCount]) {
    for (int i = 0; i < kHookCount; ++i) {
        const auto* p = static_cast<const unsigned char*>(g_targets[i].entry);
        out[i].name = g_targets[i].name;
        out[i].present = (g_installed & (1u << i)) != 0;
        out[i].bytes_same = p && std::memcmp(p, g_targets[i].expected, sizeof(g_targets[i].expected)) == 0;
        out[i].first_jump = p ? jump_target(p) : 0;
    }
}

std::string entry_bytes_hex(int index, bool expected) {
    if (index < 0 || index >= kHookCount || !g_targets[index].entry) return std::string();
    return expected ? hex(g_targets[index].expected, 16) : hex(g_targets[index].entry, 16);
}

}  // namespace mebet::hooks
