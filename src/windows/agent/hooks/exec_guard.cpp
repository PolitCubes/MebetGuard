// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "hooks/exec_guard.hpp"

#include <cstdio>
#include <vector>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/module_table.hpp"
#include "core/timing.hpp"
#include "core/win_util.hpp"
#include "json_writer.hpp"
#include "report/cards.hpp"
#include "strings.hpp"

namespace mebet::execguard {

namespace {

struct Pending {
    std::uintptr_t begin, end, requester;
};

struct PendingList {
    SRWLOCK lock = SRWLOCK_INIT;
    std::vector<Pending> items;
};

PendingList& pending() {
    static PendingList* p = new PendingList();
    return *p;
}

void close_foreign_code(const Requester& r, const char* operation, std::uintptr_t address, std::size_t size,
                        const char* when) {
    report::Event ev;
    ev.type = "close.foreign_code";
    ev.level = report::Level::error;
    char title[160];
    std::snprintf(title, sizeof(title), "Closed: executable memory requested by %s (%s)",
                  r.from_jvm_code ? "Java code through the Foreign Function API"
                  : r.address     ? "a module that is not allowed"
                                  : "code outside any module",
                  operation);
    ev.title = title;
    JsonWriter w;
    w.begin_object();
    w.field("operation", operation);
    w.field("when", when);
    w.field("address", cards::address_hex(address));
    w.field("size", static_cast<std::uint64_t>(size));
    w.key("requester").raw(cards::address_json(r.address));
    if (r.from_jvm_code) w.field("requester_kind", "jvm_generated_code");
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.foreign_code", cards::address_owner_key(r.address)};
    guard::signal(config::Module::foreign_exec_memory, config::Reason::foreign_code, std::wstring(), std::move(ev));
}

}  // namespace

bool is_current_process(HANDLE process) {
    if (process == nt::current_process()) return true;
    if (!process) return false;
    return GetProcessId(process) == GetCurrentProcessId();
}

Requester find_requester() {
    Requester r;
    void* frames[16];
    const USHORT n = RtlCaptureStackBackTrace(0, 16, frames, nullptr);
    USHORT i = 0;
    // The agent's own frames on top (this function, the slow path, the hook) …
    while (i < n && modules::in_self(reinterpret_cast<std::uintptr_t>(frames[i]))) ++i;
    // … then ntdll / kernelbase / kernel32 (ТЗ §5: skip them, look up to a few frames).
    while (i < n && modules::is_system_frame(reinterpret_cast<std::uintptr_t>(frames[i]))) ++i;
    if (i >= n) return r;  // only system frames: nothing asked, e.g. a thread started right at VirtualAlloc
    r.address = reinterpret_cast<std::uintptr_t>(frames[i]);
    if (modules::in_self(r.address)) {
        r.trust = trust::Trust::self;
        r.module_base = modules::self_base();
        r.allowed = true;
        return r;
    }
    trust::Trust t;
    std::uintptr_t base = 0;
    if (modules::find(r.address, &t, &base)) {
        r.trust = t;
        r.module_base = base;
        r.allowed = t != trust::Trust::unknown;
        return r;
    }
    exec::Owner owner{};
    if (exec::find(r.address, &owner)) {  // JIT stub or another allowed executable region
        r.trust = owner.trust;
        r.module_base = owner.module_base;
        r.from_exec_region = true;
        // The JVM asks for executable memory from jvm.dll, never from the code it generated.
        // A request whose first frame is in that code (JIT, interpreter, a downcall stub) is
        // Java code calling the OS through the Foreign Function API: a mod's way to shellcode
        // without a DLL of its own.
        //
        // Not on 32-bit x86. There the stack is walked by frame pointers, jvm.dll is built
        // without them, and the walk can skip its frames and land in the Java code that called
        // into the JVM: the code cache growing would look like such a request and close the
        // game. And there is nothing to catch: 32-bit Windows Java has no Foreign Function
        // linker at all. The periodic sweep covers executable memory there as everywhere.
#if defined(_M_IX86)
        r.from_jvm_code = false;
#else
        r.from_jvm_code = owner.trust == trust::Trust::java;
#endif
        r.allowed = owner.trust != trust::Trust::unknown && !r.from_jvm_code;
    }
    return r;
}

bool may_create_exec(const Requester& r, const char* operation, std::uintptr_t address, std::size_t size) {
    if (!config::enabled(config::Module::foreign_exec_memory)) return true;
    if (r.allowed) return true;
    if (!guard::armed()) return true;  // recorded as pending, judged after the start-up scan
    timing::Scope scope(config::Module::foreign_exec_memory);
    close_foreign_code(r, operation, address, size, "hook");
    return !config::closes(config::Module::foreign_exec_memory);
}

void record(std::uintptr_t begin, std::size_t size, const Requester& r, exec::Source source) {
    if (!size) return;
    const std::uintptr_t page = 0x1000;
    const std::uintptr_t b = begin & ~(page - 1);
    const std::uintptr_t e = (begin + size + page - 1) & ~(page - 1);
    if (!r.allowed && !guard::armed()) {
        PendingList& p = pending();
        AcquireSRWLockExclusive(&p.lock);
        p.items.push_back({b, e, r.address});
        ReleaseSRWLockExclusive(&p.lock);
    }
    exec::allow(b, e, exec::Owner{r.allowed ? r.trust : trust::Trust::unknown, r.module_base, source});
}

void judge_pending() {
    PendingList& p = pending();
    AcquireSRWLockExclusive(&p.lock);
    std::vector<Pending> items;
    items.swap(p.items);
    ReleaseSRWLockExclusive(&p.lock);
    for (const Pending& it : items) {
        Requester r;
        r.address = it.requester;
        trust::Trust t;
        std::uintptr_t base = 0;
        if (it.requester && modules::find(it.requester, &t, &base) && t != trust::Trust::unknown) {
            exec::allow(it.begin, it.end, exec::Owner{t, base, exec::Source::allocate});
            continue;
        }
        if (it.requester && modules::in_self(it.requester)) continue;
        close_foreign_code(r, "early allocation", it.begin, it.end - it.begin, "startup");
    }
}

bool allocation_range(std::uintptr_t addr, std::uintptr_t* begin, std::uintptr_t* end) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) || mbi.State == MEM_FREE) return false;
    const auto alloc = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
    std::uintptr_t pos = alloc;
    for (int guard_count = 0; guard_count < 65536; ++guard_count) {
        MEMORY_BASIC_INFORMATION m{};
        if (!VirtualQuery(reinterpret_cast<void*>(pos), &m, sizeof(m)) ||
            reinterpret_cast<std::uintptr_t>(m.AllocationBase) != alloc || m.State == MEM_FREE)
            break;
        pos = reinterpret_cast<std::uintptr_t>(m.BaseAddress) + m.RegionSize;
    }
    if (pos <= alloc) return false;
    *begin = alloc;
    *end = pos;
    return true;
}

}  // namespace mebet::execguard
