// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Executable memory accounting (ТЗ §5 «Чужой код в памяти»). Executable memory is rare,
// so a request for it takes the slow path: up to a few stack frames above the system DLLs
// tell which module asked. An allowed module gets the region recorded; anything else is
// denied and the client is closed.
#pragma once

#include <cstdint>

#include "core/exec_table.hpp"
#include "nt.hpp"

namespace mebet::execguard {

struct Requester {
    std::uintptr_t address = 0;  // first return address above ntdll/kernelbase/kernel32
    trust::Trust trust = trust::Trust::unknown;
    std::uintptr_t module_base = 0;
    bool allowed = false;
    bool from_exec_region = false;  // JIT stub or other recorded executable memory
};

Requester find_requester();

inline bool executable(ULONG protect) { return (protect & 0xF0) != 0; }  // PAGE_EXECUTE*
bool is_current_process(HANDLE process);

// Called before the real call. false = deny (the close was requested).
bool may_create_exec(const Requester& r, const char* operation, std::uintptr_t address, std::size_t size);
// Called after a successful real call.
void record(std::uintptr_t begin, std::size_t size, const Requester& r, exec::Source source);

// Regions recorded before the guard was armed: judged once the modules are known.
void judge_pending();

// Region bounds of an allocation (for MEM_RELEASE accounting).
bool allocation_range(std::uintptr_t addr, std::uintptr_t* begin, std::uintptr_t* end);

}  // namespace mebet::execguard
