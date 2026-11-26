// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Table of allowed executable memory outside images (ТЗ §5 «Чужой код в памяти»).
// Filled by the hooks when an allowed module asks for executable memory (the JVM code
// cache, JNA/libffi closures, overlay trampolines…) and by the start-up scan; the region
// sweep closes the client on executable private/mapped memory that is not in here.
#pragma once

#include <cstdint>

#include "trust/verdict.hpp"

namespace mebet::exec {

enum class Source : unsigned char {
    allocate,     // NtAllocateVirtualMemory with an executable protection
    protect,      // NtProtectVirtualMemory to an executable protection
    map,          // NtMapViewOfSection of a non-image section, executable
    preexisting,  // found by the start-up scan and proven to lead into an allowed module
    hooks,        // trampolines of the agent's own hooks
};

struct Owner {
    trust::Trust trust;
    std::uintptr_t module_base;  // module that asked (0 for preexisting with several targets)
    Source source;
    bool operator==(const Owner& o) const {
        return trust == o.trust && module_base == o.module_base && source == o.source;
    }
};

void allow(std::uintptr_t begin, std::uintptr_t end, const Owner& owner);
void forget(std::uintptr_t begin, std::uintptr_t end);
bool find(std::uintptr_t addr, Owner* out = nullptr);
bool covers(std::uintptr_t begin, std::uintptr_t end);
bool overlaps(std::uintptr_t begin, std::uintptr_t end);

}  // namespace mebet::exec
