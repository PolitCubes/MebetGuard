// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Address ranges of every image the guard has accepted (loader modules, KnownDLLs, the
// agent, the wrapper). Used by the hooks to find "who asked" and by the sweeps to tell a
// registered image from a hidden one (ТЗ §5).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "trust/verdict.hpp"

namespace mebet::modules {

struct Record {
    std::uintptr_t base;
    std::size_t size;
    trust::Trust trust;
    std::wstring path;  // DOS path from the kernel, may be empty for early modules
};

void init();  // remembers ntdll / kernelbase / kernel32 / self / exe ranges

void add(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path);
void remove(std::uintptr_t base);

// Lock-free lookups.
bool find(std::uintptr_t addr, trust::Trust* t = nullptr, std::uintptr_t* base = nullptr);
// Frames to skip when looking for the module that asked for memory (ТЗ §5: skip
// ntdll / kernelbase / kernel32).
bool is_system_frame(std::uintptr_t addr);
bool in_self(std::uintptr_t addr);
std::uintptr_t self_base();

std::wstring path_of(std::uintptr_t base);
std::vector<Record> all();

}  // namespace mebet::modules
