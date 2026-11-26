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
    std::uint64_t serial = 0;  // unique per add: tells this record from a later one at the same base
};

void init();  // remembers ntdll / kernelbase / kernel32 / self / exe ranges

void add(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path);
void remove(std::uintptr_t base);
// For the sweep, which judges a file while other threads load and unload: adds only when the base
// has no record yet (the hook that mapped a library there has the last word) and returns the
// serial of the new record, 0 when nothing was added; remove_if removes only that very record.
std::uint64_t add_if_absent(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path);
void remove_if(std::uintptr_t base, std::uint64_t serial);
// A view whose file is being judged right now (the load gate's slow path): the sweep leaves it alone
// for a while — not for good: a judging thread that never finishes (suspended, killed, a file that
// never opens) must not leave an image unjudged. Cleared by add() and remove().
void add_pending(std::uintptr_t base);
bool pending_within(std::uintptr_t base, std::uint64_t max_ms);
// The loader's unload notification: removes the module and remembers that it went, and whether it
// was trusted — its image stays mapped for a moment after the notification.
void remove_unloading(std::uintptr_t base);
// A trusted module was unloaded from `base` within the last `max_age_ms` — with `path`, one whose record
// named that very file.
bool unloaded_recently(std::uintptr_t base, std::uint64_t max_age_ms, const std::wstring* path = nullptr);

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
