// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Address ranges of every image the guard has accepted (loader modules, KnownDLLs, the
// agent, the wrapper). Used by the hooks to find "who asked" and by the sweeps to tell a
// registered image from a hidden one (ТЗ §5).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "trust/file_identity.hpp"
#include "trust/verdict.hpp"

namespace mebet::modules {

struct Record {
    std::uintptr_t base;
    std::size_t size;
    trust::Trust trust;
    std::wstring path;  // DOS path from the kernel, may be empty for early modules
    std::uint64_t serial = 0;  // unique per add: tells this record from a later one at the same base
    trust::FileIdentity id{};  // of the file the trust engine judged, when id_known
    bool id_known = false;
    std::wstring kernel_name;  // the mapping's name as the kernel gives it (same form the sweep reads):
                               // a different file mapped at this base has a different name, even when
                               // its own file cannot be read to compare ids.
};

void init();  // remembers ntdll / kernelbase / kernel32 / self / exe ranges

// `id`: the file the trust engine judged for this image (a Decision's facts.identity), when known.
void add(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path,
         const trust::FileIdentity* id = nullptr);
void remove(std::uintptr_t base);
// For the sweep, which judges a file while other threads load and unload: adds only when the base
// has no record yet (the hook that mapped a library there has the last word) and returns the
// serial of the new record, 0 when nothing was added; remove_if removes only that very record.
std::uint64_t add_if_absent(std::uintptr_t base, std::size_t size, trust::Trust t, const std::wstring& path,
                            const trust::FileIdentity* id = nullptr);
// The record of the module at `base`, if any.
bool record_at(std::uintptr_t base, Record* out);
void remove_if(std::uintptr_t base, std::uint64_t serial);
// The sweep has proven which file the record `serial` at `base` (made without an id) is about.
void prove_identity(std::uintptr_t base, std::uint64_t serial, const trust::FileIdentity& id);
// A view whose file is being judged right now (the load gate's slow path): the sweep leaves it alone
// for a while — not for good: a judging thread that never finishes (suspended, killed, a file that
// never opens) must not leave an image unjudged. Cleared by add() and remove().
void add_pending(std::uintptr_t base);
bool pending_within(std::uintptr_t base, std::uint64_t max_ms);
// The loader's unload notification: removes the module and remembers that it went, and whether it
// was trusted — its image stays mapped for a moment after the notification.
void remove_unloading(std::uintptr_t base);
// A trusted module was unloaded from `base` within the last `max_age_ms`.
bool unloaded_recently(std::uintptr_t base, std::uint64_t max_age_ms);
// ... and the file at `path` now is the very file its record had judged — by file id, whatever form
// the name takes (8.3, a mapped drive, a volume without a letter); a record without an id by the id of
// the file under its own name.
bool unloaded_recently_file(std::uintptr_t base, std::uint64_t max_age_ms, const std::wstring& path);

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
