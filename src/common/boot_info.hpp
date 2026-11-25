// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Contract between the wrapper executable and the agent library.
//
// The wrapper does only what must happen before any other DLL is loaded (ТЗ §4 step 1:
// DLL search order, extension points, environment), verifies the agent by its hash and
// calls MebetGuardMain. Everything else — hooks, checks, splash, the JVM start — lives in
// the agent, so that every protection block sits in one module with one report channel.
#pragma once

#include <cstdint>

#if defined(_WIN32)
#define MEBET_CALL __cdecl
#define MEBET_EXPORT extern "C" __declspec(dllexport)
#else
#define MEBET_CALL
#define MEBET_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace mebet {

inline constexpr std::uint32_t kBootInfoVersion = 1;
inline constexpr unsigned kMaxClearedEnv = 32;

// What step 1 of the wrapper achieved (bit flags).
enum BootHardening : std::uint32_t {
    kBootDllDirsDefault = 1u << 0,     // SetDefaultDllDirectories(SYSTEM32 | USER_DIRS)
    kBootDllDirsNoCwd = 1u << 1,       // SetDllDirectoryW(L"")
    kBootExtPointsDisabled = 1u << 2,  // ProcessExtensionPointDisablePolicy
    kBootEnvCleared = 1u << 3,         // ТЗ §4 environment list cleared
    kBootVulkanFiltered = 1u << 4,     // VK_LOADER_LAYERS_DISABLE / _ALLOW set
};

struct BootInfo {
    std::uint32_t size;
    std::uint32_t version;
    void* exe_module;  // HMODULE of the wrapper (resources: icon, splash bitmaps); nullptr on POSIX
    std::uint32_t hardening;
    std::uint32_t cleared_count;
    const char* cleared_names[kMaxClearedEnv];   // environment variables that were set and got cleared
    const char* cleared_values[kMaxClearedEnv];  // UTF-8, already cut to 512 characters
    std::uint64_t start_ms;                      // monotonic start time of the wrapper
    int argc;            // POSIX: argv of main(); Windows: 0 (the agent reads GetCommandLine via JLI)
    char** argv;
    const char* exe_path;  // UTF-8 path of the wrapper
};

using MebetGuardMainFn = int(MEBET_CALL*)(const BootInfo* boot);

inline constexpr const char* kAgentEntryName = "MebetGuardMain";

}  // namespace mebet
