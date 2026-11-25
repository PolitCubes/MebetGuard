// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Mebet wrapper for Linux and macOS (ТЗ §11): own executable that starts the JVM through
// libjli with the guard's -agentpath. Same split as on Windows: this file clears the
// Java environment, verifies the agent by the SHA-256 embedded at build time, loads it by
// full path and hands over.
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#include "agent_hash.hpp"
#include "boot_info.hpp"
#include "config.hpp"
#include "env_list.hpp"
#include "sha256.hpp"

namespace {

std::string self_path() {
#if defined(__APPLE__)
    char buf[PATH_MAX * 2];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0) return std::string();
    char real[PATH_MAX];
    return realpath(buf, real) ? std::string(real) : std::string(buf);
#else
    char buf[PATH_MAX];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::string();
    buf[n] = 0;
    return buf;
#endif
}

[[noreturn]] void fail(mebet::config::Reason r, const std::string& detail) {
    const auto& d = mebet::config::reason(r);
    std::fprintf(stderr, "[Mebet] closed: %s (code %d) %s\n", d.id, d.exit_code, detail.c_str());
    std::fflush(stderr);
    _exit(d.exit_code);
}

bool read_fd(int fd, std::string& out) {
    char buf[1 << 16];
    for (;;) {
        const ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) return false;
        if (n == 0) return true;
        out.append(buf, static_cast<size_t>(n));
    }
}

// Static storage for the cleared variables handed to the agent.
char g_names[mebet::kMaxClearedEnv][40];
char g_values[mebet::kMaxClearedEnv][2048];

void clear_java_env(mebet::BootInfo& boot) {
    for (const char* name : mebet::kJavaEnvVars) {
        const char* v = getenv(name);
        if (!v) continue;
        if (boot.cleared_count < mebet::kMaxClearedEnv) {
            const unsigned k = boot.cleared_count++;
            std::snprintf(g_names[k], sizeof(g_names[k]), "%s", name);
            std::snprintf(g_values[k], 513, "%s", v);  // ТЗ §12: value ≤ 512 characters
            boot.cleared_names[k] = g_names[k];
            boot.cleared_values[k] = g_values[k];
        }
        unsetenv(name);
    }
    boot.hardening |= mebet::kBootEnvCleared;
}

}  // namespace

// Exported with default visibility: on macOS libjli calls main() again on a new thread
// (dlsym(RTLD_DEFAULT, "main")) to run the JVM off the AppKit main thread.
__attribute__((visibility("default"))) int main(int argc, char** argv) {
    static mebet::BootInfo boot{};
    boot.size = sizeof(boot);
    boot.version = mebet::kBootInfoVersion;
    boot.argc = argc;
    boot.argv = argv;
    clear_java_env(boot);

    static std::string exe = self_path();
    boot.exe_path = exe.c_str();
    const std::string dir = exe.substr(0, exe.find_last_of('/'));
    const std::string agent = dir + "/" + mebet::generated::kAgentFileName;

    // The verified bytes and the loaded library are the same file: on Linux the library is
    // loaded through the descriptor that was hashed.
    const int fd = open(agent.c_str(), O_RDONLY | O_CLOEXEC);
    std::string bytes;
    if (fd < 0 || !read_fd(fd, bytes)) fail(mebet::config::Reason::agent_integrity, agent);
    const mebet::Sha256Digest d = mebet::Sha256::of(bytes.data(), bytes.size());
    if (std::memcmp(d.bytes, mebet::generated::kAgentHash, 32) != 0) fail(mebet::config::Reason::agent_integrity, agent);
#if defined(__linux__)
    const std::string load_path = "/proc/self/fd/" + std::to_string(fd);
#else
    const std::string load_path = agent;
#endif
    void* lib = dlopen(load_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    close(fd);
    if (!lib) fail(mebet::config::Reason::agent_integrity, dlerror());
    auto entry = reinterpret_cast<mebet::MebetGuardMainFn>(dlsym(lib, mebet::kAgentEntryName));
    if (!entry) fail(mebet::config::Reason::agent_integrity, agent);
    return entry(&boot);
}
