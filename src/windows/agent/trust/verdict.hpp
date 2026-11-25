// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Result of the module trust decision (ТЗ §6 «Собранный список разрешённого»).
#pragma once

#include <string>

#include "config.hpp"

namespace mebet::trust {

// Why a module is allowed. Every allowed module has exactly one of these.
enum class Trust : unsigned char {
    unknown,    // not allowed
    os,         // Microsoft: Windows components, Microsoft runtimes (rule, not a list entry)
    known_dll,  // mapped from \KnownDlls — created by the system at boot
    java,       // the game Java: publisher from config/java.json, file inside JAVA_HOME
    publisher,  // trusted publisher from config/publishers.json
    whql,       // WHQL-only file inside the active display driver folder
    hash,       // game / mod native library, by SHA-256
    self,       // the agent itself
    exe,        // the wrapper executable (the process image)
};

const char* trust_name(Trust t);

struct Verdict {
    bool allowed = false;
    Trust trust = Trust::unknown;
    int publisher = -1;  // index into config::kPublishers when trust == publisher/java
    config::Reason reason = config::Reason::untrusted_module;  // when !allowed
    std::string rule;     // short name of the deciding rule, for the report card
    std::string matched;  // matched list entry, or empty
    bool new_certificate = false;  // known publisher, certificate serial not seen before
};

}  // namespace mebet::trust
