// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Module trust decision (ТЗ §6): the one place that says whether a file may run in the
// game process. Order: denylist → collected list (hashes) → signatures (Microsoft rule,
// trusted publishers, WHQL in the display driver folder). One decision per file, cached
// in memory by FileId + size + mtime (ТЗ §5); nothing is written to disk.
#pragma once

#include <string>
#include <vector>

#include "nt.hpp"
#include "trust/file_identity.hpp"
#include "trust/signatures.hpp"
#include "trust/verdict.hpp"

namespace mebet::trust {

struct FileFacts {
    std::wstring path;
    FileIdentity identity{};
    bool identity_known = false;
    bool hashed = false;
    Sha256Digest sha256{};
    Signatures sigs;
};

struct Decision {
    Verdict verdict;
    FileFacts facts;
    double ms = 0;  // time spent deciding (cache miss only)
};

// Called once at agent start, before the hooks (paths of our own files, display drivers).
void init_engine(const std::wstring& java_home);

// Decision for a file opened by someone else (the loader's handle). The file content is
// always read through this handle, so the decision is about the file that will be mapped.
Decision decide(HANDLE file, const std::wstring& path_hint);
// Decision for a file by path (mapped images found later, proxy-DLL check).
Decision decide_path(const std::wstring& path);

// SHA-256 of a whole file through a handle (reports, hash list).
bool sha256_of(HANDLE file, Sha256Digest& out, std::uint64_t max_bytes);

// JAVA_HOME from the launcher, resolved like final_path(); the only place where files of
// the Java vendor from config/java.json are trusted as the game Java.
bool is_java_dir_file(const std::wstring& path);
const std::wstring& java_home();

}  // namespace mebet::trust
