// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Identity of a file as the kernel sees it (ТЗ §5: cache key FileId + size + mtime).
#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#include "nt.hpp"

namespace mebet::trust {

struct FileIdentity {
    std::uint64_t volume = 0;
    unsigned char file_id[16] = {};
    std::uint64_t size = 0;
    std::uint64_t mtime = 0;

    bool operator==(const FileIdentity& o) const {
        return volume == o.volume && size == o.size && mtime == o.mtime && std::memcmp(file_id, o.file_id, 16) == 0;
    }
    bool operator<(const FileIdentity& o) const {
        if (volume != o.volume) return volume < o.volume;
        const int c = std::memcmp(file_id, o.file_id, 16);
        if (c != 0) return c < 0;
        if (size != o.size) return size < o.size;
        return mtime < o.mtime;
    }
};

// FileIdInfo (128-bit id, Windows 8+) or the 64-bit index of GetFileInformationByHandle.
bool identity_of(HANDLE file, FileIdentity& out);

// DOS path of an open file, from the kernel (GetFinalPathNameByHandleW), without "\\?\".
std::wstring final_path(HANDLE file);

// Opens a file for reading; shares everything so that a check never blocks another program.
HANDLE open_read(const std::wstring& path);

}  // namespace mebet::trust
