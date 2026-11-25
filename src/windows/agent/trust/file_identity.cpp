// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "trust/file_identity.hpp"

namespace mebet::trust {

namespace {

// FILE_ID_INFO / FILE_STANDARD_INFO by class number: hidden by the SDK below 0x0602.
struct FileIdInfo {
    ULONGLONG VolumeSerialNumber;
    unsigned char FileId[16];
};
struct FileStandardInfo {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    DWORD NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
};
constexpr int kFileStandardInfoClass = 1;
constexpr int kFileIdInfoClass = 18;

using GetFileInformationByHandleExFn = BOOL(WINAPI*)(HANDLE, int, LPVOID, DWORD);

GetFileInformationByHandleExFn get_info_ex() {
    static const auto fn = reinterpret_cast<GetFileInformationByHandleExFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFileInformationByHandleEx")));
    return fn;
}

}  // namespace

bool identity_of(HANDLE file, FileIdentity& out) {
    out = FileIdentity{};
    bool have = false;
    BY_HANDLE_FILE_INFORMATION bh{};
    if (GetFileInformationByHandle(file, &bh)) {
        out.volume = bh.dwVolumeSerialNumber;
        out.size = (static_cast<std::uint64_t>(bh.nFileSizeHigh) << 32) | bh.nFileSizeLow;
        out.mtime =
            (static_cast<std::uint64_t>(bh.ftLastWriteTime.dwHighDateTime) << 32) | bh.ftLastWriteTime.dwLowDateTime;
        std::memcpy(out.file_id, &bh.nFileIndexLow, 4);
        std::memcpy(out.file_id + 4, &bh.nFileIndexHigh, 4);
        have = true;
    }
    if (auto ex = get_info_ex()) {
        // The loader opens DLLs without FILE_READ_ATTRIBUTES; these two classes need no
        // particular access right, and FileIdInfo also covers ReFS 128-bit ids.
        FileIdInfo id{};
        if (ex(file, kFileIdInfoClass, &id, sizeof(id))) {
            out.volume = id.VolumeSerialNumber;
            std::memcpy(out.file_id, id.FileId, 16);
            if (!have) {
                FileStandardInfo st{};
                if (ex(file, kFileStandardInfoClass, &st, sizeof(st))) {
                    out.size = static_cast<std::uint64_t>(st.EndOfFile.QuadPart);
                    have = true;  // mtime stays 0: still unique per file version for the session
                }
            }
        }
    }
    return have;
}

std::wstring final_path(HANDLE file) {
    wchar_t small[MAX_PATH + 8];
    DWORD n = GetFinalPathNameByHandleW(file, small, MAX_PATH + 8, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    std::wstring p;
    if (n == 0) return p;
    if (n < MAX_PATH + 8) {
        p.assign(small, n);
    } else {
        p.resize(n);
        n = GetFinalPathNameByHandleW(file, &p[0], n, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        p.resize(n);
    }
    if (p.compare(0, 8, L"\\\\?\\UNC\\") == 0) return L"\\\\" + p.substr(8);
    if (p.compare(0, 4, L"\\\\?\\") == 0) return p.substr(4);
    return p;
}

HANDLE open_read(const std::wstring& path) {
    return CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

std::wstring resolved_path(const std::wstring& path) {
    if (path.empty()) return path;
    // Attributes only: no data access, so no sharing conflict and no section is created.
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return path;
    std::wstring p = final_path(h);
    CloseHandle(h);
    return p.empty() ? path : p;
}

}  // namespace mebet::trust
