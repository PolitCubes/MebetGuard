// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "trust/file_identity.hpp"

#include "core/watchdog.hpp"
#include "core/win_util.hpp"

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

// NtQueryInformationFile(FileInternalInformation) and NtQueryVolumeInformationFile(FileFsVolume): the
// 64-bit NTFS file id and the volume serial, from a handle with no access rights at all — the last
// resort on Windows 7, where the loader's section-file handle gives neither of the two above, so a
// record would have no id and an image swapped in under the same name could keep its trust.
struct IoStatusBlock {
    union {
        LONG Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
};
struct FileInternalInfo {
    LARGE_INTEGER IndexNumber;
};
struct FileFsVolumeInfo {
    LARGE_INTEGER VolumeCreationTime;
    ULONG VolumeSerialNumber;
    ULONG VolumeLabelLength;
    BOOLEAN SupportsObjects;
    WCHAR VolumeLabel[1];
};
using NtQueryInformationFileFn = LONG(NTAPI*)(HANDLE, IoStatusBlock*, PVOID, ULONG, int);
using NtQueryVolumeInformationFileFn = LONG(NTAPI*)(HANDLE, IoStatusBlock*, PVOID, ULONG, int);

bool nt_file_id(HANDLE file, FileIdentity& out) {
    static const auto q = reinterpret_cast<NtQueryInformationFileFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationFile")));
    static const auto qv = reinterpret_cast<NtQueryVolumeInformationFileFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVolumeInformationFile")));
    if (!q || !qv) return false;
    IoStatusBlock iosb{};
    FileInternalInfo id{};
    if (q(file, &iosb, &id, sizeof(id), 6 /*FileInternalInformation*/) < 0) return false;  // STATUS_SUCCESS is 0
    alignas(8) unsigned char buf[sizeof(FileFsVolumeInfo) + 64] = {};
    if (qv(file, &iosb, buf, sizeof(buf), 1 /*FileFsVolumeInformation*/) < 0) return false;
    out.volume = reinterpret_cast<const FileFsVolumeInfo*>(buf)->VolumeSerialNumber;
    std::memcpy(out.file_id, &id.IndexNumber.QuadPart, 8);  // upper 8 bytes stay 0, as the other paths leave them
    return true;
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
    if (!have && nt_file_id(file, out)) {
        FileStandardInfo st{};
        if (auto ex = get_info_ex(); ex && ex(file, kFileStandardInfoClass, &st, sizeof(st)))
            out.size = static_cast<std::uint64_t>(st.EndOfFile.QuadPart);
        have = true;  // an id and a volume: enough to tell this file from the one swapped in for it
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
    watchdog::SlowWork slow;  // an open can wait on a slow or unreachable disk
    const std::wstring exact = win::exact_path(path);
    const HANDLE f = CreateFileW(exact.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) return f;
#if defined(_M_IX86) || defined(__i386__)
    // Under WOW64 the system redirects System32 to SysWOW64, where a 64-bit-only file is not: the
    // kernel names csrss.exe as C:\Windows\System32\csrss.exe, and that open says "not found" from a
    // 32-bit process — the holder then looked unreadable and the game was closed (227) on the runner.
    // `Sysnative` is the native System32, seen by WOW64 only.
    if (win::path_under(path, win::windows_dir() + L"\\System32")) {
        const std::wstring native = win::windows_dir() + L"\\Sysnative" + path.substr((win::windows_dir() + L"\\System32").size());
        return CreateFileW(win::exact_path(native).c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    }
#endif
    return f;
}

}  // namespace mebet::trust
