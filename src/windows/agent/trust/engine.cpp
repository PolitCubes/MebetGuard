// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "trust/engine.hpp"

#include <winver.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

#include "config.hpp"
#include "core/watchdog.hpp"
#include "core/win_util.hpp"
#include "hooks/load_gate.hpp"
#include "mebet_trust_data.hpp"
#include "strings.hpp"

namespace mebet::trust {

namespace {

struct State {
    SRWLOCK lock = SRWLOCK_INIT;
    std::map<FileIdentity, Decision> cache;
    std::wstring java_home;
    std::vector<std::wstring> display_dirs;  // WHQL rule (ТЗ §6 «Правила сверки подписей»)
    FileIdentity self_id{}, exe_id{};
    bool self_known = false, exe_known = false;
    bool catalog_broken = false;
};

State& state() {
    static State* s = new State();
    return *s;
}

// --- Collected list: native libraries by SHA-256 (ТЗ §6) ---------------------------------

bool hash_size_listed(std::uint64_t size) {
    const auto* begin = config::kNativeHashes;
    const auto* end = config::kNativeHashes + config::kNativeHashCount;
    const auto* it = std::lower_bound(begin, end, size, [](const config::HashDef& h, std::uint64_t s) { return h.size < s; });
    return it != end && it->size == size;
}

const char* hash_listed(std::uint64_t size, const Sha256Digest& d) {
    for (unsigned i = 0; i < config::kNativeHashCount; ++i) {
        const auto& h = config::kNativeHashes[i];
        if (h.size == size && std::memcmp(h.sha256, d.bytes, 32) == 0) return h.label;
    }
    return nullptr;
}

bool denylist_has_file_hashes() {
    for (unsigned i = 0; i < config::kDenylistCount; ++i)
        if (config::kDenylist[i].kind == config::DenyKind::file_sha256) return true;
    return false;
}

const char* denied_file_hash(const Sha256Digest& d) {
    for (unsigned i = 0; i < config::kDenylistCount; ++i) {
        const auto& e = config::kDenylist[i];
        if (e.kind == config::DenyKind::file_sha256 && std::memcmp(e.sha256, d.bytes, 32) == 0) return e.id;
    }
    return nullptr;
}

const char* denied_signer(const Signer& s, const std::wstring& file_name) {
    const std::string cn = normalize_name(s.cn), o = normalize_name(s.o), issuer = normalize_name(s.issuer_cn);
    const std::string file = to_utf8(lower_ascii(file_name));
    for (unsigned i = 0; i < config::kDenylistCount; ++i) {
        const auto& e = config::kDenylist[i];
        switch (e.kind) {
            case config::DenyKind::leaf_sha256:
                if (std::memcmp(e.sha256, s.leaf_sha256.bytes, 32) == 0) return e.id;
                break;
            case config::DenyKind::issuer_serial:
                if (issuer == e.a && s.serial == e.b) return e.id;
                break;
            case config::DenyKind::publisher_file:
                if (cn == e.a && o == e.b && file == e.c) return e.id;
                break;
            case config::DenyKind::file_sha256:
                break;
        }
    }
    return nullptr;
}

// --- Signature rules ---------------------------------------------------------------------

// Microsoft: leaf O = Microsoft Corporation, CN «Microsoft Windows» / «Microsoft
// Corporation» / «Microsoft … Publisher», chain to a Microsoft root by key. The Hardware
// Compatibility Publisher (WHQL) is third-party code and has its own rule (ТЗ §6).
bool microsoft_signer(const Signer& s) {
    if (!s.ms_os && !s.ms_app) return false;
    if (normalize_name(s.o) != "microsoftcorporation") return false;
    const std::string cn = normalize_name(s.cn);
    if (cn == "microsoftwindowshardwarecompatibilitypublisher") return false;
    if (cn == "microsoftwindows" || cn == "microsoftcorporation") return true;
    return cn.size() > 18 && cn.compare(0, 9, "microsoft") == 0 && cn.compare(cn.size() - 9, 9, "publisher") == 0;
}

bool whcp_signer(const Signer& s) {
    return (s.ms_os || s.ms_app) && normalize_name(s.o) == "microsoftcorporation" &&
           normalize_name(s.cn) == "microsoftwindowshardwarecompatibilitypublisher";
}

bool in_display_driver_dir(const std::wstring& path) {
    for (const auto& d : state().display_dirs)
        if (win::path_under(path, d)) return true;
    return false;
}

std::string product_version(const std::wstring& path) {
    gate::OwnReadScope own;
    // GetFileVersionInfo trims a dot or a space at the end of a name: for "name.dll." it reads the
    // "name.dll" next to it, while the signature was verified on the dotted file through its
    // handle. No version then — and a publisher rule with a version floor does not match.
    if (win::exact_path(path) != path) return std::string();
    DWORD dummy = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (!size) return std::string();
    std::vector<unsigned char> buf(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buf.data())) return std::string();
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&ffi), &len) || !ffi) return std::string();
    char v[64];
    std::snprintf(v, sizeof(v), "%u.%u.%u.%u", HIWORD(ffi->dwProductVersionMS), LOWORD(ffi->dwProductVersionMS),
                  HIWORD(ffi->dwProductVersionLS), LOWORD(ffi->dwProductVersionLS));
    return v;
}

// Trusted publisher: CN + O variant + one of its pinned roots anchoring the chain, by the root's
// identity anywhere in it (ТЗ §6). Never by serial/thumbprint.
int publisher_of(const Signer& s, const std::wstring& path, bool* new_cert) {
    *new_cert = false;
    if (s.pinned_mask == 0) return -1;
    const std::string cn = normalize_name(s.cn), o = normalize_name(s.o), issuer = normalize_name(s.issuer_cn);
    for (const auto& d : config::kSigners) {
        const auto& p = config::kPublishers[d.publisher];
        if ((p.root_mask & s.pinned_mask) == 0 || cn != d.cn || o != d.o) continue;
        if (d.issuer_cn && issuer != d.issuer_cn) continue;
        if (p.min_product_version && compare_versions(product_version(path), p.min_product_version) < 0) continue;
        bool seen = false;
        bool any_observation = false;
        for (unsigned i = 0; i < config::kObservationCount; ++i) {
            if (config::kObservations[i].publisher != d.publisher) continue;
            any_observation = true;
            const char* pre = config::kObservations[i].serial_prefix;
            if (s.serial.compare(0, std::strlen(pre), pre) == 0) seen = true;
        }
        *new_cert = any_observation && !seen;
        return d.publisher;
    }
    return -1;
}

bool apply_signers(const Signatures& sigs, const std::wstring& path, Verdict& v) {
    const std::wstring file = win::file_name_of(path);
    for (const Signer& s : sigs.signers) {
        if (const char* id = denied_signer(s, file)) {
            v.allowed = false;
            v.reason = config::Reason::denylisted_module;
            v.rule = "denylist";
            v.matched = id;
            return true;  // final: a denylisted signature overrides everything
        }
    }
    for (const Signer& s : sigs.signers) {
        if (microsoft_signer(s)) {
            v.allowed = true;
            v.trust = Trust::os;
            v.rule = sigs.kind == SigKind::catalog ? "microsoft_catalog" : "microsoft";
            v.matched = s.cn;
            return true;
        }
        bool fresh = false;
        const int p = publisher_of(s, path, &fresh);
        if (p >= 0) {
            v.allowed = true;
            v.publisher = p;
            v.trust = std::strcmp(config::kPublishers[p].group, "java") == 0 ? Trust::java : Trust::publisher;
            v.rule = "publisher";
            v.matched = config::kPublishers[p].id;
            v.new_certificate = fresh;
            return true;
        }
        if (whcp_signer(s) && in_display_driver_dir(path)) {
            v.allowed = true;
            v.trust = Trust::whql;
            v.rule = "whql_display_driver";
            v.matched = to_utf8(win::dir_of(path));
            return true;
        }
    }
    return false;
}

// Directory of the INF package for DriverStore paths, otherwise the file's folder.
std::wstring driver_root(const std::wstring& file) {
    static const std::wstring marker = L"\\DriverStore\\FileRepository\\";
    const std::wstring low = lower_ascii(file);
    const auto pos = low.find(lower_ascii(marker));
    if (pos != std::wstring::npos) {
        const auto start = pos + marker.size();
        const auto end = file.find(L'\\', start);
        if (end != std::wstring::npos) return file.substr(0, end);
    }
    return win::dir_of(file);
}

void collect_display_dirs(std::vector<std::wstring>& out) {
    const wchar_t* cls = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
    const wchar_t* values[] = {L"InstalledDisplayDrivers", L"UserModeDriverName", L"UserModeDriverNameWow",
                               L"OpenGLDriverName", L"OpenGLDriverNameWow"};
    for (const auto& sub : win::reg_subkeys(HKEY_LOCAL_MACHINE, cls)) {
        if (sub.size() != 4) continue;  // 0000, 0001…
        const std::wstring key = std::wstring(cls) + L"\\" + sub;
        for (const wchar_t* v : values) {
            for (const auto& item : win::reg_multi_string(HKEY_LOCAL_MACHINE, key.c_str(), v)) {
                if (item.find(L'\\') == std::wstring::npos) continue;  // Windows 7 style bare name
                const std::wstring dir = driver_root(item);
                if (!dir.empty() && std::find(out.begin(), out.end(), dir) == out.end()) out.push_back(dir);
            }
        }
    }
    // Windows 7 drivers live in System32 / SysWOW64 (ТЗ §6).
    if (!win::os_version().at_least(6, 2)) {
        out.push_back(win::windows_dir() + L"\\System32");
        out.push_back(win::windows_dir() + L"\\SysWOW64");
    }
}

LARGE_INTEGER qpc() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t;
}

double ms_since(LARGE_INTEGER start) {
    LARGE_INTEGER f, now = qpc();
    QueryPerformanceFrequency(&f);
    return static_cast<double>(now.QuadPart - start.QuadPart) * 1000.0 / static_cast<double>(f.QuadPart);
}

bool identity_of_path(const std::wstring& path, FileIdentity& id) {
    HANDLE f = open_read(path);
    if (f == INVALID_HANDLE_VALUE) return false;
    const bool ok = identity_of(f, id);
    CloseHandle(f);
    return ok;
}

}  // namespace

const char* trust_name(Trust t) {
    switch (t) {
        case Trust::unknown: return "unknown";
        case Trust::os: return "os";
        case Trust::known_dll: return "known_dll";
        case Trust::java: return "java";
        case Trust::publisher: return "publisher";
        case Trust::whql: return "whql";
        case Trust::hash: return "hash";
        case Trust::self: return "self";
        case Trust::exe: return "exe";
    }
    return "unknown";
}

void init_engine(const std::wstring& java_home) {
    State& s = state();
    s.java_home = win::full_path(java_home);
    collect_display_dirs(s.display_dirs);

    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&init_engine), &self);
    s.self_known = identity_of_path(win::module_path(self), s.self_id);
    const DWORD self_err = GetLastError();
    s.exe_known = identity_of_path(win::module_path(nullptr), s.exe_id);
    const DWORD exe_err = GetLastError();
    // Test builds: say when our own files cannot be identified — they would be refused next.
    if (config::kTestBuild && (!s.self_known || !s.exe_known)) {
        std::fprintf(stderr, "[Mebet] own identity: agent=%s (error %lu) exe=%s (error %lu) %s\n",
                     s.self_known ? "yes" : "no", s.self_known ? 0ul : self_err, s.exe_known ? "yes" : "no",
                     s.exe_known ? 0ul : exe_err, to_utf8(win::module_path(nullptr)).c_str());
        std::fflush(stderr);
    }

    // Catalog infrastructure check: kernel32.dll is catalog-signed on every Windows.
    const std::wstring k32 = win::system_dir() + L"\\kernel32.dll";
    HANDLE f = open_read(k32);
    if (f != INVALID_HANDLE_VALUE) {
        const Signatures sig = read_catalog(f, k32);
        const Signatures emb = sig.signers.empty() ? read_embedded(f, k32) : Signatures{};
        s.catalog_broken = sig.signers.empty() && emb.signers.empty();
        CloseHandle(f);
    }
}

const std::wstring& java_home() { return state().java_home; }

bool is_java_dir_file(const std::wstring& path) { return win::path_under(path, state().java_home); }

namespace {

// Hashes a mapped file chunk by chunk, so that on the worker thread a big file on a slow disk is
// work the watchdog can see, not half a minute of silence. False when the view faults (the file
// shrank under it). In a function of its own: structured exception handling cannot share one
// with objects that have destructors.
bool sha256_of_view(const void* view, std::size_t total, Sha256Digest& out) {
    __try {
        const auto* bytes = static_cast<const unsigned char*>(view);
        const std::size_t chunk = 4u << 20;
        Sha256 h;
        for (std::size_t done = 0; done < total; done += chunk) {
            h.update(bytes + done, total - done < chunk ? total - done : chunk);
            watchdog::worker_beat();
        }
        out = h.finish();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool sha256_of(HANDLE file, Sha256Digest& out, std::uint64_t max_bytes) {
    watchdog::SlowWork slow;  // the first touch of a file on a cold disk
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || static_cast<std::uint64_t>(size.QuadPart) > max_bytes) return false;
    if (size.QuadPart == 0) {
        out = Sha256::of("", 0);
        return true;
    }
    // A read-only view: does not move the file pointer of a handle that belongs to the loader.
    HANDLE map = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) return false;
    const void* view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    bool ok = false;
    if (view) {
        ok = sha256_of_view(view, static_cast<std::size_t>(size.QuadPart), out);
        UnmapViewOfFile(view);
    }
    CloseHandle(map);
    return ok;
}

Decision decide(HANDLE file, const std::wstring& path_hint) {
    watchdog::SlowWork slow;  // a signature or catalog check shows nothing while it runs
    State& st = state();
    Decision d;
    FileFacts& f = d.facts;
    f.path = final_path(file);
    if (f.path.empty()) f.path = path_hint;
    f.identity_known = identity_of(file, f.identity);

    if (f.identity_known) {
        AcquireSRWLockShared(&st.lock);
        auto it = st.cache.find(f.identity);
        if (it != st.cache.end()) {
            Decision cached = it->second;
            ReleaseSRWLockShared(&st.lock);
            return cached;
        }
        ReleaseSRWLockShared(&st.lock);
        if (st.self_known && f.identity == st.self_id) {
            d.verdict.allowed = true;
            d.verdict.trust = Trust::self;
            d.verdict.rule = "self";
            return d;
        }
        if (st.exe_known && f.identity == st.exe_id) {
            d.verdict.allowed = true;
            d.verdict.trust = Trust::exe;
            d.verdict.rule = "exe";
            return d;
        }
    }

    const LARGE_INTEGER t0 = qpc();
    const std::uint64_t witnessed0 = watchdog::witnessed_100ns();
    Verdict& v = d.verdict;
    bool decided = false;

    // 1. Hashes: only when a listed native or a denylisted file has this exact size, so a
    //    86 MB GPU driver is never hashed for nothing (ТЗ §5).
    const std::uint64_t size = f.identity_known ? f.identity.size : 0;
    if ((f.identity_known && hash_size_listed(size)) || denylist_has_file_hashes()) {
        f.hashed = sha256_of(file, f.sha256, 512ull << 20);
        if (f.hashed) {
            if (const char* id = denied_file_hash(f.sha256)) {
                v.allowed = false;
                v.reason = config::Reason::denylisted_module;
                v.rule = "denylist_file";
                v.matched = id;
                decided = true;
            } else if (const char* label = hash_listed(size, f.sha256)) {
                v.allowed = true;
                v.trust = Trust::hash;
                v.rule = "native_hash";
                v.matched = label;
                decided = true;
            }
        }
    }

    // 2. Signatures: embedded first, the catalog when the embedded ones did not decide.
    if (!decided) {
        f.sigs = read_embedded(file, f.path);
        decided = apply_signers(f.sigs, f.path, v);
        if (!decided && !f.sigs.digest_invalid) {
            Signatures cat = read_catalog(file, f.path);
            if (!cat.signers.empty()) {
                const bool cat_decided = apply_signers(cat, f.path, v);
                if (cat_decided || f.sigs.signers.empty()) {
                    // keep the embedded signers in the card as well
                    for (auto& s : f.sigs.signers) cat.signers.push_back(s);
                    f.sigs = std::move(cat);
                }
                decided = cat_decided;
            }
        }
    }

    if (!decided) {
        v.allowed = false;
        v.rule = "not_listed";
        if (f.sigs.digest_invalid) {
            v.rule = "bad_digest";
        } else if (windows7_without_sha2() && !f.sigs.signers.empty()) {
            v.reason = config::Reason::win7_no_sha2;
        } else if (f.sigs.kind == SigKind::none && st.catalog_broken) {
            v.reason = config::Reason::catalog_unavailable;
        }
    }

    d.ms = ms_since(t0);
    // The limit is on the time the check took, not on the time the game was held meanwhile: a
    // game paused as a whole (Suspend in a task manager) in the middle of a library load came
    // back with half a minute on the clock, and a correctly signed system DLL was refused as
    // verify_timeout. With the watchdog running, no more is counted than it saw the process run
    // (plus its own granularity).
    double judged_ms = d.ms;
    if (witnessed0) {
        const double seen_ms = static_cast<double>(watchdog::witnessed_100ns() - witnessed0) / 10000.0 + 1500.0;
        if (seen_ms < judged_ms) judged_ms = seen_ms;
    }
    if (judged_ms > static_cast<double>(config::opt::verify_timeout_ms)) {
        v.allowed = false;
        v.reason = config::Reason::verify_timeout;
        v.rule = "timeout";
    }

    if (f.identity_known && v.reason != config::Reason::verify_timeout) {
        AcquireSRWLockExclusive(&st.lock);
        st.cache.emplace(f.identity, d);
        ReleaseSRWLockExclusive(&st.lock);
    }
    return d;
}

Decision decide_path(const std::wstring& path) {
    watchdog::SlowWork slow;  // the open itself can wait on a slow disk
    HANDLE f = open_read(path);
    if (f == INVALID_HANDLE_VALUE) {
        Decision d;
        d.facts.path = path;
        d.verdict.allowed = false;
        d.verdict.rule = "unreadable";
        return d;
    }
    Decision d = decide(f, path);
    CloseHandle(f);
    return d;
}

}  // namespace mebet::trust
