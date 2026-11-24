#include "report/cards.hpp"

#include <winver.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>
#include <vector>

#include "config.hpp"
#include "core/exec_table.hpp"
#include "core/module_table.hpp"
#include "core/win_util.hpp"
#include "json_writer.hpp"
#include "strings.hpp"

namespace mebet::cards {

namespace {

struct Prefixes {
    SRWLOCK lock = SRWLOCK_INIT;
    std::vector<std::pair<std::wstring, std::wstring>> list;  // (prefix, replacement), most specific first
    bool ready = false;
    std::wstring game;
};

Prefixes& prefixes() {
    static Prefixes* p = new Prefixes();
    return *p;
}

void build_prefixes(Prefixes& p) {
    p.list.clear();
    auto add = [&](const std::wstring& dir, const wchar_t* name) {
        const std::wstring d = win::full_path(dir);
        if (d.size() > 3) p.list.emplace_back(d, name);
    };
    if (!p.game.empty()) add(p.game, L"%GAME%");
    if (!trust::java_home().empty()) add(trust::java_home(), L"%JAVA%");
    add(win::env(L"TEMP"), L"%TEMP%");
    add(win::env(L"APPDATA"), L"%APPDATA%");
    add(win::env(L"LOCALAPPDATA"), L"%LOCALAPPDATA%");
    add(win::env(L"USERPROFILE"), L"%USERPROFILE%");
    add(win::env(L"ProgramFiles(x86)"), L"%ProgramFiles(x86)%");
    add(win::env(L"ProgramFiles"), L"%ProgramFiles%");
    add(win::env(L"ProgramData"), L"%ProgramData%");
    add(win::windows_dir(), L"%WINDIR%");
    // Longest prefix first, so %GAME% inside %APPDATA% wins.
    for (std::size_t i = 0; i < p.list.size(); ++i)
        for (std::size_t j = i + 1; j < p.list.size(); ++j)
            if (p.list[j].first.size() > p.list[i].first.size()) std::swap(p.list[i], p.list[j]);
    p.ready = true;
}

std::string json_string_or_null(const std::string& s) {
    JsonWriter w;
    if (s.empty()) w.null_value(); else w.value(s);
    return w.take();
}

std::string iso_date(std::int64_t unix_s) {
    if (unix_s <= 0) return std::string();
    const std::time_t t = static_cast<std::time_t>(unix_s);
    std::tm tm{};
    if (gmtime_s(&tm, &t) != 0) return std::string();
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

struct VersionStrings {
    std::string company, product, description, file_version, product_version, original_filename, internal_name;
};

VersionStrings version_strings(const std::wstring& path) {
    VersionStrings v;
    DWORD dummy = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (!size || size > (4u << 20)) return v;
    std::vector<unsigned char> buf(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buf.data())) return v;
    struct LangCp {
        WORD lang, cp;
    };
    LangCp* tr = nullptr;
    UINT len = 0;
    wchar_t prefix[64] = L"\\StringFileInfo\\040904B0\\";
    if (VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&tr), &len) && tr &&
        len >= sizeof(LangCp)) {
        swprintf_s(prefix, L"\\StringFileInfo\\%04x%04x\\", tr->lang, tr->cp);
    }
    auto get = [&](const wchar_t* key) {
        std::wstring q = std::wstring(prefix) + key;
        wchar_t* val = nullptr;
        UINT n = 0;
        if (VerQueryValueW(buf.data(), q.c_str(), reinterpret_cast<void**>(&val), &n) && val && n)
            return truncate_utf8(to_utf8(std::wstring(val, wcsnlen(val, n))), config::kLimit_string_chars);
        return std::string();
    };
    v.company = get(L"CompanyName");
    v.product = get(L"ProductName");
    v.description = get(L"FileDescription");
    v.file_version = get(L"FileVersion");
    v.product_version = get(L"ProductVersion");
    v.original_filename = get(L"OriginalFilename");
    v.internal_name = get(L"InternalName");
    return v;
}

struct PeFacts {
    const char* machine = nullptr;
    std::uint32_t timestamp = 0;
    std::uint32_t size_of_image = 0;
};

const char* machine_name(WORD m) {
    switch (m) {
        case IMAGE_FILE_MACHINE_I386: return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case 0xAA64: return "arm64";
        case 0xA641: return "arm64ec";
        case IMAGE_FILE_MACHINE_ARMNT: return "arm";
        default: return "other";
    }
}

PeFacts pe_facts_from(const unsigned char* p, std::size_t n) {
    PeFacts f;
    if (n < 0x40 || p[0] != 'M' || p[1] != 'Z') return f;
    const std::uint32_t e = *reinterpret_cast<const std::uint32_t*>(p + 0x3C);
    if (e + 24 + 60 > n || std::memcmp(p + e, "PE\0\0", 4) != 0) return f;
    const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(p + e + 4);
    f.machine = machine_name(fh->Machine);
    f.timestamp = fh->TimeDateStamp;
    f.size_of_image = *reinterpret_cast<const std::uint32_t*>(p + e + 24 + 56);  // OptionalHeader.SizeOfImage
    return f;
}

PeFacts pe_facts(const std::wstring& path) {
    PeFacts f;
    HANDLE h = trust::open_read(path);
    if (h == INVALID_HANDLE_VALUE) return f;
    unsigned char buf[4096];
    DWORD got = 0;
    if (ReadFile(h, buf, sizeof(buf), &got, nullptr)) f = pe_facts_from(buf, got);
    CloseHandle(h);
    return f;
}

bool dir_writable(const std::wstring& dir) {
    HANDLE h = CreateFileW(dir.c_str(), FILE_ADD_FILE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

const char* root_class_name(const trust::Signer& s) {
    if (s.ms_os) return "ms_os";
    if (s.ms_app) return "ms_app";
    if (s.pinned_root >= 0) {
        return config::kRoots[s.pinned_root].cls == config::RootClass::ms_ivr ? "ms_ivr" : "public";
    }
    return "unknown";
}

void write_signer(JsonWriter& w, const trust::Signer& s) {
    w.begin_object();
    w.field("cn", s.cn);
    w.field("o", s.o);
    w.field("ou", s.ou);
    w.field("c", s.c);
    w.field("serial", s.serial);
    w.field("leaf_sha256", s.leaf_sha256.hex());
    w.field("issuer", s.issuer_cn);
    w.field("root", s.root_cn);
    w.field("root_class", root_class_name(s));
    if (s.pinned_root >= 0) w.field("root_id", config::kRoots[s.pinned_root].id);
    w.key("eku").begin_array();
    for (const auto& e : s.ekus) w.value(e);
    w.end_array();
    w.field("not_before", iso_date(s.not_before));
    w.field("not_after", iso_date(s.not_after));
    if (s.timestamp) {
        w.field("timestamp", iso_date(s.timestamp));
        w.field("tsa", s.tsa_cn);
    }
    w.end_object();
}

std::string short_hex(std::uintptr_t a) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(a));
    return buf;
}

}  // namespace

void set_game_dir(const std::wstring& dir) {
    Prefixes& p = prefixes();
    AcquireSRWLockExclusive(&p.lock);
    p.game = dir;
    p.ready = false;
    ReleaseSRWLockExclusive(&p.lock);
}

std::string anonymize(const std::wstring& path) {
    Prefixes& p = prefixes();
    AcquireSRWLockExclusive(&p.lock);
    if (!p.ready) build_prefixes(p);
    std::wstring out = path;
    for (const auto& kv : p.list) {
        if (out.size() >= kv.first.size() && istarts_with(out, kv.first) &&
            (out.size() == kv.first.size() || out[kv.first.size()] == L'\\' || out[kv.first.size()] == L'/')) {
            out = kv.second + out.substr(kv.first.size());
            break;
        }
    }
    ReleaseSRWLockExclusive(&p.lock);
    // Any other user folder: hide the name.
    const std::wstring users = L":\\Users\\";
    const auto pos = lower_ascii(out).find(lower_ascii(users));
    if (pos != std::wstring::npos) {
        const auto start = pos + users.size();
        const auto end = out.find(L'\\', start);
        out = out.substr(0, start) + L"<user>" + (end == std::wstring::npos ? std::wstring() : out.substr(end));
    }
    return truncate_utf8(to_utf8(out), config::kLimit_string_chars);
}

const char* dir_class(const std::wstring& path) {
    const std::wstring win = win::windows_dir();
    if (win::path_under(path, win + L"\\System32") || win::path_under(path, win + L"\\SysWOW64") ||
        win::path_under(path, win + L"\\WinSxS"))
        return "system32";
    if (win::path_under(path, win)) return "windows";
    if (!trust::java_home().empty() && win::path_under(path, trust::java_home())) return "java";
    {
        Prefixes& p = prefixes();
        AcquireSRWLockShared(&p.lock);
        const std::wstring game = p.game;
        ReleaseSRWLockShared(&p.lock);
        if (!game.empty() && win::path_under(path, game)) return "game";
    }
    const std::wstring pf = win::env(L"ProgramFiles"), pf86 = win::env(L"ProgramFiles(x86)");
    if ((!pf.empty() && win::path_under(path, pf)) || (!pf86.empty() && win::path_under(path, pf86))) return "program_files";
    const std::wstring temp = win::env(L"TEMP");
    if (!temp.empty() && win::path_under(path, temp)) return "temp";
    const std::wstring appdata = win::env(L"APPDATA"), local = win::env(L"LOCALAPPDATA");
    if ((!appdata.empty() && win::path_under(path, appdata)) || (!local.empty() && win::path_under(path, local))) return "appdata";
    const std::wstring pd = win::env(L"ProgramData");
    if (!pd.empty() && win::path_under(path, pd)) return "program_data";
    return "other";
}

std::string file_label(const trust::Decision& d) {
    std::string name = to_utf8(win::file_name_of(d.facts.path));
    if (name.empty()) name = "?";
    if (!d.facts.sigs.signers.empty()) {
        const auto& s = d.facts.sigs.signers.front();
        return name + " (" + (s.o.empty() ? s.cn : s.o) + ")";
    }
    return name + " (unsigned)";
}

std::string file_card_json(const trust::Decision& d) {
    const trust::FileFacts& f = d.facts;
    JsonWriter w;
    w.begin_object();
    // File
    w.field("name", to_utf8(win::file_name_of(f.path)));
    w.field("path", anonymize(f.path));
    w.field("dir_class", dir_class(f.path));
    w.field("dir_writable", dir_writable(win::dir_of(f.path)));
    w.field("size", f.identity.size);
    Sha256Digest sha = f.sha256;
    bool hashed = f.hashed;
    if (!hashed) {
        HANDLE h = trust::open_read(f.path);
        if (h != INVALID_HANDLE_VALUE) {
            hashed = trust::sha256_of(h, sha, 512ull << 20);
            CloseHandle(h);
        }
    }
    if (hashed) w.field("sha256", sha.hex()); else w.key("sha256").null_value();
    // PE
    const PeFacts pe = pe_facts(f.path);
    w.key("pe").begin_object();
    w.field("machine", pe.machine ? pe.machine : "");
    w.field("time_date_stamp", static_cast<std::uint64_t>(pe.timestamp));
    const VersionStrings v = version_strings(f.path);
    w.field("company", v.company);
    w.field("product", v.product);
    w.field("description", v.description);
    w.field("file_version", v.file_version);
    w.field("product_version", v.product_version);
    w.field("original_filename", v.original_filename);
    w.field("internal_name", v.internal_name);
    w.end_object();
    // Signatures
    w.key("signature").begin_object();
    char code[16];
    std::snprintf(code, sizeof(code), "0x%08lX", static_cast<unsigned long>(f.sigs.result));
    w.field("winverifytrust", code);
    w.field("kind", f.sigs.kind == trust::SigKind::embedded ? "embedded"
                    : f.sigs.kind == trust::SigKind::catalog ? "catalog" : "none");
    if (f.sigs.kind == trust::SigKind::catalog) w.field("catalog", to_utf8(f.sigs.catalog));
    w.field("digest_invalid", f.sigs.digest_invalid);
    w.key("signers").begin_array();
    for (std::size_t i = 0; i < f.sigs.signers.size() && i < config::kLimit_list_items; ++i) write_signer(w, f.sigs.signers[i]);
    w.end_array();
    w.end_object();
    // Decision
    w.key("decision").begin_object();
    w.field("allowed", d.verdict.allowed);
    w.field("trust", trust::trust_name(d.verdict.trust));
    w.field("rule", d.verdict.rule);
    w.key("matched").raw(json_string_or_null(d.verdict.matched));
    w.key("ms").value_double(d.ms);
    w.end_object();
    w.end_object();
    return w.take();
}

std::string file_card_json(const std::wstring& path) { return file_card_json(trust::decide_path(path)); }

std::string address_hex(std::uintptr_t a) { return short_hex(a); }

std::string address_json(std::uintptr_t a) {
    JsonWriter w;
    w.begin_object();
    w.field("address", short_hex(a));
    trust::Trust t;
    std::uintptr_t base = 0;
    if (a && modules::find(a, &t, &base)) {
        w.field("module", anonymize(modules::path_of(base)));
        w.field("trust", trust::trust_name(t));
        w.field("offset", short_hex(a - base));
    } else if (a) {
        exec::Owner o{};
        MEMORY_BASIC_INFORMATION mbi{};
        if (exec::find(a, &o)) {
            w.field("region_owner", anonymize(modules::path_of(o.module_base)));
            w.field("region_owner_trust", trust::trust_name(o.trust));
        } else if (VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof(mbi))) {
            w.field("region_base", short_hex(reinterpret_cast<std::uintptr_t>(mbi.AllocationBase)));
            w.field("region_type", mbi.Type == MEM_IMAGE ? "image" : mbi.Type == MEM_MAPPED ? "mapped" : "private");
            const std::wstring mapped = win::mapped_file_name(reinterpret_cast<void*>(a));
            if (!mapped.empty()) w.field("mapped_file", anonymize(mapped));
        }
    }
    w.end_object();
    return w.take();
}

std::string address_owner_key(std::uintptr_t a) {
    trust::Trust t;
    std::uintptr_t base = 0;
    if (a && modules::find(a, &t, &base)) return to_utf8(lower_ascii(win::file_name_of(modules::path_of(base))));
    std::string key;
    if (a) region_json(a, &key);
    return key.empty() ? std::string("no_module") : key;
}

std::string region_json(std::uintptr_t addr, std::string* group_key) {
    JsonWriter w;
    w.begin_object();
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) {
        w.field("address", short_hex(addr));
        w.end_object();
        return w.take();
    }
    const auto alloc = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
    w.field("address", short_hex(addr));
    w.field("allocation_base", short_hex(alloc));
    w.field("region_base", short_hex(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress)));
    w.field("size", static_cast<std::uint64_t>(mbi.RegionSize));
    w.field("type", mbi.Type == MEM_IMAGE ? "image" : mbi.Type == MEM_MAPPED ? "mapped" : "private");
    char prot[16];
    std::snprintf(prot, sizeof(prot), "0x%lx", static_cast<unsigned long>(mbi.Protect));
    w.field("protect", prot);

    // Up to 16 MB of the region for the SHA-256, the first 256 bytes verbatim (ТЗ §12).
    const std::size_t take = mbi.RegionSize > (16u << 20) ? (16u << 20) : mbi.RegionSize;
    std::vector<unsigned char> copy(take);
    std::size_t got = 0;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, copy.data(), take, &read)) got = read;
    if (got) {
        const Sha256Digest d = Sha256::of(copy.data(), got);
        w.field("sha256", d.hex());
        const std::size_t head = got < config::kLimit_memory_bytes ? got : config::kLimit_memory_bytes;
        w.field("first_bytes", hex(copy.data(), head));
        const PeFacts pe = pe_facts_from(copy.data(), got);
        std::string export_name;
        if (pe.machine) {
            w.field("pe_time_date_stamp", static_cast<std::uint64_t>(pe.timestamp));
            w.field("pe_size_of_image", static_cast<std::uint64_t>(pe.size_of_image));
            // Export directory name, if the header survived (manual mappers usually erase it).
            const std::uint32_t e = *reinterpret_cast<const std::uint32_t*>(copy.data() + 0x3C);
            const auto* nth = reinterpret_cast<const IMAGE_NT_HEADERS*>(copy.data() + e);
            if (e + sizeof(IMAGE_NT_HEADERS) <= got) {
                const IMAGE_DATA_DIRECTORY& dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (dir.VirtualAddress && dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) <= got) {
                    const auto* ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(copy.data() + dir.VirtualAddress);
                    if (ed->Name && ed->Name < got) {
                        const char* nm = reinterpret_cast<const char*>(copy.data() + ed->Name);
                        export_name.assign(nm, strnlen(nm, got - ed->Name < 128 ? got - ed->Name : 128));
                    }
                }
            }
            if (!export_name.empty()) w.field("pe_export_name", truncate_utf8(export_name, 128));
        }
        if (group_key) *group_key = !export_name.empty() ? "export:" + export_name : "region:" + d.hex().substr(0, 32);
    }
    w.end_object();
    return w.take();
}

}  // namespace mebet::cards
