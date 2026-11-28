// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "scan/image_integrity.hpp"

#include "nt.hpp"

#include <psapi.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/module_table.hpp"
#include "core/watchdog.hpp"
#include "core/win_util.hpp"
#include "hooks/nt_hooks.hpp"
#include "json_writer.hpp"
#include "report/cards.hpp"
#include "scan/scans.hpp"
#include "strings.hpp"
#include "trust/file_identity.hpp"

namespace mebet::integrity {

namespace {

constexpr std::uint32_t kPage = 0x1000;

#if defined(_M_X64)
constexpr USHORT kOwnMachine = IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64)
constexpr USHORT kOwnMachine = IMAGE_FILE_MACHINE_ARM64;
#else
constexpr USHORT kOwnMachine = IMAGE_FILE_MACHINE_I386;
#endif

struct Section {
    std::uint32_t va, vsize, raw_ptr, raw_size, characteristics;
};

// What the file says, read once per module record (from the file, never from memory a cheat can write).
struct Layout {
    bool usable = false;
    std::uint64_t image_base = 0;
    std::uint32_t section_alignment = 0;
    std::vector<Section> sections;
    std::uint32_t reloc_rva = 0, reloc_size = 0;
    bool relocs_loaded = false;
    std::vector<unsigned char> relocs;  // the base relocation directory, read when first needed
};

struct Known {
    std::uint64_t serial = 0;
    Layout layout;
};

// Worker thread only.
std::map<std::uintptr_t, Known>& layouts() {
    static auto* m = new std::map<std::uintptr_t, Known>();
    return *m;
}
// (module base, page rva) → hash of the content last judged honest: not compared again until it changes.
std::map<std::pair<std::uintptr_t, std::uint32_t>, std::uint64_t>& judged() {
    static auto* m = new std::map<std::pair<std::uintptr_t, std::uint32_t>, std::uint64_t>();
    return *m;
}

std::uint64_t fnv(const unsigned char* p, std::size_t n) {
    std::uint64_t h = 1469598103934665603ull;
    for (std::size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 1099511628211ull;
    return h;
}

bool read_at(HANDLE f, std::uint64_t offset, void* out, DWORD n) {
    OVERLAPPED ov{};
    ov.Offset = static_cast<DWORD>(offset);
    ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD got = 0;
    return ReadFile(f, out, n, &got, &ov) && got == n;
}

// Opens the module's file and proves it is the one recorded (by id, when the record has one).
HANDLE open_module_file(const modules::Record& rec) {
    if (rec.path.empty()) return INVALID_HANDLE_VALUE;
    const HANDLE h = trust::open_read(rec.path);
    if (h == INVALID_HANDLE_VALUE || !rec.id_known) return h;
    trust::FileIdentity now{};
    if (!trust::identity_of(h, now) || now.volume != rec.id.volume ||
        std::memcmp(now.file_id, rec.id.file_id, sizeof(now.file_id)) != 0) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

Layout read_layout(HANDLE f) {
    Layout l;
    IMAGE_DOS_HEADER dos{};
    if (!read_at(f, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        dos.e_lfanew > 0x10000)
        return l;
    const auto nt_off = static_cast<std::uint64_t>(dos.e_lfanew);
    DWORD sig = 0;
    IMAGE_FILE_HEADER fh{};
    if (!read_at(f, nt_off, &sig, sizeof(sig)) || sig != IMAGE_NT_SIGNATURE ||
        !read_at(f, nt_off + 4, &fh, sizeof(fh)))
        return l;
    // Only images of our own machine type: an ARM64X image in an emulated x64 process, or the native
    // WOW64 layer in a 32-bit one, is laid out in memory by rules this comparison does not follow.
    if (fh.Machine != kOwnMachine || fh.NumberOfSections == 0 || fh.NumberOfSections > 96) return l;
    const std::uint64_t opt_off = nt_off + 4 + sizeof(fh);
    WORD magic = 0;
    if (!read_at(f, opt_off, &magic, sizeof(magic))) return l;
    IMAGE_DATA_DIRECTORY reloc{};
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 oh{};
        if (fh.SizeOfOptionalHeader < offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) ||
            !read_at(f, opt_off, &oh, sizeof(oh)))
            return l;
        l.image_base = oh.ImageBase;
        l.section_alignment = oh.SectionAlignment;
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) reloc = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 oh{};
        if (fh.SizeOfOptionalHeader < offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) ||
            !read_at(f, opt_off, &oh, sizeof(oh)))
            return l;
        l.image_base = oh.ImageBase;
        l.section_alignment = oh.SectionAlignment;
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) reloc = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
        return l;
    }
    // Images whose sections are not page-aligned map pieces of several sections into one page.
    if (l.section_alignment < kPage) return l;
    std::vector<IMAGE_SECTION_HEADER> sh(fh.NumberOfSections);
    if (!read_at(f, opt_off + fh.SizeOfOptionalHeader, sh.data(),
                 static_cast<DWORD>(sh.size() * sizeof(IMAGE_SECTION_HEADER))))
        return l;
    for (const auto& s : sh)
        l.sections.push_back({s.VirtualAddress, s.Misc.VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Characteristics});
    l.reloc_rva = reloc.VirtualAddress;
    l.reloc_size = reloc.Size;
    l.usable = true;
    return l;
}

std::uint32_t align_up(std::uint32_t v, std::uint32_t a) { return (v + a - 1) & ~(a - 1); }

// File bytes as the image maps them at rva [from, from + n): a section's raw data up to its raw size
// (capped by its aligned virtual size), zero after it and between sections.
bool file_view(HANDLE f, const Layout& l, std::uint32_t from, std::uint32_t n, unsigned char* out) {
    std::memset(out, 0, n);
    for (const Section& s : l.sections) {
        const std::uint32_t mapped = s.raw_size < align_up(s.vsize ? s.vsize : s.raw_size, l.section_alignment)
                                         ? s.raw_size
                                         : align_up(s.vsize ? s.vsize : s.raw_size, l.section_alignment);
        const std::uint64_t b = s.va > from ? s.va : from;
        const std::uint64_t e = std::uint64_t{s.va} + mapped < std::uint64_t{from} + n ? std::uint64_t{s.va} + mapped
                                                                                      : std::uint64_t{from} + n;
        if (b >= e || !s.raw_ptr) continue;
        if (!read_at(f, s.raw_ptr + (b - s.va), out + (b - from), static_cast<DWORD>(e - b))) return false;
    }
    return true;
}

bool load_relocs(HANDLE f, Layout& l) {
    if (l.relocs_loaded) return true;
    l.relocs_loaded = true;
    if (!l.reloc_rva || !l.reloc_size || l.reloc_size > (16u << 20)) return true;  // none: nothing to apply
    l.relocs.resize(l.reloc_size);
    if (!file_view(f, l, l.reloc_rva, l.reloc_size, l.relocs.data())) {
        l.relocs.clear();
        return false;
    }
    return true;
}

// Applies the base relocations of the blocks that touch rva [from, from + n) to `buf`, as the loader
// would for an image at `actual`. False on a relocation kind this comparison does not know.
bool relocate(const Layout& l, std::uint64_t actual, std::uint32_t from, std::uint32_t n, unsigned char* buf) {
    const std::uint64_t delta = actual - l.image_base;
    if (!delta) return true;
    std::size_t off = 0;
    while (off + sizeof(IMAGE_BASE_RELOCATION) <= l.relocs.size()) {
        IMAGE_BASE_RELOCATION blk;
        std::memcpy(&blk, l.relocs.data() + off, sizeof(blk));
        if (blk.SizeOfBlock < sizeof(blk) || off + blk.SizeOfBlock > l.relocs.size()) break;
        // A block covers one page; an entry near its end can reach into the next.
        if (blk.VirtualAddress + kPage + 8 > from && blk.VirtualAddress < from + n) {
            const std::size_t entries = (blk.SizeOfBlock - sizeof(blk)) / sizeof(WORD);
            for (std::size_t i = 0; i < entries; ++i) {
                WORD e;
                std::memcpy(&e, l.relocs.data() + off + sizeof(blk) + i * sizeof(WORD), sizeof(e));
                const int type = e >> 12;
                const std::uint64_t rva = std::uint64_t{blk.VirtualAddress} + (e & 0xFFF);
                int width = 0;
                if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                if (type == IMAGE_REL_BASED_HIGHLOW) width = 4;
                else if (type == IMAGE_REL_BASED_DIR64) width = 8;
                else return false;
                // The part of the value inside the buffer; a value split by the buffer's edge is
                // rebuilt from what is inside only when it is whole.
                if (rva < from || rva + width > std::uint64_t{from} + n) continue;
                unsigned char* p = buf + (rva - from);
                if (width == 4) {
                    std::uint32_t v;
                    std::memcpy(&v, p, 4);
                    v += static_cast<std::uint32_t>(delta);
                    std::memcpy(p, &v, 4);
                } else {
                    std::uint64_t v;
                    std::memcpy(&v, p, 8);
                    v += delta;
                    std::memcpy(p, &v, 8);
                }
            }
        }
        off += blk.SizeOfBlock;
    }
    return true;
}

bool read_self(std::uintptr_t addr, void* out, std::size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(addr), out, n, &got) && got == n;
}

bool leads_to_allowed(std::uintptr_t target) { return target && scan::allowed_code(target); }

// A jump written at `at` (inside `mem`, the page at `page`) whose bytes end at or after `run_end`,
// leading into allowed code: an overlay's hook, or the guard's own.
bool honest_jump(const unsigned char* mem, std::uint32_t at, std::uint32_t run_end, std::uintptr_t page) {
    const unsigned char* b = mem + at;
    const std::uint32_t room = kPage - at;
#if defined(_M_ARM64)
    if (at % 4) return false;
    std::uint32_t op;
    if (room < 4) return false;
    std::memcpy(&op, b, 4);
    if ((op & 0xFC000000u) == 0x14000000u && at + 4 >= run_end) {  // B imm26
        std::int32_t imm = static_cast<std::int32_t>(op & 0x03FFFFFFu);
        if (imm & 0x02000000) imm -= 0x04000000;
        return leads_to_allowed(page + at + static_cast<std::intptr_t>(imm) * 4);
    }
    // LDR X16|X17, #8 ; BR X16|X17 ; .quad target
    if (room >= 16 && at + 16 >= run_end) {
        std::uint32_t op2;
        std::memcpy(&op2, b + 4, 4);
        const bool ldr = op == 0x58000050u || op == 0x58000051u;
        const bool br = op2 == 0xD61F0200u || op2 == 0xD61F0220u;
        if (ldr && br && (op & 0x1F) == ((op2 >> 5) & 0x1F)) {
            std::uint64_t t;
            std::memcpy(&t, b + 8, 8);
            return leads_to_allowed(static_cast<std::uintptr_t>(t));
        }
    }
    return false;
#else
    if (room >= 5 && b[0] == 0xE9 && at + 5 >= run_end) {  // jmp rel32
        std::int32_t rel;
        std::memcpy(&rel, b + 1, 4);
        return leads_to_allowed(page + at + 5 + static_cast<std::intptr_t>(rel));
    }
    if (room >= 2 && b[0] == 0xEB && at + 2 >= run_end)  // jmp rel8: stays inside the module
        return leads_to_allowed(page + at + 2 + static_cast<std::int8_t>(b[1]));
    if (room >= 6 && b[0] == 0xFF && b[1] == 0x25 && at + 6 >= run_end) {  // jmp [rip+disp32] / jmp [abs32]
        std::int32_t d;
        std::memcpy(&d, b + 2, 4);
#if defined(_M_X64)
        const std::uintptr_t slot = page + at + 6 + static_cast<std::intptr_t>(d);
#else
        const std::uintptr_t slot = static_cast<std::uint32_t>(d);
#endif
        std::uintptr_t t = 0;
        return read_self(slot, &t, sizeof(t)) && leads_to_allowed(t);
    }
    if (room >= 6 && b[0] == 0x68 && b[5] == 0xC3 && at + 6 >= run_end) {  // push imm32; ret
        std::uint32_t t;
        std::memcpy(&t, b + 1, 4);
        return leads_to_allowed(t);
    }
#if defined(_M_X64)
    if (room >= 12 && b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0 && at + 12 >= run_end) {
        std::uint64_t t;  // mov rax, imm64; jmp rax
        std::memcpy(&t, b + 2, 8);
        return leads_to_allowed(static_cast<std::uintptr_t>(t));
    }
    if (room >= 13 && b[0] == 0x49 && b[1] == 0xBB && b[10] == 0x41 && b[11] == 0xFF && b[12] == 0xE3 &&
        at + 13 >= run_end) {
        std::uint64_t t;  // mov r11, imm64; jmp r11
        std::memcpy(&t, b + 2, 8);
        return leads_to_allowed(static_cast<std::uintptr_t>(t));
    }
    if (room >= 14 && b[0] == 0x68 && b[5] == 0xC7 && b[6] == 0x44 && b[7] == 0x24 && b[8] == 0x04 && b[13] == 0xC3 &&
        at + 14 >= run_end) {
        std::uint32_t lo, hi;  // push lo32; mov dword [rsp+4], hi32; ret
        std::memcpy(&lo, b + 1, 4);
        std::memcpy(&hi, b + 9, 4);
        return leads_to_allowed(static_cast<std::uintptr_t>((std::uint64_t{hi} << 32) | lo));
    }
#endif
    return false;
#endif
}

// One run of changed bytes [s, e) of the page: honest, or not.
bool honest_run(const unsigned char* mem, std::uint32_t s, std::uint32_t e, std::uintptr_t page) {
    if (hooks::in_own_patch(page + s, page + e)) return true;
    // A pointer (an import table inside a code section, a hook's slot) into allowed code.
    const std::uint32_t slot = s & ~static_cast<std::uint32_t>(sizeof(void*) - 1);
    if (e <= slot + sizeof(void*) && slot + sizeof(void*) <= kPage) {
        std::uintptr_t v;
        std::memcpy(&v, mem + slot, sizeof(v));
        if (leads_to_allowed(v)) return true;
    }
    if (e - s > 24) return false;  // longer than any hook: code laid in, a body rewritten
    for (std::uint32_t back = 0; back <= 8 && back <= s; ++back)
        if (honest_jump(mem, s - back, e, page)) return true;
    return false;
}

struct Finding {
    std::uint32_t at = 0, len = 0;
};

// The first dishonest run of changed bytes in the page, if any.
bool foreign_change(const unsigned char* mem, const unsigned char* file, std::uintptr_t page, Finding* out) {
    std::uint32_t i = 0;
    while (i < kPage) {
        if (mem[i] == file[i]) {
            ++i;
            continue;
        }
        std::uint32_t e = i + 1;
        // Runs a few equal bytes apart are one change (a jump whose displacement keeps a byte).
        for (std::uint32_t j = e; j < kPage && j < e + 8; ++j)
            if (mem[j] != file[j]) e = j + 1;
        if (!honest_run(mem, i, e, page)) {
            out->at = i;
            out->len = e - i;
            return true;
        }
        i = e;
    }
    return false;
}

std::string hex_bytes(const unsigned char* p, std::size_t n) {
    static const char d[] = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        s += d[p[i] >> 4];
        s += d[p[i] & 15];
    }
    return s;
}

void close_patched(const modules::Record& rec, std::uint32_t rva, const Finding& f, const unsigned char* mem,
                   const unsigned char* file) {
    report::Event ev;
    ev.type = "close.image_patched";
    ev.level = report::Level::error;
    const std::wstring name = win::file_name_of(rec.path);
    ev.title = "Closed: code changed in memory inside " + to_utf8(name);
    const std::uint32_t show = f.len < 32 ? f.len : 32;
    JsonWriter w;
    w.begin_object();
    w.key("module").raw(cards::file_card_json(rec.path));
    char at[32];
    std::snprintf(at, sizeof(at), "0x%x", static_cast<unsigned>(rva + f.at));
    w.field("rva", at);
    w.field("length", static_cast<std::uint64_t>(f.len));
    w.field("memory_bytes", hex_bytes(mem + f.at, show));
    w.field("file_bytes", hex_bytes(file + f.at, show));
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.image_patched", to_utf8(lower_ascii(name))};
    guard::signal(config::Module::image_integrity, config::Reason::image_patched, name, std::move(ev));
}

// The image recorded at rec.base is still the one mapped there (not unloaded, not replaced).
bool still_mapped(const modules::Record& rec) {
    MEMORY_BASIC_INFORMATION m{};
    if (!VirtualQuery(reinterpret_cast<void*>(rec.base), &m, sizeof(m)) || m.Type != MEM_IMAGE ||
        reinterpret_cast<std::uintptr_t>(m.AllocationBase) != rec.base)
        return false;
    const std::wstring name = win::mapped_file_name(reinterpret_cast<void*>(rec.base));
    if (name.empty()) return false;
    if (!rec.kernel_name.empty()) return win::name_equals(name, rec.kernel_name);
    return win::name_equals(name, rec.path) || win::same_path(name, rec.path);
}

struct Candidate {
    std::size_t record;
    std::uint32_t rva;
};

}  // namespace

void sweep() {
    if (!config::enabled(config::Module::image_integrity)) return;
    const std::vector<modules::Record> recs = modules::all();
    auto& known = layouts();

    // Forget modules that are gone (a base reused by another image is another record).
    for (auto it = known.begin(); it != known.end();) {
        bool live = false;
        for (const auto& r : recs) live = live || (r.base == it->first && r.serial == it->second.serial);
        if (!live) {
            auto& j = judged();
            for (auto k = j.begin(); k != j.end();) k = k->first.first == it->first ? j.erase(k) : std::next(k);
            it = known.erase(it);
        } else {
            ++it;
        }
    }

    // Every executable page of every trusted module, in one query.
    std::vector<PSAPI_WORKING_SET_EX_INFORMATION> pages;
    std::vector<Candidate> where;
    for (std::size_t i = 0; i < recs.size(); ++i) {
        const modules::Record& r = recs[i];
        if (r.trust == trust::Trust::unknown || r.path.empty() || !r.size) continue;
        auto it = known.find(r.base);
        if (it == known.end() || it->second.serial != r.serial) {
            const HANDLE f = open_module_file(r);
            if (f == INVALID_HANDLE_VALUE) continue;  // tried again next sweep
            Known k;
            k.serial = r.serial;
            k.layout = read_layout(f);
            CloseHandle(f);
            it = known.insert_or_assign(r.base, std::move(k)).first;
            watchdog::worker_beat();
        }
        const Layout& l = it->second.layout;
        if (!l.usable) continue;
        for (const Section& s : l.sections) {
            if (!(s.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            const std::uint32_t end = s.va + align_up(s.vsize ? s.vsize : s.raw_size, kPage);
            for (std::uint32_t rva = s.va & ~(kPage - 1); rva < end && rva < r.size; rva += kPage) {
                PSAPI_WORKING_SET_EX_INFORMATION q{};
                q.VirtualAddress = reinterpret_cast<void*>(r.base + rva);
                pages.push_back(q);
                where.push_back({i, rva});
            }
        }
    }
    if (pages.empty()) return;
    if (!QueryWorkingSetEx(GetCurrentProcess(), pages.data(),
                           static_cast<DWORD>(pages.size() * sizeof(PSAPI_WORKING_SET_EX_INFORMATION))))
        return;
    watchdog::worker_beat();

    std::vector<unsigned char> mem(kPage), file(kPage);
    for (std::size_t p = 0; p < pages.size() && !guard::closing(); ++p) {
        const auto& a = pages[p].VirtualAttributes;
        if (!a.Valid || a.Shared) continue;  // shared with the file's other mappings: unchanged
        const modules::Record& r = recs[where[p].record];
        const std::uint32_t rva = where[p].rva;
        const std::uintptr_t page = r.base + rva;
        if (!read_self(page, mem.data(), kPage)) continue;
        const std::uint64_t h = fnv(mem.data(), kPage);
        auto& j = judged();
        const auto key = std::make_pair(r.base, rva);
        const auto seen = j.find(key);
        if (seen != j.end() && seen->second == h) continue;

        Layout& l = known[r.base].layout;
        const HANDLE f = open_module_file(r);
        if (f == INVALID_HANDLE_VALUE) continue;
        const bool built = file_view(f, l, rva, kPage, file.data()) && load_relocs(f, l) &&
                           relocate(l, r.base, rva, kPage, file.data());
        CloseHandle(f);
        watchdog::worker_beat();
        if (!built) {
            j[key] = h;  // cannot be rebuilt (an unknown relocation kind): not judged, not retried
            continue;
        }
        Finding found;
        if (!foreign_change(mem.data(), file.data(), page, &found)) {
            j[key] = h;
            continue;
        }
        // A change seen once: looked at again a moment later, on an image proven still mapped — a
        // library unloaded under the look leaves its record for a moment, and another image's bytes
        // at its base are no patch of it.
        Sleep(20);
        if (!still_mapped(r) || !read_self(page, mem.data(), kPage)) continue;
        if (!foreign_change(mem.data(), file.data(), page, &found)) continue;
        close_patched(r, rva, found, mem.data(), file.data());
        j[key] = fnv(mem.data(), kPage);  // report mode: once per change
        if (config::closes(config::Module::image_integrity)) return;
    }
}

}  // namespace mebet::integrity
