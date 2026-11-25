// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "strings.hpp"

#include <cstdint>

namespace mebet {

namespace {

// Decodes one code point from UTF-8; returns 0xFFFD on malformed input.
char32_t next_utf8(std::string_view s, std::size_t& i) {
    const unsigned char c = static_cast<unsigned char>(s[i++]);
    if (c < 0x80) return c;
    int extra = 0;
    char32_t cp = 0;
    if ((c & 0xE0) == 0xC0) {
        extra = 1;
        cp = c & 0x1F;
    } else if ((c & 0xF0) == 0xE0) {
        extra = 2;
        cp = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
        extra = 3;
        cp = c & 0x07;
    } else {
        return 0xFFFD;
    }
    for (int k = 0; k < extra; ++k) {
        if (i >= s.size()) return 0xFFFD;
        const unsigned char cc = static_cast<unsigned char>(s[i]);
        if ((cc & 0xC0) != 0x80) return 0xFFFD;
        cp = (cp << 6) | (cc & 0x3F);
        ++i;
    }
    return cp;
}

void put_utf8(std::string& out, char32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

}  // namespace

std::string normalize_name(std::string_view utf8) {
    std::string out;
    out.reserve(utf8.size());
    for (unsigned char c : utf8) {
        if (c >= 0x80) {
            out.push_back(static_cast<char>(c));  // non-ASCII bytes kept verbatim
        } else if (c >= 'A' && c <= 'Z') {
            out.push_back(static_cast<char>(c - 'A' + 'a'));
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

std::string to_utf8(std::wstring_view w) {
    std::string out;
    out.reserve(w.size());
    for (std::size_t i = 0; i < w.size(); ++i) {
        char32_t cp = static_cast<char32_t>(w[i]);
        if constexpr (sizeof(wchar_t) == 2) {
            cp &= 0xFFFF;
            if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < w.size()) {
                const char32_t lo = static_cast<char32_t>(w[i + 1]) & 0xFFFF;
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    ++i;
                }
            }
            if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;
        }
        put_utf8(out, cp);
    }
    return out;
}

std::wstring from_utf8(std::string_view s) {
    std::wstring out;
    out.reserve(s.size());
    std::size_t i = 0;
    while (i < s.size()) {
        const char32_t cp = next_utf8(s, i);
        if (sizeof(wchar_t) == 2 && cp >= 0x10000) {  // NOLINT: UTF-16 surrogates on Windows only
            const char32_t v = cp - 0x10000;
            out.push_back(static_cast<wchar_t>(0xD800 + (v >> 10)));
            out.push_back(static_cast<wchar_t>(0xDC00 + (v & 0x3FF)));
        } else {
            out.push_back(static_cast<wchar_t>(cp));
        }
    }
    return out;
}

char ascii_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }
wchar_t ascii_lower(wchar_t c) { return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c; }

std::string lower_ascii(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = ascii_lower(c);
    return out;
}

std::wstring lower_ascii(std::wstring_view s) {
    std::wstring out(s);
    for (auto& c : out) c = ascii_lower(c);
    return out;
}

bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    return true;
}

bool iequals_ascii(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    return true;
}

bool istarts_with(std::wstring_view s, std::wstring_view prefix) {
    return s.size() >= prefix.size() && iequals_ascii(s.substr(0, prefix.size()), prefix);
}

bool istarts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && iequals_ascii(s.substr(0, prefix.size()), prefix);
}

bool iends_with(std::wstring_view s, std::wstring_view suffix) {
    return s.size() >= suffix.size() && iequals_ascii(s.substr(s.size() - suffix.size()), suffix);
}

std::string hex(const void* data, std::size_t len, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    const unsigned char* p = static_cast<const unsigned char*>(data);
    std::string s(len * 2, '0');
    for (std::size_t i = 0; i < len; ++i) {
        s[2 * i] = digits[p[i] >> 4];
        s[2 * i + 1] = digits[p[i] & 15];
    }
    return s;
}

std::string truncate_utf8(std::string_view s, std::size_t max_chars) {
    std::size_t i = 0, chars = 0;
    while (i < s.size() && chars < max_chars) {
        next_utf8(s, i);
        ++chars;
    }
    return std::string(s.substr(0, i));
}

std::string sanitize_utf8(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    std::size_t i = 0;
    while (i < s.size()) put_utf8(out, next_utf8(s, i));
    return out;
}

int compare_versions(std::string_view a, std::string_view b) {
    std::size_t i = 0, j = 0;
    while (i < a.size() || j < b.size()) {
        std::uint64_t x = 0, y = 0;
        while (i < a.size() && a[i] >= '0' && a[i] <= '9') x = x * 10 + static_cast<unsigned>(a[i++] - '0');
        while (j < b.size() && b[j] >= '0' && b[j] <= '9') y = y * 10 + static_cast<unsigned>(b[j++] - '0');
        if (x != y) return x < y ? -1 : 1;
        while (i < a.size() && (a[i] < '0' || a[i] > '9')) ++i;
        while (j < b.size() && (b[j] < '0' || b[j] > '9')) ++j;
    }
    return 0;
}

}  // namespace mebet
