// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Small string helpers shared by every platform. Kept dependency-free on purpose.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace mebet {

// Publisher name folding used for CN / O matching (ТЗ §6 «Правила сверки подписей»):
// ASCII letters are lowered, ASCII digits kept, any other ASCII (spaces, punctuation)
// dropped, non-ASCII kept as is. Must stay identical to norm_name() in tools/gen_config.py.
std::string normalize_name(std::string_view utf8);

std::string to_utf8(std::wstring_view w);
std::wstring from_utf8(std::string_view s);

char ascii_lower(char c);
wchar_t ascii_lower(wchar_t c);
std::string lower_ascii(std::string_view s);
std::wstring lower_ascii(std::wstring_view s);
bool iequals_ascii(std::string_view a, std::string_view b);
bool iequals_ascii(std::wstring_view a, std::wstring_view b);
bool istarts_with(std::wstring_view s, std::wstring_view prefix);
bool istarts_with(std::string_view s, std::string_view prefix);
bool iends_with(std::wstring_view s, std::wstring_view suffix);

std::string hex(const void* data, std::size_t len, bool upper = false);

// Cuts a UTF-8 string to at most max_chars code points (ТЗ §12: strings ≤ 512 chars).
std::string truncate_utf8(std::string_view s, std::size_t max_chars);

// Replaces malformed UTF-8 with U+FFFD so that report JSON is always valid.
std::string sanitize_utf8(std::string_view s);

// Compares dotted versions ("8.8.7" vs "8.10.0"); missing parts count as 0.
int compare_versions(std::string_view a, std::string_view b);

}  // namespace mebet
