// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Report payloads (ТЗ §12 «Карточка файла», «События», «Обезличивание»). Everything here
// is anonymous: user folders become %USERPROFILE% etc., no names, no machine ids, file
// contents only as hashes, memory only from foreign executable regions and ≤ 256 bytes.
#pragma once

#include <cstdint>
#include <string>

#include "trust/engine.hpp"

namespace mebet::cards {

// C:\Users\<name>\… → %USERPROFILE%\…, likewise %APPDATA%, %LOCALAPPDATA%, %TEMP%,
// %ProgramFiles%, %WINDIR%; the game folder → %GAME%, Java → %JAVA%.
std::string anonymize(const std::wstring& path);
void set_game_dir(const std::wstring& dir);

// System32 / Program Files / game folder / Java / AppData / Temp / other.
const char* dir_class(const std::wstring& path);

// The full card of a decided file.
std::string file_card_json(const trust::Decision& d);
std::string file_card_json(const std::wstring& path);  // decides first (cached)
// "xyz.dll (signer O)" / "xyz.dll (unsigned)" for event titles.
std::string file_label(const trust::Decision& d);

std::string address_hex(std::uintptr_t a);
// Which module or region an address belongs to: {"address", "module" | "region"}.
std::string address_json(std::uintptr_t a);
// Grouping key for GlitchTip: the module file name, or the SHA-256 of the region.
std::string address_owner_key(std::uintptr_t a);
// A foreign executable region: address, size, type, protection, SHA-256 (≤ 16 MB),
// the first 256 bytes, and the export name / TimeDateStamp / SizeOfImage of a PE header.
std::string region_json(std::uintptr_t addr, std::string* group_key);

}  // namespace mebet::cards
