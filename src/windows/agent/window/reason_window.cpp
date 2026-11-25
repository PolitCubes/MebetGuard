// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "window/reason_window.hpp"

#include "nt.hpp"

namespace mebet::reason_window {

void show(const std::wstring& title, const std::wstring& text) {
    // Standard message box until the mockup of the custom window is chosen.
    MessageBoxW(nullptr, text.c_str(), title.c_str(), MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND | MB_TASKMODAL);
}

}  // namespace mebet::reason_window
