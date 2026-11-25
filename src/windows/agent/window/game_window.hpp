// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// The game window (ТЗ §4 «Заголовок и значок окна», §9 «Источник ввода»).
//
// The window is found by EVENT_OBJECT_CREATE (class GLFW30 for Classic, SDL_app for
// Modern) and its window procedure is replaced with SetWindowLongPtrW — no inline hook on
// CreateWindowExW. The new procedure replaces WM_SETTEXT / WM_SETICON with the server's
// title and icon and drops input that Windows marks as injected; everything else goes to
// the original procedure.
#pragma once

#include <cstdint>
#include <string>

namespace mebet::game_window {

void configure(const std::wstring& title, const std::wstring& icon_path, void* exe_module);
void install_in_worker();  // SetWinEventHook needs the message loop of the worker

struct InputCounters {
    std::uint64_t hardware = 0;
    std::uint64_t injected_clicks = 0, injected_keys = 0, injected_moves = 0, injected_raw = 0;
    std::uint64_t posted = 0;  // input messages without a source: PostMessage clickers
    std::uint64_t peak_injected_per_s = 0;
};
InputCounters counters();
bool input_source_supported();  // Windows 8+

// "Отчёт: инжектированный ввод" — every 30 minutes and at exit (ТЗ §12).
void report_input(bool final_report);

}  // namespace mebet::game_window
