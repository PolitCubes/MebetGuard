// Start-up splash (ТЗ §4 «Заставка при запуске»): the Mebet logo for at least 2 s, gone
// when the game window appears. Own thread with its own message loop, so the start of the
// game never waits for it. Layered, borderless, no taskbar button, never takes focus.
// Size and animation are provisional until the mockup is chosen.
#pragma once

#include "nt.hpp"

namespace mebet::splash {

void start(HMODULE exe_module);
void game_window_shown();
void hide_now();

}  // namespace mebet::splash
