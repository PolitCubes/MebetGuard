// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Foreign handles on the game process (ТЗ §7).
//
// The DACL keeps out a program of the player's own user. An administrator's program with
// SeDebugPrivilege opens the game past any DACL, and one that only reads or writes memory
// (ReadProcessMemory / WriteProcessMemory: an ESP, a value editor) leaves nothing in the game for
// the other layers to find — no module, no executable memory, no thread. What it cannot hide from
// user mode is the handle it holds. So the system's handle table is looked at periodically: a
// handle on this process, held by another one, that can read or write its memory or start a thread
// in it, is judged by the program holding it.
//
// Let off: the launcher that started the game (the parent, proven by its creation time), session 0
// (services: antivirus, the system's own), the kernel, and every program whose executable the trust
// engine allows (Microsoft, trusted publishers — csrss, conhost, Task Manager, an overlay's helper).
// A program in the player's session that cannot even be opened to tell what it is counts as foreign:
// that is what an elevated program that set its own DACL looks like.
//
// Where the system hides kernel object addresses from the game (Windows 11 24H2+ without
// SeDebugPrivilege) a handle is tied to this process by duplicating it from its owner instead —
// possible only for owners the game may open, so there an elevated holder stays out of sight.
#pragma once

namespace mebet::handles {

// Periodic (worker).
void sweep();

}  // namespace mebet::handles
