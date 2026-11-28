// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Code changed inside trusted images (ТЗ §5 «Чужой код в памяти»).
//
// The memory sweep proves that the file mapped at a module's base is the file that was judged — not
// that the code in memory is still the file's. A program from outside (an administrator's, past the
// DACL: VirtualProtectEx + WriteProcessMemory) could put a hook into jvm.dll or opengl32.dll, or its
// own code into the padding of a signed DLL, and every check passed: the image was trusted, the
// memory was an image's.
//
// An unchanged page of an image is shared with the file's other mappings; a page written to is the
// process's own copy. So the executable pages of every trusted module are asked for that
// (QueryWorkingSetEx, one call for all of them), and only the private ones are compared with the file,
// relocations applied. A difference stands as foreign unless it is what honest programs write there:
// the guard's own hooks on ntdll, a jump (an overlay's hook: Steam, OBS, RTSS) or a pointer (an import
// table inside a code section) that leads into allowed code. Anything else — code laid into a cave,
// a function body rewritten — is reported (and in the test build closes).
#pragma once

namespace mebet::integrity {

// Periodic (worker).
void sweep();

}  // namespace mebet::integrity
