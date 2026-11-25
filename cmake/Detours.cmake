# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
# Microsoft Detours (MIT) at a pinned commit: x86, x64 and ARM64 with one API (ТЗ §5
# allows MinHook or Detours; MinHook has no ARM64). Only the hooking core is compiled —
# no process-creation or binary-editing helpers.
include(FetchContent)
FetchContent_Declare(detours
    GIT_REPOSITORY https://github.com/microsoft/Detours.git
    GIT_TAG 1dbd4ea281d73d478aa8d09a8b83fbd265f715f7)
FetchContent_GetProperties(detours)
if(NOT detours_POPULATED)
    FetchContent_Populate(detours)
endif()

add_library(detours STATIC
    "${detours_SOURCE_DIR}/src/detours.cpp"
    "${detours_SOURCE_DIR}/src/modules.cpp"
    "${detours_SOURCE_DIR}/src/disasm.cpp")
target_include_directories(detours PUBLIC "${detours_SOURCE_DIR}/src")
target_compile_definitions(detours PRIVATE WIN32_LEAN_AND_MEAN ${MEBET_WINNT_DEFS})
if(MSVC)
    target_compile_options(detours PRIVATE /W3 /wd4091 /wd4456 /wd4457 /wd4458 /wd4706)
endif()
