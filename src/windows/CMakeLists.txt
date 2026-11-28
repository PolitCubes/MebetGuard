# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
# Windows: MebetGuard.exe (wrapper) + MebetGuard.dll (agent) for x64, x86 and ARM64.

if(MEBET_ARCH STREQUAL "arm64")
    set(MEBET_WINNT_DEFS _WIN32_WINNT=0x0A00 WINVER=0x0A00)  # Windows on ARM starts at 10
else()
    set(MEBET_WINNT_DEFS _WIN32_WINNT=0x0601 WINVER=0x0601)  # Windows 7 (ТЗ §2 pillar 3)
endif()
set(MEBET_WINNT_DEFS ${MEBET_WINNT_DEFS} PARENT_SCOPE)

include("${CMAKE_SOURCE_DIR}/cmake/Detours.cmake")

set(MEBET_WIN_DEFS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE ${MEBET_WINNT_DEFS})
set(MEBET_WIN_CFLAGS /utf-8 /permissive- /W4 /wd4100 /wd4201 /wd4505 /Zi /Gy /guard:cf /EHsc)
set(MEBET_WIN_LFLAGS /DEBUG /OPT:REF /OPT:ICF /guard:cf /DYNAMICBASE /NXCOMPAT)
if(MEBET_ARCH STREQUAL "x64" OR MEBET_ARCH STREQUAL "x86")
    list(APPEND MEBET_WIN_LFLAGS /CETCOMPAT:NO)  # the JVM rewrites its own stacks
endif()
target_compile_options(mebet_common PRIVATE /utf-8 /permissive- /W4 /wd4100)
target_compile_definitions(mebet_common PUBLIC ${MEBET_WIN_DEFS})

# --- Code shared by the wrapper and the agent ----------------------------------------------
add_library(mebet_win_shared STATIC shared/nt.cpp shared/pe_hash.cpp shared/hardening.cpp)
target_include_directories(mebet_win_shared PUBLIC shared)
target_link_libraries(mebet_win_shared PUBLIC mebet_common)
target_compile_options(mebet_win_shared PRIVATE ${MEBET_WIN_CFLAGS})

# --- Agent DLL --------------------------------------------------------------------------------
add_library(mebet_agent SHARED
    agent/entry.cpp
    agent/agent.rc
    agent/core/private_heap.cpp
    agent/core/module_table.cpp
    agent/core/exec_table.cpp
    agent/core/timing.cpp
    agent/core/win_util.cpp
    agent/core/guard.cpp
    agent/core/watchdog.cpp
    agent/trust/file_identity.cpp
    agent/trust/signatures.cpp
    agent/trust/engine.cpp
    agent/hooks/nt_hooks.cpp
    agent/hooks/load_gate.cpp
    agent/hooks/exec_guard.cpp
    agent/hooks/hook_check.cpp
    agent/scan/scans.cpp
    agent/process/dacl.cpp
    agent/system/environment.cpp
    agent/launch/launch.cpp
    agent/window/splash.cpp
    agent/window/reason_window.cpp
    agent/window/game_window.cpp
    agent/report/cards.cpp
    agent/report/session_tags.cpp
    agent/report/transport_winhttp.cpp
    "${CMAKE_SOURCE_DIR}/src/common/jvm_guard.cpp")
set_target_properties(mebet_agent PROPERTIES
    OUTPUT_NAME MebetGuard
    PDB_NAME MebetGuard.dll
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/agent")
target_include_directories(mebet_agent PRIVATE agent ${MEBET_JNI_INCLUDES})
target_compile_options(mebet_agent PRIVATE ${MEBET_WIN_CFLAGS})
# /MANIFEST:NO: the linker's default DLL manifest (resource #2, only trustInfo, which means nothing
# for a DLL) makes the loader build an activation context, and that fails with error 206 once the
# DLL path is 252 characters long: a guard folder of ~237 characters, the exe itself still
# startable, closed as agent_integrity (201).
target_link_options(mebet_agent PRIVATE ${MEBET_WIN_LFLAGS} /MANIFEST:NO)
target_link_libraries(mebet_agent PRIVATE mebet_win_shared mebet_common detours
    wintrust crypt32 winhttp version psapi advapi32 user32 gdi32)

# The wrapper embeds the hash of exactly this agent (ТЗ §4 step 4: the exe is built after the dll).
add_custom_command(
    OUTPUT "${MEBET_GEN}/agent_hash.hpp"
    COMMAND Python3::Interpreter "${CMAKE_SOURCE_DIR}/tools/agent_hash.py" --mode pe
            --file "$<TARGET_FILE:mebet_agent>" --name MebetGuard.dll --out "${MEBET_GEN}/agent_hash.hpp"
    DEPENDS mebet_agent "${CMAKE_SOURCE_DIR}/tools/agent_hash.py"
    COMMENT "Embedding the agent hash into the wrapper"
    VERBATIM)

# Splash bitmaps: PNG rendered from logo.svg → premultiplied BGRA resources.
set(MEBET_SPLASH_BINS "")
foreach(scale 100 150 200)
    add_custom_command(
        OUTPUT "${MEBET_GEN}/splash_${scale}.bin"
        COMMAND Python3::Interpreter "${CMAKE_SOURCE_DIR}/tools/png_to_bgra.py"
                "${CMAKE_SOURCE_DIR}/assets/splash/logo@${scale}.png" ${scale} "${MEBET_GEN}/splash_${scale}.bin"
        DEPENDS "${CMAKE_SOURCE_DIR}/assets/splash/logo@${scale}.png" "${CMAKE_SOURCE_DIR}/tools/png_to_bgra.py"
        VERBATIM)
    list(APPEND MEBET_SPLASH_BINS "${MEBET_GEN}/splash_${scale}.bin")
endforeach()
add_custom_target(mebet_exe_inputs DEPENDS "${MEBET_GEN}/agent_hash.hpp" ${MEBET_SPLASH_BINS})

# --- Wrapper EXE ------------------------------------------------------------------------------
add_executable(mebet_exe WIN32 exe/main.cpp exe/exe.rc exe/app.manifest)
add_dependencies(mebet_exe mebet_exe_inputs)
set_target_properties(mebet_exe PROPERTIES
    OUTPUT_NAME MebetGuard
    PDB_NAME MebetGuard.exe
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/exe")
target_include_directories(mebet_exe PRIVATE "${MEBET_GEN}" "${CMAKE_SOURCE_DIR}/assets")
target_compile_options(mebet_exe PRIVATE ${MEBET_WIN_CFLAGS})
# Imports: KnownDLLs only (kernel32); user32 waits until after step 1. Dependencies of the
# exe come from System32 only on Windows 10 1607+ (ТЗ §4 «PE, манифест, ресурсы»).
target_link_options(mebet_exe PRIVATE ${MEBET_WIN_LFLAGS} /DELAYLOAD:user32.dll /DEPENDENTLOADFLAG:0x800)
target_link_libraries(mebet_exe PRIVATE mebet_win_shared mebet_common delayimp user32)

if(MEBET_REPORT_SMOKE)
    add_executable(mebet_report_smoke "${CMAKE_SOURCE_DIR}/tests/native/report_smoke.cpp"
                   agent/report/transport_winhttp.cpp)
    target_include_directories(mebet_report_smoke PRIVATE agent)
    target_compile_options(mebet_report_smoke PRIVATE ${MEBET_WIN_CFLAGS})
    target_link_libraries(mebet_report_smoke PRIVATE mebet_win_shared mebet_common winhttp advapi32)
endif()
