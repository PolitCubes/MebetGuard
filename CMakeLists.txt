# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
cmake_minimum_required(VERSION 3.18)

# Mebet Anticheat — native client guard of PolitCubes.
# Output per platform: the wrapper executable and the agent library (ТЗ §1: 1 exe + 1 dll).
project(MebetGuard VERSION 0.1.0 LANGUAGES C CXX)

set(MEBET_BUILD_KIND "release" CACHE STRING
    "release: every module on, the build players get; test: modules may be off (VM stand), never signed")
set_property(CACHE MEBET_BUILD_KIND PROPERTY STRINGS release test)
if(NOT MEBET_BUILD_KIND MATCHES "^(release|test)$")
    message(FATAL_ERROR "MEBET_BUILD_KIND must be release or test")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Static CRT everywhere on Windows: no vcruntime140.dll import that could be proxied, and
# the JVM's own runtime DLLs are never mixed with ours.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

find_package(Python3 REQUIRED COMPONENTS Interpreter)

# --- JNI / JVMTI headers from a JDK (not stored in the repository) -------------------------
set(MEBET_JAVA_HOME "$ENV{JAVA_HOME}" CACHE PATH "JDK whose include/ provides jni.h and jvmti.h")
find_path(MEBET_JNI_INCLUDE jni.h PATHS "${MEBET_JAVA_HOME}/include" NO_DEFAULT_PATH)
if(NOT MEBET_JNI_INCLUDE)
    message(FATAL_ERROR "jni.h not found: set JAVA_HOME or -DMEBET_JAVA_HOME to a JDK")
endif()
if(WIN32)
    set(MEBET_JNI_MD win32)
elseif(APPLE)
    set(MEBET_JNI_MD darwin)
else()
    set(MEBET_JNI_MD linux)
endif()
set(MEBET_JNI_INCLUDES "${MEBET_JNI_INCLUDE}" "${MEBET_JNI_INCLUDE}/${MEBET_JNI_MD}")

# --- Target OS / architecture for the generated tables ------------------------------------
if(WIN32)
    set(MEBET_OS windows)
    string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}${CMAKE_VS_PLATFORM_NAME}" _plat)
    if(_plat MATCHES "arm64")
        set(MEBET_ARCH arm64)
    elseif(_plat MATCHES "win32" OR CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(MEBET_ARCH x86)
    else()
        set(MEBET_ARCH x64)
    endif()
elseif(APPLE)
    set(MEBET_OS macos)
    list(LENGTH CMAKE_OSX_ARCHITECTURES _n)
    if(_n GREATER 1)
        set(MEBET_ARCH universal)
    elseif(CMAKE_OSX_ARCHITECTURES MATCHES "x86_64" OR (NOT CMAKE_OSX_ARCHITECTURES AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64"))
        set(MEBET_ARCH x64)
    else()
        set(MEBET_ARCH arm64)
    endif()
else()
    set(MEBET_OS linux)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(MEBET_ARCH arm64)
    else()
        set(MEBET_ARCH x64)
    endif()
endif()
message(STATUS "Mebet: ${MEBET_OS}/${MEBET_ARCH}, build kind ${MEBET_BUILD_KIND}")

find_package(Git QUIET)
set(MEBET_COMMIT "")
if(GIT_FOUND)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE MEBET_COMMIT
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()

# --- Config → C++ tables (ТЗ §3: lists and levels are baked into the build) ---------------
set(MEBET_GEN "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${MEBET_GEN}")
file(GLOB MEBET_CONFIG_INPUTS CONFIGURE_DEPENDS
     "${CMAKE_SOURCE_DIR}/config/*.json" "${CMAKE_SOURCE_DIR}/config/roots/*.pem" "${CMAKE_SOURCE_DIR}/config/hashes/*.txt")
add_custom_command(
    OUTPUT "${MEBET_GEN}/mebet_config.hpp" "${MEBET_GEN}/mebet_trust_data.hpp"
    COMMAND Python3::Interpreter "${CMAKE_SOURCE_DIR}/tools/gen_config.py"
            --config "${CMAKE_SOURCE_DIR}/config" --out "${MEBET_GEN}" --kind ${MEBET_BUILD_KIND}
            --os ${MEBET_OS} --arch ${MEBET_ARCH} --version ${PROJECT_VERSION} --commit "${MEBET_COMMIT}"
    DEPENDS ${MEBET_CONFIG_INPUTS} "${CMAKE_SOURCE_DIR}/tools/gen_config.py"
    COMMENT "Generating guard tables from config/"
    VERBATIM)
add_custom_target(mebet_config DEPENDS "${MEBET_GEN}/mebet_config.hpp" "${MEBET_GEN}/mebet_trust_data.hpp")
configure_file("${CMAKE_SOURCE_DIR}/cmake/mebet_version.h.in" "${MEBET_GEN}/mebet_version.h" @ONLY)

# --- Shared, platform-neutral code --------------------------------------------------------
add_library(mebet_common STATIC
    src/common/sha256.cpp
    src/common/strings.cpp
    src/common/json_writer.cpp
    src/common/jvm_args.cpp
    src/common/report.cpp)
target_include_directories(mebet_common PUBLIC src/common "${MEBET_GEN}")
add_dependencies(mebet_common mebet_config)
set_target_properties(mebet_common PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(WIN32)
    add_subdirectory(src/windows)
else()
    add_subdirectory(src/posix)
endif()
