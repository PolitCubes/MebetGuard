// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Environment variables the wrapper clears before anything else (ТЗ §4 step 1).
#pragma once

namespace mebet {

// Java: each of these can smuggle -agentpath / -javaagent into the JVM. JAVA_TOOL_OPTIONS
// is read by the JVM itself, JDK_JAVA_OPTIONS by the Java launcher (and by JLI inside the
// wrapper); the rest are read by scripts and tools. CLASSPATH would add jars.
inline constexpr const char* kJavaEnvVars[] = {
    "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTIONS", "JAVA_OPTS", "_JAVA_OPTS", "CLASSPATH",
};

// Vulkan loader: variables that add layers or drivers (Windows only, ТЗ §4 and §6).
inline constexpr const char* kVulkanEnvVars[] = {
    "VK_INSTANCE_LAYERS",  "VK_LAYER_PATH",       "VK_ADD_LAYER_PATH",   "VK_IMPLICIT_LAYER_PATH",
    "VK_ADD_IMPLICIT_LAYER_PATH", "VK_ICD_FILENAMES", "VK_DRIVER_FILES", "VK_ADD_DRIVER_FILES",
    "VK_LOADER_LAYERS_ENABLE", "VK_LOADER_LAYERS_DISABLE", "VK_LOADER_LAYERS_ALLOW",
};

// Third-party implicit layers are switched off for the game; GPU switching layers and the
// OBS capture layer stay allowed (ТЗ §6 «Рендер», §7 «Оверлеи»). Loaders older than
// 1.3.234 ignore these filters, which is why the profile pins its own vulkan-1.dll.
inline constexpr const char* kVulkanLayersDisable = "~implicit~";
inline constexpr const char* kVulkanLayersAllow =
    "VK_LAYER_NV_optimus,VK_LAYER_AMD_switchable_graphics_64,VK_LAYER_AMD_switchable_graphics_32,"
    "VK_LAYER_OBS_hook,VK_LAYER_OBS_HOOK";

// NVIDIA Optimus hint copied literally from Sodium 0.5.x (ТЗ §4).
inline constexpr const char* kShimMcCompatName = "SHIM_MCCOMPAT";
inline constexpr const char* kShimMcCompatValue = "0x800000001";

}  // namespace mebet
