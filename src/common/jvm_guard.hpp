// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// JVM protection through JVMTI (ТЗ §10, §5 «Защита JVM»). Platform-neutral; every
// platform supplies the few hooks below.
//
// - ThreadStart arrives for every new Java thread and for native threads that attach
//   with AttachCurrentThread: a thread that did not start in allowed code is an external
//   attach (injected code calling into the JVM) → close.
// - DefineClass / RegisterNatives in the JNI table are replaced and judged by the return
//   address of the nearest frame only (no stack walk); hot LWJGL slots are untouched.
// - ClassFileLoadHook keeps a light account of classes defined at runtime outside jars
//   (report only until Classic ships prebuilt mixins, ТЗ §10).
#pragma once

#include <string>

#include "config.hpp"
#include "report.hpp"

namespace mebet::jvm {

struct Platform {
    // ThreadStart / attach: is the current native thread allowed? detail = start address.
    bool (*current_thread_allowed)(std::string* detail_json) = nullptr;
    // Is this return address inside allowed code?
    bool (*code_allowed)(const void* address) = nullptr;
    // VMInit: JVM library paths and forbidden agent modules (instrument, jdwp, attach).
    void (*on_vm_init)() = nullptr;
    // VMDeath: final reports, timing summary.
    void (*on_vm_death)() = nullptr;
    // Route a detection by module level (close / report).
    void (*signal)(config::Module m, config::Reason r, const std::string& detail_utf8, report::Event ev) = nullptr;
};

void set_platform(const Platform& p);
bool started();  // Agent_OnLoad ran

}  // namespace mebet::jvm
