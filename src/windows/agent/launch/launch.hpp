// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Start of the JVM (ТЗ §4 «Порядок запуска Java», §10) and the checks that must pass
// before it: Java location, files next to the wrapper, proxy DLLs, agent arguments.
#pragma once

#include <string>
#include <vector>

#include "jvm_args.hpp"
#include "nt.hpp"

namespace mebet::launch {

struct Jli;

struct Context {
    std::wstring java_home;
    std::wstring exe_path;
    std::wstring exe_dir;
    std::wstring agent_path;
    std::vector<std::string> argv;  // arguments as JLI parsed them (ANSI code page)
    jvmargs::Inspection args;
    std::vector<std::wstring> natives_dirs;
};

// JAVA_HOME from the launcher (LauncherGuard_lmodule sets it); closes if unusable.
void locate_java(Context& ctx);

// ТЗ §4 steps 5–8: jli.dll by full path, AddDllDirectory, exports, JLI_InitArgProcessing
// with @argfiles off, JLI_CmdToArgs(GetCommandLineA()).
void load_jli_and_parse(Context& ctx);

// ТЗ §4 step 3 / §7: nothing but the guard next to the exe; system-named DLLs next to the
// exe, in the Java folder and in natives must pass the trust rule.
void check_files(const Context& ctx);

// ТЗ §4 step 9: foreign -agentpath/-agentlib/-javaagent/-Xrun close; our own agent
// argument (from an old launcher config) is removed, ours is added by us.
void check_agent_args(Context& ctx);

// ТЗ §4 step 10: JLI_Launch. Returns the exit code of the JVM.
int run_jvm(Context& ctx);

}  // namespace mebet::launch
