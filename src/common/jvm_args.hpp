// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Inspection of the Java command line that the launcher passed to the wrapper
// (ТЗ §4 step 9, §10 «Чужой агент при старте»). The arguments are the ones JLI itself
// produced (JLI_GetStdArgs on Windows, argv on Linux/macOS), so quoting and order are
// exactly what the JVM will see.
#pragma once

#include <string>
#include <vector>

namespace mebet::jvmargs {

enum class Kind {
    agent_path,       // -agentpath:<path>[=options]
    agent_lib,        // -agentlib:<name>[=options]
    java_agent,       // -javaagent:<jar>[=options]
    xrun,             // -Xrun<lib>[:options]
    attach_enabling,  // -XX:+EnableDynamicAgentLoading, -XX:-DisableAttachMechanism, …
    options_file,     // -XX:VMOptionsFile=, -XX:Flags= — options read from a file
    jvm_location,     // -XXaltjvm=, -Dsun.boot.library.path= — JVM libraries from elsewhere
    report_only,      // -Xbootclasspath/a:, -Djava.system.class.loader= — worth a report
};

struct Finding {
    Kind kind;
    int index;           // position in argv
    std::string arg;     // the whole argument
    std::string target;  // path / library name / jar, without "=options"
};

struct Inspection {
    std::vector<Finding> findings;
    std::string library_path;  // -Djava.library.path=
    bool reports_enabled = true;  // -Dmebet.reports=false turns the reports channel off (ТЗ §12)
    bool errors_enabled = true;   // -Dmebet.errors=false turns guard error events off
    std::string window_title;     // -Dmebet.title=
    std::string window_icon;      // -Dmebet.icon=<path to .ico>
    std::string client;           // -Dmebet.client=classic|modern
    int first_app_arg = -1;       // index of the main class / -jar file / -m module, -1 if none
};

// argv[0] is the program; everything after the main class is an application argument
// and is not inspected (the JVM does not interpret it).
Inspection inspect(const std::vector<std::string>& argv);

// Quick pre-scan of a raw command line for the two privacy switches, used before JLI has
// parsed the arguments (a failure that early still has to respect the player's choice).
void prescan_switches(const std::string& raw_command_line, bool& reports_enabled, bool& errors_enabled);

const char* kind_name(Kind k);

}  // namespace mebet::jvmargs
