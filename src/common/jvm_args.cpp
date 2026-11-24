#include "jvm_args.hpp"

#include <cstring>
#include <string_view>

#include "strings.hpp"

namespace mebet::jvmargs {

namespace {

bool starts(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.compare(0, p.size(), p) == 0; }

// Options that take their value as the next argument (JDK java.c IsWhiteSpaceOption).
bool takes_separate_value(std::string_view a) {
    static const char* const kOpts[] = {
        "-cp", "-classpath", "--class-path", "-p", "--module-path", "--upgrade-module-path",
        "--add-modules", "--enable-native-access", "--limit-modules", "--add-exports", "--add-opens",
        "--add-reads", "--patch-module", "--describe-module", "-d", "--source",
    };
    for (const char* o : kOpts)
        if (a == o) return true;
    return false;
}

// Options after which the next argument starts the application (-jar file, -m module).
bool ends_options(std::string_view a) { return a == "-jar" || a == "-m" || a == "--module"; }

std::string strip_options(std::string_view v, char sep) {
    const auto pos = v.find(sep);
    return std::string(pos == std::string_view::npos ? v : v.substr(0, pos));
}

bool is_false(std::string_view v) { return iequals_ascii(v, "false") || v == "0" || iequals_ascii(v, "off"); }

}  // namespace

const char* kind_name(Kind k) {
    switch (k) {
        case Kind::agent_path: return "agentpath";
        case Kind::agent_lib: return "agentlib";
        case Kind::java_agent: return "javaagent";
        case Kind::xrun: return "xrun";
        case Kind::attach_enabling: return "attach_enabling";
        case Kind::options_file: return "options_file";
        case Kind::jvm_location: return "jvm_location";
        case Kind::report_only: return "report_only";
    }
    return "unknown";
}

Inspection inspect(const std::vector<std::string>& argv) {
    Inspection r;
    for (int i = 1; i < static_cast<int>(argv.size()); ++i) {
        const std::string_view a = argv[i];
        auto add = [&](Kind k, std::string target) { r.findings.push_back({k, i, std::string(a), std::move(target)}); };

        if (a.empty()) continue;
        if (a[0] != '-') {  // main class
            r.first_app_arg = i;
            break;
        }
        if (ends_options(a)) {
            r.first_app_arg = i + 1 < static_cast<int>(argv.size()) ? i + 1 : -1;
            break;
        }
        if (takes_separate_value(a)) {
            ++i;  // skip the value
            continue;
        }
        if (starts(a, "--module=")) {
            r.first_app_arg = i;
            break;
        }

        if (starts(a, "-agentpath:")) {
            add(Kind::agent_path, strip_options(a.substr(11), '='));
        } else if (starts(a, "-agentlib:")) {
            add(Kind::agent_lib, strip_options(a.substr(10), '='));
        } else if (starts(a, "-javaagent:")) {
            add(Kind::java_agent, strip_options(a.substr(11), '='));
        } else if (starts(a, "-Xrun")) {
            add(Kind::xrun, strip_options(a.substr(5), ':'));
        } else if (a == "-XX:+EnableDynamicAgentLoading" || a == "-XX:+StartAttachListener" ||
                   a == "-XX:-DisableAttachMechanism" || starts(a, "-Djdk.attach.allowAttachSelf=")) {
            if (!(starts(a, "-Djdk.attach.allowAttachSelf=") && is_false(a.substr(29)))) add(Kind::attach_enabling, "");
        } else if (starts(a, "-XX:VMOptionsFile=") || starts(a, "-XX:Flags=")) {
            add(Kind::options_file, std::string(a.substr(a.find('=') + 1)));
        } else if (starts(a, "-XXaltjvm=") || starts(a, "-J-XXaltjvm=") || starts(a, "-Dsun.boot.library.path=")) {
            add(Kind::jvm_location, std::string(a.substr(a.find('=') + 1)));
        } else if (starts(a, "-Xbootclasspath/a:") || starts(a, "-Xbootclasspath/p:")) {
            add(Kind::report_only, std::string(a.substr(18)));
        } else if (starts(a, "-Djava.system.class.loader=")) {
            add(Kind::report_only, std::string(a.substr(27)));
        } else if (starts(a, "-Djava.library.path=")) {
            r.library_path = std::string(a.substr(20));
        } else if (starts(a, "-Dmebet.reports=")) {
            r.reports_enabled = !is_false(a.substr(16));
        } else if (starts(a, "-Dmebet.errors=")) {
            r.errors_enabled = !is_false(a.substr(15));
        } else if (starts(a, "-Dmebet.title=")) {
            r.window_title = std::string(a.substr(14));
        } else if (starts(a, "-Dmebet.icon=")) {
            r.window_icon = std::string(a.substr(13));
        } else if (starts(a, "-Dmebet.client=")) {
            r.client = lower_ascii(a.substr(15));
        }
    }
    return r;
}

void prescan_switches(const std::string& raw, bool& reports_enabled, bool& errors_enabled) {
    // Conservative: any mention of the switch with a false value disables the channel.
    auto off = [&](const char* key) {
        std::size_t pos = 0;
        const std::size_t klen = std::strlen(key);
        while ((pos = raw.find(key, pos)) != std::string::npos) {
            pos += klen;
            std::size_t end = pos;
            while (end < raw.size() && raw[end] != ' ' && raw[end] != '"' && raw[end] != '\t') ++end;
            if (is_false(std::string_view(raw).substr(pos, end - pos))) return true;
        }
        return false;
    };
    if (off("-Dmebet.reports=")) reports_enabled = false;
    if (off("-Dmebet.errors=")) errors_enabled = false;
}

}  // namespace mebet::jvmargs
