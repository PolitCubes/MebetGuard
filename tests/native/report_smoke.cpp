// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// GlitchTip delivery smoke (.github/workflows/glitchtip.yml): the guard's own reporting code —
// report.cpp (envelope, X-Sentry-Auth, the 64 KB limit) and the platform transport (WinHTTP /
// libcurl) — sends marked events to the DSNs baked into this build and fails unless GlitchTip
// answers 2xx for every one. Built only with -DMEBET_REPORT_SMOKE=ON, never shipped.
//
//   mebet_report_smoke <marker>     marker: [A-Za-z0-9._-]{1,64}, e.g. ci-<run id>-<attempt>
//
// Per channel: one small event and one close to the event size limit (extra ≈ 60 KB), so a
// server-side size cap below the guard's own one shows up here and not as reports lost in play.
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>

#include "json_writer.hpp"
#include "report.hpp"

#if defined(_WIN32)
#include "core/win_util.hpp"

// transport_winhttp.cpp asks for the OS version; the rest of win_util.cpp (watchdog and all)
// is not needed here.
namespace mebet::win {
const OsVersion& os_version() {
    static const OsVersion v = [] {
        OsVersion r;
        RTL_OSVERSIONINFOW info{};
        info.dwOSVersionInfoSize = sizeof(info);
        if (nt::api().RtlGetVersion && nt::ok(nt::api().RtlGetVersion(&info))) {
            r.major = info.dwMajorVersion;
            r.minor = info.dwMinorVersion;
            r.build = info.dwBuildNumber;
        }
        return r;
    }();
    return v;
}
}  // namespace mebet::win
#endif

using namespace mebet::report;

namespace {

bool marker_ok(const char* m) {
    const std::size_t n = std::strlen(m);
    if (n == 0 || n > 64) return false;
    for (std::size_t i = 0; i < n; ++i) {
        const char c = m[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == '-'))
            return false;
    }
    return true;
}

Event make(Channel ch, const std::string& marker, bool large) {
    Event ev;
    ev.channel = ch;
    ev.level = Level::info;
    ev.type = large ? "smoke.large" : "smoke.small";
    ev.title = std::string("CI smoke ") + (large ? "large " : "") + marker;
    ev.fingerprint = {"ci_smoke", ev.type};  // one issue per kind, however many runs
    ev.tags = {{"smoke", marker}};
    mebet::JsonWriter w;
    w.begin_object();
    w.field("marker", marker);
    if (large) {
        // ≈ 60 KB of payload: under kLimit_event_bytes (64 KB) with the tags and the envelope.
        w.key("filler").begin_array();
        for (int i = 0; i < 50; ++i) w.value(std::string(1200, static_cast<char>('a' + i % 26)));
        w.end_array();
    }
    w.end_object();
    ev.extra_json = w.take();
    return ev;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 || !marker_ok(argv[1])) {
        std::fprintf(stderr, "usage: mebet_report_smoke <marker [A-Za-z0-9._-]{1,64}>\n");
        return 2;
    }
    const std::string marker = argv[1];
    Reporter& r = Reporter::instance();
    r.configure(true, true);
    r.set_tag("client", "ci-smoke");
    int failed = 0;
    const struct {
        Channel ch;
        const char* name;
    } channels[] = {{Channel::errors, "errors"}, {Channel::reports, "reports"}};
    for (const auto& c : channels) {
        if (!r.channel_enabled(c.ch)) {
            std::printf("%s: no DSN in this build\n", c.name);
            ++failed;
            continue;
        }
        for (bool large : {false, true}) {
            const Event ev = make(c.ch, marker, large);
            const std::size_t bytes = r.build_event_json(ev, std::string(32, '0')).size();
            const bool ok = r.send_now(ev, 20000);
            std::printf("%s %s (%zu bytes): %s\n", c.name, ev.type.c_str(), bytes,
                        ok ? "accepted (2xx)" : "NOT accepted");
            if (!ok) ++failed;
        }
    }
    return failed ? 1 : 0;
}
