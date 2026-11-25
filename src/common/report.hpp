// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Reports and guard errors (ТЗ §12). Two GlitchTip channels, both anonymous, both on by
// default and switched off separately by the launcher (-Dmebet.reports=false,
// -Dmebet.errors=false). Decisions of the guard never depend on these switches.
//
// Events are serialized as Sentry envelopes and posted by the platform transport
// (WinHTTP on Windows, libcurl loaded at runtime on Linux/macOS). Nothing is written to
// disk: without network the event is lost (ТЗ §12, no disk queue).
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace mebet::report {

enum class Channel { errors, reports };
enum class Level { info, warning, error, fatal };

using Tags = std::vector<std::pair<std::string, std::string>>;

struct Event {
    Channel channel = Channel::reports;
    Level level = Level::warning;
    std::string type;                      // "close.untrusted_module", "inventory.module", …
    std::string title;                     // human readable, shown as the GlitchTip issue title
    std::vector<std::string> fingerprint;  // grouping key (ТЗ §12 «Одна задача в GlitchTip на»)
    Tags tags;                             // event specific tags (global session tags are added)
    std::string extra_json;                // serialized JSON object, "" = none
    std::string dedupe_key;                // at most one event per key and session; "" = no dedupe
    bool inventory = false;                // counts against the inventory limit (ТЗ §12: ≤ 50)
};

struct Dsn {
    bool valid = false;
    bool https = true;
    std::string host;
    unsigned port = 443;
    std::string public_key;
    std::string project_id;
    std::string envelope_path() const { return "/api/" + project_id + "/envelope/"; }
};

Dsn parse_dsn(const char* dsn);

// Platform hooks, implemented in src/windows/agent/report/… and src/posix/agent/….
bool platform_post(const Dsn& dsn, const std::string& body, const std::string& auth_header, unsigned timeout_ms);
bool platform_random(void* out, std::size_t len);
std::uint64_t platform_unix_ms();

class Reporter {
public:
    static Reporter& instance();

    // Called once by the platform entry after the arguments are parsed.
    void configure(bool reports_enabled, bool errors_enabled);
    bool channel_enabled(Channel c) const;

    void set_tag(const std::string& key, const std::string& value);
    const std::string& session_id() const { return session_id_; }
    std::uint64_t uptime_s() const;

    // Queues the event for the background sender. Applies dedupe and the session limits.
    bool submit(Event ev);
    // Sends right away and waits at most timeout_ms (used when closing the client).
    bool send_now(Event ev, unsigned timeout_ms);
    // Waits until the queue is empty or timeout_ms passed.
    void drain(unsigned timeout_ms);

    // Serialization, public for tests.
    std::string build_event_json(const Event& ev, const std::string& event_id) const;

private:
    Reporter();
    bool admit(const Event& ev);  // dedupe + limits; caller holds the lock
    bool post(const Event& ev, unsigned timeout_ms);
    void sender_loop();

    struct Impl;
    Impl* impl_;
    std::string session_id_;
    std::uint64_t start_ms_ = 0;
};

// Convenience: guard error event on the errors channel.
void guard_error(const std::string& type, const std::string& message, const std::string& extra_json = "");

}  // namespace mebet::report
