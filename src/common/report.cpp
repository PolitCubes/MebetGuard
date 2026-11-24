#include "report.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "json_writer.hpp"
#include "mebet_config.hpp"
#include "strings.hpp"

namespace mebet::report {

namespace {

const char* level_name(Level l) {
    switch (l) {
        case Level::info: return "info";
        case Level::warning: return "warning";
        case Level::error: return "error";
        case Level::fatal: return "fatal";
    }
    return "error";
}

std::string random_hex(std::size_t bytes) {
    unsigned char buf[32] = {};
    if (bytes > sizeof(buf)) bytes = sizeof(buf);
    if (!platform_random(buf, bytes)) {
        // Fall back to the clock; uniqueness is all we need for event ids.
        const std::uint64_t t = platform_unix_ms() ^ reinterpret_cast<std::uintptr_t>(&bytes);
        for (std::size_t i = 0; i < bytes; ++i) buf[i] = static_cast<unsigned char>(t >> ((i % 8) * 8)) ^ static_cast<unsigned char>(i * 31);
    }
    return hex(buf, bytes);
}

std::string iso8601(std::uint64_t unix_ms) {
    // Civil-from-days (Howard Hinnant), UTC.
    std::int64_t secs = static_cast<std::int64_t>(unix_ms / 1000);
    std::int64_t days = secs / 86400;
    std::int64_t rem = secs % 86400;
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(days - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) ++y;
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02u:%02u:%02uZ", static_cast<long long>(y), m, d,
                  static_cast<unsigned>(rem / 3600), static_cast<unsigned>((rem / 60) % 60),
                  static_cast<unsigned>(rem % 60));
    return buf;
}

}  // namespace

Dsn parse_dsn(const char* dsn) {
    Dsn d;
    if (!dsn || !*dsn) return d;
    std::string s(dsn);
    std::size_t p = 0;
    if (s.compare(0, 8, "https://") == 0) {
        p = 8;
    } else if (s.compare(0, 7, "http://") == 0) {
        p = 7;
        d.https = false;
        d.port = 80;
    } else {
        return d;
    }
    const std::size_t at = s.find('@', p);
    const std::size_t slash = s.find('/', at == std::string::npos ? p : at);
    if (at == std::string::npos || slash == std::string::npos) return d;
    d.public_key = s.substr(p, at - p);
    std::string hostport = s.substr(at + 1, slash - at - 1);
    const std::size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        d.port = static_cast<unsigned>(std::strtoul(hostport.c_str() + colon + 1, nullptr, 10));
        hostport.resize(colon);
    }
    d.host = hostport;
    d.project_id = s.substr(slash + 1);
    while (!d.project_id.empty() && d.project_id.back() == '/') d.project_id.pop_back();
    d.valid = !d.public_key.empty() && !d.host.empty() && !d.project_id.empty() && d.port != 0;
    return d;
}

struct Reporter::Impl {
    std::mutex mu;
    std::condition_variable cv;
    std::condition_variable idle_cv;
    std::deque<Event> queue;
    std::set<std::string> dedupe;
    Tags tags;
    unsigned events = 0;
    unsigned inventory = 0;
    bool reports_enabled = true;
    bool errors_enabled = true;
    bool sender_started = false;
    bool sending = false;
    Dsn errors_dsn;
    Dsn reports_dsn;
};

Reporter& Reporter::instance() {
    // Leaked on purpose: hooks and late threads may report while the process is exiting.
    static Reporter* r = new Reporter();
    return *r;
}

Reporter::Reporter() : impl_(new Impl()) {
    session_id_ = random_hex(16);
    start_ms_ = platform_unix_ms();
    impl_->errors_dsn = parse_dsn(config::kErrorsDsn);
    impl_->reports_dsn = parse_dsn(config::kReportsDsn);
}

void Reporter::configure(bool reports_enabled, bool errors_enabled) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->reports_enabled = reports_enabled;
    impl_->errors_enabled = errors_enabled;
}

bool Reporter::channel_enabled(Channel c) const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (c == Channel::errors) return impl_->errors_enabled && impl_->errors_dsn.valid;
    return impl_->reports_enabled && impl_->reports_dsn.valid;
}

void Reporter::set_tag(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    for (auto& kv : impl_->tags) {
        if (kv.first == key) {
            kv.second = truncate_utf8(value, 200);
            return;
        }
    }
    impl_->tags.emplace_back(key, truncate_utf8(value, 200));
}

std::uint64_t Reporter::uptime_s() const { return (platform_unix_ms() - start_ms_) / 1000; }

bool Reporter::admit(const Event& ev) {
    const bool enabled = ev.channel == Channel::errors ? (impl_->errors_enabled && impl_->errors_dsn.valid)
                                                       : (impl_->reports_enabled && impl_->reports_dsn.valid);
    if (!enabled) return false;
    if (!ev.dedupe_key.empty()) {
        if (!impl_->dedupe.insert(ev.dedupe_key).second) return false;
    }
    if (impl_->events >= config::kLimit_events_per_session) return false;
    if (ev.inventory && impl_->inventory >= config::kLimit_inventory_per_session) return false;
    ++impl_->events;
    if (ev.inventory) ++impl_->inventory;
    return true;
}

std::string Reporter::build_event_json(const Event& ev, const std::string& event_id) const {
    Tags tags;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        tags = impl_->tags;
    }
    JsonWriter w;
    w.begin_object();
    w.field("event_id", event_id);
    w.key("timestamp").value_double(static_cast<double>(platform_unix_ms()) / 1000.0);
    w.field("platform", "native");
    w.field("level", level_name(ev.level));
    w.field("logger", "mebet");
    w.field("release", std::string("mebet@") + config::kVersion);
    w.field("environment", config::kBuildKind);
    w.key("message").begin_object().field("formatted", truncate_utf8(ev.title, 512)).end_object();
    if (!ev.fingerprint.empty()) {
        w.key("fingerprint").begin_array();
        for (const auto& f : ev.fingerprint) w.value(truncate_utf8(f, 200));
        w.end_array();
    }
    w.key("tags").begin_object();
    w.field("type", ev.type);
    w.field("build", config::kBuildKind);
    w.field("session", session_id_);
    for (const auto& kv : tags) w.field(kv.first, kv.second);
    for (const auto& kv : ev.tags) w.field(kv.first, truncate_utf8(kv.second, 200));
    w.end_object();
    w.key("extra").begin_object();
    w.field("uptime_s", uptime_s());
    if (!ev.extra_json.empty()) w.key("data").raw(ev.extra_json);
    w.end_object();
    w.end_object();
    std::string json = w.take();
    static const char* const kTruncated = "{\"truncated\":true}";
    if (json.size() > config::kLimit_event_bytes && ev.extra_json != kTruncated) {
        // ТЗ §12: event ≤ 64 KB. Drop the payload rather than send a broken event.
        Event slim = ev;
        slim.extra_json = kTruncated;
        return build_event_json(slim, event_id);
    }
    return json;
}

bool Reporter::post(const Event& ev, unsigned timeout_ms) {
    const Dsn& dsn = ev.channel == Channel::errors ? impl_->errors_dsn : impl_->reports_dsn;
    if (!dsn.valid) return false;
    const std::string id = random_hex(16);
    const std::string body_json = build_event_json(ev, id);
    std::string env;
    env.reserve(body_json.size() + 160);
    env += "{\"event_id\":\"" + id + "\",\"sent_at\":\"" + iso8601(platform_unix_ms()) + "\"}\n";
    env += "{\"type\":\"event\",\"length\":" + std::to_string(body_json.size()) +
           ",\"content_type\":\"application/json\"}\n";
    env += body_json;
    env += "\n";
    const std::string auth = std::string("Sentry sentry_version=7, sentry_client=mebet/") + config::kVersion +
                             ", sentry_key=" + dsn.public_key;
    return platform_post(dsn, env, auth, timeout_ms);
}

void Reporter::sender_loop() {
    for (;;) {
        Event ev;
        {
            std::unique_lock<std::mutex> lk(impl_->mu);
            impl_->sending = false;
            impl_->idle_cv.notify_all();
            impl_->cv.wait(lk, [&] { return !impl_->queue.empty(); });
            ev = std::move(impl_->queue.front());
            impl_->queue.pop_front();
            impl_->sending = true;
        }
        post(ev, 10000);
    }
}

bool Reporter::submit(Event ev) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (!admit(ev)) return false;
    impl_->queue.push_back(std::move(ev));
    if (!impl_->sender_started) {
        impl_->sender_started = true;
        std::thread([this] { sender_loop(); }).detach();
    }
    impl_->cv.notify_one();
    return true;
}

bool Reporter::send_now(Event ev, unsigned timeout_ms) {
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        if (!admit(ev)) return false;
    }
    auto done = std::make_shared<std::promise<bool>>();
    auto fut = done->get_future();
    std::thread([this, ev = std::move(ev), done, timeout_ms]() mutable {
        done->set_value(post(ev, timeout_ms));
    }).detach();
    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) != std::future_status::ready) return false;
    return fut.get();
}

void Reporter::drain(unsigned timeout_ms) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    impl_->idle_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                            [&] { return impl_->queue.empty() && !impl_->sending; });
}

void guard_error(const std::string& type, const std::string& message, const std::string& extra_json) {
    Event ev;
    ev.channel = Channel::errors;
    ev.level = Level::error;
    ev.type = "guard_error." + type;
    ev.title = "Guard error: " + type + ": " + message;
    ev.fingerprint = {"guard_error", type};
    ev.extra_json = extra_json;
    ev.dedupe_key = "guard_error." + type;
    Reporter::instance().submit(std::move(ev));
}

}  // namespace mebet::report
