// Report transport on Linux/macOS: libcurl loaded at runtime (no link-time dependency;
// without libcurl the guard works the same and simply sends nothing).
#include <dlfcn.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <string>

#if defined(__linux__)
#include <sys/random.h>
#endif

#include "config.hpp"
#include "report.hpp"

namespace mebet::report {

namespace {

// The few libcurl entry points we need; option numbers are part of the stable curl ABI.
using CurlInit = void* (*)();
using CurlSetopt = int (*)(void*, int, ...);
using CurlPerform = int (*)(void*);
using CurlCleanup = void (*)(void*);
using CurlGetinfo = int (*)(void*, int, ...);
using SlistAppend = void* (*)(void*, const char*);
using SlistFree = void (*)(void*);

constexpr int kOptUrl = 10002;            // CURLOPT_URL
constexpr int kOptPostFields = 10015;     // CURLOPT_POSTFIELDS
constexpr int kOptPostFieldSize = 60;     // CURLOPT_POSTFIELDSIZE
constexpr int kOptHttpHeader = 10023;     // CURLOPT_HTTPHEADER
constexpr int kOptTimeoutMs = 155;        // CURLOPT_TIMEOUT_MS
constexpr int kOptNoSignal = 99;          // CURLOPT_NOSIGNAL
constexpr int kOptUserAgent = 10018;      // CURLOPT_USERAGENT
constexpr int kInfoResponseCode = 0x200002;  // CURLINFO_RESPONSE_CODE

struct Curl {
    CurlInit init = nullptr;
    CurlSetopt setopt = nullptr;
    CurlPerform perform = nullptr;
    CurlCleanup cleanup = nullptr;
    CurlGetinfo getinfo = nullptr;
    SlistAppend slist_append = nullptr;
    SlistFree slist_free = nullptr;
    bool ok = false;
};

const Curl& curl() {
    static const Curl c = [] {
        Curl r;
#if defined(__APPLE__)
        const char* names[] = {"/usr/lib/libcurl.4.dylib", "libcurl.4.dylib"};
#else
        const char* names[] = {"libcurl.so.4", "libcurl-gnutls.so.4"};
#endif
        void* lib = nullptr;
        for (const char* n : names)
            if ((lib = dlopen(n, RTLD_NOW | RTLD_LOCAL))) break;
        if (!lib) return r;
        r.init = reinterpret_cast<CurlInit>(dlsym(lib, "curl_easy_init"));
        r.setopt = reinterpret_cast<CurlSetopt>(dlsym(lib, "curl_easy_setopt"));
        r.perform = reinterpret_cast<CurlPerform>(dlsym(lib, "curl_easy_perform"));
        r.cleanup = reinterpret_cast<CurlCleanup>(dlsym(lib, "curl_easy_cleanup"));
        r.getinfo = reinterpret_cast<CurlGetinfo>(dlsym(lib, "curl_easy_getinfo"));
        r.slist_append = reinterpret_cast<SlistAppend>(dlsym(lib, "curl_slist_append"));
        r.slist_free = reinterpret_cast<SlistFree>(dlsym(lib, "curl_slist_free_all"));
        r.ok = r.init && r.setopt && r.perform && r.cleanup && r.getinfo && r.slist_append && r.slist_free;
        return r;
    }();
    return c;
}

}  // namespace

bool platform_post(const Dsn& dsn, const std::string& body, const std::string& auth_header, unsigned timeout_ms) {
    const Curl& c = curl();
    if (!c.ok) return false;
    void* h = c.init();
    if (!h) return false;
    const std::string url = std::string(dsn.https ? "https://" : "http://") + dsn.host + ":" + std::to_string(dsn.port) +
                            dsn.envelope_path();
    const std::string agent = std::string("Mebet/") + config::kVersion;
    void* headers = nullptr;
    headers = c.slist_append(headers, "Content-Type: application/x-sentry-envelope");
    headers = c.slist_append(headers, ("X-Sentry-Auth: " + auth_header).c_str());
    c.setopt(h, kOptUrl, url.c_str());
    c.setopt(h, kOptHttpHeader, headers);
    c.setopt(h, kOptPostFields, body.data());
    c.setopt(h, kOptPostFieldSize, static_cast<long>(body.size()));
    c.setopt(h, kOptTimeoutMs, static_cast<long>(timeout_ms));
    c.setopt(h, kOptNoSignal, 1L);
    c.setopt(h, kOptUserAgent, agent.c_str());
    bool ok = false;
    if (c.perform(h) == 0) {
        long status = 0;
        c.getinfo(h, kInfoResponseCode, &status);
        ok = status >= 200 && status < 300;
    }
    c.slist_free(headers);
    c.cleanup(h);
    return ok;
}

bool platform_random(void* out, std::size_t len) {
#if defined(__APPLE__)
    arc4random_buf(out, len);
    return true;
#else
    if (getrandom(out, len, 0) == static_cast<ssize_t>(len)) return true;
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = read(fd, out, len) == static_cast<ssize_t>(len);
    close(fd);
    return ok;
#endif
}

std::uint64_t platform_unix_ms() {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000u + static_cast<std::uint64_t>(ts.tv_nsec) / 1000000u;
}

}  // namespace mebet::report
