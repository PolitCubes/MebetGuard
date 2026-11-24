// Report transport on Windows: WinHTTP, the guard's own HTTPS client (ТЗ §12: a second
// sentry-native client cannot live in the same process). No disk queue: offline = lost.
#include "core/win_util.hpp"  // windows.h before winhttp.h

#include <winhttp.h>

#include "config.hpp"
#include "report.hpp"
#include "strings.hpp"

namespace mebet::report {

namespace {
constexpr DWORD kAccessTypeAutomaticProxy = 4;           // WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, Windows 8.1+
constexpr DWORD kProtocolTls12 = 0x00000800;             // WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
constexpr DWORD kProtocolTls13 = 0x00002000;             // WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
}  // namespace

bool platform_post(const Dsn& dsn, const std::string& body, const std::string& auth_header, unsigned timeout_ms) {
    const std::wstring agent = L"Mebet/" + from_utf8(config::kVersion);
    const bool modern = win::os_version().at_least(6, 3);
    HINTERNET session = WinHttpOpen(agent.c_str(), modern ? kAccessTypeAutomaticProxy : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;
    const int t = static_cast<int>(timeout_ms);
    WinHttpSetTimeouts(session, t, t, t, t);
    DWORD protocols = kProtocolTls12 | (win::os_version().build >= 20348 ? kProtocolTls13 : 0);
    WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    bool ok = false;
    const std::wstring host = from_utf8(dsn.host);
    const std::wstring path = from_utf8(dsn.envelope_path());
    if (HINTERNET conn = WinHttpConnect(session, host.c_str(), static_cast<INTERNET_PORT>(dsn.port), 0)) {
        if (HINTERNET req = WinHttpOpenRequest(conn, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES, dsn.https ? WINHTTP_FLAG_SECURE : 0)) {
            const std::wstring headers = L"Content-Type: application/x-sentry-envelope\r\nX-Sentry-Auth: " +
                                         from_utf8(auth_header) + L"\r\n";
            if (WinHttpSendRequest(req, headers.c_str(), static_cast<DWORD>(-1L), const_cast<char*>(body.data()),
                                   static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) &&
                WinHttpReceiveResponse(req, nullptr)) {
                DWORD status = 0, size = sizeof(status);
                if (WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                        &status, &size, WINHTTP_NO_HEADER_INDEX))
                    ok = status >= 200 && status < 300;
            }
            WinHttpCloseHandle(req);
        }
        WinHttpCloseHandle(conn);
    }
    WinHttpCloseHandle(session);
    return ok;
}

bool platform_random(void* out, std::size_t len) {
    using RtlGenRandomFn = BOOLEAN(WINAPI*)(PVOID, ULONG);
    static const auto fn = reinterpret_cast<RtlGenRandomFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "SystemFunction036")));
    return fn && fn(out, static_cast<ULONG>(len));
}

std::uint64_t platform_unix_ms() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const std::uint64_t t = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ull) / 10000ull;
}

}  // namespace mebet::report
