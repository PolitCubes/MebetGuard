// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "window/game_window.hpp"

#include <atomic>
#include <cwchar>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/win_util.hpp"
#include "json_writer.hpp"
#include "nt.hpp"
#include "window/splash.hpp"

namespace mebet::game_window {

namespace {

// GetCurrentInputMessageSource (Windows 8+), declared here for the Windows 7 SDK level.
struct InputMessageSource {
    int deviceType;  // IMDT_*
    int originId;    // IMO_*
};
constexpr int kImoUnavailable = 0x00;
constexpr int kImoInjected = 0x02;
constexpr int kImdtUnavailable = 0x00;
using GetCurrentInputMessageSourceFn = BOOL(WINAPI*)(InputMessageSource*);

UINT kApplyMessage = 0xFFFFFFFF;  // registered in configure(), never in DllMain
constexpr const wchar_t* kOrigProp = L"MebetOrigProc";

std::wstring g_title;
HICON g_icon_big = nullptr;
HICON g_icon_small = nullptr;
GetCurrentInputMessageSourceFn g_source = nullptr;
HWINEVENTHOOK g_hook = nullptr;

struct Counters {
    std::atomic<std::uint64_t> hardware{0}, clicks{0}, keys{0}, moves{0}, raw{0}, posted{0}, peak{0};
    std::atomic<std::uint64_t> second{0}, in_second{0};
};
Counters g_counters;

bool is_game_class(const wchar_t* cls) {
    return std::wcscmp(cls, L"GLFW30") == 0 || std::wcsncmp(cls, L"SDL_app", 7) == 0 || std::wcsncmp(cls, L"SDL", 3) == 0;
}

void count_injected(std::atomic<std::uint64_t>& bucket) {
    bucket.fetch_add(1, std::memory_order_relaxed);
    const std::uint64_t now_s = GetTickCount64() / 1000;
    if (g_counters.second.exchange(now_s) != now_s) {
        g_counters.in_second.store(0);
    }
    const std::uint64_t n = g_counters.in_second.fetch_add(1) + 1;
    std::uint64_t peak = g_counters.peak.load();
    while (n > peak && !g_counters.peak.compare_exchange_weak(peak, n)) {
    }
}

bool is_click(UINT m) {
    return (m >= WM_LBUTTONDOWN && m <= WM_MBUTTONDBLCLK) || m == WM_XBUTTONDOWN || m == WM_XBUTTONUP ||
           m == WM_XBUTTONDBLCLK || m == WM_MOUSEWHEEL || m == WM_MOUSEHWHEEL;
}
bool is_key(UINT m) { return m == WM_KEYDOWN || m == WM_KEYUP || m == WM_SYSKEYDOWN || m == WM_SYSKEYUP; }

// true = drop the message (ТЗ §9: injected input is dropped by default and counted).
bool filter_input(UINT m, LPARAM l) {
    if (m == WM_INPUT) {
        RAWINPUTHEADER h{};
        UINT size = sizeof(h);
        if (GetRawInputData(reinterpret_cast<HRAWINPUT>(l), RID_HEADER, &h, &size, sizeof(RAWINPUTHEADER)) ==
                sizeof(h) &&
            h.hDevice == nullptr && (h.dwType == RIM_TYPEMOUSE || h.dwType == RIM_TYPEKEYBOARD)) {
            count_injected(g_counters.raw);
            return true;
        }
        g_counters.hardware.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    const bool click = is_click(m), key = is_key(m), move = m == WM_MOUSEMOVE;
    if (!click && !key && !move) return false;
    InputMessageSource src{};
    if (!g_source(&src)) return false;
    if (src.originId == kImoInjected) {
        count_injected(click ? g_counters.clicks : key ? g_counters.keys : g_counters.moves);
        return true;
    }
    if (src.originId == kImoUnavailable && src.deviceType == kImdtUnavailable) {
        g_counters.posted.fetch_add(1, std::memory_order_relaxed);  // counted, not dropped
    } else {
        g_counters.hardware.fetch_add(1, std::memory_order_relaxed);
    }
    return false;
}

void apply_identity(HWND hwnd) {
    if (!g_title.empty()) SetWindowTextW(hwnd, g_title.c_str());
    if (g_icon_big) SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(g_icon_big));
    if (g_icon_small) SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(g_icon_small));
}

LRESULT CALLBACK game_proc(HWND hwnd, UINT m, WPARAM w, LPARAM l) {
    const auto orig = reinterpret_cast<WNDPROC>(GetPropW(hwnd, kOrigProp));
    if (!orig) return DefWindowProcW(hwnd, m, w, l);
    if (m == kApplyMessage) {
        apply_identity(hwnd);
        return 0;
    }
    switch (m) {
        case WM_SETTEXT:
            if (!g_title.empty()) return CallWindowProcW(orig, hwnd, m, w, reinterpret_cast<LPARAM>(g_title.c_str()));
            break;
        case WM_SETICON:
            if (w == ICON_BIG && g_icon_big) l = reinterpret_cast<LPARAM>(g_icon_big);
            if ((w == ICON_SMALL || w == 2 /* ICON_SMALL2 */) && g_icon_small) l = reinterpret_cast<LPARAM>(g_icon_small);
            break;
        case WM_NCDESTROY: {
            const LRESULT r = CallWindowProcW(orig, hwnd, m, w, l);
            RemovePropW(hwnd, kOrigProp);
            return r;
        }
        default:
            if (g_source && config::enabled(config::Module::input_source) && filter_input(m, l)) {
                return m == WM_INPUT ? DefWindowProcW(hwnd, m, w, l) : 0;
            }
            break;
    }
    return CallWindowProcW(orig, hwnd, m, w, l);
}

void subclass(HWND hwnd) {
    if (GetPropW(hwnd, kOrigProp)) return;
    const LONG_PTR prev = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
    if (!prev || prev == reinterpret_cast<LONG_PTR>(&game_proc)) return;
    SetPropW(hwnd, kOrigProp, reinterpret_cast<HANDLE>(prev));
    SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&game_proc));
    // The title set by CreateWindowEx already went to the old procedure: rewrite it on the
    // window's own thread (no cross-thread SendMessage from the worker).
    PostMessageW(hwnd, kApplyMessage, 0, 0);
}

void CALLBACK on_win_event(HWINEVENTHOOK, DWORD event, HWND hwnd, LONG id_object, LONG id_child, DWORD, DWORD) {
    if (!hwnd || id_object != OBJID_WINDOW || id_child != CHILDID_SELF) return;
    if (GetAncestor(hwnd, GA_ROOT) != hwnd) return;
    wchar_t cls[64];
    if (!GetClassNameW(hwnd, cls, 64) || !is_game_class(cls)) return;
    if (event == EVENT_OBJECT_CREATE) {
        if (config::enabled(config::Module::window_identity) || config::enabled(config::Module::input_source)) subclass(hwnd);
    } else if (event == EVENT_OBJECT_SHOW) {
        subclass(hwnd);
        splash::game_window_shown();
    }
}

HICON load_icon(const std::wstring& path, void* exe, int cx, int cy) {
    if (!path.empty()) {
        if (HICON h = static_cast<HICON>(LoadImageW(nullptr, path.c_str(), IMAGE_ICON, cx, cy, LR_LOADFROMFILE))) return h;
    }
    return static_cast<HICON>(LoadImageW(static_cast<HMODULE>(exe), MAKEINTRESOURCEW(1), IMAGE_ICON, cx, cy, LR_SHARED));
}

}  // namespace

void configure(const std::wstring& title, const std::wstring& icon_path, void* exe_module) {
    kApplyMessage = RegisterWindowMessageW(L"MebetApplyIdentity");
    g_title = title;
    if (config::enabled(config::Module::window_identity)) {
        g_icon_big = load_icon(icon_path, exe_module, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON));
        g_icon_small = load_icon(icon_path, exe_module, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));
    } else {
        g_title.clear();
    }
    g_source = reinterpret_cast<GetCurrentInputMessageSourceFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetCurrentInputMessageSource")));
}

void install_in_worker() {
    g_hook = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW, nullptr, &on_win_event, GetCurrentProcessId(), 0,
                             WINEVENT_OUTOFCONTEXT);
}

bool input_source_supported() { return g_source != nullptr; }

InputCounters counters() {
    InputCounters c;
    c.hardware = g_counters.hardware.load();
    c.injected_clicks = g_counters.clicks.load();
    c.injected_keys = g_counters.keys.load();
    c.injected_moves = g_counters.moves.load();
    c.injected_raw = g_counters.raw.load();
    c.posted = g_counters.posted.load();
    c.peak_injected_per_s = g_counters.peak.load();
    return c;
}

void report_input(bool final_report) {
    if (!config::enabled(config::Module::input_source) || !g_source) return;
    const InputCounters c = counters();
    const std::uint64_t injected = c.injected_clicks + c.injected_keys + c.injected_moves + c.injected_raw;
    if (injected == 0 && c.posted == 0) return;
    report::Event ev;
    ev.type = "report.injected_input";
    ev.level = report::Level::warning;
    ev.title = "Report: injected input";
    ev.fingerprint = {"report.injected_input", injected ? "injected" : "posted"};
    JsonWriter w;
    w.begin_object();
    w.field("final", final_report);
    w.field("clicks", c.injected_clicks);
    w.field("keys", c.injected_keys);
    w.field("moves", c.injected_moves);
    w.field("raw_input", c.injected_raw);
    w.field("posted", c.posted);
    w.field("hardware", c.hardware);
    const double share = c.hardware + injected ? static_cast<double>(injected) / static_cast<double>(c.hardware + injected) : 0.0;
    w.key("injected_share").value_double(share);
    w.field("peak_per_second", c.peak_injected_per_s);
    w.end_object();
    ev.extra_json = w.take();
    if (final_report) {
        report::Reporter::instance().submit(std::move(ev));
    } else {
        guard::defer_event(std::move(ev));
    }
}

}  // namespace mebet::game_window
