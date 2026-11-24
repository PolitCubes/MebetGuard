#include "window/splash.hpp"

#include <atomic>
#include <cstring>

#include "config.hpp"
#include "core/win_util.hpp"

namespace mebet::splash {

namespace {

// Resource layout written by tools/png_to_bgra.py: "MBSP", width, height, scale %, then
// width × height premultiplied BGRA pixels, top row first. No image decoder at runtime.
struct BitmapHeader {
    char magic[4];
    std::uint32_t width;
    std::uint32_t height;
    std::uint32_t scale;
};

constexpr UINT kTimerId = 1;
constexpr UINT kFrameMs = 16;
constexpr std::uint64_t kMaxLifetimeMs = 120000;  // never outlive a game that fails to open a window

std::atomic<bool> g_game_shown{false};
std::atomic<bool> g_hide{false};
std::atomic<HWND> g_hwnd{nullptr};
HMODULE g_exe = nullptr;

struct State {
    HDC mem_dc = nullptr;
    HBITMAP bitmap = nullptr;
    HGDIOBJ old = nullptr;
    SIZE size{};
    POINT pos{};
    std::uint64_t shown_at = 0;
    std::uint64_t fade_out_at = 0;
    BYTE alpha = 0;
};

using GetDpiForMonitorFn = HRESULT(WINAPI*)(HMONITOR, int, UINT*, UINT*);

UINT monitor_dpi(HMONITOR mon) {
    static const auto fn = [] {
        HMODULE shcore = LoadLibraryExW(L"shcore.dll", nullptr, 0x00000800 /* LOAD_LIBRARY_SEARCH_SYSTEM32 */);
        return shcore ? reinterpret_cast<GetDpiForMonitorFn>(reinterpret_cast<void*>(GetProcAddress(shcore, "GetDpiForMonitor")))
                      : nullptr;
    }();
    UINT x = 96, y = 96;
    if (fn && SUCCEEDED(fn(mon, 0 /* MDT_EFFECTIVE_DPI */, &x, &y))) return x;
    HDC dc = GetDC(nullptr);
    const int d = dc ? GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(nullptr, dc);
    return static_cast<UINT>(d);
}

const BitmapHeader* load_bitmap(unsigned scale) {
    const wchar_t* name = scale >= 200 ? L"MEBET_SPLASH_200" : scale >= 150 ? L"MEBET_SPLASH_150" : L"MEBET_SPLASH_100";
    HRSRC r = FindResourceW(g_exe, name, MAKEINTRESOURCEW(10) /* RT_RCDATA */);
    if (!r) return nullptr;
    HGLOBAL g = LoadResource(g_exe, r);
    const DWORD size = SizeofResource(g_exe, r);
    const auto* h = g ? static_cast<const BitmapHeader*>(LockResource(g)) : nullptr;
    if (!h || size < sizeof(BitmapHeader) || std::memcmp(h->magic, "MBSP", 4) != 0) return nullptr;
    if (static_cast<std::uint64_t>(h->width) * h->height * 4 + sizeof(BitmapHeader) > size) return nullptr;
    return h;
}

void present(HWND hwnd, State& s) {
    HDC screen = GetDC(nullptr);
    POINT src{0, 0};
    BLENDFUNCTION blend{AC_SRC_OVER, 0, s.alpha, AC_SRC_ALPHA};
    UpdateLayeredWindow(hwnd, screen, &s.pos, &s.size, s.mem_dc, &src, 0, &blend, ULW_ALPHA);
    ReleaseDC(nullptr, screen);
}

LRESULT CALLBACK splash_proc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    auto* s = reinterpret_cast<State*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_TIMER: {
            if (!s) break;
            const std::uint64_t now = win::now_ms();
            const std::uint64_t elapsed = now - s->shown_at;
            const unsigned fade = config::opt::splash_fade_ms ? config::opt::splash_fade_ms : 1;
            const bool may_hide = (g_game_shown.load() && elapsed >= config::opt::splash_min_ms) || elapsed >= kMaxLifetimeMs;
            if (g_hide.load()) {
                DestroyWindow(hwnd);
                return 0;
            }
            if (!s->fade_out_at && may_hide) s->fade_out_at = now;
            int alpha;
            if (s->fade_out_at) {
                const std::uint64_t t = now - s->fade_out_at;
                if (t >= fade) {
                    DestroyWindow(hwnd);
                    return 0;
                }
                alpha = 255 - static_cast<int>(255 * t / fade);
            } else {
                alpha = elapsed >= fade ? 255 : static_cast<int>(255 * elapsed / fade);
            }
            const BYTE a = static_cast<BYTE>(alpha < 0 ? 0 : alpha > 255 ? 255 : alpha);
            if (a != s->alpha) {
                s->alpha = a;
                present(hwnd, *s);
            }
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            g_hwnd.store(nullptr);
            PostQuitMessage(0);
            return 0;
        case WM_MOUSEACTIVATE:
            return MA_NOACTIVATE;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

DWORD WINAPI splash_thread(void*) {
    POINT cursor{};
    GetCursorPos(&cursor);
    HMONITOR mon = MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(mon, &mi)) return 0;
    const unsigned scale = monitor_dpi(mon) * 100 / 96;
    const BitmapHeader* bmp = load_bitmap(scale);
    if (!bmp) return 0;

    State s;
    s.size = {static_cast<LONG>(bmp->width), static_cast<LONG>(bmp->height)};
    s.pos = {mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - s.size.cx) / 2,
             mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - s.size.cy) / 2};

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = s.size.cx;
    bi.bmiHeader.biHeight = -s.size.cy;  // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HDC screen = GetDC(nullptr);
    s.mem_dc = CreateCompatibleDC(screen);
    s.bitmap = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, screen);
    if (!s.mem_dc || !s.bitmap || !bits) return 0;
    std::memcpy(bits, reinterpret_cast<const unsigned char*>(bmp) + sizeof(BitmapHeader),
                static_cast<std::size_t>(bmp->width) * bmp->height * 4);
    s.old = SelectObject(s.mem_dc, s.bitmap);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &splash_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"MebetSplash";
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512) /* IDC_ARROW */);
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST, wc.lpszClassName,
                                L"Mebet Anticheat", WS_POPUP, s.pos.x, s.pos.y, s.size.cx, s.size.cy, nullptr, nullptr,
                                wc.hInstance, nullptr);
    if (!hwnd) return 0;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&s));
    g_hwnd.store(hwnd);
    s.alpha = 0;
    present(hwnd, s);
    ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    s.shown_at = win::now_ms();
    SetTimer(hwnd, kTimerId, kFrameMs, nullptr);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    SelectObject(s.mem_dc, s.old);
    DeleteObject(s.bitmap);
    DeleteDC(s.mem_dc);
    return 0;
}

}  // namespace

void start(HMODULE exe_module) {
    if (!config::enabled(config::Module::splash)) return;
    g_exe = exe_module;
    HANDLE t = CreateThread(nullptr, 0, &splash_thread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

void game_window_shown() { g_game_shown.store(true); }

void hide_now() {
    g_hide.store(true);
    if (HWND h = g_hwnd.load()) PostMessageW(h, WM_CLOSE, 0, 0);
    for (int i = 0; i < 25 && g_hwnd.load(); ++i) Sleep(10);
}

}  // namespace mebet::splash
