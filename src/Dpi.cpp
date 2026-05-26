#include "Dpi.h"

namespace nl::dpi {

uint32_t g_dpi = 96;

// Force 96 DPI rendering regardless of the actual monitor DPI. Result:
// on a 4K screen the UI stays compact (small physical inches) and
// renders crisp at native pixel resolution. The PerMonitorV2 manifest
// declaration keeps Windows from bitmap-stretching the window — text
// and lines render 1:1.
//
// Set this to `false` to restore proper per-monitor DPI scaling.
constexpr bool kForce96Dpi = true;

namespace {

// Runtime-resolved DPI helpers. GetDpiForWindow / GetDpiForSystem are
// user32 exports added in Windows 10 1607 (build 14393). On Server 2012
// / 2008R2 / Win 7 / 8 / 8.1 the EXE fails to load with "entry point
// not found" if these symbols sit in the static import table. Using
// GetProcAddress moves resolution to runtime; if the symbol isn't
// present we fall back to GDI's LOGPIXELSX query (shipped since
// Windows 2000).
using PFN_GetDpiForWindow = UINT (WINAPI*)(HWND);
using PFN_GetDpiForSystem = UINT (WINAPI*)(void);

UINT GdiDpiFallback() {
    HDC dc = GetDC(nullptr);
    UINT d = dc ? static_cast<UINT>(GetDeviceCaps(dc, LOGPIXELSX)) : 96u;
    if (dc) ReleaseDC(nullptr, dc);
    return d == 0 ? 96u : d;
}

UINT DpiForWindowCompat(HWND hwnd) {
    static PFN_GetDpiForWindow fn = []() -> PFN_GetDpiForWindow {
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (!user32) return nullptr;
        return reinterpret_cast<PFN_GetDpiForWindow>(
            GetProcAddress(user32, "GetDpiForWindow"));
    }();
    if (fn && hwnd) return fn(hwnd);
    return GdiDpiFallback();
}

} // anonymous namespace

UINT GetDpiForSystemCompat() {
    static PFN_GetDpiForSystem fn = []() -> PFN_GetDpiForSystem {
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (!user32) return nullptr;
        return reinterpret_cast<PFN_GetDpiForSystem>(
            GetProcAddress(user32, "GetDpiForSystem"));
    }();
    if (fn) return fn();
    return GdiDpiFallback();
}

void Init(HWND hwnd) {
    if (kForce96Dpi) { g_dpi = 96; return; }
    UINT d = DpiForWindowCompat(hwnd);
    g_dpi = (d == 0) ? 96 : d;
}

void Update(uint32_t newDpi) {
    if (kForce96Dpi) { g_dpi = 96; return; }
    g_dpi = (newDpi == 0) ? 96 : newDpi;
}

}  // namespace nl::dpi
