#include "GuiUtils.h"

#include "../resources/resource.h"

#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <mutex>
#include <unordered_map>
#include <vector>

namespace netlens::gui {

namespace {

// Cached brushes keyed by RGB. Freed at process exit.
std::mutex                              g_brushMu;
std::unordered_map<COLORREF, HBRUSH>    g_brushCache;

} // anonymous namespace

int dpiFor(HWND hwnd) {
    // GetDpiForWindow is Win10 1607+; fall back to system DPI otherwise.
    using GetDpiForWindowFn = UINT (WINAPI*)(HWND);
    static GetDpiForWindowFn pfn = []() -> GetDpiForWindowFn {
        HMODULE u = ::GetModuleHandleW(L"user32.dll");
        return u ? reinterpret_cast<GetDpiForWindowFn>(::GetProcAddress(u, "GetDpiForWindow"))
                 : nullptr;
    }();
    if (hwnd && pfn) {
        UINT v = pfn(hwnd);
        if (v != 0) return static_cast<int>(v);
    }
    HDC dc = ::GetDC(nullptr);
    int dpi = dc ? ::GetDeviceCaps(dc, LOGPIXELSY) : 96;
    if (dc) ::ReleaseDC(nullptr, dc);
    return dpi == 0 ? 96 : dpi;
}

std::wstring getText(HWND hwnd) {
    int len = ::GetWindowTextLengthW(hwnd);
    if (len <= 0) return L"";
    std::wstring buf(static_cast<size_t>(len), L'\0');
    int got = ::GetWindowTextW(hwnd, buf.data(), len + 1);
    if (got <= 0) return L"";
    buf.resize(static_cast<size_t>(got));
    return buf;
}

HFONT createUiFont(HWND parent, int pointSize, bool bold) {
    int dpi    = dpiFor(parent);
    int height = -MulDiv(pointSize, dpi, 72);

    LOGFONTW lf{};
    lf.lfHeight         = height;
    lf.lfWeight         = bold ? FW_SEMIBOLD : FW_NORMAL;
    lf.lfCharSet        = DEFAULT_CHARSET;
    lf.lfOutPrecision   = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision  = CLIP_DEFAULT_PRECIS;
    lf.lfQuality        = CLEARTYPE_QUALITY;
    lf.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
    wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI");
    return ::CreateFontIndirectW(&lf);
}

HBRUSH cachedSolidBrush(COLORREF rgb) {
    std::lock_guard<std::mutex> lk(g_brushMu);
    auto it = g_brushCache.find(rgb);
    if (it != g_brushCache.end()) return it->second;
    HBRUSH b = ::CreateSolidBrush(rgb);
    g_brushCache[rgb] = b;
    return b;
}

std::wstring promptSaveAs(HWND parent, const wchar_t* title,
                          const wchar_t* defaultName,
                          const wchar_t* filter)
{
    wchar_t buf[MAX_PATH];
    if (defaultName) {
        wcsncpy_s(buf, MAX_PATH, defaultName, _TRUNCATE);
    } else {
        buf[0] = L'\0';
    }

    OPENFILENAMEW ofn{};
    ofn.lStructSize     = sizeof(ofn);
    ofn.hwndOwner       = parent;
    ofn.lpstrTitle      = title;
    ofn.lpstrFilter     = filter;
    ofn.lpstrFile       = buf;
    ofn.nMaxFile        = MAX_PATH;
    ofn.Flags           = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (!::GetSaveFileNameW(&ofn)) return L"";
    return std::wstring(buf);
}

void revealInExplorer(const std::wstring& path) {
    if (path.empty()) return;
    ::ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void postStatusMessage(HWND mainWnd, const std::wstring& msg) {
    if (!mainWnd) return;
    auto* heap = new std::wstring(msg);
    if (!::PostMessageW(mainWnd, WM_NL_STATUS, 0, reinterpret_cast<LPARAM>(heap))) {
        delete heap;
    }
}

} // namespace netlens::gui
