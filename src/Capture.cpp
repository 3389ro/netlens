#include "Capture.h"

// GDI+ needs std::min/max + PROPID before its headers (NOMINMAX is on).
#include <algorithm>
using std::min;
using std::max;
#include <objidl.h>
#include <gdiplus.h>

#include <vector>

namespace nl {
namespace capture {

namespace {

// Module-static session state — kept here (not in App) so dialogs that
// don't include App.h can still call into us.
std::wstring g_folder;
int          g_count        = 0;
bool         g_autoCapturing = false;

int GetPngEncoderClsid(CLSID* clsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    std::vector<BYTE> buf(size);
    auto* info = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
    Gdiplus::GetImageEncoders(num, size, info);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(info[i].MimeType, L"image/png") == 0) {
            *clsid = info[i].Clsid;
            return static_cast<int>(i);
        }
    }
    return -1;
}

std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring s(buf, n);
    size_t pos = s.find_last_of(L"\\/");
    if (pos != std::wstring::npos) s.resize(pos);
    return s;
}

const std::wstring& EnsureFolder() {
    if (!g_folder.empty()) return g_folder;
    SYSTEMTIME t{};
    GetLocalTime(&t);
    wchar_t stamp[64];
    swprintf_s(stamp, L"captures-%04d%02d%02d-%02d%02d%02d",
               t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    g_folder = GetExeDir() + L"\\" + stamp;
    CreateDirectoryW(g_folder.c_str(), nullptr);
    return g_folder;
}

}  // namespace

// Returns true if the bitmap looks black/empty. Detects a failed
// PrintWindow on custom-painted dialogs whose WM_PRINTCLIENT path
// doesn't drive the double-buffered WM_PAINT handler — PrintWindow
// returns TRUE but the destination DC stays untouched, so we end up
// saving an all-black PNG. Heuristic: read the centre scanline and
// count pixels with R+G+B > 30 (anything non-near-black).
static bool BitmapLooksBlank(HBITMAP bmp, int w, int h) {
    BITMAPINFO bi{};
    bi.bmiHeader.biSize        = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth       = w;
    bi.bmiHeader.biHeight      = -1;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    std::vector<uint32_t> row(static_cast<size_t>(w));
    HDC dc = GetDC(nullptr);
    int got = GetDIBits(dc, bmp, h / 2, 1, row.data(), &bi, DIB_RGB_COLORS);
    ReleaseDC(nullptr, dc);
    if (got <= 0) return true;     // can't read — assume blank
    int nonBlack = 0;
    for (uint32_t p : row) {
        uint8_t b = static_cast<uint8_t>(p);
        uint8_t g = static_cast<uint8_t>(p >> 8);
        uint8_t r = static_cast<uint8_t>(p >> 16);
        if (r + g + b > 30) {
            if (++nonBlack > 8) return false;
        }
    }
    return true;
}

bool SaveWindowPng(HWND hwnd, const std::wstring& path) {
    RECT rc;
    GetWindowRect(hwnd, &rc);
    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) return false;

    // Force a sync repaint cycle so any deferred WM_PAINT lands before
    // we read the window's pixels.
    RedrawWindow(hwnd, nullptr, nullptr,
                 RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);

    HDC     screenDc = GetDC(nullptr);
    HDC     memDc    = CreateCompatibleDC(screenDc);
    HBITMAP bmp      = CreateCompatibleBitmap(screenDc, w, h);
    HBITMAP oldBmp   = static_cast<HBITMAP>(SelectObject(memDc, bmp));

    // PW_RENDERFULLCONTENT = 0x00000002 — needed for DWM-composited windows.
    BOOL ok = PrintWindow(hwnd, memDc, 0x00000002 /* PW_RENDERFULLCONTENT */);

    // Fallback: PrintWindow can silently leave the bitmap blank when
    // the target uses double-buffered WM_PAINT without a matching
    // WM_PRINTCLIENT handler (Settings / Adapters dialogs in this
    // tree). Detect that case and capture the window region from the
    // screen DC instead — since the dialog is the active foreground
    // window at this point, its pixels are visible on screen.
    if (!ok || BitmapLooksBlank(bmp, w, h)) {
        BitBlt(memDc, 0, 0, w, h, screenDc, rc.left, rc.top, SRCCOPY);
        ok = TRUE;
    }

    {
        CLSID pngClsid;
        if (GetPngEncoderClsid(&pngClsid) >= 0) {
            Gdiplus::Bitmap gbmp(bmp, nullptr);
            ok = (gbmp.Save(path.c_str(), &pngClsid, nullptr) == Gdiplus::Ok);
        } else ok = FALSE;
    }

    SelectObject(memDc, oldBmp);
    DeleteObject(bmp);
    DeleteDC(memDc);
    ReleaseDC(nullptr, screenDc);
    return !!ok;
}

void ResetSession() {
    g_folder.clear();
    g_count = 0;
}

const std::wstring& SessionFolder() {
    return g_folder;   // possibly empty until first AppendWindow()
}

bool AppendWindow(HWND hwnd, const wchar_t* tag) {
    const std::wstring& folder = EnsureFolder();
    ++g_count;
    wchar_t name[96];
    swprintf_s(name, L"\\%02d-%s.png", g_count, tag ? tag : L"window");
    return SaveWindowPng(hwnd, folder + name);
}

bool IsAutoCapturing()        { return g_autoCapturing; }
void SetAutoCapturing(bool b) { g_autoCapturing = b; }

}  // namespace capture
}  // namespace nl
