#include "MainWindow.h"

#include "../AppConstants.h"
#include "../core/IpAddressUtils.h"
#include "../core/IpRangeParser.h"
#include "../core/NetworkAdapterService.h"
#include "../core/ReportExporter.h"
#include "../core/ScanPresetService.h"
#include "../core/Stopwatch.h"
#include "../resources/resource.h"
#include "GuiControls.h"
#include "GuiLayout.h"
#include "GuiUtils.h"
#include "MonitorWindow.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <uxtheme.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <ctime>
#include <sstream>

#pragma comment(lib, "uxtheme.lib")

namespace netlens::gui {

namespace {

constexpr wchar_t kClassName[] = L"NetLensMainWnd";

// Heap payload for the scanner → UI handoff. The scanner fires onFinished
// on its driver thread; instead of mutating MainWindow members directly
// from there (the old shape, which was cross-thread and a latent data
// race), we package the result into this struct, PostMessage it via
// WM_NL_SCAN_FINISHED, and let the UI thread unwrap + move into members.
// The handler owns the pointer and deletes it; the lambda deletes on
// PostMessage failure so we don't leak when the target HWND is gone.
struct ScanFinishedPayload {
    bool                          cancelled = false;
    netlens::ScanSummary         summary;
    std::vector<netlens::ScanResult> results;
};

// Sidebar is kept compiled but hidden in this layout — flip to true to bring
// it back. The code paths are still exercised by the compiler.
constexpr bool kSidebarEnabled = false;
constexpr int  kSidebarWidth   = 190;  // design pixels

// -----------------------------------------------------------------------------
// Palette
// -----------------------------------------------------------------------------
constexpr COLORREF kBgApp          = RGB(246, 248, 252);
constexpr COLORREF kBgCard         = RGB(255, 255, 255);
constexpr COLORREF kBgSidebar      = RGB(247, 249, 253);
constexpr COLORREF kBgSidebarHover = RGB(232, 238, 248);
constexpr COLORREF kBgSidebarActive= RGB(225, 234, 248);
constexpr COLORREF kBgAdapterBtn   = RGB(241, 245, 251);
constexpr COLORREF kBgAdapterHover = RGB(225, 234, 248);
constexpr COLORREF kBorder         = RGB(220, 226, 235);

constexpr COLORREF kFgPrimary      = RGB(25,  32,  44);
constexpr COLORREF kFgSecondary    = RGB(90,  100, 115);
constexpr COLORREF kFgMuted        = RGB(140, 150, 165);
constexpr COLORREF kFgAccent       = RGB(31,  78,  162);
constexpr COLORREF kFgDanger       = RGB(196, 30,  30);
constexpr COLORREF kFgDangerDown   = RGB(160, 22,  22);
constexpr COLORREF kFgSuccess      = RGB(22,  163, 74);
constexpr COLORREF kFgSuccessDown  = RGB(15,  130, 60);
constexpr COLORREF kFgWhite        = RGB(255, 255, 255);

constexpr COLORREF kRiskHighBg     = RGB(254, 226, 226);
constexpr COLORREF kRiskHighFg     = RGB(153, 27,  27);
constexpr COLORREF kRiskMedBg      = RGB(254, 243, 199);
constexpr COLORREF kRiskMedFg      = RGB(146, 64,  14);
constexpr COLORREF kRiskLowFg      = RGB(30,  64,  175);
constexpr COLORREF kAltRowBg       = RGB(249, 250, 252);

// KPI accent stripe colours — 4-card strip: Online / Progress / ETA / Duration.
constexpr COLORREF kKpiAccents[4] = {
    RGB(22,  163, 74),    // Online      (green check)
    RGB(31,  78,  162),   // Progress    (brand blue)
    RGB(217, 119, 6),     // ETA         (amber clock)
    RGB(140, 150, 165)    // Duration    (neutral stopwatch)
};

// -----------------------------------------------------------------------------
// MDL2 Assets glyphs and icon-font helper
// -----------------------------------------------------------------------------
HFONT createIconFont(HWND parent, int pointSize) {
    int dpi = dpiFor(parent);
    int height = -MulDiv(pointSize, dpi, 72);
    LOGFONTW lf{};
    lf.lfHeight         = height;
    lf.lfWeight         = FW_NORMAL;
    lf.lfCharSet        = DEFAULT_CHARSET;
    lf.lfOutPrecision   = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision  = CLIP_DEFAULT_PRECIS;
    lf.lfQuality        = CLEARTYPE_QUALITY;
    lf.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
    wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe MDL2 Assets");
    return ::CreateFontIndirectW(&lf);
}

constexpr wchar_t kGlyphBrand    [] = L"\xE839";   // NetworkAdapter
constexpr wchar_t kGlyphScanner  [] = L"\xE721";   // Zoom
constexpr wchar_t kGlyphSettings [] = L"\xE713";   // Settings
constexpr wchar_t kGlyphAbout    [] = L"\xE946";   // Info
constexpr wchar_t kGlyphAdapter  [] = L"\xE839";   // NetworkAdapter — for the adapter button
// KPI strip glyphs — 4 cards
constexpr wchar_t kGlyphKpi[4][2] = {
    { L'\xE930', 0 },   // Online   — Completed
    { L'\xE9D9', 0 },   // Progress — Diagnostic
    { L'\xE823', 0 },   // ETA      — Clock
    { L'\xE916', 0 }    // Duration — Stopwatch
};

// -----------------------------------------------------------------------------
// ListView columns
// -----------------------------------------------------------------------------
struct ColumnSpec { const wchar_t* title; int width; };
constexpr ColumnSpec kColumns[] = {
    { L"IP address",   120 },
    { L"Status",        80 },
    { L"Hostname",     180 },
    { L"Vendor",       170 },
    { L"MAC address",  150 },
    { L"Open ports",   170 },
    { L"Risk",          80 },
    { L"Risk hints",   300 },
    { L"RTT (ms)",      70 },
    { L"Discovery",    110 }
};
constexpr int kColumnCount = static_cast<int>(sizeof(kColumns) / sizeof(kColumns[0]));

enum : int {
    COL_IP        = 0,
    COL_STATUS    = 1,
    COL_HOSTNAME  = 2,
    COL_VENDOR    = 3,
    COL_MAC       = 4,
    COL_PORTS     = 5,
    COL_RISK      = 6,
    COL_HINTS     = 7,
    COL_RTT       = 8,
    COL_DISCOVERY = 9
};

// -----------------------------------------------------------------------------
// Misc helpers
// -----------------------------------------------------------------------------

int parseIntFromEdit(HWND ed, int fallback) {
    std::wstring s = getText(ed);
    if (s.empty()) return fallback;
    wchar_t* end = nullptr;
    long v = std::wcstol(s.c_str(), &end, 10);
    if (!end || *end != L'\0') return fallback;
    return static_cast<int>(v);
}

std::wstring suggestFileName(const wchar_t* extension) {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t buf[64];
    std::wcsftime(buf, 64, L"netlens-scan-%Y%m%d-%H%M%S", &tm);
    std::wstring r = buf;
    r += L".";
    r += extension;
    return r;
}

std::wstring formatDuration(int64_t ms) {
    if (ms < 1000) return std::to_wstring(ms) + L" ms";
    if (ms < 60'000) {
        wchar_t b[32]; std::swprintf(b, 32, L"%.1f s", ms / 1000.0);
        return b;
    }
    int mins = static_cast<int>(ms / 60'000);
    int secs = static_cast<int>((ms / 1000) % 60);
    wchar_t b[32]; std::swprintf(b, 32, L"%d:%02d", mins, secs);
    return b;
}

std::wstring trim(std::wstring s) {
    auto notSpace = [](wchar_t c){ return !std::iswspace(static_cast<wint_t>(c)); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

std::wstring toLower(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c)));
    return s;
}

void buildResultRow(const ScanResult& r, std::vector<std::wstring>& outCells) {
    outCells.clear();
    outCells.reserve(kColumnCount);
    outCells.push_back(r.ipAddress);
    outCells.push_back(std::wstring(L"●  ") + r.statusText());
    outCells.push_back(r.effectiveHostname());
    outCells.push_back(r.vendor);
    outCells.push_back(r.macAddress);
    outCells.push_back(r.openPortsText());
    outCells.push_back(RiskLevelToString(r.riskLevel));
    outCells.push_back(r.riskHints);
    outCells.push_back(r.isOnline ? std::to_wstring(r.responseTimeMs) : std::wstring());
    outCells.push_back(DiscoveryMethodToString(r.discovery));
}

int compareIp(const std::wstring& a, const std::wstring& b) {
    uint32_t av = ip::parseDotted(a).value_or(0);
    uint32_t bv = ip::parseDotted(b).value_or(0);
    if (av < bv) return -1;
    if (av > bv) return  1;
    return 0;
}
int compareInt(int64_t a, int64_t b) { return (a < b) ? -1 : (a > b ? 1 : 0); }
int compareRisk(RiskLevel a, RiskLevel b) { return compareInt(static_cast<int>(a), static_cast<int>(b)); }
int compareStr(const std::wstring& a, const std::wstring& b) {
    return ::CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) - CSTR_EQUAL;
}

void drawBorder(HDC dc, const RECT& rc, COLORREF color) {
    HBRUSH br = cachedSolidBrush(color);
    RECT top    { rc.left,      rc.top,        rc.right,     rc.top + 1 };
    RECT bottom { rc.left,      rc.bottom - 1, rc.right,     rc.bottom };
    RECT left   { rc.left,      rc.top,        rc.left + 1,  rc.bottom };
    RECT right  { rc.right - 1, rc.top,        rc.right,     rc.bottom };
    ::FillRect(dc, &top,    br);
    ::FillRect(dc, &bottom, br);
    ::FillRect(dc, &left,   br);
    ::FillRect(dc, &right,  br);
}

bool hostHasPort(const ScanResult& r, int port) {
    for (const auto& p : r.ports) {
        if (p.isOpen && p.port == port) return true;
    }
    return false;
}

std::wstring buildCsvLine(const ScanResult& r) {
    std::wstring s;
    auto add = [&](const std::wstring& v) {
        if (!s.empty()) s += L",";
        if (v.find(L',') != std::wstring::npos || v.find(L'"') != std::wstring::npos) {
            std::wstring esc = v;
            size_t pos = 0;
            while ((pos = esc.find(L'"', pos)) != std::wstring::npos) {
                esc.replace(pos, 1, L"\"\"");
                pos += 2;
            }
            s += L"\"" + esc + L"\"";
        } else {
            s += v;
        }
    };
    add(r.ipAddress);
    add(r.statusText());
    add(r.hostname);
    add(r.vendor);
    add(r.macAddress);
    add(r.openPortsText());
    add(RiskLevelToString(r.riskLevel));
    add(r.riskHints);
    add(r.isOnline ? std::to_wstring(r.responseTimeMs) : std::wstring());
    add(DiscoveryMethodToString(r.discovery));
    return s;
}

void copyToClipboard(HWND owner, const std::wstring& s) {
    if (s.empty() || !::OpenClipboard(owner)) return;
    ::EmptyClipboard();
    const size_t bytes = (s.size() + 1) * sizeof(wchar_t);
    HGLOBAL hg = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hg) {
        auto* p = static_cast<wchar_t*>(::GlobalLock(hg));
        if (p) {
            std::memcpy(p, s.c_str(), bytes);
            ::GlobalUnlock(hg);
            ::SetClipboardData(CF_UNICODETEXT, hg);
        } else {
            ::GlobalFree(hg);
        }
    }
    ::CloseClipboard();
}

void shellOpen(HWND owner, const std::wstring& file, const std::wstring& args) {
    ::ShellExecuteW(owner, L"open", file.c_str(),
                    args.empty() ? nullptr : args.c_str(),
                    nullptr, SW_SHOWNORMAL);
}

// Context-menu command IDs.
// Recommend a parallel-worker count for the host machine at GUI startup.
// LAN scanning is network-bound — workers spend most of their time blocked
// in select() — so we comfortably oversubscribe logical cores. The engine
// also clamps the runtime value to min(parallel, hosts-to-scan), so an
// over-tuned baseline never burns extra threads on a tiny /24 sweep.
//
//   2 cores  →  128 workers
//   4 cores  →  256
//   8 cores  →  512
//  16 cores  → 1024
//  24 cores  → 1536  (e.g. i9-12900K — 8P+8E with HT on the P-cores)
//  32 cores  → 2048
//  64+ cores → 2048  (capped by kMaxParallel)
int recommendedParallel() {
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    int cores = static_cast<int>(si.dwNumberOfProcessors);
    if (cores <= 0) cores = 4;
    int parallel = cores * 64;
    if (parallel < kMinParallel) parallel = kMinParallel;
    if (parallel > kMaxParallel) parallel = kMaxParallel;
    return parallel;
}

constexpr UINT kCtxCopyIp    = 6001;
constexpr UINT kCtxCopyMac   = 6002;
constexpr UINT kCtxCopyHost  = 6003;
constexpr UINT kCtxCopyRow   = 6004;
constexpr UINT kCtxOpenHttp  = 6010;
constexpr UINT kCtxOpenHttps = 6011;
constexpr UINT kCtxRdp       = 6020;
constexpr UINT kCtxSsh       = 6021;
constexpr UINT kCtxPing      = 6030;
constexpr UINT kCtxMonitor   = 6040;

} // anonymous namespace

// =============================================================================
// Construction / WndProc plumbing
// =============================================================================

MainWindow::MainWindow() : scanner_(std::make_unique<NetworkScanner>()) {
    settingsTimeoutMs_ = kDefaultTimeoutMs;
    // Auto-tune the parallel-workers default to the host's logical-core count.
    // The Settings dialog still lets the user override it.
    settingsParallel_  = recommendedParallel();
}

MainWindow::~MainWindow() {
    // Join the driver thread before anything else: the worker captures
    // `mainWnd` and PostMessages a heap ScanFinishedPayload* on exit. Once
    // the message pump for this window stops draining (we're already past
    // WM_DESTROY by the time we hit here), any payload that's still queued
    // would leak. PostMessage to a dead HWND returns FALSE and the lambda
    // deletes the payload itself, so as long as the driver has joined we
    // can't leak. Joining synchronously here is the cheapest way to enforce
    // that ordering.
    if (scanner_) {
        scanner_->cancel();
        scanner_.reset();
    }
    // Drain any WM_NL_SCAN_FINISHED that arrived between cancel() and now.
    // The window is gone, so the WndProc won't be called for these messages
    // again — peek-and-delete the payload manually.
    MSG msg;
    while (::PeekMessageW(&msg, hwnd_, WM_NL_SCAN_FINISHED, WM_NL_SCAN_FINISHED,
                          PM_REMOVE)) {
        auto* payload = reinterpret_cast<ScanFinishedPayload*>(msg.lParam);
        delete payload;
    }
    if (bodyFont_)          ::DeleteObject(bodyFont_);
    if (labelFont_)         ::DeleteObject(labelFont_);
    if (kpiLabelFont_)      ::DeleteObject(kpiLabelFont_);
    if (kpiValueFont_)      ::DeleteObject(kpiValueFont_);
    if (buttonFont_)        ::DeleteObject(buttonFont_);
    if (primaryBtnFont_)    ::DeleteObject(primaryBtnFont_);
    if (sectionFont_)       ::DeleteObject(sectionFont_);
    if (sidebarBrandFont_)  ::DeleteObject(sidebarBrandFont_);
    if (sidebarNavFont_)    ::DeleteObject(sidebarNavFont_);
    if (sidebarFootFont_)   ::DeleteObject(sidebarFootFont_);
    if (iconFontMed_)       ::DeleteObject(iconFontMed_);
    if (iconFontLarge_)     ::DeleteObject(iconFontLarge_);
}

LRESULT CALLBACK MainWindow::staticWndProc(HWND hWnd, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(l);
        auto* self = static_cast<MainWindow*>(cs->lpCreateParams);
        self->hwnd_ = hWnd;
        ::SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    auto* self = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    if (self) return self->instanceWndProc(msg, w, l);
    return ::DefWindowProcW(hWnd, msg, w, l);
}

bool MainWindow::create(HINSTANCE hInst) {
    hInst_ = hInst;

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &MainWindow::staticWndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = cachedSolidBrush(kBgApp);
    wc.lpszClassName = kClassName;
    wc.lpszMenuName  = MAKEINTRESOURCEW(IDR_MAIN_MENU);
    wc.hIcon         = ::LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hIconSm       = ::LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APP_ICON));
    if (!wc.hIcon)   wc.hIcon   = ::LoadIcon(nullptr, IDI_APPLICATION);
    if (!wc.hIconSm) wc.hIconSm = wc.hIcon;
    if (!::RegisterClassExW(&wc)) return false;

    const int designW = 1360;
    const int designH = 860;
    int dpi = dpiFor(nullptr);
    int w = MulDiv(designW, dpi, 96);
    int h = MulDiv(designH, dpi, 96);
    int x = (::GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (::GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;

    HWND hwnd = ::CreateWindowExW(
        0, kClassName,
        std::wstring(std::wstring(kAppName) + L" " + kAppVersion).c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        x, y, w, h, nullptr, nullptr, hInst, this);
    return hwnd != nullptr;
}

void MainWindow::show(int nShowCmd) {
    ::ShowWindow(hwnd_, nShowCmd);
    ::UpdateWindow(hwnd_);
}

LRESULT MainWindow::instanceWndProc(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:                onCreate(); return 0;
        case WM_SIZE:                  onSize(LOWORD(lParam), HIWORD(lParam)); return 0;

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            int dpi = dpiFor(hwnd_);
            mmi->ptMinTrackSize.x = MulDiv(1180, dpi, 96);
            mmi->ptMinTrackSize.y = MulDiv(720,  dpi, 96);
            return 0;
        }

        case WM_PAINT:                 onPaint(); return 0;
        case WM_ERASEBKGND:            return 1;
        case WM_DRAWITEM:              return onDrawItem(reinterpret_cast<LPDRAWITEMSTRUCT>(lParam));
        case WM_COMMAND:
            onCommand(LOWORD(wParam), HIWORD(wParam), reinterpret_cast<HWND>(lParam));
            return 0;
        case WM_NOTIFY:                return onNotify(reinterpret_cast<LPNMHDR>(lParam));

        case WM_TIMER:
            if (wParam == IDT_FLUSH) {
                flushPending();
            } else if (wParam == IDT_SEARCH_DEBOUNCE) {
                ::KillTimer(hwnd_, IDT_SEARCH_DEBOUNCE);
                rebuildVisibleRows();
                updateResultsCountLabel();
            }
            return 0;

        case WM_CLOSE:                 onClose(); return 0;
        case WM_DESTROY:
            ::KillTimer(hwnd_, IDT_FLUSH);
            ::KillTimer(hwnd_, IDT_SEARCH_DEBOUNCE);
            ::PostQuitMessage(0);
            return 0;

        case WM_CTLCOLORSTATIC: {
            HDC  dc  = reinterpret_cast<HDC>(wParam);
            HWND ctl = reinterpret_cast<HWND>(lParam);
            ::SetBkMode(dc, TRANSPARENT);
            if (ctl == lblResultsTitle_) {
                ::SetTextColor(dc, kFgPrimary);
            } else if (ctl == lblResultsCount_ || ctl == lblPorts_ || ctl == lblFilter_) {
                ::SetTextColor(dc, kFgSecondary);
            } else if (ctl == status_) {
                ::SetTextColor(dc, kFgPrimary);
            } else {
                bool handled = false;
                for (int i = 0; i < 4; ++i) {
                    if (ctl == cards_[i])     { ::SetTextColor(dc, kFgPrimary);  handled = true; break; }
                    if (ctl == cardLbls_[i])  { ::SetTextColor(dc, kFgSecondary); handled = true; break; }
                }
                if (!handled) ::SetTextColor(dc, kFgPrimary);
            }
            return reinterpret_cast<LRESULT>(cachedSolidBrush(kBgCard));
        }

        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, OPAQUE);
            ::SetTextColor(dc, kFgPrimary);
            ::SetBkColor(dc, kBgCard);
            return reinterpret_cast<LRESULT>(cachedSolidBrush(kBgCard));
        }

        case WM_NL_SCAN_FINISHED: {
            // Take ownership of the heap payload posted by the scanner thread,
            // move the summary + results into our members on the UI thread
            // (where they're allowed to live), then run the regular finished
            // handler. wParam carries the cancelled flag as a fallback for
            // the legacy code path that doesn't allocate a payload.
            auto* payload = reinterpret_cast<ScanFinishedPayload*>(lParam);
            bool cancelled = (wParam != 0);
            if (payload) {
                lastResults_ = std::move(payload->results);
                lastSummary_ = std::move(payload->summary);
                cancelled    = payload->cancelled;
                delete payload;
            }
            ::KillTimer(hwnd_, IDT_FLUSH);
            flushPending();
            onScanFinished(cancelled);
            return 0;
        }

        case WM_NL_STATUS: {
            auto* s = reinterpret_cast<std::wstring*>(lParam);
            if (s) { setStatus(*s); delete s; }
            return 0;
        }
    }
    return ::DefWindowProcW(hwnd_, msg, wParam, lParam);
}

// =============================================================================
// Owner-draw
// =============================================================================

LRESULT MainWindow::onDrawItem(LPDRAWITEMSTRUCT dis) {
    if (!dis) return 0;

    #pragma warning(suppress: 4127)
    if (kSidebarEnabled &&
        (dis->CtlID == IDC_NAV_SCANNER ||
         dis->CtlID == IDC_NAV_SETTINGS ||
         dis->CtlID == IDC_NAV_ABOUT))
    {
        const wchar_t* glyph = L"";
        const wchar_t* label = L"";
        bool active = false;
        switch (dis->CtlID) {
            case IDC_NAV_SCANNER:  glyph = kGlyphScanner;  label = L"Scanner";  active = true; break;
            case IDC_NAV_SETTINGS: glyph = kGlyphSettings; label = L"Settings"; break;
            case IDC_NAV_ABOUT:    glyph = kGlyphAbout;    label = L"About";    break;
        }
        drawNavButton(dis, glyph, label, active);
        return TRUE;
    }

    if (dis->CtlID == IDC_ADAPTER_BTN) {
        drawAdapterButton(dis);
        return TRUE;
    }

    if (dis->CtlID != IDC_START_BTN) return 0;

    const bool disabled = (dis->itemState & ODS_DISABLED) != 0;
    const bool pressed  = (dis->itemState & ODS_SELECTED) != 0;
    const bool focused  = (dis->itemState & ODS_FOCUS)    != 0;

    COLORREF bg, edge, fg;
    if (disabled) {
        bg = RGB(220, 224, 232); edge = bg; fg = RGB(150, 158, 172);
    } else if (scanning_) {
        bg   = pressed ? kFgDangerDown  : kFgDanger;
        edge = kFgDangerDown;
        fg   = kFgWhite;
    } else {
        bg   = pressed ? kFgSuccessDown : kFgSuccess;
        edge = kFgSuccessDown;
        fg   = kFgWhite;
    }

    RECT rc = dis->rcItem;
    ::FillRect(dis->hDC, &rc, cachedSolidBrush(bg));
    if (!disabled) {
        RECT shade{ rc.left, rc.bottom - 2, rc.right, rc.bottom };
        ::FillRect(dis->hDC, &shade, cachedSolidBrush(edge));
    }
    if (focused && !disabled) {
        RECT ir{ rc.left + 2, rc.top + 2, rc.right - 2, rc.bottom - 2 };
        drawBorder(dis->hDC, ir, RGB(255, 255, 255));
    }

    wchar_t buf[64] = {};
    int len = ::GetWindowTextW(dis->hwndItem, buf, 63);
    if (len > 0) {
        HFONT prev = (HFONT)::SelectObject(
            dis->hDC, primaryBtnFont_ ? primaryBtnFont_ : buttonFont_);
        ::SetBkMode(dis->hDC, TRANSPARENT);
        ::SetTextColor(dis->hDC, fg);
        ::DrawTextW(dis->hDC, buf, len, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        ::SelectObject(dis->hDC, prev);
    }
    return TRUE;
}

void MainWindow::drawAdapterButton(LPDRAWITEMSTRUCT dis) {
    const bool pressed  = (dis->itemState & ODS_SELECTED) != 0;
    const bool disabled = (dis->itemState & ODS_DISABLED) != 0;
    RECT rc = dis->rcItem;

    COLORREF bg = disabled ? kBgAdapterBtn
                : (pressed ? kBgSidebarActive : kBgAdapterBtn);
    ::FillRect(dis->hDC, &rc, cachedSolidBrush(bg));
    drawBorder(dis->hDC, rc, kBorder);

    if (iconFontMed_) {
        HFONT prev = (HFONT)::SelectObject(dis->hDC, iconFontMed_);
        ::SetBkMode(dis->hDC, TRANSPARENT);
        ::SetTextColor(dis->hDC, disabled ? kFgMuted : kFgAccent);
        ::DrawTextW(dis->hDC, kGlyphAdapter, -1, &rc,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        ::SelectObject(dis->hDC, prev);
    }
}

void MainWindow::drawNavButton(LPDRAWITEMSTRUCT dis,
                               const wchar_t* glyph, const wchar_t* label,
                               bool active)
{
    if (!dis) return;
    const bool pressed = (dis->itemState & ODS_SELECTED) != 0;
    RECT rc = dis->rcItem;
    COLORREF bg, fg, accent;
    if (active) { bg = kBgSidebarActive; fg = kFgAccent;    accent = kFgAccent; }
    else if (pressed) { bg = kBgSidebarHover; fg = kFgPrimary; accent = 0; }
    else { bg = kBgSidebar; fg = kFgSecondary; accent = 0; }
    ::FillRect(dis->hDC, &rc, cachedSolidBrush(bg));
    if (active) {
        RECT stripe{ rc.left, rc.top + 4, rc.left + 3, rc.bottom - 4 };
        ::FillRect(dis->hDC, &stripe, cachedSolidBrush(accent));
    }
    ::SetBkMode(dis->hDC, TRANSPARENT);
    ::SetTextColor(dis->hDC, fg);
    int padL = MulDiv(16, dpiFor(hwnd_), 96);
    int iconW = MulDiv(22, dpiFor(hwnd_), 96);
    if (glyph && glyph[0] && iconFontMed_) {
        HFONT prev = (HFONT)::SelectObject(dis->hDC, iconFontMed_);
        RECT gr{ rc.left + padL, rc.top, rc.left + padL + iconW, rc.bottom };
        ::DrawTextW(dis->hDC, glyph, -1, &gr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        ::SelectObject(dis->hDC, prev);
    }
    if (label && label[0] && sidebarNavFont_) {
        HFONT prev = (HFONT)::SelectObject(dis->hDC, sidebarNavFont_);
        RECT tr{ rc.left + padL + iconW + MulDiv(10, dpiFor(hwnd_), 96),
                 rc.top, rc.right - padL, rc.bottom };
        ::DrawTextW(dis->hDC, label, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        ::SelectObject(dis->hDC, prev);
    }
}

// =============================================================================
// onCreate
// =============================================================================

void MainWindow::onCreate() {
    bodyFont_         = createUiFont(hwnd_, 10, false);
    labelFont_        = createUiFont(hwnd_, 9,  false);
    sectionFont_      = createUiFont(hwnd_, 11, true);
    kpiLabelFont_     = createUiFont(hwnd_, 9,  false);
    kpiValueFont_     = createUiFont(hwnd_, 22, true);
    buttonFont_       = createUiFont(hwnd_, 10, false);
    primaryBtnFont_   = createUiFont(hwnd_, 11, true);
    sidebarBrandFont_ = createUiFont(hwnd_, 13, true);
    sidebarNavFont_   = createUiFont(hwnd_, 10, false);
    sidebarFootFont_  = createUiFont(hwnd_, 8,  false);
    iconFontMed_      = createIconFont(hwnd_, 12);
    iconFontLarge_    = createIconFont(hwnd_, 18);

    auto setF = [&](HWND h, HFONT f) {
        ::SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), TRUE);
    };

    // Sidebar buttons — created but hidden when kSidebarEnabled == false.
    btnNavScanner_  = ::CreateWindowExW(0, L"BUTTON", L"Scanner",
                                        WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
                                        0, 0, 0, 0, hwnd_,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_NAV_SCANNER)),
                                        hInst_, nullptr);
    btnNavSettings_ = ::CreateWindowExW(0, L"BUTTON", L"Settings",
                                        WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
                                        0, 0, 0, 0, hwnd_,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_NAV_SETTINGS)),
                                        hInst_, nullptr);
    btnNavAbout_    = ::CreateWindowExW(0, L"BUTTON", L"About",
                                        WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
                                        0, 0, 0, 0, hwnd_,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_NAV_ABOUT)),
                                        hInst_, nullptr);
    if (kSidebarEnabled) {
        ::ShowWindow(btnNavScanner_, SW_SHOW);
        ::ShowWindow(btnNavSettings_, SW_SHOW);
        ::ShowWindow(btnNavAbout_, SW_SHOW);
    }

    // ---- Top row: IP range / adapter icon / profile / start ----------------
    // Use WS_BORDER (flat 1px themed border) instead of WS_EX_CLIENTEDGE
    // (3D sunken border). The sunken border eats ~4 px of vertical content
    // area, making EDITs look noticeably shorter than the themed flat
    // combo box next to them at the same MoveWindow height. WS_BORDER
    // renders the same themed flat outline as the combobox.
    edRange_ = ::CreateWindowExW(0, L"EDIT", L"192.168.1.1-254",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                                 0, 0, 0, 0, hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_RANGE_EDIT)),
                                 hInst_, nullptr);
    setF(edRange_, bodyFont_);
    ::SendMessageW(edRange_, EM_SETCUEBANNER, TRUE,
                   reinterpret_cast<LPARAM>(L"IP range — 192.168.1.1-254, 10.0.0.0/24..."));

    btnAdapter_ = ::CreateWindowExW(0, L"BUTTON", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                                    0, 0, 0, 0, hwnd_,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_ADAPTER_BTN)),
                                    hInst_, nullptr);

    cbPreset_ = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                  0, 0, 0, 0, hwnd_,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PRESET_COMBO)),
                                  hInst_, nullptr);
    setF(cbPreset_, bodyFont_);

    btnStart_ = ::CreateWindowExW(0, L"BUTTON", L"Start scan",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                                  0, 0, 0, 0, hwnd_,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_START_BTN)),
                                  hInst_, nullptr);
    setF(btnStart_, primaryBtnFont_);

    // ---- Custom-ports row (hidden by default) ------------------------------
    lblPorts_ = ::CreateWindowExW(0, L"STATIC", L"Custom ports",
                                  WS_CHILD | SS_LEFT,
                                  0, 0, 0, 0, hwnd_, nullptr, hInst_, nullptr);
    setF(lblPorts_, labelFont_);

    edPorts_ = ::CreateWindowExW(0, L"EDIT", L"",
                                 WS_CHILD | WS_TABSTOP | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                                 0, 0, 0, 0, hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PORTS_EDIT)),
                                 hInst_, nullptr);
    setF(edPorts_, bodyFont_);
    ::SendMessageW(edPorts_, EM_SETCUEBANNER, TRUE,
                   reinterpret_cast<LPARAM>(L"TCP ports — supports ranges, e.g. 22,80,443,8000-8010,3389"));

    // ---- KPI strip (4 cards) — hidden until first scan ---------------------
    const wchar_t* kCardLabels[4] = {
        L"Online hosts", L"Progress", L"Time remaining", L"Duration"
    };
    for (int i = 0; i < 4; ++i) {
        cards_[i] = ::CreateWindowExW(0, L"STATIC", i == 0 ? L"0" : L"—",
                                      WS_CHILD | SS_LEFT,
                                      0, 0, 0, 0, hwnd_,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CARD_TOTAL + i)),
                                      hInst_, nullptr);
        setF(cards_[i], kpiValueFont_);

        cardLbls_[i] = ::CreateWindowExW(0, L"STATIC", kCardLabels[i],
                                         WS_CHILD | SS_LEFT,
                                         0, 0, 0, 0, hwnd_, nullptr, hInst_, nullptr);
        setF(cardLbls_[i], kpiLabelFont_);
    }

    // ---- Results toolbar ---------------------------------------------------
    lblResultsTitle_ = ::CreateWindowExW(0, L"STATIC", L"Scan results",
                                         WS_CHILD | WS_VISIBLE | SS_LEFT,
                                         0, 0, 0, 0, hwnd_,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_RESULTS_TITLE)),
                                         hInst_, nullptr);
    setF(lblResultsTitle_, sectionFont_);

    lblResultsCount_ = ::CreateWindowExW(0, L"STATIC", L"No results yet.",
                                         WS_CHILD | WS_VISIBLE | SS_LEFT,
                                         0, 0, 0, 0, hwnd_,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_RESULTS_COUNT)),
                                         hInst_, nullptr);
    setF(lblResultsCount_, labelFont_);

    lblFilter_ = ::CreateWindowExW(0, L"STATIC", L"Filter",
                                   WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   0, 0, 0, 0, hwnd_, nullptr, hInst_, nullptr);
    setF(lblFilter_, labelFont_);

    cbFilter_ = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                  0, 0, 0, 0, hwnd_,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FILTER_COMBO)),
                                  hInst_, nullptr);
    setF(cbFilter_, bodyFont_);
    {
        std::vector<std::wstring> items = {
            L"All hosts", L"High risk", L"Medium risk", L"Low risk",
            L"Online only", L"Offline only"
        };
        cbFill(cbFilter_, items, 0);
    }

    edSearch_ = ::CreateWindowExW(0, L"EDIT", L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                                  0, 0, 0, 0, hwnd_,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_SEARCH_EDIT)),
                                  hInst_, nullptr);
    setF(edSearch_, bodyFont_);
    ::SendMessageW(edSearch_, EM_SETCUEBANNER, TRUE,
                   reinterpret_cast<LPARAM>(L"Search IP, hostname, vendor, ports..."));

    chkHideOffline_ = ::CreateWindowExW(0, L"BUTTON", L"Hide offline hosts",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        0, 0, 0, 0, hwnd_,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_HIDE_OFFLINE_CHECK)),
                                        hInst_, nullptr);
    setF(chkHideOffline_, bodyFont_);
    ::SendMessageW(chkHideOffline_, BM_SETCHECK, BST_CHECKED, 0);

    // ---- ListView ----------------------------------------------------------
    list_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                              LVS_SHOWSELALWAYS | LVS_SINGLESEL,
                              0, 0, 0, 0, hwnd_,
                              reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_RESULTS_LIST)),
                              hInst_, nullptr);
    setF(list_, bodyFont_);
    ListView_SetExtendedListViewStyle(list_,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP |
        LVS_EX_LABELTIP);
    ::SetWindowTheme(list_, L"Explorer", nullptr);

    int dpi = dpiFor(hwnd_);
    auto px = [&](int v){ return MulDiv(v, dpi, 96); };
    for (int i = 0; i < kColumnCount; ++i) {
        lvAddColumn(list_, i, kColumns[i].title, px(kColumns[i].width));
    }

    // ---- Bottom action bar -------------------------------------------------
    progress_ = ::CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
                                  WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                  0, 0, 0, 0, hwnd_,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PROGRESS)),
                                  hInst_, nullptr);
    pbConfigure(progress_, 1);

    status_ = ::CreateWindowExW(0, L"STATIC", L"Ready.",
                                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
                                0, 0, 0, 0, hwnd_,
                                reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS)),
                                hInst_, nullptr);
    setF(status_, bodyFont_);

    btnClear_ = ::CreateWindowExW(0, L"BUTTON", L"Clear results",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                  0, 0, 0, 0, hwnd_,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CLEAR_BTN)),
                                  hInst_, nullptr);
    setF(btnClear_, buttonFont_);

    btnExportCsv_ = ::CreateWindowExW(0, L"BUTTON", L"Export CSV",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
                                      0, 0, 0, 0, hwnd_,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_EXPORT_CSV_BTN)),
                                      hInst_, nullptr);
    setF(btnExportCsv_, buttonFont_);

    btnExportHtml_ = ::CreateWindowExW(0, L"BUTTON", L"Export HTML report",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
                                       0, 0, 0, 0, hwnd_,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_EXPORT_HTML_BTN)),
                                       hInst_, nullptr);
    setF(btnExportHtml_, buttonFont_);

    // ---- Profile combo + tooltip for the adapter button --------------------
    rebuildPresetCombo(0);

    tipAdapter_ = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                    WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                    CW_USEDEFAULT, CW_USEDEFAULT,
                                    CW_USEDEFAULT, CW_USEDEFAULT,
                                    hwnd_, nullptr, hInst_, nullptr);
    if (tipAdapter_) {
        TOOLINFOW ti{};
        ti.cbSize    = sizeof(ti);
        ti.uFlags    = TTF_IDISHWND | TTF_SUBCLASS;
        ti.hwnd      = hwnd_;
        ti.uId       = reinterpret_cast<UINT_PTR>(btnAdapter_);
        ti.lpszText  = const_cast<LPWSTR>(L"Select network adapter — auto-fills the IP range");
        ::SendMessageW(tipAdapter_, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&ti));
        ::SendMessageW(tipAdapter_, TTM_SETMAXTIPWIDTH, 0, 400);
    }

    refreshAdapters();
    onPresetChanged();
    updateResultsCountLabel();
    setStatus(L"Ready.");
}

// =============================================================================
// Layout
// =============================================================================

void MainWindow::onSize(int, int) {
    layoutChildren();
    ::RedrawWindow(hwnd_, nullptr, nullptr,
                   RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

void MainWindow::layoutChildren() {
    RECT rc; ::GetClientRect(hwnd_, &rc);
    int dpi = dpiFor(hwnd_);
    auto px = [&](int v){ return MulDiv(v, dpi, 96); };

    const int marginX    = px(20);
    const int marginTop  = px(16);
    const int gap        = px(10);
    const int rowH       = px(32);
    const int btnH       = px(36);
    const int lblH       = px(16);

    // Sidebar (hidden when kSidebarEnabled is false — sidebarW becomes 0).
    const int sidebarW = kSidebarEnabled ? px(kSidebarWidth) : 0;
    rectSidebar_ = RECT{ 0, 0, sidebarW, rc.bottom };
    if (kSidebarEnabled) {
        int navY = px(110);
        int navH = px(40);
        int navGap = px(2);
        ::MoveWindow(btnNavScanner_,  px(8), navY,                 sidebarW - px(16), navH, TRUE);
        ::MoveWindow(btnNavSettings_, px(8), navY + navH + navGap, sidebarW - px(16), navH, TRUE);
        ::MoveWindow(btnNavAbout_,    px(8), navY + 2 * (navH + navGap), sidebarW - px(16), navH, TRUE);
    }

    const int contentX = sidebarW;
    const int contentR = rc.right;
    const int innerL   = contentX + marginX;
    const int innerR   = contentR - marginX;
    const int innerW   = innerR - innerL;

    // -------------------------------------------------------------------------
    // Top row: [IP range -----------] [adapter ⚇] [Profile ▼] [Start scan]
    // Card aligned exactly with innerL/innerR (matches KPI band and Scan
    // results card). Controls sit inset by topCardPadX from the card edges
    // so they don't touch the 1px border.
    // -------------------------------------------------------------------------
    const int topCardPadY = px(12);
    const int topCardPadX = px(14);
    int y = marginTop;
    int topRowY = y + topCardPadY;
    int topInnerL = innerL + topCardPadX;
    int topInnerR = innerR - topCardPadX;
    int topInnerW = topInnerR - topInnerL;

    int presetW = px(170);
    int startW  = px(160);

    // Probe the themed combo's natural rendered height first. CBS_DROPDOWNLIST
    // combos enforce a per-font minimum (typically a few pixels taller than
    // what we pass) and render that way regardless of MoveWindow. We unify
    // every control in this row to that same height so edit, combo, adapter
    // icon button and Start scan all line up at top AND bottom — no mix of
    // tall buttons with shorter inputs.
    ::MoveWindow(cbPreset_, topInnerL, topRowY, presetW, rowH, TRUE);
    RECT cbRect;
    ::GetWindowRect(cbPreset_, &cbRect);
    int ctrlH = cbRect.bottom - cbRect.top;
    if (ctrlH < px(18) || ctrlH > px(64)) ctrlH = rowH;

    int adapterBtnW = ctrlH;  // square icon button, matches row height
    int rangeW = topInnerW - adapterBtnW - presetW - startW - 3 * gap;
    if (rangeW < px(280)) rangeW = px(280);

    int x = topInnerL;
    int rangeX   = x;            x += rangeW + gap;
    int adapterX = x;            x += adapterBtnW + gap;
    int presetX  = x;
    int startX   = topInnerR - startW;

    ::MoveWindow(edRange_,    rangeX,   topRowY, rangeW,      ctrlH, TRUE);
    ::MoveWindow(btnAdapter_, adapterX, topRowY, adapterBtnW, ctrlH, TRUE);
    ::MoveWindow(cbPreset_,   presetX,  topRowY, presetW,     ctrlH, TRUE);
    ::MoveWindow(btnStart_,   startX,   topRowY, startW,      ctrlH, TRUE);

    int topCardH = topCardPadY * 2 + ctrlH;
    rectTopRow_ = RECT{ innerL, y, innerR, y + topCardH };

    y += topCardH + gap;

    // -------------------------------------------------------------------------
    // Custom-ports row (visible only when customPortsMode_) — aligned with
    // the top row card edges.
    // -------------------------------------------------------------------------
    if (customPortsMode_) {
        int customPadY = px(10);
        int rowY = y + customPadY;
        int lblW = px(110);
        ::MoveWindow(lblPorts_, topInnerL,             rowY + (rowH - lblH) / 2,
                     lblW, lblH, TRUE);
        ::MoveWindow(edPorts_,  topInnerL + lblW + gap, rowY,
                     topInnerW - lblW - gap, rowH, TRUE);
        int customCardH = customPadY * 2 + rowH;
        rectCustomRow_ = RECT{ innerL, y, innerR, y + customCardH };
        y += customCardH + gap;
    } else {
        rectCustomRow_ = RECT{0, 0, 0, 0};
    }

    // -------------------------------------------------------------------------
    // KPI strip — 3 cards. Only visible after the first scan has started.
    // -------------------------------------------------------------------------
    if (hasScannedOnce_) {
        int kpiCardH = px(76);
        rectKpiBand_ = RECT{ innerL, y, innerR, y + kpiCardH };
        int kpiGap = px(10);
        int kpiW = (innerW - 3 * kpiGap) / 4;
        for (int i = 0; i < 4; ++i) {
            int kx = innerL + i * (kpiW + kpiGap);
            rectKpiCard_[i] = RECT{ kx, y, kx + kpiW, y + kpiCardH };
            int textX = kx + px(14);
            int textW = kpiW - px(48);
            if (textW < px(80)) textW = px(80);
            ::MoveWindow(cards_[i],    textX, y + px(14), textW, px(34), TRUE);
            ::MoveWindow(cardLbls_[i], textX, y + px(50), textW, px(18), TRUE);
        }
        y += kpiCardH + gap;
    } else {
        rectKpiBand_ = RECT{0, 0, 0, 0};
        for (int i = 0; i < 4; ++i) rectKpiCard_[i] = RECT{0, 0, 0, 0};
    }

    // -------------------------------------------------------------------------
    // Results toolbar.
    // -------------------------------------------------------------------------
    int barH = px(56);
    rectResultsBar_ = RECT{ innerL, y, innerR, y + barH };
    int cardPad = px(14);
    ::MoveWindow(lblResultsTitle_, innerL + cardPad, y + px(8),  px(200), px(22), TRUE);
    ::MoveWindow(lblResultsCount_, innerL + cardPad, y + px(30), px(420), px(18), TRUE);

    int searchW = px(220);
    int filterW = px(150);
    int hideW   = px(150);
    int rx = innerR - cardPad;
    int hideX   = rx - hideW;
    int searchX = hideX - gap - searchW;
    int filterX = searchX - gap - filterW;
    int filterLblX = filterX - px(40);

    // Same trick as the top row: query the themed filter combo's real
    // closed height so the search edit can match it pixel-perfect.
    int probeY = y + px(14);
    ::MoveWindow(cbFilter_, filterX, probeY, filterW, rowH, TRUE);
    RECT fbRect;
    ::GetWindowRect(cbFilter_, &fbRect);
    int filterRenderedH = fbRect.bottom - fbRect.top;
    if (filterRenderedH < px(18) || filterRenderedH > px(64)) {
        filterRenderedH = rowH;
    }
    int ctrlY = y + (barH - filterRenderedH) / 2;

    ::MoveWindow(cbFilter_,       filterX,    ctrlY,                filterW, filterRenderedH, TRUE);
    ::MoveWindow(edSearch_,       searchX,    ctrlY,                searchW, filterRenderedH, TRUE);
    ::MoveWindow(chkHideOffline_, hideX,      ctrlY,                hideW,   filterRenderedH, TRUE);
    ::MoveWindow(lblFilter_,      filterLblX, ctrlY + (filterRenderedH - lblH) / 2,
                                                                    px(36),  lblH,            TRUE);

    y += barH + gap;

    // -------------------------------------------------------------------------
    // Bottom bar (pinned to the bottom edge).
    // -------------------------------------------------------------------------
    int bottomH = px(62);
    int bottomY = rc.bottom - bottomH;
    rectBottomBar_ = RECT{ contentX, bottomY, contentR, rc.bottom };
    int bInnerX = innerL;
    int bInnerR = innerR;
    int expHtmlW = px(160);
    int expCsvW  = px(110);
    int clearW   = px(120);
    int bx = bInnerR;
    int htmlX  = bx - expHtmlW;                bx = htmlX - gap;
    int csvX   = bx - expCsvW;                 bx = csvX  - gap;
    int clearX = bx - clearW;
    ::MoveWindow(btnExportHtml_, htmlX,  bottomY + px(14), expHtmlW, btnH, TRUE);
    ::MoveWindow(btnExportCsv_,  csvX,   bottomY + px(14), expCsvW,  btnH, TRUE);
    ::MoveWindow(btnClear_,      clearX, bottomY + px(14), clearW,   btnH, TRUE);
    int leftW = clearX - bInnerX - gap;
    if (leftW < px(200)) leftW = px(200);
    ::MoveWindow(status_,   bInnerX, bottomY + px(10), leftW, px(18), TRUE);
    ::MoveWindow(progress_, bInnerX, bottomY + px(32), leftW, px(14), TRUE);

    // -------------------------------------------------------------------------
    // ListView fills the space between toolbar and bottom bar.
    // -------------------------------------------------------------------------
    int listY = y;
    int listH = bottomY - listY - gap;
    if (listH < px(120)) listH = px(120);
    ::MoveWindow(list_, innerL, listY, innerW, listH, TRUE);
}

// =============================================================================
// Painting
// =============================================================================

void MainWindow::onPaint() {
    PAINTSTRUCT ps;
    HDC dc = ::BeginPaint(hwnd_, &ps);

    RECT rc; ::GetClientRect(hwnd_, &rc);
    ::FillRect(dc, &rc, cachedSolidBrush(kBgApp));

    if (kSidebarEnabled) {
        paintSidebar(dc, rectSidebar_);
    }

    // Top row card backdrop (a single subtle white pill behind range + buttons).
    paintCardBackground(dc, rectTopRow_, false, kFgAccent);

    if (customPortsMode_) {
        paintCardBackground(dc, rectCustomRow_, false, kFgAccent);
    }

    if (hasScannedOnce_) {
        for (int i = 0; i < 4; ++i) {
            paintKpiCard(dc, i, rectKpiCard_[i]);
        }
    }

    paintCardBackground(dc, rectResultsBar_, false, kFgAccent);
    paintCardBackground(dc, rectBottomBar_,  false, kFgAccent);

    ::EndPaint(hwnd_, &ps);
}

void MainWindow::paintCardBackground(HDC dc, const RECT& rc, bool, COLORREF) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) return;
    ::FillRect(dc, &rc, cachedSolidBrush(kBgCard));
    drawBorder(dc, rc, kBorder);
}

void MainWindow::paintKpiCard(HDC dc, int index, const RECT& rc) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) return;
    int dpi = dpiFor(hwnd_);
    auto px = [&](int v){ return MulDiv(v, dpi, 96); };

    ::FillRect(dc, &rc, cachedSolidBrush(kBgCard));
    drawBorder(dc, rc, kBorder);

    RECT stripe{ rc.left, rc.top, rc.left + 4, rc.bottom };
    ::FillRect(dc, &stripe, cachedSolidBrush(kKpiAccents[index]));

    if (iconFontMed_) {
        HFONT prev = (HFONT)::SelectObject(dc, iconFontMed_);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, kKpiAccents[index]);
        RECT g{ rc.right - px(34), rc.top + px(10),
                rc.right - px(8),  rc.top + px(34) };
        ::DrawTextW(dc, kGlyphKpi[index], -1, &g,
                    DT_RIGHT | DT_TOP | DT_SINGLELINE);
        ::SelectObject(dc, prev);
    }
}

void MainWindow::paintSidebar(HDC dc, const RECT& rc) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) return;
    int dpi = dpiFor(hwnd_);
    auto px = [&](int v){ return MulDiv(v, dpi, 96); };

    ::FillRect(dc, &rc, cachedSolidBrush(kBgSidebar));
    RECT edge{ rc.right - 1, rc.top, rc.right, rc.bottom };
    ::FillRect(dc, &edge, cachedSolidBrush(kBorder));
    ::SetBkMode(dc, TRANSPARENT);

    if (iconFontLarge_) {
        HFONT prev = (HFONT)::SelectObject(dc, iconFontLarge_);
        ::SetTextColor(dc, kFgAccent);
        RECT gr{ rc.left + px(16), px(22), rc.left + px(56), px(54) };
        ::DrawTextW(dc, kGlyphBrand, -1, &gr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        ::SelectObject(dc, prev);
    }
    if (sidebarBrandFont_) {
        HFONT prev = (HFONT)::SelectObject(dc, sidebarBrandFont_);
        ::SetTextColor(dc, kFgPrimary);
        RECT tr{ rc.left + px(54), px(22), rc.right - px(8), px(46) };
        ::DrawTextW(dc, L"NetLens", -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        ::SelectObject(dc, prev);
    }
}

// =============================================================================
// Commands / notifications
// =============================================================================

void MainWindow::onCommand(WORD id, WORD notifyCode, HWND) {
    switch (id) {
        case IDM_FILE_EXPORT_CSV:
        case IDC_EXPORT_CSV_BTN:       exportCsv();           return;
        case IDM_FILE_EXPORT_HTML:
        case IDC_EXPORT_HTML_BTN:      exportHtml();          return;
        case IDM_FILE_EXIT:            ::PostMessageW(hwnd_, WM_CLOSE, 0, 0); return;
        case IDM_TOOLS_REFRESH:        refreshAdapters();     return;
        case IDM_TOOLS_CLEAR:
        case IDC_CLEAR_BTN:            clearResults();        return;
        case IDM_TOOLS_SETTINGS:       showSettingsDialog();  return;
        case IDM_TOOLS_PRESETS:        showPresetManager();   return;
        case IDM_TOOLS_ADAPTERS:
        case IDC_ADAPTER_BTN:          showAdapterDialog();   return;
        case IDM_HELP_ABOUT:           showAbout();           return;
        case IDC_START_BTN:
            if (scanning_) stopScan(); else startScan();
            return;
        case IDM_VIEW_HIDE_OFFLINE:    onMenuToggleHideOffline(); return;
        case IDC_NAV_SCANNER:                                  return;
        case IDC_NAV_SETTINGS:         showSettingsDialog();   return;
        case IDC_NAV_ABOUT:            showAbout();            return;
        case IDC_HIDE_OFFLINE_CHECK:
            if (notifyCode == BN_CLICKED) onHideOfflineToggled();
            return;
        case IDC_PRESET_COMBO:
            if (notifyCode == CBN_SELCHANGE) onPresetChanged();
            return;
        case IDC_FILTER_COMBO:
            if (notifyCode == CBN_SELCHANGE) onFilterChanged();
            return;
        case IDC_PORTS_EDIT:
            if (notifyCode == EN_CHANGE) onPortsEdited();
            return;
        case IDC_SEARCH_EDIT:
            if (notifyCode == EN_CHANGE) onSearchChanged();
            return;
    }
}

LRESULT MainWindow::onNotify(LPNMHDR nm) {
    if (!nm) return 0;
    if (nm->hwndFrom == list_) {
        if (nm->code == NM_CUSTOMDRAW) {
            return handleListCustomDraw(reinterpret_cast<LPNMLVCUSTOMDRAW>(nm));
        }
        if (nm->code == LVN_COLUMNCLICK) {
            auto* lv = reinterpret_cast<LPNMLISTVIEW>(nm);
            onColumnHeaderClicked(lv->iSubItem);
            return 0;
        }
        if (nm->code == NM_RCLICK) {
            auto* ia = reinterpret_cast<LPNMITEMACTIVATE>(nm);
            if (ia && ia->iItem >= 0) {
                ListView_SetItemState(list_, ia->iItem,
                                      LVIS_FOCUSED | LVIS_SELECTED,
                                      LVIS_FOCUSED | LVIS_SELECTED);
                showRowContextMenu(ia->iItem);
            }
            return 0;
        }
        if (nm->code == NM_DBLCLK) {
            auto* ia = reinterpret_cast<LPNMITEMACTIVATE>(nm);
            if (ia && ia->iItem >= 0) {
                if (const ScanResult* r = resultForRow(ia->iItem)) {
                    showHostDetailsDialog(*r);
                }
            }
            return 0;
        }
    }
    return 0;
}

void MainWindow::onClose() {
    if (scanning_) {
        if (::MessageBoxW(hwnd_,
                          L"A scan is currently running. Stop scan and exit?",
                          kAppName,
                          MB_OKCANCEL | MB_ICONQUESTION) != IDOK) {
            return;
        }
        if (scanner_) scanner_->cancel();
    }
    ::DestroyWindow(hwnd_);
}

// =============================================================================
// Filter / search / hide offline
// =============================================================================

void MainWindow::onFilterChanged() {
    filterIndex_ = cbSelectedIndex(cbFilter_);
    if (filterIndex_ < 0) filterIndex_ = 0;
    rebuildVisibleRows();
    updateResultsCountLabel();
}

void MainWindow::onSearchChanged() {
    searchText_ = trim(getText(edSearch_));
    ::SetTimer(hwnd_, IDT_SEARCH_DEBOUNCE, 200, nullptr);
}

void MainWindow::onMenuToggleHideOffline() {
    bool nowOn = !hideOffline_;
    ::SendMessageW(chkHideOffline_, BM_SETCHECK,
                   nowOn ? BST_CHECKED : BST_UNCHECKED, 0);
    onHideOfflineToggled();
}

void MainWindow::onHideOfflineToggled() {
    hideOffline_ = (::SendMessageW(chkHideOffline_, BM_GETCHECK, 0, 0) == BST_CHECKED);
    HMENU menu = ::GetMenu(hwnd_);
    if (menu) {
        ::CheckMenuItem(menu, IDM_VIEW_HIDE_OFFLINE,
                        MF_BYCOMMAND | (hideOffline_ ? MF_CHECKED : MF_UNCHECKED));
    }
    rebuildVisibleRows();
    updateResultsCountLabel();
}

bool MainWindow::resultMatchesSearch(const ScanResult& r) const {
    if (searchText_.empty()) return true;
    std::wstring q = toLower(searchText_);
    auto contains = [&](const std::wstring& f) {
        return !f.empty() && toLower(f).find(q) != std::wstring::npos;
    };
    if (contains(r.ipAddress)) return true;
    if (contains(r.hostname))  return true;
    if (contains(r.udp.netbiosName))      return true;
    if (contains(r.udp.netbiosWorkgroup)) return true;
    if (contains(r.udp.upnpServer))       return true;
    if (contains(r.udp.snmpSysDescr))     return true;
    if (contains(r.macAddress)) return true;
    if (contains(r.vendor)) return true;
    if (contains(r.riskHints)) return true;
    if (contains(r.openPortsText())) return true;
    if (contains(r.serviceLabelsText())) return true;
    if (contains(std::wstring(DiscoveryMethodToString(r.discovery)))) return true;
    if (contains(std::wstring(RiskLevelToString(r.riskLevel)))) return true;
    return false;
}

bool MainWindow::shouldShowResult(const ScanResult& r) const {
    if (hideOffline_ && !r.isOnline) return false;
    switch (filterIndex_) {
        case 0: break;
        case 1: if (r.riskLevel != RiskLevel::High)   return false; break;
        case 2: if (r.riskLevel != RiskLevel::Medium) return false; break;
        case 3: if (r.riskLevel != RiskLevel::Low)    return false; break;
        case 4: if (!r.isOnline) return false; break;
        case 5: if (r.isOnline)  return false; break;
    }
    if (!searchText_.empty() && !resultMatchesSearch(r)) return false;
    return true;
}

// =============================================================================
// Custom-draw
// =============================================================================

const ScanResult* MainWindow::resultForRow(int row) const {
    LVITEMW it{};
    it.mask  = LVIF_PARAM;
    it.iItem = row;
    if (!ListView_GetItem(list_, &it)) return nullptr;
    size_t idx = static_cast<size_t>(it.lParam);
    if (idx >= displayedResults_.size()) return nullptr;
    return &displayedResults_[idx];
}

LRESULT MainWindow::handleListCustomDraw(LPNMLVCUSTOMDRAW cd) {
    switch (cd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
            return CDRF_NOTIFYITEMDRAW;

        case CDDS_ITEMPREPAINT: {
            int row = static_cast<int>(cd->nmcd.dwItemSpec);
            const ScanResult* r = resultForRow(row);
            if (!r) return CDRF_DODEFAULT;

            const bool altRow = (row & 1) != 0;
            cd->clrTextBk = altRow ? kAltRowBg : kBgCard;
            cd->clrText   = r->isOnline ? kFgPrimary : kFgMuted;

            if (r->isOnline) {
                switch (r->riskLevel) {
                    case RiskLevel::High:
                        cd->clrTextBk = kRiskHighBg;
                        cd->clrText   = kRiskHighFg;
                        break;
                    case RiskLevel::Medium:
                        cd->clrTextBk = kRiskMedBg;
                        cd->clrText   = kRiskMedFg;
                        break;
                    case RiskLevel::Low:
                        cd->clrText   = kRiskLowFg;
                        break;
                    case RiskLevel::None:
                    default: break;
                }
            }
            return CDRF_NEWFONT | CDRF_NOTIFYSUBITEMDRAW;
        }

        case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
            int row = static_cast<int>(cd->nmcd.dwItemSpec);
            const ScanResult* r = resultForRow(row);
            if (!r) return CDRF_DODEFAULT;
            if (cd->iSubItem == COL_STATUS) {
                cd->clrText = r->isOnline ? kFgSuccess : kFgMuted;
            }
            return CDRF_NEWFONT;
        }
    }
    return CDRF_DODEFAULT;
}

// =============================================================================
// Sort
// =============================================================================

void MainWindow::onColumnHeaderClicked(int column) {
    if (column == sortColumn_) sortAscending_ = !sortAscending_;
    else { sortColumn_ = column; sortAscending_ = true; }
    applyListSort();
}

namespace {
int compareCells(const ScanResult& a, const ScanResult& b, int col) {
    switch (col) {
        case COL_IP:        return compareIp(a.ipAddress, b.ipAddress);
        case COL_STATUS:    return compareInt(a.isOnline ? 1 : 0, b.isOnline ? 1 : 0);
        case COL_HOSTNAME:  return compareStr(a.effectiveHostname(), b.effectiveHostname());
        case COL_VENDOR:    return compareStr(a.vendor, b.vendor);
        case COL_MAC:       return compareStr(a.macAddress, b.macAddress);
        case COL_PORTS:     return compareStr(a.openPortsText(), b.openPortsText());
        case COL_RISK:      return compareRisk(a.riskLevel, b.riskLevel);
        case COL_HINTS:     return compareStr(a.riskHints, b.riskHints);
        case COL_RTT:       return compareInt(a.responseTimeMs, b.responseTimeMs);
        case COL_DISCOVERY: return compareInt(static_cast<int>(a.discovery),
                                              static_cast<int>(b.discovery));
        default:            return 0;
    }
}
struct SortContext { const std::vector<ScanResult>* data; int column; bool ascending; };
int CALLBACK sortCallback(LPARAM l1, LPARAM l2, LPARAM ctxParam) {
    auto* ctx = reinterpret_cast<SortContext*>(ctxParam);
    size_t i1 = static_cast<size_t>(l1), i2 = static_cast<size_t>(l2);
    if (i1 >= ctx->data->size() || i2 >= ctx->data->size()) return 0;
    int cmp = compareCells((*ctx->data)[i1], (*ctx->data)[i2], ctx->column);
    return ctx->ascending ? cmp : -cmp;
}
} // namespace

void MainWindow::applyListSort() {
    if (sortColumn_ < 0) return;
    SortContext ctx{ &displayedResults_, sortColumn_, sortAscending_ };
    ListView_SortItems(list_, sortCallback, reinterpret_cast<LPARAM>(&ctx));
    HWND hdr = ListView_GetHeader(list_);
    if (hdr) {
        int n = Header_GetItemCount(hdr);
        for (int i = 0; i < n; ++i) {
            HDITEMW hi{}; hi.mask = HDI_FORMAT;
            if (!Header_GetItem(hdr, i, &hi)) continue;
            hi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
            if (i == sortColumn_) hi.fmt |= (sortAscending_ ? HDF_SORTUP : HDF_SORTDOWN);
            Header_SetItem(hdr, i, &hi);
        }
    }
}

// =============================================================================
// Adapters / presets
// =============================================================================

void MainWindow::refreshAdapters() {
    setStatus(L"Detecting adapters...");
    adapters_ = NetworkAdapterService::enumerate();
    if (adapters_.empty()) {
        adapterIndex_ = -1;
        setStatus(L"No IPv4 adapters detected. You can enter a range manually.");
    } else {
        adapterIndex_ = 0;
        selectAdapter(0);
        setStatus(L"Adapters loaded.");
    }
}

void MainWindow::selectAdapter(int adapterIndex) {
    if (adapterIndex < 0 || adapterIndex >= static_cast<int>(adapters_.size())) {
        adapterIndex_ = -1;
        return;
    }
    adapterIndex_ = adapterIndex;
    const auto& a = adapters_[adapterIndex];
    if (!a.suggestedScanRange.empty()) {
        setText(edRange_, a.suggestedScanRange);
    }
    std::wstring info = L"Adapter: ";
    info += a.friendlyName.empty() ? a.description : a.friendlyName;
    if (!a.ipv4.empty()) {
        info += L"   ·   IP " + a.ipv4;
        if (a.prefixLength > 0) info += L"/" + std::to_wstring(a.prefixLength);
    }
    if (!a.gateway.empty()) info += L"   ·   GW " + a.gateway;
    setStatus(info);
}

void MainWindow::onPresetChanged() {
    int idx = cbSelectedIndex(cbPreset_);
    const auto& presets = ScanPresetService::presets();
    if (idx < 0 || idx >= static_cast<int>(presets.size())) return;
    const auto& p = presets[idx];

    bool nextCustom = (p.id == L"custom");
    if (nextCustom != customPortsMode_) {
        customPortsMode_ = nextCustom;
        ::ShowWindow(lblPorts_, customPortsMode_ ? SW_SHOW : SW_HIDE);
        ::ShowWindow(edPorts_,  customPortsMode_ ? SW_SHOW : SW_HIDE);
        layoutChildren();
        ::RedrawWindow(hwnd_, nullptr, nullptr,
                       RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
    }
    if (!nextCustom) {
        // For non-custom presets, ports come from the preset directly. We don't
        // touch the (hidden) Custom Ports edit so the user's last text survives
        // a Profile round-trip.
    }
}

void MainWindow::onPortsEdited() {
    if (suppressPortsEdit_) return;
    // Once user types ports, force the Profile to "Custom Ports" so the field
    // they're editing actually drives the scan.
    const auto& presets = ScanPresetService::presets();
    int customIdx = -1;
    for (size_t i = 0; i < presets.size(); ++i) {
        if (presets[i].id == L"custom") { customIdx = static_cast<int>(i); break; }
    }
    if (customIdx < 0) return;
    int curIdx = cbSelectedIndex(cbPreset_);
    if (curIdx != customIdx) {
        ::SendMessageW(cbPreset_, CB_SETCURSEL, customIdx, 0);
        onPresetChanged();
    }
}

// =============================================================================
// Scan flow
// =============================================================================

void MainWindow::startScan() {
    if (scanning_) return;

    std::wstring rangeText = trim(getText(edRange_));
    if (rangeText.empty()) {
        ::MessageBoxW(hwnd_, L"Enter an IP range to scan.", kAppName,
                      MB_OK | MB_ICONINFORMATION);
        return;
    }

    auto parsed = IpRangeParser::parse(rangeText, false);
    if (!parsed.ok) {
        setStatus(L"Invalid range");
        ::MessageBoxW(hwnd_, parsed.error.c_str(), kAppName, MB_OK | MB_ICONWARNING);
        return;
    }
    if (parsed.addresses.size() > kLargeRangeWarnAbove) {
        std::wstring warn = L"This range expands to " +
                            std::to_wstring(parsed.addresses.size()) +
                            L" hosts. Continue?";
        if (::MessageBoxW(hwnd_, warn.c_str(), kAppName,
                          MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
            return;
    }

    ScanOptions opts;
    opts.rangeText = rangeText;
    opts.timeoutMs = settingsTimeoutMs_;
    opts.parallel  = settingsParallel_;
    opts.mode      = settingsMode_;
    opts.skipDns   = !settingsResolveDns_;
    opts.skipMac   = !settingsResolveMac_;
    opts.skipUdp   = !settingsResolveUdp_;

    // Auto-disable reverse DNS for large scans. The resolver spawns a
    // detached OS thread per lookup (no native timeout on GetNameInfo), so
    // a /16 with a slow corporate DNS could pile up thousands of zombie
    // lookups before the user notices. We don't touch settingsResolveDns_
    // (that's the user's saved preference) — only the per-scan opts. Same
    // logic applies to the UDP probes: each online host costs one extra
    // timeout window for the parallel UDP fan-out, so /16 sweeps get the
    // probes auto-suppressed.
    constexpr size_t kDnsAutoOffThreshold = 1024;
    constexpr size_t kUdpAutoOffThreshold = 1024;
    bool dnsAutoDisabled = false;
    bool udpAutoDisabled = false;
    if (!opts.skipDns && parsed.addresses.size() > kDnsAutoOffThreshold) {
        opts.skipDns = true;
        dnsAutoDisabled = true;
    }
    if (!opts.skipUdp && parsed.addresses.size() > kUdpAutoOffThreshold) {
        opts.skipUdp = true;
        udpAutoDisabled = true;
    }

    if (opts.timeoutMs < kMinTimeoutMs)  opts.timeoutMs = kMinTimeoutMs;
    if (opts.timeoutMs > kMaxTimeoutMs)  opts.timeoutMs = kMaxTimeoutMs;
    if (opts.parallel  < kMinParallel)   opts.parallel  = kMinParallel;
    if (opts.parallel  > kMaxParallel)   opts.parallel  = kMaxParallel;

    int presetIdx = cbSelectedIndex(cbPreset_);
    const auto& presets = ScanPresetService::presets();
    if (presetIdx >= 0 && presetIdx < static_cast<int>(presets.size())) {
        const auto& p = presets[presetIdx];
        opts.presetName = p.displayName;
        if (p.id == L"custom") {
            opts.ports = ScanPresetService::parsePortList(getText(edPorts_));
        } else {
            opts.ports = p.ports;
        }
    }

    if (opts.mode == ScanMode::DiscoveryOnly) opts.skipPorts = true;

    // Snapshot work units so the KPI strip can compute a meaningful
    // work-progress %. portsPerHost_ = ports actually scanned for confirmed
    // online hosts; fallbackPortsPerHost_ = discovery probe for ICMP-silent
    // hosts in Fast mode (Deep uses full port list as fallback).
    portsPerHost_ = opts.skipPorts ? 0 : static_cast<int>(opts.ports.size());
    switch (opts.mode) {
        case ScanMode::Fast:
            fallbackPortsPerHost_ = opts.skipPorts ? 0
                : static_cast<int>(sizeof(kFastDiscoveryPorts) /
                                   sizeof(kFastDiscoveryPorts[0]));
            break;
        case ScanMode::Deep:
            fallbackPortsPerHost_ = portsPerHost_;
            break;
        case ScanMode::DiscoveryOnly:
            fallbackPortsPerHost_ = 0;
            break;
    }

    if (adapterIndex_ >= 0 && adapterIndex_ < static_cast<int>(adapters_.size())) {
        const auto& a = adapters_[adapterIndex_];
        opts.adapterLabel = a.friendlyName.empty() ? a.description : a.friendlyName;
    } else {
        opts.adapterLabel = L"Manual";
    }

    clearResults();
    totalCount_ = static_cast<int>(parsed.addresses.size());
    pbConfigure(progress_, totalCount_);
    scanning_ = true;
    doneCount_.store(0);

    bool firstScan = !hasScannedOnce_;
    hasScannedOnce_ = true;
    if (firstScan) {
        for (int i = 0; i < 4; ++i) {
            ::ShowWindow(cards_[i],    SW_SHOW);
            ::ShowWindow(cardLbls_[i], SW_SHOW);
        }
        layoutChildren();
    }
    setStartStopEnabled(true);
    updateKpiStrip();

    hideOffline_ = (::SendMessageW(chkHideOffline_, BM_GETCHECK, 0, 0) == BST_CHECKED);
    filterIndex_ = cbSelectedIndex(cbFilter_);
    if (filterIndex_ < 0) filterIndex_ = 0;
    searchText_  = trim(getText(edSearch_));

    auto onHost = [this](const ScanResult& r) {
        std::lock_guard<std::mutex> lk(pendingMu_);
        pendingResults_.push_back(r);
    };
    auto onProgress = [this](int done, int /*total*/) { doneCount_.store(done); };
    HWND mainWnd = hwnd_;
    // No `this` capture: GUI state mutation is the UI thread's job. We just
    // hand it a heap payload and let WM_NL_SCAN_FINISHED do the writes.
    // Delete the payload locally if PostMessage fails (window already
    // destroyed) so we don't leak on shutdown races.
    auto onFinished = [mainWnd](bool cancelled,
                                const ScanSummary& s,
                                const std::vector<ScanResult>& res) {
        auto* payload = new (std::nothrow) ScanFinishedPayload{ cancelled, s, res };
        if (!payload) return;
        if (!::PostMessageW(mainWnd, WM_NL_SCAN_FINISHED,
                             cancelled ? 1 : 0,
                             reinterpret_cast<LPARAM>(payload))) {
            delete payload;
        }
    };

    if (dnsAutoDisabled && udpAutoDisabled) {
        setStatus(L"Scanning...   ·   DNS + UDP service probes disabled for large scan");
    } else if (dnsAutoDisabled) {
        setStatus(L"Scanning...   ·   DNS resolution disabled for large scan");
    } else if (udpAutoDisabled) {
        setStatus(L"Scanning...   ·   UDP service probes disabled for large scan");
    } else {
        setStatus(L"Scanning...");
    }
    scanStartedAt_ = std::chrono::steady_clock::now();
    probeSamples_.clear();   // ETA window resets per scan
    ::SetTimer(hwnd_, IDT_FLUSH, kUiFlushIntervalMs, nullptr);
    scanner_->start(parsed.addresses, opts, onHost, onProgress, onFinished);

    ::RedrawWindow(hwnd_, nullptr, nullptr,
                   RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

void MainWindow::stopScan() {
    if (!scanning_) return;
    setStatus(L"Cancelling...");
    ::InvalidateRect(btnStart_, nullptr, TRUE);
    if (scanner_) scanner_->cancel();
}

// =============================================================================
// Batched UI flush
// =============================================================================

void MainWindow::flushPending() {
    std::vector<ScanResult> batch;
    {
        std::lock_guard<std::mutex> lk(pendingMu_);
        batch.swap(pendingResults_);
    }
    if (!batch.empty()) {
        ::SendMessageW(list_, WM_SETREDRAW, FALSE, 0);
        for (const auto& r : batch) upsertVisibleRow(r);
        ::SendMessageW(list_, WM_SETREDRAW, TRUE, 0);
        ::InvalidateRect(list_, nullptr, FALSE);
    }
    int done = doneCount_.load();
    if (totalCount_ > 0) {
        pbSetValue(progress_, done);
        wchar_t buf[64];
        std::swprintf(buf, 64, L"Scanning %d / %d hosts...", done, totalCount_);
        setStatus(buf);
    }
    updateKpiStrip();
    updateResultsCountLabel();
}

int MainWindow::upsertVisibleRow(const ScanResult& r) {
    auto it = ipToDisplayIndex_.find(r.ipAddress);
    if (it != ipToDisplayIndex_.end()) {
        size_t idx = it->second;
        displayedResults_[idx] = r;
        int rowCount = ListView_GetItemCount(list_);
        int foundRow = -1;
        for (int i = 0; i < rowCount; ++i) {
            LVITEMW q{}; q.mask = LVIF_PARAM; q.iItem = i;
            if (ListView_GetItem(list_, &q) && static_cast<size_t>(q.lParam) == idx) {
                foundRow = i; break;
            }
        }
        const bool nowVisible = shouldShowResult(r);
        if (foundRow >= 0 && !nowVisible) {
            ListView_DeleteItem(list_, foundRow);
            return -1;
        }
        if (foundRow >= 0 && nowVisible) {
            std::vector<std::wstring> cells;
            buildResultRow(r, cells);
            for (size_t c = 0; c < cells.size(); ++c) {
                ListView_SetItemText(list_, foundRow, static_cast<int>(c),
                                     const_cast<LPWSTR>(cells[c].c_str()));
            }
            return foundRow;
        }
        if (foundRow < 0 && nowVisible) {
            std::vector<std::wstring> cells;
            buildResultRow(r, cells);
            LVITEMW item{};
            item.mask    = LVIF_TEXT | LVIF_PARAM;
            item.iItem   = ListView_GetItemCount(list_);
            item.pszText = const_cast<LPWSTR>(cells[0].c_str());
            item.lParam  = static_cast<LPARAM>(idx);
            int row = ListView_InsertItem(list_, &item);
            if (row >= 0) {
                for (size_t c = 1; c < cells.size(); ++c) {
                    ListView_SetItemText(list_, row, static_cast<int>(c),
                                         const_cast<LPWSTR>(cells[c].c_str()));
                }
            }
            return row;
        }
        return foundRow;
    }

    size_t newIdx = displayedResults_.size();
    displayedResults_.push_back(r);
    ipToDisplayIndex_[r.ipAddress] = newIdx;
    if (!shouldShowResult(r)) return -1;

    std::vector<std::wstring> cells;
    buildResultRow(r, cells);
    LVITEMW item{};
    item.mask    = LVIF_TEXT | LVIF_PARAM;
    item.iItem   = ListView_GetItemCount(list_);
    item.pszText = const_cast<LPWSTR>(cells[0].c_str());
    item.lParam  = static_cast<LPARAM>(newIdx);
    int row = ListView_InsertItem(list_, &item);
    if (row < 0) return -1;
    for (size_t c = 1; c < cells.size(); ++c) {
        ListView_SetItemText(list_, row, static_cast<int>(c),
                             const_cast<LPWSTR>(cells[c].c_str()));
    }
    return row;
}

void MainWindow::rebuildVisibleRows() {
    ::SendMessageW(list_, WM_SETREDRAW, FALSE, 0);
    lvClear(list_);
    for (size_t i = 0; i < displayedResults_.size(); ++i) {
        const auto& r = displayedResults_[i];
        if (!shouldShowResult(r)) continue;
        std::vector<std::wstring> cells;
        buildResultRow(r, cells);
        LVITEMW item{};
        item.mask    = LVIF_TEXT | LVIF_PARAM;
        item.iItem   = ListView_GetItemCount(list_);
        item.pszText = const_cast<LPWSTR>(cells[0].c_str());
        item.lParam  = static_cast<LPARAM>(i);
        int row = ListView_InsertItem(list_, &item);
        if (row >= 0) {
            for (size_t c = 1; c < cells.size(); ++c) {
                ListView_SetItemText(list_, row, static_cast<int>(c),
                                     const_cast<LPWSTR>(cells[c].c_str()));
            }
        }
    }
    if (sortColumn_ >= 0) applyListSort();
    ::SendMessageW(list_, WM_SETREDRAW, TRUE, 0);
    ::InvalidateRect(list_, nullptr, FALSE);
}

void MainWindow::onScanFinished(bool cancelled) {
    scanning_ = false;
    setStartStopEnabled(false);

    if (!lastResults_.empty()) {
        displayedResults_ = lastResults_;
        ipToDisplayIndex_.clear();
        ipToDisplayIndex_.reserve(displayedResults_.size());
        for (size_t i = 0; i < displayedResults_.size(); ++i) {
            ipToDisplayIndex_[displayedResults_[i].ipAddress] = i;
        }
        rebuildVisibleRows();
    }

    updateKpiStrip();
    updateResultsCountLabel();

    const bool haveResults = !lastResults_.empty();
    ::EnableWindow(btnExportCsv_,  haveResults ? TRUE : FALSE);
    ::EnableWindow(btnExportHtml_, haveResults ? TRUE : FALSE);

    if (cancelled) {
        // Be explicit about partial state — the third-party review (and
        // common sense) flagged that a bare "Scan cancelled" reads like the
        // app just stopped, with no acknowledgement that whatever's on
        // screen is a partial snapshot.
        const int online = lastSummary_.onlineCount;
        const int hostsDone = doneCount_.load();
        wchar_t buf[200];
        if (online > 0) {
            std::swprintf(buf, 200,
                L"Scan cancelled  ·  partial results: %d online host%ls  "
                L"·  %d / %d hosts probed",
                online, online == 1 ? L"" : L"s",
                hostsDone, totalCount_);
        } else {
            std::swprintf(buf, 200,
                L"Scan cancelled  ·  %d / %d hosts probed before stop",
                hostsDone, totalCount_);
        }
        setStatus(buf);
    } else {
        wchar_t buf[96];
        std::swprintf(buf, 96, L"Scan completed in %ls   ·   mode %ls",
                      formatDuration(lastSummary_.durationMs).c_str(),
                      ScanModeToString(lastSummary_.modeUsed));
        setStatus(buf);
    }
}

void MainWindow::updateKpiStrip() {
    // Card 0 — Online hosts.
    int onlineCount = 0;
    for (const auto& r : displayedResults_) if (r.isOnline) ++onlineCount;
    if (!scanning_ && !lastResults_.empty()) {
        onlineCount = lastSummary_.onlineCount;
    }
    setText(cards_[0], std::to_wstring(onlineCount));

    // Card 1 — work-progress %. We compute total work units as actual TCP
    // probes (online_hosts * ports + offline_hosts * fallback_ports) and read
    // the live counter from the engine. Stays meaningful on long scans
    // (All Ports) where the host-level % flatlines at 95% while online hosts
    // grind through their 65535-port sweep.
    if (totalCount_ > 0) {
        const int hostsDone  = doneCount_.load();
        const int hostsTotal = totalCount_;

        int64_t probesDone = scanner_ ? scanner_->probesDone() : 0;

        // Estimated online host count. Once a host's full result lands we
        // know exactly; for hosts not yet probed we extrapolate from the
        // observed rate so the denominator stops shrinking on us mid-scan.
        int onlineEstimate = onlineCount;
        if (hostsDone > 0 && hostsDone < hostsTotal && portsPerHost_ > 0) {
            double rate = static_cast<double>(onlineCount) / hostsDone;
            int extrapolated = static_cast<int>(rate * hostsTotal + 0.5);
            if (extrapolated > onlineEstimate) onlineEstimate = extrapolated;
        }
        if (onlineEstimate > hostsTotal) onlineEstimate = hostsTotal;
        const int offlineEstimate = hostsTotal - onlineEstimate;

        int64_t probesTotal =
            static_cast<int64_t>(onlineEstimate)  * portsPerHost_ +
            static_cast<int64_t>(offlineEstimate) * fallbackPortsPerHost_;

        // Once the scan is fully done (not cancelled), pin the denominator to
        // the actual probes performed so the displayed % lands cleanly on
        // 100%. For cancelled scans we deliberately leave the ratio at
        // probesDone/probesTotal — pinning to 100% would lie to the user
        // about how much of the work actually ran.
        const bool finishedCleanly = !scanning_ && !lastSummary_.wasCancelled;
        if (finishedCleanly) {
            int64_t actual = 0;
            for (const auto& r : lastResults_) actual += r.ports.size();
            if (actual > 0) {
                probesTotal = actual;
                if (actual > probesDone) probesDone = actual;
            }
        }

        if (probesTotal <= 0) probesTotal = std::max<int64_t>(hostsTotal, 1);

        int pct = static_cast<int>(probesDone * 100 / probesTotal);
        if (pct > 100) pct = 100;
        if (finishedCleanly && hostsDone >= hostsTotal) pct = 100;

        wchar_t buf[64];
        std::swprintf(buf, 64, L"%d%%", pct);
        setText(cards_[1], buf);

        std::wstring sub;
        if (portsPerHost_ <= 64) {
            // Small port set → host-level X/Y is the most legible subtitle.
            sub = std::to_wstring(hostsDone) + L" / " +
                  std::to_wstring(hostsTotal) + L" hosts probed";
        } else {
            // All Ports / wide preset → show raw probe counts.
            sub = std::to_wstring(probesDone) + L" of ~" +
                  std::to_wstring(probesTotal) + L" probes";
        }
        setText(cardLbls_[1], sub);
    } else {
        setText(cards_[1], L"—");
        setText(cardLbls_[1], L"Progress");
    }

    // Compute elapsed time once — used by ETA (card 2) and Duration (card 3).
    int64_t elapsedMs = 0;
    if (scanning_) {
        auto now = std::chrono::steady_clock::now();
        elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - scanStartedAt_).count();
    } else {
        elapsedMs = lastSummary_.durationMs;
    }

    // Card 2 — Time remaining (ETA).
    //
    // We compute ETA from a SLIDING-WINDOW probes-per-second rate (last
    // ~5 seconds), not the cumulative average. The cumulative version was
    // biased by the very fast ICMP-discovery phase at the start of a scan,
    // which made ETA balloon when the slow port-scan phase kicked in.
    //
    // We also gate the display: until ICMP discovery is mostly complete
    // (>=85% of hosts probed) we show "…" rather than a wildly fluctuating
    // figure based on a half-known online count.
    if (scanning_ && totalCount_ > 0) {
        const int hostsDone = doneCount_.load();
        const double icmpProgress =
            static_cast<double>(hostsDone) / static_cast<double>(totalCount_);
        const int64_t probesDoneNow = scanner_ ? scanner_->probesDone() : 0;

        // Append a sample (timestamp + probes counter) and trim entries
        // older than the window so we always compute rate over recent work.
        constexpr int64_t kWindowMs = 5000;
        probeSamples_.push_back({ elapsedMs, probesDoneNow });
        while (probeSamples_.size() > 1 &&
               probeSamples_.front().tMs < elapsedMs - kWindowMs) {
            probeSamples_.pop_front();
        }

        // Need a stable online-count read and at least a couple of samples
        // before we trust the rate. While ICMP discovery is still running
        // we can't bound the work either; defer to "…".
        if (icmpProgress < 0.85 || probeSamples_.size() < 2 || elapsedMs < 2000) {
            setText(cards_[2], L"…");
            setText(cardLbls_[2], L"Estimating...");
        } else {
            const auto& first = probeSamples_.front();
            const auto& last  = probeSamples_.back();
            const int64_t dProbes = last.probes - first.probes;
            const int64_t dMs     = last.tMs    - first.tMs;
            double pps = (dMs > 0) ? (dProbes * 1000.0 / dMs) : 0.0;

            // Once ICMP discovery is essentially done, online count is
            // stable — compute the firm probes-plan from it.
            const int offlineCount = totalCount_ - onlineCount;
            int64_t probesPlan =
                static_cast<int64_t>(onlineCount)  * portsPerHost_ +
                static_cast<int64_t>(offlineCount) * fallbackPortsPerHost_;
            int64_t probesRemain = probesPlan - probesDoneNow;
            if (probesRemain < 0) probesRemain = 0;

            if (probesRemain > 0 && pps > 1.0) {
                int64_t etaMs = static_cast<int64_t>(probesRemain * 1000.0 / pps);
                setText(cards_[2], formatDuration(etaMs));
            } else if (probesRemain == 0) {
                setText(cards_[2], L"~0 s");
            } else {
                // pps too low to estimate (scan paused or extremely slow).
                setText(cards_[2], L"…");
            }
            setText(cardLbls_[2], L"Time remaining");
        }
    } else if (!scanning_ && elapsedMs > 0) {
        setText(cards_[2], L"—");
        setText(cardLbls_[2], L"Time remaining");
    } else {
        setText(cards_[2], L"…");
        setText(cardLbls_[2], L"Time remaining");
    }

    // Card 3 — Duration. Live counter while scanning, final value after.
    if (scanning_) {
        setText(cards_[3], formatDuration(elapsedMs));
    } else if (elapsedMs > 0) {
        setText(cards_[3], formatDuration(elapsedMs));
    } else {
        setText(cards_[3], L"—");
    }
}

void MainWindow::updateResultsCountLabel() {
    int total = static_cast<int>(displayedResults_.size());
    int visible = ListView_GetItemCount(list_);
    std::wstring s;
    if (total == 0 && totalCount_ == 0) {
        setText(lblResultsCount_, L"No results yet.");
        return;
    }
    if (totalCount_ > 0 && scanning_) {
        s = L"Showing " + std::to_wstring(visible) + L" host" +
            (visible == 1 ? L"" : L"s") +
            L" · " + std::to_wstring(total) + L" recorded · " +
            std::to_wstring(totalCount_) + L" planned";
    } else {
        s = L"Showing " + std::to_wstring(visible) + L" of " +
            std::to_wstring(total) + L" host" +
            (total == 1 ? L"" : L"s");
        if (hideOffline_)     s += L"   ·   offline hidden";
        if (filterIndex_ > 0) {
            const wchar_t* names[] = {
                L"", L"high risk", L"medium risk", L"low risk", L"online", L"offline"
            };
            s += L"   ·   filter: ";
            s += names[filterIndex_];
        }
        if (!searchText_.empty()) {
            s += L"   ·   search: \"" + searchText_ + L"\"";
        }
    }
    setText(lblResultsCount_, s);
}

void MainWindow::setStatus(const std::wstring& text) { setText(status_, text); }

void MainWindow::setStartStopEnabled(bool scanning) {
    ::EnableWindow(btnStart_,   TRUE);
    ::EnableWindow(cbPreset_,   scanning ? FALSE : TRUE);
    ::EnableWindow(edRange_,    scanning ? FALSE : TRUE);
    ::EnableWindow(btnAdapter_, scanning ? FALSE : TRUE);
    ::EnableWindow(edPorts_,    scanning ? FALSE : TRUE);
    if (scanning) {
        ::EnableWindow(btnExportCsv_,  FALSE);
        ::EnableWindow(btnExportHtml_, FALSE);
    }
    setText(btnStart_, scanning ? L"Stop scan" : L"Start scan");
    ::InvalidateRect(btnStart_, nullptr, TRUE);
}

void MainWindow::clearResults() {
    lvClear(list_);
    displayedResults_.clear();
    ipToDisplayIndex_.clear();
    lastResults_.clear();
    lastSummary_ = ScanSummary{};
    { std::lock_guard<std::mutex> lk(pendingMu_); pendingResults_.clear(); }
    doneCount_.store(0);
    totalCount_     = 0;
    probeSamples_.clear();
    sortColumn_     = -1;
    sortAscending_  = true;
    pbSetValue(progress_, 0);
    if (hasScannedOnce_) {
        setText(cards_[0], L"0");
        setText(cards_[1], L"—");
        setText(cards_[2], L"—");
        setText(cardLbls_[1], L"Progress");
    }
    ::EnableWindow(btnExportCsv_,  FALSE);
    ::EnableWindow(btnExportHtml_, FALSE);
    updateResultsCountLabel();
}

// =============================================================================
// Exports / About
// =============================================================================

void MainWindow::exportCsv() {
    if (lastResults_.empty()) return;
    std::wstring path = promptSaveAs(
        hwnd_, L"Export results as CSV",
        suggestFileName(L"csv").c_str(),
        L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0\0");
    if (path.empty()) return;
    if (ReportExporter::exportCsv(path, lastResults_)) {
        setStatus(L"Export completed: " + path);
    } else {
        setStatus(L"Error: CSV export failed");
        ::MessageBoxW(hwnd_, L"Failed to write CSV.", kAppName, MB_OK | MB_ICONERROR);
    }
}

void MainWindow::exportHtml() {
    if (lastResults_.empty()) return;
    std::wstring path = promptSaveAs(
        hwnd_, L"Export results as HTML",
        suggestFileName(L"html").c_str(),
        L"HTML files (*.html)\0*.html\0All files (*.*)\0*.*\0\0");
    if (path.empty()) return;
    if (ReportExporter::exportHtml(path, lastResults_, lastSummary_)) {
        setStatus(L"Export completed: " + path);
        revealInExplorer(path);
    } else {
        setStatus(L"Error: HTML export failed");
        ::MessageBoxW(hwnd_, L"Failed to write HTML.", kAppName, MB_OK | MB_ICONERROR);
    }
}

void MainWindow::showAbout() {
    std::wstring msg;
    msg += kAppName;
    msg += L"\n";
    msg += kAppSubtitle;
    msg += L"\nVersion ";
    msg += kAppVersion;
    msg += L"\n\n";
    msg += L"\xA9 2026 ";
    msg += kAppCompany;
    msg += L"\n\n";
    msg += L"No telemetry. No cloud. No installation required.\n";
    msg += L"Designed for authorized small-business LAN visibility.\n\n";
    msg += L"MAC vendor lookup uses the public IEEE Registration\n";
    msg += L"Authority OUI registry embedded in the .exe (MA-L /24,\n";
    msg += L"MA-M /28, MA-S /36), with per-vendor port-priority profiles\n";
    msg += L"(Dahua / Hikvision / VMware / MikroTik / Cisco / Synology\n";
    msg += L"/ printers / NAS / IoT / etc.).\n\n";
    msg += L"Online hosts are also probed on the six high-signal UDP\n";
    msg += L"service ports: NetBIOS (137), mDNS (5353), SSDP/UPnP (1900),\n";
    msg += L"SNMP (161), DNS (53), NTP (123) — for richer hostname /\n";
    msg += L"workgroup / device-model info than TCP scans alone provide.\n\n";
    msg += L"This software reports open ports and exposure hints. It does\n";
    msg += L"not confirm vulnerabilities. Use only on networks you own or\n";
    msg += L"have explicit permission to scan.";
    ::MessageBoxW(hwnd_, msg.c_str(), kAppName, MB_OK | MB_ICONINFORMATION);
}

// =============================================================================
// Row context menu
// =============================================================================

void MainWindow::showRowContextMenu(int row) {
    const ScanResult* r = resultForRow(row);
    if (!r) return;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) return;
    ::AppendMenuW(menu, MF_STRING, kCtxCopyIp,
                  (L"Copy IP address  (" + r->ipAddress + L")").c_str());
    if (!r->macAddress.empty())
        ::AppendMenuW(menu, MF_STRING, kCtxCopyMac, L"Copy MAC address");
    if (!r->hostname.empty())
        ::AppendMenuW(menu, MF_STRING, kCtxCopyHost, L"Copy hostname");
    ::AppendMenuW(menu, MF_STRING, kCtxCopyRow, L"Copy row as CSV line");

    const bool httpOpen  = hostHasPort(*r, 80) || hostHasPort(*r, 8080);
    const bool httpsOpen = hostHasPort(*r, 443) || hostHasPort(*r, 8443);
    const bool rdpOpen   = hostHasPort(*r, 3389);
    const bool sshOpen   = hostHasPort(*r, 22);

    if (httpOpen || httpsOpen || rdpOpen || sshOpen || r->isOnline) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    }
    ::AppendMenuW(menu, MF_STRING | (httpOpen  ? 0u : (MF_DISABLED | MF_GRAYED)),
                  kCtxOpenHttp,  L"Open in browser  (http://)");
    ::AppendMenuW(menu, MF_STRING | (httpsOpen ? 0u : (MF_DISABLED | MF_GRAYED)),
                  kCtxOpenHttps, L"Open in browser  (https://)");
    ::AppendMenuW(menu, MF_STRING | (rdpOpen   ? 0u : (MF_DISABLED | MF_GRAYED)),
                  kCtxRdp,       L"Connect via RDP");
    ::AppendMenuW(menu, MF_STRING | (sshOpen   ? 0u : (MF_DISABLED | MF_GRAYED)),
                  kCtxSsh,       L"Copy SSH command to clipboard");
    if (r->isOnline) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kCtxPing,    L"Ping in command prompt");
        ::AppendMenuW(menu, MF_STRING, kCtxMonitor, L"Monitor host  (continuous probes + chart)");
    }
    POINT pt; ::GetCursorPos(&pt);
    UINT cmd = ::TrackPopupMenuEx(menu,
                                  TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_TOPALIGN,
                                  pt.x, pt.y, hwnd_, nullptr);
    ::DestroyMenu(menu);
    if (cmd != 0) handleContextAction(static_cast<int>(cmd), *r);
}

void MainWindow::handleContextAction(int cmd, const ScanResult& r) {
    switch (cmd) {
        case kCtxCopyIp:    copyToClipboard(hwnd_, r.ipAddress);     setStatus(L"Copied IP address: " + r.ipAddress); break;
        case kCtxCopyMac:   copyToClipboard(hwnd_, r.macAddress);    setStatus(L"Copied MAC address."); break;
        case kCtxCopyHost:  copyToClipboard(hwnd_, r.hostname);      setStatus(L"Copied hostname."); break;
        case kCtxCopyRow:   copyToClipboard(hwnd_, buildCsvLine(r)); setStatus(L"Copied row as CSV line."); break;
        case kCtxOpenHttp:  shellOpen(hwnd_, L"http://"  + r.ipAddress + L"/", L""); break;
        case kCtxOpenHttps: shellOpen(hwnd_, L"https://" + r.ipAddress + L"/", L""); break;
        case kCtxRdp:       shellOpen(hwnd_, L"mstsc.exe", L"/v:" + r.ipAddress);
                            setStatus(L"Launching Remote Desktop to " + r.ipAddress + L"...");
                            break;
        case kCtxSsh: {
            std::wstring line = L"ssh " + r.ipAddress;
            copyToClipboard(hwnd_, line);
            setStatus(L"Copied SSH command: " + line);
            break;
        }
        case kCtxPing:      shellOpen(hwnd_, L"cmd.exe", L"/k ping " + r.ipAddress); break;
        case kCtxMonitor: {
            MonitorConfig cfg;
            cfg.ip         = r.ipAddress;
            cfg.hostname   = !r.hostname.empty() ? r.hostname
                              : (!r.vendor.empty() ? r.vendor : std::wstring());
            cfg.type       = ProbeType::Icmp;
            cfg.port       = 80;
            cfg.intervalMs = 1000;
            cfg.timeoutMs  = 800;
            MonitorWindow::addMonitor(hInst_, hwnd_, cfg);
            break;
        }
        default: break;
    }
}

// =============================================================================
// Modal dialogs: adapter selection + scan settings
// =============================================================================

// ----- Adapter dialog ----------

INT_PTR CALLBACK MainWindow::adapterDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* self = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hDlg, GWLP_USERDATA));

    auto populate = [&](MainWindow* mw) {
        if (!mw) return;
        HWND lb = ::GetDlgItem(hDlg, IDC_ADA_LIST);
        ::SendMessageW(lb, LB_RESETCONTENT, 0, 0);
        for (const auto& a : mw->adapters_) {
            ::SendMessageW(lb, LB_ADDSTRING, 0,
                           reinterpret_cast<LPARAM>(a.guiLine().c_str()));
        }
        if (mw->adapterIndex_ >= 0 &&
            mw->adapterIndex_ < static_cast<int>(mw->adapters_.size())) {
            ::SendMessageW(lb, LB_SETCURSEL, mw->adapterIndex_, 0);
        }
    };

    auto refreshInfo = [&](MainWindow* mw) {
        if (!mw) return;
        HWND lb = ::GetDlgItem(hDlg, IDC_ADA_LIST);
        int sel = static_cast<int>(::SendMessageW(lb, LB_GETCURSEL, 0, 0));
        std::wstring info;
        if (sel >= 0 && sel < static_cast<int>(mw->adapters_.size())) {
            const auto& a = mw->adapters_[sel];
            if (!a.ipv4.empty())
                info += L"IP: " + a.ipv4 + L"/" + std::to_wstring(a.prefixLength);
            if (!a.gateway.empty())
                info += L"    Gateway: " + a.gateway;
            if (!a.suggestedScanRange.empty())
                info += L"    Range: " + a.suggestedScanRange;
        } else {
            info = L"(no adapter selected — manual range mode)";
        }
        ::SetDlgItemTextW(hDlg, IDC_ADA_INFO, info.c_str());
    };

    switch (msg) {
        case WM_INITDIALOG: {
            self = reinterpret_cast<MainWindow*>(lParam);
            ::SetWindowLongPtrW(hDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            populate(self);
            refreshInfo(self);
            return TRUE;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_ADA_LIST:
                    if (HIWORD(wParam) == LBN_SELCHANGE) {
                        refreshInfo(self);
                    } else if (HIWORD(wParam) == LBN_DBLCLK) {
                        ::SendMessageW(hDlg, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
                    }
                    return TRUE;
                case IDC_ADA_REFRESH:
                    if (self) {
                        self->adapters_ = NetworkAdapterService::enumerate();
                    }
                    populate(self);
                    refreshInfo(self);
                    return TRUE;
                case IDOK: {
                    HWND lb = ::GetDlgItem(hDlg, IDC_ADA_LIST);
                    int sel = static_cast<int>(::SendMessageW(lb, LB_GETCURSEL, 0, 0));
                    if (self && sel >= 0) self->selectAdapter(sel);
                    ::EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    ::EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

void MainWindow::showAdapterDialog() {
    ::DialogBoxParamW(hInst_, MAKEINTRESOURCEW(IDD_ADAPTER_DIALOG), hwnd_,
                      &MainWindow::adapterDlgProc,
                      reinterpret_cast<LPARAM>(this));
}

// ----- Settings dialog ----------

void MainWindow::showSettingsDialog() {
    // We bind the MainWindow* directly via a stateful dialog proc — but because
    // the dialog template is simple and we only need to ferry a few numbers,
    // we use a small struct + a lambda-friendly proc declared here.
    struct Bridge { MainWindow* mw; };
    Bridge bridge{ this };

    auto proc = [](HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) -> INT_PTR {
        auto* b = reinterpret_cast<Bridge*>(::GetWindowLongPtrW(hDlg, GWLP_USERDATA));

        switch (msg) {
            case WM_INITDIALOG: {
                ::SetWindowLongPtrW(hDlg, GWLP_USERDATA, lParam);
                b = reinterpret_cast<Bridge*>(lParam);
                MainWindow* mw = b->mw;
                ::SetDlgItemInt(hDlg, IDC_SET_TIMEOUT,  mw->settingsTimeoutMs_, FALSE);
                ::SetDlgItemInt(hDlg, IDC_SET_PARALLEL, mw->settingsParallel_,  FALSE);

                // Attach a tooltip to the Parallel-probes edit so the user
                // can see the host-tuned recommendation without us touching
                // the static label (which shares id IDC_STATIC with every
                // other LTEXT in the dialog template).
                SYSTEM_INFO si{};
                ::GetSystemInfo(&si);
                int cores = static_cast<int>(si.dwNumberOfProcessors);
                static wchar_t hint[128];   // static so the tooltip pointer stays valid
                std::swprintf(hint, 128,
                    L"Auto-tuned default: %d (this host reports %d logical cores).",
                    recommendedParallel(), cores);
                HWND tt = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                            WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                            CW_USEDEFAULT, CW_USEDEFAULT,
                                            CW_USEDEFAULT, CW_USEDEFAULT,
                                            hDlg, nullptr,
                                            ::GetModuleHandleW(nullptr), nullptr);
                if (tt) {
                    TOOLINFOW ti{};
                    ti.cbSize   = sizeof(ti);
                    ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
                    ti.hwnd     = hDlg;
                    ti.uId      = reinterpret_cast<UINT_PTR>(
                                      ::GetDlgItem(hDlg, IDC_SET_PARALLEL));
                    ti.lpszText = hint;
                    ::SendMessageW(tt, TTM_ADDTOOLW, 0,
                                   reinterpret_cast<LPARAM>(&ti));
                    ::SendMessageW(tt, TTM_SETMAXTIPWIDTH, 0, 360);
                }
                HWND combo = ::GetDlgItem(hDlg, IDC_SET_MODE);
                ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Fast (default)"));
                ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Deep (full TCP fallback)"));
                ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Discovery-only (ICMP + DNS + MAC)"));
                ::SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(mw->settingsMode_), 0);
                ::CheckDlgButton(hDlg, IDC_SET_DNS, mw->settingsResolveDns_ ? BST_CHECKED : BST_UNCHECKED);
                ::CheckDlgButton(hDlg, IDC_SET_MAC, mw->settingsResolveMac_ ? BST_CHECKED : BST_UNCHECKED);
                ::CheckDlgButton(hDlg, IDC_SET_UDP, mw->settingsResolveUdp_ ? BST_CHECKED : BST_UNCHECKED);
                return TRUE;
            }
            case WM_COMMAND:
                switch (LOWORD(wParam)) {
                    case IDOK: {
                        if (!b) { ::EndDialog(hDlg, IDCANCEL); return TRUE; }
                        MainWindow* mw = b->mw;
                        BOOL ok1 = FALSE, ok2 = FALSE;
                        UINT t = ::GetDlgItemInt(hDlg, IDC_SET_TIMEOUT,  &ok1, FALSE);
                        UINT p = ::GetDlgItemInt(hDlg, IDC_SET_PARALLEL, &ok2, FALSE);
                        if (ok1) mw->settingsTimeoutMs_ = std::clamp(static_cast<int>(t),
                                                                     kMinTimeoutMs, kMaxTimeoutMs);
                        if (ok2) mw->settingsParallel_  = std::clamp(static_cast<int>(p),
                                                                     kMinParallel,  kMaxParallel);
                        int mIdx = static_cast<int>(::SendMessageW(::GetDlgItem(hDlg, IDC_SET_MODE),
                                                                   CB_GETCURSEL, 0, 0));
                        if (mIdx >= 0) mw->settingsMode_ = static_cast<ScanMode>(mIdx);
                        mw->settingsResolveDns_ = (::IsDlgButtonChecked(hDlg, IDC_SET_DNS) == BST_CHECKED);
                        mw->settingsResolveMac_ = (::IsDlgButtonChecked(hDlg, IDC_SET_MAC) == BST_CHECKED);
                        mw->settingsResolveUdp_ = (::IsDlgButtonChecked(hDlg, IDC_SET_UDP) == BST_CHECKED);
                        ::EndDialog(hDlg, IDOK);
                        return TRUE;
                    }
                    case IDCANCEL:
                        ::EndDialog(hDlg, IDCANCEL);
                        return TRUE;
                }
                break;
        }
        return FALSE;
    };

    ::DialogBoxParamW(hInst_, MAKEINTRESOURCEW(IDD_SETTINGS_DIALOG), hwnd_,
                      static_cast<DLGPROC>(proc),
                      reinterpret_cast<LPARAM>(&bridge));
}

// ----- Host-details dialog ----------

namespace {

// Sort state for the host-details ports ListView.
struct PortsSortCtx {
    HWND lv        = nullptr;
    int  column    = 0;       // 0=Port, 1=Protocol, 2=Service
    bool ascending = true;
};

// ListView_SortItemsEx callback — receives row indices (NOT LPARAMs).
int CALLBACK portsSortEx(LPARAM r1, LPARAM r2, LPARAM ctxParam) {
    auto* ctx = reinterpret_cast<PortsSortCtx*>(ctxParam);
    int row1 = static_cast<int>(r1);
    int row2 = static_cast<int>(r2);

    wchar_t a[64] = {}, b[64] = {};
    ListView_GetItemText(ctx->lv, row1, ctx->column, a, 63);
    ListView_GetItemText(ctx->lv, row2, ctx->column, b, 63);

    int cmp;
    if (ctx->column == 0) {
        // Numeric port compare so 22 sorts before 80, not lexicographically.
        cmp = _wtoi(a) - _wtoi(b);
    } else {
        cmp = ::CompareStringOrdinal(a, -1, b, -1, TRUE) - CSTR_EQUAL;
    }
    return ctx->ascending ? cmp : -cmp;
}

} // namespace

void MainWindow::showHostDetailsDialog(const ScanResult& r) {
    // Bridge pattern: stash a pointer to a stack struct in DWLP_USER so the
    // captureless DLGPROC can recover the MainWindow + ScanResult + sort
    // state on each message. Lifetime is the duration of the modal call.
    struct Bridge {
        MainWindow*       mw;
        const ScanResult* r;
        PortsSortCtx      sort;
    };
    Bridge bridge{ this, &r, {} };

    auto proc = [](HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) -> INT_PTR {
        auto* b = reinterpret_cast<Bridge*>(::GetWindowLongPtrW(hDlg, GWLP_USERDATA));

        switch (msg) {
            case WM_INITDIALOG: {
                ::SetWindowLongPtrW(hDlg, GWLP_USERDATA, lParam);
                b = reinterpret_cast<Bridge*>(lParam);
                const ScanResult& r = *b->r;

                // Header labels.
                ::SetDlgItemTextW(hDlg, IDC_HD_IP,         r.ipAddress.c_str());
                ::SetDlgItemTextW(hDlg, IDC_HD_STATUS,
                                  r.isOnline ? L"Online" : L"Offline");
                ::SetDlgItemTextW(hDlg, IDC_HD_HOSTNAME,
                                  r.effectiveHostname().empty()
                                      ? L"—"
                                      : r.effectiveHostname().c_str());
                ::SetDlgItemTextW(hDlg, IDC_HD_VENDOR,
                                  r.vendor.empty() ? L"—" : r.vendor.c_str());
                ::SetDlgItemTextW(hDlg, IDC_HD_MAC,
                                  r.macAddress.empty() ? L"—" : r.macAddress.c_str());
                ::SetDlgItemTextW(hDlg, IDC_HD_DISCOVERY,
                                  DiscoveryMethodToString(r.discovery));
                ::SetDlgItemTextW(hDlg, IDC_HD_RISK,
                                  RiskLevelToString(r.riskLevel));
                ::SetDlgItemTextW(hDlg, IDC_HD_RISK_HINTS,
                                  r.riskHints.empty() ? L"—" : r.riskHints.c_str());

                // Populate the open-ports ListView with numeric ordering.
                HWND lv = ::GetDlgItem(hDlg, IDC_HD_PORTS_LIST);
                ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT |
                                                        LVS_EX_DOUBLEBUFFER);
                // Columns
                LVCOLUMNW col{};
                col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
                col.pszText = const_cast<LPWSTR>(L"Port");      col.cx = 70;
                col.iSubItem = 0; ListView_InsertColumn(lv, 0, &col);
                col.pszText = const_cast<LPWSTR>(L"Protocol");  col.cx = 70;
                col.iSubItem = 1; ListView_InsertColumn(lv, 1, &col);
                col.pszText = const_cast<LPWSTR>(L"Service");   col.cx = 240;
                col.iSubItem = 2; ListView_InsertColumn(lv, 2, &col);

                // Sort open ports numerically before inserting.
                std::vector<PortStatus> open;
                for (const auto& p : r.ports) if (p.isOpen) open.push_back(p);
                std::sort(open.begin(), open.end(),
                          [](const PortStatus& a, const PortStatus& b){
                              return a.port < b.port;
                          });

                for (size_t i = 0; i < open.size(); ++i) {
                    LVITEMW item{};
                    item.mask    = LVIF_TEXT | LVIF_PARAM;
                    item.iItem   = static_cast<int>(i);
                    std::wstring portStr = std::to_wstring(open[i].port);
                    item.pszText = const_cast<LPWSTR>(portStr.c_str());
                    item.lParam  = static_cast<LPARAM>(open[i].port);
                    int row = ListView_InsertItem(lv, &item);
                    if (row < 0) continue;
                    ListView_SetItemText(lv, row, 1, const_cast<LPWSTR>(L"TCP"));
                    std::wstring svc = open[i].service.empty()
                                       ? std::wstring(L"—")
                                       : open[i].service;
                    ListView_SetItemText(lv, row, 2,
                                         const_cast<LPWSTR>(svc.c_str()));
                }

                // All connect-style buttons are enabled whenever the host is
                // online — the action sends to the port currently selected in
                // the ports ListView (or each protocol's default port if no
                // row is selected). This lets the user telnet/ssh/curl to
                // non-standard ports (e.g. SSH on 2222, Telnet on 9100, an
                // HTTP banner on 8001) instead of being gated on the small
                // canonical set.
                const bool online = b->r->isOnline;
                ::EnableWindow(::GetDlgItem(hDlg, IDC_HD_OPEN_BROWSER), online ? TRUE : FALSE);
                ::EnableWindow(::GetDlgItem(hDlg, IDC_HD_OPEN_RDP),     online ? TRUE : FALSE);
                ::EnableWindow(::GetDlgItem(hDlg, IDC_HD_OPEN_SSH),     online ? TRUE : FALSE);
                ::EnableWindow(::GetDlgItem(hDlg, IDC_HD_OPEN_TELNET),  online ? TRUE : FALSE);
                ::EnableWindow(::GetDlgItem(hDlg, IDC_HD_OPEN_VNC),     online ? TRUE : FALSE);
                ::EnableWindow(::GetDlgItem(hDlg, IDC_HD_PING),         online ? TRUE : FALSE);

                // Mark the default sort indicator on the Port column.
                HWND hdr = ListView_GetHeader(lv);
                if (hdr) {
                    HDITEMW hi{};
                    hi.mask = HDI_FORMAT;
                    if (Header_GetItem(hdr, 0, &hi)) {
                        hi.fmt |= HDF_SORTUP;
                        Header_SetItem(hdr, 0, &hi);
                    }
                }
                return TRUE;
            }
            case WM_NOTIFY: {
                auto* nm = reinterpret_cast<LPNMHDR>(lParam);
                if (nm && nm->idFrom == IDC_HD_PORTS_LIST &&
                    nm->code == LVN_COLUMNCLICK && b)
                {
                    auto* lv = reinterpret_cast<LPNMLISTVIEW>(lParam);
                    HWND list = ::GetDlgItem(hDlg, IDC_HD_PORTS_LIST);
                    if (lv->iSubItem == b->sort.column) {
                        b->sort.ascending = !b->sort.ascending;
                    } else {
                        b->sort.column    = lv->iSubItem;
                        b->sort.ascending = true;
                    }
                    b->sort.lv = list;
                    ListView_SortItemsEx(list, portsSortEx,
                                         reinterpret_cast<LPARAM>(&b->sort));

                    HWND hdr = ListView_GetHeader(list);
                    if (hdr) {
                        int n = Header_GetItemCount(hdr);
                        for (int i = 0; i < n; ++i) {
                            HDITEMW hi{};
                            hi.mask = HDI_FORMAT;
                            if (!Header_GetItem(hdr, i, &hi)) continue;
                            hi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
                            if (i == b->sort.column) {
                                hi.fmt |= (b->sort.ascending ? HDF_SORTUP : HDF_SORTDOWN);
                            }
                            Header_SetItem(hdr, i, &hi);
                        }
                    }
                    return TRUE;
                }
                break;
            }
            case WM_DRAWITEM: {
                // Per-row "copy" icon buttons. Owner-drawn so we can render
                // the Segoe MDL2 Copy glyph at brand-blue on a subtle hover
                // background, matching the rest of the dialog's themed look.
                auto* dis = reinterpret_cast<LPDRAWITEMSTRUCT>(lParam);
                UINT id = dis->CtlID;
                if (id >= IDC_HD_COPY_BTN_IP && id <= IDC_HD_COPY_BTN_HINTS && b) {
                    const bool pressed = (dis->itemState & ODS_SELECTED) != 0;
                    const bool disabled = (dis->itemState & ODS_DISABLED) != 0;
                    RECT rc = dis->rcItem;
                    COLORREF bg = pressed ? RGB(225, 234, 248) : RGB(248, 250, 252);
                    ::FillRect(dis->hDC, &rc, cachedSolidBrush(bg));
                    drawBorder(dis->hDC, rc, RGB(220, 226, 235));
                    if (b->mw->iconFontMed_) {
                        HFONT prev = (HFONT)::SelectObject(dis->hDC, b->mw->iconFontMed_);
                        ::SetBkMode(dis->hDC, TRANSPARENT);
                        ::SetTextColor(dis->hDC, disabled ? RGB(140, 150, 165)
                                                          : RGB(31,  78,  162));
                        // MDL2 Copy glyph
                        ::DrawTextW(dis->hDC, L"\xE8C8", -1, &rc,
                                    DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                        ::SelectObject(dis->hDC, prev);
                    }
                    return TRUE;
                }
                break;
            }
            case WM_COMMAND: {
                // Resolve the port the connect actions should target. If the
                // user has a row selected in the ports ListView, use that
                // port number; otherwise fall back to the protocol's
                // canonical default. This is what makes Telnet/SSH/etc.
                // work on any port — pick the port first, then the action.
                auto resolvePort = [&](int defaultPort) -> int {
                    HWND lv = ::GetDlgItem(hDlg, IDC_HD_PORTS_LIST);
                    int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
                    if (sel < 0) return defaultPort;
                    wchar_t buf[16] = {};
                    ListView_GetItemText(lv, sel, 0, buf, 15);
                    int p = _wtoi(buf);
                    return (p > 0 && p <= 65535) ? p : defaultPort;
                };

                switch (LOWORD(wParam)) {
                    // Per-row copy buttons — each grabs exactly one field.
                    case IDC_HD_COPY_BTN_IP:
                        if (b) copyToClipboard(hDlg, b->r->ipAddress);
                        return TRUE;
                    case IDC_HD_COPY_BTN_STATUS:
                        if (b) copyToClipboard(hDlg, b->r->statusText());
                        return TRUE;
                    case IDC_HD_COPY_BTN_HOSTNAME:
                        if (b) copyToClipboard(hDlg, b->r->hostname);
                        return TRUE;
                    case IDC_HD_COPY_BTN_VENDOR:
                        if (b) copyToClipboard(hDlg, b->r->vendor);
                        return TRUE;
                    case IDC_HD_COPY_BTN_MAC:
                        if (b) copyToClipboard(hDlg, b->r->macAddress);
                        return TRUE;
                    case IDC_HD_COPY_BTN_DISC:
                        if (b) copyToClipboard(hDlg,
                            std::wstring(DiscoveryMethodToString(b->r->discovery)));
                        return TRUE;
                    case IDC_HD_COPY_BTN_RISK:
                        if (b) copyToClipboard(hDlg,
                            std::wstring(RiskLevelToString(b->r->riskLevel)));
                        return TRUE;
                    case IDC_HD_COPY_BTN_HINTS:
                        if (b) copyToClipboard(hDlg, b->r->riskHints);
                        return TRUE;
                    case IDC_HD_PING:
                        if (b) shellOpen(hDlg, L"cmd.exe",
                                          L"/k ping " + b->r->ipAddress);
                        return TRUE;
                    case IDC_HD_OPEN_BROWSER:
                        if (b) {
                            int port = resolvePort(80);
                            // Heuristic: 443/8443/9443 etc. → https://, else http://.
                            // Also covers a selected non-canonical port by
                            // looking at whether the row's service is HTTPS.
                            bool https = (port == 443 || port == 8443 ||
                                          port == 9443 || port == 4443);
                            std::wstring url = (https ? L"https://" : L"http://")
                                               + b->r->ipAddress;
                            if (port != 80 && port != 443) {
                                url += L":" + std::to_wstring(port);
                            }
                            url += L"/";
                            shellOpen(hDlg, url, L"");
                        }
                        return TRUE;
                    case IDC_HD_OPEN_RDP:
                        if (b) {
                            int port = resolvePort(3389);
                            std::wstring target = L"/v:" + b->r->ipAddress;
                            if (port != 3389) {
                                target += L":" + std::to_wstring(port);
                            }
                            shellOpen(hDlg, L"mstsc.exe", target);
                        }
                        return TRUE;
                    case IDC_HD_OPEN_SSH:
                        if (b) {
                            int port = resolvePort(22);
                            std::wstring args = L"/k ssh";
                            if (port != 22) {
                                args += L" -p " + std::to_wstring(port);
                            }
                            args += L" " + b->r->ipAddress;
                            shellOpen(hDlg, L"cmd.exe", args);
                        }
                        return TRUE;
                    case IDC_HD_OPEN_TELNET:
                        // Telnet on any port: takes "host port" as separate
                        // args. Bare "telnet host" alone defaults to 23, but
                        // for non-23 services the user almost always wants
                        // to test a specific port (e.g. SMTP banner on 25,
                        // HTTP banner on 80, JetDirect on 9100).
                        if (b) {
                            int port = resolvePort(23);
                            std::wstring args = L"/k telnet " + b->r->ipAddress +
                                                L" " + std::to_wstring(port);
                            shellOpen(hDlg, L"cmd.exe", args);
                        }
                        return TRUE;
                    case IDC_HD_OPEN_VNC:
                        // vnc:// URL syntax accepts an optional :port suffix
                        // that all major VNC viewers (TightVNC, RealVNC,
                        // UltraVNC) honor.
                        if (b) {
                            int port = resolvePort(5900);
                            std::wstring url = L"vnc://" + b->r->ipAddress;
                            if (port != 5900) {
                                url += L":" + std::to_wstring(port);
                            }
                            shellOpen(hDlg, url, L"");
                        }
                        return TRUE;
                    case IDOK:
                    case IDCANCEL:
                        ::EndDialog(hDlg, IDOK);
                        return TRUE;
                }
                break;
            }
        }
        return FALSE;
    };

    ::DialogBoxParamW(hInst_, MAKEINTRESOURCEW(IDD_HOST_DETAILS), hwnd_,
                      static_cast<DLGPROC>(proc),
                      reinterpret_cast<LPARAM>(&bridge));
}

// =============================================================================
// Preset manager dialog
//
//   The dialog edits a working copy of the user-editable preset list. The two
//   auto-managed sentinels ("all" and "custom") are filtered out before the
//   dialog opens and auto-restored by ScanPresetService::setPresets() on OK,
//   so the dropdown stays consistent even after add/delete/edit.
// =============================================================================

namespace {

struct PresetMgrCtx {
    std::vector<ScanPreset> working;
    int                     selIdx = -1;
};

std::wstring listLineFor(const ScanPreset& p) {
    std::wstring line = p.displayName;
    line += L"   ·  ";
    line += std::to_wstring(p.ports.size());
    line += (p.ports.size() == 1 ? L" port" : L" ports");
    return line;
}

void pmRefreshList(HWND hDlg, PresetMgrCtx* ctx, int sel) {
    HWND lb = ::GetDlgItem(hDlg, IDC_PM_LIST);
    ::SendMessageW(lb, WM_SETREDRAW, FALSE, 0);
    ::SendMessageW(lb, LB_RESETCONTENT, 0, 0);
    for (const auto& p : ctx->working) {
        std::wstring line = listLineFor(p);
        ::SendMessageW(lb, LB_ADDSTRING, 0,
                       reinterpret_cast<LPARAM>(line.c_str()));
    }
    ::SendMessageW(lb, WM_SETREDRAW, TRUE, 0);
    ::InvalidateRect(lb, nullptr, TRUE);

    if (sel < 0 && !ctx->working.empty()) sel = 0;
    if (sel >= static_cast<int>(ctx->working.size())) {
        sel = static_cast<int>(ctx->working.size()) - 1;
    }

    if (sel >= 0) {
        ::SendMessageW(lb, LB_SETCURSEL, sel, 0);
        ctx->selIdx = sel;
        ::SetDlgItemTextW(hDlg, IDC_PM_NAME,  ctx->working[sel].displayName.c_str());
        ::SetDlgItemTextW(hDlg, IDC_PM_PORTS,
                          ScanPresetService::formatPortList(ctx->working[sel].ports).c_str());
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_NAME),   TRUE);
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_PORTS),  TRUE);
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_APPLY),  TRUE);
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_DELETE), TRUE);
    } else {
        ctx->selIdx = -1;
        ::SetDlgItemTextW(hDlg, IDC_PM_NAME,  L"");
        ::SetDlgItemTextW(hDlg, IDC_PM_PORTS, L"");
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_NAME),   FALSE);
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_PORTS),  FALSE);
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_APPLY),  FALSE);
        ::EnableWindow(::GetDlgItem(hDlg, IDC_PM_DELETE), FALSE);
    }
}

std::wstring pmReadEditText(HWND hDlg, int ctrlId) {
    HWND h = ::GetDlgItem(hDlg, ctrlId);
    int len = ::GetWindowTextLengthW(h);
    if (len <= 0) return {};
    std::wstring out(static_cast<size_t>(len), L'\0');
    int got = ::GetWindowTextW(h, out.data(), len + 1);
    out.resize(static_cast<size_t>(got));
    return out;
}

} // anonymous namespace

void MainWindow::rebuildPresetCombo(int selectIndex) {
    if (!cbPreset_) return;
    std::vector<std::wstring> items;
    for (const auto& p : ScanPresetService::presets()) {
        items.push_back(p.displayName);
    }
    if (selectIndex < 0 || selectIndex >= static_cast<int>(items.size())) {
        selectIndex = items.empty() ? -1 : 0;
    }
    cbFill(cbPreset_, items, selectIndex >= 0 ? selectIndex : 0);
    onPresetChanged();
}

void MainWindow::showPresetManager() {
    PresetMgrCtx ctx;
    for (const auto& p : ScanPresetService::presets()) {
        if (p.id == L"all" || p.id == L"custom") continue;
        ctx.working.push_back(p);
    }

    INT_PTR rc = ::DialogBoxParamW(hInst_, MAKEINTRESOURCEW(IDD_PRESET_MANAGER),
                                   hwnd_, &MainWindow::presetMgrDlgProc,
                                   reinterpret_cast<LPARAM>(&ctx));

    if (rc == IDOK) {
        ScanPresetService::setPresets(std::move(ctx.working));
        rebuildPresetCombo(0);
        setStatus(L"Port presets updated.");
    }
}

INT_PTR CALLBACK MainWindow::presetMgrDlgProc(HWND hDlg, UINT msg,
                                              WPARAM wParam, LPARAM lParam) {
    auto* ctx = reinterpret_cast<PresetMgrCtx*>(
        ::GetWindowLongPtrW(hDlg, GWLP_USERDATA));

    switch (msg) {
        case WM_INITDIALOG: {
            ctx = reinterpret_cast<PresetMgrCtx*>(lParam);
            ::SetWindowLongPtrW(hDlg, GWLP_USERDATA,
                                reinterpret_cast<LONG_PTR>(ctx));
            pmRefreshList(hDlg, ctx, ctx->working.empty() ? -1 : 0);
            return TRUE;
        }

        case WM_COMMAND: {
            if (!ctx) break;
            const WORD id     = LOWORD(wParam);
            const WORD notify = HIWORD(wParam);

            switch (id) {
                case IDC_PM_LIST:
                    if (notify == LBN_SELCHANGE) {
                        int sel = static_cast<int>(::SendMessageW(
                            ::GetDlgItem(hDlg, IDC_PM_LIST),
                            LB_GETCURSEL, 0, 0));
                        if (sel >= 0 && sel < static_cast<int>(ctx->working.size())) {
                            ctx->selIdx = sel;
                            ::SetDlgItemTextW(hDlg, IDC_PM_NAME,
                                              ctx->working[sel].displayName.c_str());
                            ::SetDlgItemTextW(hDlg, IDC_PM_PORTS,
                                              ScanPresetService::formatPortList(
                                                  ctx->working[sel].ports).c_str());
                        }
                    }
                    return TRUE;

                case IDC_PM_APPLY: {
                    if (ctx->selIdx < 0 ||
                        ctx->selIdx >= static_cast<int>(ctx->working.size())) {
                        return TRUE;
                    }
                    std::wstring name  = pmReadEditText(hDlg, IDC_PM_NAME);
                    std::wstring csv   = pmReadEditText(hDlg, IDC_PM_PORTS);
                    if (name.empty()) name = L"(unnamed preset)";
                    ctx->working[ctx->selIdx].displayName = name;
                    ctx->working[ctx->selIdx].ports =
                        ScanPresetService::parsePortList(csv);
                    pmRefreshList(hDlg, ctx, ctx->selIdx);
                    return TRUE;
                }

                case IDC_PM_NEW: {
                    ScanPreset np;
                    np.id          = L"user_" +
                                     std::to_wstring(ctx->working.size() + 1);
                    np.displayName = L"New preset";
                    np.ports       = {};
                    ctx->working.push_back(std::move(np));
                    pmRefreshList(hDlg, ctx, static_cast<int>(ctx->working.size()) - 1);
                    ::SetFocus(::GetDlgItem(hDlg, IDC_PM_NAME));
                    return TRUE;
                }

                case IDC_PM_DELETE: {
                    if (ctx->selIdx < 0 ||
                        ctx->selIdx >= static_cast<int>(ctx->working.size())) {
                        return TRUE;
                    }
                    ctx->working.erase(ctx->working.begin() + ctx->selIdx);
                    int newSel = ctx->selIdx;
                    if (newSel >= static_cast<int>(ctx->working.size())) {
                        newSel = static_cast<int>(ctx->working.size()) - 1;
                    }
                    pmRefreshList(hDlg, ctx, newSel);
                    return TRUE;
                }

                case IDC_PM_RESET: {
                    if (::MessageBoxW(hDlg,
                            L"Restore the built-in default presets and discard "
                            L"your edits in this dialog?",
                            L"Reset presets",
                            MB_OKCANCEL | MB_ICONQUESTION) != IDOK) {
                        return TRUE;
                    }
                    ctx->working = ScanPresetService::defaultPresets();
                    pmRefreshList(hDlg, ctx, 0);
                    return TRUE;
                }

                case IDOK:
                    ::EndDialog(hDlg, IDOK);
                    return TRUE;
                case IDCANCEL:
                    ::EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            return FALSE;
        }

        case WM_CLOSE:
            ::EndDialog(hDlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

} // namespace netlens::gui
