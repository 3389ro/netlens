#include "MonitorWindow.h"

#include "GuiUtils.h"
#include "../AppConstants.h"
#include "../core/IpAddressUtils.h"
#include "../resources/resource.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <uxtheme.h>

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <cwchar>

#pragma comment(lib, "uxtheme.lib")

namespace netlens::gui {

namespace {

constexpr wchar_t kClassName[]     = L"NetLensMonitorWnd";
constexpr UINT    kIdcNew          = 4001;
constexpr UINT    kIdcCloseTab     = 4002;
constexpr UINT    kIdcProbeCombo   = 4003;
constexpr UINT    kIdcPortEdit     = 4004;
constexpr UINT    kIdcIntervalCombo= 4005;
constexpr UINT    kIdcPauseBtn     = 4006;
constexpr UINT    kIdcResetBtn     = 4007;
constexpr UINT    kIdcTabControl   = 4008;
constexpr UINT    kIdcExportBtn    = 4009;

constexpr UINT    kTimerRefresh    = 1;

constexpr COLORREF kBgWindow   = RGB(246, 248, 252);
constexpr COLORREF kBgCard     = RGB(255, 255, 255);
constexpr COLORREF kBorder     = RGB(220, 226, 235);
constexpr COLORREF kFgPrimary  = RGB(25,  32,  44);
constexpr COLORREF kFgSecondary= RGB(90,  100, 115);
constexpr COLORREF kFgAccent   = RGB(31,  78,  162);
constexpr COLORREF kFgSuccess  = RGB(22,  163, 74);
constexpr COLORREF kFgDanger   = RGB(196, 30,  30);
constexpr COLORREF kFgChartLine= RGB(31,  78,  162);
constexpr COLORREF kFgChartFail= RGB(196, 30,  30);
constexpr COLORREF kFgGrid     = RGB(230, 235, 245);

// Simple modal prompt — single text box for an IP address. Returns the
// entered string or empty on cancel. Built on a bespoke #32770-class
// window so we don't need a resource entry per call site.
std::wstring promptForIp(HINSTANCE hInst, HWND parent,
                         const wchar_t* title,
                         const wchar_t* prompt,
                         const wchar_t* initial) {
    // Center against the parent (or screen if the parent rect is unusable).
    // CreateWindowExW does NOT honour DS_CENTER — that flag is only acted on
    // by the DialogBox* APIs — so without this the prompt lands at screen
    // (0,0). This was the bug behind "fereastra de add host se duce stanga
    // sus" in the user's v1.0.5 testing.
    constexpr int dlgW = 320;
    constexpr int dlgH = 130;
    int dlgX = 0, dlgY = 0;
    {
        RECT pr{};
        bool gotParent = parent && ::IsWindow(parent) && ::GetWindowRect(parent, &pr);
        if (gotParent && (pr.right - pr.left) > 0 && (pr.bottom - pr.top) > 0) {
            dlgX = pr.left + ((pr.right  - pr.left) - dlgW) / 2;
            dlgY = pr.top  + ((pr.bottom - pr.top)  - dlgH) / 2;
        } else {
            dlgX = (::GetSystemMetrics(SM_CXSCREEN) - dlgW) / 2;
            dlgY = (::GetSystemMetrics(SM_CYSCREEN) - dlgH) / 2;
        }
        if (dlgX < 0) dlgX = 0;
        if (dlgY < 0) dlgY = 0;
    }

    HWND dlg = ::CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
                                  L"#32770", title,
                                  WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                  dlgX, dlgY, dlgW, dlgH,
                                  parent, nullptr, hInst, nullptr);
    if (!dlg) return L"";
    std::wstring initialText = initial ? std::wstring(initial) : L"";

    HFONT font = createUiFont(parent, 10, false);
    HWND lbl = ::CreateWindowExW(0, L"STATIC", prompt,
                                 WS_CHILD | WS_VISIBLE | SS_LEFT,
                                 12, 14, 296, 16, dlg, nullptr, hInst, nullptr);
    ::SendMessageW(lbl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    HWND ed = ::CreateWindowExW(0, L"EDIT", initialText.c_str(),
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL,
                                12, 36, 296, 24, dlg, nullptr, hInst, nullptr);
    ::SendMessageW(ed, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    HWND okBtn = ::CreateWindowExW(0, L"BUTTON", L"OK",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                    180, 74, 60, 22, dlg,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)),
                                    hInst, nullptr);
    ::SendMessageW(okBtn, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    HWND cancelBtn = ::CreateWindowExW(0, L"BUTTON", L"Cancel",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                        246, 74, 60, 22, dlg,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)),
                                        hInst, nullptr);
    ::SendMessageW(cancelBtn, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    ::SetFocus(ed);
    ::SendMessageW(ed, EM_SETSEL, 0, -1);
    ::EnableWindow(parent, FALSE);
    ::ShowWindow(dlg, SW_SHOW);
    ::UpdateWindow(dlg);

    MSG msg;
    bool done = false;
    bool ok   = false;
    while (!done && ::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            ok = true; done = true; break;
        }
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            done = true; break;
        }
        if (msg.message == WM_COMMAND && (HWND)msg.lParam == okBtn) {
            ok = true; done = true; break;
        }
        if (msg.message == WM_COMMAND && (HWND)msg.lParam == cancelBtn) {
            done = true; break;
        }
        if (!::IsDialogMessageW(dlg, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
        if (!::IsWindow(dlg)) { done = true; break; }
    }

    std::wstring out;
    if (ok) {
        int len = ::GetWindowTextLengthW(ed);
        if (len > 0) {
            out.resize(static_cast<size_t>(len), L'\0');
            ::GetWindowTextW(ed, out.data(), len + 1);
            out.resize(static_cast<size_t>(len));
        }
    }

    ::EnableWindow(parent, TRUE);
    if (::IsWindow(dlg)) ::DestroyWindow(dlg);
    if (font) ::DeleteObject(font);
    return out;
}

ProbeType comboIndexToProbe(int idx) {
    switch (idx) {
        case 0: return ProbeType::Icmp;
        case 1: return ProbeType::Tcp;
        case 2: return ProbeType::Http;
        case 3: return ProbeType::Https;
        default: return ProbeType::Icmp;
    }
}
int probeToComboIndex(ProbeType t) {
    switch (t) {
        case ProbeType::Icmp:  return 0;
        case ProbeType::Tcp:   return 1;
        case ProbeType::Http:  return 2;
        case ProbeType::Https: return 3;
    }
    return 0;
}

const int kIntervalMs[] = { 500, 1000, 2000, 5000, 10000, 30000 };
const wchar_t* kIntervalLbl[] = {
    L"0.5 s", L"1 s", L"2 s", L"5 s", L"10 s", L"30 s"
};
int intervalToComboIndex(int ms) {
    for (int i = 0; i < (int)(sizeof(kIntervalMs)/sizeof(int)); ++i) {
        if (kIntervalMs[i] == ms) return i;
    }
    return 1;
}

} // anonymous namespace

MonitorWindow* MonitorWindow::s_instance_ = nullptr;

MonitorWindow* MonitorWindow::addMonitor(HINSTANCE hInst, HWND parent,
                                         const MonitorConfig& cfg) {
    if (!s_instance_) {
        s_instance_ = new MonitorWindow(hInst, parent);
        if (!s_instance_->createWindow()) {
            delete s_instance_;
            s_instance_ = nullptr;
            return nullptr;
        }
    }
    if (static_cast<int>(s_instance_->tabs_.size()) >= kMaxMonitors) {
        // Hard cap. 16 worker threads + 16 HostMonitor instances each holding
        // a 600-sample deque + an open CSV log file is plenty for the use
        // case (multi-host network monitoring); going higher invites resource
        // leaks and weird thread-storm behaviour.
        wchar_t msg[160];
        std::swprintf(msg, 160,
            L"You already have %d monitors open — that's the maximum.\n"
            L"Close a tab before adding a new host.", kMaxMonitors);
        ::MessageBoxW(s_instance_->hwnd_, msg, L"NetLens Monitor",
                       MB_OK | MB_ICONINFORMATION);
        ::SetForegroundWindow(s_instance_->hwnd_);
        return s_instance_;
    }
    s_instance_->addTab(cfg);
    ::ShowWindow(s_instance_->hwnd_, SW_SHOW);
    ::SetForegroundWindow(s_instance_->hwnd_);
    return s_instance_;
}

void MonitorWindow::bringToFront() {
    if (s_instance_ && s_instance_->hwnd_) {
        ::ShowWindow(s_instance_->hwnd_, SW_SHOWNORMAL);
        ::SetForegroundWindow(s_instance_->hwnd_);
    }
}

bool MonitorWindow::isOpen() {
    return s_instance_ != nullptr;
}

int MonitorWindow::activeCount() {
    return s_instance_ ? static_cast<int>(s_instance_->tabs_.size()) : 0;
}

MonitorWindow::MonitorWindow(HINSTANCE hInst, HWND parent)
    : hInst_(hInst), parent_(parent) {}

MonitorWindow::~MonitorWindow() {
    for (auto& t : tabs_) {
        if (t.monitor) t.monitor->stop();
    }
    releaseChartBuffer();
    if (bodyFont_)   ::DeleteObject(bodyFont_);
    if (labelFont_)  ::DeleteObject(labelFont_);
    if (statusFont_) ::DeleteObject(statusFont_);
    if (statsFont_)  ::DeleteObject(statsFont_);
}

void MonitorWindow::ensureChartBuffer(int w, int h) {
    if (w <= 0 || h <= 0) return;
    if (chartBmp_ && chartMemDC_ && chartBmpW_ == w && chartBmpH_ == h) return;

    // Tear down the previous buffer (if any) before resizing.
    releaseChartBuffer();

    HDC screenDC = ::GetDC(hwnd_);
    if (!screenDC) return;
    chartMemDC_ = ::CreateCompatibleDC(screenDC);
    chartBmp_   = ::CreateCompatibleBitmap(screenDC, w, h);
    ::ReleaseDC(hwnd_, screenDC);
    if (chartMemDC_ && chartBmp_) {
        ::SelectObject(chartMemDC_, chartBmp_);
        chartBmpW_ = w;
        chartBmpH_ = h;
    } else {
        releaseChartBuffer();
    }
}

void MonitorWindow::releaseChartBuffer() {
    if (chartMemDC_) { ::DeleteDC(chartMemDC_); chartMemDC_ = nullptr; }
    if (chartBmp_)   { ::DeleteObject(chartBmp_); chartBmp_ = nullptr; }
    chartBmpW_ = 0;
    chartBmpH_ = 0;
}

LRESULT CALLBACK MonitorWindow::staticWndProc(HWND hWnd, UINT msg,
                                              WPARAM wParam, LPARAM lParam) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        auto* self = static_cast<MonitorWindow*>(cs->lpCreateParams);
        self->hwnd_ = hWnd;
        ::SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    auto* self = reinterpret_cast<MonitorWindow*>(
        ::GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    if (self) return self->wndProc(msg, wParam, lParam);
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

bool MonitorWindow::createWindow() {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &MonitorWindow::staticWndProc;
    wc.hInstance     = hInst_;
    wc.hCursor       = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = cachedSolidBrush(kBgWindow);
    wc.lpszClassName = kClassName;
    wc.hIcon         = ::LoadIconW(hInst_, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hIconSm       = wc.hIcon;
    ::RegisterClassExW(&wc);

    int dpi = dpiFor(parent_);
    int w = MulDiv(720, dpi, 96);
    int h = MulDiv(540, dpi, 96);
    int x = (::GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (::GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    HWND wnd = ::CreateWindowExW(
        0, kClassName, L"NetLens Monitor",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        x, y, w, h,
        nullptr, nullptr, hInst_, this);
    return wnd != nullptr;
}

void MonitorWindow::onCreate() {
    bodyFont_   = createUiFont(hwnd_, 10, false);
    labelFont_  = createUiFont(hwnd_, 9,  false);
    statusFont_ = createUiFont(hwnd_, 12, true);
    statsFont_  = createUiFont(hwnd_, 10, false);

    auto setF = [&](HWND h, HFONT f) {
        ::SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), TRUE);
    };

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    ::InitCommonControlsEx(&icc);

    // SysTabControl32 — themed so it renders as proper Win10/11 tabs rather
    // than the old chunky look that made the user think they were modal
    // frames. We also drop TCS_FIXEDWIDTH so each tab sizes to its label,
    // and add TCS_TOOLTIPS so very long titles show on hover.
    hTab_ = ::CreateWindowExW(0, WC_TABCONTROLW, L"",
                              WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS |
                              TCS_TOOLTIPS | TCS_FOCUSNEVER,
                              0, 0, 0, 0, hwnd_,
                              reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcTabControl)),
                              hInst_, nullptr);
    setF(hTab_, bodyFont_);
    ::SetWindowTheme(hTab_, L"Explorer", nullptr);
    // Min tab item size so even single-char labels look like a tab and
    // not a button. 14 dlu vertical so tab strip is comfortable to click.
    TabCtrl_SetMinTabWidth(hTab_, MulDiv(100, dpiFor(hwnd_), 96));
    TabCtrl_SetPadding(hTab_, MulDiv(12, dpiFor(hwnd_), 96),
                                MulDiv(4,  dpiFor(hwnd_), 96));

    btnNew_ = ::CreateWindowExW(0, L"BUTTON", L"+ Add",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                0, 0, 0, 0, hwnd_,
                                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcNew)),
                                hInst_, nullptr);
    setF(btnNew_, bodyFont_);

    btnCloseTab_ = ::CreateWindowExW(0, L"BUTTON", L"Close tab",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                      0, 0, 0, 0, hwnd_,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcCloseTab)),
                                      hInst_, nullptr);
    setF(btnCloseTab_, bodyFont_);

    auto mkLabel = [&](const wchar_t* text) {
        HWND h = ::CreateWindowExW(0, L"STATIC", text,
                                   WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   0, 0, 0, 0, hwnd_, nullptr, hInst_, nullptr);
        setF(h, labelFont_);
        return h;
    };
    lblProbe_    = mkLabel(L"Probe");
    lblPort_     = mkLabel(L"Port");
    lblInterval_ = mkLabel(L"Interval");

    cbProbe_ = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                 0, 0, 0, 0, hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcProbeCombo)),
                                 hInst_, nullptr);
    setF(cbProbe_, bodyFont_);
    ::SendMessageW(cbProbe_, CB_ADDSTRING, 0, (LPARAM)L"ICMP");
    ::SendMessageW(cbProbe_, CB_ADDSTRING, 0, (LPARAM)L"TCP");
    ::SendMessageW(cbProbe_, CB_ADDSTRING, 0, (LPARAM)L"HTTP");
    ::SendMessageW(cbProbe_, CB_ADDSTRING, 0, (LPARAM)L"HTTPS");

    edPort_ = ::CreateWindowExW(0, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_NUMBER,
                                 0, 0, 0, 0, hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcPortEdit)),
                                 hInst_, nullptr);
    setF(edPort_, bodyFont_);

    cbInterval_ = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                     0, 0, 0, 0, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcIntervalCombo)),
                                     hInst_, nullptr);
    setF(cbInterval_, bodyFont_);
    for (auto* lbl : kIntervalLbl) {
        ::SendMessageW(cbInterval_, CB_ADDSTRING, 0, (LPARAM)lbl);
    }

    btnPause_ = ::CreateWindowExW(0, L"BUTTON", L"Pause",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   0, 0, 0, 0, hwnd_,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcPauseBtn)),
                                   hInst_, nullptr);
    setF(btnPause_, bodyFont_);

    btnReset_ = ::CreateWindowExW(0, L"BUTTON", L"Reset stats",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   0, 0, 0, 0, hwnd_,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcResetBtn)),
                                   hInst_, nullptr);
    setF(btnReset_, bodyFont_);

    btnExport_ = ::CreateWindowExW(0, L"BUTTON", L"Export samples...",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                    0, 0, 0, 0, hwnd_,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdcExportBtn)),
                                    hInst_, nullptr);
    setF(btnExport_, bodyFont_);

    lblStatus_ = ::CreateWindowExW(0, L"STATIC", L"",
                                    WS_CHILD | WS_VISIBLE | SS_LEFT,
                                    0, 0, 0, 0, hwnd_, nullptr, hInst_, nullptr);
    setF(lblStatus_, statusFont_);

    lblStats_ = ::CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   0, 0, 0, 0, hwnd_, nullptr, hInst_, nullptr);
    setF(lblStats_, statsFont_);

    lblLog_ = ::CreateWindowExW(0, L"STATIC", L"",
                                 WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
                                 0, 0, 0, 0, hwnd_, nullptr, hInst_, nullptr);
    setF(lblLog_, labelFont_);

    refreshTimer_ = ::SetTimer(hwnd_, kTimerRefresh, 500, nullptr);
}

void MonitorWindow::onSize(int w, int h) {
    int dpi = dpiFor(hwnd_);
    auto px = [&](int v){ return MulDiv(v, dpi, 96); };

    const int marginX = px(12);
    const int marginY = px(12);
    const int gap     = px(8);
    const int rowH    = px(26);
    const int btnH    = px(26);
    const int lblH    = px(14);

    // ---- Tab row at top ----
    int tabH = px(28);
    int newW = px(70);
    int closeW = px(80);
    ::MoveWindow(hTab_,        marginX, marginY,
                 w - 2 * marginX - newW - closeW - 2 * gap, tabH, TRUE);
    ::MoveWindow(btnNew_,      w - marginX - newW - closeW - gap,
                 marginY, newW, tabH, TRUE);
    ::MoveWindow(btnCloseTab_, w - marginX - closeW, marginY, closeW, tabH, TRUE);

    // ---- Body controls row ----
    int yBody = marginY + tabH + gap + px(8);
    int probeLblW = px(40);
    int probeW    = px(80);
    int portLblW  = px(28);
    int portW     = px(60);
    int intLblW   = px(50);
    int intW      = px(70);
    int pauseW    = px(70);
    int resetW    = px(86);

    int exportW = px(120);

    int x = marginX;
    ::MoveWindow(lblProbe_,    x, yBody + px(6), probeLblW, lblH, TRUE);
    x += probeLblW + px(4);
    ::MoveWindow(cbProbe_,     x, yBody, probeW, rowH, TRUE);
    x += probeW + gap;
    ::MoveWindow(lblPort_,     x, yBody + px(6), portLblW, lblH, TRUE);
    x += portLblW + px(4);
    ::MoveWindow(edPort_,      x, yBody, portW, rowH, TRUE);
    x += portW + gap;
    ::MoveWindow(lblInterval_, x, yBody + px(6), intLblW, lblH, TRUE);
    x += intLblW + px(4);
    ::MoveWindow(cbInterval_,  x, yBody, intW, rowH, TRUE);
    x += intW + gap * 2;
    ::MoveWindow(btnPause_,    x, yBody, pauseW, btnH, TRUE);
    x += pauseW + gap;
    ::MoveWindow(btnReset_,    x, yBody, resetW, btnH, TRUE);
    // Export anchored to the right edge so it doesn't fight the row's
    // density on narrow window sizes.
    ::MoveWindow(btnExport_, w - marginX - exportW, yBody, exportW, btnH, TRUE);

    // ---- Status / stats / log path ----
    int yStatus = yBody + rowH + gap + px(6);
    ::MoveWindow(lblStatus_, marginX, yStatus,
                 w - 2 * marginX, px(20), TRUE);
    ::MoveWindow(lblStats_,  marginX, yStatus + px(22),
                 w - 2 * marginX, px(18), TRUE);
    ::MoveWindow(lblLog_,    marginX, yStatus + px(42),
                 w - 2 * marginX, px(16), TRUE);

    // ---- Chart area ----
    int yChart = yStatus + px(66);
    int chartH = h - yChart - marginY;
    if (chartH < px(120)) chartH = px(120);
    rectChart_ = RECT{ marginX, yChart,
                        w - marginX, yChart + chartH };

    // Resize the chart's double-buffer to match.
    ensureChartBuffer(rectChart_.right - rectChart_.left,
                       rectChart_.bottom - rectChart_.top);
}

LRESULT MonitorWindow::wndProc(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:                onCreate(); return 0;
        case WM_SIZE:                  onSize(LOWORD(lParam), HIWORD(lParam));
                                       ::InvalidateRect(hwnd_, nullptr, TRUE);
                                       return 0;
        case WM_PAINT:                 onPaint();  return 0;
        case WM_ERASEBKGND:            return 1;
        case WM_COMMAND:
            onCommand(LOWORD(wParam), HIWORD(wParam),
                      reinterpret_cast<HWND>(lParam));
            return 0;
        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<LPNMHDR>(lParam);
            return onNotify(nm);
        }
        case WM_TIMER:
            if (wParam == kTimerRefresh) {
                refreshActiveBody();
                ::InvalidateRect(hwnd_, &rectChart_, FALSE);
            }
            return 0;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            HWND ctl = reinterpret_cast<HWND>(lParam);
            ::SetBkMode(dc, TRANSPARENT);
            if (ctl == lblStatus_) {
                ::SetTextColor(dc, kFgPrimary);
            } else if (ctl == lblStats_) {
                ::SetTextColor(dc, kFgSecondary);
            } else {
                ::SetTextColor(dc, kFgSecondary);
            }
            return reinterpret_cast<LRESULT>(cachedSolidBrush(kBgWindow));
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, OPAQUE);
            ::SetBkColor(dc, kBgCard);
            ::SetTextColor(dc, kFgPrimary);
            return reinterpret_cast<LRESULT>(cachedSolidBrush(kBgCard));
        }
        case WM_CLOSE:
            onDestroy();
            return 0;
        case WM_DESTROY:
            if (refreshTimer_) ::KillTimer(hwnd_, kTimerRefresh);
            return 0;
    }
    return ::DefWindowProcW(hwnd_, msg, wParam, lParam);
}

void MonitorWindow::onPaint() {
    PAINTSTRUCT ps;
    HDC dc = ::BeginPaint(hwnd_, &ps);
    RECT rc; ::GetClientRect(hwnd_, &rc);
    ::FillRect(dc, &rc, cachedSolidBrush(kBgWindow));
    paintChart(dc, rectChart_);
    ::EndPaint(hwnd_, &ps);
}

void MonitorWindow::paintChart(HDC dc, const RECT& rc) {
    const int W = rc.right  - rc.left;
    const int H = rc.bottom - rc.top;
    if (W <= 0 || H <= 0) return;

    // Make sure the back-buffer matches the current chart size. onSize already
    // calls ensureChartBuffer, but on first paint before WM_SIZE arrives the
    // buffer may not exist yet.
    ensureChartBuffer(W, H);
    HDC memDC = chartMemDC_;
    const bool buffered = (memDC != nullptr);
    // Local rectangle in buffer coordinates (origin 0,0); we BitBlt at the end.
    RECT lrc{ 0, 0, W, H };
    HDC paintDC = buffered ? memDC : dc;
    const int offX = buffered ? 0 : rc.left;
    const int offY = buffered ? 0 : rc.top;
    if (!buffered) lrc = rc;

    // Card background + border.
    ::FillRect(paintDC, &lrc, cachedSolidBrush(kBgCard));
    {
        HBRUSH br = cachedSolidBrush(kBorder);
        RECT t{ lrc.left, lrc.top, lrc.right, lrc.top + 1 };
        RECT b{ lrc.left, lrc.bottom - 1, lrc.right, lrc.bottom };
        RECT l{ lrc.left, lrc.top, lrc.left + 1, lrc.bottom };
        RECT r{ lrc.right - 1, lrc.top, lrc.right, lrc.bottom };
        ::FillRect(paintDC, &t, br); ::FillRect(paintDC, &b, br);
        ::FillRect(paintDC, &l, br); ::FillRect(paintDC, &r, br);
    }

    auto blitOut = [&]() {
        if (buffered) {
            ::BitBlt(dc, rc.left, rc.top, W, H, memDC, 0, 0, SRCCOPY);
        }
    };

    if (active_ < 0 || active_ >= (int)tabs_.size()) { blitOut(); return; }
    auto& tab = tabs_[active_];
    if (!tab.monitor) { blitOut(); return; }

    auto samples = tab.monitor->snapshot();
    if (samples.size() < 2) {
        ::SetBkMode(paintDC, TRANSPARENT);
        ::SetTextColor(paintDC, kFgSecondary);
        HFONT prev = (HFONT)::SelectObject(paintDC, bodyFont_);
        ::DrawTextW(paintDC, L"Waiting for samples...", -1, &lrc,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        ::SelectObject(paintDC, prev);
        blitOut();
        return;
    }

    // Padding inside the chart card.
    int padL = 40, padR = 12, padT = 12, padB = 24;
    int plotL = lrc.left + padL;
    int plotT = lrc.top + padT;
    int plotR = lrc.right - padR;
    int plotB = lrc.bottom - padB;
    int plotW = plotR - plotL;
    int plotH = plotB - plotT;
    if (plotW <= 0 || plotH <= 0) { blitOut(); return; }

    // Y axis scaling — use observed max latency, clamped to a minimum
    // for visual sanity.
    int maxMs = 10;
    for (const auto& s : samples) {
        if (s.success && s.latencyMs > maxMs) maxMs = s.latencyMs;
    }
    int gridStep;
    if      (maxMs <= 20)   { maxMs = 20;   gridStep = 5;  }
    else if (maxMs <= 50)   { maxMs = 50;   gridStep = 10; }
    else if (maxMs <= 100)  { maxMs = 100;  gridStep = 25; }
    else if (maxMs <= 250)  { maxMs = 250;  gridStep = 50; }
    else if (maxMs <= 500)  { maxMs = 500;  gridStep = 100;}
    else if (maxMs <= 1000) { maxMs = 1000; gridStep = 250;}
    else                    { maxMs = ((maxMs + 499)/500)*500; gridStep = maxMs/4; }

    HFONT prev = (HFONT)::SelectObject(paintDC, labelFont_);
    ::SetBkMode(paintDC, TRANSPARENT);

    // Horizontal grid lines + Y labels.
    HBRUSH gridBr = cachedSolidBrush(kFgGrid);
    for (int v = 0; v <= maxMs; v += gridStep) {
        int y = plotB - (v * plotH / maxMs);
        RECT line{ plotL, y, plotR, y + 1 };
        ::FillRect(paintDC, &line, gridBr);
        wchar_t lblBuf[16];
        std::swprintf(lblBuf, 16, L"%d ms", v);
        RECT lblR{ lrc.left + 4, y - 8, plotL - 4, y + 8 };
        ::SetTextColor(paintDC, kFgSecondary);
        ::DrawTextW(paintDC, lblBuf, -1, &lblR,
                    DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    }

    std::vector<POINT> linePts;
    linePts.reserve(samples.size());
    std::vector<int>   failX;
    failX.reserve(samples.size());

    int n = (int)samples.size();
    for (int i = 0; i < n; ++i) {
        int x = plotL + (i * plotW) / std::max(1, n - 1);
        if (samples[i].success) {
            int y = plotB - (samples[i].latencyMs * plotH / maxMs);
            if (y < plotT) y = plotT;
            linePts.push_back({ x, y });
        } else {
            failX.push_back(x);
        }
    }

    if (!failX.empty()) {
        HBRUSH failBr = cachedSolidBrush(kFgChartFail);
        for (int x : failX) {
            RECT bar{ x - 1, plotB - 4, x + 1, plotB };
            ::FillRect(paintDC, &bar, failBr);
        }
    }

    if (linePts.size() >= 2) {
        HPEN pen = ::CreatePen(PS_SOLID, 2, kFgChartLine);
        HPEN oldPen = (HPEN)::SelectObject(paintDC, pen);
        ::Polyline(paintDC, linePts.data(), (int)linePts.size());
        ::SelectObject(paintDC, oldPen);
        ::DeleteObject(pen);
    }

    if (!linePts.empty()) {
        const POINT& p = linePts.back();
        HBRUSH dotBr = cachedSolidBrush(kFgAccent);
        RECT dot{ p.x - 3, p.y - 3, p.x + 4, p.y + 4 };
        ::FillRect(paintDC, &dot, dotBr);
    }

    ::SetTextColor(paintDC, kFgSecondary);
    RECT xLbl{ plotL, plotB + 4, plotR, plotB + padB };
    wchar_t caption[64];
    std::swprintf(caption, 64, L"last %d samples", n);
    ::DrawTextW(paintDC, caption, -1, &xLbl,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    ::SelectObject(paintDC, prev);

    (void)offX; (void)offY; // unused once we always blit from origin
    blitOut();
}

void MonitorWindow::onCommand(WORD id, WORD /*code*/, HWND /*ctl*/) {
    switch (id) {
        case kIdcNew:        onNewMonitorClicked(); return;
        case kIdcCloseTab:   onCloseTabClicked();   return;
        case kIdcPauseBtn:   onPauseToggle();       return;
        case kIdcResetBtn:
            if (active_ >= 0 && active_ < (int)tabs_.size()) {
                tabs_[active_].monitor->resetStats();
                ::InvalidateRect(hwnd_, nullptr, TRUE);
            }
            return;
        case kIdcProbeCombo:
            onProbeTypeChanged();
            return;
        case kIdcPortEdit:
            // EN_CHANGE fires while typing; apply on focus loss or pause.
            // Simplest: apply immediately. The thread snapshots config
            // each iteration.
            onPortChanged();
            return;
        case kIdcIntervalCombo:
            onIntervalChanged();
            return;
        case kIdcExportBtn:
            onExportClicked();
            return;
    }
}

LRESULT MonitorWindow::onNotify(LPNMHDR nm) {
    if (!nm) return 0;
    if (nm->hwndFrom == hTab_ && nm->code == TCN_SELCHANGE) {
        int sel = TabCtrl_GetCurSel(hTab_);
        selectTab(sel);
    }
    return 0;
}

void MonitorWindow::onDestroy() {
    for (auto& t : tabs_) {
        if (t.monitor) t.monitor->stop();
    }
    tabs_.clear();
    active_ = -1;
    HWND wnd = hwnd_;
    s_instance_ = nullptr;
    ::DestroyWindow(wnd);
    delete this;
}

void MonitorWindow::addTab(const MonitorConfig& cfg) {
    Tab t;
    t.title = cfg.hostname.empty() ? cfg.ip
                                    : (cfg.hostname + L"  (" + cfg.ip + L")");
    t.monitor = std::make_unique<HostMonitor>(cfg, nullptr);
    t.monitor->start();
    tabs_.push_back(std::move(t));

    TCITEMW ti{};
    ti.mask = TCIF_TEXT;
    ti.pszText = const_cast<LPWSTR>(tabs_.back().title.c_str());
    TabCtrl_InsertItem(hTab_, (int)tabs_.size() - 1, &ti);
    selectTab((int)tabs_.size() - 1);
}

void MonitorWindow::removeTab(int index) {
    if (index < 0 || index >= (int)tabs_.size()) return;
    if (tabs_[index].monitor) tabs_[index].monitor->stop();
    tabs_.erase(tabs_.begin() + index);
    TabCtrl_DeleteItem(hTab_, index);
    if (tabs_.empty()) {
        onDestroy();
        return;
    }
    if (active_ >= (int)tabs_.size()) active_ = (int)tabs_.size() - 1;
    if (active_ < 0) active_ = 0;
    TabCtrl_SetCurSel(hTab_, active_);
    refreshActiveBody();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
}

void MonitorWindow::selectTab(int index) {
    if (index < 0 || index >= (int)tabs_.size()) {
        active_ = -1;
        return;
    }
    active_ = index;
    TabCtrl_SetCurSel(hTab_, index);
    refreshActiveBody();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
}

void MonitorWindow::refreshActiveBody() {
    if (active_ < 0 || active_ >= (int)tabs_.size()) return;
    auto& tab = tabs_[active_];
    if (!tab.monitor) return;

    auto cfg = tab.monitor->config();
    ::SendMessageW(cbProbe_,    CB_SETCURSEL, probeToComboIndex(cfg.type),  0);
    ::SendMessageW(cbInterval_, CB_SETCURSEL, intervalToComboIndex(cfg.intervalMs), 0);

    bool showPort = (cfg.type != ProbeType::Icmp);
    ::EnableWindow(edPort_, showPort);
    ::EnableWindow(lblPort_, showPort);
    wchar_t portBuf[16];
    std::swprintf(portBuf, 16, L"%d", cfg.port);
    setText(edPort_, portBuf);

    ::SetWindowTextW(btnPause_, tab.monitor->isPaused() ? L"Resume" : L"Pause");

    auto stats = tab.monitor->stats();
    wchar_t status[200];
    if (stats.samples == 0) {
        std::swprintf(status, 200, L"○  Starting...   Monitoring %ls",
                       cfg.ip.c_str());
    } else {
        const bool up = stats.lastMs >= 0;
        // Materialise the latency string so we don't pass a c_str() into
        // a temporary. (%ls = wide-char in MS wide-printf.)
        wchar_t lastBuf[32];
        if (up) std::swprintf(lastBuf, 32, L"%d ms", stats.lastMs);
        else    std::swprintf(lastBuf, 32, L"—");
        std::swprintf(status, 200, L"%ls  %ls   Last: %ls",
                       up ? L"●" : L"●",
                       up ? L"UP" : L"DOWN",
                       lastBuf);
    }
    setText(lblStatus_, status);

    wchar_t statline[256];
    std::swprintf(statline, 256,
        L"Probe %ls   ·   Min %d / Avg %.1f / Max %d ms   ·   Uptime %.1f%%   ·   %d samples",
        ProbeTypeToString(cfg.type),
        stats.minMs >= 0 ? stats.minMs : 0,
        stats.avgMs,
        stats.maxMs >= 0 ? stats.maxMs : 0,
        stats.uptimePct,
        stats.samples);
    setText(lblStats_, statline);

    // Log path label — confirms to the user that auto-save is on and shows
    // exactly where the CSV is, so Export samples is just a copy-to-known.
    std::wstring logPath = tab.monitor->logPath();
    if (logPath.empty()) {
        setText(lblLog_, L"Auto-saving samples...");
    } else {
        setText(lblLog_, L"Auto-save CSV: " + logPath);
    }
}

void MonitorWindow::onNewMonitorClicked() {
    std::wstring ip = promptForIp(hInst_, hwnd_,
        L"Add monitor",
        L"Enter an IP address (or hostname) to monitor:",
        L"");
    if (ip.empty()) return;
    MonitorConfig cfg;
    cfg.ip = ip;
    cfg.hostname.clear();
    cfg.type = ProbeType::Icmp;
    cfg.port = 80;
    cfg.intervalMs = 1000;
    cfg.timeoutMs  = 800;
    addTab(cfg);
}

void MonitorWindow::onCloseTabClicked() {
    if (active_ >= 0) removeTab(active_);
}

void MonitorWindow::onPauseToggle() {
    if (active_ < 0 || active_ >= (int)tabs_.size()) return;
    auto& m = tabs_[active_].monitor;
    if (!m) return;
    if (m->isPaused()) m->resume();
    else               m->pause();
    refreshActiveBody();
}

void MonitorWindow::onProbeTypeChanged() {
    if (active_ < 0 || active_ >= (int)tabs_.size()) return;
    auto& m = tabs_[active_].monitor;
    if (!m) return;
    MonitorConfig cfg = m->config();
    int idx = (int)::SendMessageW(cbProbe_, CB_GETCURSEL, 0, 0);
    cfg.type = comboIndexToProbe(idx);
    // Set sensible default port per type if the existing one looks "wrong".
    if (cfg.type == ProbeType::Http  && cfg.port != 80 && cfg.port != 8080) cfg.port = 80;
    if (cfg.type == ProbeType::Https && cfg.port != 443 && cfg.port != 8443) cfg.port = 443;
    if (cfg.type == ProbeType::Tcp   && (cfg.port < 1 || cfg.port > 65535)) cfg.port = 80;
    m->setConfig(cfg);
    refreshActiveBody();
}

void MonitorWindow::onPortChanged() {
    if (active_ < 0 || active_ >= (int)tabs_.size()) return;
    auto& m = tabs_[active_].monitor;
    if (!m) return;
    wchar_t buf[16] = {};
    ::GetWindowTextW(edPort_, buf, 15);
    int p = _wtoi(buf);
    if (p < 1 || p > 65535) return;
    auto cfg = m->config();
    cfg.port = p;
    m->setConfig(cfg);
}

void MonitorWindow::onIntervalChanged() {
    if (active_ < 0 || active_ >= (int)tabs_.size()) return;
    auto& m = tabs_[active_].monitor;
    if (!m) return;
    int idx = (int)::SendMessageW(cbInterval_, CB_GETCURSEL, 0, 0);
    if (idx < 0 || idx >= (int)(sizeof(kIntervalMs)/sizeof(int))) return;
    auto cfg = m->config();
    cfg.intervalMs = kIntervalMs[idx];
    m->setConfig(cfg);
}

void MonitorWindow::closeIfEmpty() {
    if (tabs_.empty()) onDestroy();
}

void MonitorWindow::refreshChart() {
    ::InvalidateRect(hwnd_, &rectChart_, FALSE);
}

void MonitorWindow::onExportClicked() {
    // Export = a snapshot copy of the auto-save CSV. The auto-save log is
    // already a complete, ever-growing CSV; copying it is faster and more
    // honest than re-serialising the in-memory ring buffer (which is capped
    // at kMaxSamples = 600 samples).
    if (active_ < 0 || active_ >= (int)tabs_.size()) return;
    auto& m = tabs_[active_].monitor;
    if (!m) return;
    std::wstring src = m->logPath();
    if (src.empty()) {
        ::MessageBoxW(hwnd_,
                       L"This monitor hasn't logged any samples yet.\n"
                       L"Wait for at least one probe to complete and try again.",
                       L"Export samples", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Suggest a default filename = the auto-save log's basename.
    std::wstring defaultName;
    size_t slash = src.find_last_of(L"\\/");
    defaultName = (slash == std::wstring::npos) ? src : src.substr(slash + 1);

    std::wstring dst = promptSaveAs(hwnd_,
                                    L"Export monitor samples",
                                    defaultName.c_str(),
                                    L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0");
    if (dst.empty()) return;

    // Flush whatever the worker has queued before copying. The log handle
    // is opened with FILE_APPEND_DATA so OS buffers should already be
    // visible, but FlushFileBuffers makes it deterministic.
    // (We don't expose the handle here — the writes are already done
    //  synchronously inside appendLogRow, so a plain CopyFileW suffices.)
    if (!::CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
        DWORD err = ::GetLastError();
        wchar_t msg[256];
        std::swprintf(msg, 256,
                       L"Failed to write %ls\nWindows error %lu.",
                       dst.c_str(), err);
        ::MessageBoxW(hwnd_, msg, L"Export samples", MB_OK | MB_ICONERROR);
        return;
    }
    revealInExplorer(dst);
}

} // namespace netlens::gui
