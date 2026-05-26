#include "SettingsDialog.h"

#include <cstdio>
#include <string>

#include "../App.h"
#include "../Dpi.h"
#include "../Models.h"
#include "../Theme.h"
#include "../../Resource.h"
#include "../Capture.h"

namespace nl {

namespace {

constexpr const wchar_t* kClassName = L"NetLensSettingsDlg";

constexpr int kId_TimeoutEdit       = 2001;
constexpr int kId_ParallelEdit      = 2002;
constexpr int kId_FingerprintEdit   = 2003;
constexpr int kId_ModeCombo         = 2004;
constexpr int kId_SkipDns           = 2101;
constexpr int kId_SkipMac           = 2102;
constexpr int kId_SkipPorts         = 2103;
constexpr int kId_SkipFingerprint   = 2104;
constexpr int kId_SkipClockDrift    = 2105;
constexpr int kId_BtnOk             = 2201;
constexpr int kId_BtnCancel         = 2202;

struct State {
    HWND hTimeout = nullptr;
    HWND hParallel = nullptr;
    HWND hFingerprint = nullptr;
    HWND hMode = nullptr;
    HWND hSkipDns = nullptr;
    HWND hSkipMac = nullptr;
    HWND hSkipPorts = nullptr;
    HWND hSkipFingerprint = nullptr;
    HWND hSkipClockDrift = nullptr;
    HWND hOk = nullptr;
    HWND hCancel = nullptr;

    // Computed Y positions of the two cards — set in DoLayout, used by paint.
    int timingCardTop = 0;
    int timingCardBot = 0;
    int skipCardTop   = 0;
    int skipCardBot   = 0;
};

State* GetState(HWND h) {
    return reinterpret_cast<State*>(GetWindowLongPtrW(h, GWLP_USERDATA));
}

void PaintFlatButton(const DRAWITEMSTRUCT& dis, bool primary) {
    const bool pressed = (dis.itemState & ODS_SELECTED) != 0;
    HDC hdc = dis.hDC;
    RECT rc = dis.rcItem;
    COLORREF fill, border, text;
    if (primary) {
        fill   = pressed ? theme::Get(theme::Color::AccentHover) : theme::Get(theme::Color::Accent);
        border = fill;
        text   = theme::Get(theme::Color::TextInverse);
    } else {
        fill   = pressed ? theme::Get(theme::Color::Hover) : theme::Get(theme::Color::Surface);
        border = theme::Get(theme::Color::Border);
        text   = theme::Get(theme::Color::TextPrimary);
    }
    HBRUSH brF = CreateSolidBrush(fill);
    FillRect(hdc, &rc, brF);
    DeleteObject(brF);
    HPEN pn = CreatePen(PS_SOLID, 1, border);
    HPEN op = static_cast<HPEN>(SelectObject(hdc, pn));
    HBRUSH ob = static_cast<HBRUSH>(SelectObject(hdc, GetStockObject(NULL_BRUSH)));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, ob); SelectObject(hdc, op);
    DeleteObject(pn);

    wchar_t buf[64]; buf[0] = 0;
    GetWindowTextW(dis.hwndItem, buf, 64);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text);
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    DrawTextW(hdc, buf, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

void PaintCardRect(HDC hdc, RECT rc) {
    HBRUSH br = theme::Brush(theme::Color::Surface);
    FillRect(hdc, &rc, br);
    HPEN pn = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HPEN op = static_cast<HPEN>(SelectObject(hdc, pn));
    HBRUSH ob = static_cast<HBRUSH>(SelectObject(hdc, GetStockObject(NULL_BRUSH)));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, ob); SelectObject(hdc, op);
    DeleteObject(pn);
}

void DrawTextLine(HDC hdc, const RECT& rc, const wchar_t* text, HFONT f,
                  COLORREF color, DWORD flags) {
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, f));
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT);
    RECT r = rc;
    DrawTextW(hdc, text, -1, &r, flags);
    SelectObject(hdc, oldF);
}

void PaintBody(HWND hwnd) {
    State* st = GetState(hwnd);
    PAINTSTRUCT ps;
    HDC hdcWin = BeginPaint(hwnd, &ps);
    RECT rcAll; GetClientRect(hwnd, &rcAll);
    int W = rcAll.right;
    int H = rcAll.bottom;

    HDC memDc = CreateCompatibleDC(hdcWin);
    HBITMAP bmp = CreateCompatibleBitmap(hdcWin, W, H);
    HBITMAP oldB = static_cast<HBITMAP>(SelectObject(memDc, bmp));

    FillRect(memDc, &rcAll, theme::Brush(theme::Color::Bg));

    const int padX = dpi::Scale(24);
    int y = dpi::Scale(18);

    // Title
    DrawTextLine(memDc, { padX, y, W - padX, y + dpi::Scale(28) },
             L"Settings",
             theme::Fonts().heading,
             theme::Get(theme::Color::TextPrimary),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    // Subtitle sits 3 px tighter to the title so descenders of words
    // like "only" / "g" / "j" don't drop into the TIMING card below.
    y += dpi::Scale(25);

    DrawTextLine(memDc, { padX, y, W - padX, y + dpi::Scale(20) },
             L"Session-only \x2014 these reset to defaults the next time NetLens starts.",
             theme::Fonts().regular,
             theme::Get(theme::Color::TextMuted),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

    // Cards (painted between input controls — DoLayout positioned them).
    if (st->timingCardBot > st->timingCardTop) {
        RECT card = { padX, st->timingCardTop, W - padX, st->timingCardBot };
        PaintCardRect(memDc, card);
        DrawTextLine(memDc, { card.left + dpi::Scale(16), card.top + dpi::Scale(10),
                          card.right, card.top + dpi::Scale(28) },
                 L"TIMING",
                 theme::Fonts().label,
                 theme::Get(theme::Color::TextMuted),
                 DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        // Field labels — left column
        const wchar_t* lbls[4] = {
            L"TCP timeout (ms)",
            L"Parallel sockets",
            L"Fingerprint timeout (ms)",
            L"Scan mode"
        };
        const int rowH = dpi::Scale(36);
        const int firstRowY = card.top + dpi::Scale(36);
        for (int i = 0; i < 4; ++i) {
            int ry = firstRowY + i * rowH;
            DrawTextLine(memDc, { card.left + dpi::Scale(16), ry + dpi::Scale(8),
                              card.left + dpi::Scale(200), ry + dpi::Scale(26) },
                     lbls[i],
                     theme::Fonts().regular,
                     theme::Get(theme::Color::TextPrimary),
                     DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        }
    }

    if (st->skipCardBot > st->skipCardTop) {
        RECT card = { padX, st->skipCardTop, W - padX, st->skipCardBot };
        PaintCardRect(memDc, card);
        DrawTextLine(memDc, { card.left + dpi::Scale(16), card.top + dpi::Scale(10),
                          card.right, card.top + dpi::Scale(28) },
                 L"SKIP PHASES",
                 theme::Fonts().label,
                 theme::Get(theme::Color::TextMuted),
                 DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    }

    BitBlt(hdcWin, 0, 0, W, H, memDc, 0, 0, SRCCOPY);
    SelectObject(memDc, oldB);
    DeleteObject(bmp);
    DeleteDC(memDc);
    EndPaint(hwnd, &ps);
}

void DoLayout(HWND hwnd) {
    State* st = GetState(hwnd);
    if (!st) return;
    RECT rc; GetClientRect(hwnd, &rc);
    const int W = rc.right;
    const int H = rc.bottom;
    const int padX = dpi::Scale(24);

    // Header reserved area
    int y = dpi::Scale(60);   // after title+subtitle

    // ---- Timing card ----
    const int rowH      = dpi::Scale(36);
    const int cardTopPad = dpi::Scale(36);    // for the "TIMING" label
    const int cardBotPad = dpi::Scale(14);
    int timingHeight = cardTopPad + 4 * rowH + cardBotPad;
    st->timingCardTop = y;
    st->timingCardBot = y + timingHeight;

    const int labelW = dpi::Scale(200);
    const int valX   = padX + dpi::Scale(16) + labelW;
    const int valW   = W - padX - dpi::Scale(16) - valX;

    auto rowY = [&](int i) {
        return y + cardTopPad + i * rowH + dpi::Scale(4);
    };
    SetWindowPos(st->hTimeout,     nullptr, valX, rowY(0), valW, dpi::Scale(26), SWP_NOZORDER);
    SetWindowPos(st->hParallel,    nullptr, valX, rowY(1), valW, dpi::Scale(26), SWP_NOZORDER);
    SetWindowPos(st->hFingerprint, nullptr, valX, rowY(2), valW, dpi::Scale(26), SWP_NOZORDER);
    SetWindowPos(st->hMode,        nullptr, valX, rowY(3), valW, dpi::Scale(200), SWP_NOZORDER);

    y += timingHeight + dpi::Scale(14);

    // ---- Skip phases card ----
    const int chkRowH = dpi::Scale(30);
    int skipHeight = cardTopPad + 5 * chkRowH + cardBotPad;
    st->skipCardTop = y;
    st->skipCardBot = y + skipHeight;

    const HWND chks[5] = {
        st->hSkipDns, st->hSkipMac, st->hSkipPorts,
        st->hSkipFingerprint, st->hSkipClockDrift
    };
    for (int i = 0; i < 5; ++i) {
        int cy = y + cardTopPad + i * chkRowH;
        SetWindowPos(chks[i], nullptr, padX + dpi::Scale(16), cy,
                     W - 2 * padX - dpi::Scale(32), chkRowH - dpi::Scale(4),
                     SWP_NOZORDER);
    }

    // ---- Buttons ----
    const int btnH = dpi::Scale(34);
    const int btnW = dpi::Scale(110);
    const int padR = dpi::Scale(24);
    const int padB = dpi::Scale(16);
    int by = H - padB - btnH;
    int xOk    = W - padR - btnW;
    int xCancel = xOk - dpi::Scale(8) - btnW;
    SetWindowPos(st->hCancel, nullptr, xCancel, by, btnW, btnH, SWP_NOZORDER);
    SetWindowPos(st->hOk,     nullptr, xOk,     by, btnW, btnH, SWP_NOZORDER);
}

int GetIntFromEdit(HWND e, int fallback) {
    wchar_t buf[32] = {};
    GetWindowTextW(e, buf, 32);
    int v = fallback;
    if (swscanf_s(buf, L"%d", &v) != 1) v = fallback;
    return v;
}

void SetIntInEdit(HWND e, int v) {
    wchar_t buf[32];
    swprintf_s(buf, L"%d", v);
    SetWindowTextW(e, buf);
}

void PopulateFromSettings(State& st) {
    const auto& s = App::Instance().Settings();
    SetIntInEdit(st.hTimeout,     s.timeoutMs);
    SetIntInEdit(st.hParallel,    s.parallel);
    SetIntInEdit(st.hFingerprint, s.fingerprintTimeoutMs);

    // Combo: 0=Discovery, 1=Standard (Fast), 2=Deep — mapped to ScanMode enum
    // The engine has: Fast=0, Deep=1, DiscoveryOnly=2. Reorder for UX so
    // the combo reads top→bottom Discovery → Standard → Deep.
    int sel = 1;  // Standard (Fast)
    if (s.mode == ScanMode::DiscoveryOnly) sel = 0;
    else if (s.mode == ScanMode::Deep)     sel = 2;
    SendMessageW(st.hMode, CB_SETCURSEL, sel, 0);

    SendMessageW(st.hSkipDns,         BM_SETCHECK, s.skipDns         ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(st.hSkipMac,         BM_SETCHECK, s.skipMac         ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(st.hSkipPorts,       BM_SETCHECK, s.skipPorts       ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(st.hSkipFingerprint, BM_SETCHECK, s.skipFingerprint ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(st.hSkipClockDrift,  BM_SETCHECK, s.skipClockDrift  ? BST_CHECKED : BST_UNCHECKED, 0);
}

// Engine has hard limits ([50, 10000] ms timeout, [1, 1024] parallel,
// [100, 5000] ms fingerprint timeout per engine/AppConstants.h). Without
// clamping the user could enter timeoutMs=999999 and the scan would
// stall 16 minutes per offline host.
namespace {
constexpr int kMinTimeoutMs            = 50;
constexpr int kMaxTimeoutMs            = 10'000;
constexpr int kMinParallel             = 1;
constexpr int kMaxParallel             = 1024;
constexpr int kMinFingerprintTimeoutMs = 100;
constexpr int kMaxFingerprintTimeoutMs = 5'000;
template <typename T> T clampRange(T v, T lo, T hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}
}

void CommitToSettings(State& st) {
    auto& s = App::Instance().Settings();
    s.timeoutMs            = clampRange(GetIntFromEdit(st.hTimeout,     s.timeoutMs),
                                        kMinTimeoutMs, kMaxTimeoutMs);
    s.parallel             = clampRange(GetIntFromEdit(st.hParallel,    s.parallel),
                                        kMinParallel, kMaxParallel);
    s.fingerprintTimeoutMs = clampRange(GetIntFromEdit(st.hFingerprint, s.fingerprintTimeoutMs),
                                        kMinFingerprintTimeoutMs, kMaxFingerprintTimeoutMs);

    int sel = static_cast<int>(SendMessageW(st.hMode, CB_GETCURSEL, 0, 0));
    if (sel == 0) s.mode = ScanMode::DiscoveryOnly;
    else if (sel == 2) s.mode = ScanMode::Deep;
    else s.mode = ScanMode::Fast;

    s.skipDns         = SendMessageW(st.hSkipDns,         BM_GETCHECK, 0, 0) == BST_CHECKED;
    s.skipMac         = SendMessageW(st.hSkipMac,         BM_GETCHECK, 0, 0) == BST_CHECKED;
    s.skipPorts       = SendMessageW(st.hSkipPorts,       BM_GETCHECK, 0, 0) == BST_CHECKED;
    s.skipFingerprint = SendMessageW(st.hSkipFingerprint, BM_GETCHECK, 0, 0) == BST_CHECKED;
    s.skipClockDrift  = SendMessageW(st.hSkipClockDrift,  BM_GETCHECK, 0, 0) == BST_CHECKED;
}

LRESULT CALLBACK Proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_NCCREATE: {
            State* st = new State();
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_CREATE: {
            State* st = GetState(hwnd);
            HINSTANCE hi = reinterpret_cast<LPCREATESTRUCTW>(lp)->hInstance;
            HFONT f = theme::Fonts().regular;
            auto setFont = [&](HWND h) {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), MAKELPARAM(TRUE, 0));
            };

            auto makeEdit = [&](int id) -> HWND {
                HWND h = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_NUMBER,
                    0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                    hi, nullptr);
                setFont(h);
                return h;
            };
            st->hTimeout     = makeEdit(kId_TimeoutEdit);
            st->hParallel    = makeEdit(kId_ParallelEdit);
            st->hFingerprint = makeEdit(kId_FingerprintEdit);

            st->hMode = CreateWindowExW(0, L"COMBOBOX", L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                0, 0, 0, 0, hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kId_ModeCombo)),
                hi, nullptr);
            setFont(st->hMode);
            SendMessageW(st->hMode, CB_ADDSTRING, 0, (LPARAM)L"Discovery (host probe only)");
            SendMessageW(st->hMode, CB_ADDSTRING, 0, (LPARAM)L"Standard (fast scan)");
            SendMessageW(st->hMode, CB_ADDSTRING, 0, (LPARAM)L"Deep (with fingerprinting)");

            auto makeChk = [&](int id, const wchar_t* label) -> HWND {
                HWND h = CreateWindowExW(0, L"BUTTON", label,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                    0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                    hi, nullptr);
                setFont(h);
                return h;
            };
            st->hSkipDns         = makeChk(kId_SkipDns,
                L"Skip reverse DNS lookups");
            st->hSkipMac         = makeChk(kId_SkipMac,
                L"Skip ARP / MAC vendor lookup");
            st->hSkipPorts       = makeChk(kId_SkipPorts,
                L"Skip port scan");
            st->hSkipFingerprint = makeChk(kId_SkipFingerprint,
                L"Skip service fingerprinting");
            st->hSkipClockDrift  = makeChk(kId_SkipClockDrift,
                L"Skip clock-drift / time-of-day probe");

            auto makeBtn = [&](int id, const wchar_t* label, bool def) -> HWND {
                DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW;
                if (def) style |= BS_DEFPUSHBUTTON;
                HWND h = CreateWindowExW(0, L"BUTTON", label, style,
                    0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                    hi, nullptr);
                setFont(h);
                return h;
            };
            st->hCancel = makeBtn(kId_BtnCancel, L"Cancel", false);
            st->hOk     = makeBtn(kId_BtnOk,     L"OK",     true);

            PopulateFromSettings(*st);
            return 0;
        }
        case WM_SIZE:
            DoLayout(hwnd);
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            PaintBody(hwnd);
            return 0;
        case WM_DRAWITEM: {
            auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
            if (dis->CtlType == ODT_BUTTON) {
                PaintFlatButton(*dis, dis->CtlID == kId_BtnOk);
                return TRUE;
            }
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (HIWORD(wp) == BN_CLICKED) {
                if (id == kId_BtnOk) {
                    CommitToSettings(*GetState(hwnd));
                    DestroyWindow(hwnd);
                } else if (id == kId_BtnCancel) {
                    DestroyWindow(hwnd);
                }
            }
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_NCDESTROY: {
            if (State* st = GetState(hwnd)) {
                delete st;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, theme::Get(theme::Color::TextPrimary));
            SetBkColor  (dc, theme::Get(theme::Color::Surface));
            return reinterpret_cast<LRESULT>(theme::Brush(theme::Color::Surface));
        }
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC dc = reinterpret_cast<HDC>(wp);
            HWND ctrl = reinterpret_cast<HWND>(lp);
            State* st = GetState(hwnd);
            // Checkboxes sit on a Surface card.
            bool onCard = st && (ctrl == st->hSkipDns || ctrl == st->hSkipMac
                              || ctrl == st->hSkipPorts || ctrl == st->hSkipFingerprint
                              || ctrl == st->hSkipClockDrift);
            COLORREF bg = onCard ? theme::Get(theme::Color::Surface)
                                 : theme::Get(theme::Color::Bg);
            SetTextColor(dc, theme::Get(theme::Color::TextPrimary));
            SetBkColor  (dc, bg);
            return reinterpret_cast<LRESULT>(
                onCard ? theme::Brush(theme::Color::Surface)
                       : theme::Brush(theme::Color::Bg));
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void EnsureRegistered(HINSTANCE hi) {
    static bool registered = false;
    if (registered) return;
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = Proc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon         = LoadIconW(hi, MAKEINTRESOURCEW(IDI_NETLENS));
    wc.lpszClassName = kClassName;
    RegisterClassExW(&wc);
    registered = true;
}

void CenterOn(HWND child, HWND parent) {
    RECT rp, rc;
    if (parent) GetWindowRect(parent, &rp); else SystemParametersInfoW(SPI_GETWORKAREA, 0, &rp, 0);
    GetWindowRect(child, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    int x = rp.left + ((rp.right - rp.left) - w) / 2;
    int y = rp.top  + ((rp.bottom - rp.top) - h) / 2;
    SetWindowPos(child, nullptr, x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
}

}  // namespace

void SettingsDialog::Show(HWND parent) {
    HINSTANCE hi = App::Instance().Inst();
    EnsureRegistered(hi);

    const int w = dpi::Scale(540);
    const int h = dpi::Scale(580);

    HWND dlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
        kClassName, L"Settings",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, w, h,
        parent, nullptr, hi, nullptr);
    if (!dlg) return;
    CenterOn(dlg, parent);

    EnableWindow(parent, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    if (capture::IsAutoCapturing()) {
        capture::AppendWindow(dlg, L"settings");
        DestroyWindow(dlg);
        EnableWindow(parent, TRUE);
        SetForegroundWindow(parent);
        return;
    }

    MSG msg;
    while (IsWindow(dlg) && GetMessageW(&msg, nullptr, 0, 0)) {
        // ESC closes the dialog.
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            DestroyWindow(dlg);
            continue;
        }
        // Global Ctrl+T forwards to main so the capture includes both
        // this dialog and the underlying main window.
        if (msg.message == WM_KEYDOWN && msg.wParam == 'T'
            && (GetKeyState(VK_CONTROL) & 0x8000)) {
            PostMessageW(parent, WM_COMMAND, IDM_TOOLS_CAPTURE, 0);
            continue;
        }
        if (!IsDialogMessageW(dlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // AttachThreadInput-backed focus restore (see AboutDialog.cpp for
    // the explanation of why plain SetForegroundWindow isn't enough).
    EnableWindow(parent, TRUE);
    DWORD fgThreadId  = GetWindowThreadProcessId(GetForegroundWindow(), nullptr);
    DWORD ourThreadId = GetCurrentThreadId();
    bool  attached    = false;
    if (fgThreadId && fgThreadId != ourThreadId) {
        attached = AttachThreadInput(ourThreadId, fgThreadId, TRUE) != 0;
    }
    BringWindowToTop(parent);
    SetForegroundWindow(parent);
    SetActiveWindow(parent);
    SetFocus(parent);
    if (attached) {
        AttachThreadInput(ourThreadId, fgThreadId, FALSE);
    }
}

}  // namespace nl
