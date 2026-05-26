#include "AboutDialog.h"

#include <shellapi.h>
#include <string>

#include "../App.h"
#include "../Capture.h"
#include "../Dpi.h"
#include "../Theme.h"
#include "../../Resource.h"

namespace nl {

namespace {

constexpr const wchar_t* kClassName  = L"NetLensAboutDlg";
constexpr int kBtnIdVisit  = 1001;
constexpr int kBtnIdClose  = 1002;

struct State {
    HWND hBtnVisit = nullptr;
    HWND hBtnClose = nullptr;
    RECT urlRect{};   // M5 — hit rect for the painted "https://3389.ro" link
};

State* GetState(HWND h) {
    return reinterpret_cast<State*>(GetWindowLongPtrW(h, GWLP_USERDATA));
}

// ---------------------------------------------------------------------------
// Flat button painter (mirrors the one in MainWindow.cpp).
// ---------------------------------------------------------------------------
void PaintFlatButton(const DRAWITEMSTRUCT& dis, bool primary) {
    const bool pressed = (dis.itemState & ODS_SELECTED) != 0;
    HDC hdc = dis.hDC;
    RECT rc = dis.rcItem;

    COLORREF fill, border, text;
    if (primary) {
        fill   = pressed ? theme::Get(theme::Color::AccentHover)
                         : theme::Get(theme::Color::Accent);
        border = fill;
        text   = theme::Get(theme::Color::TextInverse);
    } else {
        fill   = pressed ? theme::Get(theme::Color::Hover)
                         : theme::Get(theme::Color::Surface);
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

    wchar_t buf[96]; buf[0] = 0;
    GetWindowTextW(dis.hwndItem, buf, 96);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text);
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    DrawTextW(hdc, buf, -1, &rc,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

// ---------------------------------------------------------------------------
// Body painter.
// ---------------------------------------------------------------------------
void PaintCardRect(HDC hdc, RECT rc, COLORREF fill, bool border) {
    HBRUSH brF = CreateSolidBrush(fill);
    FillRect(hdc, &rc, brF);
    DeleteObject(brF);
    if (border) {
        HPEN pn = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
        HPEN op = static_cast<HPEN>(SelectObject(hdc, pn));
        HBRUSH ob = static_cast<HBRUSH>(SelectObject(hdc, GetStockObject(NULL_BRUSH)));
        Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
        SelectObject(hdc, ob); SelectObject(hdc, op);
        DeleteObject(pn);
    }
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

int MeasureTextHeight(HDC hdc, int width, const wchar_t* text, HFONT f) {
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, f));
    RECT calc{ 0, 0, width, 1000 };
    DrawTextW(hdc, text, -1, &calc,
              DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
    SelectObject(hdc, oldF);
    return calc.bottom - calc.top;
}

void PaintBody(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdcWin = BeginPaint(hwnd, &ps);
    RECT rcAll; GetClientRect(hwnd, &rcAll);
    const int W = rcAll.right;
    const int H = rcAll.bottom;

    // Double buffer
    HDC     memDc = CreateCompatibleDC(hdcWin);
    HBITMAP bmp   = CreateCompatibleBitmap(hdcWin, W, H);
    HBITMAP oldB  = static_cast<HBITMAP>(SelectObject(memDc, bmp));

    // Background
    FillRect(memDc, &rcAll, theme::Brush(theme::Color::Bg));

    const int padX = dpi::Scale(28);
    int y = dpi::Scale(22);

    // ---- Hero: 56x56 app icon + title + version + tagline ----
    // Renders the real IDI_NETLENS icon (the same one shown in the
    // window title bar and on the taskbar) so the brand mark is
    // consistent across exe, brand bar and About.
    {
        const int heroLogoSize = dpi::Scale(56);
        const int heroLogoX = padX;
        const int heroLogoY = y;

        HICON hIco = static_cast<HICON>(LoadImageW(
            App::Instance().Inst(), MAKEINTRESOURCEW(IDI_NETLENS),
            IMAGE_ICON, heroLogoSize, heroLogoSize, LR_DEFAULTCOLOR));
        if (hIco) {
            DrawIconEx(memDc, heroLogoX, heroLogoY, hIco,
                       heroLogoSize, heroLogoSize, 0, nullptr, DI_NORMAL);
            DestroyIcon(hIco);
        }

        // Title to the right of the logo. The 20pt-bold "NetLens" word-
        // mark is ~28 px tall at 96 dpi; reserve 34 px below it before
        // dropping the version line so descenders + the next ascender
        // don't kiss.
        const int textX = heroLogoX + heroLogoSize + dpi::Scale(16);
        int ty = heroLogoY + dpi::Scale(2);
        DrawTextLine(memDc, { textX, ty, W - padX, ty + dpi::Scale(30) },
                     L"NetLens",
                     theme::Fonts().ipBig,
                     theme::Get(theme::Color::TextPrimary),
                     DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        ty += dpi::Scale(34);

        // Version line.
        #define NLWIDEN2_(x) L##x
        #define NLWIDEN_(x)  NLWIDEN2_(x)
        std::wstring ver = std::wstring(L"v") + NLWIDEN_(NETLENS_VERSION_STR);
        #undef NLWIDEN_
        #undef NLWIDEN2_
        if (App::Instance().EngineOk()) {
            ver += L"  \x2022  engine ";
            ver += App::Instance().EngineVersion();
        }
        DrawTextLine(memDc, { textX, ty, W - padX, ty + dpi::Scale(18) },
                     ver.c_str(),
                     theme::Fonts().regular,
                     theme::Get(theme::Color::TextMuted),
                     DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        ty += dpi::Scale(20);

        // Tagline.
        DrawTextLine(memDc, { textX, ty, W - padX, ty + dpi::Scale(18) },
                     L"Portable LAN scanner  \x2022  local only  \x2022  no telemetry",
                     theme::Fonts().regular,
                     theme::Get(theme::Color::TextSecondary),
                     DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

        y = heroLogoY + heroLogoSize + dpi::Scale(18);
    }

    // Description
    // Description explicitly names the UDP-discovery pass so a reader
    // sees that NBNS / mDNS / SSDP / SQL Browser / IPMI etc. are probed
    // alongside the TCP sweep.
    const wchar_t* descTxt =
        L"NetLens enumerates the hosts on a Windows LAN: ICMP / ARP discovery, "
        L"MAC vendor lookup, a configurable TCP port sweep, lightweight service "
        L"fingerprints, and a small UDP discovery pass (NBNS, mDNS, SSDP, "
        L"SQL Browser, NTP, DNS, LLMNR, IPMI). Results are presented in a "
        L"sortable grid + per-host details pane, and can be exported to CSV "
        L"or a self-contained HTML report.";
    int descH = MeasureTextHeight(memDc, W - 2 * padX, descTxt, theme::Fonts().regular);
    DrawTextLine(memDc, { padX, y, W - padX, y + descH },
             descTxt,
             theme::Fonts().regular,
             theme::Get(theme::Color::TextPrimary),
             DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
    y += descH + dpi::Scale(18);

    // ---- "WHAT IT WON'T DO" card ----
    const int cardX = padX;
    const int cardW = W - 2 * padX;
    const int cardPad = dpi::Scale(14);
    const int innerW  = cardW - 2 * cardPad - dpi::Scale(24);
    // Bullet bodies are short enough to fit a single line at the 640 px
    // dialog width — compact bullets read faster than 3-line paragraphs.
    struct Bullet { const wchar_t* head; const wchar_t* body; };
    Bullet bullets[] = {
        { L"No telemetry.",
          L"Scans stay local \xb7 nothing is uploaded." },
        { L"No credentials.",
          L"Unauthenticated banners only \xb7 no SMB / RDP / SSH logins." },
        { L"No elevation.",
          L"Runs as the current user \xb7 ARP / ICMP work without admin." },
        { L"No installer.",
          L"Single .exe \xb7 no registry, no AppData footprint." },
        { L"TCP-only with minimal UDP discovery.",
          L"NBNS / NTP / SSDP / mDNS / SQL Browser / DNS / LLMNR / IPMI." },
    };

    // Compute card height
    int cardInner = dpi::Scale(8);   // top pad
    {
        HDC dc = memDc;
        HFONT oldF = static_cast<HFONT>(SelectObject(dc, theme::Fonts().semibold));
        cardInner += dpi::Scale(22);  // "WHAT IT WON'T DO" label
        SelectObject(dc, oldF);
    }
    // Bullets array sized at compile time so adding entries doesn't
    // require chasing hard-coded counts through this file.
    constexpr int kBulletCount = static_cast<int>(std::size(bullets));
    int bulletH[kBulletCount];
    for (int i = 0; i < kBulletCount; ++i) {
        int bh = MeasureTextHeight(memDc, innerW, bullets[i].body, theme::Fonts().regular);
        bulletH[i] = bh + dpi::Scale(20);   // + heading line + spacing
        cardInner += bulletH[i] + dpi::Scale(6);
    }
    cardInner += dpi::Scale(8);

    RECT cardRc = { cardX, y, cardX + cardW, y + cardInner };
    PaintCardRect(memDc, cardRc, theme::Get(theme::Color::Surface), true);

    int innerY = cardRc.top + dpi::Scale(14);
    DrawTextLine(memDc, { cardRc.left + cardPad, innerY, cardRc.right - cardPad, innerY + dpi::Scale(18) },
             L"WHAT IT WON'T DO",
             theme::Fonts().label,
             theme::Get(theme::Color::TextMuted),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    innerY += dpi::Scale(22);

    for (int i = 0; i < kBulletCount; ++i) {
        // Green check mark
        // Bullet dot — uses the 3389 logo green and is vertically
        // centered on the head/body text line (was sitting 4 px low,
        // misaligning with the first line of text).
        const int chkSize = dpi::Scale(7);
        const int lineHBullet = dpi::Scale(18);
        const int chkX = cardRc.left + cardPad + dpi::Scale(2);
        const int chkY = innerY + (lineHBullet - chkSize * 2) / 2;
        const COLORREF k3389Green = RGB(0x8D, 0xC6, 0x3F);   // 3389 logo lime
        HBRUSH brOk = CreateSolidBrush(k3389Green);
        HBRUSH obr  = static_cast<HBRUSH>(SelectObject(memDc, brOk));
        HPEN   opn  = static_cast<HPEN>(SelectObject(memDc, GetStockObject(NULL_PEN)));
        Ellipse(memDc, chkX, chkY, chkX + chkSize * 2, chkY + chkSize * 2);
        SelectObject(memDc, obr); SelectObject(memDc, opn);
        DeleteObject(brOk);

        int textX = cardRc.left + cardPad + dpi::Scale(24);
        int textW = cardRc.right - cardPad - textX;

        // Inline head + body in one wrapped paragraph
        // ("No telemetry. <body> Scans stay on this machine. </body>").
        // The head is bold; the body wraps below into the gutter.
        const int lineH = dpi::Scale(18);

        // Measure bold head width.
        HFONT boldF = theme::Fonts().semibold;
        HFONT regF  = theme::Fonts().regular;
        SetBkMode(memDc, TRANSPARENT);

        HFONT ofb = static_cast<HFONT>(SelectObject(memDc, boldF));
        SIZE szHead{};
        GetTextExtentPoint32W(memDc, bullets[i].head,
                              lstrlenW(bullets[i].head), &szHead);
        SetTextColor(memDc, theme::Get(theme::Color::TextPrimary));
        RECT rcHead = { textX, innerY, textX + szHead.cx + dpi::Scale(2),
                        innerY + lineH };
        DrawTextW(memDc, bullets[i].head, -1, &rcHead,
                  DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(memDc, ofb);

        // Figure out how much of the body fits on the first line after head.
        SelectObject(memDc, regF);
        const int gapAfterHead = dpi::Scale(4);
        const int firstLineMaxW = textW - szHead.cx - gapAfterHead;
        const int bodyLen = lstrlenW(bullets[i].body);
        int fitChars = 0;
        SIZE szDummy{};
        if (firstLineMaxW > 0) {
            GetTextExtentExPointW(memDc, bullets[i].body, bodyLen,
                                  firstLineMaxW, &fitChars, nullptr, &szDummy);
        }
        int firstSegLen = fitChars;
        if (firstSegLen < bodyLen) {
            int back = firstSegLen;
            while (back > 0 && bullets[i].body[back] != L' ') --back;
            if (back > 0) firstSegLen = back;
        }

        // Paint first body segment inline.
        SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));
        RECT rcInline = { textX + szHead.cx + gapAfterHead, innerY,
                          textX + textW, innerY + lineH };
        if (firstSegLen > 0) {
            DrawTextW(memDc, bullets[i].body, firstSegLen, &rcInline,
                      DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        }

        int totalBulletH = lineH;
        // Rest of body on subsequent lines (left-aligned with head).
        if (firstSegLen < bodyLen) {
            const wchar_t* rest = bullets[i].body + firstSegLen;
            while (*rest == L' ') ++rest;
            RECT rcCalc = { textX, innerY + lineH, textX + textW,
                            innerY + lineH + dpi::Scale(200) };
            DrawTextW(memDc, rest, -1, &rcCalc,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
            RECT rcRest = { textX, innerY + lineH, textX + textW, rcCalc.bottom };
            DrawTextW(memDc, rest, -1, &rcRest,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
            totalBulletH = rcCalc.bottom - innerY;
        }

        bulletH[i] = totalBulletH;
        innerY += bulletH[i] + dpi::Scale(8);
    }

    y = cardRc.bottom + dpi::Scale(16);

    // ---- Tech line ----
    DrawTextLine(memDc, { padX, y, W - padX, y + dpi::Scale(18) },
             L"Native C++ Win32  \x2022  C++ scan engine",
             theme::Fonts().regular,
             theme::Get(theme::Color::TextSecondary),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    y += dpi::Scale(18);

    // Freeware disclaimer.
    DrawTextLine(memDc, { padX, y, W - padX, y + dpi::Scale(18) },
             L"Released as freeware under the MIT License.  "
             L"Not affiliated with any third-party trademarks shown.",
             theme::Fonts().regular,
             theme::Get(theme::Color::TextSecondary),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    y += dpi::Scale(22);

    // ---- "Built by" card ----
    const wchar_t* builtTitle = L"3389 Software Outsourcing";
    const wchar_t* builtSub   = L"Bucharest, Romania  \x2022  Windows freeware for IT operations.";
    const wchar_t* builtLink  = L"https://3389.ro";

    int builtH = dpi::Scale(14)              // top pad
               + dpi::Scale(16)              // BUILT BY label
               + dpi::Scale(24)              // title
               + dpi::Scale(20)              // sub
               + dpi::Scale(22)              // link
               + dpi::Scale(12);             // bottom pad
    RECT builtRc = { padX, y, W - padX, y + builtH };
    // SurfaceAlt for a slightly grayed footer card.
    PaintCardRect(memDc, builtRc, theme::Get(theme::Color::SurfaceAlt), true);

    // ---- 3389 logo (real PNG → BMP embedded via RT_BITMAP). ----
    const int logoTargetH = dpi::Scale(46);
    const int logoX = builtRc.left + cardPad;
    const int logoY = builtRc.top + (builtH - logoTargetH) / 2;
    int logoActualW = dpi::Scale(96);
    {
        HBITMAP hLogo = LoadBitmapW(App::Instance().Inst(),
                                    MAKEINTRESOURCEW(IDB_3389_LOGO));
        if (hLogo) {
            BITMAP bm{};
            GetObject(hLogo, sizeof(bm), &bm);
            if (bm.bmWidth > 0 && bm.bmHeight > 0) {
                logoActualW = MulDiv(logoTargetH, bm.bmWidth, bm.bmHeight);
            }
            HDC bmpDc = CreateCompatibleDC(memDc);
            HBITMAP oldBmp = static_cast<HBITMAP>(SelectObject(bmpDc, hLogo));
            SetStretchBltMode(memDc, HALFTONE);
            SetBrushOrgEx(memDc, 0, 0, nullptr);
            StretchBlt(memDc,
                       logoX, logoY, logoActualW, logoTargetH,
                       bmpDc, 0, 0, bm.bmWidth, bm.bmHeight,
                       SRCCOPY);
            SelectObject(bmpDc, oldBmp);
            DeleteDC(bmpDc);
            DeleteObject(hLogo);
        }
    }

    const int textL = logoX + logoActualW + dpi::Scale(14);
    int by = builtRc.top + dpi::Scale(14);
    DrawTextLine(memDc, { textL, by, builtRc.right - cardPad, by + dpi::Scale(16) },
             L"BUILT BY", theme::Fonts().label,
             theme::Get(theme::Color::TextMuted),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    by += dpi::Scale(16);
    DrawTextLine(memDc, { textL, by, builtRc.right - cardPad, by + dpi::Scale(24) },
             builtTitle, theme::Fonts().heading,
             theme::Get(theme::Color::Accent),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    by += dpi::Scale(24);
    DrawTextLine(memDc, { textL, by, builtRc.right - cardPad, by + dpi::Scale(20) },
             builtSub, theme::Fonts().regular,
             theme::Get(theme::Color::TextSecondary),
             DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    by += dpi::Scale(20);

    // M5 — measure the URL so we can hit-test it later.
    {
        HFONT linkF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
        SIZE szLink{};
        GetTextExtentPoint32W(memDc, builtLink, lstrlenW(builtLink), &szLink);
        SelectObject(memDc, linkF);

        int linkX = textL;
        int linkY = by;
        int linkH = dpi::Scale(20);
        if (State* sp = GetState(hwnd)) {
            sp->urlRect = { linkX, linkY, linkX + szLink.cx, linkY + linkH };
        }

        // Paint underlined link
        HFONT srcF = theme::Fonts().regular;
        LOGFONTW lf{};
        GetObjectW(srcF, sizeof(lf), &lf);
        lf.lfUnderline = TRUE;
        HFONT linkUnder = CreateFontIndirectW(&lf);
        HFONT old = static_cast<HFONT>(SelectObject(memDc, linkUnder));
        SetTextColor(memDc, theme::Get(theme::Color::Accent));
        SetBkMode(memDc, TRANSPARENT);
        RECT rLink = { linkX, linkY, linkX + szLink.cx, linkY + linkH };
        DrawTextW(memDc, builtLink, -1, &rLink,
                  DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(memDc, old);
        DeleteObject(linkUnder);
    }

    // Blit
    BitBlt(hdcWin, 0, 0, W, H, memDc, 0, 0, SRCCOPY);
    SelectObject(memDc, oldB);
    DeleteObject(bmp);
    DeleteDC(memDc);
    EndPaint(hwnd, &ps);
}

void LayoutButtons(HWND hwnd) {
    State* st = GetState(hwnd);
    if (!st) return;
    RECT rc; GetClientRect(hwnd, &rc);
    const int btnH = dpi::Scale(32);
    const int btnW1 = dpi::Scale(140);
    const int btnW2 = dpi::Scale(110);
    const int padR = dpi::Scale(20);
    const int padB = dpi::Scale(16);
    int y = rc.bottom - padB - btnH;
    int x2 = rc.right - padR - btnW2;
    int x1 = x2 - dpi::Scale(8) - btnW1;
    SetWindowPos(st->hBtnVisit, nullptr, x1, y, btnW1, btnH, SWP_NOZORDER);
    SetWindowPos(st->hBtnClose, nullptr, x2, y, btnW2, btnH, SWP_NOZORDER);
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
            st->hBtnVisit = CreateWindowExW(0, L"BUTTON", L"Visit 3389.ro",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                0, 0, 0, 0, hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kBtnIdVisit)),
                hi, nullptr);
            st->hBtnClose = CreateWindowExW(0, L"BUTTON", L"Close",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW | BS_DEFPUSHBUTTON,
                0, 0, 0, 0, hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kBtnIdClose)),
                hi, nullptr);
            SendMessageW(st->hBtnVisit, WM_SETFONT,
                         reinterpret_cast<WPARAM>(theme::Fonts().regular),
                         MAKELPARAM(TRUE, 0));
            SendMessageW(st->hBtnClose, WM_SETFONT,
                         reinterpret_cast<WPARAM>(theme::Fonts().regular),
                         MAKELPARAM(TRUE, 0));
            return 0;
        }
        case WM_SIZE:
            LayoutButtons(hwnd);
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            PaintBody(hwnd);
            return 0;
        case WM_DRAWITEM: {
            auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
            if (dis->CtlType == ODT_BUTTON) {
                PaintFlatButton(*dis, dis->CtlID == kBtnIdClose);
                return TRUE;
            }
            break;
        }
        case WM_COMMAND: {
            if (HIWORD(wp) == BN_CLICKED) {
                if (LOWORD(wp) == kBtnIdClose) {
                    DestroyWindow(hwnd);
                } else if (LOWORD(wp) == kBtnIdVisit) {
                    ShellExecuteW(hwnd, L"open", L"https://3389.ro/",
                                  nullptr, nullptr, SW_SHOWNORMAL);
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
        case WM_CTLCOLORBTN:
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetBkColor(dc, theme::Get(theme::Color::Bg));
            return reinterpret_cast<LRESULT>(theme::Brush(theme::Color::Bg));
        }
        case WM_LBUTTONDOWN: {
            // M5 — clickable URL.
            State* st = GetState(hwnd);
            if (st) {
                POINT pt = { LOWORD(lp), HIWORD(lp) };
                if (PtInRect(&st->urlRect, pt)) {
                    ShellExecuteW(hwnd, L"open", L"https://3389.ro/",
                                  nullptr, nullptr, SW_SHOWNORMAL);
                    return 0;
                }
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_SETCURSOR: {
            if (LOWORD(lp) == HTCLIENT) {
                State* st = GetState(hwnd);
                if (st) {
                    POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
                    if (PtInRect(&st->urlRect, pt)) {
                        SetCursor(LoadCursorW(nullptr, IDC_HAND));
                        return TRUE;
                    }
                }
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
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

void AboutDialog::Show(HWND parent) {
    HINSTANCE hi = App::Instance().Inst();
    EnsureRegistered(hi);

    // Width 640 px is what the WHAT IT WON'T DO bullets need to fit
    // head + one-line body on a single row each.
    const int w = dpi::Scale(640);
    const int h = dpi::Scale(700);

    HWND dlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
        kClassName, L"About NetLens",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, w, h,
        parent, nullptr, hi, nullptr);
    if (!dlg) return;

    CenterOn(dlg, parent);

    EnableWindow(parent, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    // Ctrl+T full-UI sweep: snap ourselves and bail before entering
    // the user-facing modal pump.
    if (capture::IsAutoCapturing()) {
        capture::AppendWindow(dlg, L"about");
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

    // Bulletproof focus restore via AttachThreadInput. Plain
    // BringWindowToTop+SetForegroundWindow works at idle but gets
    // refused while a scan is running (the scanner thread's PostMessage
    // calls interfere with the same-thread input queue and trip
    // Windows' anti-hijack heuristics). Attaching our UI thread's
    // input queue to the foreground thread's queue lifts that
    // restriction.
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
