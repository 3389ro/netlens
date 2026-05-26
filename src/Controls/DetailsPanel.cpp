#include "DetailsPanel.h"

#include <shellapi.h>
#include <string>
#include <vector>

#include "../App.h"
#include "../Dpi.h"
#include "../Models.h"
#include "../Theme.h"

namespace nl {

namespace {

#define WM_DP_SET_HOST  (WM_USER + 1)

// Telnet + VNC dropped from the visible action bar; both still
// available via right-click context menu on the host grid. IDs kept
// (with gaps) so existing WM_COMMAND handlers below still recognise
// them when the menu invokes them.
constexpr int kBtnCount    = 5;
constexpr int kBtnIdBase   = 5000;
enum : int {
    ID_BTN_PING = kBtnIdBase,
    ID_BTN_BROWSER,
    ID_BTN_RDP,
    ID_BTN_SSH,
    ID_BTN_TELNET,
    ID_BTN_VNC,
    ID_BTN_COPY,
};

const wchar_t* const kBtnLabels[kBtnCount] = {
    L"Ping", L"Browser", L"RDP", L"SSH", L"Copy report"
};

// M5 — per-field copy affordances.
enum class CopyKind : uint8_t {
    None, IP, Hostname, MAC, Vendor, OpenPorts,
    // additional copyable blocks (printer supplies + UDP discovery).
    PrinterSupplies, UdpDiscovery
};
struct CopyHit {
    CopyKind kind = CopyKind::None;
    RECT     rc{};   // in client coords (paint-time, already scroll-adjusted)
};

struct State {
    int   hostIndex = -1;
    HWND  buttons[kBtnCount] = {};
    int   scrollY        = 0;
    int   bodyTopY       = 0;     // y where the scrollable body starts (set by PaintPanel)
    int   bodyContentH   = 0;     // total body content height (set by PaintPanel)
    int   bodyVisibleH   = 0;     // visible body height (set by PaintPanel)
    int   actionRowY     = 0;     // actual y where action buttons go (set by PaintPanel)
    int   actionRowsUsed = 1;     // # of rows LayoutButtons actually consumed
    std::vector<CopyHit> copyHits;   // refreshed every paint
};

State* Get(HWND h) {
    return reinterpret_cast<State*>(GetWindowLongPtrW(h, GWLP_USERDATA));
}

// --- flat button painter (duplicated from MainWindow.cpp; small enough) ---
void PaintFlatButton(const DRAWITEMSTRUCT& dis) {
    const bool pressed = (dis.itemState & ODS_SELECTED) != 0;
    const bool focused = (dis.itemState & ODS_FOCUS) != 0;

    HDC hdc = dis.hDC;
    RECT rc = dis.rcItem;

    COLORREF fill   = theme::Get(theme::Color::Surface);
    COLORREF border = theme::Get(theme::Color::Border);
    COLORREF text   = theme::Get(theme::Color::TextPrimary);
    if (pressed) {
        fill   = theme::Get(theme::Color::Hover);
        border = theme::Get(theme::Color::Accent);
    }

    HBRUSH brFill = CreateSolidBrush(fill);
    FillRect(hdc, &rc, brFill);
    DeleteObject(brFill);

    HPEN penB = CreatePen(PS_SOLID, 1, border);
    HPEN oldP = static_cast<HPEN>(SelectObject(hdc, penB));
    HBRUSH oldB = static_cast<HBRUSH>(SelectObject(hdc, GetStockObject(NULL_BRUSH)));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, oldB);
    SelectObject(hdc, oldP);
    DeleteObject(penB);

    // Label
    wchar_t buf[64]; buf[0] = 0;
    GetWindowTextW(dis.hwndItem, buf, 64);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text);
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    DrawTextW(hdc, buf, -1, &rc,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);

    if (focused) DrawFocusRect(hdc, &rc);
}

void DrawSectionHeader(HDC hdc, const RECT& rc, const wchar_t* text) {
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, theme::Get(theme::Color::TextMuted));
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().label));
    RECT rt = rc;
    DrawTextW(hdc, text, -1, &rt,
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

// M5 — set the Unicode clipboard from a wstring.
void SetClipboardText(HWND owner, const std::wstring& text) {
    if (!OpenClipboard(owner)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hMem) {
        if (void* p = GlobalLock(hMem)) {
            memcpy(p, text.c_str(), bytes);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        } else {
            GlobalFree(hMem);
        }
    }
    CloseClipboard();
}

// Label-aware palette duplicated from HostTable.cpp so DetailsPanel
// doesn't take a dependency on it. Kept in sync by hand.
void BadgeColors(const ServiceBadge& b, COLORREF& bg, COLORREF& fg) {
    using C = theme::Color;
    const std::wstring& label = b.label;
    auto eq = [&](const wchar_t* s) { return label == s; };

    if (eq(L"HTTPS") || eq(L"LDAPS") || eq(L"IMAPS") || eq(L"POP3S")
        || eq(L"SMTPS") || eq(L"FTPS") || eq(L"WinRM-TLS") || eq(L"K8s API")) {
        bg = RGB(0xE6, 0xE0, 0xFA);
        fg = RGB(0x59, 0x3E, 0xC6);
        return;
    }
    if (eq(L"SMB") || eq(L"NetBIOS") || eq(L"AFP") || eq(L"NFS") || eq(L"FTP")) {
        bg = RGB(0xD4, 0xEE, 0xF4);
        fg = RGB(0x0D, 0x73, 0x95);
        return;
    }
    if (eq(L"WinRM") || eq(L"SNMP") || eq(L"IPMI") || eq(L"WSDAPI")) {
        bg = RGB(0xFD, 0xE5, 0xCC);
        fg = RGB(0xC2, 0x63, 0x18);
        return;
    }
    if (eq(L"MySQL") || eq(L"MSSQL") || eq(L"PostgreSQL") || eq(L"Oracle")
        || eq(L"MongoDB") || eq(L"Redis") || eq(L"Memcached") || eq(L"Cassandra")) {
        bg = theme::Get(C::DangerSurface);
        fg = theme::Get(C::Danger);
        return;
    }

    switch (b.category) {
        case ServiceCategory::Web:    bg = theme::Get(C::InfoSurface);    fg = theme::Get(C::Info);    break;
        case ServiceCategory::Remote: bg = theme::Get(C::WarningSurface); fg = theme::Get(C::Warning); break;
        case ServiceCategory::Shell:  bg = theme::Get(C::SuccessSurface); fg = theme::Get(C::Success); break;
        case ServiceCategory::Share:  bg = RGB(0xD4, 0xEE, 0xF4); fg = RGB(0x0D, 0x73, 0x95); break;
        case ServiceCategory::Mgmt:   bg = RGB(0xFD, 0xE5, 0xCC); fg = RGB(0xC2, 0x63, 0x18); break;
        case ServiceCategory::Db:     bg = theme::Get(C::DangerSurface);  fg = theme::Get(C::Danger);  break;
        case ServiceCategory::Other:
        default:                      bg = theme::Get(C::NeutralSurface); fg = theme::Get(C::TextSecondary); break;
    }
}

// M5 — small "copy" glyph affordance (Unicode ⧉). Paints in a 20x20 cell.
void PaintCopyGlyph(HDC hdc, int x, int y, bool hot) {
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    SetTextColor(hdc, hot ? theme::Get(theme::Color::Accent)
                          : theme::Get(theme::Color::TextMuted));
    SetBkMode(hdc, TRANSPARENT);
    RECT rc = { x, y, x + dpi::Scale(20), y + dpi::Scale(20) };
    DrawTextW(hdc, L"\x29C9", -1, &rc,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

// Adds a hit-rect to the state's copyHits and paints the glyph at
// (rightX-20, rowTopY + (rowH-20)/2). `clientYDelta` is subtracted from the
// paint Y to produce the client-space hit-rect (used to translate body
// content-space y → on-screen y when the body is scrolled). visTop/visBot
// clip the hit rect to the visible region of the panel so body hits don't
// bleed into the sticky header.
void AddCopyAffordance(State* st, HDC hdc, CopyKind kind,
                       int rightX, int rowTopY, int rowH, int clientYDelta,
                       int visTop = 0, int visBot = 0x7FFFFFFF) {
    const int glyphW = dpi::Scale(20);
    const int glyphH = dpi::Scale(20);
    int gx = rightX - glyphW;
    int gy = rowTopY + (rowH - glyphH) / 2;
    PaintCopyGlyph(hdc, gx, gy, /*hot=*/false);

    int clientY = gy - clientYDelta;
    if (clientY + glyphH <= visTop) return;
    if (clientY >= visBot) return;

    int top = (clientY < visTop) ? visTop : clientY;
    int bot = (clientY + glyphH > visBot) ? visBot : (clientY + glyphH);

    CopyHit hit;
    hit.kind = kind;
    hit.rc = { gx, top, gx + glyphW, bot };
    st->copyHits.push_back(hit);
}

// Returns the y advance after drawing a key-value pair.
int DrawKeyValue(HDC hdc, int x, int y, int wKey, int wVal,
                 const wchar_t* key, const wchar_t* value) {
    SetBkMode(hdc, TRANSPARENT);
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().smallFont));

    SetTextColor(hdc, theme::Get(theme::Color::TextMuted));
    RECT rcK = { x, y, x + wKey, y + dpi::Scale(20) };
    DrawTextW(hdc, key, -1, &rcK,
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, theme::Fonts().regular);
    SetTextColor(hdc, theme::Get(theme::Color::TextPrimary));
    RECT rcV = { x + wKey + dpi::Scale(10), y,
                 x + wKey + dpi::Scale(10) + wVal, y + dpi::Scale(20) };

    // For multi-line values (brand hint can contain '\n'), use DT_WORDBREAK.
    DWORD flags = DT_LEFT | DT_TOP | DT_NOPREFIX | DT_END_ELLIPSIS;
    bool multiline = false;
    for (const wchar_t* p = value; *p; ++p) if (*p == L'\n') { multiline = true; break; }
    if (multiline) {
        // Expand height to fit multiple lines (rough estimate)
        rcV.bottom = y + dpi::Scale(80);
        flags = DT_LEFT | DT_TOP | DT_NOPREFIX | DT_WORDBREAK;
        // Calculate actual height
        RECT calc = rcV;
        DrawTextW(hdc, value, -1, &calc, flags | DT_CALCRECT);
        rcV.bottom = calc.bottom;
    }
    DrawTextW(hdc, value, -1, &rcV, flags);

    SelectObject(hdc, oldF);
    return (rcV.bottom - rcV.top) + dpi::Scale(4);
}

void PaintPanel(HWND hwnd) {
    State* st = Get(hwnd);
    if (!st) return;

    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc; GetClientRect(hwnd, &rc);
    const int W = rc.right  - rc.left;
    const int H = rc.bottom - rc.top;

    // Double buffer
    HDC     memDc = CreateCompatibleDC(hdc);
    HBITMAP bmp   = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldB  = static_cast<HBITMAP>(SelectObject(memDc, bmp));

    // Surface
    HBRUSH brSurf = theme::Brush(theme::Color::Surface);
    FillRect(memDc, &rc, brSurf);

    // Border
    HPEN penB = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HPEN oldP = static_cast<HPEN>(SelectObject(memDc, penB));
    HBRUSH oldBr = static_cast<HBRUSH>(SelectObject(memDc, GetStockObject(NULL_BRUSH)));
    Rectangle(memDc, 0, 0, W, H);
    SelectObject(memDc, oldBr);
    SelectObject(memDc, oldP);
    DeleteObject(penB);

    const int padL = dpi::Scale(16);
    const int padR = dpi::Scale(16);

    // Reset copy-affordance hit map; PaintPanel rebuilds it each frame.
    st->copyHits.clear();

    if (st->hostIndex < 0
        || st->hostIndex >= static_cast<int>(App::Instance().Hosts().size())) {
        // Empty state — also collapse any leftover scrollbar state from a
        // previous selection so the panel doesn't show a spurious bar
        // alongside the centered placeholder text.
        SetBkMode(memDc, TRANSPARENT);
        SetTextColor(memDc, theme::Get(theme::Color::TextMuted));
        HFONT oldF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
        RECT rcMsg = rc;
        DrawTextW(memDc, L"Select a host to see details.", -1, &rcMsg,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(memDc, oldF);

        SCROLLINFO siEmpty{};
        siEmpty.cbSize = sizeof(siEmpty);
        siEmpty.fMask  = SIF_RANGE | SIF_PAGE | SIF_POS;
        siEmpty.nMin   = 0;
        siEmpty.nMax   = 0;
        siEmpty.nPage  = 1;
        siEmpty.nPos   = 0;
        SetScrollInfo(hwnd, SB_VERT, &siEmpty, TRUE);
        ShowScrollBar(hwnd, SB_VERT, FALSE);
        st->bodyContentH = 0;
        st->bodyVisibleH = 0;
        st->scrollY      = 0;
    } else {
        const HostRow& h = App::Instance().Hosts()[st->hostIndex];

        // ---- Header ----
        int y = dpi::Scale(14);

        // Big IP + status dot + status text — all vertically centered in a
        // common 36 px band so the dot aligns with both the IP baseline and
        // the "Online" text (M4.5 fix).
        const int ipRowH = dpi::Scale(36);

        SetBkMode(memDc, TRANSPARENT);
        SetTextColor(memDc, theme::Get(theme::Color::TextPrimary));
        HFONT oldF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().ipBig));

        SIZE szIp{};
        GetTextExtentPoint32W(memDc, h.ip.c_str(),
                              static_cast<int>(h.ip.size()), &szIp);
        RECT rcIp = { padL, y, padL + szIp.cx + dpi::Scale(2), y + ipRowH };
        DrawTextW(memDc, h.ip.c_str(), -1, &rcIp,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        const int dotR  = dpi::Scale(5);
        const int dotCx = rcIp.right + dpi::Scale(14);
        const int dotCy = y + ipRowH / 2;
        COLORREF dotColor = h.isOnline
            ? theme::Get(theme::Color::Success)
            : theme::Get(theme::Color::Neutral);
        HBRUSH brDot = CreateSolidBrush(dotColor);
        HBRUSH oldBrDot = static_cast<HBRUSH>(SelectObject(memDc, brDot));
        HPEN oldPenDot = static_cast<HPEN>(SelectObject(memDc, GetStockObject(NULL_PEN)));
        Ellipse(memDc, dotCx - dotR, dotCy - dotR, dotCx + dotR, dotCy + dotR);
        SelectObject(memDc, oldBrDot);
        SelectObject(memDc, oldPenDot);
        DeleteObject(brDot);

        SelectObject(memDc, theme::Fonts().semibold);
        SetTextColor(memDc, h.isOnline
                               ? theme::Get(theme::Color::Success)
                               : theme::Get(theme::Color::TextMuted));
        RECT rcStatus = { dotCx + dotR + dpi::Scale(6), y,
                          W - padR - dpi::Scale(24), y + ipRowH };
        DrawTextW(memDc, h.isOnline ? L"Online" : L"Offline", -1, &rcStatus,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        // IP copy affordance — right edge of the header row.
        AddCopyAffordance(st, memDc, CopyKind::IP,
                          W - padR, y, ipRowH, /*clientYDelta=*/0);

        SelectObject(memDc, oldF);

        y += ipRowH + dpi::Scale(2);

        // Subtitle: hostname  •  vendor  •  device-type, word-wrapped (M5.1).
        if (!h.hostname.empty() || !h.vendor.empty() || !h.deviceType.empty()) {
            std::wstring sub;
            auto append = [&](const std::wstring& seg) {
                if (seg.empty()) return;
                if (!sub.empty()) sub += L"  \x2022  ";
                sub += seg;
            };
            append(h.hostname);
            append(h.vendor);
            append(h.deviceType);

            HFONT subF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
            SetTextColor(memDc, theme::Get(theme::Color::TextMuted));
            // Calc actual height for wrapped text.
            RECT calc = { padL, y, W - padR, y + dpi::Scale(60) };
            DrawTextW(memDc, sub.c_str(), -1, &calc,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
            int subH = calc.bottom - calc.top;
            if (subH < dpi::Scale(20)) subH = dpi::Scale(20);
            RECT rcSub = { padL, y, W - padR, y + subH };
            DrawTextW(memDc, sub.c_str(), -1, &rcSub,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
            SelectObject(memDc, subF);
            y += subH + dpi::Scale(2);
        }

        // Chips row: RTT (always when online), CLOCK Δ (when engine reports
        // a time-of-day response), VIA (discovery method).
        if (h.isOnline) {
            HFONT cF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().smallBold));

            auto drawChip = [&](int xLeft, const wchar_t* text,
                                COLORREF surface, COLORREF border, COLORREF textCol) -> int {
                SIZE sz{};
                GetTextExtentPoint32W(memDc, text, lstrlenW(text), &sz);
                int chipW = sz.cx + dpi::Scale(16);
                int chipH = dpi::Scale(20);
                RECT chipRc = { xLeft, y + dpi::Scale(4),
                                xLeft + chipW, y + dpi::Scale(4) + chipH };
                HBRUSH brChip = CreateSolidBrush(surface);
                HPEN   pnChip = CreatePen(PS_SOLID, 1, border);
                HBRUSH ob = static_cast<HBRUSH>(SelectObject(memDc, brChip));
                HPEN   op = static_cast<HPEN>(SelectObject(memDc, pnChip));
                RoundRect(memDc, chipRc.left, chipRc.top, chipRc.right, chipRc.bottom,
                          dpi::Scale(8), dpi::Scale(8));
                SelectObject(memDc, ob);
                SelectObject(memDc, op);
                DeleteObject(brChip);
                DeleteObject(pnChip);
                SetTextColor(memDc, textCol);
                DrawTextW(memDc, text, -1, &chipRc,
                          DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                return chipW;
            };

            int cx = padL;
            wchar_t rttBuf[32];
            swprintf_s(rttBuf, L"RTT  %d ms", h.responseMs);
            cx += drawChip(cx, rttBuf,
                           theme::Get(theme::Color::AccentSurface),
                           theme::Get(theme::Color::Border),
                           theme::Get(theme::Color::Accent)) + dpi::Scale(8);

            // CLOCK Δ — only when engine got a time-of-day response.
            if (h.clockResponded) {
                wchar_t clkBuf[64];
                long long ms     = h.clockOffsetMs;
                long long abs_ms = ms < 0 ? -ms : ms;
                const wchar_t* sign = ms < 0 ? L"-" : L"+";
                if (abs_ms < 1000) {
                    swprintf_s(clkBuf, L"CLOCK \x0394  %s%lld ms", sign, abs_ms);
                } else if (abs_ms < 60'000) {
                    swprintf_s(clkBuf, L"CLOCK \x0394  %s%lld.%01lld s",
                               sign, abs_ms / 1000, (abs_ms % 1000) / 100);
                } else if (abs_ms < 3'600'000) {
                    swprintf_s(clkBuf, L"CLOCK \x0394  %s%lldm %02llds",
                               sign, abs_ms / 60'000, (abs_ms % 60'000) / 1000);
                } else if (abs_ms < 86'400'000) {
                    swprintf_s(clkBuf, L"CLOCK \x0394  %s%lldh %02lldm",
                               sign, abs_ms / 3'600'000,
                               (abs_ms % 3'600'000) / 60'000);
                } else {
                    swprintf_s(clkBuf, L"CLOCK \x0394  %s%lldd %02lldh",
                               sign, abs_ms / 86'400'000,
                               (abs_ms % 86'400'000) / 3'600'000);
                }
                cx += drawChip(cx, clkBuf,
                               theme::Get(theme::Color::WarningSurface),
                               theme::Get(theme::Color::Border),
                               theme::Get(theme::Color::Warning)) + dpi::Scale(8);
            }

            // VIA — discovery method.
            const wchar_t* via = nullptr;
            switch (h.discovery) {
                case DiscoveryMethod::ICMP:    via = L"ICMP";     break;
                case DiscoveryMethod::ARP:     via = L"ARP";      break;
                case DiscoveryMethod::TCP:     via = L"TCP";      break;
                case DiscoveryMethod::ArpIcmp: via = L"ARP+ICMP"; break;
                default: break;
            }
            if (via) {
                wchar_t viaBuf[40];
                swprintf_s(viaBuf, L"VIA  %s", via);
                drawChip(cx, viaBuf,
                         theme::Get(theme::Color::SurfaceAlt),
                         theme::Get(theme::Color::Border),
                         theme::Get(theme::Color::TextSecondary));
            }

            SelectObject(memDc, cF);
            y += dpi::Scale(28);
        }

        // Divider line
        HPEN penDiv = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
        HPEN opd    = static_cast<HPEN>(SelectObject(memDc, penDiv));
        MoveToEx(memDc, padL, y + dpi::Scale(2), nullptr);
        LineTo  (memDc, W - padR, y + dpi::Scale(2));
        SelectObject(memDc, opd);
        DeleteObject(penDiv);

        y += dpi::Scale(8);

        // Record where the action button row actually starts. If the
        // position changed (subtitle wrapped, extra chips appeared),
        // schedule a re-layout AFTER this paint completes — PostMessage
        // keeps the SetWindowPos inside LayoutButtons from recursing
        // back into the current paint pass.
        const int btnH    = dpi::Scale(28);
        const int btnGap  = dpi::Scale(6);
        if (st->actionRowY != y) {
            st->actionRowY = y;
            PostMessageW(hwnd, WM_USER + 99, 0, 0);   // resync buttons
        }
        // Buttons may wrap to 2+ rows in narrow panels; account for
        // every row in the y advance so the divider + IDENTITY section
        // don't sit on top of the wrapped Copy-report button.
        const int rows = (st->actionRowsUsed > 0) ? st->actionRowsUsed : 1;
        y += rows * btnH + (rows - 1) * btnGap + dpi::Scale(12);

        // Divider line under buttons
        HPEN penDiv2 = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
        HPEN opd2    = static_cast<HPEN>(SelectObject(memDc, penDiv2));
        MoveToEx(memDc, padL, y, nullptr);
        LineTo  (memDc, W - padR, y);
        SelectObject(memDc, opd2);
        DeleteObject(penDiv2);

        y += dpi::Scale(12);

        // ===== Scrollable body starts here ===========================
        st->bodyTopY = y;
        st->bodyVisibleH = H - y - dpi::Scale(4);

        // Clip + offset for scrolled body.
        int savedDc = SaveDC(memDc);
        IntersectClipRect(memDc, 0, y, W, H);
        // Translate so the body's "y=0" maps to (0, y - scrollY).
        POINT oldOrg;
        SetViewportOrgEx(memDc, 0, -st->scrollY, &oldOrg);
        int bodyStart = y;

        // ---- Identity ----
        DrawSectionHeader(memDc, { padL, y, W - padR, y + dpi::Scale(16) }, L"IDENTITY");
        y += dpi::Scale(20);

        const int copyW = dpi::Scale(24);
        const int wKey  = dpi::Scale(70);
        const int wVal  = W - padR - padL - wKey - dpi::Scale(10) - copyW;
        // Body uses scrolled viewport, so client_y = content_y - scrollY.
        const int bodyDelta = st->scrollY;

        auto kvCopy = [&](const wchar_t* key, const std::wstring& value,
                          CopyKind kind, bool hasValue) {
            int rowStart = y;
            int adv = DrawKeyValue(memDc, padL, y, wKey, wVal, key,
                                   value.empty() ? L"\x2014" : value.c_str());
            if (hasValue) {
                AddCopyAffordance(st, memDc, kind,
                                  W - padR, rowStart, adv, bodyDelta,
                                  bodyStart, H);
            }
            y += adv;
        };

        // The "Device model" row used to render here but was almost
        // always empty (engine only populates it for a narrow set of
        // WebUI-probed devices), so it just added a row of "—" noise.
        kvCopy(L"IP address",   h.ip,          CopyKind::IP,       !h.ip.empty());
        kvCopy(L"Hostname",     h.hostname,    CopyKind::Hostname, !h.hostname.empty());
        kvCopy(L"MAC address",  h.mac,         CopyKind::MAC,      !h.mac.empty());
        kvCopy(L"Vendor",       h.vendor,      CopyKind::Vendor,   !h.vendor.empty());
        kvCopy(L"Device",       h.deviceType,  CopyKind::None,     false);

        y += dpi::Scale(10);

        // ---- Services badges (M5.2) ----
        if (!h.badges.empty()) {
            DrawSectionHeader(memDc, { padL, y, W - padR, y + dpi::Scale(16) },
                              L"SERVICES");
            y += dpi::Scale(22);

            // Wrap badges into rows, similar to the host-grid services column.
            HFONT oldF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().smallBold));
            const int padX = dpi::Scale(8);
            const int gap  = dpi::Scale(6);
            const int chipH = dpi::Scale(20);
            int rx = padL;
            int ry = y;
            const int rightLimit = W - padR;
            for (const auto& b : h.badges) {
                SIZE bs{};
                GetTextExtentPoint32W(memDc, b.label.c_str(),
                                      static_cast<int>(b.label.size()), &bs);
                int cw = bs.cx + padX * 2;
                if (rx + cw > rightLimit && rx > padL) {
                    rx = padL;
                    ry += chipH + gap;
                }
                COLORREF bg, fg;
                BadgeColors(b, bg, fg);
                HBRUSH brFill = CreateSolidBrush(bg);
                HPEN   pnFill = CreatePen(PS_SOLID, 1, bg);
                HBRUSH ob = static_cast<HBRUSH>(SelectObject(memDc, brFill));
                HPEN   op = static_cast<HPEN>(SelectObject(memDc, pnFill));
                RoundRect(memDc, rx, ry, rx + cw, ry + chipH,
                          dpi::Scale(8), dpi::Scale(8));
                SelectObject(memDc, ob);
                SelectObject(memDc, op);
                DeleteObject(brFill);
                DeleteObject(pnFill);
                SetTextColor(memDc, fg);
                RECT rcTxt = { rx + padX, ry, rx + cw - padX, ry + chipH };
                DrawTextW(memDc, b.label.c_str(), -1, &rcTxt,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                rx += cw + gap;
            }
            SelectObject(memDc, oldF);
            y = ry + chipH + dpi::Scale(14);
        }

        // ---- Inferred ----
        if (!h.brandHint.empty() || !h.osHint.empty()
            || !h.deviceHint.empty() || !h.webUiModel.empty()) {
            DrawSectionHeader(memDc, { padL, y, W - padR, y + dpi::Scale(16) },
                              L"INFERRED");
            y += dpi::Scale(20);
            if (!h.brandHint.empty())
                y += DrawKeyValue(memDc, padL, y, wKey, wVal, L"Brand", h.brandHint.c_str());
            if (!h.osHint.empty())
                y += DrawKeyValue(memDc, padL, y, wKey, wVal, L"OS",    h.osHint.c_str());
            if (!h.deviceHint.empty())
                y += DrawKeyValue(memDc, padL, y, wKey, wVal, L"Hint",  h.deviceHint.c_str());
            if (!h.webUiModel.empty())
                y += DrawKeyValue(memDc, padL, y, wKey, wVal, L"Web UI", h.webUiModel.c_str());
            y += dpi::Scale(10);
        }

        // ---- PRINTER SUPPLIES ----
        // For printer hosts the consumables are the single most useful
        // datum a sysadmin opens this panel for, so they sit immediately
        // after INFERRED (above the open-ports detail). When SNMP didn't
        // answer the section still renders with a one-line note so the
        // "Printer detected" signal isn't lost.
        if (h.isPrinter) {
            int phdrTop = y;
            DrawSectionHeader(memDc,
                { padL, y, W - padR, y + dpi::Scale(16) },
                L"PRINTER SUPPLIES");
            AddCopyAffordance(st, memDc, CopyKind::PrinterSupplies,
                              W - padR, phdrTop - dpi::Scale(4),
                              dpi::Scale(20), bodyDelta,
                              bodyStart, H);
            y += dpi::Scale(22);

            // Slim header: only the serial number (vendor + model are
            // already shown in IDENTITY / Device rows above). When SN
            // isn't readable the line is skipped and we go straight to
            // the supplies table.
            if (!h.printerSerial.empty()) {
                std::wstring head = L"SN ";
                head += h.printerSerial;
                HFONT pf = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().smallFont));
                SetTextColor(memDc, theme::Get(theme::Color::TextMuted));
                RECT rcHead = { padL, y, W - padR, y + dpi::Scale(14) };
                DrawTextW(memDc, head.c_str(), -1, &rcHead,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
                SelectObject(memDc, pf);
                y += dpi::Scale(16);
            }

            if (!h.printerSupplies.empty()) {
                struct SupplyRow { std::wstring color, type, pct, level, max, desc; };
                std::vector<SupplyRow> rows;
                const std::wstring& s = h.printerSupplies;
                size_t i = 0;
                while (i < s.size()) {
                    size_t eol = s.find(L"\r\n", i);
                    std::wstring line = s.substr(i,
                        eol == std::wstring::npos ? std::wstring::npos : eol - i);
                    i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                    if (line.empty()) continue;
                    SupplyRow rr{};
                    auto take = [&](std::wstring& dst) {
                        size_t t = line.find(L'\t');
                        if (t == std::wstring::npos) { dst = line; line.clear(); }
                        else { dst = line.substr(0, t); line.erase(0, t + 1); }
                    };
                    take(rr.color);
                    take(rr.type);
                    take(rr.pct);
                    take(rr.level);
                    take(rr.max);
                    rr.desc = line;
                    rows.push_back(std::move(rr));
                }

                if (!rows.empty()) {
                    const int colColorW   = dpi::Scale(90);
                    const int colLevelW   = dpi::Scale(160);
                    const int gapCol      = dpi::Scale(8);
                    const int colX0 = padL;
                    const int colX1 = colX0 + colColorW + gapCol;
                    const int colX2 = colX1 + colLevelW + gapCol;
                    const int colDescW = (W - padR) - colX2;

                    HFONT hf = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().semibold));
                    SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));
                    RECT rcH0 = { colX0, y, colX0 + colColorW, y + dpi::Scale(16) };
                    RECT rcH1 = { colX1, y, colX1 + colLevelW, y + dpi::Scale(16) };
                    RECT rcH2 = { colX2, y, colX2 + colDescW,  y + dpi::Scale(16) };
                    DrawTextW(memDc, L"Consumable", -1, &rcH0, DT_LEFT  | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    DrawTextW(memDc, L"Level",      -1, &rcH1, DT_LEFT  | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    DrawTextW(memDc, L"Description",-1, &rcH2, DT_LEFT  | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    SelectObject(memDc, hf);
                    y += dpi::Scale(18);

                    const int rowH = dpi::Scale(22);
                    HFONT pf = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
                    for (const auto& rr : rows) {
                        COLORREF colorTint = theme::Get(theme::Color::TextPrimary);
                        if      (rr.color == L"Black")   colorTint = RGB(0x21, 0x21, 0x21);
                        else if (rr.color == L"Cyan")    colorTint = RGB(0x00, 0xAC, 0xC1);
                        else if (rr.color == L"Magenta") colorTint = RGB(0xD8, 0x1B, 0x60);
                        else if (rr.color == L"Yellow")  colorTint = RGB(0xE0, 0xB5, 0x1A);
                        SetTextColor(memDc, colorTint);
                        RECT rcC = { colX0, y, colX0 + colColorW, y + rowH };
                        DrawTextW(memDc, rr.color.empty() ? L"Supply" : rr.color.c_str(),
                                  -1, &rcC,
                                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

                        SetTextColor(memDc, theme::Get(theme::Color::TextPrimary));
                        RECT rcPct = { colX1, y, colX1 + dpi::Scale(46), y + rowH };
                        DrawTextW(memDc, rr.pct.empty() ? L"\x2014" : rr.pct.c_str(),
                                  -1, &rcPct,
                                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

                        int barX = colX1 + dpi::Scale(54);
                        int barW = colLevelW - dpi::Scale(54);
                        int barH = dpi::Scale(8);
                        int barY = y + (rowH - barH) / 2;
                        RECT rcBar = { barX, barY, barX + barW, barY + barH };
                        FillRect(memDc, &rcBar, theme::Brush(theme::Color::SurfaceAlt));
                        int pctVal = -1;
                        if (!rr.pct.empty()) {
                            int v = 0;
                            for (wchar_t c : rr.pct) {
                                if (c >= L'0' && c <= L'9') v = v * 10 + (c - L'0');
                                else if (c == L'%') break;
                                else if (v > 0) break;
                            }
                            if (v >= 0 && v <= 100) pctVal = v;
                        }
                        if (pctVal >= 0) {
                            int fillW = (barW * pctVal) / 100;
                            if (fillW > 0) {
                                COLORREF fillCol;
                                if (pctVal < 15)      fillCol = theme::Get(theme::Color::Danger);
                                else if (pctVal < 30) fillCol = theme::Get(theme::Color::Warning);
                                else                  fillCol = colorTint;
                                RECT rcFill = { barX, barY, barX + fillW, barY + barH };
                                HBRUSH br = CreateSolidBrush(fillCol);
                                FillRect(memDc, &rcFill, br);
                                DeleteObject(br);
                            }
                        }

                        SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));
                        RECT rcD = { colX2, y, colX2 + colDescW, y + rowH };
                        DrawTextW(memDc, rr.desc.c_str(), -1, &rcD,
                                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

                        y += rowH;
                    }
                    SelectObject(memDc, pf);
                }
            } else {
                HFONT pf = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
                SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));
                std::wstring note;
                if (h.printerSnmpStatus == L"unavailable")
                    note = L"Printer detected, supplies unavailable via SNMP.";
                else if (h.printerSnmpStatus == L"no supplies")
                    note = L"Printer detected, no consumables exposed via SNMP.";
                else if (h.printerSnmpStatus == L"not probed")
                    note = L"Printer detected. Run a Standard or Full Common scan to read supplies via SNMP.";
                else
                    note = L"Printer detected.";
                RECT rcN = { padL, y, W - padR, y + dpi::Scale(40) };
                DrawTextW(memDc, note.c_str(), -1, &rcN,
                          DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
                RECT calc = rcN;
                DrawTextW(memDc, note.c_str(), -1, &calc,
                          DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
                SelectObject(memDc, pf);
                y += (calc.bottom - calc.top);
            }
            y += dpi::Scale(10);
        }

        // ---- Open ports ----  (bullet-separated)
        if (!h.openPorts.empty()) {
            int hdrTop = y;
            // Section is labelled "TCP" to reflect engine reality: only
            // TCP connect scan is performed for the preset port list.
            // UDP-only ports (123 NTP, 137 NBNS, 161 SNMP, 1900 SSDP,
            // 5353 mDNS, …) that happen to sit in the preset list would
            // show as "not open" simply because we don't speak UDP on
            // them — without the label the user could draw false
            // negatives. Engine-side UDP discovery surfaces in its own
            // section below.
            DrawSectionHeader(memDc, { padL, y, W - padR, y + dpi::Scale(16) },
                              L"OPEN TCP PORTS");
            AddCopyAffordance(st, memDc, CopyKind::OpenPorts,
                              W - padR, hdrTop - dpi::Scale(4),
                              dpi::Scale(20), bodyDelta,
                              bodyStart, H);
            y += dpi::Scale(22);

            // Convert "80, 135, 139, ..." into "80 · 135 · 139 · ..."
            // (mid-dot separators read cleaner than commas in this
            // section).
            std::wstring bullets;
            bullets.reserve(h.openPorts.size() + 16);
            std::wstring tok;
            auto flushTok = [&]() {
                while (!tok.empty() && (tok.front() == L' ')) tok.erase(tok.begin());
                while (!tok.empty() && (tok.back()  == L' ')) tok.pop_back();
                if (!tok.empty()) {
                    if (!bullets.empty()) bullets += L"  \xb7  ";
                    bullets += tok;
                }
                tok.clear();
            };
            for (wchar_t c : h.openPorts) {
                if (c == L',') flushTok();
                else           tok.push_back(c);
            }
            flushTok();

            HFONT pf = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
            SetTextColor(memDc, theme::Get(theme::Color::TextPrimary));
            RECT rcPorts = { padL, y, W - padR, y + dpi::Scale(120) };
            DrawTextW(memDc, bullets.c_str(), -1, &rcPorts,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
            RECT calc = rcPorts;
            DrawTextW(memDc, bullets.c_str(), -1, &calc,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
            SelectObject(memDc, pf);
            y += (calc.bottom - calc.top) + dpi::Scale(10);
        }

        // ---- OPEN PORTS & SERVICES (N) table (M5.3) ----
        const std::vector<PortRow>& ports = App::Instance().PortsForHost(st->hostIndex);
        if (!ports.empty()) {
            wchar_t hdr[64];
            swprintf_s(hdr, L"OPEN TCP PORTS & SERVICES (%zu)", ports.size());
            DrawSectionHeader(memDc, { padL, y, W - padR, y + dpi::Scale(16) }, hdr);
            y += dpi::Scale(22);

            // Column layout: Port (right-aligned), Service, Product, Version.
            const int innerW = W - padL - padR;
            const int colPortW    = dpi::Scale(54);
            const int colServiceW = dpi::Scale(90);
            const int gapCol      = dpi::Scale(8);
            const int colProductW = (innerW - colPortW - colServiceW - gapCol * 3) * 60 / 100;
            const int colVersionW = innerW - colPortW - colServiceW - colProductW - gapCol * 3;

            int colX0 = padL;
            int colX1 = colX0 + colPortW    + gapCol;
            int colX2 = colX1 + colServiceW + gapCol;
            int colX3 = colX2 + colProductW + gapCol;

            const int rowH = dpi::Scale(20);

            // Column headers.
            {
                HFONT oldF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().label));
                SetTextColor(memDc, theme::Get(theme::Color::TextMuted));
                RECT rcPort = { colX0, y, colX0 + colPortW, y + dpi::Scale(16) };
                RECT rcSvc  = { colX1, y, colX1 + colServiceW, y + dpi::Scale(16) };
                RECT rcProd = { colX2, y, colX2 + colProductW, y + dpi::Scale(16) };
                RECT rcVer  = { colX3, y, colX3 + colVersionW, y + dpi::Scale(16) };
                DrawTextW(memDc, L"Port",    -1, &rcPort, DT_RIGHT  | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
                DrawTextW(memDc, L"Service", -1, &rcSvc,  DT_LEFT   | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
                DrawTextW(memDc, L"Product", -1, &rcProd, DT_LEFT   | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
                DrawTextW(memDc, L"Version", -1, &rcVer,  DT_LEFT   | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(memDc, oldF);
                y += dpi::Scale(18);
            }

            // Header divider line.
            HPEN penH = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
            HPEN op   = static_cast<HPEN>(SelectObject(memDc, penH));
            MoveToEx(memDc, padL, y, nullptr);
            LineTo  (memDc, W - padR, y);
            SelectObject(memDc, op);
            DeleteObject(penH);
            y += dpi::Scale(2);

            HFONT oldF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
            for (size_t i = 0; i < ports.size(); ++i) {
                const PortRow& pr = ports[i];

                // Alternate row tint.
                if ((i & 1) == 0) {
                    HBRUSH brAlt = CreateSolidBrush(theme::Get(theme::Color::TableAltRow));
                    RECT rcRow = { padL, y, W - padR, y + rowH };
                    FillRect(memDc, &rcRow, brAlt);
                    DeleteObject(brAlt);
                }

                wchar_t pbuf[16];
                swprintf_s(pbuf, L"%d", pr.port);

                SetTextColor(memDc, theme::Get(theme::Color::Accent));
                RECT rcPort = { colX0, y, colX0 + colPortW, y + rowH };
                DrawTextW(memDc, pbuf, -1, &rcPort,
                          DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

                SetTextColor(memDc, theme::Get(theme::Color::TextPrimary));
                const wchar_t* svc = !pr.service.empty()
                    ? pr.service.c_str()
                    : App::CanonicalServiceForPort(static_cast<uint16_t>(pr.port));
                RECT rcSvc = { colX1, y, colX1 + colServiceW, y + rowH };
                DrawTextW(memDc, svc, -1, &rcSvc,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

                SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));
                RECT rcProd = { colX2, y, colX2 + colProductW, y + rowH };
                DrawTextW(memDc, pr.product.empty() ? L"" : pr.product.c_str(),
                          -1, &rcProd,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

                RECT rcVer = { colX3, y, colX3 + colVersionW, y + rowH };
                DrawTextW(memDc, pr.version.empty() ? L"" : pr.version.c_str(),
                          -1, &rcVer,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

                y += rowH;
            }
            SelectObject(memDc, oldF);
            y += dpi::Scale(10);
        }

        // ---- UDP DISCOVERY ----
        // Targeted UDP probes (NBNS/137, NTP/123, SSDP/1900, mDNS/5353,
        // SQL Server Browser/1434, DNS/53, LLMNR/5355, IPMI/623). The
        // engine emits one line per responder: "<port>\t<service>\t<detail>".
        // We split into a 3-column table that mirrors OPEN TCP PORTS &
        // SERVICES — same layout, same column widths — so a user can
        // visually compare TCP and UDP findings side by side. A missing
        // row means "no response in budget", NOT "closed" (which is the
        // word reserved for TCP).
        if (!h.udpDiscovery.empty()) {
            // Parse "\r\n"-separated rows into [port, service, detail] tuples.
            struct UdpRow { std::wstring port, service, detail; };
            std::vector<UdpRow> rows;
            {
                const std::wstring& s = h.udpDiscovery;
                size_t i = 0;
                while (i < s.size()) {
                    size_t eol = s.find(L"\r\n", i);
                    std::wstring line = s.substr(i,
                        eol == std::wstring::npos ? std::wstring::npos : eol - i);
                    i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                    if (line.empty()) continue;
                    UdpRow r{};
                    size_t t1 = line.find(L'\t');
                    if (t1 == std::wstring::npos) { r.detail = line; rows.push_back(r); continue; }
                    r.port = line.substr(0, t1);
                    size_t t2 = line.find(L'\t', t1 + 1);
                    if (t2 == std::wstring::npos) {
                        r.service = line.substr(t1 + 1);
                    } else {
                        r.service = line.substr(t1 + 1, t2 - t1 - 1);
                        r.detail  = line.substr(t2 + 1);
                    }
                    rows.push_back(std::move(r));
                }
            }
            if (!rows.empty()) {
                wchar_t hdr[64];
                swprintf_s(hdr, L"UDP DISCOVERY (%zu)", rows.size());
                int udpHdrTop = y;
                DrawSectionHeader(memDc, { padL, y, W - padR, y + dpi::Scale(16) }, hdr);
                AddCopyAffordance(st, memDc, CopyKind::UdpDiscovery,
                                  W - padR, udpHdrTop - dpi::Scale(4),
                                  dpi::Scale(20), bodyDelta,
                                  bodyStart, H);
                y += dpi::Scale(22);

                // Reuse the OPEN TCP PORTS & SERVICES column geometry so
                // the two tables read as a matched pair.
                const int colPortW    = dpi::Scale(54);
                const int colServiceW = dpi::Scale(90);
                const int gapCol      = dpi::Scale(8);
                const int colX0 = padL;
                const int colX1 = colX0 + colPortW + gapCol;
                const int colX2 = colX1 + colServiceW + gapCol;
                const int colDetailW = (W - padR) - colX2;

                // Column header row.
                HFONT hf = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().semibold));
                SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));
                RECT rcH0 = { colX0, y, colX0 + colPortW,    y + dpi::Scale(16) };
                RECT rcH1 = { colX1, y, colX1 + colServiceW, y + dpi::Scale(16) };
                RECT rcH2 = { colX2, y, colX2 + colDetailW,  y + dpi::Scale(16) };
                DrawTextW(memDc, L"Port",    -1, &rcH0, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                DrawTextW(memDc, L"Service", -1, &rcH1, DT_LEFT  | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                DrawTextW(memDc, L"Detail",  -1, &rcH2, DT_LEFT  | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(memDc, hf);
                y += dpi::Scale(18);

                // Rows.
                const int rowH = dpi::Scale(20);
                HFONT pf = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().regular));
                for (const auto& r : rows) {
                    SetTextColor(memDc, theme::Get(theme::Color::TextPrimary));
                    RECT rcP = { colX0, y, colX0 + colPortW,    y + rowH };
                    DrawTextW(memDc, r.port.c_str(), -1, &rcP,
                              DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

                    SetTextColor(memDc, theme::Get(theme::Color::Accent));
                    RECT rcS = { colX1, y, colX1 + colServiceW, y + rowH };
                    DrawTextW(memDc, r.service.c_str(), -1, &rcS,
                              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

                    SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));
                    RECT rcD = { colX2, y, colX2 + colDetailW,  y + rowH };
                    DrawTextW(memDc, r.detail.c_str(), -1, &rcD,
                              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
                    y += rowH;
                }
                SelectObject(memDc, pf);
                y += dpi::Scale(10);
            }
        }

        // Body content done — restore DC and update scrollbar.
        st->bodyContentH = y - bodyStart;
        SetViewportOrgEx(memDc, oldOrg.x, oldOrg.y, nullptr);
        RestoreDC(memDc, savedDc);

        // Configure scrollbar to reflect content overflow. We set the range
        // unconditionally and then explicitly show/hide the bar — relying on
        // Win32's "hide when nPage >= nMax+1" heuristic was unreliable in
        // narrow layouts (M5.5 capture #2: 4 port-rows hidden, no scrollbar).
        const bool needScroll = (st->bodyContentH > st->bodyVisibleH);
        SCROLLINFO si{};
        si.cbSize = sizeof(si);
        si.fMask  = SIF_RANGE | SIF_PAGE | SIF_POS;
        si.nMin   = 0;
        si.nMax   = needScroll ? (st->bodyContentH - 1) : 0;
        si.nPage  = static_cast<UINT>(st->bodyVisibleH > 0 ? st->bodyVisibleH : 1);
        si.nPos   = st->scrollY;
        SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
        ShowScrollBar(hwnd, SB_VERT, needScroll ? TRUE : FALSE);

        const int maxScroll = needScroll
                                ? (st->bodyContentH - st->bodyVisibleH) : 0;
        if (st->scrollY > maxScroll) st->scrollY = maxScroll;
        if (st->scrollY < 0)         st->scrollY = 0;
    }

    // Blit
    BitBlt(hdc, 0, 0, W, H, memDc, 0, 0, SRCCOPY);
    SelectObject(memDc, oldB);
    DeleteObject(bmp);
    DeleteDC(memDc);

    EndPaint(hwnd, &ps);
}

void LayoutButtons(HWND hwnd) {
    State* st = Get(hwnd);
    if (!st) return;
    RECT rc; GetClientRect(hwnd, &rc);

    // When no host is selected, hide the entire action bar.
    // The "Select a host to see details." placeholder is centered on
    // the panel and the buttons (Ping / Browser / RDP / SSH / Telnet /
    // VNC / Copy report) have nothing to act on, so showing them at
    // that moment would just be visual clutter.
    const bool haveHost = (st->hostIndex >= 0)
        && (st->hostIndex < static_cast<int>(App::Instance().Hosts().size()));
    if (!haveHost) {
        for (int i = 0; i < kBtnCount; ++i) {
            if (st->buttons[i]) ShowWindow(st->buttons[i], SW_HIDE);
        }
        if (st->actionRowsUsed != 1) {
            st->actionRowsUsed = 1;
        }
        return;
    }
    // Make sure buttons are visible when a host is selected (they may have
    // been hidden by a previous "no selection" pass).
    for (int i = 0; i < kBtnCount; ++i) {
        if (st->buttons[i] && !IsWindowVisible(st->buttons[i])) {
            ShowWindow(st->buttons[i], SW_SHOWNA);
        }
    }

    const int padL = dpi::Scale(16);
    const int padR = dpi::Scale(16);

    // Prefer the actual Y reported by the last PaintPanel call so
    // wrapped subtitles + variable chip rows don't push buttons under
    // the header. Falls back to a conservative estimate before the
    // first paint.
    int y = (st->actionRowY > 0)
        ? st->actionRowY
        : (dpi::Scale(14)
           + dpi::Scale(36 + 2)
           + dpi::Scale(20)
           + dpi::Scale(28)
           + dpi::Scale(10));

    const int btnH = dpi::Scale(28);
    int x = padL;
    const int gap = dpi::Scale(6);
    const int maxX = rc.right - padR;
    const int rowStartY = y;
    int rowsUsed = 1;

    for (int i = 0; i < kBtnCount; ++i) {
        SIZE sz{};
        HDC dc = GetDC(hwnd);
        HFONT old = static_cast<HFONT>(SelectObject(dc, theme::Fonts().regular));
        GetTextExtentPoint32W(dc, kBtnLabels[i], lstrlenW(kBtnLabels[i]), &sz);
        SelectObject(dc, old);
        ReleaseDC(hwnd, dc);

        int w = sz.cx + dpi::Scale(18);
        if (x + w > maxX) {
            x = padL;
            y += btnH + gap;
            ++rowsUsed;
        }
        SetWindowPos(st->buttons[i], nullptr, x, y, w, btnH, SWP_NOZORDER);
        x += w + gap;
    }

    // If the row count changed (window narrower/wider, custom-ports
    // edit toggled, …), the body sections need to shift down/up.
    // Invalidate so PaintPanel re-runs with the new actionRowsUsed.
    if (st->actionRowsUsed != rowsUsed) {
        st->actionRowsUsed = rowsUsed;
        InvalidateRect(hwnd, nullptr, FALSE);
    }
    (void)rowStartY;
}

void OnCommand(HWND hwnd, int id) {
    State* st = Get(hwnd);
    if (!st || st->hostIndex < 0) return;
    const HostRow& h = App::Instance().Hosts()[st->hostIndex];
    const std::wstring& ip = h.ip;

    switch (id) {
        case ID_BTN_PING: {
            std::wstring args = L"/k ping " + ip;
            ShellExecuteW(hwnd, L"open", L"cmd.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
            break;
        }
        case ID_BTN_BROWSER: {
            std::wstring url = L"http://" + ip;
            ShellExecuteW(hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        }
        case ID_BTN_RDP: {
            std::wstring args = L"/v:" + ip;
            ShellExecuteW(hwnd, L"open", L"mstsc.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
            break;
        }
        case ID_BTN_SSH: {
            ShellExecuteW(hwnd, L"open", L"ssh.exe", ip.c_str(), nullptr, SW_SHOWNORMAL);
            break;
        }
        case ID_BTN_TELNET: {
            ShellExecuteW(hwnd, L"open", L"telnet.exe", ip.c_str(), nullptr, SW_SHOWNORMAL);
            break;
        }
        case ID_BTN_VNC: {
            MessageBoxW(hwnd, L"VNC client launch \x2014 not configured (milestone 2).",
                        L"NetLens", MB_OK | MB_ICONINFORMATION);
            break;
        }
        case ID_BTN_COPY: {
            // Full host report: identity + open TCP ports + printer
            // details + UDP discovery + a version footer so the
            // recipient knows which build produced it.
            std::wstring rpt;
            rpt += L"NetLens v" + App::Instance().EngineVersion() + L"  \x2014  host report\r\n";
            rpt += L"================================================\r\n";
            rpt += L"Host: " + h.ip + L"\r\n";
            if (!h.hostname.empty())   rpt += L"Hostname: "   + h.hostname   + L"\r\n";
            if (!h.mac.empty())        rpt += L"MAC: "        + h.mac        + L"\r\n";
            if (!h.vendor.empty())     rpt += L"Vendor: "     + h.vendor     + L"\r\n";
            if (!h.deviceType.empty()) rpt += L"Device: "     + h.deviceType + L"\r\n";
            if (!h.openPorts.empty())  rpt += L"Open TCP ports: " + h.openPorts + L"\r\n";
            if (!h.brandHint.empty())  rpt += L"Brand hint: " + h.brandHint  + L"\r\n";
            if (!h.osHint.empty())     rpt += L"OS hint: "    + h.osHint     + L"\r\n";

            // Printer block.
            if (h.isPrinter) {
                rpt += L"\r\n-- Printer ----------\r\n";
                if (!h.printerVendor.empty()) rpt += L"Vendor: " + h.printerVendor + L"\r\n";
                if (!h.printerModel.empty())  rpt += L"Model: "  + h.printerModel  + L"\r\n";
                if (!h.printerSerial.empty()) rpt += L"Serial: " + h.printerSerial + L"\r\n";
                if (!h.printerSnmpStatus.empty()) rpt += L"SNMP status: " + h.printerSnmpStatus + L"\r\n";
                // Parse tab-encoded supplies into a readable list.
                const std::wstring& s = h.printerSupplies;
                size_t i = 0;
                while (i < s.size()) {
                    size_t eol = s.find(L"\r\n", i);
                    std::wstring line = s.substr(i,
                        eol == std::wstring::npos ? std::wstring::npos : eol - i);
                    i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                    if (line.empty()) continue;
                    std::wstring col, type, pct, lvl, mx, desc;
                    auto take = [&](std::wstring& dst) {
                        size_t t = line.find(L'\t');
                        if (t == std::wstring::npos) { dst = line; line.clear(); }
                        else { dst = line.substr(0, t); line.erase(0, t + 1); }
                    };
                    take(col); take(type); take(pct); take(lvl); take(mx); desc = line;
                    rpt += L"  ";
                    rpt += col.empty() ? L"Supply" : col;
                    rpt += L": ";
                    rpt += pct.empty() ? L"unknown" : pct;
                    if (!lvl.empty() && !mx.empty()) {
                        rpt += L" ("; rpt += lvl; rpt += L"/"; rpt += mx; rpt += L")";
                    }
                    if (!desc.empty()) { rpt += L"  \x2014  "; rpt += desc; }
                    rpt += L"\r\n";
                }
            }

            // UDP discovery block.
            if (!h.udpDiscovery.empty()) {
                rpt += L"\r\n-- UDP discovery ----\r\n";
                const std::wstring& s = h.udpDiscovery;
                size_t i = 0;
                while (i < s.size()) {
                    size_t eol = s.find(L"\r\n", i);
                    std::wstring line = s.substr(i,
                        eol == std::wstring::npos ? std::wstring::npos : eol - i);
                    i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                    if (line.empty()) continue;
                    std::wstring port, svc, detail;
                    size_t t1 = line.find(L'\t');
                    if (t1 != std::wstring::npos) {
                        port = line.substr(0, t1);
                        size_t t2 = line.find(L'\t', t1 + 1);
                        if (t2 != std::wstring::npos) {
                            svc    = line.substr(t1 + 1, t2 - t1 - 1);
                            detail = line.substr(t2 + 1);
                        } else {
                            svc = line.substr(t1 + 1);
                        }
                    } else {
                        detail = line;
                    }
                    rpt += L"  UDP/"; rpt += port;
                    rpt += L"  "; rpt += svc;
                    if (!detail.empty()) { rpt += L"  \x2014  "; rpt += detail; }
                    rpt += L"\r\n";
                }
            }

            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t bytes = (rpt.size() + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
                if (hMem) {
                    if (void* p = GlobalLock(hMem)) {
                        memcpy(p, rpt.c_str(), bytes);
                        GlobalUnlock(hMem);
                        SetClipboardData(CF_UNICODETEXT, hMem);
                    } else {
                        GlobalFree(hMem);
                    }
                }
                CloseClipboard();
            }
            break;
        }
    }
}

void CopyFieldByKind(HWND hwnd, CopyKind kind) {
    State* st = Get(hwnd);
    if (!st || st->hostIndex < 0
        || st->hostIndex >= static_cast<int>(App::Instance().Hosts().size()))
        return;
    const HostRow& h = App::Instance().Hosts()[st->hostIndex];
    const std::wstring* text = nullptr;
    std::wstring composed;   // for kinds that build a multi-line block
    switch (kind) {
        case CopyKind::IP:        text = &h.ip;        break;
        case CopyKind::Hostname:  text = &h.hostname;  break;
        case CopyKind::MAC:       text = &h.mac;       break;
        case CopyKind::Vendor:    text = &h.vendor;    break;
        case CopyKind::OpenPorts: text = &h.openPorts; break;
        case CopyKind::PrinterSupplies: {
            // Assemble a readable plain-text block with the printer's
            // full identity and one line per supply.
            if (!h.isPrinter) return;
            if (!h.printerVendor.empty()) { composed += L"Vendor: "; composed += h.printerVendor; composed += L"\r\n"; }
            if (!h.printerModel.empty())  { composed += L"Model: ";  composed += h.printerModel;  composed += L"\r\n"; }
            if (!h.printerSerial.empty()) { composed += L"Serial: "; composed += h.printerSerial; composed += L"\r\n"; }
            if (!h.printerSnmpStatus.empty()) {
                composed += L"SNMP: "; composed += h.printerSnmpStatus; composed += L"\r\n";
            }
            // Parse the tab-encoded supplies blob into "Color: pct (level/max) — desc" lines.
            const std::wstring& s = h.printerSupplies;
            size_t i = 0;
            while (i < s.size()) {
                size_t eol = s.find(L"\r\n", i);
                std::wstring line = s.substr(i,
                    eol == std::wstring::npos ? std::wstring::npos : eol - i);
                i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                if (line.empty()) continue;
                std::wstring col, type, pct, lvl, mx, desc;
                auto take = [&](std::wstring& dst) {
                    size_t t = line.find(L'\t');
                    if (t == std::wstring::npos) { dst = line; line.clear(); }
                    else { dst = line.substr(0, t); line.erase(0, t + 1); }
                };
                take(col); take(type); take(pct); take(lvl); take(mx); desc = line;
                if (col.empty() && desc.empty()) continue;
                composed += L"- ";
                composed += col.empty() ? L"Supply" : col;
                composed += L": ";
                composed += pct.empty() ? L"unknown" : pct;
                if (!lvl.empty() && !mx.empty()) {
                    composed += L" ("; composed += lvl; composed += L"/"; composed += mx; composed += L")";
                }
                if (!desc.empty()) { composed += L"  \x2014  "; composed += desc; }
                composed += L"\r\n";
            }
            text = &composed;
            break;
        }
        case CopyKind::UdpDiscovery: {
            // Assemble a multi-line UDP discovery report.
            if (h.udpDiscovery.empty()) return;
            const std::wstring& s = h.udpDiscovery;
            size_t i = 0;
            while (i < s.size()) {
                size_t eol = s.find(L"\r\n", i);
                std::wstring line = s.substr(i,
                    eol == std::wstring::npos ? std::wstring::npos : eol - i);
                i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                if (line.empty()) continue;
                std::wstring port, svc, detail;
                size_t t1 = line.find(L'\t');
                if (t1 != std::wstring::npos) {
                    port = line.substr(0, t1);
                    size_t t2 = line.find(L'\t', t1 + 1);
                    if (t2 != std::wstring::npos) {
                        svc    = line.substr(t1 + 1, t2 - t1 - 1);
                        detail = line.substr(t2 + 1);
                    } else {
                        svc = line.substr(t1 + 1);
                    }
                } else {
                    detail = line;
                }
                composed += L"UDP/"; composed += port;
                composed += L"  "; composed += svc;
                if (!detail.empty()) { composed += L"  \x2014  "; composed += detail; }
                composed += L"\r\n";
            }
            text = &composed;
            break;
        }
        default: return;
    }
    if (!text || text->empty()) return;
    SetClipboardText(hwnd, *text);
}

LRESULT CALLBACK Proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_NCCREATE: {
            State* st = new State();
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_CREATE: {
            State* st = Get(hwnd);
            HINSTANCE hi = reinterpret_cast<LPCREATESTRUCTW>(lp)->hInstance;
            // 5 action buttons (Telnet+VNC moved to right-click menu).
            const int ids[kBtnCount] = {
                ID_BTN_PING, ID_BTN_BROWSER, ID_BTN_RDP,
                ID_BTN_SSH,  ID_BTN_COPY
            };
            for (int i = 0; i < kBtnCount; ++i) {
                st->buttons[i] = CreateWindowExW(
                    0, L"BUTTON", kBtnLabels[i],
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP,
                    0, 0, 0, 0,
                    hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ids[i])),
                    hi, nullptr);
                SendMessageW(st->buttons[i], WM_SETFONT,
                             reinterpret_cast<WPARAM>(theme::Fonts().regular),
                             MAKELPARAM(TRUE, 0));
            }
            return 0;
        }
        case WM_NCDESTROY: {
            if (State* st = Get(hwnd)) {
                delete st;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            PaintPanel(hwnd);
            return 0;
        case WM_SIZE:
            LayoutButtons(hwnd);
            return 0;
        case WM_DRAWITEM:
            PaintFlatButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lp));
            return TRUE;
        case WM_COMMAND:
            if (HIWORD(wp) == BN_CLICKED) OnCommand(hwnd, LOWORD(wp));
            return 0;
        case WM_DP_SET_HOST: {
            if (State* st = Get(hwnd)) {
                st->hostIndex = static_cast<int>(wp);
                st->scrollY   = 0;
                st->actionRowY = 0;   // force LayoutButtons recompute
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_USER + 99:
            // Resync action buttons after PaintPanel detected a layout shift.
            LayoutButtons(hwnd);
            return 0;
        case WM_VSCROLL: {
            State* st = Get(hwnd);
            if (!st) return 0;
            int maxScroll = (st->bodyContentH > st->bodyVisibleH)
                              ? (st->bodyContentH - st->bodyVisibleH) : 0;
            SCROLLINFO si{};
            si.cbSize = sizeof(si);
            si.fMask  = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            int newY = st->scrollY;
            switch (LOWORD(wp)) {
                case SB_LINEUP:        newY -= dpi::Scale(24); break;
                case SB_LINEDOWN:      newY += dpi::Scale(24); break;
                case SB_PAGEUP:        newY -= st->bodyVisibleH; break;
                case SB_PAGEDOWN:      newY += st->bodyVisibleH; break;
                case SB_THUMBPOSITION:
                case SB_THUMBTRACK:    newY = si.nTrackPos; break;
                case SB_TOP:           newY = 0; break;
                case SB_BOTTOM:        newY = maxScroll; break;
            }
            if (newY < 0)         newY = 0;
            if (newY > maxScroll) newY = maxScroll;
            if (newY != st->scrollY) {
                st->scrollY = newY;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_LBUTTONDOWN: {
            State* st = Get(hwnd);
            if (!st) return 0;
            POINT pt = { LOWORD(lp), HIWORD(lp) };
            for (const auto& a : st->copyHits) {
                if (PtInRect(&a.rc, pt)) {
                    CopyFieldByKind(hwnd, a.kind);
                    return 0;
                }
            }
            return 0;
        }
        case WM_SETCURSOR: {
            if (LOWORD(lp) == HTCLIENT) {
                State* st = Get(hwnd);
                if (st) {
                    POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
                    for (const auto& a : st->copyHits) {
                        if (PtInRect(&a.rc, pt)) {
                            SetCursor(LoadCursorW(nullptr, IDC_HAND));
                            return TRUE;
                        }
                    }
                }
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_MOUSEWHEEL: {
            State* st = Get(hwnd);
            if (!st) return 0;
            int delta = GET_WHEEL_DELTA_WPARAM(wp);
            int step  = dpi::Scale(40);
            int newY = st->scrollY - (delta * step / WHEEL_DELTA);
            int maxScroll = (st->bodyContentH > st->bodyVisibleH)
                              ? (st->bodyContentH - st->bodyVisibleH) : 0;
            if (newY < 0)         newY = 0;
            if (newY > maxScroll) newY = maxScroll;
            if (newY != st->scrollY) {
                st->scrollY = newY;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

void DetailsPanel::Register(HINSTANCE hInst) {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = Proc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = ClassName();
    RegisterClassExW(&wc);
}

HWND DetailsPanel::Create(HWND parent, HINSTANCE hInst, int id) {
    return CreateWindowExW(
        0, ClassName(), L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | WS_VSCROLL,
        0, 0, 0, 0,
        parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        hInst, nullptr);
}

void DetailsPanel::SetHostIndex(HWND h, int hostIndex) {
    SendMessageW(h, WM_DP_SET_HOST, static_cast<WPARAM>(hostIndex), 0);
}

}  // namespace nl
