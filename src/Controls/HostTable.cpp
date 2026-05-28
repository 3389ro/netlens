#include "HostTable.h"

#include <commctrl.h>
#include <uxtheme.h>
#include <string>

#include "../App.h"
#include "../Dpi.h"
#include "../Models.h"
#include "../Theme.h"
#include "../../Resource.h"

namespace nl::HostTable {

namespace {

// v1.3.3 — tracks the wall-clock time of the user's most recent
// interaction with the host listview (mouse wheel, scrollbar, click,
// keyboard cursor). RefreshData consults it during a scan and
// suppresses the auto-snap "make selected row visible" call when the
// user has been actively scrolling within the last kRespectUserMs.
// Without this, the user would see the table fight their mouse wheel
// every snapshot — virtual ListView (LVS_OWNERDATA) loses its
// selection state on SetItemCountEx, so the snapshot path re-asserts
// LVIS_SELECTED+LVIS_FOCUSED, and the focused-item assertion plus an
// explicit ListView_EnsureVisible scrolled the table back to the
// selected row 4× per second.
ULONGLONG s_lastUserInputMs = 0;
constexpr ULONGLONG kRespectUserMs = 600;
bool userIsScrolling() {
    return (::GetTickCount64() - s_lastUserInputMs) < kRespectUserMs;
}

LRESULT CALLBACK ListSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp,
                              UINT_PTR /*id*/, DWORD_PTR /*ref*/) {
    switch (msg) {
        case WM_MOUSEWHEEL:
        case WM_VSCROLL:
        case WM_HSCROLL:
        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
        case WM_KEYDOWN:
            // Stamp BEFORE forwarding so RefreshData fired by any
            // resulting LVN_ITEMCHANGED sees the freshest timestamp.
            s_lastUserInputMs = ::GetTickCount64();
            break;
        case WM_NCDESTROY:
            RemoveWindowSubclass(h, ListSubclass, 1);
            break;
    }
    return DefSubclassProc(h, msg, wp, lp);
}

struct ColumnSpec {
    const wchar_t* title;
    int            widthPx96;  // unscaled
    int            align;      // LVCFMT_LEFT / RIGHT / CENTER
};

const ColumnSpec kColumns[COL_COUNT] = {
    { L"IP",          110, LVCFMT_LEFT  },
    { L"MAC",         136, LVCFMT_LEFT  },
    { L"Status",       82, LVCFMT_LEFT  },
    { L"Hostname",    160, LVCFMT_LEFT  },
    { L"Device Type", 180, LVCFMT_LEFT  },
    { L"Model",       180, LVCFMT_LEFT  },
    { L"Vendor",      110, LVCFMT_LEFT  },
    { L"Open TCP ports", 170, LVCFMT_LEFT  },
    { L"Services",    260, LVCFMT_LEFT  },
    { L"RTT",          64, LVCFMT_RIGHT },
};

// Label-aware palette so HTTP / HTTPS / SMB don't all collapse to the
// same blue. Each TLS variant gets indigo; share-family services get a
// distinct teal; Mgmt uses a deeper amber than Remote so WinRM ≠ RDP
// visually. Category remains the fallback.
void BadgeColors(const ServiceBadge& b, COLORREF& bg, COLORREF& fg) {
    using C = theme::Color;
    const std::wstring& label = b.label;

    auto eq = [&](const wchar_t* s) { return label == s; };

    // TLS / secure variants — indigo.
    if (eq(L"HTTPS") || eq(L"LDAPS") || eq(L"IMAPS") || eq(L"POP3S")
        || eq(L"SMTPS") || eq(L"FTPS") || eq(L"WinRM-TLS") || eq(L"K8s API")) {
        bg = RGB(0xE6, 0xE0, 0xFA);   // light indigo
        fg = RGB(0x59, 0x3E, 0xC6);   // deep indigo
        return;
    }
    // Share family (file/protocol-share) — teal.
    if (eq(L"SMB") || eq(L"NetBIOS") || eq(L"AFP") || eq(L"NFS") || eq(L"FTP")) {
        bg = RGB(0xD4, 0xEE, 0xF4);
        fg = RGB(0x0D, 0x73, 0x95);
        return;
    }
    // Mgmt — deeper warm orange than Remote.
    if (eq(L"WinRM") || eq(L"SNMP") || eq(L"IPMI") || eq(L"WSDAPI")) {
        bg = RGB(0xFD, 0xE5, 0xCC);
        fg = RGB(0xC2, 0x63, 0x18);
        return;
    }
    // Databases (and DB-adjacent) — red/pink.
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

void FillRgnRect(HDC hdc, const RECT& rc, COLORREF color) {
    HBRUSH br = CreateSolidBrush(color);
    FillRect(hdc, &rc, br);
    DeleteObject(br);
}

void PaintStatusCell(HDC hdc, const RECT& cell, const HostRow& h) {
    SetBkMode(hdc, TRANSPARENT);

    const int dotR = dpi::Scale(4);
    const int dotCx = cell.left + dpi::Scale(10);
    const int dotCy = (cell.top + cell.bottom) / 2;

    COLORREF dotColor = h.isOnline
        ? theme::Get(theme::Color::Success)
        : theme::Get(theme::Color::Neutral);

    HBRUSH br = CreateSolidBrush(dotColor);
    HBRUSH oldBr = static_cast<HBRUSH>(SelectObject(hdc, br));
    HPEN   penOld = static_cast<HPEN>(SelectObject(hdc, GetStockObject(NULL_PEN)));
    Ellipse(hdc, dotCx - dotR, dotCy - dotR, dotCx + dotR, dotCy + dotR);
    SelectObject(hdc, oldBr);
    SelectObject(hdc, penOld);
    DeleteObject(br);

    const wchar_t* txt = h.isOnline ? L"Online" : L"Offline";
    SetTextColor(hdc, h.isOnline
                       ? theme::Get(theme::Color::TextPrimary)
                       : theme::Get(theme::Color::TextMuted));
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    RECT rcText = cell;
    rcText.left += dpi::Scale(20);
    DrawTextW(hdc, txt, -1, &rcText,
              DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

void PaintServicesCell(HDC hdc, const RECT& cell, const HostRow& h) {
    if (h.badges.empty()) return;

    SetBkMode(hdc, TRANSPARENT);

    // Hard clip to the cell — protects against off-by-one issues at column edges.
    int saved = SaveDC(hdc);
    IntersectClipRect(hdc, cell.left, cell.top, cell.right, cell.bottom);

    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().smallBold));

    int x = cell.left + dpi::Scale(6);
    const int padX     = dpi::Scale(8);
    const int gap      = dpi::Scale(5);
    const int radius   = dpi::Scale(8);
    const int height   = (cell.bottom - cell.top) - dpi::Scale(8);
    const int yTop     = cell.top + ((cell.bottom - cell.top) - height) / 2;
    const int safeR    = cell.right - dpi::Scale(8);
    const int ellipsisW = dpi::Scale(16);

    auto paintBadge = [&](int xL, COLORREF bg, COLORREF fg,
                          const wchar_t* text, int textW) {
        int w = textW + padX * 2;
        HBRUSH brFill = CreateSolidBrush(bg);
        HPEN   penFill = CreatePen(PS_SOLID, 1, bg);
        HBRUSH oldBr   = static_cast<HBRUSH>(SelectObject(hdc, brFill));
        HPEN   oldPen  = static_cast<HPEN>(SelectObject(hdc, penFill));
        RoundRect(hdc, xL, yTop, xL + w, yTop + height, radius, radius);
        SelectObject(hdc, oldBr);
        SelectObject(hdc, oldPen);
        DeleteObject(brFill);
        DeleteObject(penFill);
        SetTextColor(hdc, fg);
        RECT rcText = { xL + padX, yTop, xL + w - padX, yTop + height };
        DrawTextW(hdc, text, -1, &rcText,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        return w;
    };

    for (size_t i = 0; i < h.badges.size(); ++i) {
        const auto& b = h.badges[i];
        SIZE sz{};
        GetTextExtentPoint32W(hdc, b.label.c_str(),
                              static_cast<int>(b.label.size()), &sz);
        const int w = sz.cx + padX * 2;

        // Reserve room for "+N" overflow badge when more remain.
        const bool isLast = (i + 1 == h.badges.size());
        const int  limit  = isLast ? safeR : (safeR - ellipsisW);

        if (x + w > limit) {
            // Overflow — render "+N" badge in the neutral palette.
            int remaining = static_cast<int>(h.badges.size() - i);
            wchar_t buf[12];
            swprintf_s(buf, L"+%d", remaining);
            SIZE szN{};
            GetTextExtentPoint32W(hdc, buf, lstrlenW(buf), &szN);
            paintBadge(x,
                       theme::Get(theme::Color::NeutralSurface),
                       theme::Get(theme::Color::TextSecondary),
                       buf, szN.cx);
            break;
        }

        COLORREF bg, fg;
        BadgeColors(b, bg, fg);
        int drew = paintBadge(x, bg, fg, b.label.c_str(), sz.cx);
        x += drew + gap;
    }

    SelectObject(hdc, oldF);
    RestoreDC(hdc, saved);
}

// M5 — custom paint for the listview's header child.
LRESULT CALLBACK HeaderSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp,
                                UINT_PTR id, DWORD_PTR /*ref*/) {
    if (msg == WM_NCDESTROY) {
        RemoveWindowSubclass(h, HeaderSubclass, id);
        return DefSubclassProc(h, msg, wp, lp);
    }
    if (msg == WM_ERASEBKGND) return 1;
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(h, &ps);
        RECT rcAll; GetClientRect(h, &rcAll);

        // Double buffer
        HDC memDc = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, rcAll.right, rcAll.bottom);
        HBITMAP oldB = static_cast<HBITMAP>(SelectObject(memDc, bmp));

        FillRect(memDc, &rcAll, theme::Brush(theme::Color::TableHeader));

        int n = static_cast<int>(SendMessageW(h, HDM_GETITEMCOUNT, 0, 0));
        HFONT oldF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().semibold));
        SetBkMode(memDc, TRANSPARENT);
        SetTextColor(memDc, theme::Get(theme::Color::TextSecondary));

        for (int i = 0; i < n; ++i) {
            RECT ir{};
            SendMessageW(h, HDM_GETITEMRECT, i, reinterpret_cast<LPARAM>(&ir));

            wchar_t buf[64] = {};
            HDITEMW hi{};
            hi.mask = HDI_TEXT | HDI_FORMAT;
            hi.pszText = buf;
            hi.cchTextMax = 64;
            SendMessageW(h, HDM_GETITEM, i, reinterpret_cast<LPARAM>(&hi));

            const int arrowW = dpi::Scale(14);
            const bool sortUp   = (hi.fmt & HDF_SORTUP)   != 0;
            const bool sortDown = (hi.fmt & HDF_SORTDOWN) != 0;
            const bool hasArrow = sortUp || sortDown;

            RECT tr = ir;
            tr.left += dpi::Scale(10);
            tr.right -= dpi::Scale(8) + (hasArrow ? arrowW : 0);
            DWORD flags = DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX
                        | DT_END_ELLIPSIS;
            if ((hi.fmt & HDF_RIGHT) != 0) {
                flags &= ~DT_LEFT;
                flags |= DT_RIGHT;
            }
            DrawTextW(memDc, buf, -1, &tr, flags);

            if (hasArrow) {
                int ax = ir.right - dpi::Scale(10);
                int ay = (ir.top + ir.bottom) / 2;
                POINT pts[3];
                if (sortUp) {
                    pts[0] = { ax - dpi::Scale(4), ay + dpi::Scale(2) };
                    pts[1] = { ax + dpi::Scale(4), ay + dpi::Scale(2) };
                    pts[2] = { ax,                  ay - dpi::Scale(3) };
                } else {
                    pts[0] = { ax - dpi::Scale(4), ay - dpi::Scale(2) };
                    pts[1] = { ax + dpi::Scale(4), ay - dpi::Scale(2) };
                    pts[2] = { ax,                  ay + dpi::Scale(3) };
                }
                HBRUSH br = CreateSolidBrush(theme::Get(theme::Color::Accent));
                HBRUSH obr = static_cast<HBRUSH>(SelectObject(memDc, br));
                HPEN   opn = static_cast<HPEN>(SelectObject(memDc, GetStockObject(NULL_PEN)));
                Polygon(memDc, pts, 3);
                SelectObject(memDc, obr);
                SelectObject(memDc, opn);
                DeleteObject(br);
            }

            // Subtle separator on the right edge of each column header.
            HPEN p = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
            HPEN op = static_cast<HPEN>(SelectObject(memDc, p));
            MoveToEx(memDc, ir.right - 1, ir.top + dpi::Scale(6), nullptr);
            LineTo  (memDc, ir.right - 1, ir.bottom - dpi::Scale(6));
            SelectObject(memDc, op);
            DeleteObject(p);
        }

        // Bottom border across the whole header.
        HPEN p = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
        HPEN op = static_cast<HPEN>(SelectObject(memDc, p));
        MoveToEx(memDc, 0, rcAll.bottom - 1, nullptr);
        LineTo  (memDc, rcAll.right, rcAll.bottom - 1);
        SelectObject(memDc, op);
        DeleteObject(p);

        SelectObject(memDc, oldF);

        BitBlt(hdc, 0, 0, rcAll.right, rcAll.bottom, memDc, 0, 0, SRCCOPY);
        SelectObject(memDc, oldB);
        DeleteObject(bmp);
        DeleteDC(memDc);
        EndPaint(h, &ps);
        return 0;
    }
    return DefSubclassProc(h, msg, wp, lp);
}

}  // namespace

HWND Create(HWND parent, HINSTANCE hInst, int id) {
    HWND hLv = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS
        | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
        0, 0, 0, 0,
        parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        hInst, nullptr);
    if (!hLv) return nullptr;

    ListView_SetExtendedListViewStyle(hLv,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);

    // Use a 1x dummy image list to drive the listview's row height.
    HIMAGELIST hImg = ImageList_Create(1, dpi::Scale(26), ILC_COLOR32, 0, 0);
    ListView_SetImageList(hLv, hImg, LVSIL_SMALL);

    // Columns
    for (int i = 0; i < COL_COUNT; ++i) {
        LVCOLUMNW c{};
        c.mask    = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        c.pszText = const_cast<LPWSTR>(kColumns[i].title);
        c.cx      = dpi::Scale(kColumns[i].widthPx96);
        c.fmt     = kColumns[i].align;
        ListView_InsertColumn(hLv, i, &c);
    }

    SendMessageW(hLv, WM_SETFONT,
                 reinterpret_cast<WPARAM>(theme::Fonts().regular),
                 MAKELPARAM(TRUE, 0));

    // Modern Explorer styling for the listview itself; the header is fully
    // owner-painted by HeaderSubclass below so SetWindowTheme isn't needed on it.
    SetWindowTheme(hLv, L"Explorer", nullptr);
    if (HWND hHdr = ListView_GetHeader(hLv)) {
        SendMessageW(hHdr, WM_SETFONT,
                     reinterpret_cast<WPARAM>(theme::Fonts().semibold),
                     MAKELPARAM(TRUE, 0));
        SetWindowSubclass(hHdr, HeaderSubclass, 1, 0);
    }

    // v1.3.3 — subclass the listview itself so user interaction events
    // (wheel, scroll, click, key) stamp the global last-user-input
    // timestamp. Used by RefreshData to suppress auto-snap during
    // active scrolling.
    SetWindowSubclass(hLv, ListSubclass, 1, 0);

    UpdateSortIndicator(hLv);
    RefreshData(hLv);
    return hLv;
}

namespace {
// Map ListView column → App::SortColumn. Returns -1 for non-sortable columns
// (none right now — every column maps to a key).
int ColumnToSortCol(int col) {
    using SC = App::SortColumn;
    switch (col) {
        case COL_IP:         return static_cast<int>(SC::IpV4);
        case COL_MAC:        return static_cast<int>(SC::Mac);
        case COL_STATUS:     return static_cast<int>(SC::Status);
        case COL_HOSTNAME:   return static_cast<int>(SC::Hostname);
        case COL_DEVICE:     return static_cast<int>(SC::Device);
        case COL_MODEL:      return static_cast<int>(SC::Model);
        case COL_VENDOR:     return static_cast<int>(SC::Vendor);
        case COL_OPEN_PORTS: return static_cast<int>(SC::OpenPortCount);
        case COL_SERVICES:   return static_cast<int>(SC::Services);
        case COL_RTT:        return static_cast<int>(SC::Rtt);
        default:             return -1;
    }
}

int SortColToColumn(App::SortColumn sc) {
    using SC = App::SortColumn;
    switch (sc) {
        case SC::IpV4:          return COL_IP;
        case SC::Mac:           return COL_MAC;
        case SC::Hostname:      return COL_HOSTNAME;
        case SC::Vendor:        return COL_VENDOR;
        case SC::Device:        return COL_DEVICE;
        case SC::Model:         return COL_MODEL;
        case SC::OpenPortCount: return COL_OPEN_PORTS;
        case SC::Services:      return COL_SERVICES;
        case SC::Rtt:           return COL_RTT;
        case SC::Status:        return COL_STATUS;
    }
    return COL_IP;
}
}  // namespace

void OnColumnClick(HWND hLv, int column) {
    int sc = ColumnToSortCol(column);
    if (sc < 0) return;  // non-sortable
    App::Instance().ToggleSort(static_cast<App::SortColumn>(sc));
    UpdateSortIndicator(hLv);
    // User-initiated sort change must paint immediately — bypass the
    // in-scan visible-refresh throttle inside RefreshData.
    RefreshData(hLv, /*forceRepaint=*/true);
}

void UpdateSortIndicator(HWND hLv) {
    HWND hHdr = ListView_GetHeader(hLv);
    if (!hHdr) return;
    int activeCol = SortColToColumn(App::Instance().SortCol());
    int nCols = static_cast<int>(SendMessageW(hHdr, HDM_GETITEMCOUNT, 0, 0));
    for (int i = 0; i < nCols; ++i) {
        HDITEMW hi{};
        hi.mask = HDI_FORMAT;
        SendMessageW(hHdr, HDM_GETITEM, i, reinterpret_cast<LPARAM>(&hi));
        hi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == activeCol) {
            hi.fmt |= (App::Instance().SortAscending() ? HDF_SORTUP : HDF_SORTDOWN);
        }
        SendMessageW(hHdr, HDM_SETITEM, i, reinterpret_cast<LPARAM>(&hi));
    }
}

void SetStatusColumnVisible(HWND hLv, bool /*visible*/) {
    // Implemented via AutoSizeColumns which reads App::ViewOffline() and
    // sets Status column width to 0 when offline rows are hidden.
    AutoSizeColumns(hLv);
}

void AutoSizeColumns(HWND hLv) {
    if (!hLv) return;
    RECT rc; GetClientRect(hLv, &rc);
    int avail = rc.right - rc.left;
    if (avail <= 0) return;

    // Reserve scrollbar gutter so the rightmost column isn't pushed under it.
    int sbW = GetSystemMetrics(SM_CXVSCROLL);
    avail = (avail > sbW + dpi::Scale(8)) ? avail - sbW : avail;

    const bool statusVisible = App::Instance().ViewOffline();

    // Services and RTT columns are hidden (width 0):
    //   - Services duplicated the right-pane OPEN TCP PORTS & SERVICES
    //     table; the badges were the table's widest column (260 px)
    //     with no info the right pane didn't already carry.
    //   - RTT for LAN scans is essentially constant (1-5 ms). Useful
    //     diagnostically but better shown as the RTT chip in the right
    //     pane header — saves 64 px from a wide grid.
    // Open TCP ports flexes to fill the freed width.
    int wIp        = dpi::Scale(90);
    int wMac       = dpi::Scale(126);
    int wStatus    = statusVisible ? dpi::Scale(72) : 0;
    int wHostname  = dpi::Scale(125);
    int wDevice    = dpi::Scale(150);
    int wModel     = dpi::Scale(160);   // exact model (printer/AP/ESXi/web title)
    int wVendor    = dpi::Scale(100);
    int wServices  = 0;       // hidden
    int wRtt       = 0;       // hidden

    int fixed = wIp + wMac + wStatus + wHostname + wDevice + wModel
              + wVendor + wServices + wRtt;
    int wOpenPorts = avail - fixed;
    int wOpenPortsMin = dpi::Scale(150);
    if (wOpenPorts < wOpenPortsMin) wOpenPorts = wOpenPortsMin;

    ListView_SetColumnWidth(hLv, COL_IP,         wIp);
    ListView_SetColumnWidth(hLv, COL_MAC,        wMac);
    ListView_SetColumnWidth(hLv, COL_STATUS,     wStatus);
    ListView_SetColumnWidth(hLv, COL_HOSTNAME,   wHostname);
    ListView_SetColumnWidth(hLv, COL_DEVICE,     wDevice);
    ListView_SetColumnWidth(hLv, COL_MODEL,      wModel);
    ListView_SetColumnWidth(hLv, COL_VENDOR,     wVendor);
    ListView_SetColumnWidth(hLv, COL_OPEN_PORTS, wOpenPorts);
    ListView_SetColumnWidth(hLv, COL_SERVICES,   wServices);
    ListView_SetColumnWidth(hLv, COL_RTT,        wRtt);

    // Make sure the leftmost column is in view — the listview can hold a
    // scroll position from a previous layout.
    ListView_Scroll(hLv, -INT_MAX, 0);
}

void RefreshData(HWND hLv, bool forceRepaint) {
    if (!hLv) return;
    const auto& idx = App::Instance().FilteredIndex();

    // Preserve scroll position across snapshot refreshes. On an
    // AllPortsFast scan snapshots arrive at 10 Hz, and each
    // SetItemCountEx + InvalidateRect would knock the user's scroll
    // back to the top whenever the count grew. Saving the top index
    // and re-scrolling by row-pixel delta keeps the view stable.
    int topBefore = ListView_GetTopIndex(hLv);

    // The row count itself we always sync. Two flags are critical:
    //   LVSICF_NOINVALIDATEALL — don't repaint the whole control; we
    //                            do the throttled InvalidateRect below.
    //   LVSICF_NOSCROLL        — don't auto-scroll the viewport.
    //
    // The NOSCROLL bit is the one that finally killed the "wheel scrolls
    // then snaps back to the selected row" bug. Per MSDN: "The default
    // behavior of the control is to scroll if needed when items are
    // added or removed." On a scan that's 10× per second; every
    // snapshot the listview was hauling the viewport back to wherever
    // it thought the selection should be visible. With NOSCROLL set the
    // count just updates and the user's wheel-set scroll position is
    // preserved unconditionally.
    ListView_SetItemCountEx(hLv, static_cast<int>(idx.size()),
                            LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

    // Throttle the actual visual repaint during a scan. Snapshots land
    // at 10 Hz; without throttling, every 100 ms the host grid would
    // tear-down its visible row paints and immediately repaint — and
    // when a non-default sort column (RTT, Status, Open ports) is
    // active the live data churn keeps shuffling row order, so the
    // user-reported effect is rows flickering and jumping every 100 ms.
    // Cap visible refresh at ~4 Hz while the engine is mid-scan; the
    // last snapshot pulse (isScanning=false) always paints so the final
    // view is correct.
    static ULONGLONG s_lastInvalidate = 0;
    const ULONGLONG now = ::GetTickCount64();
    const bool scanning = App::Instance().Stats().isScanning;
    constexpr ULONGLONG kRefreshMinMs = 250;  // ~4 Hz during scan
    bool doInvalidate = true;
    if (!forceRepaint && scanning
        && (now - s_lastInvalidate) < kRefreshMinMs) {
        doInvalidate = false;
    }
    if (doInvalidate) {
        s_lastInvalidate = now;
        InvalidateRect(hLv, nullptr, FALSE);
    }

    // (v1.3.3) Removed the topBefore/topAfter scroll-restore branch.
    // It was a safety net for SetItemCountEx clamping topIndex when
    // the count shrinks below the previous top — but during a scan
    // count only grows, so the branch was a no-op the 99% of the time
    // it ran, and on the 1% (end-of-scan reshuffle / Clear / filter
    // change) the user-reported symptom was the table snapping back to
    // an earlier scroll position. Letting the listview handle scroll
    // natively is the right behaviour; the worst case after a count
    // shrink (Clear) is the view clamps to the new tail, which is
    // self-correcting on the next user interaction. `topBefore` is no
    // longer read after this point — kept as a local for now in case
    // we need to bring back conditional logic.
    (void)topBefore;

    // Selection re-stamp. With LVSICF_NOSCROLL on the SetItemCountEx
    // above, calling SetItemState here no longer drags the viewport —
    // so we can safely keep the visible selection in sync with App's
    // IP-tracked selectedIp_ on every snapshot. EnsureVisible /
    // LVIS_FOCUSED are still gated on forceRepaint (user-initiated)
    // because those genuinely DO scroll on purpose.
    int hostIdx = App::Instance().SelectedIndex();
    int desiredRow = -1;
    for (size_t i = 0; i < idx.size(); ++i) {
        if (idx[i] == hostIdx) { desiredRow = static_cast<int>(i); break; }
    }
    int currentSel = ListView_GetNextItem(hLv, -1, LVNI_SELECTED);
    if (desiredRow != currentSel) {
        if (currentSel >= 0) {
            ListView_SetItemState(hLv, currentSel, 0,
                                  LVIS_SELECTED | LVIS_FOCUSED);
        }
        if (desiredRow >= 0) {
            UINT flags = forceRepaint ? (LVIS_SELECTED | LVIS_FOCUSED)
                                      : LVIS_SELECTED;
            ListView_SetItemState(hLv, desiredRow, flags,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            if (forceRepaint) {
                ListView_EnsureVisible(hLv, desiredRow, FALSE);
            }
        }
    }
}

void OnGetDispInfo(HWND /*hLv*/, NMLVDISPINFOW* p) {
    auto& app = App::Instance();
    const auto& filtered = app.FilteredIndex();
    const int row = p->item.iItem;
    if (row < 0 || row >= static_cast<int>(filtered.size())) {
        if (p->item.mask & LVIF_TEXT) p->item.pszText = const_cast<LPWSTR>(L"");
        return;
    }
    const int hostIdx = filtered[row];
    const HostRow& h = app.Hosts()[hostIdx];

    if (p->item.mask & LVIF_TEXT) {
        switch (p->item.iSubItem) {
            case COL_IP:         p->item.pszText = const_cast<LPWSTR>(h.ip.c_str()); break;
            case COL_MAC:        p->item.pszText = const_cast<LPWSTR>(h.mac.c_str()); break;
            case COL_STATUS:     p->item.pszText = const_cast<LPWSTR>(L"");          break;  // custom
            case COL_HOSTNAME:   p->item.pszText = const_cast<LPWSTR>(h.hostname.c_str()); break;
            case COL_DEVICE:     p->item.pszText = const_cast<LPWSTR>(h.deviceType.c_str()); break;
            case COL_MODEL:      p->item.pszText = const_cast<LPWSTR>(h.deviceModel.c_str()); break;
            case COL_VENDOR:     p->item.pszText = const_cast<LPWSTR>(h.vendor.c_str()); break;
            case COL_OPEN_PORTS: p->item.pszText = const_cast<LPWSTR>(h.openPorts.c_str()); break;
            case COL_SERVICES:   p->item.pszText = const_cast<LPWSTR>(L""); break;  // custom
            case COL_RTT: {
                static thread_local wchar_t buf[16];
                if (h.isOnline) {
                    wsprintfW(buf, L"%d ms", h.responseMs);
                    p->item.pszText = buf;
                } else {
                    p->item.pszText = const_cast<LPWSTR>(L"");
                }
                break;
            }
            default: p->item.pszText = const_cast<LPWSTR>(L""); break;
        }
    }
}

LRESULT OnCustomDraw(HWND hLv, NMLVCUSTOMDRAW* p) {
    switch (p->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
            return CDRF_NOTIFYITEMDRAW;

        case CDDS_ITEMPREPAINT: {
            const int row = static_cast<int>(p->nmcd.dwItemSpec);

            // Don't trust the listview's CDIS_SELECTED bit. In virtual
            // mode (LVS_OWNERDATA), after rebuilding the data set every
            // tick during a live scan, the listview's internal selection
            // state ends up sticking on multiple rows even though only
            // one host is actually selected. Cross-check against App's
            // tracked SelectedIndex (set by LVN_ITEMCHANGED) so only the
            // genuinely-selected host gets the blue tint.
            const auto& filtered = App::Instance().FilteredIndex();
            const int selectedHostIdx = App::Instance().SelectedIndex();
            bool sel = false;
            if (selectedHostIdx >= 0
                && row >= 0 && row < static_cast<int>(filtered.size())) {
                sel = (filtered[row] == selectedHostIdx);
            }

            // v1.3.2 — tint the text colour of rows that have security
            // findings, so a /24 scrolling past the operator visually
            // surfaces the risky hosts even before they click a row.
            // Font colour ONLY (no background fill, no row stripe) per
            // user preference: keeps the grid calm.
            //   Critical  → red    (red-600)
            //   High      → orange (orange-600)
            //   Medium    → amber  (amber-600)
            //   Low / no findings → default TextPrimary
            // Selection takes precedence — a selected row keeps the
            // normal selection colour pair so red-on-light-blue
            // doesn't read as a contrast accident.
            COLORREF rowText = theme::Get(theme::Color::TextPrimary);
            if (!sel && row >= 0
                && row < static_cast<int>(filtered.size())) {
                const HostRow& h = App::Instance().Hosts()[filtered[row]];
                FindingSeverity worst = FindingSeverity::Low;
                bool any = false;
                for (const auto& f : h.findings) {
                    if (!any || static_cast<int>(f.severity)
                                  < static_cast<int>(worst)) {
                        worst = f.severity;
                    }
                    any = true;
                    if (worst == FindingSeverity::Critical) break;  // already at max
                }
                if (any) {
                    switch (worst) {
                        case FindingSeverity::Critical:
                            rowText = RGB(0xDC, 0x26, 0x26); break;  // red-600
                        case FindingSeverity::High:
                            rowText = RGB(0xEA, 0x58, 0x0C); break;  // orange-600
                        case FindingSeverity::Medium:
                            rowText = RGB(0xD9, 0x77, 0x06); break;  // amber-600
                        case FindingSeverity::Low:
                            break;  // keep default
                    }
                }
            }

            if (sel) {
                p->clrTextBk = theme::Get(theme::Color::SelectionBg);
                p->clrText   = theme::Get(theme::Color::TextPrimary);
            } else {
                p->clrTextBk = theme::Get(theme::Color::Surface);
                p->clrText   = rowText;
            }
            return CDRF_NEWFONT | CDRF_NOTIFYSUBITEMDRAW;
        }

        case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
            const int row = static_cast<int>(p->nmcd.dwItemSpec);
            const int col = p->iSubItem;

            if (col != COL_STATUS && col != COL_SERVICES) {
                return CDRF_DODEFAULT;
            }

            const auto& filtered = App::Instance().FilteredIndex();
            if (row < 0 || row >= static_cast<int>(filtered.size())) {
                return CDRF_DODEFAULT;
            }
            const HostRow& h = App::Instance().Hosts()[filtered[row]];

            RECT rcSub{};
            ListView_GetSubItemRect(hLv, row, col, LVIR_BOUNDS, &rcSub);

            // Fill the cell with the row background (matches what ListView
            // would have drawn). Without this we'd see the default white.
            FillRgnRect(p->nmcd.hdc, rcSub, p->clrTextBk);

            if (col == COL_STATUS) {
                PaintStatusCell(p->nmcd.hdc, rcSub, h);
            } else {
                PaintServicesCell(p->nmcd.hdc, rcSub, h);
            }
            return CDRF_SKIPDEFAULT;
        }
    }
    return CDRF_DODEFAULT;
}

}  // namespace nl::HostTable
