#include "MainWindow.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cstdio>
#include <string>
#include <vector>

#include "../Resource.h"
#include "App.h"
#include "Capture.h"
#include "Dpi.h"
#include "Models.h"
#include "Theme.h"
#include "Controls/DetailsPanel.h"
#include "Controls/HostTable.h"
#include "Controls/StatCard.h"
#include "Dialogs/AboutDialog.h"
#include "Dialogs/AdaptersDialog.h"
#include "Dialogs/PortListsDialog.h"
#include "Dialogs/SettingsDialog.h"

namespace nl {

namespace {

// Single source of truth for the details-pane minimum width (px @96 dpi).
// Used by BOTH the layout clamp in Compute() and the splitter-drag clamp, so
// they can't disagree (they previously used 280 and 390 respectively, which
// let a window-resize after a drag snap the panel to a different width).
constexpr int kDetailsMinDip = 360;

// ---------------------------------------------------------------------------
// Per-instance state — heap-allocated, pointer stashed in GWLP_USERDATA.
// ---------------------------------------------------------------------------
struct State {
    HWND  hwnd = nullptr;
    HMENU menu = nullptr;

    HWND  rangeEdit       = nullptr;
    HWND  adapterBtn      = nullptr;
    HWND  presetCombo     = nullptr;
    HWND  customPortsEdit = nullptr;
    HWND  startBtn        = nullptr;
    HWND  clearBtn        = nullptr;
    HWND  exportCsvBtn    = nullptr;
    HWND  exportHtmlBtn   = nullptr;
    HWND  settingsBtn     = nullptr;
    HWND  aboutBtn        = nullptr;

    HWND  kpiCards[4]     = {};

    HWND  filterCombo     = nullptr;
    HWND  searchEdit      = nullptr;
    HWND  viewOfflineChk  = nullptr;
    HWND  severityCombo   = nullptr;   // v1.3.3 — CVE / EOL severity filter

    HWND  hostTable       = nullptr;
    HWND  detailsPanel    = nullptr;
    // The bottom progress bar is custom-painted in PaintStatusBar (cleaner
    // look than msctls_progress32's chunky block), so no HWND is needed.

    enum class PillState { Ready, Scanning, Cancelling, Done, Cancelled, Error };
    PillState     pillState        = PillState::Ready;
    std::wstring  pillText         = L"Ready";
    UINT          currentTimerMs   = 800;
    bool          userCancelled    = false;
    bool          lastStartFailed  = false;
    int           idleTicks        = 0;
    // TIME LEFT card update throttle. Snapshots arrive at 100 ms cadence
    // but the ETA value is volatile (rate fluctuates as the engine
    // transitions phases); updating the displayed value every 500 ms
    // keeps it readable without sacrificing grid live-update speed.
    int64_t       lastEtaUpdateMs  = 0;
    // Percent at the moment user hit Cancel. -1 = not cancelled. Shown
    // on the pill as "Cancelled · 42%" so the user knows where they
    // stopped.
    int           cancelledAtPct   = -1;
    // Idempotency guard for SyncToolbarMode — without it the
    // SetWindowText / EnableWindow / InvalidateRect chain runs every
    // 100 ms snapshot tick and the resulting 8+ control repaints show
    // up as visible UI hitching at scan end.
    int           toolbarModeCache = -1;   // -1 = uninitialised
    std::wstring  lastPillTextCache;

    HWND          hSplitter        = nullptr;
    HWND          hTooltip         = nullptr;
    int           detailsWidthDip  = 460;   // px@96 — user can drag the splitter (v1.5.1: +70 for richer fingerprint sections)

    // Ctrl+T full-UI-sweep state. -1 = idle; 0..3 = which dialog index
    // the sweep is currently opening.
    int           captureSeqIdx      = -1;
};

State* GetState(HWND h) {
    return reinterpret_cast<State*>(GetWindowLongPtrW(h, GWLP_USERDATA));
}

// ---------------------------------------------------------------------------
// Layout — all metrics in px@96, scaled at use.
// ---------------------------------------------------------------------------
struct Layout {
    int W = 0, H = 0;
    int padL = 0, padR = 0;

    // Y bands
    int brandY = 0,  brandH = 0;
    int toolY = 0,   toolH = 0;
    int kpiY = 0,    kpiH = 0;
    int filterY = 0, filterH = 0;
    int gridY = 0,   gridH = 0;
    int statusY = 0, statusH = 0;

    // Right column
    bool detailsVisible = true;
    int  detailsW = 0;
    int  splitX = 0;
    int  detailsX = 0;
    int  leftRightX = 0;     // right edge of column-0 content

    // True when the toolbar can't fit on a single row at the current
    // width; layout falls back to two rows (range/adapter/preset on row
    // 1, start/clear/exports on row 2).
    bool wrapToolbar = false;

    // Y of the first toolbar row. Stored on Layout so PaintToolbar can
    // drop the "RANGE" label there instead of vertically centering it
    // in the (possibly tall) toolbar band — when the bar wraps to two
    // rows, V-centering would put the label between rows where it gets
    // clipped by the wrapped buttons.
    int  toolRow1Y = 0;
};

Layout Compute(int cx, int cy, int detailsWidthScaled, bool detailsVisible) {
    Layout L{};
    L.W = cx; L.H = cy;
    L.padL = dpi::Scale(18);
    L.padR = dpi::Scale(18);

    L.brandH  = dpi::Scale(56);
    L.toolH   = dpi::Scale(58);
    L.kpiH    = dpi::Scale(102);   // room for label + value + secondary line
    L.filterH = dpi::Scale(44);
    L.statusH = dpi::Scale(28);

    L.brandY  = 0;
    L.toolY   = L.brandY + L.brandH;
    L.kpiY    = L.toolY + L.toolH;
    L.filterY = L.kpiY + L.kpiH;
    L.gridY   = L.filterY + L.filterH;
    L.statusY = cy - L.statusH;
    L.gridH   = (L.statusY > L.gridY) ? (L.statusY - L.gridY) : 0;

    L.detailsVisible = detailsVisible;
    if (detailsVisible) {
        int dw = detailsWidthScaled;
        const int minDw = dpi::Scale(kDetailsMinDip);
        const int minTable = dpi::Scale(700);
        const int maxDw = cx - L.padR - minTable - dpi::Scale(6) - L.padL;
        if (dw < minDw) dw = minDw;
        if (dw > maxDw && maxDw > minDw) dw = maxDw;
        if (dw > cx / 2) dw = cx / 2;
        L.detailsW   = dw;
        L.detailsX   = cx - dw - L.padR;
        L.splitX     = L.detailsX - dpi::Scale(6);
        L.leftRightX = L.splitX - dpi::Scale(6);
    } else {
        L.detailsW = 0;
        L.detailsX = cx;
        L.splitX   = cx;
        L.leftRightX = cx;
    }

    // Does the toolbar fit on one row? If not, reserve room for 2 rows.
    // The threshold MUST include a generous safety gap so the right-
    // anchored action buttons never collide with the left flow (and
    // never extend past leftRightX into the splitter / details area).
    const bool customVisible =
        (App::Instance().CurrentPreset() == ScanPreset::CustomPorts);
    const int leftFlowPx96  = 18 + 50 + 240 + 8 + 86 + 8 + 170 + 8
                            + (customVisible ? (190 + 8) : 0);
    const int rightActPx96  = 110 + 6 + 70 + 6 + 110 + 6 + 110;
    const int safetyGapPx96 = 32;
    const int oneRowMinPx96 = leftFlowPx96 + safetyGapPx96 + rightActPx96 + 18;
    L.wrapToolbar = (L.leftRightX < dpi::Scale(oneRowMinPx96));
    if (L.wrapToolbar) {
        L.toolH = dpi::Scale(98);
        // Re-derive y positions that depend on toolH.
        L.kpiY    = L.toolY + L.toolH;
        L.filterY = L.kpiY + L.kpiH;
        L.gridY   = L.filterY + L.filterH;
        L.gridH   = (L.statusY > L.gridY) ? (L.statusY - L.gridY) : 0;
    }
    L.toolRow1Y = L.wrapToolbar
        ? (L.toolY + dpi::Scale(8))
        : (L.toolY + (L.toolH - dpi::Scale(30)) / 2);
    return L;
}

// ---------------------------------------------------------------------------
// Splitter child window.
//
// 6 px vertical bar between the host table and the details panel. While the
// mouse is captured, posts WM_NETLENS_SPLIT_DRAG to its parent with the new
// client-x of the splitter — the parent recomputes detailsWidthDip and re-lays
// the world out.
// ---------------------------------------------------------------------------
constexpr UINT WM_NETLENS_SPLIT_DRAG = WM_APP + 1;

LRESULT CALLBACK SplitterProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_SETCURSOR:
            SetCursor(LoadCursorW(nullptr, IDC_SIZEWE));
            return TRUE;
        case WM_LBUTTONDOWN:
            SetCapture(hwnd);
            return 0;
        case WM_LBUTTONUP:
            if (GetCapture() == hwnd) ReleaseCapture();
            return 0;
        case WM_MOUSEMOVE:
            if (GetCapture() == hwnd) {
                POINT pt; GetCursorPos(&pt);
                ScreenToClient(GetParent(hwnd), &pt);
                SendMessageW(GetParent(hwnd), WM_NETLENS_SPLIT_DRAG,
                             static_cast<WPARAM>(pt.x), 0);
            }
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc; GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, theme::Brush(theme::Color::Bg));

            // M5 — 3-dot grip glyph, vertically centred. Makes the splitter
            // read as something draggable.
            int cx = (rc.right - rc.left) / 2;
            int cy = (rc.bottom - rc.top) / 2;
            int dotR    = dpi::Scale(1);
            int spacing = dpi::Scale(5);
            HBRUSH brDot = CreateSolidBrush(theme::Get(theme::Color::TextMuted));
            HBRUSH obr   = static_cast<HBRUSH>(SelectObject(hdc, brDot));
            HPEN   opn   = static_cast<HPEN>(SelectObject(hdc, GetStockObject(NULL_PEN)));
            for (int i = -1; i <= 1; ++i) {
                int y = cy + i * spacing;
                Ellipse(hdc, cx - dotR, y - dotR, cx + dotR + 1, y + dotR + 1);
            }
            SelectObject(hdc, obr);
            SelectObject(hdc, opn);
            DeleteObject(brDot);

            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void RegisterSplitterClass(HINSTANCE hi) {
    static bool reg = false;
    if (reg) return;
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = SplitterProc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursorW(nullptr, IDC_SIZEWE);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"NetLensSplitter";
    RegisterClassExW(&wc);
    reg = true;
}

// ---------------------------------------------------------------------------
// Owner-draw flat button helper + hover-state subclass.
// ---------------------------------------------------------------------------
enum class BtnKind { Primary, Secondary, Danger };  // Danger = red (Cancel during scan)

constexpr const wchar_t* kHoverProp = L"NL_HOVER";

LRESULT CALLBACK ButtonHoverSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp,
                                     UINT_PTR id, DWORD_PTR /*ref*/) {
    switch (msg) {
        case WM_MOUSEMOVE: {
            if (!GetProp(h, kHoverProp)) {
                SetProp(h, kHoverProp, reinterpret_cast<HANDLE>(static_cast<DWORD_PTR>(1)));
                TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
                TrackMouseEvent(&tme);
                InvalidateRect(h, nullptr, FALSE);
            }
            break;
        }
        case WM_MOUSELEAVE: {
            RemoveProp(h, kHoverProp);
            InvalidateRect(h, nullptr, FALSE);
            break;
        }
        case WM_NCDESTROY:
            RemoveProp(h, kHoverProp);
            RemoveWindowSubclass(h, ButtonHoverSubclass, id);
            break;
    }
    return DefSubclassProc(h, msg, wp, lp);
}

void AttachHover(HWND button) {
    if (button) SetWindowSubclass(button, ButtonHoverSubclass, 1, 0);
}

// Visual vertical-centering for single-line EDIT controls.
//
// Win32 single-line EDIT controls force the formatting rectangle to match
// the client area (EM_SETRECT is a no-op for them), so we can't shift the
// text down with that API. Instead the caller sizes the EDIT window
// shorter than the surrounding toolbar row and positions it vertically
// centered within the row — the EDIT then naturally renders its
// (top-aligned) single line near the visual middle.
//
// The helper below computes the natural "compact" height a single-line
// EDIT wants given its active font, so the toolbar layout code can place
// each edit at row-Y + (rowH - compactH) / 2 with that compactH.
int EditCompactHeight(HWND edit) {
    HFONT f = reinterpret_cast<HFONT>(SendMessageW(edit, WM_GETFONT, 0, 0));
    HDC dc = GetDC(edit);
    HFONT old = f ? static_cast<HFONT>(SelectObject(dc, f)) : nullptr;
    TEXTMETRICW tm{};
    GetTextMetricsW(dc, &tm);
    if (old) SelectObject(dc, old);
    ReleaseDC(edit, dc);
    // Font height + a small breathing room for the descenders + the
    // CLIENTEDGE 2-px frame on each side. ~22 px for our regular font.
    return tm.tmHeight + dpi::Scale(4) + 2 * 2;
}

void PaintFlatButton(const DRAWITEMSTRUCT& dis, BtnKind kind) {
    const bool pressed  = (dis.itemState & ODS_SELECTED) != 0;
    const bool disabled = (dis.itemState & ODS_DISABLED) != 0;
    const bool focused  = (dis.itemState & ODS_FOCUS) != 0;
    const bool hovered  = GetProp(dis.hwndItem, kHoverProp) != nullptr;

    HDC hdc = dis.hDC;
    RECT rc = dis.rcItem;

    COLORREF fill, border, text;
    if (kind == BtnKind::Primary) {
        fill   = pressed ? theme::Get(theme::Color::AccentHover)
               : hovered ? theme::Get(theme::Color::AccentHover)
                         : theme::Get(theme::Color::Accent);
        border = fill;
        text   = theme::Get(theme::Color::TextInverse);
    } else if (kind == BtnKind::Danger) {
        // Solid red for the Cancel state of the Start button. Slightly
        // darker on hover/press so the affordance still reads.
        const COLORREF red       = RGB(0xDC, 0x35, 0x45);
        const COLORREF redHover  = RGB(0xC8, 0x2A, 0x39);
        fill   = (pressed || hovered) ? redHover : red;
        border = fill;
        text   = theme::Get(theme::Color::TextInverse);
    } else {
        fill   = pressed ? theme::Get(theme::Color::Hover)
               : hovered ? theme::Get(theme::Color::Hover)
                         : theme::Get(theme::Color::Surface);
        border = hovered ? theme::Get(theme::Color::Accent)
                         : theme::Get(theme::Color::Border);
        text   = theme::Get(theme::Color::TextPrimary);
    }
    if (disabled) {
        // On the Danger (red) kind, the default TextMuted gray gets lost
        // against the red fill (the "Cancelling…" caption goes invisible).
        // A soft pink-tinted white keeps the label readable while still
        // signalling "disabled".
        text = (kind == BtnKind::Danger)
             ? RGB(0xFF, 0xCD, 0xD4)
             : theme::Get(theme::Color::TextMuted);
    }

    HBRUSH brF = CreateSolidBrush(fill);
    FillRect(hdc, &rc, brF);
    DeleteObject(brF);

    HPEN penB = CreatePen(PS_SOLID, 1, border);
    HPEN oldP = static_cast<HPEN>(SelectObject(hdc, penB));
    HBRUSH oldB = static_cast<HBRUSH>(SelectObject(hdc, GetStockObject(NULL_BRUSH)));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, oldB);
    SelectObject(hdc, oldP);
    DeleteObject(penB);

    wchar_t buf[96]; buf[0] = 0;
    GetWindowTextW(dis.hwndItem, buf, 96);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text);

    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    DrawTextW(hdc, buf, -1, &rc,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);

    if (focused) {
        RECT rcF = rc;
        InflateRect(&rcF, -dpi::Scale(2), -dpi::Scale(2));
        DrawFocusRect(hdc, &rcF);
    }
}

BtnKind KindForButton(int ctlId, HWND hWnd = nullptr) {
    // The Start button morphs into a red Cancel button while a scan is
    // in flight. Derive the kind from the BUTTON's visible text (set by
    // SyncToolbarMode), not from App::IsScanning(): the text flips
    // instantly on Cancel-click, but engine workers take up to timeoutMs
    // to actually unwind, so IsScanning() lags. Driving from text
    // matches the UI exactly.
    if (ctlId == IDC_START_BTN && hWnd) {
        wchar_t buf[32]{};
        GetWindowTextW(hWnd, buf, 32);
        // Both "Cancel" (active) and "Cancelling…" (mid-cancel disabled) are
        // the same red Danger kind so the morph stays visually consistent.
        if (wcscmp(buf, L"Cancel") == 0)        return BtnKind::Danger;
        if (wcscmp(buf, L"Cancelling\x2026") == 0) return BtnKind::Danger;
        return BtnKind::Primary;
    }
    return BtnKind::Secondary;
}

// ---------------------------------------------------------------------------
// Brand bar paint
// ---------------------------------------------------------------------------
void PaintLogo(HDC hdc, int x, int y, int size) {
    // Render the real IDI_NETLENS icon so the brand bar mark matches
    // the title-bar / taskbar / About-hero icon exactly. Loading at
    // the target size lets LoadImage pick the best-fitting frame from
    // the multi-resolution .ico, then DrawIconEx blits it 1:1.
    HICON hIco = static_cast<HICON>(LoadImageW(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_NETLENS),
        IMAGE_ICON, size, size, LR_DEFAULTCOLOR));
    if (hIco) {
        DrawIconEx(hdc, x, y, hIco, size, size, 0, nullptr, DI_NORMAL);
        DestroyIcon(hIco);
    }
}

void PaintStatusPill(HDC hdc, int x, int y,
                     State::PillState ps, const std::wstring& text) {
    using PS = State::PillState;

    COLORREF cFill, cBorder, cDot, cText;
    switch (ps) {
        case PS::Scanning:
            cFill = theme::Get(theme::Color::AccentSurface);
            cBorder = cDot = cText = theme::Get(theme::Color::Accent);
            break;
        case PS::Done:
            cFill = theme::Get(theme::Color::SuccessSurface);
            cBorder = cDot = cText = theme::Get(theme::Color::Success);
            break;
        case PS::Cancelling:
            // Solid amber fill with white text + dot so the pill stands
            // out at a glance ("something is actively happening") instead
            // of blending into the surface. The "Cancelling…" text
            // differentiates from the terminal "Cancelled · X%" state.
            cFill   = theme::Get(theme::Color::Warning);
            cBorder = theme::Get(theme::Color::Warning);
            cDot    = RGB(0xFF, 0xFF, 0xFF);
            cText   = RGB(0xFF, 0xFF, 0xFF);
            break;
        case PS::Cancelled:
            cFill = theme::Get(theme::Color::WarningSurface);
            cBorder = cDot = cText = theme::Get(theme::Color::Warning);
            break;
        case PS::Error:
            cFill = theme::Get(theme::Color::DangerSurface);
            cBorder = cDot = cText = theme::Get(theme::Color::Danger);
            break;
        case PS::Ready:
        default:
            cFill   = theme::Get(theme::Color::AccentSurface);
            cBorder = theme::Get(theme::Color::Accent);
            cDot    = theme::Get(theme::Color::Success);
            cText   = theme::Get(theme::Color::Accent);
            break;
    }

    HFONT f = theme::Fonts().semibold;
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, f));

    const wchar_t* str = text.empty() ? L"Ready" : text.c_str();
    SIZE sz{};
    GetTextExtentPoint32W(hdc, str, lstrlenW(str), &sz);

    int dotR  = dpi::Scale(4);
    int padL  = dpi::Scale(12);
    int padR  = dpi::Scale(12);
    int gap   = dpi::Scale(8);
    int innerH = dpi::Scale(24);
    int w = padL + dotR * 2 + gap + sz.cx + padR;

    RECT rc = { x, y, x + w, y + innerH };
    int radius = dpi::Scale(7) * 2;

    HBRUSH brFill = CreateSolidBrush(cFill);
    HPEN   penB   = CreatePen(PS_SOLID, 1, cBorder);
    HBRUSH ob = static_cast<HBRUSH>(SelectObject(hdc, brFill));
    HPEN   op = static_cast<HPEN>(SelectObject(hdc, penB));
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brFill);
    DeleteObject(penB);

    int dotCx = rc.left + padL + dotR;
    int dotCy = (rc.top + rc.bottom) / 2;
    HBRUSH brDot = CreateSolidBrush(cDot);
    ob = static_cast<HBRUSH>(SelectObject(hdc, brDot));
    op = static_cast<HPEN>(SelectObject(hdc, GetStockObject(NULL_PEN)));
    Ellipse(hdc, dotCx - dotR, dotCy - dotR, dotCx + dotR, dotCy + dotR);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brDot);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, cText);
    RECT rcText = { dotCx + dotR + gap, rc.top, rc.right - padR, rc.bottom };
    DrawTextW(hdc, str, -1, &rcText,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, oldF);
}

void PaintBrandBar(HDC hdc, const Layout& L, const State& st) {
    RECT rc = { 0, L.brandY, L.leftRightX, L.brandY + L.brandH };
    FillRect(hdc, &rc, theme::Brush(theme::Color::Surface));

    // Bottom 1-px border
    HPEN penB = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HPEN oldP = static_cast<HPEN>(SelectObject(hdc, penB));
    MoveToEx(hdc, rc.left, rc.bottom - 1, nullptr);
    LineTo  (hdc, rc.right, rc.bottom - 1);
    SelectObject(hdc, oldP);
    DeleteObject(penB);

    // Logo + wordmark
    int logoSize = dpi::Scale(32);
    int logoX = L.padL;
    int logoY = rc.top + (L.brandH - logoSize) / 2;
    PaintLogo(hdc, logoX, logoY, logoSize);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, theme::Get(theme::Color::TextPrimary));
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().brand));
    RECT rcName = { logoX + logoSize + dpi::Scale(12),
                    rc.top, rc.right, rc.bottom };
    DrawTextW(hdc, L"NetLens", -1, &rcName,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);

    // Status pill — placed to the right of the wordmark
    int pillX = logoX + logoSize + dpi::Scale(12 + 80);
    int pillY = rc.top + (L.brandH - dpi::Scale(24)) / 2;
    PaintStatusPill(hdc, pillX, pillY, st.pillState, st.pillText);
}

void PaintLabel(HDC hdc, int x, int y, int w, int h, const wchar_t* text,
                COLORREF color, HFONT font) {
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, color);
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, font));
    RECT rc = { x, y, x + w, y + h };
    DrawTextW(hdc, text, -1, &rc,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

void PaintToolbar(HDC hdc, const Layout& L) {
    RECT rc = { 0, L.toolY, L.leftRightX, L.toolY + L.toolH };
    FillRect(hdc, &rc, theme::Brush(theme::Color::Surface));

    HPEN penB = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HPEN oldP = static_cast<HPEN>(SelectObject(hdc, penB));
    MoveToEx(hdc, rc.left, rc.bottom - 1, nullptr);
    LineTo  (hdc, rc.right, rc.bottom - 1);
    SelectObject(hdc, oldP);
    DeleteObject(penB);

    // "RANGE" label — anchored to row 1 of the toolbar so it doesn't slip
    // into the gap between rows when the bar wraps (M5.9 fix).
    PaintLabel(hdc, L.padL, L.toolRow1Y, dpi::Scale(50), dpi::Scale(30),
               L"RANGE",
               theme::Get(theme::Color::TextMuted), theme::Fonts().label);
}

void PaintFilterBar(HDC hdc, const Layout& L) {
    RECT rc = { 0, L.filterY, L.leftRightX, L.filterY + L.filterH };
    FillRect(hdc, &rc, theme::Brush(theme::Color::Bg));

    // "Filter" label
    PaintLabel(hdc, L.padL, L.filterY, dpi::Scale(40), L.filterH, L"Filter",
               theme::Get(theme::Color::TextSecondary), theme::Fonts().regular);

    // "Search" label — positioned just before the search edit. Layout
    // arithmetic mirrors the SetWindowPos sequence in Create():
    //   padL + 40 (Filter label) + 0 (gap)
    //         + 150 (filter combo width)
    //         + 8   (gap to severity combo)
    //         + 160 (severity combo width — v1.3.3)
    //         + 16  (gap to Search label)
    int searchLabelX = L.padL + dpi::Scale(40 + 150 + 8 + 160 + 16);
    PaintLabel(hdc, searchLabelX, L.filterY, dpi::Scale(50), L.filterH, L"Search",
               theme::Get(theme::Color::TextSecondary), theme::Fonts().regular);

    // Result count chip — right-aligned within the column-0 area.
    // Hidden entirely at idle so we don't paint "0 of 0 hosts" before
    // any scan has run; appears as soon as the host list has any entry.
    auto& app = App::Instance();
    if (app.Hosts().empty()) return;
    wchar_t buf[64];
    wsprintfW(buf, L"%d of %d hosts",
              static_cast<int>(app.FilteredIndex().size()),
              static_cast<int>(app.Hosts().size()));

    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().smallBold));
    SIZE sz{};
    GetTextExtentPoint32W(hdc, buf, lstrlenW(buf), &sz);

    int chipW = sz.cx + dpi::Scale(20);
    int chipH = dpi::Scale(22);
    int chipX = L.leftRightX - L.padR - chipW;
    int chipY = L.filterY + (L.filterH - chipH) / 2;

    HBRUSH br = CreateSolidBrush(theme::Get(theme::Color::NeutralSurface));
    HPEN   pn = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HBRUSH ob = static_cast<HBRUSH>(SelectObject(hdc, br));
    HPEN   op = static_cast<HPEN>(SelectObject(hdc, pn));
    RoundRect(hdc, chipX, chipY, chipX + chipW, chipY + chipH,
              dpi::Scale(8), dpi::Scale(8));
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(br);
    DeleteObject(pn);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, theme::Get(theme::Color::TextSecondary));
    RECT chipRc = { chipX, chipY, chipX + chipW, chipY + chipH };
    DrawTextW(hdc, buf, -1, &chipRc,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, oldF);
}

void PaintKpiStripBg(HDC hdc, const Layout& L) {
    RECT rc = { 0, L.kpiY, L.leftRightX, L.kpiY + L.kpiH };
    FillRect(hdc, &rc, theme::Brush(theme::Color::Bg));
}

void PaintSplitter(HDC hdc, const Layout& L) {
    if (!L.detailsVisible) return;
    RECT rc = { L.leftRightX, 0, L.detailsX, L.statusY };
    FillRect(hdc, &rc, theme::Brush(theme::Color::Bg));
}

void PaintStatusBar(HDC hdc, const Layout& L, const State& s) {
    RECT rc = { 0, L.statusY, L.W, L.statusY + L.statusH };
    FillRect(hdc, &rc, theme::Brush(theme::Color::Surface));

    HPEN penB = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HPEN oldP = static_cast<HPEN>(SelectObject(hdc, penB));
    MoveToEx(hdc, rc.left, rc.top, nullptr);
    LineTo  (hdc, rc.right, rc.top);
    SelectObject(hdc, oldP);
    DeleteObject(penB);

    const auto& stats = App::Instance().Stats();
    SetBkMode(hdc, TRANSPARENT);

    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    SetTextColor(hdc, theme::Get(theme::Color::TextPrimary));
    RECT rcLabel = { dpi::Scale(14), L.statusY, dpi::Scale(280), L.statusY + L.statusH };
    // Mirror the pill text (which honors userCancelled correctly).
    // Falls back to engine statusText for things the pill doesn't drive.
    const wchar_t* text = !s.pillText.empty() ? s.pillText.c_str()
                        : (stats.statusText.empty() ? L"Ready"
                                                    : stats.statusText.c_str());
    DrawTextW(hdc, text, -1, &rcLabel,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    // Flat custom progress bar (replaces the chunky msctls_progress32).
    {
        const int progW = dpi::Scale(220);
        const int progH = dpi::Scale(6);
        const int progX = dpi::Scale(14 + 200 + 12);
        const int progY = L.statusY + (L.statusH - progH) / 2;

        // Track (rounded subtle gray).
        RECT trk = { progX, progY, progX + progW, progY + progH };
        HBRUSH brTrk = CreateSolidBrush(theme::Get(theme::Color::SurfaceAlt));
        FillRect(hdc, &trk, brTrk);
        DeleteObject(brTrk);

        // Fill (accent while running, success on completion). Probe-based
        // for consistency with pill + KPI + status text.
        double probeFrac = 0.0;
        if (stats.probesTotalEstimate > 0) {
            probeFrac = static_cast<double>(stats.probesDone)
                      / static_cast<double>(stats.probesTotalEstimate);
        } else if (stats.progressTotal > 0) {
            probeFrac = stats.progress01;
        }
        if (probeFrac > 1.0) probeFrac = 1.0;
        // A cancelled scan freezes the bar at the point the user
        // stopped (drawn from the frozen s.cancelledAtPct). The live
        // probesDone counter keeps advancing as workers wind down,
        // which would otherwise drag the bar past where the pill
        // claims the scan stopped.
        if (s.userCancelled && s.cancelledAtPct >= 0) {
            probeFrac = static_cast<double>(s.cancelledAtPct) / 100.0;
        } else if (!stats.isScanning && stats.totalScanned > 0) {
            // Clean completion → pin to full.
            probeFrac = 1.0;
        }
        int fillW = static_cast<int>(probeFrac * progW);
        if (fillW < 0) fillW = 0;
        if (fillW > progW) fillW = progW;
        if (fillW > 0) {
            COLORREF fc = stats.isScanning
                ? theme::Get(theme::Color::Accent)
                : theme::Get(theme::Color::Success);
            HBRUSH brFill = CreateSolidBrush(fc);
            RECT f = { progX, progY, progX + fillW, progY + progH };
            FillRect(hdc, &f, brFill);
            DeleteObject(brFill);
        }
    }

    // Right: "Local only · no telemetry"  +  "Built by 3389.ro"
    const wchar_t* tail1 = L"Local only \x2022 no telemetry";
    const wchar_t* tail2 = L"Built by 3389.ro";

    HFONT fSmall = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().smallFont));
    SIZE s1{}, s2{};
    GetTextExtentPoint32W(hdc, tail1, lstrlenW(tail1), &s1);
    GetTextExtentPoint32W(hdc, tail2, lstrlenW(tail2), &s2);

    int rightX = L.W - dpi::Scale(14);
    int yMid = L.statusY + L.statusH / 2;

    SetTextColor(hdc, theme::Get(theme::Color::Accent));
    SelectObject(hdc, theme::Fonts().smallBold);
    RECT r2 = { rightX - s2.cx, L.statusY, rightX, L.statusY + L.statusH };
    DrawTextW(hdc, tail2, -1, &r2,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, theme::Fonts().smallFont);
    SetTextColor(hdc, theme::Get(theme::Color::TextMuted));
    RECT r1 = { r2.left - dpi::Scale(16) - s1.cx, L.statusY,
                r2.left - dpi::Scale(16), L.statusY + L.statusH };
    DrawTextW(hdc, tail1, -1, &r1,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, oldF);
    SelectObject(hdc, fSmall);
    (void)yMid;
}

// ---------------------------------------------------------------------------
// Duration / Time-Left formatters. Note: wsprintfW does NOT support %lld —
// that was the source of the "0.d s" bug in M2. We use swprintf_s here.
// ---------------------------------------------------------------------------
void FormatDuration(long long ms, wchar_t* buf, size_t cap) {
    if (ms <= 0) {
        swprintf_s(buf, cap, L"0.0 s");
    } else if (ms < 60000) {
        long long secs   = ms / 1000;
        long long tenths = (ms % 1000) / 100;
        swprintf_s(buf, cap, L"%lld.%lld s", secs, tenths);
    } else {
        long long mins = ms / 60000;
        long long secs = (ms % 60000) / 1000;
        swprintf_s(buf, cap, L"%lld m %02lld s", mins, secs);
    }
}

void FormatTimeLeft(const ScanStats& stats, wchar_t* buf, size_t cap, bool& isCalculating) {
    isCalculating = false;
    if (!stats.isScanning) {
        if (stats.totalScanned > 0) { swprintf_s(buf, cap, L"Done"); }
        else                        { swprintf_s(buf, cap, L"Idle"); }
        return;
    }
    if (stats.progressTotal <= 0 || stats.probesTotalEstimate <= 0) {
        swprintf_s(buf, cap, L"Calculating\x2026");
        isCalculating = true;
        return;
    }

    // Exact seconds (1 decimal) instead of coarse buckets. The 5-second
    // sliding-window rate already smooths out tick-level jitter, so a
    // displayed `12.5 s` reads as a live countdown without the dishonesty
    // of "Less than a minute". For long remaining values we switch to
    // `Xm Y.Ys` to keep the line short. The numbers fluctuate as the
    // engine transitions from online-phase to offline-tail — that's the
    // truth, not a bug.
    const double  elapsed         = static_cast<double>(stats.durationMs);
    const int64_t remainingProbes = stats.probesTotalEstimate - stats.probesDone;

    double rate = stats.recentProbesPerSec;
    if (rate < 1.0 && elapsed >= 500.0) {
        // Fallback: cumulative rate when sliding window has < 2 samples
        // (first 400 ms of scan) or scan is so slow it's near zero.
        const double cumRate = static_cast<double>(stats.probesDone)
                             / (elapsed / 1000.0);
        if (cumRate > rate) rate = cumRate;
    }
    if (rate < 1.0 || remainingProbes <= 0) {
        swprintf_s(buf, cap, L"Calculating\x2026");
        isCalculating = true;
        return;
    }

    const double remaining_s = static_cast<double>(remainingProbes) / rate;

    // Under 3 min reads as pure seconds with one decimal ("147.3 s") —
    // denser than "2 m 27.3 s" and matches how short scans are tracked.
    // Switch to "Xm Y.Ys" / "Xh Ym" only when really long.
    if (remaining_s < 180.0) {
        // Under 3 min — one-decimal seconds reads as a live countdown.
        swprintf_s(buf, cap, L"%.1f s", remaining_s);
        return;
    }
    if (remaining_s < 3600.0) {
        // Over 3 min, drop the decimal — integer seconds are easier to
        // read at that range and match the "Xh Ym" cadence below.
        int mins = static_cast<int>(remaining_s / 60.0);
        int secs = static_cast<int>(remaining_s - mins * 60.0);
        swprintf_s(buf, cap, L"%d m %d s", mins, secs);
        return;
    }
    {
        int hours = static_cast<int>(remaining_s / 3600.0);
        int mins  = static_cast<int>((remaining_s - hours * 3600.0) / 60.0);
        swprintf_s(buf, cap, L"%d h %d m", hours, mins);
        return;
    }
}


// Compact human-readable formatter for the probes counter. Raw 58674 /
// 58674 reads as a wall of digits — on an AllPortsFast /24 the number
// is in the millions and the eye can't tell 12 845 290 from 12 854 290.
// Pretty-prints with K / M suffixes:
//   <    1 000   →  "123"
//   <   10 000   →  "1.5k"
//   <  100 000   →  "58.7k"
//   < 1 000 000  →  "234k"
//   <   10 mil   →  "1.5M"
//   ≥  10 mil    →  "16M"
void FormatCompactCount(long long n, wchar_t* buf, size_t cap) {
    if (n < 1000)         { swprintf_s(buf, cap, L"%lld", n); return; }
    const double dn = static_cast<double>(n);
    if (n < 10000)        { swprintf_s(buf, cap, L"%.1fk", dn / 1000.0); return; }
    if (n < 100000)       { swprintf_s(buf, cap, L"%.1fk", dn / 1000.0); return; }
    if (n < 1000000)      { swprintf_s(buf, cap, L"%.0fk", dn / 1000.0); return; }
    if (n < 10000000)     { swprintf_s(buf, cap, L"%.1fM", dn / 1000000.0); return; }
    swprintf_s(buf, cap, L"%.0fM", dn / 1000000.0);
}

// ---------------------------------------------------------------------------
// Population of KPI cards from the App's stats.
// ---------------------------------------------------------------------------
void UpdateKpiCards(State& s) {
    const auto& stats = App::Instance().Stats();
    wchar_t buf[64];

    // Card 0 — Online hosts.
    //
    // Mirrors the probes card's "count / total · rate" pattern, but for host
    // DISCOVERY rather than port probing. The big value stays the online
    // count (the headline the card is named for); the subtitle carries the
    // discovery context:
    //   - while scanning: "{done}/{total} scanned · {hosts/s}" — how far
    //     through the range, plus the live host-discovery rate. Distinct
    //     from card 1's probe-based % (on AllPorts presets discovery finishes
    //     long before the port sweep does).
    //   - when done:      "of {scanned} hosts · {pct}% up" — the online ratio.
    StatCard::SetLabel(s.kpiCards[0], L"ONLINE HOSTS");
    swprintf_s(buf, L"%d", stats.onlineCount);
    StatCard::SetValue(s.kpiCards[0], buf);
    StatCard::SetAccent(s.kpiCards[0], theme::Get(theme::Color::Success));
    {
        wchar_t sec[96];
        if (stats.isScanning && stats.progressTotal > 0) {
            // Host-discovery progress %. The total host count is known
            // EXACTLY from the parsed range (unlike the probe total, which
            // is an estimate), so this percentage is precise from the first
            // tick — a clean "how much of the range is left" indicator. On
            // AllPorts presets this races to 100 % within seconds while the
            // SCAN PROGRESS card's probe-based % is still climbing slowly.
            int pct = static_cast<int>(
                (long long)stats.progressDone * 100 / stats.progressTotal);
            if (pct > 100) pct = 100;
            wchar_t hTotal[24];
            FormatCompactCount(stats.progressTotal, hTotal, std::size(hTotal));
            if (stats.hasRecentRate && stats.recentHostsPerSec > 0.5) {
                wchar_t hRate[24];
                FormatCompactCount(
                    static_cast<long long>(stats.recentHostsPerSec + 0.5),
                    hRate, std::size(hRate));
                swprintf_s(sec, L"%d%% of %s \xb7 %s/s", pct, hTotal, hRate);
            } else {
                swprintf_s(sec, L"%d%% of %s hosts", pct, hTotal);
            }
            StatCard::SetSecondary(s.kpiCards[0], sec);
        } else if (stats.totalScanned > 0) {
            // Scan finished — show the share of scanned hosts that were up.
            const int upPct = static_cast<int>(
                (long long)stats.onlineCount * 100 / stats.totalScanned);
            swprintf_s(sec, L"%d%% online of %d", upPct, stats.totalScanned);
            StatCard::SetSecondary(s.kpiCards[0], sec);
        } else {
            StatCard::SetSecondary(s.kpiCards[0], L"");
        }
    }

    // Card 1 — Scan progress.
    //
    // Big "X%" value computed from probesDone / probesTotalEstimate, with
    // "X / Y probes" as the subtitle. Probe-based % is much smoother than
    // host fraction because probes accumulate continuously while host
    // completions arrive in bursty clumps (online phase slow, offline tail
    // fast).
    StatCard::SetLabel(s.kpiCards[1], L"SCAN PROGRESS");
    {
        int pct;
        if (s.userCancelled && s.cancelledAtPct >= 0) {
            // Freeze at the percent captured the moment Cancel was
            // hit. The engine's probesDone counter keeps advancing as
            // in-flight select() calls return during the ~400 ms
            // wind-down; without freezing, the card would creep
            // toward 100 % while the pill says "Cancelled · 4 %",
            // making the two displays disagree.
            pct = s.cancelledAtPct;
        } else {
            const long long pdone  = static_cast<long long>(stats.probesDone);
            const long long ptotal = std::max<long long>(stats.probesTotalEstimate, 1);
            pct = static_cast<int>(pdone * 100 / ptotal);
            if (pct < 0)   pct = 0;
            if (pct > 100) pct = 100;
            // Pin to 100 % once a CLEAN completion lands (engine not
            // running + results present) so the card doesn't sit at
            // 96-99 % on a finished scan.
            if (!stats.isScanning && stats.totalScanned > 0) pct = 100;
        }
        swprintf_s(buf, L"%d%%", pct);
        StatCard::SetValue(s.kpiCards[1], buf);
    }
    StatCard::SetAccent(s.kpiCards[1], theme::Get(theme::Color::Accent));
    {
        // Subtitle: "X / Y probes [· N/s]". Counts formatted compactly
        // ("58.7k / 58.7k", "1.5M / 16M") because raw decimal digits
        // become unreadable on AllPorts presets where the totals run
        // into the millions. Rate suffix only while scanning.
        wchar_t sec[96];
        wchar_t hDone[24], hTotal[24];
        FormatCompactCount(static_cast<long long>(stats.probesDone),
                           hDone,  std::size(hDone));
        FormatCompactCount(static_cast<long long>(stats.probesTotalEstimate),
                           hTotal, std::size(hTotal));
        if (stats.isScanning && stats.recentProbesPerSec > 1.0) {
            wchar_t hRate[24];
            FormatCompactCount(static_cast<long long>(stats.recentProbesPerSec),
                               hRate, std::size(hRate));
            swprintf_s(sec, L"%s / %s probes \xb7 %s/s",
                       hDone, hTotal, hRate);
        } else {
            swprintf_s(sec, L"%s / %s probes", hDone, hTotal);
        }
        StatCard::SetSecondary(s.kpiCards[1], sec);
    }

    // Card 2 — Duration
    StatCard::SetLabel(s.kpiCards[2], L"DURATION");
    FormatDuration(stats.durationMs, buf, std::size(buf));
    StatCard::SetValue(s.kpiCards[2], buf);
    StatCard::SetAccent(s.kpiCards[2], theme::Get(theme::Color::Info));
    StatCard::SetSecondary(s.kpiCards[2], L"");

    // Card 3 — Time left.
    //
    // The TIME LEFT text refreshes at ~500 ms while scanning. Snapshots
    // arrive every 100 ms (for grid liveness) and the ETA can fluctuate
    // ±2 s tick-to-tick as the rate moves around — at the 100 ms cadence
    // it reads as digit-jitter. 500 ms is fast enough to feel live but
    // slow enough to be legible. Transitions (scan start/stop, calculating
    // state change) flush immediately so "Done" lands without lag.
    StatCard::SetLabel(s.kpiCards[3], L"TIME LEFT");
    bool calculating = false;
    FormatTimeLeft(stats, buf, std::size(buf), calculating);
    // When the user cancelled, the card reads "Cancelled" instead of
    // "Done" so it matches the pill + status bar.
    if (s.userCancelled && !stats.isScanning) {
        swprintf_s(buf, std::size(buf), L"Cancelled");
    }

    const int64_t now_ms = static_cast<int64_t>(GetTickCount64());
    const bool throttle  = stats.isScanning && !calculating;
    const bool stale     = (now_ms - s.lastEtaUpdateMs) >= 500;
    if (!throttle || stale) {
        StatCard::SetValue(s.kpiCards[3], buf);
        s.lastEtaUpdateMs = now_ms;
    }

    COLORREF accent;
    if (s.userCancelled && !stats.isScanning)                  accent = theme::Get(theme::Color::Warning);      // Cancelled
    else if (!stats.isScanning && stats.totalScanned == 0)     accent = theme::Get(theme::Color::TextMuted);    // Idle
    else if (!stats.isScanning && stats.totalScanned > 0)      accent = theme::Get(theme::Color::Success);      // Done
    else if (calculating)                                      accent = theme::Get(theme::Color::TextMuted);    // Calculating
    else                                                       accent = theme::Get(theme::Color::Warning);      // ETA
    StatCard::SetAccent(s.kpiCards[3], accent);
    StatCard::SetSecondary(s.kpiCards[3], L"");
}

// Forward declarations — definitions below CreateChildControls.
HWND CreateTooltip(HWND owner, HINSTANCE hi);
void RegisterTooltip(HWND tip, HWND tool, const wchar_t* text);

// ---------------------------------------------------------------------------
// Window-creation helper: create all standard controls.
// ---------------------------------------------------------------------------
void CreateChildControls(State& s, HINSTANCE hInst) {
    HFONT f = theme::Fonts().regular;

    auto setFont = [&](HWND h) {
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), MAKELPARAM(TRUE, 0));
    };

    // -------- Brand bar buttons (right-aligned) --------
    s.settingsBtn = CreateWindowExW(0, L"BUTTON", L"Settings",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_OWNERDRAW,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_SETTINGS_BTN), hInst, nullptr);
    setFont(s.settingsBtn);
    s.aboutBtn = CreateWindowExW(0, L"BUTTON", L"About",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_OWNERDRAW,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_ABOUT_BTN), hInst, nullptr);
    setFont(s.aboutBtn);

    // -------- Toolbar --------
    // M5.16.1 — Left-aligned text restored on the edits (user clarified:
    // by "centered" they meant vertical top-bottom centering, not
    // horizontal). Vertical centering of EDIT text is achieved later by
    // sizing the EDIT slightly shorter than the toolbar row height and
    // positioning it centered in the row.
    s.rangeEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"192.168.1.1-192.168.1.254",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_RANGE_EDIT), hInst, nullptr);
    setFont(s.rangeEdit);

    s.adapterBtn = CreateWindowExW(0, L"BUTTON", L"Adapter",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_OWNERDRAW,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_ADAPTER_BTN), hInst, nullptr);
    setFont(s.adapterBtn);

    s.presetCombo = CreateWindowExW(0, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP
            | CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS
            | WS_VSCROLL,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_PRESET_COMBO), hInst, nullptr);
    setFont(s.presetCombo);
    // M5.16.1 — Owner-drawn combo so we control the vertical text placement
    // (DT_VCENTER in WM_DRAWITEM). The default CBS_DROPDOWNLIST renders the
    // selection text top-aligned, which makes the toolbar look uneven
    // against the owner-draw buttons. Selection-field item height matches
    // the window height (30 px) so DT_VCENTER inside the item rect lands
    // the text in the middle. Dropdown items use the same 30 px so the
    // popup feels touch-friendly.
    SendMessageW(s.presetCombo, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1),
                 static_cast<LPARAM>(dpi::Scale(30) - 4));   // selection field
    SendMessageW(s.presetCombo, CB_SETITEMHEIGHT, 0,
                 static_cast<LPARAM>(dpi::Scale(28)));        // dropdown items
    SendMessageW(s.presetCombo, CB_ADDSTRING, 0, (LPARAM)L"Quick LAN Scan");
    SendMessageW(s.presetCombo, CB_ADDSTRING, 0, (LPARAM)L"Standard");
    SendMessageW(s.presetCombo, CB_ADDSTRING, 0, (LPARAM)L"Full Common");
    SendMessageW(s.presetCombo, CB_ADDSTRING, 0, (LPARAM)L"All Ports (Fast)");
    SendMessageW(s.presetCombo, CB_ADDSTRING, 0, (LPARAM)L"All Ports (Deep)");
    SendMessageW(s.presetCombo, CB_ADDSTRING, 0, (LPARAM)L"Custom Ports");
    SendMessageW(s.presetCombo, CB_SETCURSEL, 2, 0);

    s.customPortsEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | ES_AUTOHSCROLL,    // hidden by default
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_CUSTOM_PORTS_EDIT), hInst, nullptr);
    setFont(s.customPortsEdit);
    // Grey placeholder so the expected format is obvious the moment the box
    // appears: a comma-separated list of individual ports and/or a-b ranges.
    SendMessageW(s.customPortsEdit, EM_SETCUEBANNER, TRUE,
                 reinterpret_cast<LPARAM>(L"e.g. 22,80,443,8000-8100"));

    s.startBtn = CreateWindowExW(0, L"BUTTON", L"Start scan",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_OWNERDRAW | BS_DEFPUSHBUTTON,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_START_BTN), hInst, nullptr);
    setFont(s.startBtn);
    s.clearBtn = CreateWindowExW(0, L"BUTTON", L"Clear",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_OWNERDRAW,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_CLEAR_BTN), hInst, nullptr);
    setFont(s.clearBtn);
    s.exportCsvBtn = CreateWindowExW(0, L"BUTTON", L"Export CSV",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_OWNERDRAW,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_EXPORT_CSV_BTN), hInst, nullptr);
    setFont(s.exportCsvBtn);
    s.exportHtmlBtn = CreateWindowExW(0, L"BUTTON", L"Export HTML",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_OWNERDRAW,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_EXPORT_HTML_BTN), hInst, nullptr);
    setFont(s.exportHtmlBtn);

    // -------- KPI cards --------
    for (int i = 0; i < 4; ++i) {
        s.kpiCards[i] = StatCard::Create(s.hwnd, hInst, IDC_KPI_ONLINE + i);
    }
    UpdateKpiCards(s);

    // -------- Filter row --------
    s.filterCombo = CreateWindowExW(0, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_FILTER_COMBO), hInst, nullptr);
    setFont(s.filterCombo);
    SendMessageW(s.filterCombo, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1),
                 static_cast<LPARAM>(dpi::Scale(22)));
    SendMessageW(s.filterCombo, CB_SETITEMHEIGHT, 0,
                 static_cast<LPARAM>(dpi::Scale(22)));
    SendMessageW(s.filterCombo, CB_ADDSTRING, 0, (LPARAM)L"All hosts");
    SendMessageW(s.filterCombo, CB_ADDSTRING, 0, (LPARAM)L"Online only");
    SendMessageW(s.filterCombo, CB_ADDSTRING, 0, (LPARAM)L"Has open ports");
    SendMessageW(s.filterCombo, CB_SETCURSEL, 0, 0);

    s.searchEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_SEARCH_EDIT), hInst, nullptr);
    setFont(s.searchEdit);
    SendMessageW(s.searchEdit, EM_SETCUEBANNER, TRUE,
                 reinterpret_cast<LPARAM>(L"IP, hostname, vendor, ports\x2026"));

    // v1.3.3 — Severity filter combo. Orthogonal to the main filter
    // combo above; this one gates rows by the worst-finding severity
    // produced by SecurityAdvisor. CBS_OWNERDRAWFIXED so dropdown
    // items can carry a colored dot matching the host-grid row tint
    // (Critical=red, High=orange, Medium=amber).
    s.severityCombo = CreateWindowExW(0, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP
        | CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS,
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_SEVERITY_COMBO), hInst, nullptr);
    setFont(s.severityCombo);
    SendMessageW(s.severityCombo, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1),
                 static_cast<LPARAM>(dpi::Scale(22)));
    SendMessageW(s.severityCombo, CB_SETITEMHEIGHT, 0,
                 static_cast<LPARAM>(dpi::Scale(22)));
    SendMessageW(s.severityCombo, CB_ADDSTRING, 0, (LPARAM)L"Risk: all");
    SendMessageW(s.severityCombo, CB_ADDSTRING, 0, (LPARAM)L"Risk: medium+");
    SendMessageW(s.severityCombo, CB_ADDSTRING, 0, (LPARAM)L"Risk: high+");
    SendMessageW(s.severityCombo, CB_ADDSTRING, 0, (LPARAM)L"Risk: critical only");
    SendMessageW(s.severityCombo, CB_SETCURSEL, 0, 0);

    // The offline-hosts toggle lives in the View menu now. The checkbox
    // HWND is still created (wired for back-compat) but never shown.
    s.viewOfflineChk = CreateWindowExW(0, L"BUTTON", L"View offline hosts",
        WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX,   // no WS_VISIBLE
        0, 0, 0, 0,
        s.hwnd, reinterpret_cast<HMENU>(IDC_VIEW_OFFLINE_CHK), hInst, nullptr);
    setFont(s.viewOfflineChk);

    // -------- Host table + splitter + details + progress --------
    s.hostTable    = HostTable::Create(s.hwnd, hInst, IDC_HOST_LISTVIEW);

    RegisterSplitterClass(hInst);
    s.hSplitter = CreateWindowExW(0, L"NetLensSplitter", L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, 0, 0, s.hwnd, nullptr, hInst, nullptr);

    s.detailsPanel = DetailsPanel::Create(s.hwnd, hInst, IDC_DETAILS_PANEL);
    DetailsPanel::SetHostIndex(s.detailsPanel, App::Instance().SelectedIndex());

    // (Progress bar is flat custom-painted in PaintStatusBar.)

    // Hover state — subclass each owner-draw button.
    AttachHover(s.settingsBtn);
    AttachHover(s.aboutBtn);
    AttachHover(s.adapterBtn);
    AttachHover(s.startBtn);
    AttachHover(s.clearBtn);
    AttachHover(s.exportCsvBtn);
    AttachHover(s.exportHtmlBtn);

    // Single-line EDIT vertical centering is done in DoLayout() by
    // sizing each edit to its compact font height and positioning it
    // centered within the toolbar row. See EditCompactHeight().

    // Tooltips for the owner-draw buttons.
    s.hTooltip = CreateTooltip(s.hwnd, hInst);
    if (s.hTooltip) {
        RegisterTooltip(s.hTooltip, s.startBtn,      L"Start scan  (F5)");
        RegisterTooltip(s.hTooltip, s.clearBtn,      L"Clear results  (Ctrl+L)");
        RegisterTooltip(s.hTooltip, s.exportCsvBtn,  L"Export CSV  (Ctrl+E)");
        RegisterTooltip(s.hTooltip, s.exportHtmlBtn, L"Export HTML  (Ctrl+H)");
        RegisterTooltip(s.hTooltip, s.settingsBtn,   L"Open settings");
        RegisterTooltip(s.hTooltip, s.aboutBtn,      L"About NetLens  (F1)");
        RegisterTooltip(s.hTooltip, s.adapterBtn,    L"Pick network adapter \x2192 fill range");
        RegisterTooltip(s.hTooltip, s.rangeEdit,     L"IPv4 range to scan. Examples: 192.168.1.0/24, 10.0.0.1-10.0.0.50");
        RegisterTooltip(s.hTooltip, s.searchEdit,    L"Filter the host table by IP, hostname, vendor, ports or service  (Ctrl+F)");
        RegisterTooltip(s.hTooltip, s.customPortsEdit, L"Custom ports to scan \x2014 comma-separated list and/or a-b ranges. Example: 22,80,443,3389,8000-8100");
    }

    // Initial focus
    SetFocus(s.hostTable);
}

// ---------------------------------------------------------------------------
// Tooltips for the owner-draw buttons. TTF_SUBCLASS lets the tooltip control
// handle mouse tracking on the tool windows without manual relay.
// ---------------------------------------------------------------------------
HWND CreateTooltip(HWND owner, HINSTANCE hi) {
    HWND tip = CreateWindowExW(WS_EX_TOPMOST,
        TOOLTIPS_CLASSW, nullptr,
        WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        owner, nullptr, hi, nullptr);
    if (!tip) return nullptr;
    SendMessageW(tip, TTM_SETMAXTIPWIDTH, 0, 360);
    return tip;
}

void RegisterTooltip(HWND tip, HWND tool, const wchar_t* text) {
    if (!tip || !tool) return;
    TOOLINFOW ti{};
    ti.cbSize   = sizeof(ti);
    ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
    ti.hwnd     = GetParent(tool);
    ti.uId      = reinterpret_cast<UINT_PTR>(tool);
    ti.lpszText = const_cast<LPWSTR>(text);
    SendMessageW(tip, TTM_ADDTOOL, 0, reinterpret_cast<LPARAM>(&ti));
}

void CreateAppMenu(HWND hwnd) {
    HMENU menu = CreateMenu();
    HMENU mFile = CreatePopupMenu();
    AppendMenuW(mFile, MF_STRING, IDM_FILE_START,        L"&Start scan\tF5");
    AppendMenuW(mFile, MF_STRING, IDM_FILE_CANCEL,       L"&Cancel scan\tEsc");
    AppendMenuW(mFile, MF_STRING, IDM_FILE_CLEAR,        L"C&lear results\tCtrl+L");
    AppendMenuW(mFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(mFile, MF_STRING, IDM_FILE_EXPORT_CSV,   L"Export &CSV\x2026\tCtrl+E");
    AppendMenuW(mFile, MF_STRING, IDM_FILE_EXPORT_HTML,  L"Export &HTML\x2026\tCtrl+H");
    AppendMenuW(mFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(mFile, MF_STRING, IDM_FILE_EXIT,         L"E&xit");

    // "View" menu owns the offline-hosts toggle (kept out of the filter
    // row to avoid clutter). Drawn with MF_CHECKED so the checkmark
    // mirrors App::ViewOffline().
    HMENU mView = CreatePopupMenu();
    AppendMenuW(mView, MF_STRING, IDM_VIEW_OFFLINE,
                L"Show &offline hosts");

    HMENU mTools = CreatePopupMenu();
    AppendMenuW(mTools, MF_STRING, IDM_TOOLS_SETTINGS,    L"&Settings\x2026");
    AppendMenuW(mTools, MF_STRING, IDM_TOOLS_ADAPTERS,    L"&Network adapters\x2026");
    AppendMenuW(mTools, MF_STRING, IDM_TOOLS_PORT_LISTS,  L"&Port lists\x2026");
    // "Take screenshot" is intentionally NOT in the visible menu — it's
    // an internal QA shortcut, not a feature we advertise. Ctrl+T still
    // works through the accelerator + IDM_TOOLS_CAPTURE handler.

    HMENU mHelp = CreatePopupMenu();
    AppendMenuW(mHelp, MF_STRING, IDM_HELP_ABOUT,         L"&About NetLens\x2026\tF1");
    AppendMenuW(mHelp, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(mHelp, MF_STRING, IDM_HELP_VISIT_3389,    L"Visit &3389.ro");

    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(mFile),  L"&File");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(mView),  L"&View");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(mTools), L"&Tools");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(mHelp),  L"&Help");

    SetMenu(hwnd, menu);
}

// ---------------------------------------------------------------------------
// Layout the standard controls inside the bands computed by Compute().
// ---------------------------------------------------------------------------
void DoLayout(State& s) {
    RECT rc; GetClientRect(s.hwnd, &rc);
    Layout L = Compute(rc.right, rc.bottom, dpi::Scale(s.detailsWidthDip), true);

    // ---- Brand bar right-aligned buttons ----
    {
        int btnH = dpi::Scale(28);
        int padR = dpi::Scale(18);            // match the toolbar padR
        int y    = L.brandY + (L.brandH - btnH) / 2;

        int wAbout    = dpi::Scale(86);       // bumped so "About" can't visually clip
        int wSettings = dpi::Scale(96);

        int xAbout    = L.leftRightX - padR - wAbout;
        int xSettings = xAbout - dpi::Scale(8) - wSettings;
        SetWindowPos(s.settingsBtn, nullptr, xSettings, y, wSettings, btnH,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        SetWindowPos(s.aboutBtn,    nullptr, xAbout,    y, wAbout,    btnH,
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }

    // ---- Toolbar row(s) ----
    {
        const int hRow   = dpi::Scale(30);
        const int gapBtn = dpi::Scale(8);

        const int wRange   = dpi::Scale(240);
        const int wAdapter = dpi::Scale(86);
        const int wPreset  = dpi::Scale(170);
        const int wCustom  = dpi::Scale(190);
        const int wStart   = dpi::Scale(110);
        const int wClear   = dpi::Scale(70);
        const int wExp     = dpi::Scale(110);

        const bool customVisible =
            (App::Instance().CurrentPreset() == ScanPreset::CustomPorts);

        int row1Y, row2Y;
        if (L.wrapToolbar) {
            row1Y = L.toolY + dpi::Scale(8);
            row2Y = L.toolY + dpi::Scale(8 + 32 + 8);
        } else {
            row1Y = row2Y = L.toolY + (L.toolH - hRow) / 2;
        }

        // Row 1 — RANGE label is painted by PaintToolbar; row1 starts after it.
        //
        // Single-line EDIT controls draw their text top-aligned and
        // ignore EM_SETRECT — to visually center it we size the EDIT
        // shorter than the 30-px row (~22 px tall, just font + CLIENTEDGE)
        // and offset its Y so the small EDIT sits centered in the row.
        // Owner-draw buttons + owner-draw combo render with DT_VCENTER
        // already, so they stay at full row height.
        const int hEdit = EditCompactHeight(s.rangeEdit);
        const int editYOffset = (hRow - hEdit) / 2;
        int x = L.padL + dpi::Scale(50);
        SetWindowPos(s.rangeEdit,   nullptr, x, row1Y + editYOffset,
                     wRange, hEdit, SWP_NOZORDER);
        x += wRange + gapBtn;
        SetWindowPos(s.adapterBtn,  nullptr, x, row1Y, wAdapter, hRow, SWP_NOZORDER);
        x += wAdapter + gapBtn;
        SetWindowPos(s.presetCombo, nullptr, x, row1Y, wPreset,  dpi::Scale(220), SWP_NOZORDER);
        x += wPreset + gapBtn;
        if (customVisible) {
            SetWindowPos(s.customPortsEdit, nullptr, x, row1Y + editYOffset,
                         wCustom, hEdit, SWP_NOZORDER);
            x += wCustom + gapBtn;
        } else {
            // Park hidden custom-ports edit off-screen so it doesn't leak.
            SetWindowPos(s.customPortsEdit, nullptr, -wCustom, row1Y + editYOffset,
                         wCustom, hEdit, SWP_NOZORDER);
        }

        // Action buttons (Start / Clear / Export CSV / Export HTML).
        int xActions;
        if (L.wrapToolbar) {
            // Second row: flow from the left padding.
            xActions = L.padL;
        } else {
            // One-row layout: anchored to the right of column 0.
            int totalActionsW = wStart + dpi::Scale(6) + wClear
                              + dpi::Scale(6) + wExp + dpi::Scale(6) + wExp;
            xActions = L.leftRightX - L.padR - totalActionsW;
            // Make sure we never overlap the left flow.
            if (xActions < x + dpi::Scale(10)) xActions = x + dpi::Scale(10);
        }

        SetWindowPos(s.startBtn,      nullptr, xActions, row2Y, wStart, hRow, SWP_NOZORDER);
        xActions += wStart + dpi::Scale(6);
        SetWindowPos(s.clearBtn,      nullptr, xActions, row2Y, wClear, hRow, SWP_NOZORDER);
        xActions += wClear + dpi::Scale(6);
        SetWindowPos(s.exportCsvBtn,  nullptr, xActions, row2Y, wExp,   hRow, SWP_NOZORDER);
        xActions += wExp + dpi::Scale(6);
        SetWindowPos(s.exportHtmlBtn, nullptr, xActions, row2Y, wExp,   hRow, SWP_NOZORDER);
    }

    // ---- KPI cards ----
    {
        int gap = dpi::Scale(10);
        int areaL = L.padL;
        int areaR = L.leftRightX - L.padR;
        int totalW = areaR - areaL;
        int cardW = (totalW - gap * 3) / 4;
        int cardH = L.kpiH - dpi::Scale(20);
        int y = L.kpiY + dpi::Scale(10);
        int x = areaL;
        for (int i = 0; i < 4; ++i) {
            SetWindowPos(s.kpiCards[i], nullptr, x, y, cardW, cardH, SWP_NOZORDER);
            x += cardW + gap;
        }
    }

    // ---- Filter row ----
    //
    // Just: Filter combo · Search edit · "X of Y hosts" chip (chip painted
    // by PaintFilterBar at the right edge). Search edit flexes to fill
    // the gap, with a minimum room reservation for the chip so it never
    // gets clipped at narrow widths. The offline-hosts toggle moved to
    // the View menu.
    {
        int y    = L.filterY + (L.filterH - dpi::Scale(28)) / 2;
        int h    = dpi::Scale(28);
        int x    = L.padL + dpi::Scale(40);   // after "Filter" label

        const int wFilter      = dpi::Scale(150);
        const int wSeverity    = dpi::Scale(160);   // v1.3.3 — risk filter combo
        const int chipReserve  = dpi::Scale(150);   // room for "999 of 9999 hosts" + padding
        const int wSearchMin   = dpi::Scale(180);

        SetWindowPos(s.filterCombo, nullptr, x, y, wFilter, dpi::Scale(200), SWP_NOZORDER);
        x += wFilter + dpi::Scale(8);

        // v1.3.3 — severity filter combo sits directly after the main
        // filter combo. No label; the items themselves say "Risk: ..."
        // and the colored dot conveys the option visually.
        SetWindowPos(s.severityCombo, nullptr, x, y, wSeverity, dpi::Scale(200), SWP_NOZORDER);
        x += wSeverity + dpi::Scale(16);

        // "Search" label painted at x..x+50 by PaintFilterBar
        x += dpi::Scale(50 + 6);

        int searchRight = L.leftRightX - L.padR - chipReserve;
        int wSearch = searchRight - x;
        if (wSearch < wSearchMin) wSearch = wSearchMin;
        // Same compact-EDIT trick as the toolbar row, vertically centering
        // the search text relative to the filter combo's caption.
        const int hSearchEdit = EditCompactHeight(s.searchEdit);
        const int ySearchEdit = L.filterY + (L.filterH - hSearchEdit) / 2;
        SetWindowPos(s.searchEdit, nullptr, x, ySearchEdit, wSearch, hSearchEdit,
                     SWP_NOZORDER);
    }

    // ---- Host table ----
    {
        int x = L.padL;
        int y = L.gridY + dpi::Scale(6);
        int w = L.leftRightX - L.padR - x;
        int h = L.gridH - dpi::Scale(10);
        if (w < 100) w = 100;
        if (h < 100) h = 100;
        SetWindowPos(s.hostTable, nullptr, x, y, w, h, SWP_NOZORDER);
        HostTable::AutoSizeColumns(s.hostTable);   // redistribute on every layout
    }

    // ---- Splitter ----
    {
        int splitW = dpi::Scale(6);
        int y = 0;
        int h = L.statusY;
        SetWindowPos(s.hSplitter, nullptr,
                     L.detailsX - splitW, y, splitW, h, SWP_NOZORDER);
    }

    // ---- Details panel ----
    {
        int x = L.detailsX;
        int y = dpi::Scale(10);
        int w = L.W - L.padR - x;
        int h = L.statusY - dpi::Scale(20);
        if (w < 100) w = 100;
        if (h < 100) h = 100;
        SetWindowPos(s.detailsPanel, nullptr, x, y, w, h, SWP_NOZORDER);
    }

    // Status-bar progress is custom-painted; nothing to position here.
}

// ---------------------------------------------------------------------------
// Engine-driven UI sync helpers (called from WM_TIMER and the action handlers).
// ---------------------------------------------------------------------------
void UpdatePillFromState(State& s) {
    using PS = State::PillState;
    const auto& stats = App::Instance().Stats();

    if (s.lastStartFailed) {
        s.pillState = PS::Error;
        s.pillText  = L"Error";
        return;
    }
    // Honor user-initiated Cancel FIRST. nl_scanner_cancel is best-effort:
    // engine workers may still be in select() wait-states for up to
    // timeoutMs after the flag flipped, during which nl_scanner_is_running()
    // still returns true. Two visible states make the lock state legible:
    //   - Cancelling… (PS::Cancelling) while engine workers wind down
    //   - Cancelled · X%   (PS::Cancelled) once IsScanning() is finally false
    if (s.userCancelled) {
        const bool engineStillBusy = stats.isScanning;
        if (engineStillBusy) {
            s.pillState = PS::Cancelling;
            s.pillText  = L"Cancelling\x2026";
        } else {
            s.pillState = PS::Cancelled;
            if (s.cancelledAtPct >= 0) {
                wchar_t buf[32];
                wsprintfW(buf, L"Cancelled \xb7 %d%%", s.cancelledAtPct);
                s.pillText = buf;
            } else {
                s.pillText = L"Cancelled";
            }
        }
        return;
    }
    if (stats.isScanning) {
        s.pillState = PS::Scanning;
        // Probe-based percent (matches status bar + KPI card).
        int pct = 0;
        if (stats.probesTotalEstimate > 0 && stats.probesDone > 0) {
            pct = static_cast<int>(stats.probesDone * 100
                                  / stats.probesTotalEstimate);
        } else if (stats.progressTotal > 0) {
            pct = static_cast<int>(stats.progress01 * 100.0f);
        }
        if (pct > 100) pct = 100;
        wchar_t buf[32];
        wsprintfW(buf, L"Scanning \xb7 %d%%", pct);
        s.pillText = buf;
        return;
    }
    if (stats.totalScanned > 0) {
        s.pillState = PS::Done;
        s.pillText  = L"Done";
        return;
    }
    s.pillState = PS::Ready;
    s.pillText  = L"Ready";
}

void SyncProgressBar(State& /*s*/) {
    // No-op — the status bar paint reads App::Stats().progress01 directly.
}

// Toggle the toolbar through three states:
//   - idle      : Start = blue "Start scan", config controls enabled
//   - scanning  : Start = red  "Cancel",     config controls disabled
//   - cancelling: Start = red  "Cancelling…" (disabled), config controls
//                                            still disabled. Bridges the
//                                            ~400 ms gap between
//                                            nl_scanner_cancel() and the
//                                            workers actually returning,
//                                            during which a Start click
//                                            would race the engine.
enum class ToolbarMode { Idle, Scanning, Cancelling };

void SyncToolbarMode(State& s, ToolbarMode mode) {
    const wchar_t* startText;
    BOOL startEnabled;
    BOOL configEnabled;
    switch (mode) {
        case ToolbarMode::Scanning:
            startText     = L"Cancel";
            startEnabled  = TRUE;
            configEnabled = FALSE;
            break;
        case ToolbarMode::Cancelling:
            startText     = L"Cancelling\x2026";
            startEnabled  = FALSE;     // engine still busy — clicking is racy
            configEnabled = FALSE;
            break;
        case ToolbarMode::Idle:
        default:
            startText     = L"Start scan";
            startEnabled  = TRUE;
            configEnabled = TRUE;
            break;
    }
    // Idempotency guard: if we're already in this mode, the SetWindowText
    // / EnableWindow / InvalidateRect chain below is wasted work that
    // triggers redundant WM_PAINT cascades on the owner-draw buttons.
    const int newMode = static_cast<int>(mode);
    if (s.toolbarModeCache == newMode) {
        return;
    }
    s.toolbarModeCache = newMode;

    SetWindowTextW(s.startBtn, startText);
    EnableWindow(s.startBtn,         startEnabled);
    EnableWindow(s.rangeEdit,        configEnabled);
    EnableWindow(s.adapterBtn,       configEnabled);
    EnableWindow(s.presetCombo,      configEnabled);
    EnableWindow(s.customPortsEdit,  configEnabled);
    EnableWindow(s.clearBtn,         configEnabled);
    EnableWindow(s.exportCsvBtn,     configEnabled);
    EnableWindow(s.exportHtmlBtn,    configEnabled);
    // Force a repaint so PaintFlatButton picks up the new kind / label.
    InvalidateRect(s.startBtn, nullptr, TRUE);
}

// Backwards-compatible thin wrapper for the old two-state callers (DoStartScan
// / DoCancelScan paths that don't yet know about the Cancelling mid-state).
void SyncToolbarMode(State& s, bool scanning) {
    SyncToolbarMode(s, scanning ? ToolbarMode::Scanning : ToolbarMode::Idle);
}

void SyncUiFromEngine(HWND hwnd, State& s, bool dataChanged) {
    UpdateKpiCards(s);
    SyncProgressBar(s);
    UpdatePillFromState(s);
    // Three-state toolbar derived from (userCancelled, IsScanning):
    //   - !userCancelled  &&  IsScanning  → Scanning   (red Cancel button)
    //   -  userCancelled  &&  IsScanning  → Cancelling (red disabled
    //                                                   "Cancelling…")
    //   - otherwise                       → Idle       (blue Start)
    // The middle case is the ~400 ms gap between nl_scanner_cancel() and
    // workers returning. The button is visibly disabled during that
    // window so the user knows to wait instead of racing the engine.
    const bool engineBusy = App::Instance().IsScanning();
    ToolbarMode mode;
    if (s.userCancelled && engineBusy) mode = ToolbarMode::Cancelling;
    else if (engineBusy)               mode = ToolbarMode::Scanning;
    else                               mode = ToolbarMode::Idle;
    SyncToolbarMode(s, mode);
    if (dataChanged) {
        HostTable::RefreshData(s.hostTable);
        DetailsPanel::SetHostIndex(s.detailsPanel, App::Instance().SelectedIndex());
    }
    // Targeted invalidation. A blanket `InvalidateRect(hwnd, nullptr,
    // FALSE)` every tick caused visible toolbar / KPI flicker by
    // repainting regions whose pixels never change between ticks. Only
    // three regions actually animate per snapshot:
    //   1. Brand bar — the status pill ("Scanning · X%" → "Cancelled" …)
    //   2. KPI cards — value labels (set via SetWindowText, which
    //                  invalidates the card child itself)
    //   3. Status bar — mirrors pill text + the flat progress strip
    // Toolbar background, RANGE label, splitter, grid header etc. are
    // stable — leave them alone.
    RECT cr; GetClientRect(hwnd, &cr);
    Layout L = Compute(cr.right, cr.bottom, dpi::Scale(s.detailsWidthDip), true);
    RECT rcBrand  = { 0, L.brandY,  L.leftRightX, L.brandY  + L.brandH  };
    RECT rcStatus = { 0, L.statusY, L.W,          L.statusY + L.statusH };
    InvalidateRect(hwnd, &rcBrand,  FALSE);
    InvalidateRect(hwnd, &rcStatus, FALSE);
}

// AdjustTimer is a no-op stub. Engine polling has moved to a worker
// thread inside ScanSession; the stub remains to satisfy older call
// sites if any survive linking.
void AdjustTimer(HWND hwnd, State& s) { (void)hwnd; (void)s; }

std::wstring AskSavePath(HWND owner, const wchar_t* defName,
                         const wchar_t* filter, const wchar_t* defExt) {
    wchar_t buf[MAX_PATH];
    lstrcpynW(buf, defName, MAX_PATH);

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = defExt;
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return {};
    return std::wstring(buf);
}

void DoStartScan(HWND hwnd, State& s) {
    if (!App::Instance().EngineOk()) {
        MessageBoxW(hwnd, L"Engine is not available.",
                    L"NetLens", MB_OK | MB_ICONERROR);
        return;
    }

    wchar_t buf[160] = {};
    GetWindowTextW(s.rangeEdit, buf, 160);
    if (buf[0] == 0) {
        MessageBoxW(hwnd, L"Please enter a range to scan.",
                    L"NetLens", MB_OK | MB_ICONINFORMATION);
        SetFocus(s.rangeEdit);
        return;
    }
    if (App::Instance().CurrentPreset() == ScanPreset::CustomPorts) {
        wchar_t cp[256] = {};
        GetWindowTextW(s.customPortsEdit, cp, 256);
        App::Instance().SetCustomPortsCsv(cp);
    }

    int rc = App::Instance().StartScan(buf, hwnd);
    if (rc != 0) {
        s.lastStartFailed = true;
        wchar_t msg[160];
        wsprintfW(msg, L"Could not start scan (engine returned %d).\n\n"
                       L"Check that the range is valid.", rc);
        MessageBoxW(hwnd, msg, L"NetLens", MB_OK | MB_ICONERROR);
        UpdatePillFromState(s);
        InvalidateRect(hwnd, nullptr, FALSE);
        return;
    }
    s.lastStartFailed = false;
    s.userCancelled   = false;
    s.cancelledAtPct  = -1;   // drop any stale "Cancelled · X%"
    // Clear the previous scan's results from the screen IMMEDIATELY.
    // StartScan() already emptied hosts_ / filteredIndex_ / stats_ and reset
    // the selection; without an explicit sync here the old rows, KPI numbers
    // and right-pane detail would linger for the ~50 ms until the first
    // snapshot lands. A full SyncUiFromEngine now repaints the grid empty,
    // zeroes the KPI cards, blanks the details panel, and flips the toolbar
    // Start → Cancel so the user can interrupt within that first window.
    SyncUiFromEngine(hwnd, s, /*dataChanged=*/true);
    SyncToolbarMode(s, /*scanning=*/true);
    InvalidateRect(hwnd, nullptr, FALSE);
}

void DoCancelScan(HWND hwnd, State& s) {
    // Idempotent. The cancel is captured exactly once: on the FIRST
    // ESC / Cancel-click / File→Cancel press. Subsequent presses while
    // the engine winds down would otherwise re-snapshot probesDone
    // (which keeps advancing as in-flight select() calls return) and
    // bump the displayed "Cancelled · X%" toward 100, hiding where
    // the user really stopped.
    if (s.userCancelled || !App::Instance().IsScanning()) return;

    // Capture the percent BEFORE clearing the scan so the
    // "Cancelled · X%" pill knows where the user stopped.
    {
        const auto& st = App::Instance().Stats();
        if (st.probesTotalEstimate > 0 && st.probesDone > 0) {
            int p = static_cast<int>(st.probesDone * 100 / st.probesTotalEstimate);
            if (p > 100) p = 100;
            s.cancelledAtPct = p;
        } else if (st.progressTotal > 0) {
            s.cancelledAtPct = static_cast<int>(st.progress01 * 100.0f);
        }
    }
    App::Instance().CancelScan();
    s.userCancelled = true;
    UpdatePillFromState(s);
    // Engine workers take up to timeoutMs (default 400 ms) to actually
    // return from select(). During that window the toolbar sits in
    // ToolbarMode::Cancelling (red disabled "Cancelling…" + config
    // controls locked) so a Start click can't race the engine. The
    // next SyncUiFromEngine tick (driven by the scanner snapshot posted
    // on engine exit) flips back to Idle.
    const bool engineBusy = App::Instance().IsScanning();
    SyncToolbarMode(s, engineBusy ? ToolbarMode::Cancelling
                                  : ToolbarMode::Idle);
    InvalidateRect(hwnd, nullptr, FALSE);
}

void DoClear(HWND hwnd, State& s) {
    App::Instance().ClearScan();
    s.userCancelled   = false;
    s.lastStartFailed = false;
    s.cancelledAtPct  = -1;
    SyncUiFromEngine(hwnd, s, true);
}

// Build "netlens-scan-YYYYMMDD-HHMM.<ext>" using local time.
std::wstring TimestampedFilename(bool html) {
    SYSTEMTIME t{};
    GetLocalTime(&t);
    wchar_t buf[64];
    swprintf_s(buf, L"netlens-scan-%04d%02d%02d-%02d%02d.%s",
               t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
               html ? L"html" : L"csv");
    return buf;
}

// Ensure the file at `path` starts with the UTF-8 BOM. If it doesn't, prepend
// it via a read-rewrite cycle. Used after engine CSV export — gives Excel a
// hint to open the file as UTF-8 instead of ANSI.
void EnsureUtf8Bom(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    BYTE head[3] = {};
    DWORD got = 0;
    ReadFile(h, head, 3, &got, nullptr);
    if (got == 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF) {
        CloseHandle(h);
        return;
    }

    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart < 0 || sz.QuadPart > (1LL << 28)) { CloseHandle(h); return; }
    std::vector<BYTE> body(static_cast<size_t>(sz.QuadPart));
    SetFilePointer(h, 0, nullptr, FILE_BEGIN);
    DWORD bytesRead = 0;
    ReadFile(h, body.data(), static_cast<DWORD>(body.size()), &bytesRead, nullptr);
    SetFilePointer(h, 0, nullptr, FILE_BEGIN);
    SetEndOfFile(h);
    DWORD written = 0;
    const BYTE bom[3] = { 0xEF, 0xBB, 0xBF };
    WriteFile(h, bom, 3, &written, nullptr);
    WriteFile(h, body.data(), bytesRead, &written, nullptr);
    CloseHandle(h);
}

void DoExport(HWND hwnd, State& s, bool html) {
    (void)s;
    if (App::Instance().Hosts().empty()) {
        MessageBoxW(hwnd, L"No scan results to export.",
                    L"NetLens", MB_OK | MB_ICONINFORMATION);
        return;
    }
    constexpr wchar_t kFilterCsv[]  = L"CSV files (*.csv)\0*.csv\0All files\0*.*\0";
    constexpr wchar_t kFilterHtml[] = L"HTML files (*.html)\0*.html\0All files\0*.*\0";
    std::wstring defName = TimestampedFilename(html);
    std::wstring path = AskSavePath(hwnd,
                                    defName.c_str(),
                                    html ? kFilterHtml : kFilterCsv,
                                    html ? L"html" : L"csv");
    if (path.empty()) return;

    HCURSOR oldCur = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    int rc = html ? App::Instance().ExportHtml(path)
                  : App::Instance().ExportCsv(path);
    if (rc == 0 && !html) EnsureUtf8Bom(path);
    SetCursor(oldCur);

    if (rc != 0) {
        MessageBoxW(hwnd, L"Export failed.", L"NetLens", MB_OK | MB_ICONERROR);
        return;
    }

    // Auto-launch the file with the default app (HTML → browser,
    // CSV → Excel / LibreOffice / Notepad). No prompt: the common case
    // is "view what was just exported", and a prompt is an extra click.
    ShellExecuteW(hwnd, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

// ---------------------------------------------------------------------------
// Ctrl+T full-UI sweep.
//
// One Ctrl+T press = captures-<ts>/ folder with:
//   01-main.png       (the main window — captured first)
//   02-about.png      (About dialog auto-opened, auto-closed)
//   03-settings.png   (same)
//   04-adapters.png   (same)
//   05-portlists.png  (same)
//
// State machine: DoCapture() saves main + flips nl::capture::SetAutoCapturing
// + posts WM_NL_CAPTURE_NEXT(0). Main's WndProc handles that by invoking the
// dialog's Show() in modal pump mode — but each dialog's Show() checks the
// auto-capturing flag right after first paint, snaps itself, and DestroyWindow's
// itself before entering the user-facing modal loop. When Show() returns,
// the WM_NL_CAPTURE_NEXT handler increments the index and posts the next one.
// ---------------------------------------------------------------------------
constexpr UINT WM_NL_CAPTURE_NEXT = WM_APP + 2;

// Tag-from-window heuristic — main window has a registered class
// ("NetLensMain"); modal dialogs use Win32's "#32770" so we infer from title.
const wchar_t* TagForWindow(HWND hw) {
    wchar_t cls[64]   = {};
    wchar_t title[256] = {};
    GetClassNameW(hw, cls, 64);
    GetWindowTextW(hw, title, 256);

    if (wcsstr(cls, L"NetLensMain")) return L"main";
    if (wcsstr(title, L"About"))    return L"about";
    if (wcsstr(title, L"Settings")) return L"settings";
    if (wcsstr(title, L"Adapters")) return L"adapters";
    if (wcsstr(title, L"Adapter"))  return L"adapters";
    if (wcsstr(title, L"Port"))     return L"portlists";
    return L"window";
}

// True if any of our modal dialogs is currently up — used to short-circuit
// the auto-sweep (it would try to re-open something already on screen).
bool AnyDialogOpen() {
    struct Probe { bool found; DWORD pid; };
    Probe p{ false, GetCurrentProcessId() };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        auto* pr = reinterpret_cast<Probe*>(lp);
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (pid != pr->pid) return TRUE;
        if (!IsWindowVisible(h)) return TRUE;
        wchar_t cls[64] = {};
        GetClassNameW(h, cls, 64);
        // Our dialog classes all start with "NetLens" and include "Dlg".
        if (wcsstr(cls, L"NetLens") && wcsstr(cls, L"Dlg")) {
            pr->found = true;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&p));
    return p.found;
}

void DoCapture(HWND hwnd, State& s) {
    // Single Ctrl+T = one fresh session folder. Subsequent presses during
    // the sweep are no-ops (the sweep itself drives further captures).
    if (capture::IsAutoCapturing()) {
        MessageBeep(MB_OK);
        return;
    }

    capture::ResetSession();
    capture::AppendWindow(hwnd, L"main");

    // If the user already has a dialog open, don't drive the sweep (would
    // try to re-open something already on screen). Capture the open dialog
    // alongside main and stop here.
    if (AnyDialogOpen()) {
        struct EnumCtx { DWORD pid; };
        EnumCtx ec{ GetCurrentProcessId() };
        EnumWindows([](HWND h, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<EnumCtx*>(lp);
            DWORD pid = 0;
            GetWindowThreadProcessId(h, &pid);
            if (pid != c->pid) return TRUE;
            if (!IsWindowVisible(h) || IsIconic(h)) return TRUE;
            wchar_t cls[64] = {};
            GetClassNameW(h, cls, 64);
            if (!wcsstr(cls, L"NetLens") || !wcsstr(cls, L"Dlg")) return TRUE;
            capture::AppendWindow(h, TagForWindow(h));
            return TRUE;
        }, reinterpret_cast<LPARAM>(&ec));
        MessageBeep(MB_OK);
        return;
    }

    // Kick off the auto-sweep: each dialog will be opened, snapped, and
    // destroyed by its own Show() while autoCapturing is on.
    capture::SetAutoCapturing(true);
    s.captureSeqIdx = 0;
    PostMessageW(hwnd, WM_NL_CAPTURE_NEXT, 0, 0);
}

// Ctrl+W — single-shot capture of ONLY the main window. Saves next to the
// exe as netlens-main-<ts>.png and opens it in the default image viewer.
// Distinct from Ctrl+T, which drives the full-UI sweep into a captures-<ts>/
// folder (main + every dialog). This is the quick "grab what's on screen
// right now" path. SaveWindowPng falls back to a screen BitBlt when
// PrintWindow comes back blank, so the main window's custom double-buffered
// paint is captured correctly as long as it's the visible foreground window
// (which it is when the user just pressed the shortcut).
void DoCaptureMainOnly(HWND hwnd) {
    wchar_t exe[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring dir(exe, n);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) dir.resize(pos);

    SYSTEMTIME t{};
    GetLocalTime(&t);
    wchar_t name[96];
    swprintf_s(name, L"\\netlens-main-%04d%02d%02d-%02d%02d%02d.png",
               t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    const std::wstring path = dir + name;

    if (capture::SaveWindowPng(hwnd, path)) {
        ShellExecuteW(hwnd, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    } else {
        MessageBeep(MB_ICONERROR);
    }
}

// Drives the sweep — one dialog per WM_NL_CAPTURE_NEXT delivery so the
// nested modal pump runs cleanly between steps.
void CaptureSweepStep(HWND hwnd, State& s) {
    switch (s.captureSeqIdx) {
        case 0: AboutDialog::Show(hwnd);        break;
        case 1: SettingsDialog::Show(hwnd);     break;
        case 2: AdaptersDialog::Show(hwnd);     break;  // returns string, ignored
        case 3: PortListsDialog::Show(hwnd);    break;
        default:
            // Done — flip the flag off so future dialogs run normally.
            capture::SetAutoCapturing(false);
            s.captureSeqIdx = -1;
            MessageBeep(MB_OK);
            return;
    }
    ++s.captureSeqIdx;
    PostMessageW(hwnd, WM_NL_CAPTURE_NEXT, 0, 0);
}

void OnPresetChanged(State& s) {
    int sel = static_cast<int>(SendMessageW(s.presetCombo, CB_GETCURSEL, 0, 0));
    if (sel < 0) sel = 0;
    ScanPreset p = static_cast<ScanPreset>(sel);
    App::Instance().SetCurrentPreset(p);
    const bool isCustom = (p == ScanPreset::CustomPorts);
    ShowWindow(s.customPortsEdit, isCustom ? SW_SHOW : SW_HIDE);
    // Re-run the toolbar layout NOW. DoLayout parks the custom-ports box
    // off-screen (x = -wCustom) for non-Custom presets and only repositions it
    // on a layout pass; without this call, selecting "Custom Ports" would
    // SW_SHOW the box at its stale off-screen X — so it looked missing until
    // the next window resize. Then drop the caret into it for immediate typing.
    DoLayout(s);
    if (isCustom) SetFocus(s.customPortsEdit);
}

// ---------------------------------------------------------------------------
// WM_COMMAND dispatch.
// ---------------------------------------------------------------------------
void HandleCommand(HWND hwnd, State& s, int id, int notifyCode) {
    switch (id) {
        case IDM_FILE_EXIT:
            DestroyWindow(hwnd);
            return;

        case IDM_FILE_START:
        case IDC_START_BTN:
            // Same button is "Start scan" at idle and "Cancel" while
            // scanning — route to the right handler based on live state.
            // While userCancelled is still pending engine wind-down, the
            // button reads "Cancelling…" and is disabled; this defensive
            // check makes File → Start (menu / shortcut) also no-op in
            // that window so a new scan can't race a half-stopped engine.
            if (s.userCancelled && App::Instance().IsScanning()) {
                return; // engine busy unwinding — wait for it
            }
            if (App::Instance().IsScanning()) {
                DoCancelScan(hwnd, s);
            } else {
                DoStartScan(hwnd, s);
            }
            return;

        case IDM_FILE_CANCEL:
            DoCancelScan(hwnd, s);
            return;

        case IDM_FILE_CLEAR:
        case IDC_CLEAR_BTN:
            DoClear(hwnd, s);
            return;

        case IDM_FILE_EXPORT_HTML:
        case IDC_EXPORT_HTML_BTN:
            DoExport(hwnd, s, /*html=*/ true);
            return;

        case IDM_FILE_EXPORT_CSV:
        case IDC_EXPORT_CSV_BTN:
            DoExport(hwnd, s, /*html=*/ false);
            return;

        case IDM_TOOLS_SETTINGS:
        case IDC_SETTINGS_BTN:
            SettingsDialog::Show(hwnd);
            return;

        case IDM_TOOLS_ADAPTERS:
        case IDC_ADAPTER_BTN: {
            std::wstring chosen = AdaptersDialog::Show(hwnd);
            if (!chosen.empty()) {
                SetWindowTextW(s.rangeEdit, chosen.c_str());
                SetFocus(s.rangeEdit);
                // Move caret to the end so the user can edit if needed.
                SendMessageW(s.rangeEdit, EM_SETSEL,
                             static_cast<WPARAM>(chosen.size()),
                             static_cast<LPARAM>(chosen.size()));
            }
            return;
        }

        case IDM_TOOLS_PORT_LISTS:
            PortListsDialog::Show(hwnd);
            return;

        case IDM_TOOLS_CAPTURE:
            DoCapture(hwnd, s);
            return;

        case IDM_CAPTURE_MAIN:   // Ctrl+W — snap the main window only + open it
            DoCaptureMainOnly(hwnd);
            return;

        case IDM_VIEW_OFFLINE: {
            // Toggle "Show offline hosts". The state is also mirrored into
            // the hidden checkbox HWND so the rest of the app reads from
            // a single source of truth, and the menu checkmark flips.
            bool now = !App::Instance().ViewOffline();
            App::Instance().SetViewOffline(now);
            SendMessageW(s.viewOfflineChk,
                         BM_SETCHECK,
                         now ? BST_CHECKED : BST_UNCHECKED, 0);
            HostTable::SetStatusColumnVisible(s.hostTable, now);
            HostTable::RefreshData(s.hostTable, /*forceRepaint=*/true);
            if (HMENU hm = GetMenu(hwnd)) {
                CheckMenuItem(hm, IDM_VIEW_OFFLINE,
                              MF_BYCOMMAND | (now ? MF_CHECKED : MF_UNCHECKED));
            }
            InvalidateRect(hwnd, nullptr, FALSE);
            return;
        }

        case IDM_HELP_ABOUT:
        case IDC_ABOUT_BTN:
            AboutDialog::Show(hwnd);
            return;

        case IDM_HELP_VISIT_3389:
            ShellExecuteW(hwnd, L"open", L"https://3389.ro/", nullptr, nullptr, SW_SHOWNORMAL);
            return;

        case IDM_FOCUS_SEARCH:
            if (s.searchEdit) {
                SetFocus(s.searchEdit);
                SendMessageW(s.searchEdit, EM_SETSEL, 0, -1);
            }
            return;

        // Host-grid right-click context-menu actions. NM_RCLICK made the
        // clicked row the listview selection, so the target host is
        // simply App::SelectedIndex().
        case IDM_CTX_PING:
        case IDM_CTX_BROWSER:
        case IDM_CTX_RDP:
        case IDM_CTX_SSH:
        case IDM_CTX_TELNET:
        case IDM_CTX_VNC:
        case IDM_CTX_COPY_IP:
        case IDM_CTX_COPY_MAC:
        case IDM_CTX_COPY_HOSTNAME:
        case IDM_CTX_COPY_REPORT:
        case IDM_CTX_OPEN_FOLDER: {
            int idx = App::Instance().SelectedIndex();
            const auto& hosts = App::Instance().Hosts();
            if (idx < 0 || idx >= static_cast<int>(hosts.size())) return;
            const HostRow& h = hosts[idx];
            const std::wstring& ip = h.ip;

            if (id == IDM_CTX_PING) {
                std::wstring args = L"/k ping " + ip;
                ShellExecuteW(hwnd, L"open", L"cmd.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
            } else if (id == IDM_CTX_BROWSER) {
                std::wstring url = L"http://" + ip;
                ShellExecuteW(hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            } else if (id == IDM_CTX_RDP) {
                std::wstring args = L"/v:" + ip;
                ShellExecuteW(hwnd, L"open", L"mstsc.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
            } else if (id == IDM_CTX_SSH) {
                ShellExecuteW(hwnd, L"open", L"ssh.exe", ip.c_str(), nullptr, SW_SHOWNORMAL);
            } else if (id == IDM_CTX_TELNET) {
                ShellExecuteW(hwnd, L"open", L"telnet.exe", ip.c_str(), nullptr, SW_SHOWNORMAL);
            } else if (id == IDM_CTX_VNC) {
                // Tight-VNC / RealVNC default port is 5900; treat as URL
                // so installed VNC clients with registered scheme handle it.
                std::wstring url = L"vnc://" + ip;
                ShellExecuteW(hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            } else if (id == IDM_CTX_OPEN_FOLDER) {
                std::wstring url = L"\\\\" + ip + L"\\";
                ShellExecuteW(hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            } else {
                // Clipboard variants.
                std::wstring text;
                if (id == IDM_CTX_COPY_IP)            text = h.ip;
                else if (id == IDM_CTX_COPY_MAC)      text = h.mac;
                else if (id == IDM_CTX_COPY_HOSTNAME) text = h.hostname;
                else /* COPY_REPORT */ {
                    // Full report: identity + TCP + printer + UDP, with
                    // a version banner so the recipient knows the build.
                    text += L"NetLens v" + App::Instance().EngineVersion()
                          + L"  \x2014  host report\r\n";
                    text += L"================================================\r\n";
                    text += L"Host: " + h.ip + L"\r\n";
                    if (!h.hostname.empty())   text += L"Hostname: "   + h.hostname   + L"\r\n";
                    if (!h.mac.empty())        text += L"MAC: "        + h.mac        + L"\r\n";
                    if (!h.vendor.empty())     text += L"Vendor: "     + h.vendor     + L"\r\n";
                    if (!h.deviceType.empty()) text += L"Device Type: " + h.deviceType + L"\r\n";
                    if (!h.deviceModel.empty() && h.deviceModel != h.printerModel)
                        text += L"Model: "     + h.deviceModel + L"\r\n";
                    if (!h.openPorts.empty())  text += L"Open TCP ports: " + h.openPorts + L"\r\n";
                    if (!h.services.empty())   text += L"Services: "   + h.services   + L"\r\n";
                    if (!h.brandHint.empty())  text += L"Brand hint: " + h.brandHint  + L"\r\n";
                    if (!h.osHint.empty())     text += L"OS hint: "    + h.osHint     + L"\r\n";

                    if (h.isPrinter) {
                        text += L"\r\n-- Printer ----------\r\n";
                        if (!h.printerVendor.empty()) text += L"Vendor: " + h.printerVendor + L"\r\n";
                        if (!h.printerModel.empty())  text += L"Model: "  + h.printerModel  + L"\r\n";
                        if (!h.printerSerial.empty()) text += L"Serial: " + h.printerSerial + L"\r\n";
                        if (!h.printerSnmpStatus.empty())
                            text += L"SNMP status: " + h.printerSnmpStatus + L"\r\n";
                        // v1.4.1 — page / scan counters ("total\tcolor\tmono\tscans").
                        if (!h.printerPages.empty()) {
                            std::wstring pf[5]; size_t pp = 0; int pidx = 0;
                            while (pidx < 5) {
                                size_t t = h.printerPages.find(L'\t', pp);
                                pf[pidx++] = h.printerPages.substr(pp,
                                    t == std::wstring::npos ? std::wstring::npos : t - pp);
                                if (t == std::wstring::npos) break; pp = t + 1;
                            }
                            if (!pf[0].empty()) text += L"Pages printed (life): " + pf[0] + L"\r\n";
                            if (!pf[1].empty()) text += L"Color pages: " + pf[1] + L"\r\n";
                            if (!pf[2].empty()) text += L"Mono pages: "  + pf[2] + L"\r\n";
                            if (!pf[3].empty()) text += L"Scans: "       + pf[3] + L"\r\n";
                            if (!pf[4].empty()) text += L"Media printed: " + pf[4] + L"\r\n";
                        }
                        const std::wstring& s = h.printerSupplies;
                        size_t i = 0;
                        while (i < s.size()) {
                            size_t eol = s.find(L"\r\n", i);
                            std::wstring line = s.substr(i,
                                eol == std::wstring::npos ? std::wstring::npos : eol - i);
                            i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                            if (line.empty()) continue;
                            std::wstring col, ty, pct, lvl, mx, desc;
                            auto take = [&](std::wstring& dst) {
                                size_t t = line.find(L'\t');
                                if (t == std::wstring::npos) { dst = line; line.clear(); }
                                else { dst = line.substr(0, t); line.erase(0, t + 1); }
                            };
                            take(col); take(ty); take(pct); take(lvl); take(mx); desc = line;
                            text += L"  ";
                            text += col.empty() ? L"Supply" : col;
                            text += L": ";
                            text += pct.empty() ? L"unknown" : pct;
                            if (!lvl.empty() && !mx.empty()) {
                                text += L" ("; text += lvl; text += L"/"; text += mx; text += L")";
                            }
                            if (!desc.empty()) { text += L"  \x2014  "; text += desc; }
                            text += L"\r\n";
                        }
                    }

                    // SMB shares block (v1.4.5).
                    if (!h.smbShares.empty()) {
                        text += L"\r\n-- SMB shares ----\r\n";
                        const std::wstring& sh = h.smbShares;
                        size_t i = 0;
                        while (i < sh.size()) {
                            size_t eol = sh.find(L"\r\n", i);
                            std::wstring line = sh.substr(i,
                                eol == std::wstring::npos ? std::wstring::npos : eol - i);
                            i = (eol == std::wstring::npos) ? sh.size() : eol + 2;
                            if (line.empty()) continue;
                            std::wstring name, type, remark;
                            auto take = [&](std::wstring& dst) {
                                size_t t = line.find(L'\t');
                                if (t == std::wstring::npos) { dst = line; line.clear(); }
                                else { dst = line.substr(0, t); line.erase(0, t + 1); }
                            };
                            take(name); take(type); remark = line;
                            text += L"  " + name + L"  (" + type + L")";
                            if (!remark.empty()) text += L"  \x2014  " + remark;
                            text += L"\r\n";
                        }
                    }

                    if (!h.udpDiscovery.empty()) {
                        text += L"\r\n-- UDP discovery ----\r\n";
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
                            text += L"  UDP/"; text += port;
                            text += L"  "; text += svc;
                            if (!detail.empty()) { text += L"  \x2014  "; text += detail; }
                            text += L"\r\n";
                        }
                    }
                }
                if (!text.empty() && OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
                    if (HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes)) {
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
            }
            return;
        }

        case IDC_FILTER_COMBO:
            if (notifyCode == CBN_SELCHANGE) {
                int sel = static_cast<int>(SendMessageW(s.filterCombo, CB_GETCURSEL, 0, 0));
                if (sel < 0) sel = 0;
                App::Instance().SetFilter(static_cast<HostFilter>(sel));
                HostTable::RefreshData(s.hostTable, /*forceRepaint=*/true);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return;

        case IDC_SEVERITY_COMBO:
            if (notifyCode == CBN_SELCHANGE) {
                int sel = static_cast<int>(
                    SendMessageW(s.severityCombo, CB_GETCURSEL, 0, 0));
                if (sel < 0) sel = 0;
                App::Instance().SetMinSeverity(static_cast<SeverityFilter>(sel));
                HostTable::RefreshData(s.hostTable, /*forceRepaint=*/true);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return;

        case IDC_PRESET_COMBO:
            if (notifyCode == CBN_SELCHANGE) {
                OnPresetChanged(s);
            }
            return;

        case IDC_CUSTOM_PORTS_EDIT:
            if (notifyCode == EN_CHANGE) {
                wchar_t cp[256] = {};
                GetWindowTextW(s.customPortsEdit, cp, 256);
                App::Instance().SetCustomPortsCsv(cp);
            }
            return;

        case IDC_SEARCH_EDIT:
            if (notifyCode == EN_CHANGE) {
                wchar_t buf[256]; buf[0] = 0;
                GetWindowTextW(s.searchEdit, buf, 256);
                App::Instance().SetSearch(buf);
                HostTable::RefreshData(s.hostTable, /*forceRepaint=*/true);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return;

        case IDC_VIEW_OFFLINE_CHK:
            if (notifyCode == BN_CLICKED) {
                LRESULT chk = SendMessageW(s.viewOfflineChk, BM_GETCHECK, 0, 0);
                bool view = (chk == BST_CHECKED);
                App::Instance().SetViewOffline(view);
                HostTable::SetStatusColumnVisible(s.hostTable, view);
                HostTable::RefreshData(s.hostTable, /*forceRepaint=*/true);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return;
    }
}

// Build + show the host-grid right-click context menu. iItem is the
// listview row index; the clicked row is forced into selection so the
// IDM_CTX_* dispatcher in HandleCommand can use App::SelectedIndex().
void ShowHostContextMenu(HWND hwnd, HWND hLv, int iItem) {
    const auto& filtered = App::Instance().FilteredIndex();
    if (iItem < 0 || iItem >= static_cast<int>(filtered.size())) return;

    // Make the right-clicked row the active selection.
    LVITEM lvi{};
    lvi.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    lvi.state     = 0;
    ListView_SetItemState(hLv, -1, 0, lvi.stateMask);    // clear all
    lvi.state = LVIS_SELECTED | LVIS_FOCUSED;
    ListView_SetItemState(hLv, iItem, lvi.state, lvi.stateMask);

    // Also push the new selection into App + DetailsPanel right away so
    // when the user picks an action the host index matches what's shown.
    int hostIdx = filtered[iItem];
    App::Instance().SetSelected(hostIdx);
    State* st = GetState(hwnd);
    if (st) DetailsPanel::SetHostIndex(st->detailsPanel, hostIdx);

    const HostRow& h = App::Instance().Hosts()[hostIdx];

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, IDM_CTX_PING,    L"&Ping");
    AppendMenuW(menu, MF_STRING, IDM_CTX_BROWSER, L"Open in &browser  (http://)");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_CTX_RDP,    L"&RDP  (Remote Desktop)");
    AppendMenuW(menu, MF_STRING, IDM_CTX_SSH,    L"&SSH");
    AppendMenuW(menu, MF_STRING, IDM_CTX_TELNET, L"&Telnet");
    AppendMenuW(menu, MF_STRING, IDM_CTX_VNC,    L"&VNC");
    AppendMenuW(menu, MF_STRING, IDM_CTX_OPEN_FOLDER,
                L"Open SMB share  (\\\\ip\\)");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_CTX_COPY_IP,       L"Copy &IP");
    AppendMenuW(menu, MF_STRING, IDM_CTX_COPY_MAC,      L"Copy &MAC");
    if (!h.hostname.empty()) {
        AppendMenuW(menu, MF_STRING, IDM_CTX_COPY_HOSTNAME, L"Copy &hostname");
    }
    AppendMenuW(menu, MF_STRING, IDM_CTX_COPY_REPORT,   L"Copy &report");

    // Grey-out lines that don't apply (no MAC, offline, etc).
    if (h.mac.empty()) EnableMenuItem(menu, IDM_CTX_COPY_MAC, MF_BYCOMMAND | MF_GRAYED);
    if (!h.isOnline) {
        EnableMenuItem(menu, IDM_CTX_PING,    MF_BYCOMMAND | MF_GRAYED);
        EnableMenuItem(menu, IDM_CTX_BROWSER, MF_BYCOMMAND | MF_GRAYED);
        EnableMenuItem(menu, IDM_CTX_RDP,     MF_BYCOMMAND | MF_GRAYED);
        EnableMenuItem(menu, IDM_CTX_SSH,     MF_BYCOMMAND | MF_GRAYED);
        EnableMenuItem(menu, IDM_CTX_TELNET,  MF_BYCOMMAND | MF_GRAYED);
        EnableMenuItem(menu, IDM_CTX_VNC,     MF_BYCOMMAND | MF_GRAYED);
        EnableMenuItem(menu, IDM_CTX_OPEN_FOLDER, MF_BYCOMMAND | MF_GRAYED);
    }

    POINT pt;
    GetCursorPos(&pt);
    TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                   pt.x, pt.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

// ---------------------------------------------------------------------------
// WM_NOTIFY routing.
// ---------------------------------------------------------------------------
LRESULT HandleNotify(HWND hwnd, State& s, NMHDR* nm) {
    if (nm->hwndFrom == s.hostTable) {
        switch (nm->code) {
            case LVN_GETDISPINFOW:
                HostTable::OnGetDispInfo(s.hostTable,
                    reinterpret_cast<NMLVDISPINFOW*>(nm));
                return 0;
            case NM_CUSTOMDRAW:
                return HostTable::OnCustomDraw(s.hostTable,
                    reinterpret_cast<NMLVCUSTOMDRAW*>(nm));
            case LVN_ITEMCHANGED: {
                auto* p = reinterpret_cast<NMLISTVIEW*>(nm);
                if ((p->uChanged & LVIF_STATE)
                    && (p->uNewState & LVIS_SELECTED)
                    && !(p->uOldState & LVIS_SELECTED)) {
                    const auto& filtered = App::Instance().FilteredIndex();
                    if (p->iItem >= 0 && p->iItem < static_cast<int>(filtered.size())) {
                        int hostIdx = filtered[p->iItem];
                        App::Instance().SetSelected(hostIdx);
                        DetailsPanel::SetHostIndex(s.detailsPanel, hostIdx);
                    }
                }
                return 0;
            }
            case LVN_COLUMNCLICK: {
                auto* p = reinterpret_cast<NMLISTVIEW*>(nm);
                HostTable::OnColumnClick(s.hostTable, p->iSubItem);
                return 0;
            }
            case NM_RCLICK: {
                // Right-click on a host row → context menu with
                // Ping/Browser/RDP/SSH/Telnet/VNC/SMB-share + copy actions.
                auto* p = reinterpret_cast<NMITEMACTIVATE*>(nm);
                if (p->iItem >= 0) {
                    ShowHostContextMenu(hwnd, s.hostTable, p->iItem);
                }
                return 0;
            }
            case LVN_GETINFOTIPW: {
                // Full services CSV on hover (and full openPorts for that column).
                auto* p = reinterpret_cast<NMLVGETINFOTIPW*>(nm);
                const auto& filtered = App::Instance().FilteredIndex();
                if (p->iItem < 0 || p->iItem >= static_cast<int>(filtered.size())) return 0;
                const HostRow& h = App::Instance().Hosts()[filtered[p->iItem]];
                const std::wstring* tip = nullptr;
                if (!h.services.empty()) tip = &h.services;
                if (tip && p->pszText && p->cchTextMax > 1) {
                    lstrcpynW(p->pszText, tip->c_str(), p->cchTextMax);
                }
                return 0;
            }
        }
    }
    (void)hwnd;
    return 0;
}

// ---------------------------------------------------------------------------
// Re-apply current font to every standard child control. Used after WM_DPICHANGED.
// ---------------------------------------------------------------------------
void PropagateFont(const State& s) {
    HFONT f = theme::Fonts().regular;
    const HWND list[] = {
        s.rangeEdit, s.adapterBtn, s.presetCombo, s.customPortsEdit,
        s.startBtn, s.clearBtn, s.exportCsvBtn, s.exportHtmlBtn,
        s.settingsBtn, s.aboutBtn,
        s.filterCombo, s.searchEdit, s.viewOfflineChk,
        s.hostTable
    };
    for (HWND h : list) {
        if (h) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), MAKELPARAM(TRUE, 0));
    }
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------
LRESULT CALLBACK Proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_NCCREATE: {
            State* st = new State();
            st->hwnd = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_CREATE: {
            State* st = GetState(hwnd);
            dpi::Init(hwnd);
            theme::Rebuild(dpi::g_dpi);
            CreateAppMenu(hwnd);
            HINSTANCE hi = reinterpret_cast<LPCREATESTRUCTW>(lp)->hInstance;
            CreateChildControls(*st, hi);

            // Default range comes from the first usable adapter.
            std::wstring defRange = App::Instance().DefaultRange();
            if (!defRange.empty()) SetWindowTextW(st->rangeEdit, defRange.c_str());

            // Default: View offline OFF → hide the Status column.
            HostTable::SetStatusColumnVisible(st->hostTable, App::Instance().ViewOffline());

            // Initial pill / KPIs / progress reflect engine state at idle.
            UpdatePillFromState(*st);
            UpdateKpiCards(*st);
            SyncProgressBar(*st);

            // Engine polling lives on the ScanSession worker thread.
            // The UI receives WM_NL_APPLY_SNAPSHOT messages and applies
            // them; no IDT_POLL timer is needed.
            return 0;
        }
        case WM_NCDESTROY: {
            if (State* st = GetState(hwnd)) {
                delete st;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_DESTROY:
            // Make sure the scanner thread is joined before the window
            // disappears — otherwise it could PostMessage to a dead HWND.
            App::Instance().CancelScan();
            PostQuitMessage(0);
            return 0;

        case WM_NL_APPLY_SNAPSHOT: {
            // Scanner thread posted a snapshot — apply it and refresh UI.
            auto* snap = reinterpret_cast<EngineSnapshot*>(lp);
            if (!snap) {
                App::Instance().ClearSnapshotPending();
                return 0;
            }
            State* st = GetState(hwnd);
            if (st) {
                App::Instance().ApplySnapshot(std::move(*snap));
                SyncUiFromEngine(hwnd, *st, /*dataChanged=*/true);
            }
            delete snap;
            // Release back-pressure so the worker thread can build the
            // next snapshot. Pair with ScanSession::runLoop's
            // TryMarkSnapshotPending() — kept symmetric even on error
            // paths above so a transient st==nullptr doesn't strand the
            // worker.
            App::Instance().ClearSnapshotPending();
            return 0;
        }
        case WM_NL_SCAN_FINISHED: {
            // Scanner thread saw isRunning flip to false. Drives tiered
            // phase 1 → 2 transitions (kicks a fresh session).
            State* st = GetState(hwnd);
            if (st) {
                App::Instance().OnScanFinished(hwnd);
                SyncUiFromEngine(hwnd, *st, /*dataChanged=*/true);
            }
            return 0;
        }

        case WM_TIMER: {
            // IDT_POLL is retired (snapshots come via WM_NL_APPLY_SNAPSHOT).
            // The handler stays as a safety net for any timer that may
            // have been set earlier in the lifecycle.
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;  // we paint everything in WM_PAINT

        case WM_PAINT: {
            State* st = GetState(hwnd);
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc; GetClientRect(hwnd, &rc);
            Layout L = Compute(rc.right, rc.bottom, dpi::Scale(st->detailsWidthDip), true);

            // Bg fill (between bands)
            FillRect(hdc, &rc, theme::Brush(theme::Color::Bg));

            PaintBrandBar(hdc, L, *st);
            PaintToolbar(hdc, L);
            PaintKpiStripBg(hdc, L);
            PaintFilterBar(hdc, L);
            PaintSplitter(hdc, L);
            PaintStatusBar(hdc, L, *st);

            EndPaint(hwnd, &ps);
            (void)st;
            return 0;
        }

        case WM_SIZE: {
            State* st = GetState(hwnd);
            if (st) {
                // Pre-invalidate at the OLD child positions before moving
                // anything, then re-invalidate at the NEW positions.
                InvalidateRect(hwnd, nullptr, FALSE);
                DoLayout(*st);
            }
            RedrawWindow(hwnd, nullptr, nullptr,
                         RDW_INVALIDATE | RDW_ALLCHILDREN);
            return 0;
        }

        case WM_GETMINMAXINFO: {
            auto* mm = reinterpret_cast<MINMAXINFO*>(lp);
            mm->ptMinTrackSize.x = 1100;
            mm->ptMinTrackSize.y = 640;
            return 0;
        }

        case WM_DPICHANGED: {
            dpi::Update(HIWORD(wp));
            theme::Rebuild(dpi::g_dpi);

            if (State* st = GetState(hwnd)) {
                PropagateFont(*st);
            }
            auto* prc = reinterpret_cast<RECT*>(lp);
            SetWindowPos(hwnd, nullptr,
                         prc->left, prc->top,
                         prc->right - prc->left, prc->bottom - prc->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
        }

        case WM_COMMAND: {
            State* st = GetState(hwnd);
            if (st) HandleCommand(hwnd, *st, LOWORD(wp), HIWORD(wp));
            return 0;
        }

        case WM_KEYDOWN: {
            // ESC behaviour on the main window:
            //   - During a scan  → cancel the scan (complements the
            //     Cancel button — the natural "abort" gesture).
            //   - At idle / done → no-op. Post-scan state is left
            //     alone (no surprise clearing of the results).
            if (wp == VK_ESCAPE) {
                State* st = GetState(hwnd);
                if (st && App::Instance().IsScanning() && !st->userCancelled) {
                    DoCancelScan(hwnd, *st);
                    return 0;
                }
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }

        case WM_NL_CAPTURE_NEXT: {
            State* st = GetState(hwnd);
            if (st) CaptureSweepStep(hwnd, *st);
            return 0;
        }

        case WM_NETLENS_SPLIT_DRAG: {
            State* st = GetState(hwnd);
            if (!st) return 0;
            RECT rc; GetClientRect(hwnd, &rc);
            int cursorX = static_cast<int>(wp);
            int splitW  = dpi::Scale(6);
            int padR    = dpi::Scale(18);
            // The splitter sits at L.splitX = (detailsX - splitW), so the
            // details panel starts at cursorX + splitW (we treat the cursor
            // X as the splitter's left edge).
            int newDetailsW = rc.right - (cursorX + splitW) - padR;
            // Re-clamp via Compute()'s logic by going through dip units.
            int newDip = dpi::Unscale(newDetailsW);
            if (newDip < kDetailsMinDip) newDip = kDetailsMinDip;   // shared min
            int maxDip = dpi::Unscale(rc.right - padR - dpi::Scale(700) - splitW);
            if (newDip > maxDip && maxDip > kDetailsMinDip) newDip = maxDip;
            if (newDip != st->detailsWidthDip) {
                st->detailsWidthDip = newDip;
                // Invalidate at the OLD layout BEFORE moving anything so
                // stale pixels from the previous splitter position get
                // cleared by the parent's WM_PAINT.
                InvalidateRect(hwnd, nullptr, FALSE);
                DoLayout(*st);
                RedrawWindow(hwnd, nullptr, nullptr,
                             RDW_INVALIDATE | RDW_ALLCHILDREN);
            }
            return 0;
        }

        case WM_NOTIFY: {
            State* st = GetState(hwnd);
            if (st) return HandleNotify(hwnd, *st, reinterpret_cast<NMHDR*>(lp));
            return 0;
        }

        case WM_DRAWITEM: {
            auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
            if (dis->CtlType == ODT_BUTTON) {
                PaintFlatButton(*dis,
                    KindForButton(static_cast<int>(dis->CtlID), dis->hwndItem));
                return TRUE;
            }
            if (dis->CtlType == ODT_COMBOBOX) {
                // M5.16.1 — Owner-draw the preset combo so we control the
                // vertical text placement. The default CBS_DROPDOWNLIST
                // renders text top-aligned in the selection field, which
                // looked off against the owner-draw buttons. DT_VCENTER
                // here centers the text within the (full window-height)
                // item rect of the selection field.
                HDC hdc = dis->hDC;
                RECT rc = dis->rcItem;
                if (rc.right <= rc.left || rc.bottom <= rc.top) return TRUE;

                const bool isSelected = (dis->itemState & ODS_SELECTED) != 0;
                const bool isFocus    = (dis->itemState & ODS_FOCUS) != 0;
                const bool isComboEdit= (dis->itemState & ODS_COMBOBOXEDIT) != 0;

                // Background: white for the selection field at idle, accent
                // tint for hovered dropdown items.
                COLORREF fill;
                COLORREF text = theme::Get(theme::Color::TextPrimary);
                if (isComboEdit) {
                    fill = theme::Get(theme::Color::Surface);
                } else if (isSelected) {
                    fill = theme::Get(theme::Color::AccentSurface);
                    text = theme::Get(theme::Color::Accent);
                } else {
                    fill = theme::Get(theme::Color::Surface);
                }
                HBRUSH brF = CreateSolidBrush(fill);
                FillRect(hdc, &rc, brF);
                DeleteObject(brF);

                if (dis->itemID != static_cast<UINT>(-1)) {
                    wchar_t buf[128]; buf[0] = 0;
                    SendMessageW(dis->hwndItem, CB_GETLBTEXT,
                                 dis->itemID, reinterpret_cast<LPARAM>(buf));
                    if (buf[0]) {
                        SetBkMode(hdc, TRANSPARENT);
                        SetTextColor(hdc, text);
                        HFONT oldF = static_cast<HFONT>(
                            SelectObject(hdc, theme::Fonts().regular));
                        RECT rcText = rc;
                        rcText.left += dpi::Scale(6);

                        // v1.3.3 — severity combo carries a colored dot
                        // before the text (Critical=red, High=orange,
                        // Medium=amber, All=muted). Match the host-grid
                        // row tint palette so the visual mapping is
                        // immediate. The dot is drawn only on the
                        // severity combo (dis->CtlID).
                        if (dis->CtlID == IDC_SEVERITY_COMBO) {
                            COLORREF dotColor = 0;
                            switch (dis->itemID) {
                                case 0: dotColor = theme::Get(theme::Color::TextMuted); break;  // All
                                case 1: dotColor = RGB(0xD9, 0x77, 0x06); break;                // Medium+ amber
                                case 2: dotColor = RGB(0xEA, 0x58, 0x0C); break;                // High+ orange
                                case 3: dotColor = RGB(0xDC, 0x26, 0x26); break;                // Critical red
                                default: dotColor = theme::Get(theme::Color::TextMuted); break;
                            }
                            const int dotR = dpi::Scale(5);
                            const int dotCx = rcText.left + dotR;
                            const int dotCy = (rc.top + rc.bottom) / 2;
                            HBRUSH brDot = CreateSolidBrush(dotColor);
                            HBRUSH oldBr = static_cast<HBRUSH>(
                                SelectObject(hdc, brDot));
                            HPEN penDot = CreatePen(PS_SOLID, 1, dotColor);
                            HPEN oldPen = static_cast<HPEN>(
                                SelectObject(hdc, penDot));
                            Ellipse(hdc, dotCx - dotR, dotCy - dotR,
                                         dotCx + dotR + 1, dotCy + dotR + 1);
                            SelectObject(hdc, oldBr);
                            SelectObject(hdc, oldPen);
                            DeleteObject(brDot);
                            DeleteObject(penDot);
                            rcText.left = dotCx + dotR + dpi::Scale(6);
                        }
                        DrawTextW(hdc, buf, -1, &rcText,
                                  DT_LEFT | DT_VCENTER | DT_SINGLELINE
                                  | DT_NOPREFIX | DT_END_ELLIPSIS);
                        SelectObject(hdc, oldF);
                    }
                }
                if (isFocus && !isComboEdit) {
                    DrawFocusRect(hdc, &rc);
                }
                return TRUE;
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }

        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, theme::Get(theme::Color::TextPrimary));
            SetBkColor  (dc, theme::Get(theme::Color::Surface));
            return reinterpret_cast<LRESULT>(theme::Brush(theme::Color::Surface));
        }
        case WM_CTLCOLORLISTBOX: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, theme::Get(theme::Color::TextPrimary));
            SetBkColor  (dc, theme::Get(theme::Color::Surface));
            return reinterpret_cast<LRESULT>(theme::Brush(theme::Color::Surface));
        }
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC dc = reinterpret_cast<HDC>(wp);
            HWND hCtrl = reinterpret_cast<HWND>(lp);
            // Filter row is Bg (gray), brand bar is Surface (white).
            // The checkbox lives on the filter bar.
            COLORREF bg = theme::Get(theme::Color::Bg);
            if (State* st = GetState(hwnd)) {
                if (hCtrl == st->viewOfflineChk) {
                    bg = theme::Get(theme::Color::Bg);
                }
            }
            SetTextColor(dc, theme::Get(theme::Color::TextPrimary));
            SetBkColor  (dc, bg);
            return reinterpret_cast<LRESULT>(
                bg == theme::Get(theme::Color::Bg)
                    ? theme::Brush(theme::Color::Bg)
                    : theme::Brush(theme::Color::Surface));
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

void MainWindow::Register(HINSTANCE hInst) {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = Proc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon         = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_NETLENS));
    wc.hIconSm       = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_NETLENS));
    wc.hbrBackground = nullptr;
    wc.lpszClassName = ClassName();
    RegisterClassExW(&wc);
}

HWND MainWindow::Create(HINSTANCE hInst, int nCmdShow) {
    // Title bar text includes the version embedded by CMake.
    #define NLW2_(x) L##x
    #define NLW_(x)  NLW2_(x)
    constexpr const wchar_t* kTitle =
        L"NetLens v" NLW_(NETLENS_VERSION_STR) L" \x2014 LAN scanner";
    #undef NLW_
    #undef NLW2_

    // Initial window sizing:
    //   - If the primary monitor's work area is >= 1920×1080, open at
    //     1920×1080 centered in the work area. (NetLens at FHD shows
    //     the full toolbar + grid + right pane without horizontal
    //     scroll; smaller windows clip.)
    //   - Otherwise (sub-FHD laptops), open maximized so we use every
    //     pixel of the available screen.
    RECT wa{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    const int workW = wa.right  - wa.left;
    const int workH = wa.bottom - wa.top;

    int initX, initY, initW, initH;
    bool wantMaximize = false;
    if (workW >= 1920 && workH >= 1080) {
        initW = 1920;
        initH = 1080;
        initX = wa.left + (workW - initW) / 2;
        initY = wa.top  + (workH - initH) / 2;
    } else {
        // Below FullHD — pass a sensible fallback size; ShowWindow
        // immediately maximizes so the user sees a full-screen window.
        initW = workW > 0 ? workW : 1280;
        initH = workH > 0 ? workH : 800;
        initX = wa.left;
        initY = wa.top;
        wantMaximize = true;
    }

    HWND hwnd = CreateWindowExW(
        WS_EX_CONTROLPARENT,
        ClassName(),
        kTitle,
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        initX, initY, initW, initH,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return nullptr;

    ShowWindow(hwnd, wantMaximize ? SW_SHOWMAXIMIZED : nCmdShow);
    UpdateWindow(hwnd);
    return hwnd;
}

}  // namespace nl
