#include "PortListsDialog.h"

#include <commctrl.h>
#include <cstdio>
#include <string>
#include <vector>

#include "../App.h"
#include "../Capture.h"
#include "../Dpi.h"
#include "../Models.h"
#include "../Theme.h"
#include "../../Resource.h"

namespace nl {

namespace {

constexpr const wchar_t* kClassName = L"NetLensPortListsDlg";

constexpr int kId_BtnClose = 3001;
constexpr int kId_BtnCopy  = 3002;
constexpr int kId_Listview = 3010;

constexpr int kPresetCount = 5;
constexpr ScanPreset kPresets[kPresetCount] = {
    ScanPreset::Quick,
    ScanPreset::Standard,
    ScanPreset::FullCommon,
    ScanPreset::AllPortsFast,
    ScanPreset::AllPortsDeep,
};

struct State {
    HWND hListview     = nullptr;
    HWND hClose        = nullptr;
    HWND hCopy         = nullptr;
    int  selectedIdx   = 2;    // FullCommon by default — the most useful entry
    int  detailScrollY = 0;    // for the port-grid panel if it overflows
    int  detailContentH = 0;
    int  detailVisibleH = 0;
    int  detailTop      = 0;
    int  detailBot      = 0;
};

State* GetState(HWND h) {
    return reinterpret_cast<State*>(GetWindowLongPtrW(h, GWLP_USERDATA));
}

// --- common helpers --------------------------------------------------------
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
    HBRUSH brF = CreateSolidBrush(fill); FillRect(hdc, &rc, brF); DeleteObject(brF);
    HPEN pn = CreatePen(PS_SOLID, 1, border);
    HPEN op = static_cast<HPEN>(SelectObject(hdc, pn));
    HBRUSH ob = static_cast<HBRUSH>(SelectObject(hdc, GetStockObject(NULL_BRUSH)));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, ob); SelectObject(hdc, op); DeleteObject(pn);
    wchar_t buf[48]; buf[0] = 0;
    GetWindowTextW(dis.hwndItem, buf, 48);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text);
    HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
    DrawTextW(hdc, buf, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

void DrawText_(HDC hdc, RECT rc, const wchar_t* t, HFONT f, COLORREF c, DWORD flags) {
    HFONT old = static_cast<HFONT>(SelectObject(hdc, f));
    SetTextColor(hdc, c);
    SetBkMode(hdc, TRANSPARENT);
    DrawTextW(hdc, t, -1, &rc, flags);
    SelectObject(hdc, old);
}

void PaintCardOutline(HDC hdc, RECT rc) {
    HBRUSH br = theme::Brush(theme::Color::Surface);
    FillRect(hdc, &rc, br);
    HPEN pn = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HPEN op = static_cast<HPEN>(SelectObject(hdc, pn));
    HBRUSH ob = static_cast<HBRUSH>(SelectObject(hdc, GetStockObject(NULL_BRUSH)));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, ob); SelectObject(hdc, op); DeleteObject(pn);
}

void PopulateListview(State& st) {
    if (!st.hListview) return;
    ListView_DeleteAllItems(st.hListview);
    for (int i = 0; i < kPresetCount; ++i) {
        ScanPreset p = kPresets[i];

        LVITEMW it{};
        it.mask     = LVIF_TEXT | LVIF_PARAM;
        it.iItem    = i;
        it.iSubItem = 0;
        it.lParam   = i;
        it.pszText  = const_cast<LPWSTR>(App::PresetDisplayName(p));
        ListView_InsertItem(st.hListview, &it);

        // Column 1: port count
        std::vector<uint16_t> ports = App::PortsForPreset(p);
        wchar_t portBuf[32];
        if (ports.empty()) wcscpy_s(portBuf, L"1 \x2013 65535");
        else               swprintf_s(portBuf, L"%d", static_cast<int>(ports.size()));
        ListView_SetItemText(st.hListview, i, 1, portBuf);

        // Column 2: UDP/printer extras
        const bool udp = (p == ScanPreset::FullCommon)
                      || (p == ScanPreset::AllPortsFast)
                      || (p == ScanPreset::AllPortsDeep);
        const bool snmp = (p != ScanPreset::Quick);
        std::wstring extras;
        if (udp)  extras += L"UDP";
        if (snmp) { if (!extras.empty()) extras += L" \x00b7 "; extras += L"Printer SNMP"; }
        if (extras.empty()) extras = L"\x2014";
        ListView_SetItemText(st.hListview, i, 2,
                              const_cast<LPWSTR>(extras.c_str()));

        // Column 3: short description (first sentence only)
        std::wstring desc = App::PresetDescription(p);
        size_t dot = desc.find(L'.');
        if (dot != std::wstring::npos) desc.erase(dot + 1);
        ListView_SetItemText(st.hListview, i, 3,
                              const_cast<LPWSTR>(desc.c_str()));
    }
    // Restore selection
    if (st.selectedIdx >= 0 && st.selectedIdx < kPresetCount) {
        ListView_SetItemState(st.hListview, st.selectedIdx,
                              LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(st.hListview, st.selectedIdx, FALSE);
    }
}

void PaintDetail(HDC hdc, const State& st, int W, int H) {
    if (st.selectedIdx < 0 || st.selectedIdx >= kPresetCount) return;
    ScanPreset p = kPresets[st.selectedIdx];
    std::vector<uint16_t> ports = App::PortsForPreset(p);

    const int padX     = dpi::Scale(20);
    const int cardX    = padX;
    const int cardW    = W - 2 * padX;
    const int cardPad  = dpi::Scale(14);

    RECT card = { cardX, st.detailTop, cardX + cardW, st.detailBot };
    PaintCardOutline(hdc, card);

    // Clip subsequent paint to the card interior — long preset lists
    // (FullCommon = 231 ports = 77 rows) overflow the card; the
    // scrollbar (WM_VSCROLL handler) shifts content by detailScrollY.
    int saved = SaveDC(hdc);
    RECT clipRc = { card.left + 1, card.top + 1, card.right - 1, card.bottom - 1 };
    IntersectClipRect(hdc, clipRc.left, clipRc.top, clipRc.right, clipRc.bottom);

    int innerL = card.left + cardPad;
    int innerR = card.right - cardPad;
    int yLocal = card.top + dpi::Scale(12) - st.detailScrollY;

    // Header: preset display name + port-count pill
    DrawText_(hdc, { innerL, yLocal, innerR, yLocal + dpi::Scale(24) },
              App::PresetDisplayName(p),
              theme::Fonts().heading,
              theme::Get(theme::Color::TextPrimary),
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    yLocal += dpi::Scale(28);

    // Full description.
    int descH = 0;
    {
        HFONT old = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
        RECT calc{ 0, 0, innerR - innerL, 4000 };
        DrawTextW(hdc, App::PresetDescription(p), -1, &calc,
                  DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
        descH = calc.bottom - calc.top;
        SelectObject(hdc, old);
    }
    DrawText_(hdc, { innerL, yLocal, innerR, yLocal + descH },
              App::PresetDescription(p),
              theme::Fonts().regular,
              theme::Get(theme::Color::TextSecondary),
              DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
    yLocal += descH + dpi::Scale(14);

    // Port grid (3 columns) — only when there are explicit ports.
    if (!ports.empty()) {
        const int colW = (innerR - innerL) / 3;
        HFONT oldF = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().regular));
        SetBkMode(hdc, TRANSPARENT);
        for (size_t i = 0; i < ports.size(); ++i) {
            int row = static_cast<int>(i / 3);
            int col = static_cast<int>(i % 3);
            int cx = innerL + col * colW;
            int cy = yLocal + row * dpi::Scale(20);

            uint16_t port = ports[i];
            wchar_t portTxt[8];
            swprintf_s(portTxt, L"%u", port);

            SetTextColor(hdc, theme::Get(theme::Color::Accent));
            HFONT ofb = static_cast<HFONT>(SelectObject(hdc, theme::Fonts().smallBold));
            RECT rp = { cx, cy, cx + dpi::Scale(48), cy + dpi::Scale(20) };
            DrawTextW(hdc, portTxt, -1, &rp,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(hdc, ofb);

            SetTextColor(hdc, theme::Get(theme::Color::TextSecondary));
            RECT rs = { cx + dpi::Scale(50), cy, cx + colW - dpi::Scale(6),
                        cy + dpi::Scale(20) };
            const wchar_t* svc = App::ServiceForPort(port);
            DrawTextW(hdc, svc, -1, &rs,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        }
        SelectObject(hdc, oldF);
    } else {
        DrawText_(hdc, { innerL, yLocal, innerR, yLocal + dpi::Scale(24) },
                  L"(1 \x2013 65535)  \x2014  enumerated at scan time",
                  theme::Fonts().regular,
                  theme::Get(theme::Color::TextMuted),
                  DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    }

    RestoreDC(hdc, saved);
    (void)H;
}

void UpdateDetailScroll(HWND hwnd) {
    State* st = GetState(hwnd);
    if (!st) return;

    // Re-compute the detail content height for the current preset.
    ScanPreset p = kPresets[st->selectedIdx];
    std::vector<uint16_t> ports = App::PortsForPreset(p);

    HDC dc = GetDC(hwnd);
    HFONT oldF = static_cast<HFONT>(SelectObject(dc, theme::Fonts().regular));
    RECT rcAll; GetClientRect(hwnd, &rcAll);
    int W = rcAll.right;
    int innerW = (W - dpi::Scale(20) * 2) - dpi::Scale(14) * 2;
    RECT calc{ 0, 0, innerW, 4000 };
    DrawTextW(dc, App::PresetDescription(p), -1, &calc,
              DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
    int descH = calc.bottom - calc.top;
    SelectObject(dc, oldF);
    ReleaseDC(hwnd, dc);

    int gridRows = ports.empty() ? 1 : static_cast<int>((ports.size() + 2) / 3);
    int gridH = gridRows * dpi::Scale(20);

    st->detailContentH = dpi::Scale(12) + dpi::Scale(28) + descH + dpi::Scale(14)
                       + gridH + dpi::Scale(14);
    st->detailVisibleH = st->detailBot - st->detailTop;

    SCROLLINFO si{};
    si.cbSize = sizeof(si);
    si.fMask  = SIF_RANGE | SIF_PAGE;
    si.nMin = 0;
    si.nMax = (st->detailContentH > st->detailVisibleH)
                ? (st->detailContentH - 1) : 0;
    si.nPage = st->detailVisibleH;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);

    int maxScroll = (st->detailContentH > st->detailVisibleH)
                      ? (st->detailContentH - st->detailVisibleH) : 0;
    if (st->detailScrollY > maxScroll) st->detailScrollY = maxScroll;
    if (st->detailScrollY < 0)         st->detailScrollY = 0;
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

    const int padX = dpi::Scale(20);
    int y = dpi::Scale(16);
    DrawText_(memDc, { padX, y, W - padX, y + dpi::Scale(28) },
              L"Port lists",
              theme::Fonts().heading,
              theme::Get(theme::Color::TextPrimary),
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    y += dpi::Scale(26);

    DrawText_(memDc, { padX, y, W - padX, y + dpi::Scale(56) },
              L"Each preset's TCP port set is listed below. Pick a row to see the "
              L"full port → service breakdown. Eight UDP discovery probes "
              L"(53/123/137/623/1434/1900/5353/5355) run on Full Common + All "
              L"Ports + Custom presets; printer SNMP runs whenever the preset "
              L"isn't Quick.",
              theme::Fonts().regular,
              theme::Get(theme::Color::TextMuted),
              DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);

    PaintDetail(memDc, *st, W, H);

    BitBlt(hdcWin, 0, 0, W, H, memDc, 0, 0, SRCCOPY);
    SelectObject(memDc, oldB);
    DeleteObject(bmp);
    DeleteDC(memDc);
    EndPaint(hwnd, &ps);
}

void LayoutChildren(HWND hwnd) {
    State* st = GetState(hwnd);
    if (!st) return;
    RECT rcAll; GetClientRect(hwnd, &rcAll);
    int W = rcAll.right;
    int H = rcAll.bottom;

    const int padX = dpi::Scale(20);

    // Disclaimer band sits from y=16+28=44 to ~98; listview starts at 108.
    const int lvY = dpi::Scale(108);
    const int lvH = dpi::Scale(28 + 5 * 22 + 6);   // header + 5 rows + padding
    if (st->hListview) {
        SetWindowPos(st->hListview, nullptr,
                     padX, lvY, W - 2 * padX, lvH, SWP_NOZORDER);
    }

    // Footer: copy + close buttons.
    int btnH = dpi::Scale(32);
    int btnW = dpi::Scale(140);
    int padR = dpi::Scale(20);
    int padB = dpi::Scale(16);
    int by   = H - padB - btnH;

    int xClose = W - padR - dpi::Scale(110);
    int xCopy  = xClose - dpi::Scale(8) - btnW;
    SetWindowPos(st->hClose, nullptr, xClose, by, dpi::Scale(110), btnH, SWP_NOZORDER);
    SetWindowPos(st->hCopy,  nullptr, xCopy,  by, btnW,            btnH, SWP_NOZORDER);

    // Detail card: between the listview and the footer band.
    st->detailTop = lvY + lvH + dpi::Scale(12);
    st->detailBot = by - dpi::Scale(12);

    UpdateDetailScroll(hwnd);
}

void CopyCurrentPorts(HWND hwnd) {
    State* st = GetState(hwnd);
    if (!st || st->selectedIdx < 0 || st->selectedIdx >= kPresetCount) return;
    std::vector<uint16_t> ports = App::PortsForPreset(kPresets[st->selectedIdx]);

    std::wstring text;
    text.reserve(ports.size() * 6);
    for (size_t i = 0; i < ports.size(); ++i) {
        if (i) text.push_back(L',');
        wchar_t buf[12];
        swprintf_s(buf, L"%u", static_cast<unsigned>(ports[i]));
        text += buf;
    }
    if (text.empty()) text = L"1-65535";

    if (!OpenClipboard(hwnd)) return;
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

            st->hListview = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP
                | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER,
                0, 0, 0, 0, hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kId_Listview)),
                hi, nullptr);
            ListView_SetExtendedListViewStyle(st->hListview,
                LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
            SendMessageW(st->hListview, WM_SETFONT,
                         reinterpret_cast<WPARAM>(f), MAKELPARAM(TRUE, 0));

            struct Col { const wchar_t* t; int w; };
            const Col cols[] = {
                { L"Preset",            180 },
                { L"Ports",              80 },
                { L"Extra probes",      170 },
                { L"Description",       260 },
            };
            for (int i = 0; i < static_cast<int>(std::size(cols)); ++i) {
                LVCOLUMNW c{};
                c.mask    = LVCF_TEXT | LVCF_WIDTH;
                c.pszText = const_cast<LPWSTR>(cols[i].t);
                c.cx      = dpi::Scale(cols[i].w);
                ListView_InsertColumn(st->hListview, i, &c);
            }
            PopulateListview(*st);

            auto makeBtn = [&](int id, const wchar_t* label, bool def) -> HWND {
                DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW;
                if (def) style |= BS_DEFPUSHBUTTON;
                HWND h = CreateWindowExW(0, L"BUTTON", label, style,
                    0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                    hi, nullptr);
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f),
                             MAKELPARAM(TRUE, 0));
                return h;
            };
            st->hCopy  = makeBtn(kId_BtnCopy,  L"Copy port list", false);
            st->hClose = makeBtn(kId_BtnClose, L"Close",          true);
            return 0;
        }
        case WM_SIZE:
            LayoutChildren(hwnd);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            PaintBody(hwnd);
            return 0;
        case WM_DRAWITEM: {
            auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
            if (dis->CtlType == ODT_BUTTON) {
                PaintFlatButton(*dis, dis->CtlID == kId_BtnClose);
                return TRUE;
            }
            break;
        }
        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<NMHDR*>(lp);
            if (nm->idFrom == kId_Listview && nm->code == LVN_ITEMCHANGED) {
                auto* p = reinterpret_cast<NMLISTVIEW*>(lp);
                if (p->uChanged & LVIF_STATE) {
                    if (p->uNewState & LVIS_SELECTED) {
                        State* st = GetState(hwnd);
                        if (st) {
                            st->selectedIdx   = p->iItem;
                            st->detailScrollY = 0;
                            UpdateDetailScroll(hwnd);
                            InvalidateRect(hwnd, nullptr, FALSE);
                        }
                    }
                }
            }
            break;
        }
        case WM_VSCROLL: {
            State* st = GetState(hwnd);
            if (!st) return 0;
            int maxScroll = (st->detailContentH > st->detailVisibleH)
                              ? (st->detailContentH - st->detailVisibleH) : 0;
            SCROLLINFO si{};
            si.cbSize = sizeof(si);
            si.fMask  = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            int newY = st->detailScrollY;
            switch (LOWORD(wp)) {
                case SB_LINEUP:        newY -= dpi::Scale(24); break;
                case SB_LINEDOWN:      newY += dpi::Scale(24); break;
                case SB_PAGEUP:        newY -= st->detailVisibleH; break;
                case SB_PAGEDOWN:      newY += st->detailVisibleH; break;
                case SB_THUMBPOSITION:
                case SB_THUMBTRACK:    newY = si.nTrackPos; break;
                case SB_TOP:           newY = 0; break;
                case SB_BOTTOM:        newY = maxScroll; break;
            }
            if (newY < 0)         newY = 0;
            if (newY > maxScroll) newY = maxScroll;
            if (newY != st->detailScrollY) {
                st->detailScrollY = newY;
                si.fMask = SIF_POS;
                si.nPos  = newY;
                SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_MOUSEWHEEL: {
            State* st = GetState(hwnd);
            if (!st) return 0;
            short delta = GET_WHEEL_DELTA_WPARAM(wp);
            int step = dpi::Scale(40);
            int maxScroll = (st->detailContentH > st->detailVisibleH)
                              ? (st->detailContentH - st->detailVisibleH) : 0;
            int newY = st->detailScrollY - (delta * step / WHEEL_DELTA);
            if (newY < 0)         newY = 0;
            if (newY > maxScroll) newY = maxScroll;
            if (newY != st->detailScrollY) {
                st->detailScrollY = newY;
                SCROLLINFO si{};
                si.cbSize = sizeof(si);
                si.fMask  = SIF_POS;
                si.nPos   = newY;
                SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (HIWORD(wp) == BN_CLICKED) {
                if (id == kId_BtnClose) {
                    DestroyWindow(hwnd);
                } else if (id == kId_BtnCopy) {
                    CopyCurrentPorts(hwnd);
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

void PortListsDialog::Show(HWND parent) {
    HINSTANCE hi = App::Instance().Inst();
    EnsureRegistered(hi);

    const int w = dpi::Scale(820);
    const int h = dpi::Scale(660);

    HWND dlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
        kClassName, L"Port lists",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN | WS_VSCROLL,
        CW_USEDEFAULT, CW_USEDEFAULT, w, h,
        parent, nullptr, hi, nullptr);
    if (!dlg) return;
    CenterOn(dlg, parent);

    EnableWindow(parent, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    if (capture::IsAutoCapturing()) {
        capture::AppendWindow(dlg, L"portlists");
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
