#include "AdaptersDialog.h"

#include <commctrl.h>
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

constexpr const wchar_t* kClassName = L"NetLensAdaptersDlg";

constexpr int kId_List   = 4001;
constexpr int kId_BtnUse = 4002;
constexpr int kId_BtnCnc = 4003;

struct State {
    HWND  hList   = nullptr;
    HWND  hUse    = nullptr;
    HWND  hCancel = nullptr;
    std::vector<AdapterInfo> adapters;
    std::wstring result;     // empty = cancelled
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

void PaintHeader(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rcAll; GetClientRect(hwnd, &rcAll);
    const int W = rcAll.right;
    const int H = rcAll.bottom;

    HDC memDc = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldB = static_cast<HBITMAP>(SelectObject(memDc, bmp));

    FillRect(memDc, &rcAll, theme::Brush(theme::Color::Bg));

    const int padX = dpi::Scale(20);
    int y = dpi::Scale(16);

    SetBkMode(memDc, TRANSPARENT);
    HFONT oldF = static_cast<HFONT>(SelectObject(memDc, theme::Fonts().heading));
    SetTextColor(memDc, theme::Get(theme::Color::TextPrimary));
    RECT rT = { padX, y, W - padX, y + dpi::Scale(28) };
    DrawTextW(memDc, L"Network adapters", -1, &rT,
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(memDc, oldF);
    y += dpi::Scale(26);

    SelectObject(memDc, theme::Fonts().regular);
    SetTextColor(memDc, theme::Get(theme::Color::TextMuted));
    RECT rS = { padX, y, W - padX, y + dpi::Scale(20) };
    DrawTextW(memDc, L"Pick an adapter and click \x201CUse this\x201D \x2014 the range box on the toolbar updates.",
              -1, &rS, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

    BitBlt(hdc, 0, 0, W, H, memDc, 0, 0, SRCCOPY);
    SelectObject(memDc, oldB);
    DeleteObject(bmp);
    DeleteDC(memDc);
    EndPaint(hwnd, &ps);
}

void DoLayout(HWND hwnd) {
    State* st = GetState(hwnd);
    if (!st) return;
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    const int padX = dpi::Scale(20);
    const int headerH = dpi::Scale(60);
    const int btnH   = dpi::Scale(32);
    const int btnW   = dpi::Scale(110);
    const int padB   = dpi::Scale(14);

    int listY = headerH;
    int listH = H - headerH - btnH - padB * 2;
    SetWindowPos(st->hList, nullptr, padX, listY, W - 2 * padX, listH, SWP_NOZORDER);

    int by = H - padB - btnH;
    int xUse    = W - padX - btnW;
    int xCancel = xUse - dpi::Scale(8) - btnW;
    SetWindowPos(st->hCancel, nullptr, xCancel, by, btnW, btnH, SWP_NOZORDER);
    SetWindowPos(st->hUse,    nullptr, xUse,    by, btnW, btnH, SWP_NOZORDER);
}

void PopulateList(State& st) {
    st.adapters = App::Instance().Adapters();
    ListView_DeleteAllItems(st.hList);

    int row = 0;
    for (const auto& a : st.adapters) {
        LVITEMW it{};
        it.mask     = LVIF_TEXT | LVIF_PARAM;
        it.iItem    = row;
        it.iSubItem = 0;
        it.lParam   = row;
        std::wstring name = a.friendlyName.empty() ? a.description : a.friendlyName;
        it.pszText  = const_cast<LPWSTR>(name.c_str());
        int idx = ListView_InsertItem(st.hList, &it);

        ListView_SetItemText(st.hList, idx, 1, const_cast<LPWSTR>(a.ip.c_str()));
        ListView_SetItemText(st.hList, idx, 2, const_cast<LPWSTR>(a.subnet.c_str()));
        ListView_SetItemText(st.hList, idx, 3, const_cast<LPWSTR>(a.gateway.c_str()));
        const wchar_t* status = a.operational ? L"Up" : L"Down";
        ListView_SetItemText(st.hList, idx, 4, const_cast<LPWSTR>(status));
        ++row;
    }

    // Pre-select the first operational non-loopback adapter, fall back to row 0.
    int preselect = -1;
    for (size_t i = 0; i < st.adapters.size(); ++i) {
        if (st.adapters[i].operational && st.adapters[i].type != 3
            && !st.adapters[i].suggestedRange.empty()) {
            preselect = static_cast<int>(i); break;
        }
    }
    if (preselect < 0 && !st.adapters.empty()) preselect = 0;
    if (preselect >= 0) {
        ListView_SetItemState(st.hList, preselect,
                              LVIS_FOCUSED | LVIS_SELECTED,
                              LVIS_FOCUSED | LVIS_SELECTED);
        ListView_EnsureVisible(st.hList, preselect, FALSE);
    }
}

// Stashed across DestroyWindow → outer Show() reads it after the modal loop.
// Single-instance dialog, so a namespace-local is safe.
std::wstring g_chosenRange;

void Accept(HWND hwnd) {
    State* st = GetState(hwnd);
    if (!st) return;
    int sel = ListView_GetNextItem(st->hList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= static_cast<int>(st->adapters.size())) return;
    std::wstring chosen = st->adapters[sel].suggestedRange;
    if (chosen.empty()) {
        // Build a /24 from the IP if the engine didn't supply a range.
        const std::wstring& ip = st->adapters[sel].ip;
        size_t lastDot = ip.find_last_of(L'.');
        if (lastDot != std::wstring::npos) {
            std::wstring prefix = ip.substr(0, lastDot);
            chosen = prefix + L".1-" + prefix + L".254";
        }
    }
    g_chosenRange = chosen;
    st->result = chosen;
    DestroyWindow(hwnd);
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

            st->hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP
                | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER,
                0, 0, 0, 0, hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kId_List)), hi, nullptr);
            ListView_SetExtendedListViewStyle(st->hList,
                LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
            SendMessageW(st->hList, WM_SETFONT, reinterpret_cast<WPARAM>(f), MAKELPARAM(TRUE, 0));

            struct Col { const wchar_t* t; int w; };
            const Col cols[] = {
                { L"Name",    220 },
                { L"IPv4",    120 },
                { L"Mask",    120 },
                { L"Gateway", 120 },
                { L"Status",   60 }
            };
            for (int i = 0; i < static_cast<int>(std::size(cols)); ++i) {
                LVCOLUMNW c{};
                c.mask    = LVCF_TEXT | LVCF_WIDTH;
                c.pszText = const_cast<LPWSTR>(cols[i].t);
                c.cx      = dpi::Scale(cols[i].w);
                ListView_InsertColumn(st->hList, i, &c);
            }

            auto makeBtn = [&](int id, const wchar_t* label, bool def) -> HWND {
                DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW;
                if (def) style |= BS_DEFPUSHBUTTON;
                HWND h = CreateWindowExW(0, L"BUTTON", label, style,
                    0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                    hi, nullptr);
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), MAKELPARAM(TRUE, 0));
                return h;
            };
            st->hCancel = makeBtn(kId_BtnCnc, L"Cancel",   false);
            st->hUse    = makeBtn(kId_BtnUse, L"Use this", true);

            PopulateList(*st);
            return 0;
        }
        case WM_SIZE:
            DoLayout(hwnd);
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            PaintHeader(hwnd);
            return 0;
        case WM_DRAWITEM: {
            auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
            if (dis->CtlType == ODT_BUTTON) {
                PaintFlatButton(*dis, dis->CtlID == kId_BtnUse);
                return TRUE;
            }
            break;
        }
        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<NMHDR*>(lp);
            if (nm->idFrom == kId_List && nm->code == NM_DBLCLK) {
                Accept(hwnd);
                return 0;
            }
            break;
        }
        case WM_COMMAND: {
            if (HIWORD(wp) == BN_CLICKED) {
                int id = LOWORD(wp);
                if (id == kId_BtnUse)        Accept(hwnd);
                else if (id == kId_BtnCnc)   DestroyWindow(hwnd);
            }
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_NCDESTROY: {
            // result_ is captured by Show() before DestroyWindow; freeing here.
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

std::wstring AdaptersDialog::Show(HWND parent) {
    HINSTANCE hi = App::Instance().Inst();
    EnsureRegistered(hi);

    const int w = dpi::Scale(700);
    const int h = dpi::Scale(440);

    HWND dlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
        kClassName, L"Network adapters",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, w, h,
        parent, nullptr, hi, nullptr);
    if (!dlg) return {};
    CenterOn(dlg, parent);

    EnableWindow(parent, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    g_chosenRange.clear();  // reset before showing

    if (capture::IsAutoCapturing()) {
        capture::AppendWindow(dlg, L"adapters");
        DestroyWindow(dlg);
        EnableWindow(parent, TRUE);
        SetForegroundWindow(parent);
        return g_chosenRange;
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
    return g_chosenRange;
}

}  // namespace nl
