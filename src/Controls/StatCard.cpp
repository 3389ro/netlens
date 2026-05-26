#include "StatCard.h"

#include <string>

#include "../Dpi.h"
#include "../Theme.h"

namespace nl {

namespace {

#define WM_SC_SET_LABEL     (WM_USER + 1)
#define WM_SC_SET_VALUE     (WM_USER + 2)
#define WM_SC_SET_SECONDARY (WM_USER + 3)
#define WM_SC_SET_ACCENT    (WM_USER + 4)

struct Data {
    std::wstring label;
    std::wstring value;
    std::wstring secondary;
    COLORREF     accent = RGB(0x2E, 0x5B, 0xFF);
};

Data* GetData(HWND hwnd) {
    return reinterpret_cast<Data*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void Paint(HWND hwnd) {
    Data* d = GetData(hwnd);
    if (!d) return;

    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc; GetClientRect(hwnd, &rc);
    const int W = rc.right  - rc.left;
    const int H = rc.bottom - rc.top;

    // Double buffer
    HDC     memDc = CreateCompatibleDC(hdc);
    HBITMAP bmp   = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldB  = static_cast<HBITMAP>(SelectObject(memDc, bmp));

    // Surface fill
    HBRUSH brSurf = theme::Brush(theme::Color::Surface);
    FillRect(memDc, &rc, brSurf);

    // Accent strip on the left
    const int stripW = dpi::Scale(4);
    RECT rcStrip = { 0, 0, stripW, H };
    HBRUSH brAccent = CreateSolidBrush(d->accent);
    FillRect(memDc, &rcStrip, brAccent);
    DeleteObject(brAccent);

    // 1-px border around the card
    HPEN penBorder = CreatePen(PS_SOLID, 1, theme::Get(theme::Color::Border));
    HPEN oldPen = static_cast<HPEN>(SelectObject(memDc, penBorder));
    HBRUSH oldBr = static_cast<HBRUSH>(SelectObject(memDc, GetStockObject(NULL_BRUSH)));
    Rectangle(memDc, 0, 0, W, H);
    SelectObject(memDc, oldBr);
    SelectObject(memDc, oldPen);
    DeleteObject(penBorder);

    // Text layout — sequential top-down, NO bottom anchoring (M4.5 fix:
    // previously the secondary line was bottom-anchored and overlapped the
    // big value text in cards under ~80 px tall).
    const int padL = stripW + dpi::Scale(14);
    const int padR = dpi::Scale(14);

    SetBkMode(memDc, TRANSPARENT);

    const auto& fonts = theme::Fonts();
    int y = dpi::Scale(12);

    // Label (uppercase muted, ~8 pt bold)
    HFONT oldF = static_cast<HFONT>(SelectObject(memDc, fonts.label));
    SetTextColor(memDc, theme::Get(theme::Color::TextMuted));
    RECT rcLabel = { padL, y, W - padR, y + dpi::Scale(14) };
    DrawTextW(memDc, d->label.c_str(), -1, &rcLabel,
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    y += dpi::Scale(18);   // 14 px label + 4 px gap

    // Value (~17 pt bold, accent-coloured)
    SelectObject(memDc, fonts.big);
    SetTextColor(memDc, d->accent);
    RECT rcValue = { padL, y, W - padR, y + dpi::Scale(28) };
    DrawTextW(memDc, d->value.c_str(), -1, &rcValue,
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    y += dpi::Scale(30);   // 28 px value + 2 px gap

    // Secondary (small muted, single line). Only drawn if there's room.
    if (!d->secondary.empty() && y + dpi::Scale(14) <= H - dpi::Scale(4)) {
        SelectObject(memDc, fonts.smallFont);
        SetTextColor(memDc, theme::Get(theme::Color::TextMuted));
        RECT rcSec = { padL, y, W - padR, y + dpi::Scale(14) };
        DrawTextW(memDc, d->secondary.c_str(), -1, &rcSec,
                  DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    }

    SelectObject(memDc, oldF);

    // Blit
    BitBlt(hdc, 0, 0, W, H, memDc, 0, 0, SRCCOPY);
    SelectObject(memDc, oldB);
    DeleteObject(bmp);
    DeleteDC(memDc);

    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK Proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_NCCREATE: {
            Data* d = new Data();
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(d));
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_NCDESTROY: {
            if (Data* d = GetData(hwnd)) {
                delete d;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_ERASEBKGND:
            return 1;  // we paint everything in WM_PAINT
        case WM_PAINT:
            Paint(hwnd);
            return 0;

        case WM_SC_SET_LABEL: {
            if (Data* d = GetData(hwnd)) {
                d->label = reinterpret_cast<const wchar_t*>(lp);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_SC_SET_VALUE: {
            if (Data* d = GetData(hwnd)) {
                d->value = reinterpret_cast<const wchar_t*>(lp);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_SC_SET_SECONDARY: {
            if (Data* d = GetData(hwnd)) {
                d->secondary = reinterpret_cast<const wchar_t*>(lp);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_SC_SET_ACCENT: {
            if (Data* d = GetData(hwnd)) {
                d->accent = static_cast<COLORREF>(wp);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

void StatCard::Register(HINSTANCE hInst) {
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

HWND StatCard::Create(HWND parent, HINSTANCE hInst, int id) {
    return CreateWindowExW(
        0, ClassName(), L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        hInst, nullptr);
}

void StatCard::SetLabel(HWND h, const wchar_t* s) {
    SendMessageW(h, WM_SC_SET_LABEL, 0, reinterpret_cast<LPARAM>(s));
}
void StatCard::SetValue(HWND h, const wchar_t* s) {
    SendMessageW(h, WM_SC_SET_VALUE, 0, reinterpret_cast<LPARAM>(s));
}
void StatCard::SetSecondary(HWND h, const wchar_t* s) {
    SendMessageW(h, WM_SC_SET_SECONDARY, 0, reinterpret_cast<LPARAM>(s));
}
void StatCard::SetAccent(HWND h, COLORREF rgb) {
    SendMessageW(h, WM_SC_SET_ACCENT, static_cast<WPARAM>(rgb), 0);
}

}  // namespace nl
