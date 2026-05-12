#include "GuiControls.h"

namespace netlens::gui {

bool initCommonControls() {
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS |
                 ICC_STANDARD_CLASSES | ICC_BAR_CLASSES;
    return ::InitCommonControlsEx(&icc) != FALSE;
}

void lvAddColumn(HWND list, int index, const wchar_t* text, int widthPx) {
    LVCOLUMNW col{};
    col.mask     = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
    col.fmt      = LVCFMT_LEFT;
    col.cx       = widthPx;
    col.pszText  = const_cast<LPWSTR>(text);
    col.iSubItem = index;
    ListView_InsertColumn(list, index, &col);
}

int lvAddRow(HWND list, const std::vector<std::wstring>& cells) {
    if (cells.empty()) return -1;
    LVITEMW item{};
    item.mask    = LVIF_TEXT;
    item.iItem   = ListView_GetItemCount(list);
    item.pszText = const_cast<LPWSTR>(cells[0].c_str());
    int row = ListView_InsertItem(list, &item);
    if (row < 0) return -1;
    for (size_t i = 1; i < cells.size(); ++i) {
        ListView_SetItemText(list, row, static_cast<int>(i),
                             const_cast<LPWSTR>(cells[i].c_str()));
    }
    return row;
}

void lvUpdateRow(HWND list, int row, const std::vector<std::wstring>& cells) {
    if (row < 0) return;
    for (size_t i = 0; i < cells.size(); ++i) {
        ListView_SetItemText(list, row, static_cast<int>(i),
                             const_cast<LPWSTR>(cells[i].c_str()));
    }
}

void lvClear(HWND list) {
    ListView_DeleteAllItems(list);
}

void cbFill(HWND combo, const std::vector<std::wstring>& items, int selectedIndex) {
    ::SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    for (const auto& s : items) {
        ::SendMessageW(combo, CB_ADDSTRING, 0,
                       reinterpret_cast<LPARAM>(s.c_str()));
    }
    if (!items.empty() && selectedIndex >= 0 &&
        selectedIndex < static_cast<int>(items.size()))
    {
        ::SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(selectedIndex), 0);
    }
}

int cbSelectedIndex(HWND combo) {
    LRESULT v = ::SendMessageW(combo, CB_GETCURSEL, 0, 0);
    if (v == CB_ERR) return -1;
    return static_cast<int>(v);
}

std::wstring cbSelectedText(HWND combo) {
    int idx = cbSelectedIndex(combo);
    if (idx < 0) return L"";
    LRESULT len = ::SendMessageW(combo, CB_GETLBTEXTLEN, idx, 0);
    if (len <= 0) return L"";
    std::wstring buf(static_cast<size_t>(len), L'\0');
    ::SendMessageW(combo, CB_GETLBTEXT, idx, reinterpret_cast<LPARAM>(buf.data()));
    return buf;
}

void pbConfigure(HWND pb, int max) {
    if (max <= 0) max = 1;
    ::SendMessageW(pb, PBM_SETRANGE32, 0, max);
    ::SendMessageW(pb, PBM_SETPOS, 0, 0);
}

void pbSetValue(HWND pb, int value) {
    if (value < 0) value = 0;
    ::SendMessageW(pb, PBM_SETPOS, static_cast<WPARAM>(value), 0);
}

} // namespace netlens::gui
