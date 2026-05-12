#pragma once

#include <windows.h>
#include <commctrl.h>

#include "../Models.h"

#include <string>
#include <vector>

namespace netlens::gui {

/// Thin helpers for the Common Controls we use — keeps MainWindow tidy.

/// Initialise ComCtl32 for the controls we need. Call once at startup.
bool initCommonControls();

/// Adds a column to a report-mode ListView.
void lvAddColumn(HWND list, int index, const wchar_t* text, int widthPx);

/// Appends a row to a report-mode ListView. Returns the new row index.
int  lvAddRow(HWND list, const std::vector<std::wstring>& cells);

/// Updates the text of an existing row.
void lvUpdateRow(HWND list, int row, const std::vector<std::wstring>& cells);

/// Convenience: clears every row from the ListView.
void lvClear(HWND list);

/// Fills a combo box from a list of strings and selects index 0.
void cbFill(HWND combo, const std::vector<std::wstring>& items, int selectedIndex = 0);

/// Returns the currently selected index, or -1 if none.
int  cbSelectedIndex(HWND combo);

/// Returns the currently selected text. Empty string if none.
std::wstring cbSelectedText(HWND combo);

/// Sets the progress bar range and current value.
void pbConfigure(HWND pb, int max);
void pbSetValue(HWND pb, int value);

} // namespace netlens::gui
