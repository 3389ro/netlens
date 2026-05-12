#pragma once

#include <windows.h>

#include <string>

namespace netlens::gui {

/// DPI-aware helpers and convenience routines used across the GUI layer.

/// Returns the per-monitor DPI for the window, falling back to system DPI
/// when called before HWND creation.
int dpiFor(HWND hwnd);

/// Scales a design pixel value (at 96 DPI) for the current DPI of the window.
inline int scale(HWND hwnd, int designPx) {
    return MulDiv(designPx, dpiFor(hwnd), 96);
}

/// Wraps SetWindowText. Convenience: works with std::wstring directly.
inline void setText(HWND hwnd, const std::wstring& s) {
    ::SetWindowTextW(hwnd, s.c_str());
}

/// Wraps GetWindowText. Returns an empty string on failure.
std::wstring getText(HWND hwnd);

/// Creates the standard application font (Segoe UI) at the given point size,
/// scaled for the window's DPI. Caller takes ownership and must DeleteObject.
HFONT createUiFont(HWND parent, int pointSize, bool bold = false);

/// Returns a SHA-of-nothing — actually a process-wide brush cache for the
/// given RGB so we don't leak GDI objects. Brushes live until process exit.
HBRUSH cachedSolidBrush(COLORREF rgb);

/// Prompts for a save file path. Returns an empty string on cancel.
std::wstring promptSaveAs(HWND parent, const wchar_t* title,
                          const wchar_t* defaultName,
                          const wchar_t* filter);

/// Opens an explorer/shell select for the given file (used after export).
void revealInExplorer(const std::wstring& path);

/// Posts a status-bar message to the main window. Allocates a wide string
/// that the GUI will free when handling WM_NL_STATUS.
void postStatusMessage(HWND mainWnd, const std::wstring& msg);

} // namespace netlens::gui
