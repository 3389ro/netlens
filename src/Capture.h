#ifndef NETLENS_CAPTURE_H
#define NETLENS_CAPTURE_H

#include <windows.h>
#include <string>

// Screenshot helpers shared between MainWindow and the modal dialogs.
//
// - SaveWindowPng() takes a one-off PNG of any window.
// - AppendWindow() pairs that with a session folder ("captures-<ts>/") and
//   sequential numbering so a single Ctrl+T press can fire many captures.
// - The "auto-capturing" flag lets each modal dialog detect that it's been
//   opened as part of a Ctrl+T full-UI sweep — in that case it captures
//   itself right after first paint and destroys itself instead of entering
//   the user-facing modal pump.

namespace nl {
namespace capture {

// Save the given window as a PNG using PrintWindow + GDI+. Returns true on
// success. The window does not have to be the foreground window —
// PW_RENDERFULLCONTENT covers DWM-composited windows.
bool SaveWindowPng(HWND hwnd, const std::wstring& path);

// Reset the session — next AppendWindow() will create a fresh
// captures-<ts>/ folder next to the exe.
void ResetSession();

// Lazily-created session folder. Empty string before the first capture.
const std::wstring& SessionFolder();

// Save hwnd into the current session folder as
//     NN-<tag>.png
// where NN auto-increments per call. Returns true on success.
bool AppendWindow(HWND hwnd, const wchar_t* tag);

// "Auto-capturing" flag — set by MainWindow before opening a dialog as
// part of a Ctrl+T sweep, checked by each dialog's Show() to short-circuit
// the modal pump.
bool IsAutoCapturing();
void SetAutoCapturing(bool b);

}  // namespace capture
}  // namespace nl

#endif  // NETLENS_CAPTURE_H
