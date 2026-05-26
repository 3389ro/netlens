#ifndef NETLENS_MAINWINDOW_H
#define NETLENS_MAINWINDOW_H

#include <windows.h>

namespace nl {

// Custom WM_APP messages the scanner thread posts to MainWindow.
//   WM_NL_APPLY_SNAPSHOT — lParam = heap-allocated nl::EngineSnapshot*.
//                          UI takes ownership, feeds App::ApplySnapshot,
//                          deletes.
//   WM_NL_SCAN_FINISHED  — scanner thread saw isRunning flip to false.
//                          UI runs final sync + tiered-phase transition.
constexpr UINT WM_NL_APPLY_SNAPSHOT = WM_APP + 5;
constexpr UINT WM_NL_SCAN_FINISHED  = WM_APP + 6;

class MainWindow {
public:
    static void Register(HINSTANCE hInst);
    static HWND Create(HINSTANCE hInst, int nCmdShow);
    static const wchar_t* ClassName() { return L"NetLensMain"; }
};

}  // namespace nl

#endif // NETLENS_MAINWINDOW_H
