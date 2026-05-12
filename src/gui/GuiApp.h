#pragma once

#include <windows.h>

namespace netlens::gui {

/// Owns the WinMain-style message loop for the application. Creates the
/// MainWindow, pumps messages until WM_QUIT, returns the quit code.
class GuiApp {
public:
    static int run(HINSTANCE hInst, int nShowCmd);
};

} // namespace netlens::gui
