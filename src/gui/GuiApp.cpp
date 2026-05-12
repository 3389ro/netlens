#include "GuiApp.h"

#include "GuiControls.h"
#include "MainWindow.h"

#include <memory>

namespace netlens::gui {

int GuiApp::run(HINSTANCE hInst, int nShowCmd) {
    if (!initCommonControls()) {
        ::MessageBoxW(nullptr,
                      L"Failed to initialise common controls.",
                      L"NetLens",
                      MB_OK | MB_ICONERROR);
        return -1;
    }

    auto mainWnd = std::make_unique<MainWindow>();
    if (!mainWnd->create(hInst)) {
        ::MessageBoxW(nullptr,
                      L"Failed to create the application window.",
                      L"NetLens",
                      MB_OK | MB_ICONERROR);
        return -1;
    }
    mainWnd->show(nShowCmd);

    MSG msg{};
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        // IsDialogMessage gives us tab navigation between controls.
        if (!::IsDialogMessageW(mainWnd->hwnd(), &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }
    return static_cast<int>(msg.wParam);
}

} // namespace netlens::gui
