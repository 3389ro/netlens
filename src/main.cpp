// main.cpp — Win32 entry point for NetLens.win32.
//
// Sets process DPI awareness, initializes COM + common controls, builds the
// global App singleton, registers custom window classes, and pumps the
// message loop until the main window is destroyed.

#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include <shellapi.h>  // CommandLineToArgvW for --mock
// GDI+ needs std::min/max + PROPID before its headers. NOMINMAX is defined
// globally so we have to bring the std versions into the gdiplus namespace
// search scope, and <objidl.h> declares PROPID for GdiplusImaging.h.
#include <algorithm>
using std::min;
using std::max;
#include <objidl.h>
#include <gdiplus.h>

#include "../Resource.h"
#include "App.h"
#include "Dpi.h"
#include "Theme.h"
#include "MainWindow.h"
#include "Controls/DetailsPanel.h"
#include "Controls/StatCard.h"

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE /*hPrev*/, LPWSTR /*cmd*/, int nCmdShow) {
    // DPI awareness — legacy-Windows safe.
    //
    // `SetProcessDpiAwarenessContext` (Win 10 1703+) and `SetProcessDpiAwareness`
    // (shcore.dll, Win 8.1+) are newer APIs. On Windows Server 2012 / Win 7
    // they don't exist; statically linking against them makes the EXE
    // unloadable. Resolve each via GetProcAddress, walking the tiers from
    // newest to oldest, and fall back to the always-present
    // `SetProcessDPIAware` (user32, Vista+) if nothing else worked.
    //
    // app.manifest already declares PerMonitorV2; the runtime calls below
    // are a safety net for builds with a stripped manifest.
    using PFN_Set_v2     = BOOL (WINAPI*)(DPI_AWARENESS_CONTEXT);
    using PFN_Set_v1     = HRESULT (WINAPI*)(int /*PROCESS_DPI_AWARENESS*/);
    using PFN_Set_legacy = BOOL (WINAPI*)(void);
    bool dpiSet = false;
    if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
        auto fn = reinterpret_cast<PFN_Set_v2>(
            GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (fn) {
            fn(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            dpiSet = true;
        }
    }
    if (!dpiSet) {
        if (HMODULE shcore = LoadLibraryW(L"shcore.dll")) {
            auto fn = reinterpret_cast<PFN_Set_v1>(
                GetProcAddress(shcore, "SetProcessDpiAwareness"));
            if (fn) { fn(2 /* PROCESS_PER_MONITOR_DPI_AWARE */); dpiSet = true; }
            // intentionally leak the handle — process-lifetime
        }
    }
    if (!dpiSet) {
        if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
            auto fn = reinterpret_cast<PFN_Set_legacy>(
                GetProcAddress(user32, "SetProcessDPIAware"));
            if (fn) fn();
        }
    }

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    // GDI+ initialised for PNG capture (Ctrl+T).
    Gdiplus::GdiplusStartupInput gdiInput;
    ULONG_PTR gdiplusToken = 0;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiInput, nullptr);

    INITCOMMONCONTROLSEX icex{};
    icex.dwSize = sizeof(icex);
    icex.dwICC  = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS
                | ICC_BAR_CLASSES      | ICC_STANDARD_CLASSES
                | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icex);

    // Bootstrap palette + fonts at the system DPI; MainWindow refines
    // once it has its real HWND in WM_CREATE. The compat wrapper is
    // required so the binary loads on Windows Server 2012 / Win 7/8/8.1
    // (the raw GetDpiForSystem is a Win10 1607+ user32 export).
    nl::dpi::Update(nl::dpi::GetDpiForSystemCompat());
    nl::theme::Init(nl::dpi::g_dpi);

    nl::App::Instance().Init(hInst);

    // --mock — feed a hard-coded 15-host fleet from MockData.cpp instead of
    // calling the engine on Start scan. Used only to generate documentation
    // screenshots; not advertised in the menu or About dialog. Parsed from
    // GetCommandLineW so we don't have to wrap argv ourselves.
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv) {
            for (int i = 1; i < argc; ++i) {
                if (lstrcmpiW(argv[i], L"--mock") == 0
                    || lstrcmpiW(argv[i], L"/mock") == 0) {
                    nl::App::Instance().SetMockMode(true);
                    break;
                }
            }
            LocalFree(argv);
        }
    }

    nl::StatCard::Register(hInst);
    nl::DetailsPanel::Register(hInst);
    nl::MainWindow::Register(hInst);

    HWND hMain = nl::MainWindow::Create(hInst, nCmdShow);
    if (!hMain) {
        nl::theme::Shutdown();
        CoUninitialize();
        return 1;
    }

    HACCEL hAccel = LoadAcceleratorsW(hInst, MAKEINTRESOURCEW(IDR_ACCEL));

    MSG msg;
    int ret;
    while ((ret = GetMessageW(&msg, nullptr, 0, 0)) != 0) {
        if (ret == -1) break;

        // Global Ctrl+T — route to the main window regardless of which of our
        // top-level windows has focus right now (the modal About / Settings /
        // Adapters / PortLists dialogs don't propagate accelerator translation
        // up to hMain otherwise, so Ctrl+T silently dropped while a dialog was
        // up). DoCapture itself enumerates every visible top-level window in
        // this process, so one press still grabs the dialog + main pair.
        if (msg.message == WM_KEYDOWN
            && msg.wParam == 'T'
            && (GetKeyState(VK_CONTROL) & 0x8000)) {
            PostMessageW(hMain, WM_COMMAND, IDM_TOOLS_CAPTURE, 0);
            continue;
        }

        if (!hAccel || !TranslateAcceleratorW(hMain, hAccel, &msg)) {
            if (!IsDialogMessageW(hMain, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    nl::App::Instance().Shutdown();
    nl::theme::Shutdown();
    Gdiplus::GdiplusShutdown(gdiplusToken);
    CoUninitialize();
    return static_cast<int>(msg.wParam);
}
