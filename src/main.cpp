// =============================================================================
// NetLens - entry point  (v1.0.2 — GUI subsystem)
//
// We build as the **Windows GUI subsystem** so the OS never allocates a
// console for this process. GUI launches are truly flash-free.
//
// CLI mode: we AttachConsole(ATTACH_PARENT_PROCESS) when --help / --range /
// other CLI args are present. That plugs stdout/stderr into the calling
// terminal (cmd, PowerShell, Windows Terminal). When there is no parent
// console (Explorer launch of a CLI-args shortcut, or a tool that captures
// stdout differently), AllocConsole opens a fresh window. Either way the
// user gets CLI output.
//
// Note on PowerShell redirection: PowerShell does NOT wait for GUI-subsystem
// processes to exit, so `NetLens.exe --help | head` won't pipe cleanly
// from PowerShell. For piping use `cmd /c NetLens.exe --help | head`,
// or run the .exe from cmd.exe directly. Interactive CLI output (no pipe)
// works from any shell because the AttachConsole path writes to the
// terminal directly.
// =============================================================================

#include <windows.h>
#include <winsock2.h>
#include <shellapi.h>

#include <fcntl.h>
#include <io.h>
#include <stdio.h>

#include <string>
#include <vector>

#include "AppConstants.h"
#include "cli/CliApp.h"
#include "cli/CommandLineParser.h"
#include "gui/GuiApp.h"

namespace {

// Wires stdout / stderr / stdin to whichever console handle is available —
// the parent process's console if there is one, otherwise a freshly
// allocated console of our own. Idempotent; returns true on success.
bool attachOrCreateConsole() {
    bool attached = ::AttachConsole(ATTACH_PARENT_PROCESS) != FALSE;
    if (!attached) {
        // No parent console (e.g. launched from Explorer with saved args).
        // Allocate a private one so CLI output still has a destination.
        attached = ::AllocConsole() != FALSE;
    }
    if (!attached) return false;

    // Re-bind the CRT stdio streams to the new console handles. Without this
    // step printf / fputws / std::wcout still target the (closed) GUI stdio
    // and the user sees nothing.
    FILE* fp = nullptr;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$",  "r", stdin);

    // UTF-16 output so std::fputws emits proper wide-char text.
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);

    // Print a newline so the parent shell's prompt doesn't sit on the same
    // line as our first line of output (cosmetic).
    return true;
}

// Send a synthetic Enter to the attached console once we're done, so the
// parent shell's prompt redraws cleanly on its own line. Strictly cosmetic.
void nudgeParentPrompt() {
    INPUT_RECORD ir[2]{};
    ir[0].EventType = KEY_EVENT;
    ir[0].Event.KeyEvent.bKeyDown = TRUE;
    ir[0].Event.KeyEvent.wRepeatCount = 1;
    ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
    ir[0].Event.KeyEvent.uChar.UnicodeChar = L'\r';
    ir[1] = ir[0];
    ir[1].Event.KeyEvent.bKeyDown = FALSE;

    HANDLE hIn = ::GetStdHandle(STD_INPUT_HANDLE);
    if (hIn && hIn != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ::WriteConsoleInputW(hIn, ir, 2, &written);
    }
}

} // anonymous namespace

int APIENTRY wWinMain(HINSTANCE hInstance,
                      HINSTANCE /*hPrevInstance*/,
                      LPWSTR    /*lpCmdLine*/,
                      int       /*nCmdShow*/)
{
    // Winsock 2.2 — required by every network service we use.
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        ::MessageBoxW(nullptr,
                      L"Winsock initialisation failed.",
                      L"NetLens",
                      MB_OK | MB_ICONERROR);
        return -1;
    }

    // Parse the command line. wWinMain doesn't see argc/argv directly, so we
    // pull them from GetCommandLineW via the shell helper.
    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (!argv) {
        ::WSACleanup();
        return -1;
    }

    int rc = 0;
    auto parsed = netlens::CommandLineParser::parse(argc, argv);

    if (parsed.wantsCli() || parsed.hasError) {
        // CLI mode: take over the parent terminal.
        if (attachOrCreateConsole()) {
            std::fputws(L"\n", stdout);  // newline before our first output
        }
        rc = netlens::CliApp::run(argc, argv);
        nudgeParentPrompt();
        ::FreeConsole();
    } else {
        // GUI mode: zero console flash because we never had one to begin with.
        rc = netlens::gui::GuiApp::run(hInstance, SW_SHOW);
    }

    ::LocalFree(argv);
    ::WSACleanup();
    return rc;
}
