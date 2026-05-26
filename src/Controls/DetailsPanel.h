#ifndef NETLENS_DETAILSPANEL_H
#define NETLENS_DETAILSPANEL_H

#include <windows.h>

namespace nl {

// Custom owner-drawn panel showing the selected host's details. Has a small
// row of standard BS_OWNERDRAW action buttons (Ping / Browser / RDP / SSH /
// Telnet / VNC / Copy report) for which it handles WM_DRAWITEM itself.
class DetailsPanel {
public:
    static void   Register(HINSTANCE hInst);
    static HWND   Create(HWND parent, HINSTANCE hInst, int id);
    static const wchar_t* ClassName() { return L"NetLensDetailsPanel"; }

    // Called by MainWindow when the host selection changes. -1 clears.
    static void SetHostIndex(HWND hPanel, int hostIndex);
};

}  // namespace nl

#endif // NETLENS_DETAILSPANEL_H
