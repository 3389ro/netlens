#ifndef NETLENS_ABOUT_DIALOG_H
#define NETLENS_ABOUT_DIALOG_H

#include <windows.h>

namespace nl {

class AboutDialog {
public:
    // Native Win32 modal dialog. Disables `parent`, runs its own message
    // loop, re-enables `parent` on close. Not a MessageBox.
    static void Show(HWND parent);
};

}  // namespace nl

#endif // NETLENS_ABOUT_DIALOG_H
