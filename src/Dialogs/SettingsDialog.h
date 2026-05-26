#ifndef NETLENS_SETTINGS_DIALOG_H
#define NETLENS_SETTINGS_DIALOG_H

#include <windows.h>

namespace nl {

class SettingsDialog {
public:
    // Native modal. Reads from App::Settings() on open, writes back on OK.
    // Session-only — no disk persistence.
    static void Show(HWND parent);
};

}  // namespace nl

#endif // NETLENS_SETTINGS_DIALOG_H
