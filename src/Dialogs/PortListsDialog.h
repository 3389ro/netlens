#ifndef NETLENS_PORTLISTS_DIALOG_H
#define NETLENS_PORTLISTS_DIALOG_H

#include <windows.h>

namespace nl {

class PortListsDialog {
public:
    // Native modal. Scrolls. Port data comes from App::PortsForPreset() —
    // the same arrays the scanner CSV is built from.
    static void Show(HWND parent);
};

}  // namespace nl

#endif // NETLENS_PORTLISTS_DIALOG_H
