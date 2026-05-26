#ifndef NETLENS_ADAPTERS_DIALOG_H
#define NETLENS_ADAPTERS_DIALOG_H

#include <windows.h>
#include <string>

namespace nl {

class AdaptersDialog {
public:
    // Native modal listing adapters from the engine. Returns the suggested
    // range string of the chosen adapter (or empty if the user cancelled).
    static std::wstring Show(HWND parent);
};

}  // namespace nl

#endif // NETLENS_ADAPTERS_DIALOG_H
