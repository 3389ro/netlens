#ifndef NETLENS_STATCARD_H
#define NETLENS_STATCARD_H

#include <windows.h>

namespace nl {

// A single KPI card: 4-px accent strip on the left, uppercase label on top,
// big value below, optional secondary line. White surface with thin border.
class StatCard {
public:
    static void   Register(HINSTANCE hInst);
    static HWND   Create(HWND parent, HINSTANCE hInst, int id);
    static const wchar_t* ClassName() { return L"NetLensStatCard"; }

    // Setters (send custom WM_USER messages internally).
    static void SetLabel(HWND hCard, const wchar_t* label);
    static void SetValue(HWND hCard, const wchar_t* value);
    static void SetSecondary(HWND hCard, const wchar_t* secondary);
    static void SetAccent(HWND hCard, COLORREF accentRgb);
};

}  // namespace nl

#endif // NETLENS_STATCARD_H
