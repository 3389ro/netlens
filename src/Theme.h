#ifndef NETLENS_THEME_H
#define NETLENS_THEME_H

#include <windows.h>
#include <cstdint>

namespace nl::theme {

// Light theme palette — enterprise look (white surfaces, accent blue).
enum class Color : uint8_t {
    Bg,                 // #F5F7FA   window background
    Surface,            // #FFFFFF   card/panel surface
    SurfaceAlt,         // #F0F3F7   alt surface
    Border,             // #E3E8EE   thin borders
    Divider,            // #F0F3F7   grid lines
    Hover,              // #F1F4F8

    TextPrimary,        // #0F1B2D
    TextSecondary,      // #2F3D52
    TextMuted,          // #5C6B80
    TextInverse,        // #FFFFFF

    Accent,             // #2E5BFF
    AccentHover,        // #1F49E0
    AccentSurface,      // #E5ECFF
    Success,            // #2EA044
    SuccessSurface,     // #E9F5EC
    Warning,            // #D97706
    WarningSurface,     // #FEF3C7
    Danger,             // #C0392B
    DangerSurface,      // #FEE2E2
    Info,               // #2980B9
    InfoSurface,        // #DCEAF4
    Neutral,            // #95A5A6
    NeutralSurface,     // #DDE3EA

    TableHeader,        // #E8EDF3
    TableAltRow,        // #F8FAFC
    SelectionBg,        // #DBE5FF
    SelectionBgFocus,   // #C4D4FF
    Logo1,              // #2E5BFF
    Logo2,              // #5B8AFF

    COUNT
};

COLORREF Get(Color c);
HBRUSH   Brush(Color c);

// Font cache — recreated on Init/Rebuild.
struct FontSet {
    HFONT regular     = nullptr;  // ~ 9 pt
    HFONT semibold    = nullptr;  // ~ 9 pt FW_SEMIBOLD
    HFONT smallFont   = nullptr;  // ~ 8 pt   (`small` collides with a Windows MIDL typedef)
    HFONT smallBold   = nullptr;  // ~ 8 pt FW_BOLD
    HFONT label       = nullptr;  // ~ 8 pt FW_BOLD  (uppercase KPI labels)
    HFONT heading     = nullptr;  // ~11 pt FW_SEMIBOLD
    HFONT brand       = nullptr;  // ~13 pt FW_SEMIBOLD ("NetLens" wordmark)
    HFONT big         = nullptr;  // ~17 pt FW_BOLD  (KPI value)
    HFONT ipBig       = nullptr;  // ~17 pt FW_BOLD  (details header IP)
};

void  Init(uint32_t dpi);
void  Rebuild(uint32_t dpi);
void  Shutdown();

const FontSet& Fonts();

}  // namespace nl::theme

#endif // NETLENS_THEME_H
