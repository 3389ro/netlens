#include "Theme.h"
#include <array>
#include <cstring>

namespace nl::theme {

namespace {

constexpr COLORREF kPalette[static_cast<size_t>(Color::COUNT)] = {
    RGB(0xF5,0xF7,0xFA),   // Bg
    RGB(0xFF,0xFF,0xFF),   // Surface
    RGB(0xF0,0xF3,0xF7),   // SurfaceAlt
    RGB(0xD9,0xE1,0xEC),   // Border  — slightly cooler tone than pure grey
    RGB(0xF0,0xF3,0xF7),   // Divider
    RGB(0xF1,0xF4,0xF8),   // Hover

    RGB(0x0F,0x1B,0x2D),   // TextPrimary
    RGB(0x2F,0x3D,0x52),   // TextSecondary
    RGB(0x5C,0x6B,0x80),   // TextMuted
    RGB(0xFF,0xFF,0xFF),   // TextInverse

    RGB(0x2E,0x5B,0xFF),   // Accent
    RGB(0x1F,0x49,0xE0),   // AccentHover
    RGB(0xE5,0xEC,0xFF),   // AccentSurface
    RGB(0x2E,0xA0,0x44),   // Success
    RGB(0xE9,0xF5,0xEC),   // SuccessSurface
    RGB(0xD9,0x77,0x06),   // Warning
    RGB(0xFE,0xF3,0xC7),   // WarningSurface
    RGB(0xC0,0x39,0x2B),   // Danger
    RGB(0xFE,0xE2,0xE2),   // DangerSurface
    RGB(0x29,0x80,0xB9),   // Info
    RGB(0xDC,0xEA,0xF4),   // InfoSurface
    RGB(0x95,0xA5,0xA6),   // Neutral
    RGB(0xDD,0xE3,0xEA),   // NeutralSurface

    RGB(0xEE,0xF2,0xF8),   // TableHeader — slightly bluer
    RGB(0xF7,0xF9,0xFC),   // TableAltRow — barely-there zebra
    RGB(0xCF,0xDC,0xFF),   // SelectionBg  — saturated soft blue
    RGB(0xB8,0xCB,0xFF),   // SelectionBgFocus
    RGB(0x2E,0x5B,0xFF),   // Logo1
    RGB(0x5B,0x8A,0xFF),   // Logo2
};

std::array<HBRUSH, static_cast<size_t>(Color::COUNT)> g_brushes{};
FontSet g_fonts{};

// SystemParametersInfoForDpi is a Win10 1607+ user32 export — statically
// linking against it makes the EXE unloadable on Windows Server 2012 /
// Win 7/8/8.1. Resolve at runtime and fall back to the DPI-unaware
// SystemParametersInfoW when the new entry point isn't available.
using PFN_SystemParametersInfoForDpi =
    BOOL (WINAPI*)(UINT, UINT, PVOID, UINT, UINT);

static BOOL QueryNonClientMetricsForDpi(NONCLIENTMETRICSW& ncm, UINT dpi) {
    static PFN_SystemParametersInfoForDpi fn = []() -> PFN_SystemParametersInfoForDpi {
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (!user32) return nullptr;
        return reinterpret_cast<PFN_SystemParametersInfoForDpi>(
            GetProcAddress(user32, "SystemParametersInfoForDpi"));
    }();
    if (fn) {
        return fn(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0, dpi);
    }
    // Legacy fallback — DPI-unaware but always present.
    return SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
}

HFONT MakeFont(uint32_t dpi, int ptSize, int weight) {
    LOGFONTW lf{};
    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof(ncm);
    if (QueryNonClientMetricsForDpi(ncm, dpi)) {
        lf = ncm.lfMessageFont;
    } else {
        // Both APIs failed — synthesise a sensible LOGFONTW.
        wcscpy_s(lf.lfFaceName, L"Segoe UI");
        lf.lfCharSet = DEFAULT_CHARSET;
    }
    lf.lfHeight  = -MulDiv(ptSize, static_cast<int>(dpi), 72);
    lf.lfWeight  = weight;
    lf.lfItalic  = FALSE;
    lf.lfQuality = CLEARTYPE_QUALITY;
    return CreateFontIndirectW(&lf);
}

void DestroyFonts() {
    HFONT* arr = reinterpret_cast<HFONT*>(&g_fonts);
    constexpr size_t kCount = sizeof(FontSet) / sizeof(HFONT);
    for (size_t i = 0; i < kCount; ++i) {
        if (arr[i]) { DeleteObject(arr[i]); arr[i] = nullptr; }
    }
}

}  // namespace

COLORREF Get(Color c) {
    return kPalette[static_cast<size_t>(c)];
}

HBRUSH Brush(Color c) {
    return g_brushes[static_cast<size_t>(c)];
}

void Init(uint32_t dpi) {
    for (size_t i = 0; i < g_brushes.size(); ++i) {
        if (!g_brushes[i]) g_brushes[i] = CreateSolidBrush(kPalette[i]);
    }
    Rebuild(dpi);
}

void Rebuild(uint32_t dpi) {
    DestroyFonts();
    g_fonts.regular   = MakeFont(dpi,  9, FW_NORMAL);
    g_fonts.semibold  = MakeFont(dpi,  9, FW_SEMIBOLD);
    g_fonts.smallFont = MakeFont(dpi,  8, FW_NORMAL);
    g_fonts.smallBold = MakeFont(dpi,  8, FW_BOLD);
    g_fonts.label     = MakeFont(dpi,  8, FW_BOLD);
    g_fonts.heading   = MakeFont(dpi, 11, FW_SEMIBOLD);
    g_fonts.brand     = MakeFont(dpi, 13, FW_SEMIBOLD);
    g_fonts.big       = MakeFont(dpi, 16, FW_BOLD);
    g_fonts.ipBig     = MakeFont(dpi, 20, FW_BOLD);   // larger IP title
}

void Shutdown() {
    DestroyFonts();
    for (auto& b : g_brushes) {
        if (b) { DeleteObject(b); b = nullptr; }
    }
}

const FontSet& Fonts() { return g_fonts; }

}  // namespace nl::theme
