#ifndef NETLENS_DPI_H
#define NETLENS_DPI_H

#include <windows.h>
#include <cstdint>

namespace nl::dpi {

// Current DPI. Default 96 until WM_CREATE / WM_DPICHANGED updates it.
extern uint32_t g_dpi;

// Initialize from a window handle. Call after CreateWindow returns.
void Init(HWND hwnd);

// Override (used by WM_DPICHANGED handler).
void Update(uint32_t newDpi);

// Runtime-resolved replacement for `::GetDpiForSystem`. Falls back to
// GDI's LOGPIXELSX on Windows < 10 1607 (Server 2012, Win 7/8/8.1)
// where the user32 export doesn't exist. Calling sites must use this
// instead of the raw API to keep the binary loadable on legacy Windows.
UINT GetDpiForSystemCompat();

// Scale a px-at-96 value to the current DPI.
inline int  Scale(int px96)    { return MulDiv(px96, static_cast<int>(g_dpi), 96); }
inline LONG ScaleL(LONG px96)  { return MulDiv(px96, static_cast<int>(g_dpi), 96); }
inline int  Unscale(int px)    { return MulDiv(px, 96, static_cast<int>(g_dpi)); }

inline SIZE  Scale(SIZE s)     { return { Scale(static_cast<int>(s.cx)),
                                          Scale(static_cast<int>(s.cy)) }; }
inline POINT Scale(POINT p)    { return { Scale(static_cast<int>(p.x)),
                                          Scale(static_cast<int>(p.y)) }; }
inline RECT  ScaleRect(RECT r) { return { ScaleL(r.left),  ScaleL(r.top),
                                          ScaleL(r.right), ScaleL(r.bottom) }; }

}  // namespace nl::dpi

#endif // NETLENS_DPI_H
