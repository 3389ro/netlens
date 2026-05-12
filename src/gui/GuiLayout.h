#pragma once

#include <windows.h>

#include <vector>

namespace netlens::gui {

/// Tiny grid-style layout helper. Given a rectangle and a row template,
/// returns the rectangles for each cell. Pure arithmetic — no GDI calls —
/// so it's easy to test and reason about.

struct CellRect {
    int x, y, w, h;
    [[nodiscard]] RECT toRect() const { return RECT{x, y, x + w, y + h}; }
};

/// Lays out a horizontal row of controls inside `area`.
/// `weights` give the relative width of each control (1.0 = same as the others).
/// `gap` is the horizontal spacing between controls in pixels.
/// `fixedWidths` are absolute widths (overrides the weight for that column).
std::vector<CellRect> layoutRow(RECT area, const std::vector<double>& weights,
                                int gap, const std::vector<int>& fixedWidths);

/// Lays out summary cards inside `area`. Each card has the same width.
std::vector<CellRect> layoutCards(RECT area, int cardCount, int gap);

/// Common spacing constants (design pixels, scale via GuiUtils::scale).
constexpr int kMarginX           = 16;
constexpr int kMarginY           = 12;
constexpr int kRowHeight         = 30;
constexpr int kRowSpacing        = 8;
constexpr int kCardHeight        = 62;
constexpr int kHeaderHeight      = 64;
constexpr int kFooterHeight      = 110;

} // namespace netlens::gui
