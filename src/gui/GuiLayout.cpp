#include "GuiLayout.h"

#include <algorithm>
#include <numeric>

namespace netlens::gui {

std::vector<CellRect> layoutRow(RECT area, const std::vector<double>& weights,
                                int gap, const std::vector<int>& fixedWidths)
{
    std::vector<CellRect> out;
    if (weights.empty()) return out;

    int totalGap = gap * (static_cast<int>(weights.size()) - 1);
    int fixedTotal = 0;
    for (int w : fixedWidths) fixedTotal += (w > 0 ? w : 0);

    int flexible = (area.right - area.left) - totalGap - fixedTotal;
    if (flexible < 0) flexible = 0;

    double sumWeights = 0;
    for (size_t i = 0; i < weights.size(); ++i) {
        bool isFixed = (i < fixedWidths.size()) && fixedWidths[i] > 0;
        if (!isFixed) sumWeights += weights[i];
    }
    if (sumWeights <= 0) sumWeights = 1;

    int x = area.left;
    for (size_t i = 0; i < weights.size(); ++i) {
        int width;
        if (i < fixedWidths.size() && fixedWidths[i] > 0) {
            width = fixedWidths[i];
        } else {
            width = static_cast<int>((weights[i] / sumWeights) * flexible);
        }
        out.push_back(CellRect{x, area.top, width, area.bottom - area.top});
        x += width + gap;
    }
    return out;
}

std::vector<CellRect> layoutCards(RECT area, int cardCount, int gap) {
    std::vector<CellRect> out;
    if (cardCount <= 0) return out;

    int totalGap = gap * (cardCount - 1);
    int width    = (area.right - area.left - totalGap) / cardCount;
    if (width < 1) width = 1;

    int x = area.left;
    for (int i = 0; i < cardCount; ++i) {
        out.push_back(CellRect{x, area.top, width, area.bottom - area.top});
        x += width + gap;
    }
    return out;
}

} // namespace netlens::gui
