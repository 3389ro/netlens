#pragma once

#include "../Models.h"

#include <string>
#include <vector>

namespace lanscope {

/// Minimal baseline persistence. v1 supports save+load only; the GUI surfaces
/// neither (the structure exists for the v1.1 baseline-compare feature).
///
/// File format is a small, hand-rolled "TSV with header" — keeping the parser
/// dependency-free and resilient to user edits.
class BaselineStore {
public:
    struct Baseline {
        std::wstring             label;   ///< human label ("home-2026-05-11")
        std::wstring             range;   ///< range used at capture time
        std::vector<ScanResult>  hosts;
    };

    /// Writes a baseline to disk. Returns true on success.
    static bool save(const std::wstring& path, const Baseline& b);

    /// Reads a baseline from disk. Returns true on success.
    /// On failure, `out` is left untouched.
    static bool load(const std::wstring& path, Baseline& out);
};

} // namespace lanscope
