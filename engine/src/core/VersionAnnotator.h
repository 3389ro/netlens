#pragma once

#include <string>

namespace lanscope {

/// Translates a (product, version) pair into a short human-friendly note
/// suitable for the per-port Version column in the pane's open-ports
/// table.
///
/// This is **display annotation only** — release-year, EOL hint, broad
/// CVE-era flag — not a risk verdict. The conservative risk-oriented
/// table for the Risk hints column lives in VersionAdvisory (which is
/// gated on RiskAnalyzer's logic). VersionAnnotator runs unconditionally
/// for every fingerprinted service so the user always sees the era
/// alongside the raw version.
///
/// Returns empty when the product / version is not in the curated table.
class VersionAnnotator {
public:
    static std::wstring annotate(const std::wstring& product,
                                  const std::wstring& version);
};

} // namespace lanscope
