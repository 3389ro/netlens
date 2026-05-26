#pragma once

#include "../Models.h"

#include <optional>

namespace lanscope {

/// Conservative, hand-curated "this version is known-risky" advisory layer.
///
/// This is **not** a CVE scanner. It is a small static table of end-of-life
/// version lines plus a handful of famous, unambiguously version-pinned
/// takeover-class issues. Matching is a version-string heuristic — it can be a
/// false positive when a distro backports security fixes without bumping the
/// version string — so advisories are surfaced by RiskAnalyzer as risk *hints*
/// with a "verify" framing, never as a confirmed vulnerability finding. There
/// is intentionally no CVE-ID-as-verdict, no CVSS, no live feed.
class VersionAdvisory {
public:
    struct Advisory {
        std::wstring hint;       ///< short text for the risk-hints column
        RiskLevel    severity;   ///< Low/Medium for EOL, High for known critical RCE
    };

    /// Returns an advisory for the fingerprint's product + version, or nullopt
    /// when the product is unrecognised, the version is absent/unparseable, or
    /// the version is current.
    static std::optional<Advisory> check(const ServiceFingerprint& fp);
};

} // namespace lanscope
