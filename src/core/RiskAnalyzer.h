#pragma once

#include "../Models.h"

namespace netlens {

/// Derives a coarse risk level and human-readable hint list from the open-port
/// set on a host. Never claims a confirmed vulnerability — this is exposure
/// analysis only.
class RiskAnalyzer {
public:
    /// Populates result.riskLevel and result.riskHints based on result.ports.
    /// Idempotent: safe to call multiple times.
    static void evaluate(ScanResult& result);
};

} // namespace netlens
