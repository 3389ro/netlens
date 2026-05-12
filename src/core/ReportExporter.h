#pragma once

#include "../Models.h"

#include <string>
#include <vector>

namespace netlens {

/// Builds CSV and HTML reports from scan results.
/// All output is UTF-8 (CSV with BOM so Excel auto-detects).
class ReportExporter {
public:
    /// Writes a CSV report. Returns true on success.
    static bool exportCsv(const std::wstring& path,
                          const std::vector<ScanResult>& results);

    /// Writes a self-contained HTML report (embedded CSS, no external resources).
    static bool exportHtml(const std::wstring& path,
                           const std::vector<ScanResult>& results,
                           const ScanSummary& summary);

    /// Pure helpers — exposed so tests can compare strings directly.
    static std::string buildCsv(const std::vector<ScanResult>& results);
    static std::string buildHtml(const std::vector<ScanResult>& results,
                                 const ScanSummary& summary);
};

} // namespace netlens
