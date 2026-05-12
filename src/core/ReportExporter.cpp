#include "ReportExporter.h"

#include "../AppConstants.h"
#include "IpAddressUtils.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>

namespace netlens {

namespace {

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), needed, nullptr, nullptr);
    return out;
}

// RFC-4180-style CSV escape.
std::string csvEscape(const std::wstring& w) {
    std::string s = toUtf8(w);
    bool mustQuote = false;
    for (char c : s) {
        if (c == ',' || c == '"' || c == '\r' || c == '\n') { mustQuote = true; break; }
    }
    if (!mustQuote) return s;

    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else          out += c;
    }
    out += '"';
    return out;
}

// HTML escape — covers the characters that could break our generated markup.
std::string htmlEscape(const std::wstring& w) {
    std::string s = toUtf8(w);
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;        break;
        }
    }
    return out;
}

std::string riskCssClass(RiskLevel r) {
    switch (r) {
        case RiskLevel::High:   return "risk-high";
        case RiskLevel::Medium: return "risk-medium";
        case RiskLevel::Low:    return "risk-low";
        case RiskLevel::None:
        default:                return "risk-none";
    }
}

std::string formatDuration(int64_t ms) {
    if (ms < 1000)         return std::to_string(ms) + " ms";
    if (ms < 60 * 1000) {
        double s = ms / 1000.0;
        char b[32]; std::snprintf(b, 32, "%.1f s", s);
        return b;
    }
    int mins = static_cast<int>(ms / 60000);
    int secs = static_cast<int>((ms / 1000) % 60);
    char b[32]; std::snprintf(b, 32, "%d min %02d s", mins, secs);
    return b;
}

const char* kEmbeddedCss = R"CSS(
* { box-sizing: border-box; }
body { margin:0; font-family: 'Segoe UI', Tahoma, Arial, sans-serif; font-size:14px;
       color:#1f2937; background:#f3f4f6; }
header.app-header { background:#1e3a8a; color:#fff; padding:24px 32px; }
header.app-header h1 { margin:0; font-size:22px; font-weight:600; }
header.app-header .subtitle { opacity:.85; margin-top:4px; font-size:13px; }
header.app-header .meta { margin-top:14px; display:flex; flex-wrap:wrap; gap:24px;
                          font-size:13px; opacity:.92; }
header.app-header .meta .label { opacity:.7; margin-right:4px; }
.summary { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px,1fr));
           gap:12px; padding:20px 32px 0; }
.card { background:#fff; border-radius:8px; padding:16px;
        box-shadow:0 1px 2px rgba(0,0,0,.05); border-left:4px solid #94a3b8; }
.card.total   { border-left-color:#1e3a8a; }
.card.online  { border-left-color:#10b981; }
.card.offline { border-left-color:#9ca3af; }
.card.high    { border-left-color:#dc2626; }
.card.rdp     { border-left-color:#dc2626; }
.card.smb     { border-left-color:#dc2626; }
.card.web     { border-left-color:#2563eb; }
.card.duration{ border-left-color:#6b7280; }
.card-value { font-size:24px; font-weight:700; }
.card-label { font-size:12px; text-transform:uppercase; color:#6b7280;
              letter-spacing:.04em; margin-top:4px; }
section.results { padding:20px 32px; }
section.results h2 { margin:8px 0 12px 0; font-size:16px; }
table { width:100%; border-collapse:collapse; background:#fff; border-radius:8px;
        overflow:hidden; box-shadow:0 1px 2px rgba(0,0,0,.05); font-size:13px; }
thead th { background:#f9fafb; text-align:left; font-weight:600; color:#374151;
           padding:10px 12px; border-bottom:1px solid #e5e7eb; white-space:nowrap; }
tbody td { padding:8px 12px; border-bottom:1px solid #f3f4f6; vertical-align:top; }
tbody tr:last-child td { border-bottom:0; }
tbody tr.row-offline td { color:#9ca3af; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
td.ip, td.mac { font-family: Consolas,'Courier New',monospace; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px;
         font-weight:600; text-transform:uppercase; letter-spacing:.04em; }
.badge-online  { background:#d1fae5; color:#065f46; }
.badge-offline { background:#e5e7eb; color:#4b5563; }
.risk { display:inline-block; padding:3px 9px; border-radius:4px; font-size:11px;
        font-weight:600; text-transform:uppercase; letter-spacing:.04em; }
.risk-none   { background:#f3f4f6; color:#6b7280; }
.risk-low    { background:#dbeafe; color:#1e40af; }
.risk-medium { background:#fef3c7; color:#92400e; }
.risk-high   { background:#fee2e2; color:#991b1b; }
.hints span.h { display:inline-block; padding:2px 8px; border-radius:4px;
                margin-right:4px; margin-bottom:2px; font-size:11px;
                background:#f3f4f6; color:#374151; white-space:nowrap; }
.hints span.h.high   { background:#fee2e2; color:#991b1b; font-weight:600; }
.hints span.h.web    { background:#dbeafe; color:#1e40af; }
.hints span.h.muted  { background:#f3f4f6; color:#6b7280; }
section.legend { padding:0 32px 24px; color:#4b5563; font-size:13px; }
section.legend .row { display:flex; gap:24px; flex-wrap:wrap; align-items:center;
                      margin-top:8px; }
section.legend .row .swatch { display:inline-block; padding:2px 9px; border-radius:4px;
                              font-size:11px; font-weight:600; margin-right:6px;
                              text-transform:uppercase; letter-spacing:.04em; }
section.notes { padding:0 32px 24px; color:#4b5563; font-size:13px; }
section.notes p { background:#fff; border-left:4px solid #fbbf24; padding:12px 16px;
                  margin:0; border-radius:6px; }
.scan-banner { margin:0 32px; padding:14px 18px; border-radius:8px;
               background:#fef3c7; color:#92400e; border-left:6px solid #d97706;
               font-size:14px; font-weight:600; margin-top:18px; }
.scan-banner .small { display:block; font-weight:400; font-size:12.5px;
                      margin-top:4px; color:#78350f; }
.status-completed { color:#10b981; font-weight:600; }
.status-cancelled { color:#fbbf24; font-weight:600; }
footer { text-align:center; padding:18px; color:#6b7280; font-size:12px; }
@media (max-width:600px) { header.app-header,.summary,section.results,
                           section.legend,section.notes { padding-left:16px;
                           padding-right:16px; } }
)CSS";

void appendCard(std::ostringstream& html, const char* cssClass,
                const std::string& value, const char* label) {
    html << "<div class=\"card " << cssClass << "\">"
         << "<div class=\"card-value\">" << value << "</div>"
         << "<div class=\"card-label\">" << label << "</div>"
         << "</div>";
}

void appendHints(std::ostringstream& html, const std::wstring& hints) {
    if (hints.empty()) return;

    std::string s = toUtf8(hints);
    size_t start = 0;
    while (start <= s.size()) {
        size_t end = s.find(',', start);
        if (end == std::string::npos) end = s.size();
        std::string tok = s.substr(start, end - start);

        // trim
        size_t a = 0, b = tok.size();
        while (a < b && (tok[a] == ' ' || tok[a] == '\t')) ++a;
        while (b > a && (tok[b - 1] == ' ' || tok[b - 1] == '\t')) --b;
        std::string trimmed = tok.substr(a, b - a);

        if (!trimmed.empty()) {
            const char* cls = "h";
            if (trimmed == "RDP open" || trimmed == "SMB open" ||
                trimmed == "Telnet open" || trimmed == "WinRM open" ||
                trimmed == "Database port open") {
                cls = "h high";
            } else if (trimmed == "Web interface detected") {
                cls = "h web";
            } else if (trimmed == "Device unreachable") {
                cls = "h muted";
            }
            // Escape '<' etc inside the token just in case.
            std::string esc;
            for (char c : trimmed) {
                switch (c) {
                    case '&':  esc += "&amp;"; break;
                    case '<':  esc += "&lt;";  break;
                    case '>':  esc += "&gt;";  break;
                    default:   esc += c;       break;
                }
            }
            html << "<span class=\"" << cls << "\">" << esc << "</span>";
        }

        if (end == s.size()) break;
        start = end + 1;
    }
}

} // anonymous namespace

// =============================================================================
// CSV
// =============================================================================

std::string ReportExporter::buildCsv(const std::vector<ScanResult>& results) {
    std::ostringstream os;
    // Vendor inserted between MAC and OpenPorts — keeps the related identity
    // columns (Hostname, MAC, Vendor) adjacent for analyst readability.
    os << "IP,Status,Hostname,NetBIOS,Workgroup,MAC,Vendor,OpenPorts,Services,"
          "UDPServices,RiskLevel,RiskHints,ResponseTimeMs,Discovery\r\n";
    for (const auto& r : results) {
        os << csvEscape(r.ipAddress)                       << ','
           << csvEscape(r.statusText())                    << ','
           << csvEscape(r.hostname)                        << ','
           << csvEscape(r.udp.netbiosName)                 << ','
           << csvEscape(r.udp.netbiosWorkgroup)            << ','
           << csvEscape(r.macAddress)                      << ','
           << csvEscape(r.vendor)                          << ','
           << csvEscape(r.openPortsText())                 << ','
           << csvEscape(r.serviceLabelsText())             << ','
           << csvEscape(r.udp.summaryLine())               << ','
           << csvEscape(RiskLevelToString(r.riskLevel))    << ','
           << csvEscape(r.riskHints)                       << ','
           << r.responseTimeMs                             << ','
           << csvEscape(DiscoveryMethodToString(r.discovery))
           << "\r\n";
    }
    return os.str();
}

bool ReportExporter::exportCsv(const std::wstring& path,
                               const std::vector<ScanResult>& results)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;

    // UTF-8 BOM so Excel detects encoding.
    const char bom[] = {static_cast<char>(0xEF), static_cast<char>(0xBB), static_cast<char>(0xBF)};
    f.write(bom, 3);
    std::string body = buildCsv(results);
    f.write(body.data(), static_cast<std::streamsize>(body.size()));
    return static_cast<bool>(f);
}

// =============================================================================
// HTML
// =============================================================================

// Comparator used by the HTML report to order rows for the table:
//   1. Online hosts first, sorted by risk severity (High → Med → Low → None)
//   2. Within the same risk bucket, sort by IP ascending
//   3. Offline hosts come last, also IP-sorted.
//
// CSV stays in scan-order (IP) — analyst tooling expects deterministic order.
static int riskScore(RiskLevel r) {
    switch (r) {
        case RiskLevel::High:   return 0;
        case RiskLevel::Medium: return 1;
        case RiskLevel::Low:    return 2;
        case RiskLevel::None:
        default:                return 3;
    }
}

static bool reportLess(const ScanResult& a, const ScanResult& b) {
    if (a.isOnline != b.isOnline) return a.isOnline;          // online first
    if (a.isOnline) {
        int sa = riskScore(a.riskLevel);
        int sb = riskScore(b.riskLevel);
        if (sa != sb) return sa < sb;
    }
    auto av = ip::parseDotted(a.ipAddress).value_or(0);
    auto bv = ip::parseDotted(b.ipAddress).value_or(0);
    return av < bv;
}

std::string ReportExporter::buildHtml(const std::vector<ScanResult>& results,
                                      const ScanSummary& summary)
{
    // Work on a sorted copy so the caller's vector keeps its original order.
    std::vector<ScanResult> sorted(results);
    std::sort(sorted.begin(), sorted.end(), reportLess);

    std::ostringstream os;
    os << "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/>";
    os << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>";
    os << "<title>" << toUtf8(kAppName) << " - Scan Report</title>";
    os << "<style>" << kEmbeddedCss << "</style>";
    os << "</head><body>";

    // ----- Header -----
    os << "<header class=\"app-header\">";
    os << "<h1>" << toUtf8(kAppName) << "</h1>";
    os << "<div class=\"subtitle\">" << toUtf8(kAppSubtitle) << "</div>";
    os << "<div class=\"meta\">";
    os << "<div><span class=\"label\">Scan date:</span> " << htmlEscape(summary.startedAt) << "</div>";
    os << "<div><span class=\"label\">Adapter:</span> "   << htmlEscape(summary.adapterUsed) << "</div>";
    os << "<div><span class=\"label\">Range:</span> "     << htmlEscape(summary.rangeUsed) << "</div>";
    os << "<div><span class=\"label\">Preset:</span> "    << htmlEscape(summary.presetUsed) << "</div>";
    os << "<div><span class=\"label\">Mode:</span> "      << htmlEscape(ScanModeToString(summary.modeUsed)) << "</div>";
    os << "<div><span class=\"label\">Timeout:</span> "   << summary.timeoutUsed << " ms</div>";
    os << "<div><span class=\"label\">Parallel:</span> "  << summary.parallelUsed << "</div>";
    os << "<div><span class=\"label\">Duration:</span> "  << formatDuration(summary.durationMs) << "</div>";
    // Scan status — the third-party reviewer correctly pointed out that
    // a partial/cancelled scan needs to be flagged unambiguously in the
    // report so an executive reader doesn't take the host count at face
    // value.
    if (summary.wasCancelled) {
        os << "<div><span class=\"label\">Scan status:</span> "
              "<span class=\"status-cancelled\">Cancelled</span></div>";
        os << "<div><span class=\"label\">Partial results:</span> Yes</div>";
    } else {
        os << "<div><span class=\"label\">Scan status:</span> "
              "<span class=\"status-completed\">Completed</span></div>";
        os << "<div><span class=\"label\">Partial results:</span> No</div>";
    }
    os << "</div></header>";

    // Prominent banner for cancelled scans — sits between the header and
    // the summary cards so anyone skimming the report sees it before the
    // numbers.
    if (summary.wasCancelled) {
        os << "<div class=\"scan-banner\">"
              "&#9888; This scan was cancelled before completion. "
              "The results below are a partial snapshot."
              "<span class=\"small\">Hosts that the scanner had not yet "
              "reached are not represented in the table or the summary "
              "cards. Re-run the scan for a complete picture.</span>"
              "</div>";
    }

    // ----- Summary cards -----
    os << "<section class=\"summary\">";
    appendCard(os, "total",    std::to_string(summary.totalScanned), "Total scanned");
    appendCard(os, "online",   std::to_string(summary.onlineCount),  "Online");
    appendCard(os, "offline",  std::to_string(summary.offlineCount), "Offline");
    appendCard(os, "high",     std::to_string(summary.highRiskCount),"High risk");
    appendCard(os, "rdp",      std::to_string(summary.rdpOpenCount), "RDP open");
    appendCard(os, "smb",      std::to_string(summary.smbOpenCount), "SMB open");
    appendCard(os, "web",      std::to_string(summary.webOpenCount), "Web open");
    appendCard(os, "duration", formatDuration(summary.durationMs),   "Duration");
    os << "</section>";

    // ----- Results -----
    os << "<section class=\"results\"><h2>Results</h2><table>";
    os << "<thead><tr>";
    os << "<th>IP</th><th>Status</th><th>Hostname</th><th>MAC</th><th>Vendor</th>";
    os << "<th>Open ports</th><th>Services</th><th>UDP services</th>";
    os << "<th>Risk</th><th>Hints</th>";
    os << "<th class=\"num\">RTT (ms)</th><th>Discovery</th></tr></thead><tbody>";

    for (const auto& r : sorted) {
        os << "<tr class=\"" << (r.isOnline ? "row-online" : "row-offline") << "\">";
        os << "<td class=\"ip\">"   << htmlEscape(r.ipAddress)    << "</td>";
        os << "<td><span class=\"badge "
           << (r.isOnline ? "badge-online" : "badge-offline") << "\">"
           << htmlEscape(r.statusText()) << "</span></td>";
        // Hostname column shows DNS hostname when available, else the NetBIOS
        // name from the UDP 137 probe (so Windows hosts with broken reverse
        // DNS still get an identifiable label).
        os << "<td>"                << htmlEscape(r.effectiveHostname()) << "</td>";
        os << "<td class=\"mac\">"  << htmlEscape(r.macAddress)   << "</td>";
        os << "<td>"                << htmlEscape(r.vendor)       << "</td>";
        os << "<td>"                << htmlEscape(r.openPortsText())     << "</td>";
        os << "<td>"                << htmlEscape(r.serviceLabelsText()) << "</td>";
        os << "<td>"                << htmlEscape(r.udp.summaryLine())   << "</td>";
        os << "<td><span class=\"risk " << riskCssClass(r.riskLevel) << "\">"
           << htmlEscape(RiskLevelToString(r.riskLevel)) << "</span></td>";
        os << "<td class=\"hints\">";
        appendHints(os, r.riskHints);
        os << "</td>";
        os << "<td class=\"num\">";
        if (r.isOnline) os << r.responseTimeMs;
        else            os << "-";
        os << "</td>";
        os << "<td>" << htmlEscape(DiscoveryMethodToString(r.discovery)) << "</td>";
        os << "</tr>";
    }
    os << "</tbody></table></section>";

    // ----- Legend -----
    os << "<section class=\"legend\"><strong>Risk legend</strong>"
       << "<div class=\"row\">"
       << "<span><span class=\"swatch risk-none\">None</span>no relevant open ports</span>"
       << "<span><span class=\"swatch risk-low\">Low</span>web only / limited exposure</span>"
       << "<span><span class=\"swatch risk-medium\">Medium</span>SMB / RPC / FTP / SSH / VNC</span>"
       << "<span><span class=\"swatch risk-high\">High</span>RDP / Telnet / WinRM / DB / SMB+RDP combo</span>"
       << "</div></section>";

    // ----- Notes -----
    os << "<section class=\"notes\"><p>"
       << "This report shows open ports and exposure hints. It does not confirm vulnerabilities. "
       << "Use it as a network-visibility snapshot, not as a substitute for a full vulnerability scan."
       << "</p></section>";

    // ----- Footer -----
    os << "<footer>Generated by " << toUtf8(kAppName) << " " << toUtf8(kAppVersion) << "</footer>";
    os << "</body></html>";
    return os.str();
}

bool ReportExporter::exportHtml(const std::wstring& path,
                                const std::vector<ScanResult>& results,
                                const ScanSummary& summary)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    std::string body = buildHtml(results, summary);
    f.write(body.data(), static_cast<std::streamsize>(body.size()));
    return static_cast<bool>(f);
}

} // namespace netlens
