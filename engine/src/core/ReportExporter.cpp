#include "ReportExporter.h"

#include "../AppConstants.h"
#include "IpAddressUtils.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>

namespace lanscope {

namespace {

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), needed, nullptr, nullptr);
    return out;
}

// RFC-4180-style CSV escape, with a CSV-formula-injection guard.
std::string csvEscape(const std::wstring& w) {
    std::string s = toUtf8(w);

    // Formula-injection guard: a cell that Excel / Google Sheets would
    // evaluate as a formula gets a leading apostrophe so it renders as
    // literal text. Several v1.2 columns (service banners, HTTP headers,
    // the signed clock offset) carry untrusted network-sourced strings.
    if (!s.empty() && (s[0] == '=' || s[0] == '+' || s[0] == '-' ||
                       s[0] == '@' || s[0] == '\t' || s[0] == '\r')) {
        s.insert(s.begin(), '\'');
    }

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
section.fingerprints { padding:8px 32px 4px; }
section.fingerprints h2 { margin:8px 0 4px 0; font-size:16px; }
.fp-note { color:#4b5563; font-size:12.5px; margin:0 0 14px 0;
           background:#fff; border-left:4px solid #94a3b8; padding:10px 14px;
           border-radius:6px; }
.fp-host { background:#fff; border-radius:8px; margin-bottom:14px;
           overflow:hidden; box-shadow:0 1px 2px rgba(0,0,0,.05); }
.fp-host-head { padding:9px 14px; background:#f9fafb;
                border-bottom:1px solid #e5e7eb; font-weight:600; }
.fp-host-head .ip { font-family:Consolas,'Courier New',monospace; }
.fp-host-head .hn { color:#6b7280; font-weight:400; margin-left:10px; }
table.fp-table { box-shadow:none; border-radius:0; }
table.fp-table th { font-size:12px; }
table.fp-table td { font-size:12.5px; word-break:break-word; }
table.fp-table td.conf-high   { color:#065f46; font-weight:600; }
table.fp-table td.conf-medium { color:#92400e; }
table.fp-table td.conf-low    { color:#6b7280; }
.fp-empty { color:#6b7280; font-size:13px; background:#fff; border-radius:8px;
            padding:14px; box-shadow:0 1px 2px rgba(0,0,0,.05); }
section.devices { padding:14px 32px 0; }
section.devices h2 { margin:8px 0 10px 0; font-size:16px; }
.dev-row { display:flex; flex-wrap:wrap; gap:8px; }
.dev-chip { background:#fff; border:1px solid #e5e7eb; border-radius:14px;
            padding:5px 12px; font-size:12.5px; color:#374151;
            box-shadow:0 1px 2px rgba(0,0,0,.04); }
.dev-chip b { color:#1e3a8a; }
footer { text-align:center; padding:18px; color:#6b7280; font-size:12px; }
/* Inline note under the KPI cards when offline hosts were filtered
   out of the table */
p.hidden-note { padding:8px 32px 0; margin:0; color:#6b7280;
                font-size:12.5px; font-style:italic; }
/* Section-heading polish */
section.results h2, section.fingerprints h2, section.devices h2,
section.printers h2, section.udp h2 {
    margin:24px 0 12px 0; font-size:15px; font-weight:600;
    color:#1e3a8a; letter-spacing:.01em;
}
section.results h2::before,
section.printers h2::before,
section.udp h2::before,
section.fingerprints h2::before,
section.devices h2::before {
    content:""; display:inline-block; width:3px; height:14px;
    background:#1e3a8a; border-radius:2px; margin-right:8px;
    vertical-align:-2px;
}
td.num { white-space:nowrap; }
td.num .unit { color:#6b7280; font-size:11px; font-weight:400; }
td.num .disc { display:block; color:#9ca3af; font-size:10.5px;
               font-weight:400; text-transform:lowercase; margin-top:1px; }
td.num .muted { color:#cbd5e1; }
/* Printer supplies */
section.printers { padding:8px 32px 4px; }
.printer-card { background:#fff; border-radius:8px; margin-bottom:14px;
                box-shadow:0 1px 2px rgba(0,0,0,.05); overflow:hidden; }
.printer-head { padding:10px 14px; background:#f9fafb;
                border-bottom:1px solid #e5e7eb; }
.printer-head .ip { font-family:Consolas,'Courier New',monospace; font-weight:600; }
.printer-head .hn { color:#6b7280; margin-left:10px; }
.printer-meta { margin-top:6px; display:flex; flex-wrap:wrap; gap:18px;
                font-size:12.5px; color:#374151; }
.printer-meta b { color:#6b7280; font-weight:500; margin-right:4px;
                  font-size:11px; text-transform:uppercase;
                  letter-spacing:.04em; }
table.supplies { box-shadow:none; border-radius:0; }
table.supplies th { font-size:12px; }
table.supplies td.sup-color { font-weight:600; width:120px; }
table.supplies td.sup-color.sup-black   { color:#0f172a; }
table.supplies td.sup-color.sup-cyan    { color:#0891b2; }
table.supplies td.sup-color.sup-magenta { color:#be185d; }
table.supplies td.sup-color.sup-yellow  { color:#a16207; }
table.supplies td.sup-color.sup-drum    { color:#7c3aed; }
table.supplies td.sup-color.sup-waste   { color:#6b7280; }
table.supplies td.sup-bar { width:240px; }
table.supplies .bar-wrap { display:inline-block; width:160px; height:8px;
                           background:#e5e7eb; border-radius:4px;
                           vertical-align:middle; overflow:hidden; }
table.supplies .bar      { height:8px; border-radius:4px; }
table.supplies .sup-pct  { display:inline-block; width:46px;
                           margin-left:10px; text-align:right;
                           font-variant-numeric:tabular-nums;
                           color:#374151; font-weight:500; }
table.supplies .sup-desc { color:#6b7280; font-size:12.5px; }
.sup-empty { color:#6b7280; padding:12px 14px; font-size:13px; margin:0; }
/* UDP discovery */
section.udp { padding:8px 32px 4px; }
.udp-card { background:#fff; border-radius:8px; margin-bottom:14px;
            box-shadow:0 1px 2px rgba(0,0,0,.05); overflow:hidden; }
.udp-head { padding:10px 14px; background:#f9fafb;
            border-bottom:1px solid #e5e7eb; font-weight:600; }
.udp-head .ip { font-family:Consolas,'Courier New',monospace; }
.udp-head .hn { color:#6b7280; font-weight:400; margin-left:10px; }
table.udp-table { box-shadow:none; border-radius:0; }
table.udp-table th { font-size:12px; }
table.udp-table td.port { font-family:Consolas,'Courier New',monospace;
                          width:60px; color:#6b7280;
                          font-variant-numeric:tabular-nums; }
table.udp-table td.svc  { width:130px; font-weight:600; color:#1e3a8a; }
table.udp-table td.detail { color:#374151; word-break:break-word; }
@media (max-width:600px) { header.app-header,.summary,section.results,
                           section.fingerprints,section.devices,
                           section.printers,section.udp,
                           section.notes { padding-left:16px;
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

const char* confClass(const std::wstring& c) {
    if (c == L"High")   return "conf-high";
    if (c == L"Medium") return "conf-medium";
    return "conf-low";
}

// v1.2 — the device-type tally ("the rezumat"): a compact chip row of how many
// online hosts fell into each classified type.
void appendDeviceBreakdown(std::ostringstream& os, const ScanSummary& summary) {
    if (summary.deviceTypeCounts.empty()) return;
    os << "<section class=\"devices\"><h2>Device breakdown</h2><div class=\"dev-row\">";
    for (const auto& kv : summary.deviceTypeCounts) {
        os << "<span class=\"dev-chip\">" << htmlEscape(kv.first)
           << " <b>&times;" << kv.second << "</b></span>";
    }
    os << "</div></section>";
}

// v1.2 — a per-host "Service fingerprints" section listing each lightweight,
// non-authenticated identification with its source and confidence. Rendered
// after the results table; the hosts are in the same risk-sorted order.
void appendFingerprintSection(std::ostringstream& os,
                              const std::vector<ScanResult>& sorted) {
    os << "<section class=\"fingerprints\"><h2>Service fingerprints</h2>";
    os << "<p class=\"fp-note\">Service fingerprinting uses lightweight, "
          "non-authenticated protocol banners and headers. It does not perform "
          "vulnerability checks or credential testing.</p>";

    bool any = false;
    for (const auto& r : sorted) {
        if (r.fingerprints.empty()) continue;
        any = true;
        os << "<div class=\"fp-host\"><div class=\"fp-host-head\">";
        os << "<span class=\"ip\">" << htmlEscape(r.ipAddress) << "</span>";
        if (!r.hostname.empty())
            os << "<span class=\"hn\">" << htmlEscape(r.hostname) << "</span>";
        os << "</div>";
        os << "<table class=\"fp-table\"><thead><tr>"
              "<th>Port</th><th>Service</th><th>Product</th><th>Version</th>"
              "<th>Detail</th><th>Source</th><th>Confidence</th>"
              "</tr></thead><tbody>";
        for (const auto& f : r.fingerprints) {
            std::wstring portCol = std::to_wstring(f.port) + L"/"
                                 + (f.protocol.empty() ? std::wstring(L"tcp")
                                                       : f.protocol);
            os << "<tr>";
            os << "<td>" << htmlEscape(portCol)   << "</td>";
            os << "<td>" << htmlEscape(f.service) << "</td>";
            os << "<td>" << htmlEscape(f.product) << "</td>";
            os << "<td>" << htmlEscape(f.version) << "</td>";
            os << "<td>" << htmlEscape(f.detail)  << "</td>";
            os << "<td>" << htmlEscape(f.source)  << "</td>";
            os << "<td class=\"" << confClass(f.confidence) << "\">"
               << htmlEscape(f.confidence) << "</td>";
            os << "</tr>";
        }
        os << "</tbody></table></div>";
    }
    if (!any) {
        os << "<div class=\"fp-empty\">No service fingerprints were collected "
              "for this scan. Fingerprinting runs only for online hosts with "
              "open services, and can be turned off in Settings or is "
              "auto-disabled for very large ranges.</div>";
    }
    os << "</section>";
}

} // anonymous namespace

// =============================================================================
// CSV
// =============================================================================

std::string ReportExporter::buildCsv(const std::vector<ScanResult>& results) {
    std::ostringstream os;
    // Vendor inserted between MAC and OpenPorts — keeps the related identity
    // columns (Hostname, MAC, Vendor) adjacent for analyst readability.
    // v1.2 fingerprint columns are appended at the end so existing
    // positional CSV consumers keep working.
    os << "IP,Status,Hostname,MAC,Vendor,OpenPorts,Services,RiskLevel,RiskHints,"
          "ResponseTimeMs,Discovery,ServiceFingerprints,ClockOffset,ClockRTT,"
          "DeviceType,DeviceModel\r\n";
    for (const auto& r : results) {
        os << csvEscape(r.ipAddress)                       << ','
           << csvEscape(r.statusText())                    << ','
           << csvEscape(r.hostname)                        << ','
           << csvEscape(r.macAddress)                      << ','
           << csvEscape(r.vendor)                          << ','
           << csvEscape(r.openPortsText())                 << ','
           << csvEscape(r.serviceLabelsText())             << ','
           << csvEscape(RiskLevelToString(r.riskLevel))    << ','
           << csvEscape(r.riskHints)                       << ','
           << r.responseTimeMs                             << ','
           << csvEscape(DiscoveryMethodToString(r.discovery)) << ','
           << csvEscape(r.fingerprintExportText())         << ','
           << csvEscape(r.clockDrift.responded ? r.clockDrift.offsetText()
                                               : std::wstring()) << ','
           << (r.clockDrift.responded
                   ? std::to_string(r.clockDrift.roundTripMs) : std::string()) << ','
           << csvEscape(r.deviceType)                      << ','
           << csvEscape(r.deviceModel)
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

// Printer supplies block: per-printer card listing the consumables
// read via SNMP, with a colored progress bar per cartridge. Mirrors
// the GUI's PRINTER SUPPLIES section.
void appendPrinterSection(std::ostringstream& os,
                          const std::vector<ScanResult>& sorted) {
    bool any = false;
    for (const auto& r : sorted) {
        if (r.isPrinter) { any = true; break; }
    }
    if (!any) return;

    os << "<section class=\"printers\"><h2>Printer supplies</h2>";
    os << "<p class=\"fp-note\">Consumable levels read from the standard "
          "Printer-MIB (RFC 3805) over SNMP v2c (community <code>public</code>).</p>";
    for (const auto& r : sorted) {
        if (!r.isPrinter) continue;
        os << "<div class=\"printer-card\"><div class=\"printer-head\">";
        os << "<span class=\"ip\">" << htmlEscape(r.ipAddress) << "</span>";
        if (!r.hostname.empty())
            os << "<span class=\"hn\">" << htmlEscape(r.hostname) << "</span>";
        // Vendor / model / serial line.
        os << "<div class=\"printer-meta\">";
        if (!r.printerVendor.empty())
            os << "<span><b>Vendor</b> "  << htmlEscape(r.printerVendor) << "</span>";
        if (!r.printerModel.empty())
            os << "<span><b>Model</b> "   << htmlEscape(r.printerModel)  << "</span>";
        if (!r.printerSerial.empty())
            os << "<span><b>Serial</b> "  << htmlEscape(r.printerSerial) << "</span>";
        if (!r.printerSnmpStatus.empty())
            os << "<span><b>SNMP</b> "    << htmlEscape(r.printerSnmpStatus) << "</span>";
        os << "</div>";
        os << "</div>";

        // Parse the tab-encoded supplies blob.
        if (!r.printerSupplies.empty()) {
            os << "<table class=\"supplies\"><thead><tr>"
                  "<th>Consumable</th><th>Level</th><th>Description</th>"
                  "</tr></thead><tbody>";
            const std::wstring& s = r.printerSupplies;
            size_t i = 0;
            while (i < s.size()) {
                size_t eol = s.find(L"\r\n", i);
                std::wstring line = s.substr(i,
                    eol == std::wstring::npos ? std::wstring::npos : eol - i);
                i = (eol == std::wstring::npos) ? s.size() : eol + 2;
                if (line.empty()) continue;
                std::wstring col, type, pct, lvl, mx, desc;
                auto take = [&](std::wstring& dst) {
                    size_t t = line.find(L'\t');
                    if (t == std::wstring::npos) { dst = line; line.clear(); }
                    else { dst = line.substr(0, t); line.erase(0, t + 1); }
                };
                take(col); take(type); take(pct); take(lvl); take(mx); desc = line;

                // Resolve the bar tint by color name.
                const char* tint = "#475569";  // slate fallback
                std::string cssClass = "sup-other";
                if      (col == L"Black")   { tint = "#0f172a"; cssClass = "sup-black"; }
                else if (col == L"Cyan")    { tint = "#0891b2"; cssClass = "sup-cyan"; }
                else if (col == L"Magenta") { tint = "#be185d"; cssClass = "sup-magenta"; }
                else if (col == L"Yellow")  { tint = "#ca8a04"; cssClass = "sup-yellow"; }
                else if (col == L"Drum")    { tint = "#7c3aed"; cssClass = "sup-drum"; }
                else if (col == L"Waste")   { tint = "#6b7280"; cssClass = "sup-waste"; }

                int pctVal = -1;
                if (!pct.empty()) {
                    int v = 0;
                    for (wchar_t c : pct) {
                        if (c >= L'0' && c <= L'9') v = v * 10 + (c - L'0');
                        else if (c == L'%') break;
                        else if (v > 0) break;
                    }
                    if (v >= 0 && v <= 100) pctVal = v;
                }
                os << "<tr>";
                os << "<td class=\"sup-color " << cssClass << "\">"
                   << htmlEscape(col.empty() ? L"Supply" : col) << "</td>";
                os << "<td class=\"sup-bar\"><div class=\"bar-wrap\">";
                if (pctVal >= 0) {
                    os << "<div class=\"bar\" style=\"width:" << pctVal
                       << "%;background:" << tint << "\"></div>";
                }
                os << "</div><span class=\"sup-pct\">"
                   << htmlEscape(pct.empty() ? L"—" : pct)
                   << "</span></td>";
                os << "<td class=\"sup-desc\">" << htmlEscape(desc) << "</td>";
                os << "</tr>";
            }
            os << "</tbody></table>";
        } else {
            os << "<p class=\"sup-empty\">No consumables exposed via SNMP "
                  "for this host.</p>";
        }
        os << "</div>";
    }
    os << "</section>";
}

// UDP discovery block: per-host card with the multi-line response
// summary. Mirrors the GUI's UDP DISCOVERY table.
void appendUdpDiscoverySection(std::ostringstream& os,
                               const std::vector<ScanResult>& sorted) {
    bool any = false;
    for (const auto& r : sorted) {
        if (!r.udpDiscovery.empty()) { any = true; break; }
    }
    if (!any) return;

    os << "<section class=\"udp\"><h2>UDP discovery</h2>";
    os << "<p class=\"fp-note\">Best-effort UDP probes (NBNS, NTP, SSDP, "
          "mDNS, SQL Server Browser, DNS, LLMNR, IPMI). Missing rows mean "
          "no response within the per-probe budget &mdash; not "
          "&ldquo;closed&rdquo;.</p>";

    for (const auto& r : sorted) {
        if (r.udpDiscovery.empty()) continue;
        os << "<div class=\"udp-card\"><div class=\"udp-head\">";
        os << "<span class=\"ip\">" << htmlEscape(r.ipAddress) << "</span>";
        if (!r.hostname.empty())
            os << "<span class=\"hn\">" << htmlEscape(r.hostname) << "</span>";
        os << "</div>";

        os << "<table class=\"udp-table\"><thead><tr>"
              "<th>Port</th><th>Service</th><th>Detail</th>"
              "</tr></thead><tbody>";
        const std::wstring& s = r.udpDiscovery;
        size_t i = 0;
        while (i < s.size()) {
            size_t eol = s.find(L"\r\n", i);
            std::wstring line = s.substr(i,
                eol == std::wstring::npos ? std::wstring::npos : eol - i);
            i = (eol == std::wstring::npos) ? s.size() : eol + 2;
            if (line.empty()) continue;
            std::wstring port, svc, detail;
            size_t t1 = line.find(L'\t');
            if (t1 != std::wstring::npos) {
                port = line.substr(0, t1);
                size_t t2 = line.find(L'\t', t1 + 1);
                if (t2 != std::wstring::npos) {
                    svc    = line.substr(t1 + 1, t2 - t1 - 1);
                    detail = line.substr(t2 + 1);
                } else {
                    svc = line.substr(t1 + 1);
                }
            } else {
                detail = line;
            }
            os << "<tr>";
            os << "<td class=\"port\">"   << htmlEscape(port)   << "</td>";
            os << "<td class=\"svc\">"    << htmlEscape(svc)    << "</td>";
            os << "<td class=\"detail\">" << htmlEscape(detail) << "</td>";
            os << "</tr>";
        }
        os << "</tbody></table></div>";
    }
    os << "</section>";
}

std::string ReportExporter::buildHtml(const std::vector<ScanResult>& results,
                                      const ScanSummary& summary)
{
    // Offline hosts are HIDDEN from the report by default. A /24 scan
    // typically shows 14 online + 240 offline; the offline rows are
    // 94% of the table and add zero signal — they're just "host
    // replied to nothing, here's an IP". An inline note under the
    // KPI cards records how many were skipped so the reader knows
    // the report isn't a partial accident.
    std::vector<ScanResult> sorted;
    sorted.reserve(results.size());
    int hiddenOffline = 0;
    for (const auto& r : results) {
        if (r.isOnline) sorted.push_back(r);
        else            ++hiddenOffline;
    }
    std::sort(sorted.begin(), sorted.end(), reportLess);

    std::ostringstream os;
    os << "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/>";
    os << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>";
    os << "<title>" << toUtf8(kAppName) << " - Scan Report</title>";
    os << "<style>" << kEmbeddedCss << "</style>";
    os << "</head><body>";

    // ----- Header -----
    // Six fields that actually matter to a sysadmin skimming the page
    // (timeout ms / parallel worker count etc. are debugger-grade
    // detail and would clutter):
    //   - Scan date (when)
    //   - Range / Adapter (where)
    //   - Preset (what kind of scan)
    //   - Duration (how long)
    //   - Status pill (Completed / Cancelled)
    os << "<header class=\"app-header\">";
    os << "<h1>" << toUtf8(kAppName) << "</h1>";
    os << "<div class=\"subtitle\">" << toUtf8(kAppSubtitle) << "</div>";
    os << "<div class=\"meta\">";
    os << "<div><span class=\"label\">Scan date:</span> " << htmlEscape(summary.startedAt) << "</div>";
    os << "<div><span class=\"label\">Range:</span> "     << htmlEscape(summary.rangeUsed) << "</div>";
    os << "<div><span class=\"label\">Adapter:</span> "   << htmlEscape(summary.adapterUsed) << "</div>";
    os << "<div><span class=\"label\">Preset:</span> "    << htmlEscape(summary.presetUsed) << "</div>";
    os << "<div><span class=\"label\">Duration:</span> "  << formatDuration(summary.durationMs) << "</div>";
    if (summary.wasCancelled) {
        os << "<div><span class=\"label\">Status:</span> "
              "<span class=\"status-cancelled\">Cancelled (partial)</span></div>";
    } else {
        os << "<div><span class=\"label\">Status:</span> "
              "<span class=\"status-completed\">Completed</span></div>";
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
    // Offline rows are hidden from the table by default, so an
    // "Offline" card would be misleading next to a table that
    // doesn't list them. The current set focuses on online-host
    // exposure:
    //   - Online hosts        — the count the table actually shows
    //   - RDP / SMB / Web     — exposure tallies
    //   - Duration            — how long the scan took
    // Plus a small inline note under the cards saying how many offline
    // hosts were dropped, in case "240 IPs probed, 14 listed" is
    // confusing.
    os << "<section class=\"summary\">";
    appendCard(os, "online",   std::to_string(summary.onlineCount),  "Online hosts");
    appendCard(os, "rdp",      std::to_string(summary.rdpOpenCount), "RDP open");
    appendCard(os, "smb",      std::to_string(summary.smbOpenCount), "SMB open");
    appendCard(os, "web",      std::to_string(summary.webOpenCount), "Web open");
    appendCard(os, "duration", formatDuration(summary.durationMs),   "Duration");
    os << "</section>";
    if (hiddenOffline > 0) {
        os << "<p class=\"hidden-note\">"
           << hiddenOffline
           << " offline host" << (hiddenOffline == 1 ? "" : "s")
           << " not listed in this report.</p>";
    }

    // ----- Device breakdown (v1.2) -----
    appendDeviceBreakdown(os, summary);

    // ----- Results -----
    // Columns: IP / Status / Hostname / Device / MAC / Vendor /
    // Open TCP ports / Services / RTT. Risk + Hints intentionally
    // dropped (GUI hides risk too); discovery method is rendered as
    // a secondary line in the RTT cell so the table fits a 1080p
    // screen without horizontal scroll.
    os << "<section class=\"results\"><h2>Hosts</h2><table>";
    os << "<thead><tr>";
    os << "<th>IP</th><th>Status</th><th>Hostname</th><th>Device</th>";
    os << "<th>MAC</th><th>Vendor</th>";
    os << "<th>Open TCP ports</th><th>Services</th>";
    os << "<th class=\"num\">RTT</th></tr></thead><tbody>";

    for (const auto& r : sorted) {
        os << "<tr class=\"" << (r.isOnline ? "row-online" : "row-offline") << "\">";
        os << "<td class=\"ip\">"   << htmlEscape(r.ipAddress)    << "</td>";
        os << "<td><span class=\"badge "
           << (r.isOnline ? "badge-online" : "badge-offline") << "\">"
           << htmlEscape(r.statusText()) << "</span></td>";
        os << "<td>"                << htmlEscape(r.hostname)     << "</td>";
        os << "<td>"                << htmlEscape(r.deviceText()) << "</td>";
        os << "<td class=\"mac\">"  << htmlEscape(r.macAddress)   << "</td>";
        os << "<td>"                << htmlEscape(r.vendor)       << "</td>";
        os << "<td>"                << htmlEscape(r.openPortsText())     << "</td>";
        os << "<td>"                << htmlEscape(r.serviceLabelsText()) << "</td>";
        os << "<td class=\"num\">";
        if (r.isOnline) {
            os << r.responseTimeMs << "<span class=\"unit\"> ms</span>";
            os << "<span class=\"disc\">"
               << htmlEscape(DiscoveryMethodToString(r.discovery))
               << "</span>";
        } else {
            os << "<span class=\"muted\">&mdash;</span>";
        }
        os << "</td>";
        os << "</tr>";
    }
    os << "</tbody></table></section>";

    // ----- Service fingerprints (v1.2) -----
    appendFingerprintSection(os, sorted);

    // ----- Printer supplies (v1.0.38) -----
    appendPrinterSection(os, sorted);

    // ----- UDP discovery (v1.0.38) -----
    appendUdpDiscoverySection(os, sorted);

    // ----- Notes -----
    os << "<section class=\"notes\"><p>"
       << "This report is a network-visibility snapshot &mdash; it lists "
       << "what hosts answer TCP probes and what their canonical service "
       << "labels are. It does not confirm vulnerabilities. Use it alongside "
       << "a proper vulnerability scanner if you need configuration findings."
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

} // namespace lanscope
