#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lanscope {

// =============================================================================
// Shared data model for the scanner engine, GUI and CLI.
// All strings are std::wstring so reports and the GUI handle Unicode hostnames
// cleanly. Internal numeric IP forms use uint32_t in network byte order.
// =============================================================================

// -----------------------------------------------------------------------------
// Network adapter
// -----------------------------------------------------------------------------

enum class AdapterType {
    Unknown,
    Ethernet,
    WiFi,
    Loopback,
    Tunnel,
    Other
};

struct NetworkAdapter {
    uint32_t      index             = 0;             ///< OS adapter index
    std::wstring  name;                              ///< system name (GUID-style)
    std::wstring  friendlyName;                      ///< user-friendly name (e.g. "Ethernet")
    std::wstring  description;                       ///< driver description
    std::wstring  macAddress;                        ///< AA-BB-CC-DD-EE-FF
    AdapterType   type              = AdapterType::Unknown;
    bool          operational       = false;         ///< IfOperStatusUp

    std::wstring  ipv4;                              ///< primary IPv4 (dotted)
    int           prefixLength      = 0;             ///< CIDR prefix /n
    std::wstring  subnetMask;                        ///< dotted-decimal mask
    std::wstring  gateway;                           ///< default gateway, if any

    std::wstring  networkAddress;                    ///< network base (a.b.c.0 for /24)
    std::wstring  broadcastAddress;                  ///< broadcast (a.b.c.255 for /24)
    std::wstring  suggestedScanRange;                ///< "192.168.1.1-254" form

    /// Returns the GUI-facing one-line description.
    [[nodiscard]] std::wstring guiLine() const;
};

// -----------------------------------------------------------------------------
// Per-port probe result
// -----------------------------------------------------------------------------

struct PortStatus {
    int           port       = 0;
    std::wstring  service;     // friendly name ("HTTP", "RDP", ...)
    bool          isOpen      = false;
    // Eager local-process ownership. Populated by scanOneHost (via
    // LocalProcessResolver) only when the host IP matches one of this
    // machine's adapters; stays at defaults for remote hosts.
    uint32_t      ownerPid   = 0;
    std::wstring  ownerExe;     // full path OR sentinel ("needs admin", ...)
};

// -----------------------------------------------------------------------------
// Service fingerprint — lightweight, non-authenticated identification of a
// service from its standard protocol greeting, banner or response headers.
// Populated by ServiceFingerprinter for online hosts when fingerprinting is
// enabled. NEVER the product of an exploit check, brute force or credential
// test — this is exposure reporting only. All string fields are sanitised and
// length-capped network input; treat as untrusted text.
// -----------------------------------------------------------------------------

struct ServiceFingerprint {
    int           port        = 0;
    std::wstring  protocol;     ///< "tcp" or "udp"
    std::wstring  service;      ///< "http", "https", "ssh", "ftp", "smtp",
                                ///< "mysql", "mssql", "mssql-browser", "ntp"
    std::wstring  product;      ///< "Apache", "nginx", "OpenSSH", "MariaDB", ...
    std::wstring  version;      ///< best-effort version, empty when unknown
    std::wstring  detail;       ///< short normalised detail (Server header, banner)
    std::wstring  title;        ///< web page <title>, when this is an HTTP(S) service
    std::wstring  source;       ///< "HTTP Server header", "SSH banner", ...
    std::wstring  confidence;   ///< "High", "Medium", "Low"
    // Eager version annotation. Populated by scanOneHost (via
    // VersionAnnotator) when product+version match a known release
    // band; empty otherwise. Pre-computed here so per-port click
    // handlers don't burn CPU re-deriving it.
    std::wstring  versionNote;
};

// -----------------------------------------------------------------------------
// Clock drift — derived from a single, standard NTP client query to UDP 123.
// Offset/round-trip are protocol time (UTC), NOT a Windows local-time reading.
// `responded` stays false for the common case of a host that is not an NTP
// server, which is normal and not an error.
// -----------------------------------------------------------------------------

struct ClockDriftInfo {
    bool          responded   = false;
    int64_t       offsetMs     = 0;     ///< remote clock minus local clock
    int64_t       roundTripMs  = 0;
    std::wstring  source;               ///< "NTP"

    /// Signed "+HH:MM:SS" form (e.g. "+00:03:42"). Empty when not responded.
    [[nodiscard]] std::wstring offsetText() const {
        if (!responded) return {};
        int64_t ms  = offsetMs < 0 ? -offsetMs : offsetMs;
        int64_t sec = ms / 1000;
        int h = static_cast<int>(sec / 3600);
        int m = static_cast<int>((sec % 3600) / 60);
        int s = static_cast<int>(sec % 60);
        auto pad2 = [](int v) {
            std::wstring t = std::to_wstring(v);
            if (t.size() < 2) t.insert(t.begin(), L'0');
            return t;
        };
        std::wstring out = (offsetMs < 0) ? L"-" : L"+";
        out += pad2(h) + L":" + pad2(m) + L":" + pad2(s);
        return out;
    }

    /// Compact "+3m42s" / "+18s" / "+1h2m" form for the GUI. Empty when not responded.
    [[nodiscard]] std::wstring compactText() const {
        if (!responded) return {};
        int64_t ms  = offsetMs < 0 ? -offsetMs : offsetMs;
        int64_t sec = ms / 1000;
        std::wstring out = (offsetMs < 0) ? L"-" : L"+";
        if (sec >= 3600) {
            out += std::to_wstring(sec / 3600) + L"h"
                 + std::to_wstring((sec % 3600) / 60) + L"m";
        } else if (sec >= 60) {
            out += std::to_wstring(sec / 60) + L"m"
                 + std::to_wstring(sec % 60) + L"s";
        } else {
            out += std::to_wstring(sec) + L"s";
        }
        return out;
    }
};

/// Trims a dotted version string to "major.minor" for compact display.
inline std::wstring shortVersion(const std::wstring& v) {
    size_t firstDot = v.find(L'.');
    if (firstDot == std::wstring::npos) return v;
    size_t secondDot = v.find(L'.', firstDot + 1);
    if (secondDot == std::wstring::npos) return v;
    return v.substr(0, secondDot);
}

// -----------------------------------------------------------------------------
// Discovery method — how the host was confirmed online
// -----------------------------------------------------------------------------

enum class DiscoveryMethod {
    None,        ///< host did not respond at all
    Icmp,        ///< responded to ICMP echo
    Arp,         ///< ICMP failed, but the host answered ARP (local subnet only)
    TcpFallback  ///< ICMP + ARP failed, but at least one TCP port answered
};

inline const wchar_t* DiscoveryMethodToString(DiscoveryMethod m) {
    switch (m) {
        case DiscoveryMethod::Icmp:        return L"ICMP";
        case DiscoveryMethod::Arp:         return L"ARP";
        case DiscoveryMethod::TcpFallback: return L"TCP fallback";
        case DiscoveryMethod::None:
        default:                           return L"None";
    }
}

// -----------------------------------------------------------------------------
// Risk level — overall exposure indication, NOT a vulnerability claim
// -----------------------------------------------------------------------------

enum class RiskLevel {
    None,
    Low,
    Medium,
    High
};

inline const wchar_t* RiskLevelToString(RiskLevel r) {
    switch (r) {
        case RiskLevel::Low:    return L"Low";
        case RiskLevel::Medium: return L"Medium";
        case RiskLevel::High:   return L"High";
        case RiskLevel::None:
        default:                return L"None";
    }
}

// -----------------------------------------------------------------------------
// Per-host scan result
// -----------------------------------------------------------------------------

struct ScanResult {
    std::wstring             ipAddress;
    bool                     isOnline           = false;
    std::wstring             hostname;
    std::wstring             macAddress;
    std::wstring             vendor;             ///< MAC OUI vendor lookup; empty when unknown
    std::wstring             adapterLabel;       ///< adapter friendly name when known
    int64_t                  responseTimeMs     = 0;
    std::vector<PortStatus>  ports;
    DiscoveryMethod          discovery          = DiscoveryMethod::None;

    // Service fingerprinting (v1.2). Empty when fingerprinting is disabled,
    // the host is offline, or no service answered with an identifiable
    // greeting. clockDrift.responded stays false unless the host is an NTP
    // server — which most LAN clients are not, and that is normal.
    std::vector<ServiceFingerprint> fingerprints;
    ClockDriftInfo                  clockDrift;

    // Device classification (v1.2). A heuristic guess at what the host is —
    // "Windows PC", "IP Camera", "Printer", "Router / Gateway", ... or
    // "Unknown" — derived by DeviceClassifier from the MAC/OUI vendor, open
    // ports, service fingerprints and hostname. deviceModel is a best-effort
    // model string, usually from the device's web page <title>.
    std::wstring                    deviceType;
    std::wstring                    deviceModel;

    // Web-UI probe result (v1.0.45). Empty when no HTTP/HTTPS port was open
    // on this host, when the probe failed, or when neither the page <title>,
    // a known productName / switchInfo element, nor a body brand keyword
    // matched. When set, the string is already prefixed for direct display:
    //   "<Brand> (<title>)"    — brand-keyword title match
    //   "HTTP title: <text>"   — non-brand title
    //   "Web UI model: <text>" — productName / switchInfo / device-name
    //   "Web UI brand: <X>"    — body-keyword fallback
    // Populated by WebUiProbe in NetworkScanner::scanOneHost.
    std::wstring                    webUiModel;

    // Filled in by RiskAnalyzer after the host is fully probed.
    RiskLevel                riskLevel          = RiskLevel::None;
    std::wstring             riskHints;          ///< comma-separated user-readable hints

    // Cached enrichment fields. Populated ONCE by
    // `EnrichmentEngine::finalize` at the end of scanOneHost so
    // `nl_scanner_get_result` is a pure struct copy with no compute
    // on the FFI hot path — without this cache the GUI's row-click
    // handler would re-derive these per port × per click.
    std::wstring             vendorShort;        ///< VendorShortener::shorten(vendor)
    std::wstring             enhancedDeviceType; ///< EnrichmentEngine::enhancedDeviceLabel(this)
    std::wstring             brandHint;          ///< EnrichmentEngine::brandHintAggregate(this)
    std::wstring             osHintCached;       ///< EnrichmentEngine::osHintForHost(this)
    std::wstring             deviceHintCached;   ///< EnrichmentEngine::deviceHintForHost(this)

    // UDP discovery summary (NBNS, NTP, SSDP, mDNS, SQL Browser, …).
    // Multi-line ("\r\n"-separated), each line "<probe>: <detail>";
    // empty when no probe responded or skip_udp_discovery was set.
    std::wstring             udpDiscovery;

    // Printer / MFP inventory via SNMP Printer-MIB (RFC 3805).
    // Populated by PrinterSnmpScanner when the host has printer port
    // signals (9100/515/631) or a printer-vendor OUI. Empty when
    // skip_printer_snmp is set or the host doesn't look like a printer.
    bool                     isPrinter         = false;
    std::wstring             printerVendor;
    std::wstring             printerModel;
    std::wstring             printerSerial;
    std::wstring             printerSnmpStatus;   // "ok" / "unavailable" / "no supplies" / "not probed"
    // Supplies in a "\r\n"-line / TAB-column format ready for the GUI:
    //   "<color>\t<type>\t<percent>\t<level>\t<max>\t<description>"
    // The percent column is "—" when unknown.
    std::wstring             printerSupplies;
    // v1.4.1 — lifetime page / scan counters, TAB-separated:
    //   "<total>\t<color>\t<mono>\t<scans>"  (each empty when unknown).
    std::wstring             printerPages;

    // v1.4.5 — exposed SMB shares from anonymous NetShareEnum. One share per
    // "\r\n"-line, TAB columns: "<netname>\t<type>\t<remark>". Empty when the
    // host blocks anonymous enumeration or has no SMB.
    std::wstring             smbShares;

    // v1.5.0 — IoT (Roborock/Xiaomi robot-vacuum) fingerprint. Empty unless
    // the host is a candidate. First line is "<score>\t<label>"; subsequent
    // "\r\n"-lines are evidence/detail strings shown verbatim in the UI.
    std::wstring             iotFingerprint;

    // v1.3.2 — heuristic security findings populated by SecurityAdvisor
    // after the fingerprint pass. Multi-line; one finding per line, tab-
    // separated columns:
    //   severity \t id \t title \t url
    // Severity ∈ { "critical", "high", "medium", "low" }.
    // Ordering: critical first, then high, then EOL/medium/low.
    // Empty string when no rule matched.
    std::wstring             securityFindings;

    [[nodiscard]] std::wstring statusText() const { return isOnline ? L"Online" : L"Offline"; }

    [[nodiscard]] std::wstring openPortsText() const {
        // Pull out the open ports and sort numerically before formatting.
        // The internal `ports` vector is in scan order (with the All-Ports
        // preset that's "common ports first, then 1-65535"), which is helpful
        // for showing progress live but looks chaotic in the final report.
        std::vector<int> open;
        open.reserve(ports.size());
        for (const auto& p : ports) {
            if (p.isOpen) open.push_back(p.port);
        }
        std::sort(open.begin(), open.end());
        std::wstring s;
        for (size_t i = 0; i < open.size(); ++i) {
            if (i > 0) s += L", ";
            s += std::to_wstring(open[i]);
        }
        return s;
    }

    [[nodiscard]] std::wstring serviceLabelsText() const {
        // Same numeric ordering as openPortsText so the two columns align
        // for the user reading left-to-right.
        std::vector<std::pair<int, std::wstring>> open;
        open.reserve(ports.size());
        for (const auto& p : ports) {
            if (p.isOpen && !p.service.empty()) {
                open.emplace_back(p.port, p.service);
            }
        }
        std::sort(open.begin(), open.end(),
                  [](const auto& a, const auto& b){ return a.first < b.first; });
        std::wstring s;
        for (size_t i = 0; i < open.size(); ++i) {
            if (i > 0) s += L", ";
            s += open[i].second;
        }
        return s;
    }

    // --- v1.2 service-fingerprint formatting ---------------------------------

    /// Compact one-line summary for the GUI "Services" column, e.g.
    /// "Apache 2.4, MariaDB 10.6, NTP +3m42s". Empty when nothing was found.
    [[nodiscard]] std::wstring serviceSummary() const {
        std::wstring s;
        auto add = [&](const std::wstring& tok) {
            if (tok.empty()) return;
            if (!s.empty()) s += L", ";
            s += tok;
        };
        for (const auto& f : fingerprints) {
            if (f.service == L"clock") continue;  // surfaced from clockDrift below
            std::wstring tok;
            if (!f.product.empty()) {
                tok = f.product;
                if (!f.version.empty()) tok += L" " + shortVersion(f.version);
            } else if (!f.service.empty()) {
                tok = f.service;
            }
            add(tok);
        }
        if (clockDrift.responded)
            add(clockDrift.source + L" " + clockDrift.compactText());
        return s;
    }

    /// Verbose "; "-joined form for CSV export, e.g.
    /// "80/tcp Apache 2.4.58 [HTTP Server header]; 123/udp NTP offset +00:03:42".
    [[nodiscard]] std::wstring fingerprintExportText() const {
        std::wstring s;
        for (const auto& f : fingerprints) {
            if (!s.empty()) s += L"; ";
            s += std::to_wstring(f.port) + L"/"
               + (f.protocol.empty() ? std::wstring(L"tcp") : f.protocol) + L" ";
            if (f.service == L"clock") {
                s += clockDrift.source + L" offset " + clockDrift.offsetText();
                continue;
            }
            s += f.product.empty() ? f.service : f.product;
            if (!f.version.empty()) s += L" " + f.version;
            if (!f.source.empty())  s += L" [" + f.source + L"]";
        }
        return s;
    }

    /// Multi-line human-readable form for the "Copy service details" action.
    [[nodiscard]] std::wstring serviceDetailsMultiline() const {
        std::wstring s = ipAddress;
        if (!hostname.empty()) s += L"  (" + hostname + L")";
        s += L"\r\n";
        if (fingerprints.empty()) {
            s += L"  (no service fingerprints)\r\n";
            return s;
        }
        for (const auto& f : fingerprints) {
            s += L"  " + std::to_wstring(f.port) + L"/"
               + (f.protocol.empty() ? std::wstring(L"tcp") : f.protocol) + L"  ";
            s += f.product.empty() ? f.service : f.product;
            if (!f.version.empty())    s += L" " + f.version;
            if (!f.confidence.empty()) s += L"  (" + f.confidence + L" confidence)";
            s += L"\r\n";
            if (!f.detail.empty()) s += L"      " + f.detail + L"\r\n";
            if (!f.title.empty())  s += L"      title: " + f.title + L"\r\n";
            if (!f.source.empty()) s += L"      source: " + f.source + L"\r\n";
        }
        return s;
    }

    /// "<type> - <model>" for the GUI / reports, or just the type when no
    /// model was found. Empty when the host has not been classified.
    [[nodiscard]] std::wstring deviceText() const {
        if (deviceType.empty())  return {};
        if (deviceModel.empty()) return deviceType;
        return deviceType + L" - " + deviceModel;
    }
};

// -----------------------------------------------------------------------------
// Scan mode — controls how we treat hosts that don't answer ICMP
// -----------------------------------------------------------------------------

enum class ScanMode {
    /// ICMP first. For ICMP-silent hosts probe a tiny discovery port set
    /// (80, 443, 445, 3389). If none of those answers, host is Offline and
    /// we do NOT scan the full configured port list on it.
    Fast,

    /// ICMP first. For ICMP-silent hosts run the full configured port list
    /// as a TCP fallback. Slower but catches hosts that block ping AND
    /// have only "exotic" ports open.
    Deep,

    /// ICMP + DNS + MAC only. No TCP. Cheapest sweep — just "who's there".
    DiscoveryOnly
};

inline const wchar_t* ScanModeToString(ScanMode m) {
    switch (m) {
        case ScanMode::Fast:          return L"Fast";
        case ScanMode::Deep:          return L"Deep";
        case ScanMode::DiscoveryOnly: return L"Discovery-only";
    }
    return L"Fast";
}

inline const wchar_t* ScanModeId(ScanMode m) {
    switch (m) {
        case ScanMode::Fast:          return L"fast";
        case ScanMode::Deep:          return L"deep";
        case ScanMode::DiscoveryOnly: return L"discovery";
    }
    return L"fast";
}

// -----------------------------------------------------------------------------
// Scan options selected by the user
// -----------------------------------------------------------------------------

struct ScanOptions {
    std::wstring  rangeText;
    std::wstring  adapterLabel;
    std::wstring  presetName;
    std::vector<int> ports;
    int           timeoutMs       = 400;
    int           parallel        = 128;
    // v1.0.8 default: Deep. Fast was the original default but it relies on
    // ICMP-first discovery, which misses Windows boxes with the firewall
    // blocking echo replies (the SMB default) and devices that explicitly
    // drop ICMP. Deep does a TCP-fallback sweep on the configured port set
    // for ICMP-silent hosts, so the count of "online" hosts matches what
    // users see in nbtstat / nmap. It costs a few seconds more on a /24 —
    // worth it for a discovery tool whose entire job is "show me what's
    // really on this LAN".
    ScanMode      mode            = ScanMode::Deep;
    bool          onlineOnly      = false;
    bool          skipDns         = false;
    bool          skipMac         = false;
    bool          skipPorts       = false;

    // v1.2 — lightweight service fingerprinting + NTP clock drift. Both run
    // only for online hosts and never in Discovery-only mode. Auto-disabled
    // for very large ranges (see kFingerprintAutoOffThreshold), in the same
    // spirit as the existing reverse-DNS auto-disable.
    bool          skipFingerprint = false;
    bool          skipClockDrift  = false;
    bool          skipUdpDiscovery = false;  // skip UDP probes (NBNS/NTP/SSDP/mDNS/SQL Browser/DNS/LLMNR/IPMI)
    bool          skipPrinterSnmp  = false;  // skip Printer-MIB SNMP probe entirely
    bool          wantPrinterSupplies = true;// false on Quick: vendor/model only, skip the prtMarkerSupplies walk
    int           fingerprintTimeoutMs = 600;

    // v1.2 — IPv4 of the active adapter's default gateway, when known. Used by
    // DeviceClassifier as the strongest "this host is the router" signal.
    // Empty for manual ranges with no adapter selected.
    std::wstring  gatewayIp;

    // v1.3.6 — Count of leading "priority" addresses in the reordered scan
    // list (tier 1 = the local /24, tier 2 = scout candidates .1/.254/.255
    // of every other /24). When > 0, executeScanLoop uses a dynamic priority
    // queue instead of the plain sequential atomic counter: the priority
    // addresses dispatch first, and as soon as a scout (or any host) in a
    // remote /24 responds, that whole /24 is promoted ahead of the still-dead
    // subnets. 0 means "no tiering — scan the list straight through".
    size_t        priorityCount   = 0;
};

// -----------------------------------------------------------------------------
// Aggregated summary of one scan
// -----------------------------------------------------------------------------

struct ScanSummary {
    int           totalScanned       = 0;
    int           onlineCount        = 0;
    int           offlineCount       = 0;
    int           rdpOpenCount       = 0;
    int           smbOpenCount       = 0;
    int           webOpenCount       = 0;
    int           highRiskCount      = 0;
    int           mediumRiskCount    = 0;
    int64_t       durationMs         = 0;
    std::wstring  rangeUsed;
    std::wstring  adapterUsed;
    std::wstring  presetUsed;
    int           timeoutUsed        = 0;
    int           parallelUsed       = 0;
    ScanMode      modeUsed           = ScanMode::Fast;
    std::wstring  startedAt;          ///< local time, formatted "YYYY-MM-DD HH:MM:SS"

    /// v1.2 — device-type tally across the online hosts ("Windows PC" → 3,
    /// "Printer" → 2, …), ordered by count descending with "Unknown" last.
    /// Built by the scanner; surfaced in the CLI summary and HTML report.
    std::vector<std::pair<std::wstring, int>> deviceTypeCounts;

    /// True when the scan was stopped by the user before all hosts were
    /// probed. Results in this case are a partial snapshot — only hosts the
    /// driver had reached are present. Reports and the UI need to flag this
    /// state so a user doesn't mistake a 12-online partial for the full
    /// picture.
    bool          wasCancelled       = false;
};

// -----------------------------------------------------------------------------
// Scan preset
// -----------------------------------------------------------------------------

struct ScanPreset {
    std::wstring  id;          ///< machine id ("quick", "windows", ...)
    std::wstring  displayName; ///< menu label
    std::vector<int> ports;
};

} // namespace lanscope
