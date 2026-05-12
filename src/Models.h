#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace netlens {

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
};

// -----------------------------------------------------------------------------
// Discovery method — how the host was confirmed online
// -----------------------------------------------------------------------------

enum class DiscoveryMethod {
    None,        ///< host did not respond at all
    Icmp,        ///< responded to ICMP echo
    TcpFallback  ///< ICMP failed, but at least one TCP port answered
};

inline const wchar_t* DiscoveryMethodToString(DiscoveryMethod m) {
    switch (m) {
        case DiscoveryMethod::Icmp:        return L"ICMP";
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
// UDP service probe results
//
//   v1.2.0 adds light, service-specific UDP probes for high-signal ports on
//   every confirmed-online host. These are NOT a generalist UDP port scanner
//   — they are deterministic protocol probes that only ever yield a positive
//   result when the matching service is actually running. No "open|filtered"
//   ambiguity, no ICMP rate-limit dependency.
// -----------------------------------------------------------------------------

struct UdpServiceInfo {
    // UDP 137 — NetBIOS Name Service (NBSTAT)
    std::wstring               netbiosName;        ///< computer name
    std::wstring               netbiosWorkgroup;   ///< domain / workgroup

    // UDP 5353 — multicast DNS (queried unicast for response)
    std::vector<std::wstring>  mdnsServices;       ///< service-type names, e.g. "_ipp._tcp.local"

    // UDP 1900 — SSDP / UPnP discovery
    std::wstring               upnpServer;         ///< Server header value
    std::wstring               upnpLocation;       ///< Location URL of device description

    // UDP 161 — SNMPv1 GET sysDescr.0 with community "public"
    std::wstring               snmpSysDescr;       ///< trimmed system description

    // UDP 53 — DNS server version (CHAOS version.bind TXT)
    std::wstring               dnsVersion;

    // UDP 123 — NTP server response
    int                        ntpStratum = -1;    ///< -1 = no response; 0-15 = stratum
    int                        ntpVersion = 0;
    std::wstring               ntpRefId;           ///< ASCII refid for stratum-1 servers

    [[nodiscard]] bool anyOpen() const {
        return !netbiosName.empty()
            || !netbiosWorkgroup.empty()
            || !mdnsServices.empty()
            || !upnpServer.empty()
            || !snmpSysDescr.empty()
            || !dnsVersion.empty()
            || ntpStratum >= 0;
    }

    [[nodiscard]] std::wstring summaryLine() const;
};

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

    // Filled in by RiskAnalyzer after the host is fully probed.
    RiskLevel                riskLevel          = RiskLevel::None;
    std::wstring             riskHints;          ///< comma-separated user-readable hints

    // Filled in by UdpProbes when ScanOptions.skipUdp == false. Empty for
    // offline hosts and for scans that opted out of UDP enrichment.
    UdpServiceInfo           udp;

    [[nodiscard]] std::wstring statusText() const { return isOnline ? L"Online" : L"Offline"; }

    /// Returns the best human-readable name for this host: the reverse-DNS
    /// hostname if available, falling back to the NetBIOS name from the UDP
    /// 137 probe. Empty when neither is known. Used by the GUI's Hostname
    /// column, the row search, sort, and the host-details dialog so the
    /// user sees a name for Windows machines / printers / IoT even when
    /// reverse DNS is broken.
    [[nodiscard]] std::wstring effectiveHostname() const {
        return !hostname.empty() ? hostname : udp.netbiosName;
    }

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
    // v1.2.0: when false (default), each online host gets a parallel batch of
    // service-specific UDP probes (NBSTAT / mDNS / SSDP / SNMP-public / DNS
    // version / NTP) to enrich the result with IoT, printer, NAS, VoIP, and
    // network-gear info that TCP scanning typically misses. Auto-disabled by
    // the GUI for ranges above kUdpAutoOffThreshold to keep large sweeps
    // within reasonable wall-clock budgets.
    bool          skipUdp         = false;
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

} // namespace netlens
