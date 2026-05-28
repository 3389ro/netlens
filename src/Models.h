#ifndef NETLENS_MODELS_H
#define NETLENS_MODELS_H

#include <cstdint>
#include <string>
#include <vector>

namespace nl {

enum class HostStatus      : uint8_t { Unknown, Online, Offline };
enum class RiskLevel       : uint8_t { None, Low, Medium, High, Critical };
enum class DiscoveryMethod : uint8_t { Unknown, ICMP, ARP, TCP, ArpIcmp };
enum class ScanMode        : uint8_t { Fast = 0, Deep = 1, DiscoveryOnly = 2 };
enum class ScanPreset      : uint8_t {
    Quick = 0, Standard, FullCommon, AllPortsFast, AllPortsDeep, CustomPorts
};
enum class HostFilter      : uint8_t { All = 0, OnlineOnly, HasOpenPorts };
// v1.3.3 — orthogonal severity filter, applied on top of HostFilter.
// "None" passes every host through; the three positive states pass
// only hosts whose worst finding meets-or-exceeds the threshold.
// Matches the CVE colour coding (Critical=red, High=orange,
// Medium=amber) used in the host-grid row text and the right pane.
enum class SeverityFilter  : uint8_t { None = 0, MediumPlus, HighPlus, CriticalOnly };

enum class ServiceCategory : uint8_t { Other, Web, Remote, Shell, Share, Mgmt, Db };

struct ServiceBadge {
    std::wstring     label;
    ServiceCategory  category = ServiceCategory::Other;
};

// Heuristic security finding produced by the engine's SecurityAdvisor
// after the fingerprint pass. Either a curated CVE match (RCE or
// credential takeover only — no DoS / info-disclosure) or an EOL /
// lifecycle hit. Rendered in the DetailsPanel "Security findings"
// section and in the HTML report.
enum class FindingSeverity : uint8_t { Critical, High, Medium, Low };

struct SecurityFinding {
    FindingSeverity severity = FindingSeverity::Medium;
    std::wstring    id;       // "CVE-2017-0144" / "EOL-SMB1"
    std::wstring    title;    // short human-readable headline
    std::wstring    url;      // reference URL (may be empty)
};

struct PortRow {
    int32_t       port = 0;
    bool          isOpen = false;
    std::wstring  service;
    std::wstring  protocol;
    std::wstring  product;
    std::wstring  version;
    std::wstring  versionNote;
    std::wstring  detail;
    uint32_t      ownerPid = 0;
    std::wstring  ownerExe;
};

struct HostRow {
    int32_t         engineIndex = -1;
    uint32_t        ipV4 = 0;            // packed host-order for sort
    std::wstring    ip;
    std::wstring    hostname;
    std::wstring    vendor;
    std::wstring    mac;
    std::wstring    deviceType;
    std::wstring    deviceModel;
    std::wstring    openPorts;           // engine CSV "80, 443"
    std::wstring    services;            // engine CSV "http, https"
    std::wstring    brandHint;           // may be multi-line
    std::wstring    osHint;
    std::wstring    deviceHint;
    std::wstring    webUiModel;
    std::wstring    udpDiscovery;        // multi-line UDP probe summary
    // Printer / MFP inventory via SNMP (Printer-MIB).
    bool            isPrinter        = false;
    std::wstring    printerVendor;
    std::wstring    printerModel;
    std::wstring    printerSerial;
    std::wstring    printerSnmpStatus;   // "ok" / "unavailable" / "no supplies" / "not probed"
    std::wstring    printerSupplies;     // "\r\n"-lines, "\t"-cols: color/type/pct/lvl/max/desc
    std::wstring    printerPages;        // v1.4.1 — "<total>\t<color>\t<mono>\t<scans>" (blank = unknown)
    std::wstring    smbShares;           // v1.4.5 — "\r\n"-lines: "<netname>\t<type>\t<remark>"
    std::wstring    iotFingerprint;      // v1.5.0 — line0 "<score>\t<label>", then evidence lines
    bool            isOnline = false;
    RiskLevel       risk = RiskLevel::None;
    int32_t         responseMs = 0;
    DiscoveryMethod discovery = DiscoveryMethod::Unknown;
    int32_t         portCount = 0;
    int32_t         serviceCount = 0;
    bool            clockResponded = false;
    int64_t         clockOffsetMs = 0;
    // Smallest open port number on the host, parsed once at snapshot
    // build-time so the comparator that backs the "Open TCP ports" column
    // sort doesn't reparse the openPorts CSV on every comparison. 0 when
    // the host has no open ports (sorts first ascending — same place as
    // count-based sort used to put them, so the visual behaviour matches).
    int32_t         firstOpenPort = 0;
    // Heuristic security findings produced by the engine (v1.3.2).
    // Parsed at snapshot apply time from `nl_result_t.security_findings`.
    // Order is the engine's order — critical first, then high, then
    // EOL / medium / low — the DetailsPanel renders top-down.
    std::vector<SecurityFinding> findings;
    std::vector<ServiceBadge> badges;
    std::vector<PortRow>      ports;
};

struct ScanStats {
    int32_t       totalScanned = 0;
    int32_t       onlineCount = 0;
    int32_t       offlineCount = 0;
    int64_t       durationMs = 0;
    int32_t       progressDone = 0;
    int32_t       progressTotal = 0;
    int64_t       probesDone = 0;
    int64_t       probesTotalEstimate = 0;
    bool          isScanning = false;
    float         progress01 = 0.0f;
    std::wstring  statusText;
    std::wstring  lastError;

    // Recent-window rate sample for ETA. The cumulative average is
    // wildly off because online hosts (which come first) do hundreds of
    // port probes each while offline hosts only do an ICMP ping; sampling
    // a short window catches the rate flip when the scan transitions to
    // the offline-tail phase. EMA-smoothed over 5 ticks (~400 ms).
    double        recentHostsPerSec = 0.0;
    bool          hasRecentRate     = false;

    // Probe throughput. Steadier than host-rate (probes accumulate
    // 1-per-port-attempt while hosts complete in clumps) — shown on the
    // SCAN PROGRESS KPI card as a live speed read-out.
    double        recentProbesPerSec = 0.0;
};

struct AdapterInfo {
    int32_t       index = 0;
    int32_t       type = 0;
    bool          operational = false;
    std::wstring  friendlyName;
    std::wstring  description;
    std::wstring  ip;
    std::wstring  subnet;
    std::wstring  gateway;
    std::wstring  suggestedRange;
};

struct AppSettings {
    int32_t       timeoutMs = 400;
    int32_t       parallel = 256;
    ScanMode      mode = ScanMode::Deep;
    bool          skipDns = false;
    bool          skipMac = false;
    bool          skipPorts = false;
    bool          skipFingerprint = false;
    bool          skipClockDrift = false;
    bool          skipUdpDiscovery = false;   // UDP probes (NBNS/NTP/SSDP/mDNS/SQL Browser/DNS/LLMNR/IPMI)
    bool          skipPrinterSnmp  = false;   // SNMP Printer-MIB probe on printer-like hosts
    int32_t       fingerprintTimeoutMs = 600;
    std::wstring  portsCsv;     // empty = engine default
    std::wstring  gatewayIp;
};

struct PortPreset {
    ScanPreset            id = ScanPreset::Quick;
    std::wstring          displayName;
    std::vector<uint16_t> ports;
    std::wstring          description;
};

}  // namespace nl

#endif // NETLENS_MODELS_H
