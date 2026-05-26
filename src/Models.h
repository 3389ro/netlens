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

enum class ServiceCategory : uint8_t { Other, Web, Remote, Shell, Share, Mgmt, Db };

struct ServiceBadge {
    std::wstring     label;
    ServiceCategory  category = ServiceCategory::Other;
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
    bool            isOnline = false;
    RiskLevel       risk = RiskLevel::None;
    int32_t         responseMs = 0;
    DiscoveryMethod discovery = DiscoveryMethod::Unknown;
    int32_t         portCount = 0;
    int32_t         serviceCount = 0;
    bool            clockResponded = false;
    int64_t         clockOffsetMs = 0;
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
