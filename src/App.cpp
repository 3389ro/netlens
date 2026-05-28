#include "App.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <deque>
#include <iterator>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "netlens_engine.h"
#include "MainWindow.h"   // WM_NL_APPLY_SNAPSHOT, WM_NL_SCAN_FINISHED
#include "MockData.h"     // --mock fleet + embedded HTML report

namespace nl {

namespace {

// ---------------------------------------------------------------------------
// Engine handle — opaque to App.h, isolated to this translation unit.
// ---------------------------------------------------------------------------
nl_scanner_t* g_scanner = nullptr;
bool          g_inited  = false;

// ---------------------------------------------------------------------------
// UTF-8 ↔ UTF-16 helpers (Win32 only, no <codecvt>).
// ---------------------------------------------------------------------------
std::wstring Utf8ToWide(const char* s) {
    if (!s || !*s) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (len <= 1) return {};
    std::wstring w;
    w.resize(static_cast<size_t>(len - 1));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), len);
    return w;
}

// Parse a dotted-quad ASCII IPv4 into packed host-order. 0 on parse failure.
// The forked engine predates `nl_result_t::ip_v4`, so we derive it here.
uint32_t ParseIpV4(const char* s) {
    if (!s) return 0;
    uint32_t parts[4] = {};
    int idx = 0;
    uint32_t cur = 0;
    bool any = false;
    for (const char* p = s; ; ++p) {
        if (*p >= '0' && *p <= '9') {
            cur = cur * 10 + static_cast<uint32_t>(*p - '0');
            if (cur > 255) return 0;
            any = true;
        } else if (*p == '.' || *p == 0) {
            if (!any || idx >= 4) return 0;
            parts[idx++] = cur;
            cur = 0;
            any = false;
            if (*p == 0) break;
        } else {
            return 0;
        }
    }
    if (idx != 4) return 0;
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1,
                                  nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string out;
    out.resize(static_cast<size_t>(len - 1));
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), len,
                        nullptr, nullptr);
    return out;
}

// ---------------------------------------------------------------------------
// Search / categorization helpers.
// ---------------------------------------------------------------------------
bool ContainsIgnoreCase(const std::wstring& haystack, const std::wstring& needleLower) {
    if (needleLower.empty()) return true;
    if (needleLower.size() > haystack.size()) return false;
    for (size_t i = 0; i + needleLower.size() <= haystack.size(); ++i) {
        bool eq = true;
        for (size_t j = 0; j < needleLower.size(); ++j) {
            wchar_t a = haystack[i + j];
            if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a - L'A' + L'a');
            if (a != needleLower[j]) { eq = false; break; }
        }
        if (eq) return true;
    }
    return false;
}

bool ContainsLowerNeedle(const std::wstring& haystack, std::wstring_view needleLower) {
    return ContainsIgnoreCase(haystack, std::wstring{ needleLower });
}

ServiceCategory CategorizeService(const std::wstring& s) {
    auto has = [&](std::wstring_view kw) { return ContainsLowerNeedle(s, kw); };
    if (has(L"http"))                                              return ServiceCategory::Web;
    if (has(L"rdp") || has(L"vnc") || has(L"telnet"))              return ServiceCategory::Remote;
    if (has(L"ssh") || has(L"sftp"))                               return ServiceCategory::Shell;
    if (has(L"smb") || has(L"nfs") || has(L"afp") || has(L"ftp"))  return ServiceCategory::Share;
    if (has(L"snmp") || has(L"winrm") || has(L"ipmi"))             return ServiceCategory::Mgmt;
    if (has(L"sql") || has(L"postgres") || has(L"mongo")
        || has(L"redis") || has(L"maria") || has(L"oracle"))       return ServiceCategory::Db;
    return ServiceCategory::Other;
}

// Generate badges from h.openPorts (CSV of port numbers) using the
// canonical port → protocol map. Renders as "HTTP, HTTPS, SMB, RDP,
// WinRM, MySQL" instead of the engine's fingerprinted product strings
// ("Apache 2.4, Microsoft SQL Server 14.0"). Deduplicates so port 139
// + 445 don't both produce an "SMB" pill.
void ParseBadges(HostRow& h) {
    h.badges.clear();
    if (h.openPorts.empty()) return;

    std::wstring cur;
    std::vector<std::wstring> seen;  // preserves first-seen order
    auto flush = [&]() {
        while (!cur.empty() && (cur.front() == L' ' || cur.front() == L'\t')) cur.erase(cur.begin());
        while (!cur.empty() && (cur.back()  == L' ' || cur.back()  == L'\t')) cur.pop_back();
        if (cur.empty()) return;

        unsigned port = 0;
        bool ok = true;
        for (wchar_t c : cur) {
            if (c >= L'0' && c <= L'9') {
                port = port * 10 + static_cast<unsigned>(c - L'0');
                if (port > 65535) { ok = false; break; }
            } else { ok = false; break; }
        }
        cur.clear();
        if (!ok || port == 0) return;

        const wchar_t* name = App::CanonicalServiceForPort(static_cast<uint16_t>(port));
        std::wstring label(name);
        for (const auto& s : seen) if (s == label) return;
        seen.push_back(label);
        h.badges.push_back({ std::move(label), CategorizeService(name) });
    };
    for (wchar_t c : h.openPorts) {
        if (c == L',') flush();
        else           cur.push_back(c);
    }
    flush();
}

// ---------------------------------------------------------------------------
// Per-preset port arrays. SINGLE SOURCE OF TRUTH — both the scanner (which
// builds the CSV passed to nl_scan_opts_t.ports_csv) and the Port Lists dialog
// (which renders the port/service grid) read from these arrays.
//   Quick      = 61 ports
//   Standard   = 132 ports
//   FullCommon = 235 ports  (+9191/9192/9195 PaperCut, +58867 Roborock)
// ---------------------------------------------------------------------------
constexpr uint16_t kQuickPorts[] = {
    21, 22, 23, 25, 53, 80, 88, 110, 135, 137, 138, 139, 143, 161,
    389, 443, 445, 465, 500, 515, 548, 554, 587, 631, 636, 902,
    993, 995, 1433, 1723, 1883, 1900, 2049, 3000, 3128, 3306,
    3389, 5000, 5001, 5060, 5353, 5355, 5432, 5900, 5985, 5986,
    6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100,
    9200, 10000, 27017, 37777, 62078,
};

constexpr uint16_t kStandardPorts[] = {
    21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 137, 138,
    139, 143, 161, 162, 389, 443, 445, 465, 500, 514, 515, 548,
    554, 587, 623, 631, 636, 676, 873, 902, 990, 993, 995, 999,
    1080, 1194, 1311, 1433, 1434, 1521, 1723, 1812, 1813, 1883,
    1900, 2049, 2082, 2083, 2086, 2087, 2222, 2375, 2376, 3000,
    3001, 3128, 3260, 3268, 3269, 3306, 3389, 3478, 4500, 5000,
    5001, 5005, 5060, 5353, 5355, 5357, 5432, 5555, 5601, 5672,
    5800, 5900, 5985, 5986, 6379, 6443, 7001, 7070, 7547, 8000,
    8001, 8008, 8080, 8081, 8082, 8083, 8086, 8088, 8089, 8090,
    8091, 8161, 8200, 8443, 8500, 8554, 8834, 8880, 8883, 8888,
    8983, 9000, 9001, 9042, 9043, 9090, 9092, 9100, 9200, 9300,
    9443, 10000, 10250, 10255, 10443, 11211, 15672, 17988, 27017,
    27018, 32400, 37777, 50000, 62078,
};

constexpr uint16_t kFullCommonPorts[] = {
    7, 9, 13, 17, 19, 21, 22, 23, 25, 37, 49, 53, 69, 80, 88, 106,
    109, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 199, 264, 389, 427, 443, 444, 445, 464, 465, 497, 500,
    512, 513, 514, 515, 520, 546, 547, 548, 554, 563, 587, 623,
    631, 636, 664, 676, 691, 873, 902, 989, 990, 993, 995, 999,
    1025, 1026, 1027, 1028, 1029, 1080, 1194, 1241, 1311, 1433,
    1434, 1521, 1524, 1720, 1723, 1812, 1813, 1883, 1900, 2000,
    2048, 2049, 2082, 2083, 2086, 2087, 2222, 2375, 2376, 2379,
    2380, 2483, 2484, 2601, 2604, 3000, 3001, 3128, 3260, 3268,
    3269, 3306, 3389, 3478, 3544, 3690, 4369, 4443, 4500, 4567,
    4662, 4786, 4848, 4899, 5000, 5001, 5005, 5060, 5222, 5223,
    5269, 5353, 5355, 5357, 5432, 5555, 5601, 5631, 5632, 5672,
    5683, 5800, 5900, 5985, 5986, 6000, 6001, 6002, 6003, 6004,
    6005, 6006, 6007, 6379, 6443, 6666, 6667, 6668, 6669, 6881,
    7001, 7070, 7547, 7777, 7946, 8000, 8001, 8008, 8080, 8081,
    8082, 8083, 8086, 8088, 8089, 8090, 8091, 8100, 8161, 8200,
    8333, 8383, 8443, 8500, 8554, 8649, 8834, 8880, 8883, 8888,
    8983, 9000, 9001, 9042, 9043, 9090, 9092, 9100,
    9191, 9192, 9195,                         // PaperCut NG/MF admin (CVE-2023-27350)
    9200, 9300,
    9418, 9443, 9999, 10000, 10250, 10255, 10443, 11211, 15672,
    17988, 24800, 25565, 27017, 27018, 28015, 32400, 32764, 32768,
    32769, 32770, 32771, 32772, 32773, 32774, 32775, 37777, 49152,
    49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 50000,
    58867,                                    // Roborock local protocol (v1.5.0)
    62078,
};

std::wstring BuildPortsCsv(const uint16_t* arr, size_t n) {
    std::wstring out;
    out.reserve(n * 6);
    wchar_t buf[12];
    for (size_t i = 0; i < n; ++i) {
        if (i) out.push_back(L',');
        wsprintfW(buf, L"%u", static_cast<unsigned>(arr[i]));
        out += buf;
    }
    return out;
}

std::wstring PresetToPortsCsv(ScanPreset p, const std::wstring& customCsv) {
    switch (p) {
        case ScanPreset::Quick:        return BuildPortsCsv(kQuickPorts,      std::size(kQuickPorts));
        case ScanPreset::Standard:     return BuildPortsCsv(kStandardPorts,   std::size(kStandardPorts));
        case ScanPreset::FullCommon:   return BuildPortsCsv(kFullCommonPorts, std::size(kFullCommonPorts));
        case ScanPreset::AllPortsFast: return L"1-65535";
        case ScanPreset::AllPortsDeep: return L"1-65535";
        case ScanPreset::CustomPorts:  return customCsv;
    }
    return L"";
}

// Tiered phase 2 port spec: "1-65535 minus the FullCommon set". Phase 1 already
// deep-checked every FullCommon port, so phase 2 only needs the long tail — that
// makes it purely additive (it never re-scans, or momentarily re-reports as
// fewer, the ports discovery already found). Returned as a compact range list
// (e.g. "1-19,21,23-24,..."). Computed once and cached.
std::wstring AllPortsExceptFullCommonCsv() {
    static const std::wstring cached = [] {
        std::vector<bool> skip(65537, false);
        for (size_t i = 0; i < std::size(kFullCommonPorts); ++i) {
            unsigned p = kFullCommonPorts[i];
            if (p >= 1 && p <= 65535) skip[p] = true;
        }
        std::wstring out;
        int runStart = -1;
        for (int p = 1; p <= 65536; ++p) {            // p == 65536 flushes the last run
            bool inc = (p <= 65535) && !skip[p];
            if (inc) {
                if (runStart < 0) runStart = p;
            } else if (runStart >= 0) {
                int runEnd = p - 1;
                if (!out.empty()) out += L',';
                out += std::to_wstring(runStart);
                if (runEnd != runStart) { out += L'-'; out += std::to_wstring(runEnd); }
                runStart = -1;
            }
        }
        return out;
    }();
    return cached;
}

// Canonical port → service description. Used by the Port Lists dialog
// only; the engine has its own internal service detection and is not
// driven by this table.
const std::unordered_map<uint16_t, const wchar_t*>& PortServiceMap() {
    static const std::unordered_map<uint16_t, const wchar_t*> m = {
        {7,    L"echo"},
        {9,    L"discard"},
        {13,   L"daytime"},
        {17,   L"qotd / quote of the day"},
        {19,   L"chargen"},
        {21,   L"FTP"},
        {22,   L"SSH / SFTP"},
        {23,   L"Telnet"},
        {25,   L"SMTP"},
        {37,   L"time"},
        {49,   L"TACACS+"},
        {53,   L"DNS"},
        {69,   L"TFTP"},
        {80,   L"HTTP"},
        {88,   L"Kerberos"},
        {106,  L"PoP3 OpenWebmail"},
        {109,  L"POP2"},
        {110,  L"POP3"},
        {111,  L"RPCbind / Portmapper"},
        {119,  L"NNTP"},
        {123,  L"NTP"},
        {135,  L"MS RPC Endpoint Mapper"},
        {137,  L"NetBIOS Name Service"},
        {138,  L"NetBIOS Datagram"},
        {139,  L"NetBIOS Session Service"},
        {143,  L"IMAP"},
        {161,  L"SNMP"},
        {162,  L"SNMP trap"},
        {179,  L"BGP"},
        {199,  L"SMUX"},
        {264,  L"BGMP"},
        {389,  L"LDAP"},
        {427,  L"SLP"},
        {443,  L"HTTPS"},
        {444,  L"SNPP"},
        {445,  L"SMB / Microsoft-DS"},
        {464,  L"Kerberos kpasswd"},
        {465,  L"SMTPS"},
        {497,  L"Retrospect"},
        {500,  L"IKE / IPsec VPN"},
        {512,  L"exec"},
        {513,  L"rlogin"},
        {514,  L"syslog"},
        {515,  L"LPD / printer service"},
        {520,  L"RIP routing"},
        {546,  L"DHCPv6 client"},
        {547,  L"DHCPv6 server"},
        {548,  L"AFP / Apple Filing Protocol"},
        {554,  L"RTSP, IP cameras, NVR"},
        {563,  L"NNTP over SSL"},
        {587,  L"SMTP submission"},
        {623,  L"IPMI"},
        {631,  L"IPP / CUPS printing"},
        {636,  L"LDAPS"},
        {664,  L"IPMI secure"},
        {676,  L"legacy / custom (compat)"},
        {691,  L"MS Exchange routing"},
        {873,  L"rsync"},
        {902,  L"VMware ESXi / vSphere"},
        {989,  L"FTPS data"},
        {990,  L"FTPS"},
        {993,  L"IMAPS"},
        {995,  L"POP3S"},
        {999,  L"custom / legacy admin"},
        {1025, L"RPC dynamic (1025)"},
        {1026, L"RPC dynamic (1026)"},
        {1027, L"RPC dynamic (1027)"},
        {1028, L"RPC dynamic (1028)"},
        {1029, L"RPC dynamic (1029)"},
        {1080, L"SOCKS proxy"},
        {1194, L"OpenVPN"},
        {1241, L"Nessus (legacy)"},
        {1311, L"Dell OpenManage"},
        {1433, L"Microsoft SQL Server"},
        {1434, L"MSSQL Browser"},
        {1521, L"Oracle DB"},
        {1524, L"ingreslock"},
        {1720, L"H.323"},
        {1723, L"PPTP VPN"},
        {1812, L"RADIUS auth"},
        {1813, L"RADIUS accounting"},
        {1883, L"MQTT"},
        {1900, L"SSDP / UPnP"},
        {2000, L"Cisco SCCP"},
        {2048, L"dlsrv2"},
        {2049, L"NFS"},
        {2082, L"cPanel"},
        {2083, L"cPanel SSL"},
        {2086, L"WHM"},
        {2087, L"WHM SSL"},
        {2222, L"SSH-alt"},
        {2375, L"Docker API (plain)"},
        {2376, L"Docker API (TLS)"},
        {2379, L"etcd client"},
        {2380, L"etcd peer"},
        {2483, L"Oracle DB (alt)"},
        {2484, L"Oracle DB SSL (alt)"},
        {2601, L"Zebra routing"},
        {2604, L"BGPd"},
        {3000, L"dev web / Grafana / Node"},
        {3001, L"dev web / Node"},
        {3128, L"Squid proxy"},
        {3260, L"iSCSI"},
        {3268, L"AD Global Catalog"},
        {3269, L"AD Global Catalog SSL"},
        {3306, L"MySQL / MariaDB"},
        {3389, L"RDP"},
        {3478, L"STUN / TURN"},
        {3544, L"Teredo"},
        {3690, L"Subversion"},
        {4369, L"EPMD (Erlang)"},
        {4443, L"HTTPS-alt"},
        {4500, L"IPsec NAT-T"},
        {4567, L"Sinatra / dev web"},
        {4662, L"eMule"},
        {4786, L"Cisco Smart Install"},
        {4848, L"GlassFish admin"},
        {4899, L"Radmin"},
        {5000, L"Synology DSM HTTP / Flask / UPnP"},
        {5001, L"Synology DSM HTTPS"},
        {5005, L"streaming / UPnP / media"},
        {5060, L"SIP VoIP"},
        {5222, L"XMPP client"},
        {5223, L"XMPP client SSL"},
        {5269, L"XMPP server-to-server"},
        {5353, L"mDNS"},
        {5355, L"LLMNR"},
        {5357, L"WSDAPI (Windows)"},
        {5432, L"PostgreSQL"},
        {5555, L"ADB wireless / Freeciv"},
        {5601, L"Kibana"},
        {5631, L"pcAnywhere data"},
        {5632, L"pcAnywhere status"},
        {5672, L"RabbitMQ / AMQP"},
        {5683, L"CoAP"},
        {5800, L"VNC over HTTP"},
        {5900, L"VNC"},
        {5985, L"WinRM HTTP"},
        {5986, L"WinRM HTTPS"},
        {6000, L"X11"},
        {6001, L"X11 (display :1)"},
        {6002, L"X11 (display :2)"},
        {6003, L"X11 (display :3)"},
        {6004, L"X11 (display :4)"},
        {6005, L"X11 (display :5)"},
        {6006, L"X11 (display :6)"},
        {6007, L"X11 (display :7)"},
        {6379, L"Redis"},
        {6443, L"Kubernetes API"},
        {6666, L"IRC"},
        {6667, L"IRC"},
        {6668, L"IRC"},
        {6669, L"IRC"},
        {6881, L"BitTorrent"},
        {7001, L"WebLogic / app server admin"},
        {7070, L"RealServer / custom admin"},
        {7547, L"TR-069 / CWMP"},
        {7777, L"various / Oracle apps"},
        {7946, L"Docker Swarm"},
        {8000, L"HTTP-alt / cameras / NVR / dev"},
        {8001, L"HTTP-alt / admin panels"},
        {8008, L"HTTP-alt / web services"},
        {8080, L"HTTP-alt / proxy / admin"},
        {8081, L"HTTP-alt / Nexus / admin"},
        {8082, L"HTTP-alt"},
        {8083, L"HTTP-alt"},
        {8086, L"InfluxDB"},
        {8088, L"HTTP-alt / Hadoop"},
        {8089, L"Splunk"},
        {8090, L"HTTP-alt / admin"},
        {8091, L"Couchbase admin"},
        {8100, L"various"},
        {8161, L"ActiveMQ web console"},
        {8200, L"Vault / DLNA"},
        {8333, L"Bitcoin"},
        {8383, L"Synology DSM rsync"},
        {8443, L"HTTPS-alt"},
        {8500, L"Consul"},
        {8554, L"RTSP-alt, IP cameras"},
        {8649, L"Ganglia"},
        {8834, L"Tenable Nessus"},
        {8880, L"HTTP-alt"},
        {8883, L"MQTT over TLS"},
        {8888, L"HTTP-alt / Jupyter / dev"},
        {8983, L"Apache Solr"},
        {9000, L"SonarQube / PHP-FPM / MinIO"},
        {9001, L"Supervisord / Tor ORPort"},
        {9042, L"Cassandra"},
        {9043, L"WebSphere admin"},
        {9090, L"Prometheus / Cockpit"},
        {9092, L"Kafka"},
        {9100, L"JetDirect / Prometheus node exp."},
        {9200, L"Elasticsearch HTTP"},
        {9300, L"Elasticsearch transport"},
        {9418, L"git"},
        {9443, L"HTTPS-alt / admin"},
        {9999, L"various / Samsung"},
        {10000, L"Webmin"},
        {10250, L"Kubelet"},
        {10255, L"Kubelet read-only"},
        {10443, L"HTTPS-alt"},
        {11211, L"Memcached"},
        {15672, L"RabbitMQ management"},
        {17988, L"legacy / custom"},
        {24800, L"Synergy"},
        {25565, L"Minecraft"},
        {27017, L"MongoDB"},
        {27018, L"MongoDB shard / replica"},
        {28015, L"Rust (game)"},
        {32400, L"Plex"},
        {32764, L"router backdoor"},
        {32768, L"RPC dynamic (32768)"},
        {32769, L"RPC dynamic (32769)"},
        {32770, L"RPC dynamic (32770)"},
        {32771, L"RPC dynamic (32771)"},
        {32772, L"RPC dynamic (32772)"},
        {32773, L"RPC dynamic (32773)"},
        {32774, L"RPC dynamic (32774)"},
        {32775, L"RPC dynamic (32775)"},
        {37777, L"Dahua / NVR / CCTV"},
        {49152, L"RPC high (49152)"},
        {49153, L"RPC high (49153)"},
        {49154, L"RPC high (49154)"},
        {49155, L"RPC high (49155)"},
        {49156, L"RPC high (49156)"},
        {49157, L"RPC high (49157)"},
        {49158, L"RPC high (49158)"},
        {49159, L"RPC high (49159)"},
        {49160, L"RPC high (49160)"},
        {50000, L"SAP / DB2 / enterprise"},
        {62078, L"Apple iPhone sync / lockdownd"},
    };
    return m;
}

}  // namespace

// ===========================================================================
// ScanSession — owns the scanner thread that polls the engine and posts
// snapshots to the UI window. Replaces the WM_TIMER-driven polling loop.
// All engine I/O happens on this thread; the UI never blocks waiting for
// nl_scanner_* calls (except for the synchronous PortsForHost from paint,
// which the engine already guards internally).
// ===========================================================================

// v1.3.4 — Tiered scan estimator inputs.
//
// When the user picks AllPortsFast / AllPortsDeep, the scan is split into two
// engine sessions: phase 1 runs a FullCommon (231-port) sweep so the user sees
// services within seconds, then phase 2 runs the All-Ports sweep on the full
// range. The estimator must show a stable ETA across the phase flip — without
// this the % would crash from "100% of phase 1" to "0% of phase 2" the moment
// nl_scanner_clear_results is called.
//
//   phase == 1: ScanSession projects the phase-2 cost upfront so
//               probesTotalEstimate already includes both phases. probesDone
//               grows naturally with phase-1 progress.
//   phase == 2: ScanSession adds the (known, final) phase-1 probe count to
//               BOTH probesDone and probesTotalEstimate. The new engine
//               session's probesDone starts at 0 but the displayed counter
//               continues from where phase 1 left off.
struct TieredEstimatorInputs {
    int     phase                = 0;   // 0 = non-tiered, 1 = phase 1 running, 2 = phase 2 running
    int64_t phase1FinalProbes    = 0;   // valid when phase == 2: actual final probesDone from phase 1
    int64_t phase1FinalDurationMs = 0;  // valid when phase == 2: phase-1 elapsed ms, added so DURATION continues
    int     phase2PortsPerHost   = 0;   // valid when phase == 1: per-online cost of the upcoming phase 2
    int     phase2ScanMode       = 0;   // valid when phase == 1: ScanMode int of the upcoming phase 2
};

class ScanSession {
public:
    // Mode-aware estimator.
    //
    //   `portsPerHost` is the real port-list size the engine will iterate per
    //   online host: 65535 for AllPorts presets, the CSV count for Custom
    //   Ports, kQuickPorts/kStandardPorts/kFullCommonPorts size for the rest.
    //   `mode` is the engine ScanMode value (Discovery/Fast/Deep). It drives
    //   how many probes the engine emits per OFFLINE host:
    //     - Discovery: 0   (offline → skip port scan entirely)
    //     - Fast:      26  (offline → fastDiscoveryPorts sweep, see
    //                       engine/AppConstants.h:kFastDiscoveryPorts)
    //     - Deep:      portsPerHost (offline → same full port sweep as online)
    //
    //   The previous model added a fake `kFingerprintProbes = 3000` and a
    //   `kPortRetryFactor = 2` multiplier. Both were wrong: the engine's
    //   `probesDone` counter increments ONLY inside PortScanner::scanHost,
    //   once per port-connect attempt — fingerprint probes and retries don't
    //   touch it. Verified on 254-host /24 LAN:
    //     - Quick (61 ports, Deep): final 15494 probes = 254 × 61 exactly
    //     - Standard (132, Deep):   33528 = 254 × 132
    //     - FullCommon (231, Deep): 58674 = 254 × 231
    //   Hence per-host = portsPerHost (Deep) or {portsPerHost / 26 / 0}
    //   depending on online-vs-offline and mode.
    ScanSession(HWND uiHwnd, int portsPerHost, int scanModeInt,
                TieredEstimatorInputs tiered = {})
        : uiHwnd_(uiHwnd),
          portsPerHostEstimate_(portsPerHost > 0 ? portsPerHost : 32),
          scanMode_(scanModeInt),
          tiered_(tiered) {
        thread_ = std::thread([this]() { runLoop(); });
    }
    ~ScanSession() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
    }

    ScanSession(const ScanSession&)            = delete;
    ScanSession& operator=(const ScanSession&) = delete;

private:
    void runLoop() {
        bool scanEverStarted = false;
        bool postedFinished  = false;

        // Tight initial sleep so the very first snapshot lands within ~50 ms
        // of StartScan() returning, then settle to 100 ms cadence.
        std::this_thread::sleep_for(std::chrono::milliseconds(40));

        while (!stop_.load()) {
            if (!g_scanner) break;

            const bool wasRunning = (nl_scanner_is_running(g_scanner) != 0);

            // Back-pressure: don't build a fresh snapshot (≈full host copy +
            // string allocations) when a previous one is still sitting in
            // the UI queue. On AllPortsFast / large ranges the UI thread
            // can fall behind for hundreds of ms; without this each tick
            // would heap-allocate ~5000-row vectors that pile up. The
            // exception is the scan-just-ended tick — we must guarantee one
            // final "isRunning=false" snapshot lands, otherwise the pill
            // stays "Scanning…" forever.
            const bool mustForce = (scanEverStarted && !wasRunning);
            const bool canPost   = App::Instance().TryMarkSnapshotPending();
            if (!canPost && !mustForce) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            // If we forced past back-pressure, mark pending so the receiver
            // still calls ClearSnapshotPending() symmetrically.
            if (mustForce && !canPost) {
                // Already marked pending by an earlier tick — the UI will
                // clear it. Either way we're going to post this final one.
            }

            EngineSnapshot* snap = build();
            if (!snap) {
                App::Instance().ClearSnapshotPending();
                break;
            }

            const bool isRunning = snap->isRunning;
            if (isRunning) scanEverStarted = true;

            if (!PostMessageW(uiHwnd_, WM_NL_APPLY_SNAPSHOT, 0,
                              reinterpret_cast<LPARAM>(snap))) {
                delete snap;
                App::Instance().ClearSnapshotPending();
                break;   // UI window gone
            }

            if (scanEverStarted && !isRunning && !postedFinished) {
                postedFinished = true;
                PostMessageW(uiHwnd_, WM_NL_SCAN_FINISHED, 0, 0);
                return;   // scanner thread done
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    EngineSnapshot* build() {
        nl_summary_t sum{};
        nl_scanner_get_summary(g_scanner, &sum);

        const bool    isRunning = (nl_scanner_is_running(g_scanner) != 0);
        const int     done      = nl_scanner_progress_done(g_scanner);
        const int     total     = nl_scanner_progress_total(g_scanner);
        const int     cnt       = nl_scanner_result_count(g_scanner);
        const int64_t probes    = nl_scanner_probes_done(g_scanner);

        auto* snap = new (std::nothrow) EngineSnapshot{};
        if (!snap) return nullptr;

        snap->isRunning     = isRunning;
        snap->progressDone  = done;
        snap->progressTotal = total;
        snap->resultCount   = cnt;
        snap->totalScanned  = sum.total_scanned;
        snap->onlineCount   = sum.online_count;
        snap->offlineCount  = sum.offline_count;
        snap->durationMs    = sum.duration_ms;
        snap->probesDone    = probes;

        // ---- Sliding-window rate sampler ----
        // Push (t, probes, done) into the deque every tick; drop samples
        // older than kWindowMs. Rate = (last.probes - first.probes) ×
        // 1000 / (last.tMs - first.tMs) — linear regression between
        // window edges. Mirrors original NetLens v1.2.0 (probeSamples_).
        // Smoother than EMA across the online/offline phase flip because
        // it averages 5 s of actual data instead of weighting one recent
        // sample heavily.
        const int64_t now_ms = static_cast<int64_t>(GetTickCount64());
        if (isRunning) {
            samples_.push_back({ now_ms, probes, done });
            while (!samples_.empty()
                   && (now_ms - samples_.front().tMs) > kWindowMs) {
                samples_.pop_front();
            }
        } else {
            samples_.clear();
        }

        double hostsPerSec  = 0.0;
        double probesPerSec = 0.0;
        if (samples_.size() >= 2) {
            const auto& first = samples_.front();
            const auto& last  = samples_.back();
            const int64_t dt = last.tMs - first.tMs;
            if (dt > 0) {
                hostsPerSec  = static_cast<double>(last.done   - first.done)
                             * 1000.0 / static_cast<double>(dt);
                probesPerSec = static_cast<double>(last.probes - first.probes)
                             * 1000.0 / static_cast<double>(dt);
            }
        }
        snap->recentHostsPerSec  = hostsPerSec;
        snap->hasRecentRate      = samples_.size() >= 2 && hostsPerSec > 0.05;
        snap->recentProbesPerSec = probesPerSec;

        // ---- probesTotalEstimate, mode-aware floor + empirical ----
        //
        // The engine's `probesDone` counter increments exactly once per
        // PortScanner port-connect attempt; fingerprint probes, retries,
        // ICMP, ARP and DNS don't touch it. Verified on a /24 LAN with
        // settings.mode = Deep (default):
        //   Quick (61 ports):    15494 final probes = 254 × 61 exactly
        //   Standard (132):      33528             = 254 × 132
        //   FullCommon (231):    58674             = 254 × 231
        // So per-host probe count depends only on ScanMode + isOnline:
        //   ScanMode::Deep:      both online and offline → portsPerHost
        //   ScanMode::Fast:      online → portsPerHost; offline → 26
        //                        (engine/AppConstants.h kFastDiscoveryPorts)
        //   ScanMode::Discovery: online → portsPerHost; offline → 0
        //
        // The class model is now the GROUND TRUTH ceiling: it predicts
        // what the engine will actually emit. The empirical (`probes/done
        // × total`) is only useful as a smoother for mid-scan; it tracks
        // the class model once enough hosts have completed.
        //
        // For AllPortsFast on a sparse LAN (14 online + 240 offline,
        // 65535 ports each), classModel = 14×65535 + 240×26 = 923 730.
        // Previously the model under-counted to 90 896 (because
        // portsPerHost defaulted to 32 and the bogus 3000-fingerprint
        // and 2× retry constants didn't compensate) and was then
        // overridden by an empirical taken when only offline hosts had
        // completed (probes/done × total ≈ 46 000). That gave the
        // "estimated 46 727 / 90% / 3.9 s ETA" display the user called
        // disastrous: the moment online port sweeps started piling up
        // probes, the % would crash and the ETA would balloon.
        // Using max(classModel, empirical) anchors the % to the truth.
        if (isRunning) {
            // ---- Online / offline extrapolation ----
            int onlineEst = sum.online_count;
            if (done > 0 && sum.offline_count > 0 && done < total) {
                // We've seen at least one offline host so the ratio is
                // representative; extrapolate to the whole range.
                int extrapolated = static_cast<int>(
                    static_cast<double>(sum.online_count)
                    / static_cast<double>(done) * static_cast<double>(total) + 0.5);
                if (extrapolated > onlineEst) onlineEst = extrapolated;
            }
            if (onlineEst > total) onlineEst = total;
            const int offlineEst = total - onlineEst;

            // ---- Mode-aware per-host costs (matches engine semantics) ----
            constexpr int kFastDiscoveryPortCount = 26;
            const int64_t perOnline  = portsPerHostEstimate_;
            int64_t       perOffline = 0;
            switch (scanMode_) {
                case static_cast<int>(ScanMode::DiscoveryOnly):
                    perOffline = 0;
                    break;
                case static_cast<int>(ScanMode::Fast):
                    perOffline = kFastDiscoveryPortCount;
                    break;
                case static_cast<int>(ScanMode::Deep):
                default:
                    perOffline = portsPerHostEstimate_;
                    break;
            }
            int64_t classModel =
                  static_cast<int64_t>(onlineEst)  * perOnline
                + static_cast<int64_t>(offlineEst) * perOffline;

            // ---- Empirical (kicks in after a few completions) ----
            // Empirical is useful when classModel's onlineEst is still
            // settling: with 3+ hosts done and at least one offline, the
            // (probes/done × total) ratio is representative for the
            // current mix of online/offline.
            int64_t empirical = 0;
            if (done >= 3 && sum.offline_count >= 1) {
                empirical = static_cast<int64_t>(
                    static_cast<double>(probes)
                    / static_cast<double>(done) * static_cast<double>(total) + 0.5);
            }

            // The estimate must never fall below either signal: classModel
            // is the engine's deterministic upper bound; empirical can
            // exceed it only when the actual mix is heavier than predicted
            // (e.g. more onlines than extrapolation expected). Always also
            // ensure we never display > 100% by clamping est >= probes.
            int64_t est = std::max(classModel, empirical);

            // ---- v1.3.4: tiered phase-1 projects phase-2 cost upfront ----
            // Phase 1 runs FullCommon (231 ports) on the full range. Phase 2
            // will run the user's chosen All-Ports preset (65535 ports) on
            // the same range. We add the deterministic phase-2 model now
            // so % and ETA don't crash from 100% → 0% when phase 1 finishes
            // and phase 2 resets nl_scanner_probes_done to 0.
            if (tiered_.phase == 1 && tiered_.phase2PortsPerHost > 0) {
                const int64_t p2PerOnline = tiered_.phase2PortsPerHost;
                int64_t       p2PerOffline = 0;
                switch (tiered_.phase2ScanMode) {
                    case static_cast<int>(ScanMode::DiscoveryOnly):
                        p2PerOffline = 0;
                        break;
                    case static_cast<int>(ScanMode::Fast):
                        p2PerOffline = kFastDiscoveryPortCount;
                        break;
                    case static_cast<int>(ScanMode::Deep):
                    default:
                        p2PerOffline = tiered_.phase2PortsPerHost;
                        break;
                }
                const int64_t p2Projection =
                      static_cast<int64_t>(onlineEst)  * p2PerOnline
                    + static_cast<int64_t>(offlineEst) * p2PerOffline;
                est += p2Projection;
            }

            if (est < probes) est = probes;   // never display > 100%
            if (est < 1)      est = 1;
            snap->probesTotalEstimate = est;
        } else {
            // Scan done — pin denominator to actual probes so % lands on 100%.
            snap->probesTotalEstimate = std::max<int64_t>(probes, 1);
        }

        // ---- v1.3.4: tiered phase-2 shifts probesDone + estimate baseline ----
        // Phase 2 ran nl_scanner_clear_results(), so the engine's probesDone
        // counter just restarted at 0. To keep the UI's running counter
        // continuous across the phase flip, add the (frozen) phase-1 final
        // probe count to BOTH the numerator and denominator. The % therefore
        // resumes from "phase 1 fraction of total" instead of jumping to 0%.
        if (tiered_.phase == 2 && tiered_.phase1FinalProbes > 0) {
            snap->probesDone          += tiered_.phase1FinalProbes;
            snap->probesTotalEstimate += tiered_.phase1FinalProbes;
        }
        // Duration is per-engine-session, so phase 2's fresh session restarts it
        // at 0. Add phase 1's elapsed time so the DURATION card keeps counting
        // up across the flip instead of resetting.
        if (tiered_.phase == 2 && tiered_.phase1FinalDurationMs > 0) {
            snap->durationMs += tiered_.phase1FinalDurationMs;
        }

        // ---- statusText (pill + status bar) ----
        if (isRunning) {
            wchar_t buf[64];
            int pct = 0;
            if (snap->probesTotalEstimate > 0 && snap->probesDone > 0) {
                pct = static_cast<int>(snap->probesDone * 100 / snap->probesTotalEstimate);
            } else if (total > 0) {
                pct = static_cast<int>((double)done / (double)total * 100.0);
            }
            if (pct > 100) pct = 100;
            wsprintfW(buf, L"Scanning \xb7 %d%%", pct);
            snap->statusText = buf;
        } else if (cnt > 0) {
            snap->statusText = L"Done";
        } else {
            snap->statusText = L"Ready";
        }

        // ---- Host pull ----
        snap->hosts.reserve(static_cast<size_t>(cnt));
        nl_result_t r{};
        for (int i = 0; i < cnt; ++i) {
            if (nl_scanner_get_result(g_scanner, i, &r) != 0) continue;
            HostRow h;
            h.engineIndex    = i;
            h.ipV4           = ParseIpV4(r.ip);
            h.ip             = Utf8ToWide(r.ip);
            h.hostname       = Utf8ToWide(r.hostname);
            h.vendor         = Utf8ToWide(r.vendor);
            h.mac            = Utf8ToWide(r.mac);
            h.deviceType     = Utf8ToWide(r.device_type);
            h.deviceModel    = Utf8ToWide(r.device_model);
            h.openPorts      = Utf8ToWide(r.open_ports);
            h.services       = Utf8ToWide(r.services);
            // Parse the smallest port number out of the openPorts CSV
            // (engine emits them ascending, so the first one is the
            // smallest). Used as the sort key for the "Open TCP ports"
            // grid column — see App::RebuildFilter case OpenPortCount.
            {
                int firstP = 0;
                for (wchar_t c : h.openPorts) {
                    if (c >= L'0' && c <= L'9') {
                        firstP = firstP * 10 + (c - L'0');
                        if (firstP > 65535) { firstP = 0; break; }
                    } else if (firstP != 0) {
                        break;   // hit the comma/space after the first int
                    }
                }
                h.firstOpenPort = firstP;
            }
            // Parse the engine's TAB/newline-serialized security findings
            // (v1.3.2). Engine emits one finding per line in the form:
            //     severity\tid\ttitle\turl
            // The engine pre-orders by severity (critical first); we
            // preserve that ordering when pushing into HostRow.findings.
            {
                std::wstring sf = Utf8ToWide(r.security_findings);
                size_t start = 0;
                while (start < sf.size()) {
                    size_t end = sf.find(L'\n', start);
                    if (end == std::wstring::npos) end = sf.size();
                    std::wstring line = sf.substr(start, end - start);
                    start = end + 1;
                    if (line.empty()) continue;
                    // Split on tabs: severity \t id \t title \t url
                    size_t t1 = line.find(L'\t');
                    if (t1 == std::wstring::npos) continue;
                    size_t t2 = line.find(L'\t', t1 + 1);
                    if (t2 == std::wstring::npos) continue;
                    size_t t3 = line.find(L'\t', t2 + 1);
                    SecurityFinding sfRow;
                    std::wstring sev = line.substr(0, t1);
                    if      (sev == L"critical") sfRow.severity = FindingSeverity::Critical;
                    else if (sev == L"high")     sfRow.severity = FindingSeverity::High;
                    else if (sev == L"medium")   sfRow.severity = FindingSeverity::Medium;
                    else                          sfRow.severity = FindingSeverity::Low;
                    sfRow.id    = line.substr(t1 + 1, t2 - t1 - 1);
                    if (t3 == std::wstring::npos) {
                        sfRow.title = line.substr(t2 + 1);
                    } else {
                        sfRow.title = line.substr(t2 + 1, t3 - t2 - 1);
                        sfRow.url   = line.substr(t3 + 1);
                    }
                    h.findings.push_back(std::move(sfRow));
                }
            }
            h.brandHint      = Utf8ToWide(r.brand_hint);
            h.osHint         = Utf8ToWide(r.os_hint);
            h.deviceHint     = Utf8ToWide(r.device_hint);
            h.webUiModel     = Utf8ToWide(r.web_ui_model);
            h.udpDiscovery   = Utf8ToWide(r.udp_discovery);
            h.isPrinter         = (r.is_printer != 0);
            h.printerVendor     = Utf8ToWide(r.printer_vendor);
            h.printerModel      = Utf8ToWide(r.printer_model);
            h.printerSerial     = Utf8ToWide(r.printer_serial);
            h.printerSnmpStatus = Utf8ToWide(r.printer_snmp_status);
            h.printerSupplies   = Utf8ToWide(r.printer_supplies);
            h.printerPages      = Utf8ToWide(r.printer_pages);
            h.smbShares         = Utf8ToWide(r.smb_shares);
            h.iotFingerprint    = Utf8ToWide(r.iot_fingerprint);
            h.isOnline       = (r.is_online != 0);
            h.risk           = static_cast<RiskLevel>(r.risk_level);
            h.responseMs     = r.response_ms;
            h.discovery      = static_cast<DiscoveryMethod>(r.discovery);
            h.portCount      = r.port_count;
            h.serviceCount   = r.service_count;
            h.clockResponded = (r.clock_responded != 0);
            h.clockOffsetMs  = r.clock_offset_ms;
            ParseBadges(h);
            snap->hosts.push_back(std::move(h));
        }

        return snap;
    }

    HWND                  uiHwnd_;
    int                   portsPerHostEstimate_;
    int                   scanMode_;            // ScanMode as int (Discovery/Fast/Deep)
    TieredEstimatorInputs tiered_;
    std::thread           thread_;
    std::atomic<bool>     stop_{false};

    // Sliding-window rate sampler. 5-second window, linear regression
    // between first and last samples → smooth probes/sec that
    // doesn't whipsaw like the EMA did when the rate flips between online
    // and offline phases.
    struct Sample { int64_t tMs; int64_t probes; int done; };
    std::deque<Sample> samples_;
    static constexpr int64_t kWindowMs = 5000;
};

// ===========================================================================
// App
// ===========================================================================

App& App::Instance() {
    static App s;
    return s;
}

bool App::Init(HINSTANCE hInst) {
    inst_ = hInst;
    if (nl_init() == 0) {
        g_inited = true;
        g_scanner = nl_scanner_create();
        engineOk_ = (g_scanner != nullptr);
    } else {
        g_inited = false;
        engineOk_ = false;
    }

    stats_.statusText = engineOk_ ? L"Ready" : L"Engine init failed";
    stats_.isScanning = false;
    RebuildFilter();
    return engineOk_;
}

void App::Shutdown() {
    // Stop the snapshot-polling worker BEFORE destroying the engine.
    // ScanSession::runLoop reads g_scanner every ~100 ms; without this
    // ordered teardown a poll racing the destroy could call
    // nl_scanner_get_summary(...) on freed memory. ScanSession's dtor
    // sets stop_=true and joins synchronously, so once reset() returns
    // no background poll can hit the scanner.
    scanSession_.reset();
    if (g_scanner) {
        nl_scanner_destroy(g_scanner);
        g_scanner = nullptr;
    }
    if (g_inited) {
        nl_shutdown();
        g_inited = false;
    }
    engineOk_ = false;
}

void App::SetFilter(HostFilter f)         { filter_ = f;         RebuildFilter(); }
void App::SetSearch(std::wstring s)       { search_ = std::move(s); RebuildFilter(); }
void App::SetViewOffline(bool v)          { viewOffline_ = v;    RebuildFilter(); }
void App::SetMinSeverity(SeverityFilter s){ minSeverity_ = s;    RebuildFilter(); }

bool App::IsScanning() const {
    return g_scanner ? (nl_scanner_is_running(g_scanner) != 0) : false;
}

// Quick estimator for "how many IPs does this range cover?" — used
// only to decide whether to auto-disable DNS reverse lookups for big
// scans (synchronous getnameinfo per host with no native timeout). A
// loose estimate is fine; the engine itself does the precise parse.
static int EstimateRangeHostCount(const std::wstring& range) {
    auto slash = range.find(L'/');
    if (slash != std::wstring::npos) {
        int bits = _wtoi(range.c_str() + slash + 1);
        if (bits > 0 && bits <= 32) {
            int64_t total = (int64_t)1 << (32 - bits);
            return total > 1 ? static_cast<int>(total - 2) : static_cast<int>(total);
        }
        return 0;
    }
    auto dash = range.find(L'-');
    if (dash != std::wstring::npos) {
        // "a.b.c.d-e" or "a.b.c.d-a.b.c.e" — for either form, derive the
        // last octets of the two endpoints and subtract.
        std::wstring lo = range.substr(0, dash);
        std::wstring hi = range.substr(dash + 1);
        auto lastDotLo = lo.find_last_of(L'.');
        int loN = _wtoi(lastDotLo == std::wstring::npos
                        ? lo.c_str() : lo.c_str() + lastDotLo + 1);
        auto lastDotHi = hi.find_last_of(L'.');
        int hiN = _wtoi(lastDotHi == std::wstring::npos
                        ? hi.c_str() : hi.c_str() + lastDotHi + 1);
        if (hiN >= loN) return hiN - loN + 1;
        return 1;
    }
    return 1;
}

int App::startScanInternal(const std::wstring& range, ScanPreset effPreset, HWND uiHwnd) {
    if (!g_scanner) return -1;

    // Always drop any prior session before starting a new one. The dtor
    // joins the thread so there's no stale snapshot racing the fresh state.
    scanSession_.reset();

    std::string  rangeU8     = WideToUtf8(range);
    std::wstring portsCsvW   = PresetToPortsCsv(effPreset, customPortsCsv_);
    // Tiered phase 2 skips the FullCommon ports phase 1 already deep-checked:
    // the sweep is the long tail only, so it's purely additive (no re-scan of
    // discovery's ports). Phase-1 results are merged back in ApplySnapshot.
    if (tieredPhase_ == 2
        && (preset_ == ScanPreset::AllPortsFast || preset_ == ScanPreset::AllPortsDeep)) {
        portsCsvW = AllPortsExceptFullCommonCsv();
    }
    std::string  portsCsvU8  = WideToUtf8(portsCsvW);

    // Auto-disable DNS reverse lookups for big scans. getnameinfo has
    // no native timeout — on misconfigured DNS each offline host burns
    // ~5s waiting. Threshold = 1024 hosts; user can re-enable manually
    // from Settings.
    bool autoDisabledDns = false;
    if (!settings_.skipDns) {
        int estHosts = EstimateRangeHostCount(range);
        if (estHosts > 1024) {
            autoDisabledDns = true;
        }
    }

    nl_scan_opts_t opts{};
    opts.timeout_ms             = settings_.timeoutMs;
    opts.parallel               = settings_.parallel;
    opts.mode                   = (effPreset == ScanPreset::AllPortsFast)
                                      ? static_cast<int>(ScanMode::Fast)
                                      : static_cast<int>(settings_.mode);
    opts.skip_dns               = (settings_.skipDns || autoDisabledDns) ? 1 : 0;
    opts.skip_mac               = settings_.skipMac          ? 1 : 0;
    opts.skip_ports             = settings_.skipPorts        ? 1 : 0;
    opts.skip_fingerprint       = settings_.skipFingerprint  ? 1 : 0;
    opts.skip_clock_drift       = settings_.skipClockDrift   ? 1 : 0;
    // UDP discovery only runs on FullCommon and richer presets. Quick
    // / Standard exist for "show me the LAN in a few seconds" and a
    // ~600 ms-per-host UDP budget would dominate that. The user can
    // still force-disable via Settings (settings_.skipUdpDiscovery).
    const bool udpByPreset = (effPreset == ScanPreset::FullCommon)
                          || (effPreset == ScanPreset::AllPortsFast)
                          || (effPreset == ScanPreset::AllPortsDeep)
                          || (effPreset == ScanPreset::CustomPorts);
    opts.skip_udp_discovery     = (settings_.skipUdpDiscovery || !udpByPreset) ? 1 : 0;
    // Printer SNMP is always allowed when not opted out. The probe
    // itself gates on printer signals (port 9100 / 515 / 631 or vendor
    // match), so on a /24 with one printer it costs at most ~3 ×
    // timeoutMs for that single host.
    opts.skip_printer_snmp      = settings_.skipPrinterSnmp ? 1 : 0;
    // Walking the prtMarkerSupplies table costs an extra ~timeoutMs per
    // GETNEXT hop. Skip it for Quick scans (vendor + model still come
    // from sysDescr in the cheaper system-group GET).
    opts.want_printer_supplies  = (effPreset == ScanPreset::Quick) ? 0 : 1;
    opts.fingerprint_timeout_ms = settings_.fingerprintTimeoutMs;
    opts.ports_csv              = portsCsvU8.empty() ? nullptr : portsCsvU8.c_str();

    // v1.3.6 — Pass the local default gateway IP so the engine can hoist
    // the WHOLE /24 containing that gateway to the front of the work queue
    // (see prioritizeGatewayCandidates in ffi.cpp). On a /22+ scan this
    // makes the user's actual LAN finish in seconds, before any unrelated
    // sibling /24 gets touched.
    std::string gwU8;   // must outlive nl_scanner_start
    for (int i = 0, n = nl_adapters_count(); i < n; ++i) {
        nl_adapter_t a{};
        if (nl_adapters_get(i, &a) != 0) continue;
        if (!a.operational || a.type == 3) continue;   // skip loopback / down
        if (a.gateway[0] == 0) continue;
        gwU8 = a.gateway;
        break;
    }
    opts.gateway_ip = gwU8.empty() ? nullptr : gwU8.c_str();

    int rc = nl_scanner_start(g_scanner, rangeU8.c_str(), &opts);

    if (rc == 0) {
        stats_.isScanning = true;
        stats_.statusText = L"Scanning\x2026";

        // Pass the REAL per-host port count + the engine's effective
        // ScanMode to the session. PortsForPreset() returns an empty
        // vector for AllPortsFast/AllPortsDeep/CustomPorts (those
        // expand at runtime via opts.ports_csv), so we substitute the
        // actual sweep size: 65535 for AllPorts; the CSV count for
        // Custom. The mode tells the estimator how to weight offline
        // hosts (skip / 26-port discovery / full sweep) — see the
        // ScanSession ctor comment.
        int portsPerHost = static_cast<int>(PortsForPreset(effPreset).size());
        if (effPreset == ScanPreset::AllPortsFast
            || effPreset == ScanPreset::AllPortsDeep) {
            portsPerHost = 65535;
        } else if (effPreset == ScanPreset::CustomPorts) {
            // Approximate CSV count: number of comma-separated tokens.
            // Good enough for the estimator floor; exact count would
            // require running the same range expander the engine uses.
            int n = portsCsvW.empty() ? 0 : 1;
            for (wchar_t c : portsCsvW) if (c == L',') ++n;
            if (n > 0) portsPerHost = n;
        }

        // v1.3.4 — Tiered scan estimator inputs.
        // Phase 1: project the upcoming phase-2 cost so the ETA combines
        //          both phases from the very first snapshot.
        // Phase 2: pass the captured phase-1 final probe count so the
        //          counter resumes (rather than restarts from 0%).
        TieredEstimatorInputs tiered;
        tiered.phase = tieredPhase_;
        if (tieredPhase_ == 1) {
            const bool p2AllPorts =
                   (tieredOriginalPreset_ == ScanPreset::AllPortsFast)
                || (tieredOriginalPreset_ == ScanPreset::AllPortsDeep);
            tiered.phase2PortsPerHost = p2AllPorts
                ? 65535
                : static_cast<int>(PortsForPreset(tieredOriginalPreset_).size());
            // Phase 2's per-offline cost depends on its ScanMode — AllPortsFast
            // forces Fast (26-port discovery on offline); AllPortsDeep uses the
            // user's chosen mode (Discovery / Fast / Deep). Mirror the same
            // selection startScanInternal does for phase 2's actual run.
            tiered.phase2ScanMode = (tieredOriginalPreset_ == ScanPreset::AllPortsFast)
                ? static_cast<int>(ScanMode::Fast)
                : static_cast<int>(settings_.mode);
        } else if (tieredPhase_ == 2) {
            tiered.phase1FinalProbes     = tieredPhase1Probes_;
            tiered.phase1FinalDurationMs = tieredPhase1DurationMs_;
        }
        scanSession_ = std::make_unique<ScanSession>(uiHwnd, portsPerHost,
                                                     opts.mode, tiered);
    }
    return rc;
}

int App::StartScan(const std::wstring& range, HWND uiHwnd) {
    if (!g_scanner && !mockMode_) return -1;

    // v1.3.4 — tiered scan re-enabled with a stable cross-phase ETA.
    //
    // For AllPortsFast / AllPortsDeep, split the scan into two passes:
    //   phase 1 = FullCommon (231 ports) on the full range — fast, gives
    //             the user useful results within seconds
    //   phase 2 = the user's chosen All-Ports preset on the full range —
    //             slow, but already populated with phase-1 services
    // The estimator projects phase-2 cost upfront so % and ETA stay
    // continuous across the engine restart (previously this jumped 100% → 0%
    // which is the reason this was disabled in 1.3.0–1.3.3).
    //
    // Non-tiered presets (Quick, Standard, FullCommon, CustomPorts) skip
    // the split entirely — there's no "phase 2" to project.
    if (!mockMode_
        && (preset_ == ScanPreset::AllPortsFast
         || preset_ == ScanPreset::AllPortsDeep)) {
        tieredPhase_          = 1;
        tieredOriginalPreset_ = preset_;
        tieredRange_          = range;
        tieredPhase1Probes_   = 0;
        tieredPhase1DurationMs_ = 0;
    } else {
        tieredPhase_          = 0;
    }
    tieredPhase1Hosts_.clear();

    // Fresh baseline — UI thread is the only writer to these fields.
    hosts_.clear();
    filteredIndex_.clear();
    stats_ = ScanStats{};
    selectedIndex_ = -1;
    selectedIp_.clear();
    userCancelled_ = false;   // drop any stale cancel flag

    // --mock — populate from MockData and post the same snapshot
    // messages the scanner thread would have posted. No engine call.
    // Selects the first host (MikroTik router) so the right-pane
    // is populated for the screenshot.
    if (mockMode_) {
        auto* snap = new (std::nothrow) EngineSnapshot{};
        if (!snap) return -1;
        snap->hosts                = mock::BuildHosts();
        ScanStats ms               = mock::BuildStats();
        snap->isRunning            = ms.isScanning;
        snap->progressDone         = ms.progressDone;
        snap->progressTotal        = ms.progressTotal;
        snap->resultCount          = static_cast<int>(snap->hosts.size());
        snap->totalScanned         = ms.totalScanned;
        snap->onlineCount          = ms.onlineCount;
        snap->offlineCount         = ms.offlineCount;
        snap->durationMs           = ms.durationMs;
        snap->probesDone           = ms.probesDone;
        snap->probesTotalEstimate  = ms.probesTotalEstimate;
        snap->recentHostsPerSec    = ms.recentHostsPerSec;
        snap->recentProbesPerSec   = ms.recentProbesPerSec;
        snap->hasRecentRate        = ms.hasRecentRate;
        snap->statusText           = ms.statusText;

        // Capture everything we need from `snap` BEFORE handing ownership to
        // the UI thread. After PostMessageW, the UI thread may consume the
        // snapshot (hosts std::move'd into App::hosts_) and delete it, so the
        // pointer must not be touched again here — not even for .empty().
        bool         hasMock = !snap->hosts.empty();
        std::wstring firstIp = hasMock ? snap->hosts.front().ip : std::wstring();

        if (!PostMessageW(uiHwnd, WM_NL_APPLY_SNAPSHOT, 0,
                          reinterpret_cast<LPARAM>(snap))) {
            delete snap;
            return -1;
        }
        // Pre-select the first row so DetailsPanel paints. SyncUiFromEngine
        // notices selectedIp_ and tells HostTable to focus that row.
        if (hasMock) {
            selectedIp_    = firstIp;
            selectedIndex_ = 0;
        }
        PostMessageW(uiHwnd, WM_NL_SCAN_FINISHED, 0, 0);
        return 0;
    }

    // Phase 1 of a tiered scan runs FullCommon; phase 2 (kicked from
    // OnScanFinished) runs the user's chosen All-Ports preset.
    const ScanPreset effPreset = (tieredPhase_ == 1)
                                   ? ScanPreset::FullCommon
                                   : preset_;
    return startScanInternal(range, effPreset, uiHwnd);
}

void App::CancelScan() {
    if (g_scanner) nl_scanner_cancel(g_scanner);
    // Flag the intent BEFORE the worker observes !IsScanning; if a
    // WM_NL_SCAN_FINISHED is already in the UI queue, OnScanFinished
    // will see this and skip the tiered phase-2 kick.
    userCancelled_ = true;
    tieredPhase_ = 0;
    tieredPhase1Hosts_.clear();
    tieredPhase1Probes_ = 0;
    // Do NOT join the scanner thread here. We need it to keep polling
    // the engine and post one more snapshot once the workers finish
    // unwinding (which can take 5–10 s for AllPortsFast because each
    // worker is mid-batch in connect()/select()). That trailing
    // snapshot carries isRunning=false, which is what flips the pill
    // from "Cancelling…" to "Cancelled · X%" and re-enables Start.
    // The thread exits on its own in the same iteration via the
    // `scanEverStarted && !isRunning` branch, posting WM_NL_SCAN_FINISHED
    // → OnScanFinished → scanSession_.reset() to join cleanly.
}

void App::ClearScan() {
    scanSession_.reset();
    if (g_scanner) nl_scanner_clear_results(g_scanner);
    hosts_.clear();
    filteredIndex_.clear();
    portsCache_.clear();
    portsCacheHostIdx_ = -1;
    stats_ = ScanStats{};
    stats_.statusText = L"Ready";
    selectedIndex_ = -1;
    selectedIp_.clear();
    tieredPhase_ = 0;
    tieredPhase1Hosts_.clear();
    tieredPhase1Probes_ = 0;
    userCancelled_ = false;
}

int App::ExportCsv(const std::wstring& path) {
    if (!g_scanner) return -1;
    return nl_scanner_export_csv(g_scanner, WideToUtf8(path).c_str());
}

int App::ExportHtml(const std::wstring& path) {
    if (mockMode_) {
        // --mock — dump the embedded report straight to disk. Bypasses
        // the engine entirely, so this works even before any scan.
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return -1;
        const char* bytes = mock::ExportHtmlBytes();
        DWORD       size  = static_cast<DWORD>(mock::ExportHtmlSize());
        DWORD       wrote = 0;
        BOOL ok = WriteFile(h, bytes, size, &wrote, nullptr);
        CloseHandle(h);
        return (ok && wrote == size) ? 0 : -1;
    }
    if (!g_scanner) return -1;
    return nl_scanner_export_html(g_scanner, WideToUtf8(path).c_str());
}

// Apply a snapshot built by the scanner thread. The snapshot already
// contains a fully-pulled host list + rate-tracked stats; this method's
// job is just to merge phase-1 tiered cache (if any), invalidate the
// port cache, and re-sort/filter. Called only from the UI thread
// (WM_NL_APPLY_SNAPSHOT).
bool App::ApplySnapshot(EngineSnapshot&& snap) {
    const size_t prevCount = hosts_.size();

    // Save the previously-selected host's engineIndex BEFORE we move the
    // new vector in. If the same engineIndex still resolves to the same
    // host post-merge, we leave the port-detail cache intact — otherwise
    // we'd thrash the engine with nl_scanner_get_port() calls on every
    // 100 ms snapshot just to rebuild a cache that hasn't changed.
    int prevSelectedEngineIdx = -1;
    if (selectedIndex_ >= 0
        && selectedIndex_ < static_cast<int>(hosts_.size())) {
        prevSelectedEngineIdx = hosts_[selectedIndex_].engineIndex;
    }

    // Move the bulk fields in.
    hosts_                    = std::move(snap.hosts);
    stats_.totalScanned       = snap.totalScanned;
    stats_.onlineCount        = snap.onlineCount;
    stats_.offlineCount       = snap.offlineCount;
    stats_.durationMs         = snap.durationMs;
    stats_.progressDone       = snap.progressDone;
    stats_.progressTotal      = snap.progressTotal;
    stats_.probesDone         = snap.probesDone;
    stats_.isScanning         = snap.isRunning;
    stats_.probesTotalEstimate = snap.probesTotalEstimate;
    stats_.progress01         = (snap.progressTotal > 0)
                              ? (float)snap.progressDone / (float)snap.progressTotal
                              : 0.0f;
    stats_.recentHostsPerSec  = snap.recentHostsPerSec;
    stats_.recentProbesPerSec = snap.recentProbesPerSec;
    stats_.hasRecentRate      = snap.hasRecentRate;
    stats_.statusText         = std::move(snap.statusText);

    // Per-host port cache: keep it if the selected host's engineIndex is
    // unchanged across the snapshot — the user's right pane keeps
    // displaying the same port detail and we don't need to re-walk
    // nl_scanner_get_port() (which costs N engine calls per host).
    // Conservatively bust whenever the host list shrank or the count is
    // tiny (fresh-scan transition) where indices commonly reshuffle.
    bool keepPortsCache = false;
    if (portsCacheHostIdx_ >= 0
        && portsCacheHostIdx_ < static_cast<int>(hosts_.size())
        && hosts_[portsCacheHostIdx_].engineIndex == prevSelectedEngineIdx
        && prevSelectedEngineIdx >= 0
        && hosts_.size() >= prevCount) {
        keepPortsCache = true;
    }
    if (!keepPortsCache) {
        portsCache_.clear();
        portsCacheHostIdx_ = -1;
    }

    // Tiered scan phase 2: merge phase-1 cache into the grid.
    // Phase 2 rediscovers hosts via ICMP/ARP within ~1 s but the TCP port
    // sweep takes much longer (~minutes for 65k ports). During that gap
    // the engine reports the host as online with EMPTY open_ports /
    // services / device hints — losing the rich phase-1 data. Two-step:
    //   1. For each phase-2 host that has a phase-1 entry, fill empty
    //      fields from phase 1.
    //   2. Append phase-1 hosts that phase 2 hasn't discovered yet.
    if (tieredPhase_ == 2 && !tieredPhase1Hosts_.empty()) {
        std::unordered_map<std::wstring, const HostRow*> p1Map;
        p1Map.reserve(tieredPhase1Hosts_.size() * 2);
        for (const auto& h1 : tieredPhase1Hosts_) p1Map[h1.ip] = &h1;

        // Union of two "a, b, c" port CSVs, numerically sorted + de-duped. Phase
        // 2 only ever ADDS ports, so unioning with phase 1 means the grid never
        // shows fewer ports than the initial discovery already found.
        auto unionPortsCsv = [](const std::wstring& a, const std::wstring& b) -> std::wstring {
            std::vector<int> v;
            auto add = [&v](const std::wstring& csv) {
                size_t i = 0;
                while (i < csv.size()) {
                    while (i < csv.size() && (csv[i] < L'0' || csv[i] > L'9')) ++i;
                    size_t j = i;
                    while (j < csv.size() && csv[j] >= L'0' && csv[j] <= L'9') ++j;
                    if (j > i && j - i <= 6) v.push_back(std::stoi(csv.substr(i, j - i)));
                    i = (j > i) ? j : i + 1;
                }
            };
            add(a); add(b);
            std::sort(v.begin(), v.end());
            v.erase(std::unique(v.begin(), v.end()), v.end());
            std::wstring out;
            for (int p : v) { if (!out.empty()) out += L", "; out += std::to_wstring(p); }
            return out;
        };
        auto tokenCount = [](const std::wstring& csv) -> int {
            if (csv.empty()) return 0;
            return 1 + static_cast<int>(std::count(csv.begin(), csv.end(), L','));
        };

        for (auto& h : hosts_) {
            auto it = p1Map.find(h.ip);
            if (it == p1Map.end()) continue;
            const HostRow& h1 = *it->second;
            // Open ports: superset, so phase 2's incremental re-sweep never makes
            // the host's port list shrink below what phase 1 reported.
            if (!h1.openPorts.empty()) {
                std::wstring u = unionPortsCsv(h.openPorts, h1.openPorts);
                if (!u.empty()) {
                    h.openPorts = u;
                    int cnt = tokenCount(u);
                    if (cnt > h.portCount) h.portCount = cnt;
                }
            }
            // Service summary: keep whichever lists more — phase 1's fingerprints
            // are richer until phase 2 re-scans the same ports.
            if (tokenCount(h1.services) > tokenCount(h.services)) h.services = h1.services;
            if (h1.serviceCount > h.serviceCount) h.serviceCount = h1.serviceCount;
            // Enrichment phase 2 only re-derives after scanning the relevant port:
            // keep phase 1's value until phase 2 produces a (non-empty) one.
            if (h.hostname.empty()    && !h1.hostname.empty())    h.hostname    = h1.hostname;
            if (h.deviceType.empty()  && !h1.deviceType.empty())  h.deviceType  = h1.deviceType;
            if (h.deviceModel.empty() && !h1.deviceModel.empty()) h.deviceModel = h1.deviceModel;
            if (h.osHint.empty()      && !h1.osHint.empty())      h.osHint      = h1.osHint;
            if (h.brandHint.empty()   && !h1.brandHint.empty())   h.brandHint   = h1.brandHint;
            if (h.deviceHint.empty()  && !h1.deviceHint.empty())  h.deviceHint  = h1.deviceHint;
            if (h.webUiModel.empty()  && !h1.webUiModel.empty())  h.webUiModel  = h1.webUiModel;
            if (h.udpDiscovery.empty()&& !h1.udpDiscovery.empty()) h.udpDiscovery = h1.udpDiscovery;
            if (h.smbShares.empty()   && !h1.smbShares.empty())   h.smbShares   = h1.smbShares;
            if (h.badges.empty()      && !h1.badges.empty())      h.badges      = h1.badges;
            // Printer SNMP / IoT / findings / risk / clock: phase 2 re-derives
            // these only after it re-scans the relevant port (Printer-MIB walk,
            // fingerprint, clock probe). Keep phase 1's data until phase 2
            // produces its own, and never let the richer phase-1 result regress
            // (this is why printer consumables vanished when phase 2 started).
            if (!h.isPrinter                && h1.isPrinter)                    h.isPrinter         = true;
            if (h.printerVendor.empty()     && !h1.printerVendor.empty())      h.printerVendor     = h1.printerVendor;
            if (h.printerModel.empty()      && !h1.printerModel.empty())       h.printerModel      = h1.printerModel;
            if (h.printerSerial.empty()     && !h1.printerSerial.empty())      h.printerSerial     = h1.printerSerial;
            if (h.printerSnmpStatus.empty() && !h1.printerSnmpStatus.empty())  h.printerSnmpStatus = h1.printerSnmpStatus;
            if (h.printerSupplies.empty()   && !h1.printerSupplies.empty())    h.printerSupplies   = h1.printerSupplies;
            if (h.printerPages.empty()      && !h1.printerPages.empty())       h.printerPages      = h1.printerPages;
            if (h.iotFingerprint.empty()    && !h1.iotFingerprint.empty())     h.iotFingerprint    = h1.iotFingerprint;
            if (h1.findings.size() > h.findings.size())                        h.findings          = h1.findings;
            if (h1.risk > h.risk)                                              h.risk              = h1.risk;
            if (!h.clockResponded && h1.clockResponded) { h.clockResponded = true; h.clockOffsetMs = h1.clockOffsetMs; }
            p1Map.erase(it);
        }
        for (const auto& kv : p1Map) {
            HostRow copy = *kv.second;
            copy.engineIndex = -1;
            hosts_.push_back(std::move(copy));
        }
    }

    RebuildFilter();

    // Selection lifecycle.
    //
    // The engine emits hosts in scan order during the live phase but
    // replaces the whole vector with a canonically-sorted finalResults
    // when the scan ends. That re-shuffles every host's index in
    // hosts_, so a raw selectedIndex_ would suddenly point at the wrong
    // host (or past the end). Re-resolve from selectedIp_ now so the
    // right pane keeps showing whatever the user was looking at.
    //
    // Also: at the very start of a scan there's no selection AND the
    // panel would render its "Select a host to see details." placeholder
    // for several seconds. As soon as the first online host arrives,
    // auto-select it so the panel has useful content immediately.
    if (!selectedIp_.empty()) {
        int idx = -1;
        for (size_t i = 0; i < hosts_.size(); ++i) {
            if (hosts_[i].ip == selectedIp_) { idx = static_cast<int>(i); break; }
        }
        selectedIndex_ = idx;
        if (idx < 0) selectedIp_.clear();   // host disappeared from the list
    }
    if (selectedIndex_ < 0 || selectedIp_.empty()) {
        for (size_t i = 0; i < hosts_.size(); ++i) {
            if (hosts_[i].isOnline) {
                selectedIndex_ = static_cast<int>(i);
                selectedIp_    = hosts_[i].ip;
                break;
            }
        }
    }

    return hosts_.size() != prevCount;
}

// Scanner thread saw isRunning go from true to false. Called from the
// UI thread (WM_NL_SCAN_FINISHED). Mid-tiered scan, kicks phase 2;
// otherwise just cleans up the (already-joined) session pointer.
void App::OnScanFinished(HWND uiHwnd) {
    // Session has posted its final snapshot + WM_NL_SCAN_FINISHED and is
    // about to exit its thread. Drop the unique_ptr to join it cleanly.
    scanSession_.reset();

    // Honor a user-initiated cancel that arrived before the dispatcher
    // delivered our queued WM_NL_SCAN_FINISHED. Without this, hitting
    // Cancel during phase 1 of a tiered scan would still kick phase 2
    // because OnScanFinished would see tieredPhase_==1.
    if (userCancelled_) {
        userCancelled_ = false;
        tieredPhase_   = 0;
        tieredPhase1Hosts_.clear();
        tieredPhase1Probes_ = 0;
        return;
    }

    if (tieredPhase_ == 1) {
        // Snapshot phase-1 hosts so the grid stays populated while phase 2
        // re-discovers, then kick the All-Ports pass.
        tieredPhase1Hosts_ = hosts_;
        // Freeze phase-1's final probe count BEFORE clear_results — this is
        // the baseline the phase-2 ScanSession will add to its own probesDone
        // so the displayed counter resumes continuously across the flip.
        tieredPhase1Probes_ = g_scanner ? nl_scanner_probes_done(g_scanner) : 0;
        tieredPhase1DurationMs_ = stats_.durationMs;   // freeze elapsed so phase 2's DURATION continues, not resets
        // Capture phase-1 per-port detail (product / version / service) BEFORE
        // clear_results() wipes the engine — otherwise the details-pane port
        // table loses the rich phase-1 data while phase 2 re-sweeps from port 1.
        if (g_scanner) {
            for (auto& h1 : tieredPhase1Hosts_) {
                if (h1.engineIndex < 0) continue;
                int n = nl_scanner_port_count(g_scanner, h1.engineIndex);
                h1.ports.clear();
                if (n > 0) h1.ports.reserve(static_cast<size_t>(n));
                for (int i = 0; i < n; ++i) {
                    nl_port_t p{};
                    if (nl_scanner_get_port(g_scanner, h1.engineIndex, i, &p) != 0) continue;
                    if (!p.is_open) continue;
                    PortRow row;
                    row.port        = p.port;
                    row.isOpen      = (p.is_open != 0);
                    row.service     = Utf8ToWide(p.service);
                    row.protocol    = Utf8ToWide(p.protocol);
                    row.product     = Utf8ToWide(p.product);
                    row.version     = Utf8ToWide(p.version);
                    row.versionNote = Utf8ToWide(p.version_note);
                    row.detail      = Utf8ToWide(p.detail);
                    row.ownerPid    = p.owner_pid;
                    row.ownerExe    = Utf8ToWide(p.owner_exe);
                    h1.ports.push_back(std::move(row));
                }
            }
        }
        tieredPhase_       = 2;
        if (g_scanner) nl_scanner_clear_results(g_scanner);
        int rc = startScanInternal(tieredRange_, tieredOriginalPreset_, uiHwnd);
        if (rc == 0) {
            // The phase-1 final snapshot set stats_.isScanning=false and
            // statusText="Done". Override to keep the pill green ("Scanning…")
            // until phase 2's first snapshot lands, otherwise the UI flickers
            // "Done" → "Scanning · X%" the moment the next snap arrives.
            stats_.isScanning = true;
            stats_.statusText = L"Scanning\x2026";   // "Scanning…"
        } else {
            tieredPhase_ = 0;
            tieredPhase1Hosts_.clear();
            tieredPhase1Probes_ = 0;
        }
    } else if (tieredPhase_ == 2) {
        tieredPhase_ = 0;
        tieredPhase1Hosts_.clear();
        tieredPhase1Probes_ = 0;
    }
}

// RefreshFromEngine — removed in M5.8 (event-driven scanner thread). All
// engine polling is now done by ScanSession; the UI receives snapshots via
// WM_NL_APPLY_SNAPSHOT and feeds them to ApplySnapshot() above.

std::wstring App::DefaultRange() {
    // --mock — RANGE field shows the same subnet the mock fleet lives on
    // so the screenshot doesn't suggest "I scanned 192.168.6.x but the
    // results say 192.168.1.x".
    if (mockMode_) return L"192.168.1.1-192.168.1.254";
    int count = nl_adapters_count();
    for (int i = 0; i < count; ++i) {
        nl_adapter_t a{};
        if (nl_adapters_get(i, &a) != 0) continue;
        if (!a.operational)      continue;
        if (a.type == 3)         continue;   // loopback
        if (a.suggested_range[0] == 0) continue;
        return Utf8ToWide(a.suggested_range);
    }
    return L"192.168.1.1-192.168.1.254";
}

std::wstring App::EngineVersion() {
    const char* v = nl_engine_version();
    return v ? Utf8ToWide(v) : L"unknown";
}

void App::RebuildFilter() {
    filteredIndex_.clear();
    filteredIndex_.reserve(hosts_.size());

    std::wstring needle = search_;
    for (auto& c : needle) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    }

    for (int i = 0; i < static_cast<int>(hosts_.size()); ++i) {
        const HostRow& h = hosts_[i];

        if (!viewOffline_ && !h.isOnline) continue;
        if (filter_ == HostFilter::OnlineOnly && !h.isOnline) continue;
        if (filter_ == HostFilter::HasOpenPorts && h.openPorts.empty()) continue;

        // v1.3.3 — severity filter (orthogonal to the HostFilter
        // above). Find the worst finding on this host and gate on it.
        // FindingSeverity enum is ordered Critical=0, High=1,
        // Medium=2, Low=3; lower value == worse, hence the `<=`
        // direction in the gate.
        if (minSeverity_ != SeverityFilter::None) {
            // Map the SeverityFilter to the FindingSeverity threshold
            // it admits. e.g. HighPlus admits Critical OR High.
            int gateRank;
            switch (minSeverity_) {
                case SeverityFilter::CriticalOnly:
                    gateRank = static_cast<int>(FindingSeverity::Critical); break;
                case SeverityFilter::HighPlus:
                    gateRank = static_cast<int>(FindingSeverity::High);     break;
                case SeverityFilter::MediumPlus:
                    gateRank = static_cast<int>(FindingSeverity::Medium);   break;
                default:
                    gateRank = static_cast<int>(FindingSeverity::Low);      break;
            }
            int worstRank = static_cast<int>(FindingSeverity::Low) + 1;  // sentinel
            for (const auto& f : h.findings) {
                int r = static_cast<int>(f.severity);
                if (r < worstRank) worstRank = r;
                if (worstRank == 0) break;   // already at Critical
            }
            if (worstRank > gateRank) continue;
        }

        if (!needle.empty()) {
            if (!ContainsIgnoreCase(h.ip,         needle) &&
                !ContainsIgnoreCase(h.hostname,   needle) &&
                !ContainsIgnoreCase(h.vendor,     needle) &&
                !ContainsIgnoreCase(h.deviceType, needle) &&
                !ContainsIgnoreCase(h.openPorts,  needle) &&
                !ContainsIgnoreCase(h.services,   needle))
                continue;
        }

        filteredIndex_.push_back(i);
    }

    // Sort according to the user's current column + direction.
    // CmpKey returns < 0 / 0 / > 0 for the active sort key (direction-agnostic).
    auto strcmp_ = [](const std::wstring& a, const std::wstring& b) -> int {
        int r = CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
                               a.c_str(), -1, b.c_str(), -1);
        // CompareStringW returns 1/2/3; map to <0/0/>0.
        return r - 2;
    };
    auto cmpKey = [&](const HostRow& A, const HostRow& B) -> int {
        switch (sortCol_) {
            case SortColumn::IpV4:
                if (A.ipV4 != B.ipV4) return (A.ipV4 < B.ipV4) ? -1 : 1; return 0;
            case SortColumn::Mac:           return strcmp_(A.mac,        B.mac);
            case SortColumn::Hostname:      return strcmp_(A.hostname,   B.hostname);
            case SortColumn::Vendor:        return strcmp_(A.vendor,     B.vendor);
            case SortColumn::Device:        return strcmp_(A.deviceType, B.deviceType);
            case SortColumn::Model:         return strcmp_(A.deviceModel, B.deviceModel);
            case SortColumn::OpenPortCount:
                // Sort by number of open ports per host. (`firstOpenPort`
                // is kept on HostRow for other uses — sort uses portCount
                // because the column actually labels "Open TCP ports" and
                // the user's mental model is "which boxes are doing the
                // most", not "which boxes have the lowest port number".)
                if (A.portCount != B.portCount) return A.portCount - B.portCount;
                return 0;
            case SortColumn::Services:
                if (A.serviceCount != B.serviceCount) return A.serviceCount - B.serviceCount;
                return 0;
            case SortColumn::Rtt: {
                // Offline always sorts last regardless of direction.
                if (A.isOnline != B.isOnline) return A.isOnline ? -1 : 1;
                if (A.responseMs != B.responseMs) return A.responseMs - B.responseMs;
                return 0;
            }
            case SortColumn::Status:
                if (A.isOnline != B.isOnline) return A.isOnline ? -1 : 1;
                return 0;
        }
        return 0;
    };
    auto cmp = [&](int a, int b) -> bool {
        int r = cmpKey(hosts_[a], hosts_[b]);
        if (r == 0) {
            // Stable tiebreak: ascending IP keeps the visual order predictable.
            if (hosts_[a].ipV4 != hosts_[b].ipV4)
                return hosts_[a].ipV4 < hosts_[b].ipV4;
            return a < b;
        }
        return sortAsc_ ? (r < 0) : (r > 0);
    };
    std::sort(filteredIndex_.begin(), filteredIndex_.end(), cmp);
}

void App::SetSort(SortColumn col, bool ascending) {
    sortCol_ = col;
    sortAsc_ = ascending;
    RebuildFilter();
}

void App::ToggleSort(SortColumn col) {
    if (sortCol_ == col) {
        sortAsc_ = !sortAsc_;
    } else {
        sortCol_ = col;
        // RTT defaults to ascending (fastest first); others ascending too.
        sortAsc_ = true;
    }
    RebuildFilter();
}

const std::vector<PortRow>& App::PortsForHost(int hostIndex) {
    if (portsCacheHostIdx_ == hostIndex && !portsCache_.empty()) {
        return portsCache_;
    }
    portsCache_.clear();
    portsCacheHostIdx_ = hostIndex;
    if (hostIndex < 0 || hostIndex >= static_cast<int>(hosts_.size())) {
        return portsCache_;
    }
    // --mock — HostRow.ports is pre-populated by MockData.cpp.
    if (mockMode_) {
        portsCache_ = hosts_[hostIndex].ports;
        return portsCache_;
    }
    if (!g_scanner) return portsCache_;
    int engineIdx = hosts_[hostIndex].engineIndex;
    if (engineIdx < 0) {
        // Phase-1-only host (appended during a tiered scan, not yet re-found by
        // phase 2). Its HostRow.ports carries the cached phase-1 port detail.
        portsCache_ = hosts_[hostIndex].ports;
        return portsCache_;
    }

    int n = nl_scanner_port_count(g_scanner, engineIdx);
    portsCache_.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        nl_port_t p{};
        if (nl_scanner_get_port(g_scanner, engineIdx, i, &p) != 0) continue;
        if (!p.is_open) continue;
        PortRow row;
        row.port        = p.port;
        row.isOpen      = (p.is_open != 0);
        row.service     = Utf8ToWide(p.service);
        row.protocol    = Utf8ToWide(p.protocol);
        row.product     = Utf8ToWide(p.product);
        row.version     = Utf8ToWide(p.version);
        row.versionNote = Utf8ToWide(p.version_note);
        row.detail      = Utf8ToWide(p.detail);
        row.ownerPid    = p.owner_pid;
        row.ownerExe    = Utf8ToWide(p.owner_exe);
        portsCache_.push_back(std::move(row));
    }
    // Tiered scan phase 2: the engine is mid-sweep, so its live port list for
    // this host is a growing subset. Union the cached phase-1 detail so the
    // table doesn't regress; phase 2's rows already present take precedence.
    if (tieredPhase_ == 2 && !tieredPhase1Hosts_.empty()) {
        const std::wstring& ip = hosts_[hostIndex].ip;
        for (const auto& h1 : tieredPhase1Hosts_) {
            if (h1.ip != ip) continue;
            for (const auto& p1 : h1.ports) {
                bool present = false;
                for (const auto& pc : portsCache_) {
                    if (pc.port == p1.port) { present = true; break; }
                }
                if (!present) portsCache_.push_back(p1);
            }
            break;
        }
        std::sort(portsCache_.begin(), portsCache_.end(),
                  [](const PortRow& a, const PortRow& b) { return a.port < b.port; });
    }
    return portsCache_;
}

std::vector<AdapterInfo> App::Adapters() {
    std::vector<AdapterInfo> out;
    int n = nl_adapters_count();
    out.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        nl_adapter_t a{};
        if (nl_adapters_get(i, &a) != 0) continue;
        AdapterInfo ai;
        ai.index           = a.index;
        ai.type            = a.type;
        ai.operational     = (a.operational != 0);
        ai.friendlyName    = Utf8ToWide(a.friendly_name);
        ai.description     = Utf8ToWide(a.description);
        ai.ip              = Utf8ToWide(a.ip);
        ai.subnet          = Utf8ToWide(a.subnet);
        ai.gateway         = Utf8ToWide(a.gateway);
        ai.suggestedRange  = Utf8ToWide(a.suggested_range);
        out.push_back(std::move(ai));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Static preset-reference accessors (used by the Port Lists dialog).
// ---------------------------------------------------------------------------

std::vector<uint16_t> App::PortsForPreset(ScanPreset p) {
    switch (p) {
        case ScanPreset::Quick:
            return { std::begin(kQuickPorts),      std::end(kQuickPorts) };
        case ScanPreset::Standard:
            return { std::begin(kStandardPorts),   std::end(kStandardPorts) };
        case ScanPreset::FullCommon:
            return { std::begin(kFullCommonPorts), std::end(kFullCommonPorts) };
        case ScanPreset::AllPortsFast:
        case ScanPreset::AllPortsDeep:
        case ScanPreset::CustomPorts:
        default:
            return {};
    }
}

const wchar_t* App::ServiceForPort(uint16_t port) {
    const auto& m = PortServiceMap();
    auto it = m.find(port);
    return (it == m.end()) ? L"\x2014" : it->second;
}

// Short canonical protocol name for badge display: "HTTP" instead of
// the fingerprinted "Apache 2.4", "SMB" instead of "NetBIOS Session
// Service", etc. Keeps the host-grid badges scannable at a glance.
const wchar_t* App::CanonicalServiceForPort(uint16_t port) {
    switch (port) {
        case 21:    return L"FTP";
        case 22:    return L"SSH";
        case 23:    return L"Telnet";
        case 25:    return L"SMTP";
        case 53:    return L"DNS";
        case 69:    return L"TFTP";
        case 80:    return L"HTTP";
        case 88:    return L"Kerberos";
        case 110:   return L"POP3";
        case 111:   return L"RPC";
        case 123:   return L"NTP";
        case 135:   return L"RPC";
        case 137:   return L"NetBIOS";
        case 138:   return L"NetBIOS";
        case 139:   return L"SMB";
        case 143:   return L"IMAP";
        case 161:   return L"SNMP";
        case 162:   return L"SNMP";
        case 179:   return L"BGP";
        case 389:   return L"LDAP";
        case 443:   return L"HTTPS";
        case 445:   return L"SMB";
        case 465:   return L"SMTPS";
        case 500:   return L"IPsec";
        case 514:   return L"syslog";
        case 515:   return L"LPD";
        case 548:   return L"AFP";
        case 554:   return L"RTSP";
        case 587:   return L"SMTP";
        case 623:   return L"IPMI";
        case 631:   return L"IPP";
        case 636:   return L"LDAPS";
        case 873:   return L"rsync";
        case 902:   return L"VMware";
        case 989:
        case 990:   return L"FTPS";
        case 993:   return L"IMAPS";
        case 995:   return L"POP3S";
        case 1080:  return L"SOCKS";
        case 1194:  return L"OpenVPN";
        case 1433:  return L"MSSQL";
        case 1434:  return L"MSSQL";
        case 1521:  return L"Oracle";
        case 1723:  return L"PPTP";
        case 1812:
        case 1813:  return L"RADIUS";
        case 1883:  return L"MQTT";
        case 1900:  return L"SSDP";
        case 2049:  return L"NFS";
        case 2082:
        case 2083:  return L"cPanel";
        case 2086:
        case 2087:  return L"WHM";
        case 2222:  return L"SSH";
        case 2375:
        case 2376:  return L"Docker";
        case 2379:
        case 2380:  return L"etcd";
        case 3000:  return L"HTTP";
        case 3128:  return L"Proxy";
        case 3260:  return L"iSCSI";
        case 3268:
        case 3269:  return L"LDAP-GC";
        case 3306:  return L"MySQL";
        case 3389:  return L"RDP";
        case 4500:  return L"IPsec";
        // Ports 5000/5001 are shared by Synology DSM, 3CX PBX, Flask
        // dev servers and various admin UIs. The badge column shows
        // the canonical service for a TCP open-port — labelling both
        // as "DSM" would be a false claim for non-Synology hosts.
        // Show "HTTP-alt" / "HTTPS-alt" instead; the actual product
        // is reported via webUiModel / fingerprint when known.
        case 5000:  return L"HTTP-alt";
        case 5001:  return L"HTTPS-alt";
        case 5060:  return L"SIP";
        case 5222:
        case 5223:
        case 5269:  return L"XMPP";
        case 5353:  return L"mDNS";
        case 5355:  return L"LLMNR";
        case 5357:  return L"WSDAPI";
        case 5432:  return L"PostgreSQL";
        case 5555:  return L"ADB";
        case 5601:  return L"Kibana";
        case 5672:  return L"AMQP";
        case 5800:
        case 5900:  return L"VNC";
        case 5985:  return L"WinRM";
        case 5986:  return L"WinRM";
        case 6379:  return L"Redis";
        case 6443:  return L"K8s API";
        case 7547:  return L"TR-069";
        case 7676:  return L"Samsung";
        case 8000:
        case 8001:
        case 8008:
        case 8080:
        case 8081:
        case 8082:
        case 8083:
        case 8086:
        case 8088:
        case 8090:
        case 8100:
        case 8888:  return L"HTTP";
        case 8089:  return L"Splunk";
        case 8091:  return L"Couchbase";
        case 8161:  return L"ActiveMQ";
        case 8200:  return L"Vault";
        case 8443:
        case 9443:
        case 10443: return L"HTTPS";
        case 8500:  return L"Consul";
        case 8554:  return L"RTSP";
        case 8883:  return L"MQTT";
        case 8983:  return L"Solr";
        case 9000:  return L"HTTP";
        case 9042:  return L"Cassandra";
        case 9090:  return L"HTTP";
        case 9092:  return L"Kafka";
        case 9100:  return L"JetDirect";
        case 9200:
        case 9300:  return L"Elastic";
        case 9418:  return L"git";
        case 10000: return L"Webmin";
        case 10250: return L"Kubelet";
        case 11211: return L"Memcached";
        case 15672: return L"RabbitMQ";
        case 27017:
        case 27018: return L"MongoDB";
        case 32400: return L"Plex";
        case 37777: return L"Dahua";
        case 50000: return L"SAP";
        case 62078: return L"iOS sync";
        default:
            if (port >= 49152 && port <= 65535) return L"RPC";
            return L"TCP";
    }
}

const wchar_t* App::PresetDisplayName(ScanPreset p) {
    switch (p) {
        case ScanPreset::Quick:        return L"Quick LAN Scan";
        case ScanPreset::Standard:     return L"Standard";
        case ScanPreset::FullCommon:   return L"Full Common";
        case ScanPreset::AllPortsFast: return L"Full Port Fast Scan";
        case ScanPreset::AllPortsDeep: return L"Full Port Deep Scan";
        case ScanPreset::CustomPorts:  return L"Custom Ports";
    }
    return L"";
}

const wchar_t* App::PresetDescription(ScanPreset p) {
    switch (p) {
        case ScanPreset::Quick:
            return L"61 ports covering the everyday LAN: mail, AD, file shares, NAS, "
                   L"hypervisor, common DBs, dev / containers, observability. Finishes "
                   L"a /24 in seconds.";
        case ScanPreset::Standard:
            return L"132 ports adding the full Windows AD stack (Kerberos / Global "
                   L"Catalog / RADIUS), backup + management (TFTP / syslog / NTP / "
                   L"IPMI), virtualization API surface (Docker / K8s API / Vault), "
                   L"cPanel / WHM, OpenVPN / IPsec.";
        case ScanPreset::FullCommon:
            return L"231 ports \x2014 everything in Standard plus low daemons "
                   L"(echo / chargen / time / TACACS+), legacy mail (NNTP), routing "
                   L"(BGP / RIP), full RPC dynamic ranges, Subversion / git, XMPP, "
                   L"X11, IRC, BitTorrent, game ports, router-backdoor checks.";
        case ScanPreset::AllPortsFast:
            return L"Every TCP port. Fast mode skips reverse DNS / fingerprinting / "
                   L"clock-drift for speed; still ~1-3 minutes per /24.";
        case ScanPreset::AllPortsDeep:
            return L"Every TCP port + full fingerprinting. Slower (~5-15 min /24) but "
                   L"builds the richest per-host report.";
        case ScanPreset::CustomPorts:
            return L"Bring your own list. Accepts singles, ranges, and mixes: "
                   L"22,80,443,8000-8010,3389.";
    }
    return L"";
}

}  // namespace nl
