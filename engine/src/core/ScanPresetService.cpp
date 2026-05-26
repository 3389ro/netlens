#include "ScanPresetService.h"

#include <algorithm>
#include <cwctype>
#include <set>
#include <sstream>
#include <unordered_map>

namespace lanscope {

namespace {

std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::vector<int> allTcpPorts() {
    // Well-known / common ports get scanned FIRST so the user sees meaningful
    // services (HTTP, SSH, RDP, SMB, ...) appear within seconds even on a
    // 65535-port sweep. The remaining ~64k high-numbered ports trail behind
    // as the long tail. Order matters: PortScanner walks the vector
    // sequentially in 32-port batches, so the first batches now cover the
    // services that drive risk analysis.
    static const std::vector<int> kHotPorts = {
        20,    21,    22,    23,    25,    53,    67,    68,    69,    80,
        88,    110,   111,   123,   135,   137,   138,   139,   143,   161,
        162,   389,   443,   445,   465,   500,   514,   515,   587,   631,
        636,   873,   902,   993,   995,   1080,  1194,  1433,  1434,  1521,
        1701,  1723,  1812,  1813,  1883,  1900,  2049,  2082,  2083,  2086,
        2087,  2181,  2222,  2375,  2376,  2379,  2380,  3000,  3128,  3260,
        3268,  3269,  3306,  3389,  3478,  3690,  3724,  4000,  4040,  4243,
        4369,  4500,  4567,  4848,  4899,  5060,  5061,  5222,  5269,  5353,
        5355,  5357,  5432,  5555,  5601,  5631,  5666,  5672,  5800,  5900,
        5901,  5985,  5986,  6000,  6379,  6443,  6660,  6667,  6881,  6900,
        7000,  7001,  7077,  7547,  7777,  8000,  8008,  8009,  8080,  8081,
        8086,  8088,  8089,  8090,  8123,  8181,  8200,  8333,  8443,  8500,
        8554,  8800,  8834,  8888,  8983,  9000,  9001,  9042,  9080,  9090,
        9091,  9100,  9200,  9201,  9300,  9418,  9443,  9600,  9981,  10000,
        10250, 10255, 11211, 15672, 16379, 19000, 20000, 25565, 27017, 32400,
        49152, 49153, 49154, 49155, 49156, 49157, 50000
    };

    std::vector<int> v;
    v.reserve(65535);
    std::vector<bool> seen(65536, false);
    for (int p : kHotPorts) {
        if (p >= 1 && p <= 65535 && !seen[p]) {
            v.push_back(p);
            seen[p] = true;
        }
    }
    for (int p = 1; p <= 65535; ++p) {
        if (!seen[p]) v.push_back(p);
    }
    return v;
}

// Complete catalogue — visible to CLI via find(). The GUI dropdown surfaces
// only the first four.
const std::vector<ScanPreset>& allPresets() {
    static const std::vector<ScanPreset> kAll = {
        { L"quick",   L"Quick LAN Scan",
            {80, 443, 445, 3389} },
        { L"common",  L"Full Common",
            {20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
             465, 554, 587, 631, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389,
             5060, 5432, 5900, 5985, 5986, 6379, 7676, 8000, 8001, 8080, 8443,
             8888, 9100, 9200, 9300, 9999, 17988, 62078} },
        { L"all",     L"All Ports",         allTcpPorts() },
        { L"custom",  L"Custom Ports",      {} },
        // Legacy IDs — kept for CLI backwards compatibility (--preset windows etc.).
        // Not surfaced in the GUI dropdown.
        { L"windows", L"Windows Exposure",
            {135, 139, 445, 3389, 5985, 5986} },
        { L"remote",  L"Remote Access",
            {22, 23, 3389, 5900, 5901, 5985, 5986} },
        { L"web",     L"Web Devices",
            {80, 443, 8080, 8443, 8000, 8888} }
    };
    return kAll;
}

// GUI dropdown — just the first four canonical entries.
const std::vector<ScanPreset>& guiPresets() {
    static const std::vector<ScanPreset> v = [] {
        const auto& all = allPresets();
        return std::vector<ScanPreset>(all.begin(), all.begin() + 4);
    }();
    return v;
}

const std::vector<ScanPreset>& buildPresets() {
    // The GUI binds dropdown index → vector index, so this is the canonical
    // GUI-visible list.
    return guiPresets();
}

const std::unordered_map<int, std::wstring>& serviceMap() {
    // Curated TCP/UDP service map — ~150 ports. The single source of
    // truth shared by the engine fingerprinter and the GUI's port-table
    // service column.
    static const std::unordered_map<int, std::wstring> kMap = {
        {20,    L"FTP-data"},        {21,    L"FTP"},
        {22,    L"SSH"},             {23,    L"Telnet"},
        {25,    L"SMTP"},            {53,    L"DNS"},
        {67,    L"DHCP-srv"},        {68,    L"DHCP-cli"},
        {79,    L"Finger"},          {80,    L"HTTP"},
        {88,    L"Kerberos"},        {102,   L"S7"},
        {104,   L"HL7"},             {110,   L"POP3"},
        {111,   L"RPCBind"},         {113,   L"Ident"},
        {119,   L"NNTP"},            {123,   L"NTP"},
        {135,   L"RPC"},             {137,   L"NetBIOS-NS"},
        {138,   L"NetBIOS-DGM"},     {139,   L"NetBIOS-SSN"},
        {143,   L"IMAP"},            {161,   L"SNMP"},
        {162,   L"SNMPtrap"},        {179,   L"BGP"},
        {389,   L"LDAP"},            {427,   L"SLP"},
        {443,   L"HTTPS"},           {445,   L"SMB"},
        {465,   L"SMTPS"},           {500,   L"ISAKMP"},
        {502,   L"Modbus"},          {514,   L"Syslog"},
        {515,   L"LPR"},             {540,   L"UUCP"},
        {543,   L"klogin"},          {544,   L"kshell"},
        {548,   L"AFP"},             {554,   L"RTSP"},
        {587,   L"SMTP-sub"},        {593,   L"RPC-HTTP"},
        {623,   L"IPMI"},            {631,   L"IPP"},
        {636,   L"LDAPS"},           {749,   L"Kerberos-admin"},
        {853,   L"DNS-TLS"},         {873,   L"rsync"},
        {902,   L"VMware-auth"},     {912,   L"VMware-WS"},
        {993,   L"IMAPS"},           {995,   L"POP3S"},
        {1080,  L"SOCKS"},           {1099,  L"RMI"},
        {1194,  L"OpenVPN"},         {1234,  L"LM Studio"},
        {1311,  L"Dell OM"},         {1352,  L"Lotus"},
        {1400,  L"Sonos"},           {1414,  L"IBM MQ"},
        {1433,  L"MSSQL"},           {1494,  L"Citrix ICA"},
        {1521,  L"Oracle"},          {1604,  L"Citrix HTTPS"},
        {1720,  L"H.323"},           {1723,  L"PPTP"},
        {1755,  L"MMS"},             {1883,  L"MQTT"},
        {1900,  L"SSDP"},            {1911,  L"BACnet"},
        {2000,  L"Cisco SCCP"},      {2049,  L"NFS"},
        {2179,  L"Hyper-V VMConnect"},{2222, L"EtherNet/IP"},
        {2375,  L"Docker"},          {2376,  L"Docker-TLS"},
        {2379,  L"etcd-client"},     {2380,  L"etcd-peer"},
        {2381,  L"HP iLO web"},      {2598,  L"Citrix"},
        {2638,  L"Sybase"},          {3000,  L"Grafana/Node"},
        {3050,  L"Firebird"},        {3128,  L"Squid"},
        {3260,  L"iSCSI"},           {3268,  L"LDAP-cat"},
        {3269,  L"LDAPS-cat"},       {3299,  L"SAP"},
        {3306,  L"MySQL"},           {3307,  L"MySQL-alt"},
        {3389,  L"RDP"},             {3478,  L"STUN"},
        {3689,  L"DAAP"},            {3690,  L"SVN"},
        {4369,  L"Erlang"},          {4500,  L"IPSec-NAT"},
        {4662,  L"eMule"},           {4789,  L"VXLAN"},
        {4848,  L"GlassFish"},       {4899,  L"Radmin"},
        {5000,  L"DSM HTTP"},        {5001,  L"DSM HTTPS"},
        {5004,  L"RTP"},             {5005,  L"RTCP"},
        {5009,  L"AirPort"},         {5022,  L"MSSQL-alt"},
        {5040,  L"Win UPnP"},        {5060,  L"SIP"},
        {5061,  L"SIPS"},            {5190,  L"AIM"},
        {5222,  L"XMPP-client"},     {5269,  L"XMPP-server"},
        {5349,  L"TURNS"},           {5353,  L"mDNS"},
        {5355,  L"LLMNR"},           {5357,  L"WSDAPI"},
        {5432,  L"PostgreSQL"},      {5500,  L"VNC-rev"},
        {5601,  L"Kibana"},          {5631,  L"pcAnywhere"},
        {5666,  L"NRPE"},            {5672,  L"AMQP"},
        {5683,  L"CoAP"},            {5800,  L"VNC-HTTP"},
        {5900,  L"VNC"},             {5901,  L"VNC-1"},
        {5938,  L"TeamViewer"},      {5984,  L"CouchDB"},
        {5985,  L"WinRM"},           {5986,  L"WinRM-S"},
        {5988,  L"WBEM"},            {5989,  L"WBEM-S"},
        {6112,  L"Battle.net"},      {6346,  L"Gnutella"},
        {6347,  L"Gnutella-2"},      {6379,  L"Redis"},
        {6443,  L"K8s API"},
        {6660,  L"IRC"}, {6664, L"IRC"}, {6665, L"IRC"}, {6666, L"IRC"},
        {6667,  L"IRC"}, {6668, L"IRC"}, {6669, L"IRC"},
        {6679,  L"IRC"}, {6697, L"IRC"},
        {6881,  L"BitTorrent"},      {7000,  L"AirPlay"},
        {7100,  L"AirPlay-2"},       {7199,  L"Cassandra JMX"},
        {7547,  L"TR-069"},          {7680,  L"Win DO"},
        {7860,  L"Gradio"},          {7946,  L"Swarm"},
        {8000,  L"HTTP-alt"},        {8008,  L"HTTP-alt"},
        {8009,  L"Chromecast"},      {8080,  L"HTTP-alt"},
        {8086,  L"InfluxDB"},        {8087,  L"Riak"},
        {8088,  L"HTTP-alt"},        {8091,  L"Couchbase"},
        {8096,  L"Jellyfin"},        {8118,  L"Privoxy"},
        {8125,  L"statsd"},          {8140,  L"Puppet"},
        {8161,  L"ActiveMQ"},
        {8289,  L"HP/Aruba/MT web"}, {8291,  L"HP/Aruba/MT web"},
        {8295,  L"HP/Aruba/MT web"},
        {8300,  L"Consul"},          {8332,  L"BTC"},
        {8333,  L"BTC-net"},         {8443,  L"HTTPS-alt"},
        {8500,  L"Consul HTTP"},     {8501,  L"Streamlit"},
        {8554,  L"RTSP-alt"},        {8649,  L"Ganglia"},
        {8800,  L"HTTP-alt"},        {8834,  L"Nessus"},
        {8888,  L"HTTP-alt"},        {8920,  L"Emby"},
        {8983,  L"Solr"},            {9000,  L"HTTP-alt"},
        {9001,  L"Tor/HTTP"},        {9042,  L"Cassandra CQL"},
        {9050,  L"Tor SOCKS"},       {9051,  L"Tor ctrl"},
        {9080,  L"HTTP-alt"},        {9090,  L"Prometheus"},
        {9091,  L"Transmission"},    {9092,  L"Kafka"},
        {9100,  L"JetDirect"},       {9150,  L"Tor Browser"},
        {9160,  L"Cassandra Thrift"},{9200,  L"Elasticsearch"},
        {9300,  L"ES-cluster"},      {9389,  L"AD WS"},
        {9418,  L"git"},             {9443,  L"HTTPS-alt"},
        {9981,  L"tvheadend"},       {10000, L"Webmin"},
        {11211, L"Memcached"},       {11371, L"PGP keyserver"},
        {11434, L"Ollama"},
        {13720, L"NetBackup"}, {13721, L"NetBackup"}, {13722, L"NetBackup"},
        {13723, L"NetBackup"}, {13724, L"NetBackup"},
        {13782, L"NetBackup"}, {13783, L"NetBackup"},
        {15672, L"RabbitMQ mgmt"},   {17500, L"Dropbox sync"},
        {17988, L"Intel AMT"},       {18080, L"HTTP-alt"},
        {18332, L"BTC testnet"},     {18333, L"BTC testnet-net"},
        {19531, L"systemd-journal"}, {22000, L"Syncthing"},
        {25565, L"Minecraft"},       {27015, L"Steam"},
        {27017, L"MongoDB"},         {27018, L"MongoDB shard"},
        {27019, L"MongoDB cfg"},     {28017, L"MongoDB web"},
        {30303, L"Ethereum"},        {32400, L"Plex"},
        {33060, L"MySQL X"},         {34567, L"XMEye DVR"},
        {37777, L"Dahua DVR"},       {44818, L"EtherNet/IP"},
        {47001, L"WinRM HTTP"},      {47808, L"BACnet/IP"},
        {49152, L"MS RPC dyn"}, {49153, L"MS RPC dyn"},
        {49154, L"MS RPC dyn"}, {49155, L"MS RPC dyn"},
        {49156, L"MS RPC dyn"}, {49157, L"MS RPC dyn"},
        {50000, L"DB2/SAP"},         {50051, L"gRPC"},
        {50070, L"HDFS UI"},         {51820, L"WireGuard"},
        {51826, L"HomeBridge"},      {62078, L"iPhone lockdown"},
    };
    return kMap;
}

} // anonymous namespace

const std::vector<ScanPreset>& ScanPresetService::presets() {
    return buildPresets();
}

const ScanPreset* ScanPresetService::find(const std::wstring& id) {
    std::wstring needle = toLower(id);
    // Search the full catalogue so legacy CLI ids (--preset windows / remote /
    // web) keep working even though the GUI dropdown no longer lists them.
    for (const auto& p : allPresets()) {
        if (toLower(p.id) == needle) return &p;
    }
    return nullptr;
}

std::vector<int> ScanPresetService::parsePortList(const std::wstring& csv) {
    // Accepts:
    //   "80"                   single port
    //   "80,443,8080"          CSV
    //   "80-90"                inclusive range
    //   "80,8000-8010,3389"    mix of singles + ranges
    // Whitespace, commas, and semicolons all separate tokens.
    // Invalid tokens are skipped (best-effort parse — the GUI/CLI calls
    // this on user input, so silent-skip is friendlier than failing the
    // whole scan).
    std::vector<int> out;
    std::set<int>    seen;

    auto trimmed = [](const std::wstring& s, size_t& a, size_t& b) {
        a = 0; b = s.size();
        while (a < b && std::iswspace(static_cast<wint_t>(s[a]))) ++a;
        while (b > a && std::iswspace(static_cast<wint_t>(s[b - 1]))) --b;
    };
    auto parseInt = [](const std::wstring& s, size_t a, size_t b, int& out) -> bool {
        if (a == b) return false;
        int v = 0;
        for (size_t i = a; i < b; ++i) {
            wchar_t c = s[i];
            if (c < L'0' || c > L'9') return false;
            v = v * 10 + (c - L'0');
            if (v > 65535) return false;
        }
        out = v;
        return true;
    };
    auto addPort = [&](int p) {
        if (p >= 1 && p <= 65535 && seen.insert(p).second) {
            out.push_back(p);
        }
    };

    std::wstring token;
    auto flush = [&] {
        size_t a, b;
        trimmed(token, a, b);
        if (a == b) { token.clear(); return; }

        // Look for '-' inside the trimmed slice → range.
        size_t dash = std::wstring::npos;
        for (size_t i = a; i < b; ++i) {
            if (token[i] == L'-') { dash = i; break; }
        }
        if (dash != std::wstring::npos) {
            int lo = 0, hi = 0;
            size_t la, lb, ha, hb;
            // Left side: [a, dash); right side: [dash+1, b)
            std::wstring left  = token.substr(a, dash - a);
            std::wstring right = token.substr(dash + 1, b - (dash + 1));
            trimmed(left,  la, lb);
            trimmed(right, ha, hb);
            if (parseInt(left, la, lb, lo) && parseInt(right, ha, hb, hi)) {
                if (lo > hi) std::swap(lo, hi);
                // Cap range size to 65535 ports (the whole port space) so
                // a typo like "80-9999999" can't blow up.
                for (int p = lo; p <= hi; ++p) addPort(p);
            }
        } else {
            int v = 0;
            if (parseInt(token, a, b, v)) addPort(v);
        }
        token.clear();
    };

    for (wchar_t c : csv) {
        if (c == L',' || c == L';' || c == L' ' || c == L'\t' || c == L'\n' || c == L'\r') {
            flush();
        } else {
            token.push_back(c);
        }
    }
    flush();
    return out;
}

std::wstring ScanPresetService::formatPortList(const std::vector<int>& ports) {
    std::wstring out;
    for (size_t i = 0; i < ports.size(); ++i) {
        if (i > 0) out.push_back(L',');
        out += std::to_wstring(ports[i]);
    }
    return out;
}

std::wstring ScanPresetService::serviceFor(int port) {
    const auto& map = serviceMap();
    auto it = map.find(port);
    return it == map.end() ? std::wstring{} : it->second;
}

} // namespace lanscope
