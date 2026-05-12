#include "RiskAnalyzer.h"

#include <algorithm>

namespace netlens {

namespace {

bool portOpen(const std::vector<PortStatus>& ports, int p) {
    for (const auto& s : ports) {
        if (s.port == p && s.isOpen) return true;
    }
    return false;
}

bool anyOpen(const std::vector<PortStatus>& ports, std::initializer_list<int> ps) {
    for (int p : ps) if (portOpen(ports, p)) return true;
    return false;
}

void appendHint(std::wstring& acc, const wchar_t* hint) {
    if (!acc.empty()) acc += L", ";
    acc += hint;
}

} // anonymous namespace

void RiskAnalyzer::evaluate(ScanResult& r) {
    r.riskLevel = RiskLevel::None;
    r.riskHints.clear();

    // Offline hosts: always Status=Offline / Risk=None / single hint
    // "Device unreachable". Never add open-port hints to offline rows.
    if (!r.isOnline) {
        r.riskHints = L"Device unreachable";
        r.riskLevel = RiskLevel::None;
        return;
    }

    const auto& ports = r.ports;

    const bool rdp     = portOpen(ports, 3389);
    const bool smb     = portOpen(ports, 445);
    const bool ssh     = portOpen(ports, 22);
    const bool telnet  = portOpen(ports, 23);
    const bool ftp     = portOpen(ports, 21);
    const bool winrm   = anyOpen(ports, {5985, 5986});
    const bool rpc     = portOpen(ports, 135);
    const bool nbt     = portOpen(ports, 139);
    const bool web     = anyOpen(ports, {80, 443, 8080, 8443, 8000, 8888});
    const bool db      = anyOpen(ports, {1433, 1521, 3306, 5432, 6379, 9200, 9300});

    // ---- hint list (spec wording, severity-ordered) -------------------------
    if (rdp)         appendHint(r.riskHints, L"RDP open");
    if (smb)         appendHint(r.riskHints, L"SMB open");
    if (ssh)         appendHint(r.riskHints, L"SSH open");
    if (telnet)      appendHint(r.riskHints, L"Telnet open");
    if (ftp)         appendHint(r.riskHints, L"FTP open");
    if (winrm)       appendHint(r.riskHints, L"WinRM open");
    if (db)          appendHint(r.riskHints, L"Database port open");
    if (rpc || nbt)  appendHint(r.riskHints, L"Windows RPC/NetBIOS exposed");
    if (web)         appendHint(r.riskHints, L"Web interface detected");

    // ---- risk level ---------------------------------------------------------
    // bump() only raises the level — never lowers — so the order of calls
    // doesn't matter for correctness, only for readability.
    RiskLevel level = RiskLevel::None;
    auto bump = [&](RiskLevel l) {
        if (static_cast<int>(l) > static_cast<int>(level)) level = l;
    };

    // High
    if (rdp)        bump(RiskLevel::High);
    if (telnet)     bump(RiskLevel::High);
    if (winrm)      bump(RiskLevel::High);
    if (db)         bump(RiskLevel::High);

    // Medium
    if (smb)        bump(RiskLevel::Medium);
    if (rpc || nbt) bump(RiskLevel::Medium);
    if (ssh)        bump(RiskLevel::Medium);
    if (ftp)        bump(RiskLevel::Medium);

    // Low — only when nothing higher matched and there's *something* open
    if (level == RiskLevel::None && web) {
        level = RiskLevel::Low;
    }

    // ---- UDP-derived hints (v1.2.0) ----------------------------------------
    // The UDP probes are deterministic (positive only on real responses), so
    // a populated field implies the service is actually answering. We treat
    // SNMP `public` as Medium (read access to device info / config); other
    // UDP findings as Low info-disclosure hints.
    if (!r.udp.snmpSysDescr.empty()) {
        appendHint(r.riskHints, L"SNMP 'public' read access");
        bump(RiskLevel::Medium);
    }
    if (!r.udp.upnpServer.empty()) {
        appendHint(r.riskHints, L"UPnP / SSDP responding");
        if (level == RiskLevel::None) level = RiskLevel::Low;
    }
    if (!r.udp.netbiosName.empty() || !r.udp.netbiosWorkgroup.empty()) {
        appendHint(r.riskHints, L"NetBIOS name service exposed");
        if (level == RiskLevel::None) level = RiskLevel::Low;
    }
    if (!r.udp.dnsVersion.empty()) {
        appendHint(r.riskHints, L"DNS server discloses version");
        if (level == RiskLevel::None) level = RiskLevel::Low;
    }

    r.riskLevel = level;
}

} // namespace netlens
