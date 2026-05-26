#include "RiskAnalyzer.h"

#include "VersionAdvisory.h"

#include <algorithm>

namespace lanscope {

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

    // ---- v1.2: service-fingerprint + clock-drift exposure -------------------
    // Conservative by design. A visible version banner is an information-
    // disclosure observation, not a vulnerability — it never raises a host to
    // High on its own. We only bump *upward*, so a host already flagged by its
    // open ports keeps that (higher) level.
    bool versionBannerExposed = false;   // web / ssh / ftp / smtp banner
    bool dbVersionExposed     = false;   // MySQL / MariaDB / MSSQL version
    bool sqlBrowserResponding = false;   // UDP 1434 SQL Server Browser

    for (const auto& f : r.fingerprints) {
        const bool identified = !f.product.empty() || !f.version.empty();
        if (f.service == L"mssql-browser") {
            sqlBrowserResponding = true;
        } else if (f.service == L"mysql" || f.service == L"mssql") {
            if (identified) dbVersionExposed = true;
        } else if (f.service == L"http"  || f.service == L"https" ||
                   f.service == L"ssh"   || f.service == L"ftp"   ||
                   f.service == L"smtp") {
            if (identified) versionBannerExposed = true;
        }
    }

    // Clock drift — offset thresholds are absolute (a fast or slow clock is
    // equally a problem). Only one drift hint is added (the worse one).
    bool drift2 = false, drift5 = false;
    if (r.clockDrift.responded) {
        const int64_t absMs = r.clockDrift.offsetMs < 0
                              ? -r.clockDrift.offsetMs : r.clockDrift.offsetMs;
        if      (absMs > 300'000) drift5 = true;   // > 5 minutes
        else if (absMs > 120'000) drift2 = true;   // > 2 minutes
    }

    // Hints (appended after the port-based hints).
    if (versionBannerExposed) appendHint(r.riskHints, L"Service version banner exposed");
    if (dbVersionExposed)     appendHint(r.riskHints, L"Database service exposes version");
    if (sqlBrowserResponding) appendHint(r.riskHints, L"SQL Server Browser responding");
    if (drift5)               appendHint(r.riskHints, L"Clock drift above 5 minutes");
    else if (drift2)          appendHint(r.riskHints, L"Clock drift above 2 minutes");

    // Risk bumps — never above Medium for a bare visible version.
    if (versionBannerExposed) bump(RiskLevel::Low);     // Medium falls out of the
                                                       // port logic when the host
                                                       // also exposes SSH/FTP/etc.
    if (dbVersionExposed)     bump(RiskLevel::Medium);
    if (sqlBrowserResponding) bump(RiskLevel::Medium);
    if (drift2)               bump(RiskLevel::Low);
    if (drift5)               bump(RiskLevel::Medium);

    // ---- v1.2.3: known-risky-version advisories -----------------------------
    // Curated, conservative heuristic (see VersionAdvisory) — end-of-life lines
    // plus a few famous, exactly-version-pinned takeover-class issues. Unlike a
    // bare version banner, a known critical RCE advisory MAY bump to High: that
    // is the one place a visible version is allowed to raise the level, because
    // it is the explicit point of the feature. The hint text is phrased as an
    // "advisory ... verify" so it reads as a heuristic pointer, not a verdict.
    for (const auto& f : r.fingerprints) {
        if (auto a = VersionAdvisory::check(f)) {
            // De-dup: the same product/version can surface on two ports
            // (e.g. MSSQL on TCP 1433 and the SQL Browser on UDP 1434).
            if (r.riskHints.find(a->hint) == std::wstring::npos)
                appendHint(r.riskHints, a->hint.c_str());
            bump(a->severity);
        }
    }

    r.riskLevel = level;
}

} // namespace lanscope
