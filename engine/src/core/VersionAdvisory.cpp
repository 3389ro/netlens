#include "VersionAdvisory.h"

namespace lanscope {

namespace {

// Case-insensitive substring test (ASCII).
bool containsCi(const std::wstring& hay, const wchar_t* needle) {
    std::wstring h = hay, n = needle;
    auto lo = [](std::wstring& s) {
        for (auto& c : s)
            if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    };
    lo(h); lo(n);
    return h.find(n) != std::wstring::npos;
}

struct Ver { int major = 0, minor = 0, patch = 0; bool parsed = false; };

// Parses the leading "N", "N.N" or "N.N.N" of a version string. Stops at the
// first non-digit/non-dot, so "9.6p1" parses as 9.6 and "10.4.32" as 10.4.32.
Ver parseVer(const std::wstring& s) {
    Ver v;
    int comp[3] = {0, 0, 0};
    int idx = 0, cur = 0;
    bool inNum = false;
    for (wchar_t c : s) {
        if (c >= L'0' && c <= L'9') {
            cur = cur * 10 + (c - L'0');
            inNum = true;
            v.parsed = true;
        } else if (c == L'.') {
            if (idx < 3) comp[idx++] = cur;
            cur = 0;
            inNum = false;
        } else {
            break;
        }
    }
    if (inNum && idx < 3) comp[idx++] = cur;
    v.major = comp[0];
    v.minor = comp[1];
    v.patch = comp[2];
    return v;
}

VersionAdvisory::Advisory mk(std::wstring hint, RiskLevel sev) {
    return VersionAdvisory::Advisory{ std::move(hint), sev };
}

} // anonymous namespace

// =============================================================================
// The curated table. Deliberately small and conservative — end-of-life lines
// (no false-positive problem: EOL status does not depend on backported
// patches) plus a few famous, exactly-version-pinned takeover-class issues.
// Every hint is phrased as an "advisory" so it reads as a heuristic pointer,
// not a confirmed vulnerability.
// =============================================================================
std::optional<VersionAdvisory::Advisory>
VersionAdvisory::check(const ServiceFingerprint& fp) {
    const std::wstring& prod = fp.product;
    const std::wstring& ver  = fp.version;
    if (prod.empty()) return std::nullopt;     // nothing to assess
    const Ver v = parseVer(ver);

    // ---- Apache httpd --------------------------------------------------------
    if (containsCi(prod, L"Apache")) {
        // Exactly-pinned critical RCEs — these affect those builds specifically.
        if (ver == L"2.4.49")
            return mk(L"Apache 2.4.49 - known critical path-traversal RCE "
                      L"advisory (CVE-2021-41773), verify", RiskLevel::High);
        if (ver == L"2.4.50")
            return mk(L"Apache 2.4.50 - known critical path-traversal RCE "
                      L"advisory (CVE-2021-42013), verify", RiskLevel::High);
        // End-of-life: 1.3.x, 2.0.x, 2.2.x (2.4.x is the current line).
        if (v.parsed && (v.major == 1 || (v.major == 2 && v.minor < 4)))
            return mk(L"Apache " + ver + L" is end-of-life", RiskLevel::Medium);
        return std::nullopt;
    }

    // ---- vsftpd -------------------------------------------------------------
    if (containsCi(prod, L"vsftpd")) {
        if (ver == L"2.3.4")
            return mk(L"vsftpd 2.3.4 - backdoored release, known critical RCE "
                      L"advisory (CVE-2011-2523), verify", RiskLevel::High);
        return std::nullopt;
    }

    // ---- MariaDB ------------------------------------------------------------
    if (containsCi(prod, L"MariaDB")) {
        // 10.5 and earlier are past end-of-life as of 2026.
        if (v.parsed && (v.major < 10 || (v.major == 10 && v.minor <= 5)))
            return mk(L"MariaDB " + ver + L" is end-of-life", RiskLevel::Medium);
        return std::nullopt;
    }

    // ---- MySQL --------------------------------------------------------------
    if (containsCi(prod, L"MySQL")) {
        // The entire 5.x line is end-of-life (5.7 ended Oct 2023).
        if (v.parsed && v.major > 0 && v.major <= 5)
            return mk(L"MySQL " + ver + L" is end-of-life", RiskLevel::Medium);
        return std::nullopt;
    }

    // ---- Microsoft SQL Server (version "major.minor.build") -----------------
    // Major 12 = SQL Server 2014, 11 = 2012, 10 = 2008/R2 — all out of support.
    if (containsCi(prod, L"SQL Server")) {
        if (v.parsed && v.major > 0 && v.major <= 12)
            return mk(L"Microsoft SQL Server " + ver + L" is end-of-life",
                      RiskLevel::Medium);
        return std::nullopt;
    }

    // ---- OpenSSH ------------------------------------------------------------
    if (containsCi(prod, L"OpenSSH")) {
        if (v.parsed && v.major > 0 && v.major < 7)
            return mk(L"OpenSSH " + ver + L" is outdated", RiskLevel::Low);
        return std::nullopt;
    }

    // ---- Windows (version "major.minor" from NetServerGetInfo) --------------
    if (containsCi(prod, L"Windows")) {
        if (v.parsed && v.major > 0 && v.major < 10)
            return mk(L"Windows " + ver + L" is unsupported / end-of-life",
                      RiskLevel::Medium);
        return std::nullopt;
    }

    return std::nullopt;
}

} // namespace lanscope
