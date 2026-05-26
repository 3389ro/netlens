#include "VersionAnnotator.h"

#include <algorithm>
#include <cwctype>
#include <vector>

namespace lanscope {

namespace {

std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

bool contains(const std::wstring& s, const wchar_t* needle) {
    return s.find(needle) != std::wstring::npos;
}

bool startsWith(const std::wstring& s, const wchar_t* needle) {
    size_t n = 0; while (needle[n]) ++n;
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) if (s[i] != needle[i]) return false;
    return true;
}

std::vector<std::wstring> split(const std::wstring& s, wchar_t sep) {
    std::vector<std::wstring> out;
    std::wstring cur;
    for (wchar_t c : s) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

// Parse the leading run of digits as unsigned. Returns 0 on parse failure.
unsigned parseUint(const std::wstring& s) {
    unsigned v = 0;
    for (wchar_t c : s) {
        if (c < L'0' || c > L'9') break;
        v = v * 10u + static_cast<unsigned>(c - L'0');
    }
    return v;
}

} // anonymous namespace

std::wstring VersionAnnotator::annotate(const std::wstring& product,
                                         const std::wstring& version) {
    if (version.empty()) return {};
    const std::wstring pl = toLower(product);

    // ---- Microsoft SQL Server ------------------------------------------------
    // PRELOGIN VERSION token's major.minor uniquely identifies the release
    // year (SQL Server's marketing-year ⇔ internal-major map).
    if (contains(pl, L"microsoft sql server") || pl == L"mssql") {
        auto parts = split(version, L'.');
        const std::wstring major = parts.size() > 0 ? parts[0] : L"";
        const std::wstring minor = parts.size() > 1 ? parts[1] : L"";
        if (major == L"8")                            return L"SQL Server 2000";
        if (major == L"9")                            return L"SQL Server 2005";
        if (major == L"10" && minor == L"50")         return L"SQL Server 2008 R2";
        if (major == L"10")                           return L"SQL Server 2008";
        if (major == L"11")                           return L"SQL Server 2012";
        if (major == L"12")                           return L"SQL Server 2014";
        if (major == L"13")                           return L"SQL Server 2016";
        if (major == L"14")                           return L"SQL Server 2017";
        if (major == L"15")                           return L"SQL Server 2019";
        if (major == L"16")                           return L"SQL Server 2022";
        return {};
    }

    // ---- Apache HTTP Server -------------------------------------------------
    if (pl == L"apache" || startsWith(pl, L"apache/")) {
        if (startsWith(version, L"2.4.")) {
            unsigned patch = parseUint(version.substr(4));
            if (patch <= 40)                          return L"Apache 2.4 — very old (≤2019)";
            if (patch <= 48)                          return L"Apache 2.4 from 2019-2020";
            // Only 2.4.49 and 2.4.50 were vulnerable to CVE-2021-41773 /
            // -42013 (path traversal); 2.4.48 and ≤2.4.50 share an era but
            // earlier patches don't carry that specific CVE.
            if (patch == 49 || patch == 50)           return L"Apache 2.4 — CVE-2021-41773 path traversal";
            if (patch <= 53)                          return L"Apache 2.4 from late 2021";
            if (patch <= 57)                          return L"Apache 2.4 from 2022-2023";
            if (patch <= 60)                          return L"Apache 2.4 from 2023-2024";
            if (patch <= 64)                          return L"Apache 2.4 from 2024-2025";
            return L"Apache 2.4 — current line";
        }
        if (startsWith(version, L"2.2."))             return L"Apache 2.2 — EOL since 2017";
        if (startsWith(version, L"1."))               return L"Apache 1.x — EOL";
        return {};
    }

    // ---- nginx --------------------------------------------------------------
    if (pl == L"nginx") {
        auto parts = split(version, L'.');
        if (parts.size() >= 2) {
            unsigned maj = parseUint(parts[0]);
            unsigned min = parseUint(parts[1]);
            if (maj == 0)                             return L"nginx 0.x — EOL";
            if (maj == 1 && min < 20)                 return L"nginx 1.x — pre-2021, dated";
            if (maj == 1 && min < 24)                 return L"nginx 1.20–1.23 — 2021-2022";
            if (maj == 1 && min < 26)                 return L"nginx 1.24–1.25 — 2023";
            if (maj == 1 && min < 28)                 return L"nginx 1.26–1.27 — 2024-2025 current";
        }
        return {};
    }

    // ---- OpenSSH ------------------------------------------------------------
    if (pl == L"openssh") {
        auto parts = split(version, L'.');
        if (parts.size() >= 2) {
            unsigned maj = parseUint(parts[0]);
            unsigned min = parseUint(parts[1]);
            if (maj < 8)                              return L"OpenSSH < 8.x — dated";
            if (maj == 8)                             return L"OpenSSH 8.x — pre-2024, dated";
            if (maj == 9 && min < 6)                  return L"OpenSSH 9.0–9.5 — pre-2024";
            // 9.6 added CVE-2024-6387 (regreSSHion) fixes in 9.8.
            if (maj == 9 && min < 8)                  return L"OpenSSH 9.6–9.7 — pre-regreSSHion (CVE-2024-6387)";
        }
        return {};
    }

    // ---- VMware ESXi / vSphere ----------------------------------------------
    // The engine pulls the vim25 namespace version from the /sdk endpoint.
    if (contains(pl, L"esxi") || contains(pl, L"vsphere")) {
        auto parts = split(version, L'.');
        unsigned maj    = parts.size() > 0 ? parseUint(parts[0]) : 0u;
        unsigned min    = parts.size() > 1 ? parseUint(parts[1]) : 0u;
        unsigned update = parts.size() > 2 ? parseUint(parts[2]) : 99u;
        if (maj == 8 && min == 0 && update == 0)      return L"ESXi 8.0 GA (Oct 2022) — current";
        if (maj == 8 && min == 0 && update == 1)      return L"ESXi 8.0 Update 1 (Apr 2023) — current";
        if (maj == 8 && min == 0 && update == 2)      return L"ESXi 8.0 Update 2 (Sep 2023) — current";
        if (maj == 8 && min == 0 && update == 3)      return L"ESXi 8.0 Update 3 (Jun 2024) — current";
        if (maj == 8 && min == 0)                     return L"ESXi 8.0 — current line (EOL Oct 2027)";
        if (maj == 7 && min == 0 && update == 0)      return L"ESXi 7.0 GA (Apr 2020) — mainstream EOL Apr 2025";
        if (maj == 7 && min == 0 && update == 1)      return L"ESXi 7.0 Update 1 (Oct 2020) — mainstream EOL Apr 2025";
        if (maj == 7 && min == 0 && update == 2)      return L"ESXi 7.0 Update 2 (Mar 2021) — mainstream EOL Apr 2025";
        if (maj == 7 && min == 0 && update == 3)      return L"ESXi 7.0 Update 3 (Oct 2021) — mainstream EOL Apr 2025";
        if (maj == 7 && min == 0)                     return L"ESXi 7.0 — mainstream EOL Apr 2025";
        if (maj == 6 && min == 7)                     return L"ESXi 6.7 — EOL Oct 2022, unsupported";
        if (maj == 6 && min == 5)                     return L"ESXi 6.5 — EOL Nov 2021, unsupported";
        if (maj == 6 && min == 0)                     return L"ESXi 6.0 — EOL Mar 2020, unsupported";
        return {};
    }

    // ---- MariaDB / MySQL family-version commentary --------------------------
    if (pl == L"mariadb" || pl == L"mysql") {
        auto parts = split(version, L'.');
        if (parts.size() >= 2) {
            unsigned maj = parseUint(parts[0]);
            unsigned min = parseUint(parts[1]);
            if (pl == L"mysql") {
                if (maj < 5 || (maj == 5 && min < 7))     return L"MySQL < 5.7 — out of LTS";
                if (maj == 5 && min == 7)                 return L"MySQL 5.7 — extended support only";
                if (maj >= 8)                             return L"MySQL 8.x — current major";
            } else {
                if (maj == 10 && min < 6)                 return L"MariaDB 10.x pre-10.6 — older LTS";
                if (maj == 10)                            return L"MariaDB 10.x — current LTS line";
                if (maj == 11)                            return L"MariaDB 11.x — current";
            }
        }
        return {};
    }

    return {};
}

} // namespace lanscope
