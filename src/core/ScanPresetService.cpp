#include "ScanPresetService.h"

#include <algorithm>
#include <cwctype>
#include <set>
#include <sstream>
#include <unordered_map>

namespace netlens {

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

// The seed for the user-editable portion of the dropdown (does NOT include
// the auto-managed "all" / "custom" sentinels). Used both by defaultGuiPresets()
// at startup and by the preset manager's Reset button.
std::vector<ScanPreset> defaultUserPresets() {
    return {
        { L"quick",   L"Quick LAN Scan",
            {80, 443, 445, 3389} },
        { L"common",  L"Full Common",
            {20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
             465, 587, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900,
             5985, 5986, 6379, 8000, 8080, 8443, 8888, 9200, 9300} },
    };
}

// Legacy CLI-only presets (--preset windows / remote / web). Immutable —
// keeps existing scripts working even after the user edits the GUI list.
const std::vector<ScanPreset>& legacyPresets() {
    static const std::vector<ScanPreset> kLegacy = {
        { L"windows", L"Windows Exposure",
            {135, 139, 445, 3389, 5985, 5986} },
        { L"remote",  L"Remote Access",
            {22, 23, 3389, 5900, 5901, 5985, 5986} },
        { L"web",     L"Web Devices",
            {80, 443, 8080, 8443, 8000, 8888} }
    };
    return kLegacy;
}

// Default seed for the GUI-visible preset list. setPresets() can replace
// this at runtime via the Manage port presets dialog. The order is the
// dropdown order: user-editable first, then the two auto-managed sentinels.
std::vector<ScanPreset> defaultGuiPresets() {
    auto editable = defaultUserPresets();
    editable.push_back({ L"all",    L"All Ports",    allTcpPorts() });
    editable.push_back({ L"custom", L"Custom Ports", {} });
    return editable;
}

// Mutable singleton accessor — the address is stable for the const& accessor,
// the contents are replaced wholesale by setPresets() rather than mutated in
// place so callers caching iterators are not affected mid-scan.
std::vector<ScanPreset>& mutableGuiPresets() {
    static std::vector<ScanPreset> v = defaultGuiPresets();
    return v;
}

const std::unordered_map<int, std::wstring>& serviceMap() {
    static const std::unordered_map<int, std::wstring> kMap = {
        {21,   L"FTP"},
        {22,   L"SSH"},
        {23,   L"Telnet"},
        {25,   L"SMTP"},
        {53,   L"DNS"},
        {80,   L"HTTP"},
        {110,  L"POP3"},
        {111,  L"RPCBind"},
        {135,  L"RPC"},
        {139,  L"NetBIOS"},
        {143,  L"IMAP"},
        {389,  L"LDAP"},
        {443,  L"HTTPS"},
        {445,  L"SMB"},
        {465,  L"SMTPS"},
        {587,  L"SMTP Submission"},
        {993,  L"IMAPS"},
        {995,  L"POP3S"},
        {1433, L"MSSQL"},
        {1521, L"Oracle"},
        {1723, L"PPTP"},
        {2049, L"NFS"},
        {3306, L"MySQL"},
        {3389, L"RDP"},
        {5432, L"PostgreSQL"},
        {5900, L"VNC"},
        {5901, L"VNC-1"},
        {5985, L"WinRM HTTP"},
        {5986, L"WinRM HTTPS"},
        {6379, L"Redis"},
        {8000, L"HTTP Alt"},
        {8080, L"HTTP Proxy"},
        {8443, L"HTTPS Alt"},
        {8888, L"HTTP Alt"},
        {9200, L"Elasticsearch"},
        {9300, L"Elasticsearch Transport"}
    };
    return kMap;
}

} // anonymous namespace

const std::vector<ScanPreset>& ScanPresetService::presets() {
    return mutableGuiPresets();
}

const ScanPreset* ScanPresetService::find(const std::wstring& id) {
    std::wstring needle = toLower(id);
    for (const auto& p : mutableGuiPresets()) {
        if (toLower(p.id) == needle) return &p;
    }
    for (const auto& p : legacyPresets()) {
        if (toLower(p.id) == needle) return &p;
    }
    return nullptr;
}

void ScanPresetService::setPresets(std::vector<ScanPreset> presets) {
    bool hasAll = false, hasCustom = false;
    for (const auto& p : presets) {
        auto idl = toLower(p.id);
        if (idl == L"all")    hasAll = true;
        if (idl == L"custom") hasCustom = true;
    }
    if (!hasAll) {
        presets.push_back({ L"all", L"All Ports", allTcpPorts() });
    }
    if (!hasCustom) {
        presets.push_back({ L"custom", L"Custom Ports", {} });
    }
    mutableGuiPresets() = std::move(presets);
}

std::vector<ScanPreset> ScanPresetService::defaultPresets() {
    return defaultUserPresets();
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

} // namespace netlens
