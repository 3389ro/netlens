#include "CommandLineParser.h"

#include "../AppConstants.h"

#include <cstdlib>
#include <cwchar>
#include <string>

namespace netlens {

namespace {

bool needsValue(const std::wstring& flag) {
    return flag == L"--range"   || flag == L"--adapter"  || flag == L"--preset" ||
           flag == L"--ports"   || flag == L"--timeout"  || flag == L"--parallel" ||
           flag == L"--mode"    ||
           flag == L"--csv"     || flag == L"--html";
}

int parseInt(const std::wstring& s, int fallback) {
    if (s.empty()) return fallback;
    wchar_t* end = nullptr;
    long v = std::wcstol(s.c_str(), &end, 10);
    if (!end || *end != L'\0') return fallback;
    return static_cast<int>(v);
}

} // anonymous namespace

CommandLineParser::Args CommandLineParser::parse(int argc, wchar_t** argv) {
    Args a;

    for (int i = 1; i < argc; ++i) {
        std::wstring tok = argv[i];

        if (tok == L"--help" || tok == L"-h" || tok == L"/?") {
            a.showHelp = true;
            continue;
        }
        if (tok == L"--list-adapters") { a.listAdapters     = true; continue; }
        if (tok == L"--online-only")   { a.onlineOnly       = true; continue; }
        if (tok == L"--no-dns")        { a.noDns            = true; continue; }
        if (tok == L"--no-mac")        { a.noMac            = true; continue; }
        if (tok == L"--no-udp")        { a.noUdp            = true; continue; }
        if (tok == L"--no-ports")      { a.noPorts          = true; continue; }
        if (tok == L"--allow-large-range") { a.allowLargeRange = true; continue; }
        if (tok == L"--debug")         { a.debug            = true; continue; }

        if (needsValue(tok)) {
            if (i + 1 >= argc) {
                a.hasError = true;
                a.error    = L"Option " + tok + L" requires a value.";
                return a;
            }
            std::wstring val = argv[++i];
            if      (tok == L"--range")    a.range        = val;
            else if (tok == L"--adapter")  a.adapterIndex = parseInt(val, -1);
            else if (tok == L"--preset")   a.presetId     = val;
            else if (tok == L"--mode")     a.modeId       = val;
            else if (tok == L"--ports")    a.portsCsv     = val;
            else if (tok == L"--timeout")  a.timeoutMs    = parseInt(val, kDefaultTimeoutMs);
            else if (tok == L"--parallel") a.parallel     = parseInt(val, kDefaultParallel);
            else if (tok == L"--csv")      a.csvPath      = val;
            else if (tok == L"--html")     a.htmlPath     = val;
            continue;
        }

        a.hasError = true;
        a.error    = L"Unknown argument: " + tok;
        return a;
    }

    // Clamp rather than error: callers tend to expect "do what I roughly meant".
    if (a.timeoutMs < kMinTimeoutMs) a.timeoutMs = kMinTimeoutMs;
    if (a.timeoutMs > kMaxTimeoutMs) a.timeoutMs = kMaxTimeoutMs;
    if (a.parallel  < kMinParallel)  a.parallel  = kMinParallel;
    if (a.parallel  > kMaxParallel)  a.parallel  = kMaxParallel;

    // Validate --mode if provided.
    if (a.modeId != L"fast" && a.modeId != L"deep" && a.modeId != L"discovery") {
        a.hasError = true;
        a.error    = L"--mode must be one of: fast, deep, discovery.";
        return a;
    }

    return a;
}

std::wstring CommandLineParser::helpText() {
    std::wstring s;
    s += L"NetLens ";
    s += kAppVersion;
    s += L" - Portable LAN Scanner for Small Business Networks\n";
    s += L"\n";
    s += L"USAGE\n";
    s += L"  NetLens.exe                                       (launches the GUI)\n";
    s += L"  NetLens.exe --help\n";
    s += L"  NetLens.exe --list-adapters\n";
    s += L"  NetLens.exe --range 192.168.1.1-254 --preset quick --csv report.csv\n";
    s += L"  NetLens.exe --adapter 1 --preset windows --timeout 400 --parallel 128\n";
    s += L"  NetLens.exe --range 192.168.1.0/24 --mode deep --html report.html\n";
    s += L"  NetLens.exe --range 192.168.1.0/24 --ports 22,80,443 --online-only\n";
    s += L"\n";
    s += L"OPTIONS\n";
    s += L"  --help                  Show this help.\n";
    s += L"  --list-adapters         List detected IPv4 adapters and exit.\n";
    s += L"  --range <expr>          IP range to scan. Formats:\n";
    s += L"                            192.168.1.10\n";
    s += L"                            192.168.1.1-254\n";
    s += L"                            192.168.1.10-192.168.1.50\n";
    s += L"                            192.168.1.0/24\n";
    s += L"  --adapter <index>       Use the suggested range from the given adapter index.\n";
    s += L"                          Index numbers come from --list-adapters.\n";
    s += L"  --preset <id>           Port preset (default: quick). One of:\n";
    s += L"                            quick    -  80,443,445,3389\n";
    s += L"                            windows  -  135,139,445,3389,5985,5986\n";
    s += L"                            remote   -  22,23,3389,5900,5901,5985,5986\n";
    s += L"                            web      -  80,443,8080,8443,8000,8888\n";
    s += L"                            common   -  full common-ports list\n";
    s += L"  --mode <id>             Scan mode (default: fast). One of:\n";
    s += L"                            fast      -  ICMP first, only 4 discovery\n";
    s += L"                                          ports as TCP fallback\n";
    s += L"                            deep      -  ICMP first, full preset port\n";
    s += L"                                          scan as TCP fallback\n";
    s += L"                            discovery -  ICMP + DNS + MAC, no TCP\n";
    s += L"  --ports <csv>           Custom port list (overrides --preset). e.g. 22,80,443\n";
    s += L"  --timeout <ms>          Probe timeout in milliseconds (default 400).\n";
    s += L"  --parallel <n>          Max concurrent host probes (default 128).\n";
    s += L"  --csv <path>            Write a CSV report to <path>.\n";
    s += L"  --html <path>           Write an HTML report to <path>.\n";
    s += L"  --online-only           Skip offline hosts in the output / reports.\n";
    s += L"  --no-dns                Disable reverse-DNS lookup.\n";
    s += L"  --no-mac                Disable MAC lookup.\n";
    s += L"  --no-udp                Disable UDP service-probe enrichment\n";
    s += L"                          (NetBIOS / mDNS / SSDP / SNMP / DNS-version / NTP).\n";
    s += L"  --no-ports              Disable TCP port probing (ICMP only).\n";
    s += L"  --allow-large-range     Permit ranges above 65535 hosts.\n";
    s += L"  --debug                 Verbose diagnostic output to stderr.\n";
    s += L"\n";
    s += L"EXIT CODES\n";
    s += L"  0  success\n";
    s += L"  1  invalid arguments\n";
    s += L"  2  scan error\n";
    s += L"  3  export error\n";
    s += L"\n";
    s += L"SAFETY\n";
    s += L"  Use NetLens only on networks you own or have explicit authorisation\n";
    s += L"  to scan. The tool reports open ports and exposure hints - it does not\n";
    s += L"  confirm vulnerabilities.\n";
    return s;
}

} // namespace netlens
