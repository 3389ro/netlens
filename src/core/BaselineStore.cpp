#include "BaselineStore.h"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

namespace netlens {

namespace {

// Narrow UTF-8 ↔ wide conversion via the Windows multi-byte routines, but the
// baseline file format only stores ASCII hostnames / IPs / hex MAC addresses,
// so we get away with a straight passthrough for now. We escape tabs and
// newlines in case a hostname ever contains one.

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring fromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int needed = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed - 1), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), needed);
    return out;
}

std::string escape(const std::wstring& w) {
    std::string s = toUtf8(w);
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\t')      out += "\\t";
        else if (c == '\n') out += "\\n";
        else if (c == '\\') out += "\\\\";
        else                out += c;
    }
    return out;
}

std::wstring unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char next = s[++i];
            if (next == 't')      out += '\t';
            else if (next == 'n') out += '\n';
            else                  out += next;
        } else {
            out += s[i];
        }
    }
    return fromUtf8(out);
}

} // anonymous namespace

bool BaselineStore::save(const std::wstring& path, const Baseline& b) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;

    f << "NETLENS-BASELINE\t1\n";
    f << "LABEL\t" << escape(b.label) << "\n";
    f << "RANGE\t" << escape(b.range) << "\n";
    f << "COLUMNS\tIP\tStatus\tHostname\tMAC\tOpenPorts\tRiskLevel\tRiskHints\tRTT\n";

    for (const auto& r : b.hosts) {
        f << "HOST\t"
          << escape(r.ipAddress)     << "\t"
          << escape(r.statusText())  << "\t"
          << escape(r.hostname)      << "\t"
          << escape(r.macAddress)    << "\t"
          << escape(r.openPortsText())<< "\t"
          << escape(RiskLevelToString(r.riskLevel)) << "\t"
          << escape(r.riskHints)     << "\t"
          << r.responseTimeMs << "\n";
    }
    return static_cast<bool>(f);
}

bool BaselineStore::load(const std::wstring& path, Baseline& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;

    std::string header;
    if (!std::getline(f, header)) return false;
    if (header.rfind("NETLENS-BASELINE", 0) != 0) return false;

    Baseline tmp;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;

        // Trim trailing \r from Windows newlines.
        if (line.back() == '\r') line.pop_back();

        std::stringstream ss(line);
        std::string tag;
        std::getline(ss, tag, '\t');

        if (tag == "LABEL") {
            std::string v; std::getline(ss, v);
            tmp.label = unescape(v);
        } else if (tag == "RANGE") {
            std::string v; std::getline(ss, v);
            tmp.range = unescape(v);
        } else if (tag == "HOST") {
            ScanResult r;
            std::string ip, status, host, mac, ports, level, hints, rtt;
            std::getline(ss, ip,     '\t');
            std::getline(ss, status, '\t');
            std::getline(ss, host,   '\t');
            std::getline(ss, mac,    '\t');
            std::getline(ss, ports,  '\t');
            std::getline(ss, level,  '\t');
            std::getline(ss, hints,  '\t');
            std::getline(ss, rtt);

            r.ipAddress      = unescape(ip);
            r.isOnline       = (unescape(status) == L"Online");
            r.hostname       = unescape(host);
            r.macAddress     = unescape(mac);
            r.riskHints      = unescape(hints);

            std::wstring lv = unescape(level);
            if      (lv == L"High")   r.riskLevel = RiskLevel::High;
            else if (lv == L"Medium") r.riskLevel = RiskLevel::Medium;
            else if (lv == L"Low")    r.riskLevel = RiskLevel::Low;
            else                      r.riskLevel = RiskLevel::None;

            try {
                r.responseTimeMs = std::stoll(rtt);
            } catch (...) { r.responseTimeMs = 0; }

            tmp.hosts.push_back(std::move(r));
        }
        // Other tags ignored — forward-compatible.
    }

    out = std::move(tmp);
    return true;
}

} // namespace netlens
