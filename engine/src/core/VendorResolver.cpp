#include "VendorResolver.h"

#include "OuiData.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace lanscope {

namespace {

// Lookup table built once from kOuiBlob. Key is the prefix string ("000000"
// for 24-bit, "0011223" for 28-bit, "001122334" for 36-bit). Value is the
// vendor name (UTF-8 — we widen at lookup time).
//
// Using std::string for the value rather than string_view keeps the parser
// simple and the data still lives in a single contiguous arena; the cost is
// duplicating ~600 KB of vendor names. The whole table fits in ~1.5 MB heap.
struct OuiTable {
    std::unordered_map<std::string, std::string> map;

    OuiTable() {
        map.reserve(60'000);
        parse();
    }

    void parse() {
        const char* p   = kOuiBlob;
        const char* end = p + kOuiBlobSize;

        while (p < end) {
            // Skip leading whitespace within a line.
            const char* lineStart = p;
            while (p < end && *p != '\n') ++p;
            // [lineStart, p) is the current line (no trailing newline).
            std::string_view line(lineStart, static_cast<size_t>(p - lineStart));
            if (p < end) ++p; // step past '\n'

            if (line.empty() || line[0] == '#') continue;

            // Split on first whitespace.
            size_t sp = 0;
            while (sp < line.size() && line[sp] != ' ' && line[sp] != '\t') ++sp;
            if (sp == 0 || sp >= line.size()) continue;

            std::string prefix(line.substr(0, sp));
            // Trim leading whitespace from vendor name.
            size_t vs = sp;
            while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) ++vs;
            if (vs >= line.size()) continue;

            std::string vendor(line.substr(vs));
            // Trim trailing whitespace.
            while (!vendor.empty() &&
                   (vendor.back() == ' ' || vendor.back() == '\t' ||
                    vendor.back() == '\r'))
                vendor.pop_back();

            if (prefix.empty() || vendor.empty()) continue;

            // Canonicalise prefix to uppercase ASCII hex.
            for (char& c : prefix) {
                if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
            }

            // Only accept prefixes made of hex digits (defensive — the input is
            // supposed to be clean but we don't want to import junk).
            bool valid = !prefix.empty();
            for (char c : prefix) {
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
                    valid = false; break;
                }
            }
            if (!valid) continue;

            // Newer prefix wins on duplicate (rare but happens).
            map[std::move(prefix)] = std::move(vendor);
        }
    }
};

OuiTable& table() {
    // Magic-static initialisation is thread-safe in C++11+.
    static OuiTable t;
    return t;
}

// Strips '-' and ':' separators from a MAC and uppercases the hex chars.
// Returns empty if the result isn't exactly 12 hex digits.
std::string normaliseMac(const std::wstring& mac) {
    std::string out;
    out.reserve(12);
    for (wchar_t wc : mac) {
        if (wc == L'-' || wc == L':' || wc == L' ') continue;
        if (wc > 127) return {};
        char c = static_cast<char>(wc);
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return {};
        out.push_back(c);
        if (out.size() > 12) return {};
    }
    if (out.size() != 12) return {};
    return out;
}

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    int needed = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                       nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                          out.data(), needed);
    return out;
}

} // anonymous namespace

std::wstring VendorResolver::lookup(const std::wstring& mac) {
    auto canon = normaliseMac(mac);
    if (canon.empty()) return {};

    auto& m = table().map;

    // Try longest-prefix-first: 9-char (36-bit) → 7-char (28-bit) → 6-char (24-bit).
    static constexpr size_t kWidths[] = { 9, 7, 6 };
    for (size_t w : kWidths) {
        if (canon.size() < w) continue;
        auto it = m.find(canon.substr(0, w));
        if (it != m.end()) {
            return widen(it->second);
        }
    }
    return {};
}

} // namespace lanscope
