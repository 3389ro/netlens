#include "IpRangeParser.h"

#include "../AppConstants.h"
#include "IpAddressUtils.h"

#include <algorithm>
#include <cwctype>
#include <cstdlib>

namespace lanscope {

namespace {

std::wstring trim(std::wstring s) {
    auto notSpace = [](wchar_t c) { return !std::iswspace(static_cast<wint_t>(c)); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

bool tryParseOctet(const std::wstring& s, int& out) {
    if (s.empty() || s.size() > 3) return false;
    int v = 0;
    for (wchar_t c : s) {
        if (c < L'0' || c > L'9') return false;
        v = v * 10 + (c - L'0');
        if (v > 255) return false;
    }
    out = v;
    return true;
}

bool tryParsePrefix(const std::wstring& s, int& out) {
    if (s.empty() || s.size() > 2) return false;
    int v = 0;
    for (wchar_t c : s) {
        if (c < L'0' || c > L'9') return false;
        v = v * 10 + (c - L'0');
        if (v > 32) return false;
    }
    out = v;
    return true;
}

IpRangeParser::Result fail(const wchar_t* msg) {
    return IpRangeParser::Result{false, msg, {}};
}

bool exceedsLimit(uint64_t count, bool allowLarge) {
    const uint64_t cap = allowLarge ? 4'000'000ull : static_cast<uint64_t>(kMaxRangeWithoutFlag);
    return count > cap;
}

} // anonymous namespace

IpRangeParser::Result IpRangeParser::parse(const std::wstring& rawInput, bool allowLarge) {
    std::wstring input = trim(rawInput);
    if (input.empty()) return fail(L"Range is empty.");

    // ----- CIDR -----
    if (auto slash = input.find(L'/'); slash != std::wstring::npos) {
        std::wstring ipPart   = trim(input.substr(0, slash));
        std::wstring prefPart = trim(input.substr(slash + 1));

        auto base = ip::parseDotted(ipPart);
        int  prefix = 0;
        if (!base || !tryParsePrefix(prefPart, prefix)) {
            return fail(L"Invalid CIDR notation (expected a.b.c.d/n where 0<=n<=32).");
        }

        uint32_t mask      = ip::prefixToMask(prefix);
        uint32_t network   = ip::networkAddress(*base, mask);
        uint32_t broadcast = ip::broadcastAddress(*base, mask);

        // For /31 and /32 include all addresses; for wider blocks skip
        // network and broadcast which are not addressable hosts.
        uint32_t first = (prefix >= 31) ? network : network + 1;
        uint32_t last  = (prefix >= 31) ? broadcast : broadcast - 1;

        if (last < first) return fail(L"CIDR range expands to zero hosts.");
        uint64_t count = static_cast<uint64_t>(last - first) + 1;
        if (exceedsLimit(count, allowLarge)) {
            return fail(L"Range is too large. Use --allow-large-range to override (CLI only).");
        }

        Result r;
        r.ok = true;
        r.addresses.reserve(static_cast<size_t>(count));
        for (uint64_t v = first; v <= last; ++v) {
            r.addresses.push_back(static_cast<uint32_t>(v));
            if (v == 0xFFFFFFFFull) break;
        }
        return r;
    }

    // ----- Dash range -----
    if (auto dash = input.find(L'-'); dash != std::wstring::npos) {
        std::wstring leftStr  = trim(input.substr(0, dash));
        std::wstring rightStr = trim(input.substr(dash + 1));

        if (leftStr.empty() || rightStr.empty())
            return fail(L"Range is missing one of its endpoints.");

        auto leftIp = ip::parseDotted(leftStr);
        if (!leftIp) return fail(L"Range start is not a valid IPv4 address.");

        uint32_t startVal = *leftIp;
        uint32_t endVal   = 0;

        if (rightStr.find(L'.') != std::wstring::npos) {
            // Full IP on the right
            auto rightIp = ip::parseDotted(rightStr);
            if (!rightIp) return fail(L"Range end is not a valid IPv4 address.");
            endVal = *rightIp;
        } else {
            // Last-octet form
            int oct = 0;
            if (!tryParseOctet(rightStr, oct))
                return fail(L"Range end must be an octet 0-255 or a full IPv4 address.");
            endVal = (startVal & 0xFFFFFF00u) | static_cast<uint32_t>(oct);
        }

        if (endVal < startVal) return fail(L"Range end is lower than range start.");
        uint64_t count = static_cast<uint64_t>(endVal - startVal) + 1;
        if (exceedsLimit(count, allowLarge)) {
            return fail(L"Range is too large. Use --allow-large-range to override (CLI only).");
        }

        Result r;
        r.ok = true;
        r.addresses.reserve(static_cast<size_t>(count));
        for (uint64_t v = startVal; v <= endVal; ++v) {
            r.addresses.push_back(static_cast<uint32_t>(v));
            if (v == 0xFFFFFFFFull) break;
        }
        return r;
    }

    // ----- Single host -----
    auto single = ip::parseDotted(input);
    if (!single) return fail(L"Not a valid IPv4 address or range.");

    Result r;
    r.ok = true;
    r.addresses.push_back(*single);
    return r;
}

} // namespace lanscope
