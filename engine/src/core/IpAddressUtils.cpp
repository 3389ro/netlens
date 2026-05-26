#include "IpAddressUtils.h"

#include <cstdio>
#include <cstdlib>
#include <cwchar>

namespace lanscope::ip {

namespace {

template <typename CharT>
std::optional<uint32_t> parseImpl(const std::basic_string<CharT>& s) {
    // Strict dotted-decimal: exactly four 0-255 octets separated by '.'.
    uint32_t octets[4]{};
    int      idx = 0;
    int      digits = 0;
    int      value = 0;

    for (size_t i = 0; i < s.size(); ++i) {
        CharT c = s[i];
        if (c >= static_cast<CharT>('0') && c <= static_cast<CharT>('9')) {
            value = value * 10 + (c - static_cast<CharT>('0'));
            ++digits;
            if (digits > 3 || value > 255) return std::nullopt;
        } else if (c == static_cast<CharT>('.')) {
            if (digits == 0) return std::nullopt;
            if (idx >= 3) return std::nullopt;
            octets[idx++] = static_cast<uint32_t>(value);
            value = 0;
            digits = 0;
        } else {
            return std::nullopt;
        }
    }

    if (idx != 3 || digits == 0) return std::nullopt;
    octets[3] = static_cast<uint32_t>(value);

    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
}

} // anonymous namespace

std::optional<uint32_t> parseDotted(const std::wstring& s) { return parseImpl(s); }
std::optional<uint32_t> parseDotted(const std::string&  s) { return parseImpl(s); }

std::wstring formatDotted(uint32_t hostOrder) {
    wchar_t buf[32];
    std::swprintf(buf, 32, L"%u.%u.%u.%u",
                  (hostOrder >> 24) & 0xFFu,
                  (hostOrder >> 16) & 0xFFu,
                  (hostOrder >> 8)  & 0xFFu,
                  hostOrder & 0xFFu);
    return std::wstring(buf);
}

uint32_t prefixToMask(int prefix) {
    if (prefix < 0 || prefix > 32) return 0;
    if (prefix == 0)  return 0;
    if (prefix == 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - prefix);
}

std::optional<int> maskToPrefix(uint32_t mask) {
    // A valid IPv4 mask is a sequence of 1s followed by 0s.
    int ones = 0;
    bool seenZero = false;
    for (int i = 31; i >= 0; --i) {
        bool bit = ((mask >> i) & 1u) != 0;
        if (bit) {
            if (seenZero) return std::nullopt;
            ++ones;
        } else {
            seenZero = true;
        }
    }
    return ones;
}

uint32_t networkAddress(uint32_t hostOrderIp, uint32_t hostOrderMask) {
    return hostOrderIp & hostOrderMask;
}

uint32_t broadcastAddress(uint32_t hostOrderIp, uint32_t hostOrderMask) {
    return (hostOrderIp & hostOrderMask) | ~hostOrderMask;
}

std::wstring formatMac(const uint8_t* bytes, size_t len) {
    if (!bytes || len < 6) return L"";
    wchar_t buf[24];
    std::swprintf(buf, 24, L"%02X-%02X-%02X-%02X-%02X-%02X",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    return std::wstring(buf);
}

} // namespace lanscope::ip
