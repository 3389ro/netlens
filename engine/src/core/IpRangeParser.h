#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lanscope {

/// Expands user-typed IP-range expressions into a concrete list of addresses.
/// Supports:
///   - "192.168.1.10"                 (single host)
///   - "192.168.1.1-254"              (last-octet range)
///   - "192.168.1.10-192.168.1.50"    (full IP range)
///   - "192.168.1.0/24"               (CIDR)
class IpRangeParser {
public:
    struct Result {
        bool                  ok           = false;
        std::wstring          error;
        std::vector<uint32_t> addresses;   ///< host-order uint32 IPv4
    };

    /// allowLarge=false applies the kMaxRangeWithoutFlag ceiling;
    /// allowLarge=true raises it to ~4B (still bounded by uint32_t arithmetic).
    static Result parse(const std::wstring& input, bool allowLarge = false);
};

} // namespace lanscope
