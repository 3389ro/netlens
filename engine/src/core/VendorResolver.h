#pragma once

#include <string>

namespace lanscope {

/// Resolves a MAC address to a vendor name using the embedded Nmap OUI database.
///
/// The database supports three prefix widths — 24, 28 and 36 bits — and we
/// try them longest-first so newer MA-S/MA-M assignments win over the legacy
/// 24-bit blanket entries.
///
/// The first call lazily parses the embedded blob into a hash table; later
/// calls are O(1). Thread-safe.
class VendorResolver {
public:
    /// @param mac  MAC address in "AA-BB-CC-DD-EE-FF" form (case-insensitive;
    ///             separators "-" or ":" are both accepted; lowercase ok).
    /// @return     Vendor name or empty string if not found / unparseable.
    static std::wstring lookup(const std::wstring& mac);
};

} // namespace lanscope
