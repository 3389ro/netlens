#pragma once

#include "../Models.h"

#include <vector>

namespace netlens {

/// Enumerates active IPv4 network adapters via the Windows IP Helper API.
class NetworkAdapterService {
public:
    /// Returns the list of usable adapters.
    ///
    /// Filtering rules:
    ///   - Loopback and tunnel interfaces are excluded.
    ///   - Adapters without an IPv4 address are excluded.
    ///   - APIPA (169.254.0.0/16) is excluded UNLESS no other adapter exists.
    ///   - Adapters with IfOperStatusUp come first.
    ///
    /// Sorted: operational first, then by friendly name.
    static std::vector<NetworkAdapter> enumerate();
};

} // namespace netlens
