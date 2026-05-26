#pragma once

#include <cstdint>
#include <string>

namespace lanscope {

/// Resolves an IPv4's MAC via SendARP. Works only on the local broadcast
/// domain — devices behind routers return an empty string.
class MacResolver {
public:
    static std::wstring resolve(uint32_t hostOrderIp);
};

} // namespace lanscope
