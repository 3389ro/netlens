#include "MacResolver.h"

#include "IpAddressUtils.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

namespace netlens {

std::wstring MacResolver::resolve(uint32_t hostOrderIp) {
    // SendARP expects the IP in network byte order as an IPAddr (ULONG).
    IPAddr dest = htonl(hostOrderIp);

    ULONG       mac[2]   = {0, 0};      // 8 bytes (MAC + padding for alignment)
    ULONG       macLen   = 6;

    DWORD rc = ::SendARP(dest, 0, mac, &macLen);
    if (rc != NO_ERROR || macLen < 6) return L"";

    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(mac);

    // 00:00:00:00:00:00 means "not resolved" — don't surface that.
    bool allZero = true;
    for (int i = 0; i < 6; ++i) {
        if (bytes[i] != 0) { allZero = false; break; }
    }
    if (allZero) return L"";

    return ip::formatMac(bytes, 6);
}

} // namespace netlens
