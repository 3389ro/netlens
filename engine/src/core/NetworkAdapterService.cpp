#include "NetworkAdapterService.h"

#include "IpAddressUtils.h"
#include "../AppConstants.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>
#include <memory>
#include <vector>

namespace lanscope {

namespace {

AdapterType classify(DWORD ifType) {
    switch (ifType) {
        case IF_TYPE_ETHERNET_CSMACD: return AdapterType::Ethernet;
        case IF_TYPE_IEEE80211:       return AdapterType::WiFi;
        case IF_TYPE_SOFTWARE_LOOPBACK:return AdapterType::Loopback;
        case IF_TYPE_TUNNEL:          return AdapterType::Tunnel;
        default:                      return AdapterType::Other;
    }
}

std::wstring labelForType(AdapterType t, const std::wstring& fallback) {
    switch (t) {
        case AdapterType::Ethernet: return L"Ethernet";
        case AdapterType::WiFi:     return L"Wi-Fi";
        case AdapterType::Loopback: return L"Loopback";
        case AdapterType::Tunnel:   return L"Tunnel";
        default:                    return fallback.empty() ? std::wstring(L"Other") : fallback;
    }
}

// Extract IPv4 + prefix from the linked list inside an adapter entry.
bool firstIPv4(const IP_ADAPTER_ADDRESSES* aa, uint32_t& outIp, int& outPrefix) {
    for (auto* u = aa->FirstUnicastAddress; u != nullptr; u = u->Next) {
        if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
            outIp = ntohl(sin->sin_addr.S_un.S_addr);
            outPrefix = static_cast<int>(u->OnLinkPrefixLength);
            if (outPrefix == 0 || outPrefix > 32) outPrefix = 24; // sane fallback
            return true;
        }
    }
    return false;
}

std::wstring firstIPv4Gateway(const IP_ADAPTER_ADDRESSES* aa) {
    for (auto* g = aa->FirstGatewayAddress; g != nullptr; g = g->Next) {
        if (g->Address.lpSockaddr && g->Address.lpSockaddr->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<const sockaddr_in*>(g->Address.lpSockaddr);
            return ip::formatDotted(ntohl(sin->sin_addr.S_un.S_addr));
        }
    }
    return L"";
}

std::wstring buildScanRange(uint32_t ip, int prefix) {
    if (prefix < 0 || prefix > 32) prefix = 24;
    uint32_t mask = ip::prefixToMask(prefix);
    uint32_t net  = ip::networkAddress(ip, mask);
    uint32_t bcast= ip::broadcastAddress(ip, mask);

    if (prefix >= 31) {
        // /31, /32 — just the host itself
        return ip::formatDotted(ip);
    }

    uint32_t first = net + 1;
    uint32_t last  = bcast - 1;

    if (last < first) return ip::formatDotted(ip);

    return ip::formatDotted(first) + L"-" + ip::formatDotted(last);
}

bool isApipa(uint32_t hostIp) {
    return (hostIp & 0xFFFF0000u) == 0xA9FE0000u; // 169.254.0.0/16
}

NetworkAdapter buildOne(const IP_ADAPTER_ADDRESSES* aa) {
    NetworkAdapter a;
    a.index       = aa->IfIndex;
    a.name        = aa->AdapterName ? std::wstring(aa->AdapterName,
                                                   aa->AdapterName + std::char_traits<char>::length(aa->AdapterName))
                                    : std::wstring();
    a.friendlyName= aa->FriendlyName  ? std::wstring(aa->FriendlyName)  : std::wstring();
    a.description = aa->Description   ? std::wstring(aa->Description)   : std::wstring();
    a.type        = classify(aa->IfType);
    a.operational = (aa->OperStatus == IfOperStatusUp);
    a.macAddress  = (aa->PhysicalAddressLength >= 6)
                    ? ip::formatMac(aa->PhysicalAddress, aa->PhysicalAddressLength)
                    : std::wstring();

    uint32_t hostIp = 0;
    int      prefix = 0;
    if (firstIPv4(aa, hostIp, prefix)) {
        uint32_t mask = ip::prefixToMask(prefix);
        a.ipv4              = ip::formatDotted(hostIp);
        a.prefixLength      = prefix;
        a.subnetMask        = ip::formatDotted(mask);
        a.gateway           = firstIPv4Gateway(aa);
        a.networkAddress    = ip::formatDotted(ip::networkAddress(hostIp, mask));
        a.broadcastAddress  = ip::formatDotted(ip::broadcastAddress(hostIp, mask));
        a.suggestedScanRange= buildScanRange(hostIp, prefix);
    }
    return a;
}

} // anonymous namespace

std::wstring NetworkAdapter::guiLine() const {
    // "1 - Ethernet - 192.168.1.50/24 - GW 192.168.1.1"
    std::wstring line;
    line += std::to_wstring(index);
    line += L" - ";
    line += labelForType(type, friendlyName);
    if (!friendlyName.empty() &&
        (type == AdapterType::WiFi || type == AdapterType::Ethernet) &&
        friendlyName != L"Ethernet" && friendlyName != L"Wi-Fi") {
        line += L" (" + friendlyName + L")";
    }
    if (!ipv4.empty()) {
        line += L" - " + ipv4;
        if (prefixLength > 0) {
            line += L"/" + std::to_wstring(prefixLength);
        }
    }
    if (!gateway.empty()) {
        line += L" - GW " + gateway;
    }
    if (!operational) {
        line += L"  [down]";
    }
    return line;
}

std::vector<NetworkAdapter> NetworkAdapterService::enumerate() {
    std::vector<NetworkAdapter> all;

    // Iterative buffer sizing — GetAdaptersAddresses tells us the required size.
    ULONG bufLen = 16 * 1024;
    std::unique_ptr<BYTE[]> buf(new BYTE[bufLen]);

    const ULONG flags =
        GAA_FLAG_INCLUDE_GATEWAYS |
        GAA_FLAG_SKIP_ANYCAST     |
        GAA_FLAG_SKIP_MULTICAST   |
        GAA_FLAG_SKIP_DNS_SERVER;

    ULONG result = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        result = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.get()),
                                      &bufLen);
        if (result == ERROR_BUFFER_OVERFLOW) {
            buf.reset(new BYTE[bufLen]);
        }
    }
    if (result != NO_ERROR) return all;

    auto* head = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.get());
    bool haveNonApipa = false;

    // First pass: collect everything that's not loopback/tunnel and has IPv4.
    for (auto* aa = head; aa; aa = aa->Next) {
        if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (aa->IfType == IF_TYPE_TUNNEL)            continue;

        NetworkAdapter a = buildOne(aa);
        if (a.ipv4.empty()) continue;

        uint32_t hostIp = ip::parseDotted(a.ipv4).value_or(0);
        if (!isApipa(hostIp)) haveNonApipa = true;
        all.push_back(std::move(a));
    }

    // Second pass: drop APIPA if we have at least one normal adapter.
    if (haveNonApipa) {
        all.erase(std::remove_if(all.begin(), all.end(), [](const NetworkAdapter& a) {
                      uint32_t hostIp = ip::parseDotted(a.ipv4).value_or(0);
                      return isApipa(hostIp);
                  }),
                  all.end());
    }

    // Sort: operational first, then by friendly name.
    std::stable_sort(all.begin(), all.end(), [](const NetworkAdapter& a, const NetworkAdapter& b) {
        if (a.operational != b.operational) return a.operational;
        return a.friendlyName < b.friendlyName;
    });

    return all;
}

} // namespace lanscope
