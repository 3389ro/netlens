#ifndef NETLENS_UDP_DISCOVERY_SERVICE_H
#define NETLENS_UDP_DISCOVERY_SERVICE_H

#include <atomic>
#include <cstdint>
#include <string>

namespace lanscope {

// Defensive UDP discovery (NOT a generic UDP port scanner).
//
// Fires a small fixed set of targeted UDP probes at a single host, all
// in parallel via one select() loop with a global time budget. Designed
// to surface info that TCP-only scanning can't see:
//   - NBNS UDP/137         → NetBIOS name + workgroup
//   - NTP  UDP/123         → server version + stratum
//   - SSDP UDP/1900        → unicast M-SEARCH, Server header
//   - mDNS UDP/5353        → Apple / Bonjour devices
//   - SQL Browser UDP/1434 → MSSQL instance metadata
//   - DNS  UDP/53          → version.bind chaos record
//   - LLMNR UDP/5355       → multicast name resolution (Vista+)
//   - IPMI UDP/623         → RMCP/ASF Ping/Pong (BMCs)
//
// Each probe either responds or it doesn't — the caller never sees
// "open / closed" semantics (that vocabulary belongs to TCP). A
// missing response means "no answer in budget" — could be the port
// is genuinely silent, or filtered, or the budget was too tight.
//
// Returns a multi-line tab-separated table of responses:
//   "<port>\t<service>\t<detail>\r\n..."
// Empty string when no probe got a response. The tab/CRLF format
// lets the UI parse it back into a 3-column (port / service / detail)
// table without a separate side-channel.
class UdpDiscoveryService {
public:
    static std::wstring discover(uint32_t hostOrderIp,
                                  int timeoutMs,
                                  const std::atomic<bool>& cancel);
};

} // namespace lanscope

#endif // NETLENS_UDP_DISCOVERY_SERVICE_H
