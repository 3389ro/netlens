#pragma once

#include "../Models.h"

#include <atomic>
#include <cstdint>

namespace netlens {

/// Service-specific UDP probes on the six high-signal "discovery" ports.
/// Unlike a generalist UDP port scanner (which can only report
/// closed-or-open-or-filtered ambiguity), each probe here speaks the actual
/// service protocol and only reports a positive result when the matching
/// service replies with real data.
///
/// Ports probed (per call, in parallel on connected UDP sockets):
///     137  NetBIOS Name Service     NBSTAT query for "*"   -> computer name + workgroup
///     5353 multicast DNS (unicast)  DNS-SD service catalogue -> service list
///     1900 SSDP / UPnP              M-SEARCH ssdp:all      -> Server, Location headers
///     161  SNMPv1 (community public) GET sysDescr.0        -> system description
///     53   DNS                      version.bind CHAOS TXT -> server version string
///     123  NTP                      v4 client request      -> stratum, refid
///
/// The six sockets share a single `select()` timeout window, so the wall
/// cost per host is one timeout regardless of how many of the six services
/// actually respond. Closed UDP ports surface as `WSAECONNRESET` on `recv()`
/// (Windows reports ICMP Unreachable through that errno on connected UDP
/// sockets) — we treat that as "service absent" and move on.
///
/// Privileges: none required. All sockets are plain SOCK_DGRAM.
class UdpProbes {
public:
    /// Probe `hostIp` with the six service queries and return the aggregated
    /// findings. Cooperatively cancellable via `cancel`. `probesDone` (if
    /// non-null) is incremented by one for each issued probe; the GUI's
    /// progress counter can use this just like the TCP probe counter.
    static UdpServiceInfo probe(uint32_t hostIp,
                                int timeoutMs,
                                const std::atomic<bool>& cancel,
                                std::atomic<int64_t>* probesDone = nullptr);

    /// Returns the number of probes issued per host (6). Useful for the
    /// progress denominator so the % bar reflects the UDP cost as well.
    [[nodiscard]] static constexpr int probesPerHost() { return 6; }
};

} // namespace netlens
