#pragma once

#include "../Models.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

namespace netlens {

/// Probes a small set of TCP ports on a single host with a per-port timeout.
///
/// Implementation: non-blocking connect() + select() with a struct timeval.
/// All failures (refused, timeout, unreachable) map to closed; the only thing
/// that aborts mid-probe is the caller's cancel flag.
class PortScanner {
public:
    /// Fired after a batch where at least one new open port was discovered.
    /// Receives a view of the current open-only port list (sorted in scan
    /// order). The scanner uses this to push partial results to the GUI so a
    /// long All-Ports sweep shows services as they're found, not only at the
    /// end. Must be thread-safe.
    using OpenPortsCallback = std::function<void(const std::vector<PortStatus>&)>;

    /// Probe ports on the given host. Returns a PortStatus per requested port,
    /// in the same order. Calls into Winsock; WSAStartup must already be done.
    ///
    /// If `probesDone` is non-null, it is atomically incremented after each
    /// port is fully resolved (open / closed / unreachable). The scanner uses
    /// this to drive a global work-progress % across all in-flight workers.
    ///
    /// If `onOpenPorts` is non-empty, it is called after each batch where a
    /// new open port has been discovered, with the running open-ports list.
    static std::vector<PortStatus> scanHost(
        uint32_t hostOrderIp,
        const std::vector<int>& ports,
        int timeoutMs,
        const std::atomic<bool>& cancel,
        std::atomic<int64_t>* probesDone = nullptr,
        const OpenPortsCallback& onOpenPorts = {});
};

} // namespace netlens
