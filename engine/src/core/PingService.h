#pragma once

#include <atomic>
#include <cstdint>

namespace lanscope {

/// Wraps IcmpSendEcho. Single-shot, thread-safe (each call owns its handle).
class PingService {
public:
    struct Result {
        bool    success     = false;
        int64_t roundTripMs = 0;
    };

    /// Sends one ICMP echo to the given host-order IPv4 address.
    /// Returns success=false on any failure; never throws.
    ///
    /// Uses a thread_local IcmpFile handle so workers reuse the same handle
    /// across many pings instead of paying the create/close cost per call.
    /// `cancel` (optional) is checked between the two ICMP attempts so a
    /// scan-wide Stop doesn't pay the full second-attempt timeout per host.
    static Result ping(uint32_t hostOrderIp, int timeoutMs,
                       const std::atomic<bool>* cancel = nullptr);
};

} // namespace lanscope
