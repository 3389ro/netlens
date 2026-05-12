#pragma once

#include <cstdint>

namespace netlens {

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
    static Result ping(uint32_t hostOrderIp, int timeoutMs);
};

} // namespace netlens
