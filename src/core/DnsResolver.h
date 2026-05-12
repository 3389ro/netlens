#pragma once

#include <cstdint>
#include <string>

namespace netlens {

/// Reverse-DNS lookup for IPv4. Failures map to empty string; never throws.
///
/// Implementation note: `GetNameInfoW` has no native timeout, and a single
/// slow PTR query can easily take 5 seconds (the OS resolver retries multiple
/// upstream servers). We therefore run the call on a detached thread and
/// give up after `timeoutMs` — the worker returns empty, the OS thread
/// continues in the background until it completes on its own.
///
/// This costs at most one extra OS thread per slow lookup, capped naturally by
/// the number of online hosts being processed (DNS is only invoked for online
/// hosts). On a /24 with 12 online hosts that's at most 12 stale threads.
///
/// v1.0.7: default timeout shortened 800→400 ms. 800 ms made big-LAN scans
/// chase ghost PTRs for half a minute when the resolver was misbehaving;
/// 400 ms is enough for any responsive corporate DNS and gives up fast on
/// the rest. The GUI also forces opts.skipDns=true on ranges > 1024 hosts
/// so this detached-thread fan-out doesn't grow without bound.
class DnsResolver {
public:
    /// @param timeoutMs  Hard cap in milliseconds. 0 or negative disables the
    ///                   cap (falls back to OS-native blocking behaviour).
    static std::wstring reverseLookup(uint32_t hostOrderIp, int timeoutMs = 400);
};

} // namespace netlens
