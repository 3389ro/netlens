#pragma once

#include <cstdint>
#include <string>

namespace lanscope {

/// Localhost open-port → owning process resolution.
///
/// Uses `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)` to enumerate
/// every locally-listening TCP socket along with the owning PID, then
/// `QueryFullProcessImageNameW` (PROCESS_QUERY_LIMITED_INFORMATION) to
/// resolve each PID to its image path. No admin token required for the
/// table; per-PID resolution may be denied for SYSTEM / service processes
/// — in that case we return the canonical "needs admin" sentinel so the
/// pane can surface a meaningful note instead of an empty cell.
///
/// Called from `nl_scanner_get_port` when the result IP is one of the
/// adapters' own addresses (or 127.0.0.1). Internal cache keyed by
/// `(port, pid)` so repeated `get_port` calls during pane render don't
/// re-enumerate the OS table.
class LocalProcessResolver {
public:
    struct PortOwner {
        uint32_t      pid;        ///< 0 when the port has no listener
        std::wstring  exePath;    ///< full path, or empty
        std::wstring  errorNote;  ///< "needs admin", "System Idle", … when exePath is empty
    };

    /// Look up the owner of a TCP port on this machine. Returns `pid=0`
    /// when nothing listens on that port. Refreshes the internal TCP-table
    /// snapshot when it's older than the throttle window (~500 ms).
    static PortOwner lookup(int port);

    /// Force-clear the cache (e.g. between scans). Safe to call from any
    /// thread.
    static void resetCache();

    /// True if `ip` matches one of this machine's IPv4 adapter addresses
    /// (or the IPv4 loopback). Caches the adapter list with ~5 s TTL so
    /// scanning a /24 doesn't call `GetAdaptersAddresses` 254 times.
    static bool isLocalIp(const std::wstring& ip);
};

} // namespace lanscope
