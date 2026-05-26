#pragma once

#include "../AppConstants.h"
#include "../Models.h"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace lanscope {

/// Lightweight, non-authenticated service fingerprinting.
///
/// This module identifies common exposed services from their *standard*
/// protocol greeting, banner or response headers — nothing more. It performs
/// **no** vulnerability checks, exploit attempts, brute force, credential
/// testing, capability enumeration or aggressive probing. Every probe is a
/// single, timeout-bounded handshake that any healthy service answers on its
/// own. All network input is treated as hostile: strings are sanitised and
/// length-capped, parsing is fail-closed, malformed packets yield no
/// fingerprint rather than a crash.
///
/// Static API, consistent with the other core probe modules (PingService,
/// PortScanner). Winsock must already be initialised (main.cpp does this).
class ServiceFingerprinter {
public:
    struct Options {
        int  timeoutMs       = kDefaultFingerprintTimeoutMs;
        bool enableHttp      = true;   ///< HTTP HEAD on 80/8080/8000/8888
        bool enableTls       = true;   ///< HTTPS HEAD (WinHTTP) on 443/8443
        bool enableTcpBanners= true;   ///< SSH/FTP/SMTP greeting banners
        bool enableDatabases = true;   ///< MySQL handshake / MSSQL TDS prelogin
    };

    /// Fingerprints the *open* TCP ports of a single online host. Closed
    /// ports are skipped; ports without a known probe are skipped. Honours
    /// `cancel` between ports so a stopped scan unwinds promptly.
    static std::vector<ServiceFingerprint> fingerprintTcpServices(
        const std::wstring& ip,
        const std::vector<PortStatus>& openPorts,
        const Options& options,
        const std::atomic<bool>& cancel);

    /// SQL Server Browser probe — one 0x02 byte to UDP 1434. Returns a single
    /// "mssql-browser" fingerprint when a host answers, otherwise empty.
    static std::vector<ServiceFingerprint> queryMssqlBrowser(
        const std::wstring& ip, int timeoutMs);

    /// Standard NTP client query to UDP 123. `responded` is false for the
    /// common case of a host that is not an NTP server (normal, not an error).
    static ClockDriftInfo queryNtpClock(const std::wstring& ip, int timeoutMs);

    /// Windows Time-of-Day via the `NetRemoteTOD` API — the same read-only,
    /// anonymous call `net time \\host` makes over SMB. Fills the gap NTP
    /// leaves on Windows clients, which answer this even though they run no
    /// NTP server. `NetRemoteTOD` has no timeout parameter, so the call is run
    /// on a worker thread and abandoned if it overruns `timeoutMs`. Callers
    /// should only invoke this when TCP 445 is open on the host.
    static ClockDriftInfo queryWindowsTimeOfDay(const std::wstring& ip,
                                                int timeoutMs);

    /// Result of queryWindowsServerInfo: the "windows" service fingerprint plus
    /// the host's SMB/NetBIOS computer name. The name doubles as a hostname
    /// fallback for when reverse DNS can't resolve the host — common when the
    /// scanning machine's upstream resolver is public (e.g. 8.8.8.8) and has
    /// no private PTR records.
    struct WindowsServerInfo {
        ServiceFingerprint fingerprint;   ///< fingerprint.port == 0 when no answer
        std::wstring       computerName;  ///< SMB computer name, or empty
    };

    /// Windows version + computer name via the `NetServerGetInfo` API — a
    /// read-only, anonymous SMB call on the same surface as
    /// queryWindowsTimeOfDay. Runs on an abandonable worker thread. Callers
    /// should only invoke this when TCP 445 is open on the host.
    static WindowsServerInfo queryWindowsServerInfo(const std::wstring& ip,
                                                    int timeoutMs);

    /// This machine's own computer name (`GetComputerName`) — a local, instant,
    /// network-free hostname source, used as the fallback for the scanning host
    /// itself (which the SMB probes deliberately skip).
    static std::wstring localComputerName();

    /// Apple-specific device-class probe. The visible TCP services on an
    /// Apple-vendored host usually can't distinguish iPhone / iPad from Mac
    /// from Apple TV from HomePod — Apple ships with most services off by
    /// default. This probe combines three out-of-band TCP signals (lockdownd
    /// on 62078 for iOS sync, AirPlay on 7000, DAAP on 3689 for Apple TV)
    /// with a single unicast mDNS query to UDP 5353 asking for the host's
    /// advertised Bonjour service types. Returns a synthesised "apple"
    /// fingerprint whose `product` is the inferred class ("iPhone / iPad",
    /// "Mac", "Apple TV", "HomePod", "AirPlay receiver" or "Apple device").
    /// `port` stays 0 — and the caller drops the fingerprint — when nothing
    /// answered, so the existing vendor-only fallback in DeviceClassifier
    /// still kicks in. Caller invokes this only for vendor=Apple hosts.
    static ServiceFingerprint queryAppleDeviceInfo(const std::wstring& ip,
                                                   int timeoutMs);

    /// NetBIOS Name Service node-status query (UDP 137). Returns the
    /// host's NetBIOS computer name when it answers, empty string otherwise.
    /// Works on every Windows host running the Server / Workstation service
    /// and on Samba/Linux hosts running nmbd — including hosts that refuse
    /// our SMB probe (TCP 445) or report the IP address as their SMB name.
    /// The wire format is a 50-byte name-query packet asking for "*\0\0\0..."
    /// (the wildcard node-status query); the answer enumerates the host's
    /// registered NetBIOS names and we return the first unique <00> (i.e.
    /// "workstation") entry. Bounded, one packet each way.
    static std::wstring queryNbnsName(const std::wstring& ip, int timeoutMs);

    /// Unicast mDNS reverse-DNS query (UDP 5353). Asks the host for the PTR
    /// record of its own `<reverse-ip>.in-addr.arpa.` name. Apple devices,
    /// Linux hosts running Avahi, and most printer / NAS / IoT firmware that
    /// ships Bonjour answer this even when traditional reverse DNS can't
    /// resolve them (typical when the scanner's upstream resolver is public,
    /// e.g. 8.8.8.8). Returns the decoded .local hostname, or empty on no
    /// reply. Bounded, one packet each way.
    static std::wstring queryMdnsReverseName(const std::wstring& ip,
                                             int timeoutMs);

    /// Builds the "clock" ServiceFingerprint that accompanies a positive
    /// ClockDriftInfo, from either the NTP or the net-time source. Caller
    /// checks `drift.responded` first.
    static ServiceFingerprint clockDriftFingerprint(const ClockDriftInfo& drift);
};

} // namespace lanscope
