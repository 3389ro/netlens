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

    /// v1.4.5 — Enumerate the SMB shares a host exposes, via the anonymous
    /// `NetShareEnum` RPC (the same call `net view \\host` makes). Read-only
    /// reconnaissance — lists share NAMES/types/remarks only, never touches
    /// file contents and uses no credentials. Returns one TAB-encoded line per
    /// share: `"<netname>\t<type>\t<remark>"`, where type is "Disk" /
    /// "Printer" / "Device" (suffixed "(hidden)" for the admin/special `$`
    /// shares). The IPC$ pipe share is filtered out. Empty when the host
    /// blocks anonymous enumeration (modern Windows default) — NAS boxes and
    /// Samba/older servers usually allow it. Runs on an abandonable worker
    /// thread (NetShareEnum has no timeout), so a stuck RPC never stalls the
    /// scan. Caller should only invoke when TCP 445 is open.
    static std::vector<std::wstring> queryShares(const std::wstring& ip,
                                                 int timeoutMs);

    /// Raw SMB protocol-level dialect probe over TCP 445. Walks the
    /// whole SMB family (SMB1 LANMAN dialects through SMB 3.1.1) and
    /// reports the highest dialect the server actually picks. Works
    /// across IPSEC site-to-site tunnels and other routed paths where
    /// `NetServerGetInfo` silently fails (the Windows networking stack
    /// bakes an NBNS broadcast into its name-resolution step that
    /// doesn't traverse the tunnel).
    ///
    /// Probe order:
    ///   1. SMB2 NEGOTIATE with dialects 0x0202..0x0311 + Negotiate
    ///      Contexts (preauth integrity + encryption capabilities).
    ///      Modern Windows hosts pick 0x0311; older boxes downgrade.
    ///   2. If SMB2 NEGOTIATE was rejected (e.g. SMB2-disabled host),
    ///      fall back to SMB1 SMB_COM_NEGOTIATE offering ten classic
    ///      dialect strings and read the selected dialect index back.
    ///
    /// The fingerprint focuses on the SMB version itself
    /// (`product=SMB`, `version=3.1.1` / `2.0.2` / `1.0 (NT LM 0.12)`
    /// etc.). The detail string carries the dialect name + a coarse
    /// Windows-version hint as supplementary info, NOT as the primary
    /// payload. Callers should only invoke this when TCP 445 is open.
    static ServiceFingerprint queryWindowsSmbDialect(const std::wstring& ip,
                                                     int timeoutMs);

    /// v1.4.1 — Zebra label/barcode printers rarely populate the standard
    /// Printer-MIB (prtMarkerSupplies / prtMarkerLifeCount), but every modern
    /// Zebra speaks SGD (Set-Get-Do) over raw TCP 9100. We send a small batch
    /// of `! U1 getvar "..."` queries and parse the quoted replies. This is
    /// the Zebra-native way to read firmware, model, and the lifetime label /
    /// print-length odometer — and it works even when SNMP is disabled or
    /// locked to a non-default community. ONLY call this for a host already
    /// confirmed to be Zebra (vendor / OUI / sysDescr), because the SGD bytes
    /// would otherwise be interpreted as a print job by a non-Zebra 9100.
    struct ZebraStatus {
        bool         responded  = false;
        std::wstring firmware;     ///< appl.name (e.g. "V72.20.04Z")
        std::wstring model;        ///< device.product_name (e.g. "ZT411-203dpi")
        int64_t      labelCount = -1;   ///< odometer.total_label_count
        std::wstring printLength;  ///< odometer.total_print_length (with units)
    };
    static ZebraStatus queryZebraStatus(const std::wstring& ip, int timeoutMs);

    /// v1.5.0 — Xiaomi miIO discovery "hello" on UDP 54321. Defensive
    /// inventory only: sends the well-known 32-byte handshake and parses the
    /// reply. Reveals the device id and a stamp/timestamp WITHOUT a token; on
    /// very old / unprovisioned firmware the last 16 bytes leak the device
    /// token (we flag that as a finding but never use it to send commands).
    /// Model / firmware are NOT obtainable here — they require an
    /// authenticated miIO.info call with the real token. Newer Roborock
    /// devices abandoned miIO for an encrypted protocol on TCP 58867 and will
    /// simply not respond (responded == false). No control commands are ever
    /// sent.
    struct MiioHello {
        bool         responded    = false;
        uint32_t     deviceId     = 0;
        uint32_t     stamp        = 0;
        bool         tokenExposed = false;  // last 16 bytes not all 0xFF / 0x00
        std::wstring tokenHex;              // populated only when exposed
    };
    static MiioHello queryMiioHello(const std::wstring& ip, int timeoutMs);

    /// v1.5.0 — single dedicated TCP connect check, timeout-bounded. Used to
    /// confirm a port the parallel scan may have missed (IoT devices with tiny
    /// TCP stacks often drop the fast sweep's short-timeout probes). Connect
    /// only — sends nothing, closes immediately.
    static bool tcpConnectable(const std::wstring& ip, int port, int timeoutMs);

    /// v1.5.5 — Is `s` shaped like a Ubiquiti/UniFi model SKU (e.g. "U6-LR",
    /// "UAP-AC-Pro", "USW-24-PoE", "UDM-Pro")? Fail-closed: a string with a
    /// space or without a known UniFi family prefix is NOT a model. Used to
    /// (a) trust a device's self-reported hostname as its model — UniFi sets
    /// the default hostname to the SKU — and (b) keep that SKU out of the
    /// Hostname column, where it would masquerade as a network name.
    static bool looksLikeUnifiModel(const std::wstring& s);

    /// v1.5.1 — Ubiquiti UBNT Discovery on UDP 10001 (read-only inventory).
    /// Sends the 4-byte v1 discovery request and parses the TLV reply, which
    /// (when the device answers — typically unadopted UniFi gear and UniFi
    /// controllers) exposes model code, firmware, hostname and uptime WITHOUT
    /// authentication. Adopted UniFi devices often stay silent (responded ==
    /// false) — their model/firmware then need authenticated SSH or SNMP.
    struct UbntInfo {
        bool         responded = false;
        std::wstring modelCode;   // e.g. "U7PG2"
        std::wstring modelName;   // friendly, mapped or device-reported
        std::wstring firmware;    // e.g. "BZ.qca956x.v3.7.58..."
        std::wstring hostname;
        uint32_t     uptime = 0;  // seconds
    };
    static UbntInfo queryUbntDiscovery(const std::wstring& ip, int timeoutMs);

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
