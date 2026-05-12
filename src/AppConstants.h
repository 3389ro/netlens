#pragma once

#include <string>

namespace netlens {

// -----------------------------------------------------------------------------
// Application-wide constants. Centralised so build/version bumps touch one file.
// -----------------------------------------------------------------------------

constexpr const wchar_t* kAppName        = L"NetLens";
constexpr const wchar_t* kAppSubtitle    = L"Portable LAN Scanner for Small Business Networks";
constexpr const wchar_t* kAppVersion     = L"1.2.0";
constexpr const wchar_t* kAppCompany     = L"3389.ro";
constexpr const wchar_t* kAppExecName    = L"NetLens.exe";

// v1.0.1 tuning: 400 ms / 256 threads. Most modern LANs (switched gigabit)
// and the user's box (32 cores, 128 GB) handle this without breaking a sweat,
// and the All-Ports preset becomes usable. Lower it in Settings if a target
// network is rate-limiting probes.
constexpr int kDefaultTimeoutMs    = 400;
constexpr int kDefaultParallel     = 256;

constexpr int kMinTimeoutMs        = 50;
constexpr int kMaxTimeoutMs        = 10'000;
constexpr int kMinParallel         = 1;
// Hard upper bound on worker count. v1.0.7: lowered 2048→1024. Rationale:
//   - 2048 worked fine on a 32-core/128 GB box, but in the wild it trips
//     consumer router rate-limiting, soft-floods SMB switches, and pegs
//     home-grade endpoint AV (Defender included) as "scanner activity";
//   - 1024 is still aggressive enough that a /16 sweep on a 16-core box
//     finishes in minutes, and the engine clamps to host-count anyway;
//   - users on workstation-class kit can tune higher via the Settings
//     dialog, but the default ceiling protects everyone else.
constexpr int kMaxParallel         = 1024;

// Hard ceiling on a single scan, unless --allow-large-range is provided.
constexpr int kMaxRangeWithoutFlag = 65'535;
// Threshold above which we display a warning in the adapter info label.
constexpr int kLargeRangeWarnAbove = 1024;

// Exit codes for CLI mode.
constexpr int kExitOk              = 0;
constexpr int kExitInvalidArgs     = 1;
constexpr int kExitScanError       = 2;
constexpr int kExitExportError     = 3;

// Discovery probe used by Fast mode when ICMP fails. The goal is "is this host
// alive at all?" — not a full port audit. We broaden beyond the original 4
// ports because a fair number of real-world devices (printers, NAS, IoT,
// network gear, mail servers, network shares) deliberately drop ICMP yet still
// answer one of the common TCP services. False-offline rate on a mixed LAN
// drops noticeably with this set; offline-host cost only goes up a single
// timeout window thanks to the batched select() in PortScanner.
inline constexpr int kFastDiscoveryPorts[] = {
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    110,   // POP3
    139,   // NetBIOS
    143,   // IMAP
    443,   // HTTPS
    445,   // SMB
    554,   // RTSP (IP cameras)
    631,   // IPP (printers)
    993,   // IMAPS
    1723,  // PPTP VPN
    3389,  // RDP
    5985,  // WinRM
    8080,  // HTTP-alt
    8443,  // HTTPS-alt
    9100   // Raw print (HP JetDirect)
};

// GUI batches result updates on a timer rather than reacting to every host.
constexpr int kUiFlushIntervalMs   = 150;

} // namespace netlens
