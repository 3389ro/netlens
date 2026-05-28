#include "NetworkScanner.h"

#include "../AppConstants.h"
#include "DeviceClassifier.h"
#include "DnsResolver.h"
#include "EnrichmentEngine.h"
#include "IpAddressUtils.h"
#include "MacResolver.h"
#include "NetworkAdapterService.h"
#include "PingService.h"
#include "PortScanner.h"
#include "RiskAnalyzer.h"
#include "SecurityAdvisor.h"
#include "PrinterSnmpScanner.h"
#include "ServiceFingerprinter.h"
#include "Stopwatch.h"
#include "UdpDiscoveryService.h"
#include "VendorResolver.h"
#include "WebUiProbe.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <deque>
#include <exception>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ServiceDetector is still in the codebase but no longer used here — the
// PortScanner already labels every probed port on the way out. Including the
// header would add nothing.
//
// ThreadPool is also no longer used by the scanner. We now run a fixed-size
// pool of std::thread workers that pull work via a lock-free atomic index
// (one fetch_add per host) instead of allocating a packaged_task/future per
// IP. This trims ~1 µs of bookkeeping per host and removes the queue-mutex
// from the inner loop.

namespace lanscope {

// =============================================================================
// Pimpl — just the cancel flag and the driver thread handle.
// =============================================================================

struct NetworkScanner::Impl {
    std::atomic<bool>            cancel{false};
    std::unique_ptr<std::thread> driver;
};

NetworkScanner::NetworkScanner() : impl_(std::make_unique<Impl>()) {}

NetworkScanner::~NetworkScanner() {
    cancel();
    if (impl_->driver && impl_->driver->joinable()) {
        impl_->driver->join();
    }
}

void NetworkScanner::cancel() {
    impl_->cancel.store(true);
}

namespace {

// =============================================================================
// Local helpers
// =============================================================================

std::wstring nowLocalStamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto tt  = system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &tt);
    wchar_t buf[32];
    std::wcsftime(buf, 32, L"%Y-%m-%d %H:%M:%S", &tm);
    return std::wstring(buf);
}

bool anyPortOpen(const std::vector<PortStatus>& ports) {
    for (const auto& p : ports) if (p.isOpen) return true;
    return false;
}

const std::vector<int>& fastDiscoveryPorts() {
    static const std::vector<int> kPorts(std::begin(kFastDiscoveryPorts),
                                         std::end(kFastDiscoveryPorts));
    return kPorts;
}

// True when `hostIp` (host byte order) belongs to the machine running the
// scan — loopback, or one of this box's own adapter IPv4 addresses. The
// net-time clock-drift probe skips these: querying our own clock for "drift"
// is meaningless (the offset is always ~0). Adapter IPs are enumerated once.
bool isLocalHost(uint32_t hostIp) {
    if ((hostIp & 0xFF000000u) == 0x7F000000u) return true;   // 127.0.0.0/8
    static const std::vector<uint32_t> kLocalIps = [] {
        std::vector<uint32_t> v;
        for (const auto& a : NetworkAdapterService::enumerate()) {
            if (auto parsed = ip::parseDotted(a.ipv4)) v.push_back(*parsed);
        }
        return v;
    }();
    for (uint32_t local : kLocalIps) {
        if (local == hostIp) return true;
    }
    return false;
}

// =============================================================================
// Per-host pipeline.
//
//   Fast (default)
//     - ICMP ping
//     - online? → full TCP scan + DNS + MAC + vendor
//     - silent? → probe 4 discovery ports
//                  any open? → mark online via TCP fallback + DNS + MAC + vendor
//                  all closed? → mark offline. No further work.
//
//   Deep
//     - ICMP ping
//     - online? → full TCP scan + DNS + MAC + vendor
//     - silent? → full TCP scan against configured port list
//                  any open? → mark online via TCP fallback + DNS + MAC + vendor
//                  all closed? → mark offline.
//
//   DiscoveryOnly
//     - ICMP ping (no TCP at all)
//     - online? → DNS + MAC + vendor
//     - silent? → mark offline.
//
//   DNS / MAC / vendor only run when the host is considered online, which is
//   the biggest per-host perf win on a /24 with mostly absent hosts.
//
//   This function MUST be exception-safe — the worker loop relies on it not
//   throwing. All sub-calls already return error states instead of throwing,
//   but we keep a defensive outer try in the worker just in case.
// =============================================================================
ScanResult scanOneHost(uint32_t hostIp,
                       const ScanOptions& opts,
                       const std::atomic<bool>& cancel,
                       const NetworkScanner::HostCallback& onEarly,
                       std::atomic<int64_t>* probesDone)
{
    ScanResult r;
    r.ipAddress    = ip::formatDotted(hostIp);
    r.adapterLabel = opts.adapterLabel;

    // Helper that pushes the current state of r to the GUI. Wrapped so a
    // throwing callback can never take the scan down.
    auto emit = [&]() {
        if (onEarly) {
            try { onEarly(r); } catch (...) {}
        }
    };

    // ---- 1) ICMP ping ----
    if (!cancel.load(std::memory_order_relaxed)) {
        auto p = PingService::ping(hostIp, opts.timeoutMs, &cancel);
        if (p.success) {
            r.isOnline       = true;
            r.responseTimeMs = p.roundTripMs;
            r.discovery      = DiscoveryMethod::Icmp;
        }
    }

    // ---- 1b) ARP fallback ----------------------------------------------
    // ICMP-silent hosts are common on real LANs:
    //   • Cisco IP phones drop ICMP echo but answer SCCP / SIP.
    //   • Hardened Windows boxes ship with Windows Firewall blocking
    //     ICMP-in by default.
    //   • Many IoT devices (Daikin AC, Sonos, Shelly, …) ignore ping.
    //
    // ARP works for any Ethernet host on the same broadcast domain
    // regardless of ICMP/firewall behaviour — the host must answer
    // ARP for the gateway to route traffic to/from it. We piggy-back
    // on the same SendARP call MacResolver already uses for vendor
    // resolution, so this also primes r.macAddress for free.
    //
    // ARP only works on-link; non-local subnets still need TCP
    // fallback below. SendARP returns ERROR_GEN_FAILURE for off-link
    // IPs after a short timeout, so this stays fast on routed ranges.
    if (!r.isOnline && !opts.skipMac && !cancel.load(std::memory_order_relaxed)) {
        std::wstring mac = MacResolver::resolve(hostIp);
        if (!mac.empty()) {
            r.isOnline   = true;
            r.macAddress = std::move(mac);
            r.vendor     = VendorResolver::lookup(r.macAddress);
            r.discovery  = DiscoveryMethod::Arp;
        }
    }

    // ---- 2) Early emit on online (ICMP or ARP) -------------------------
    // We push a partial result the moment discovery confirms the host so
    // the "Online hosts" KPI + the new row appear immediately, even
    // before the (potentially minutes-long) port scan finishes.
    if (r.isOnline) emit();

    // ---- 3) MAC + Vendor (cheap on LAN, runs BEFORE the slow port scan) ---
    // Vendor lookup is a pure in-memory hash against the embedded OUI table.
    // MacResolver issues an ARP request — milliseconds on the same broadcast
    // domain. ARP-discovery above may have already filled mac/vendor; only
    // re-query if those are still empty (e.g. ICMP-confirmed but no
    // r.macAddress yet).
    if (r.isOnline && !opts.skipMac && r.macAddress.empty()
        && !cancel.load(std::memory_order_relaxed)) {
        r.macAddress = MacResolver::resolve(hostIp);
        if (!r.macAddress.empty()) {
            r.vendor = VendorResolver::lookup(r.macAddress);
            emit();
        }
    }

    // ---- 4) DNS reverse lookup — can be slow; emit when it returns ----
    // No native timeout on getnameinfo; on a misconfigured network this can
    // sit for a few seconds. Done before the port scan so hostname lands in
    // the UI quickly when the resolver is healthy.
    if (r.isOnline && !opts.skipDns && !cancel.load(std::memory_order_relaxed)) {
        r.hostname = DnsResolver::reverseLookup(hostIp);
        if (!r.hostname.empty()) emit();
    }

    // ---- 5) Mode-specific TCP probing ----
    const bool wantPorts = !opts.skipPorts && !opts.ports.empty();

    // Partial-port callback: PortScanner fires this after each batch that
    // discovered a new open port. We replace r.ports with the running
    // open-only snapshot, recompute risk, and push the row update.
    PortScanner::OpenPortsCallback onOpenPorts =
        [&](const std::vector<PortStatus>& openSnapshot) {
            r.ports = openSnapshot;
            RiskAnalyzer::evaluate(r);
            emit();
        };

    if (r.isOnline) {
        // ICMP succeeded — scan the configured port list. PortScanner sets the
        // service label per open port internally; no re-annotation needed.
        if (wantPorts && !cancel.load(std::memory_order_relaxed)) {
            auto full = PortScanner::scanHost(hostIp, opts.ports,
                                              opts.timeoutMs, cancel,
                                              probesDone, onOpenPorts);
            r.ports = std::move(full);
        }
    } else {
        switch (opts.mode) {
            case ScanMode::DiscoveryOnly:
                break;

            case ScanMode::Fast: {
                if (!wantPorts) break;
                if (cancel.load(std::memory_order_relaxed)) break;
                auto disc = PortScanner::scanHost(hostIp, fastDiscoveryPorts(),
                                                  opts.timeoutMs, cancel,
                                                  probesDone);
                if (anyPortOpen(disc)) {
                    r.isOnline  = true;
                    r.discovery = DiscoveryMethod::TcpFallback;
                    r.ports     = std::move(disc);
                    // Late emit: ICMP-silent but TCP-reachable host appears
                    // in the UI here.
                    emit();
                    // Also resolve MAC/vendor/DNS for late-discovered hosts.
                    if (!opts.skipMac && !cancel.load(std::memory_order_relaxed)) {
                        r.macAddress = MacResolver::resolve(hostIp);
                        if (!r.macAddress.empty()) {
                            r.vendor = VendorResolver::lookup(r.macAddress);
                        }
                    }
                    if (!opts.skipDns && !cancel.load(std::memory_order_relaxed)) {
                        r.hostname = DnsResolver::reverseLookup(hostIp);
                    }
                }
                break;
            }

            case ScanMode::Deep: {
                if (!wantPorts) break;
                if (cancel.load(std::memory_order_relaxed)) break;
                auto full = PortScanner::scanHost(hostIp, opts.ports,
                                                  opts.timeoutMs, cancel,
                                                  probesDone, onOpenPorts);
                if (anyPortOpen(full)) {
                    r.isOnline  = true;
                    r.discovery = DiscoveryMethod::TcpFallback;
                    r.ports     = std::move(full);
                    emit();
                    if (!opts.skipMac && !cancel.load(std::memory_order_relaxed)) {
                        r.macAddress = MacResolver::resolve(hostIp);
                        if (!r.macAddress.empty()) {
                            r.vendor = VendorResolver::lookup(r.macAddress);
                        }
                    }
                    if (!opts.skipDns && !cancel.load(std::memory_order_relaxed)) {
                        r.hostname = DnsResolver::reverseLookup(hostIp);
                    }
                }
                break;
            }
        }
    }

    // ---- 5b) Service fingerprinting (online hosts, non-Discovery only) ----
    // Lightweight, non-authenticated identification of the services already
    // found open: HTTP/HTTPS headers, SSH/FTP/SMTP greetings, the MySQL
    // handshake, the MSSQL TDS prelogin, and the SQL Server Browser. Closed
    // ports and offline hosts are never touched. Each probe is timeout-bounded
    // and online hosts run in parallel across the worker pool, so this doesn't
    // serially delay the sweep.
    const bool wantFingerprint = r.isOnline
                              && !opts.skipFingerprint
                              && opts.mode != ScanMode::DiscoveryOnly;
    if (wantFingerprint && !cancel.load(std::memory_order_relaxed)) {
        ServiceFingerprinter::Options fo;
        fo.timeoutMs = opts.fingerprintTimeoutMs;
        r.fingerprints = ServiceFingerprinter::fingerprintTcpServices(
            r.ipAddress, r.ports, fo, cancel);

        // SQL Server Browser lives on UDP 1434, independent of TCP 1433.
        if (!cancel.load(std::memory_order_relaxed)) {
            auto browser = ServiceFingerprinter::queryMssqlBrowser(
                r.ipAddress, opts.fingerprintTimeoutMs);
            for (auto& b : browser) r.fingerprints.push_back(std::move(b));
        }

        // Windows version via NetServerGetInfo + SMB NEGOTIATE dialect.
        //
        // The two SMB-stack probes on port 445 surface complementary
        // information:
        //   NetServerGetInfo  → Windows version (e.g. 10.0),
        //                       NetBIOS computer name,
        //                       domain-controller bit, comment.
        //                       Works on the local LAN; fails on
        //                       hosts reachable only via routed
        //                       paths (IPSEC tunnel) because it
        //                       runs an NBNS broadcast as part
        //                       of name resolution.
        //   SMB NEGOTIATE     → actual negotiated SMB dialect
        //                       (1.0 .. 3.1.1). Works over any
        //                       TCP-routable path including
        //                       IPSEC. SMB1-only hosts are a
        //                       finding in themselves.
        //
        // v1.3.6 split: SMB NEGOTIATE runs on the LOCAL machine too —
        // a plain TCP connect to 127.0.0.1:445 works fine and gives the
        // user their own SMB dialect (especially important when SMB1
        // is still enabled on this box, which is a finding). Only the
        // NetServerGetInfo half is skipped on self because its NBNS
        // broadcast for our own IP is meaningless and slow.
        if (!cancel.load(std::memory_order_relaxed)) {
            bool smbOpen = false;
            for (const auto& p : r.ports) {
                if (p.isOpen && p.port == 445) { smbOpen = true; break; }
            }
            if (smbOpen) {
                ServiceFingerprinter::WindowsServerInfo win{};
                if (!isLocalHost(hostIp)) {
                    win = ServiceFingerprinter::queryWindowsServerInfo(
                        r.ipAddress, opts.fingerprintTimeoutMs);

                    // Hostname enrichment from NetBIOS / SMB computer name.
                    // Independent of fingerprint emission. Skip a "name"
                    // that's just the IP address (some servers echo that).
                    if (r.hostname.empty() && !win.computerName.empty() &&
                        win.computerName != r.ipAddress)
                        r.hostname = win.computerName;
                }

                auto smb = ServiceFingerprinter::queryWindowsSmbDialect(
                    r.ipAddress, opts.fingerprintTimeoutMs);
                if (smb.port != 0) {
                    // To avoid two near-duplicate 445/tcp rows in the report
                    // (one labelled "Windows 10.0" via NetServerGetInfo and
                    // one labelled "SMB 3.1.1" via SMB NEGOTIATE for the same
                    // host), we merge: the SMB NEGOTIATE fingerprint is the
                    // canonical port-445 entry, and any Windows version
                    // NetServerGetInfo dug up gets appended to its detail.
                    if (win.fingerprint.port != 0
                        && !win.fingerprint.version.empty()) {
                        smb.detail += L" -- Windows "
                                    + win.fingerprint.version
                                    + L" (NetServerGetInfo)";
                    }
                    r.fingerprints.push_back(std::move(smb));
                } else if (win.fingerprint.port != 0) {
                    // SMB NEGOTIATE failed (very restricted server, port
                    // filtered mid-handshake, etc.) but NetServerGetInfo
                    // gave us something — surface it so the report
                    // doesn't lose the only data we got. This case is
                    // rare; usually the inverse holds (NetServerGetInfo
                    // fails on IPSEC, SMB NEGOTIATE succeeds).
                    r.fingerprints.push_back(std::move(win.fingerprint));
                }

                // v1.4.5 — enumerate exposed SMB shares (anonymous
                // NetShareEnum, names only). NAS boxes and Samba/older
                // servers usually allow it; modern Windows blocks anon
                // enumeration and returns nothing. Runs on self too — the
                // scanning host's own shares are worth auditing (and a
                // self-connect to \\ourip\ enumerates fine).
                if (!cancel.load(std::memory_order_relaxed)) {
                    auto shares = ServiceFingerprinter::queryShares(
                        r.ipAddress, opts.fingerprintTimeoutMs);
                    if (!shares.empty()) {
                        std::wstring blob;
                        for (const auto& line : shares) {
                            if (!blob.empty()) blob += L"\r\n";
                            blob += line;
                        }
                        r.smbShares = std::move(blob);
                    }
                }
            }
        }

        // Apple device-class probe — Apple ships with most TCP services off,
        // so a vendor=Apple host with no open ports could be an iPhone, iPad,
        // Mac, Apple TV or HomePod from the port profile alone. The dedicated
        // probe combines a tight set of out-of-band TCP signals (lockdownd /
        // AirPlay / DAAP) with a single unicast mDNS service-meta query, so
        // DeviceClassifier can pick the right subtype.
        if (!cancel.load(std::memory_order_relaxed)) {
            const bool vendorIsApple =
                r.vendor.find(L"Apple") != std::wstring::npos ||
                r.vendor.find(L"apple") != std::wstring::npos;
            if (vendorIsApple) {
                auto appleFp = ServiceFingerprinter::queryAppleDeviceInfo(
                    r.ipAddress, opts.fingerprintTimeoutMs);
                if (appleFp.port != 0)
                    r.fingerprints.push_back(std::move(appleFp));
            }
        }

        // Hostname fallbacks for hosts that reverse DNS + SMB couldn't name.
        // Common when the scanning box's upstream resolver is public (e.g.
        // 8.8.8.8 has no PTR records for the LAN) and the host either has no
        // SMB exposed or its SMB name came back as the IP address. The two
        // additional probes cover the rest of the household:
        //   - NBNS node-status (UDP 137) — every Windows / Samba host answers
        //     this without auth, even with SMB closed or returning the IP.
        //   - mDNS reverse PTR (UDP 5353) — Apple devices, Linux hosts with
        //     Avahi, and most printer / NAS / IoT firmware running Bonjour
        //     answer this. Reuses the same unicast-mDNS path as the Apple
        //     subtype probe above.
        if (r.hostname.empty() &&
            !cancel.load(std::memory_order_relaxed) &&
            !isLocalHost(hostIp))
        {
            auto nb = ServiceFingerprinter::queryNbnsName(
                r.ipAddress, opts.fingerprintTimeoutMs);
            if (!nb.empty() && nb != r.ipAddress) r.hostname = nb;
        }
        if (r.hostname.empty() &&
            !cancel.load(std::memory_order_relaxed) &&
            !isLocalHost(hostIp))
        {
            auto md = ServiceFingerprinter::queryMdnsReverseName(
                r.ipAddress, opts.fingerprintTimeoutMs);
            if (!md.empty() && md != r.ipAddress) r.hostname = md;
        }
    }

    // ---- 5c) Clock drift (online hosts, non-Discovery only) -----------------
    // NTP (UDP 123) is tried first — the proper time protocol. Most LAN
    // clients are not NTP servers and simply won't answer, which is normal;
    // for those we fall back to NetRemoteTOD ("net time") over SMB, which any
    // Windows host running the Server service answers. The fallback only runs
    // when NTP was silent AND TCP 445 is open, keeping it bounded.
    const bool wantClock = r.isOnline
                        && !opts.skipClockDrift
                        && opts.mode != ScanMode::DiscoveryOnly;
    if (wantClock && !cancel.load(std::memory_order_relaxed)) {
        r.clockDrift = ServiceFingerprinter::queryNtpClock(
            r.ipAddress, opts.fingerprintTimeoutMs);

        // net time fallback: only when NTP was silent, TCP 445 is open, and
        // the target isn't this scanning host itself (own-clock drift is ~0
        // and meaningless — see isLocalHost).
        if (!r.clockDrift.responded &&
            !cancel.load(std::memory_order_relaxed) &&
            !isLocalHost(hostIp)) {
            bool smbOpen = false;
            for (const auto& p : r.ports) {
                if (p.isOpen && p.port == 445) { smbOpen = true; break; }
            }
            if (smbOpen) {
                r.clockDrift = ServiceFingerprinter::queryWindowsTimeOfDay(
                    r.ipAddress, opts.fingerprintTimeoutMs);
            }
        }

        if (r.clockDrift.responded) {
            r.fingerprints.push_back(
                ServiceFingerprinter::clockDriftFingerprint(r.clockDrift));
        }
    }

    // Hostname fallback for the scanning host itself — reverse DNS frequently
    // can't resolve it, and the SMB probes deliberately skip it. The local
    // computer name is an instant, network-free source.
    if (r.isOnline && r.hostname.empty() && isLocalHost(hostIp)) {
        r.hostname = ServiceFingerprinter::localComputerName();
    }

    // ---- 5e) UDP discovery (online hosts, non-Discovery only) ----
    // Targeted UDP probes (NBNS, NTP, SSDP, mDNS, SQL Server Browser,
    // DNS, LLMNR, IPMI). All probes share a single select() loop with
    // a ~600 ms global budget, so per-host cost is bounded regardless
    // of how many probes are silent. Results are reported as a separate
    // "UDP discovery" string — NOT mixed into the TCP open-ports list,
    // since UDP semantics are different (no "open/closed" certainty).
    const bool wantUdp = r.isOnline
                      && !opts.skipUdpDiscovery
                      && opts.mode != ScanMode::DiscoveryOnly;
    if (wantUdp && !cancel.load(std::memory_order_relaxed)) {
        r.udpDiscovery = UdpDiscoveryService::discover(
            hostIp, opts.fingerprintTimeoutMs, cancel);
        // If NBNS gave us a NetBIOS name and reverse DNS didn't, promote
        // it to the hostname so the grid shows something useful. The
        // UDP-discovery payload is tab-separated "<port>\t<service>\t<detail>"
        // per line — walk it line-by-line and pull the NBNS detail.
        if (r.hostname.empty() && !r.udpDiscovery.empty()) {
            const std::wstring& s = r.udpDiscovery;
            size_t lineStart = 0;
            while (lineStart < s.size()) {
                size_t lineEnd = s.find(L"\r\n", lineStart);
                if (lineEnd == std::wstring::npos) lineEnd = s.size();
                std::wstring line = s.substr(lineStart, lineEnd - lineStart);
                size_t t1 = line.find(L'\t');
                size_t t2 = (t1 == std::wstring::npos)
                              ? std::wstring::npos
                              : line.find(L'\t', t1 + 1);
                if (t1 != std::wstring::npos && t2 != std::wstring::npos) {
                    std::wstring service = line.substr(t1 + 1, t2 - t1 - 1);
                    std::wstring detail  = line.substr(t2 + 1);
                    if (service == L"NBNS" && !detail.empty()) {
                        // The NBNS detail typically reads "<NAME>\<WORKGROUP>".
                        // Stop at the backslash so we keep only the machine
                        // name, then trim trailing padding spaces.
                        size_t end = detail.find_first_of(L"\\\r\n");
                        std::wstring nb = (end == std::wstring::npos)
                                            ? detail
                                            : detail.substr(0, end);
                        while (!nb.empty() && nb.back() == L' ') nb.pop_back();
                        if (!nb.empty()) {
                            r.hostname = nb;
                            break;
                        }
                    }
                }
                if (lineEnd == s.size()) break;
                lineStart = lineEnd + 2;
            }
        }
    }

    // ---- 5d) Device classification (online hosts) ----
    // Pure inference from what the scan already gathered — MAC/vendor, open
    // ports, service fingerprints, hostname, gateway. Runs for every online
    // host even when fingerprinting is disabled (MAC + ports alone classify
    // many devices).
    if (r.isOnline) {
        DeviceClassifier::classify(r, opts.gatewayIp);
    }

    // ---- 5d.1) Printer detection + SNMP supplies probe (v1.0.33) ----
    // Modular: PrinterSnmpScanner is the ONLY caller of SnmpClient, and the
    // ONLY code path that touches Printer-MIB. NetworkScanner just gathers
    // the "is this a printer" signals and asks the module to take it from
    // there. Output (vendor / model / serial / supplies) lands directly on
    // ScanResult — no further plumbing on this hot path.
    if (r.isOnline && !opts.skipPrinterSnmp
        && opts.mode != ScanMode::DiscoveryOnly
        && !cancel.load(std::memory_order_relaxed)) {
        PrinterSignals sig{};
        for (const auto& p : r.ports) {
            if (!p.isOpen) continue;
            if (p.port == 9100) sig.port9100 = true;
            else if (p.port == 515) sig.port515 = true;
            else if (p.port == 631) sig.port631 = true;
        }
        // OUI / engine signals.
        const std::wstring vl = r.vendor;
        auto vendorIs = [&](const wchar_t* needle) {
            const size_t nl = wcslen(needle);
            if (vl.size() < nl) return false;
            for (size_t i = 0; i + nl <= vl.size(); ++i) {
                bool ok = true;
                for (size_t j = 0; j < nl; ++j) {
                    wchar_t a = vl[i + j], b = needle[j];
                    if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
                    if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
                    if (a != b) { ok = false; break; }
                }
                if (ok) return true;
            }
            return false;
        };
        sig.vendorMatch =
              vendorIs(L"hp") || vendorIs(L"hewlett") || vendorIs(L"xerox")
           || vendorIs(L"brother") || vendorIs(L"canon") || vendorIs(L"epson")
           || vendorIs(L"ricoh") || vendorIs(L"kyocera") || vendorIs(L"konica")
           || vendorIs(L"lexmark") || vendorIs(L"sharp") || vendorIs(L"oki")
           || vendorIs(L"zebra") || vendorIs(L"dymo");
        sig.deviceClass = (r.deviceType.find(L"Printer") != std::wstring::npos)
                       || (r.deviceType.find(L"printer") != std::wstring::npos);

        if (sig.any()) {
            PrinterInfo pi = PrinterSnmpScanner::probe(
                hostIp, sig, opts.fingerprintTimeoutMs,
                opts.wantPrinterSupplies, cancel);
            r.isPrinter      = pi.isPrinter;
            r.printerVendor  = pi.vendor;
            r.printerModel   = pi.model;
            r.printerSerial  = pi.serial;
            switch (pi.snmpStatus) {
                case PrinterSnmpStatus::Ok:           r.printerSnmpStatus = L"ok";           break;
                case PrinterSnmpStatus::NoSupplies:   r.printerSnmpStatus = L"no supplies";  break;
                case PrinterSnmpStatus::Unavailable:  r.printerSnmpStatus = L"unavailable";  break;
                default:                              r.printerSnmpStatus = L"not probed";   break;
            }
            // Encode supplies as "\r\n"-line / TAB-column for the UI:
            //   color \t type \t pct \t level \t max \t description
            if (!pi.supplies.empty()) {
                std::wstring out;
                for (const auto& s : pi.supplies) {
                    if (!out.empty()) out += L"\r\n";
                    out += s.color.empty() ? L"" : s.color;
                    out += L"\t";
                    out += L"\t";   // reserved for future "type" column
                    if (s.percent >= 0) {
                        wchar_t buf[12];
                        swprintf_s(buf, L"%d%%", s.percent);
                        out += buf;
                    } else {
                        out += L"\x2014";
                    }
                    out += L"\t";
                    wchar_t buf[24];
                    if (s.level >= 0) { swprintf_s(buf, L"%lld", static_cast<long long>(s.level)); out += buf; }
                    out += L"\t";
                    if (s.maxLevel > 0) { swprintf_s(buf, L"%lld", static_cast<long long>(s.maxLevel)); out += buf; }
                    out += L"\t";
                    out += s.description;
                }
                r.printerSupplies = out;
            }
            // v1.4.1 — lifetime page / scan counters, TAB-separated
            //   total \t color \t mono \t scans   (blank column = unknown).
            if (pi.pagesTotal >= 0 || pi.pagesColor >= 0
             || pi.pagesMono >= 0 || pi.scansTotal >= 0) {
                auto num = [](int64_t v) -> std::wstring {
                    if (v < 0) return std::wstring{};
                    wchar_t b[24];
                    swprintf_s(b, L"%lld", static_cast<long long>(v));
                    return b;
                };
                r.printerPages = num(pi.pagesTotal) + L"\t" + num(pi.pagesColor)
                               + L"\t" + num(pi.pagesMono) + L"\t" + num(pi.scansTotal);
            }
            // Promote SNMP-derived vendor/model into the host's enrichment
            // fields when they were empty — significantly better text than
            // a raw OUI vendor.
            if (!pi.vendor.empty() && r.vendor.empty()) r.vendor = pi.vendor;
            // Note: r.deviceType is left to the classifier — Printer-MIB
            // alone can mis-classify a multi-function box.

            // ---- Zebra-native SGD probe over raw TCP 9100 ----------------
            //
            // Zebra label/barcode printers rarely populate the standard
            // Printer-MIB the way laser/inkjet boxes do, so the SNMP path
            // above often comes back with vendor only and no supplies/pages.
            // Every modern Zebra answers SGD `getvar` over 9100, which works
            // even when SNMP is disabled or locked to a non-default
            // community. We send the bytes ONLY when the host is already
            // confirmed Zebra (OUI vendor or SNMP sysDescr) and 9100 is open
            // — a non-Zebra 9100 would treat the SGD text as a print job.
            const bool zebra =
                   (r.vendor.find(L"Zebra") != std::wstring::npos)
                || (r.vendor.find(L"ZEBRA") != std::wstring::npos)
                || (pi.vendor == L"Zebra")
                || (pi.sysDescr.find(L"Zebra") != std::wstring::npos)
                || (pi.sysDescr.find(L"ZTC")   != std::wstring::npos);
            // NOTE: we do NOT require sig.port9100 here. Zebra GK-class
            // printers have a tiny TCP stack that often drops 9100/515 under
            // the parallel port sweep's short connect timeout, so the scan
            // can miss them even when they're live (verified on a real
            // GK420t: only 80 came back open). Since the host is already
            // confirmed Zebra by OUI/sysDescr, it is safe to attempt a
            // dedicated SGD connect on 9100 with the more generous
            // fingerprint timeout — if 9100 really is closed the connect
            // just fails fast and we move on.
            if (zebra && opts.wantPrinterSupplies
                && !cancel.load(std::memory_order_relaxed)) {
                auto z = ServiceFingerprinter::queryZebraStatus(
                    r.ipAddress, opts.fingerprintTimeoutMs);
                if (z.responded) {
                    r.isPrinter = true;
                    if (r.printerVendor.empty()) r.printerVendor = L"Zebra";
                    if (r.vendor.empty())        r.vendor        = L"Zebra";
                    // Compose "<model> (fw <ver>)" when we have either piece.
                    std::wstring m = z.model;
                    if (!z.firmware.empty()) {
                        if (!m.empty()) m += L" (fw " + z.firmware + L")";
                        else            m  = L"Zebra (fw " + z.firmware + L")";
                    }
                    if (!m.empty() && m.size() > r.printerModel.size())
                        r.printerModel = m;
                    // Page history → reuse the printerPages plumbing, format
                    //   "total \t color \t mono \t scans \t usage".
                    // Newer Link-OS Zebras expose odometer.total_label_count
                    // (→ total). GK-class printers like the GK420t return "?"
                    // for it and only expose odometer.total_print_length, so
                    // carry that as the free-text "usage" field — it is the
                    // only lifetime metric the device offers and is exactly
                    // the "page history" the operator is after.
                    if ((z.labelCount >= 0 || !z.printLength.empty())
                        && r.printerPages.empty()) {
                        std::wstring total;
                        if (z.labelCount >= 0) {
                            wchar_t b[24];
                            swprintf_s(b, L"%lld", static_cast<long long>(z.labelCount));
                            total = b;
                        }
                        r.printerPages = total + L"\t\t\t\t" + z.printLength;
                    }
                    // A Zebra that answered SGD is fully readable even if its
                    // SNMP MIB was empty — reflect that in the status.
                    if (r.printerSnmpStatus.empty()
                     || r.printerSnmpStatus == L"unavailable"
                     || r.printerSnmpStatus == L"no supplies"
                     || r.printerSnmpStatus == L"not probed") {
                        r.printerSnmpStatus = L"ok";
                    }
                }
            }
        }
    }

    // ---- 5e.0) IoT fingerprint — Roborock / Xiaomi robot vacuums (v1.5.0) --
    //
    // Defensive inventory ONLY. For candidate devices (Roborock/Xiaomi MAC
    // vendor, a robot-vacuum hostname, or the Roborock TCP 58867 port open) we
    // run one safe, read-only probe — the Xiaomi miIO "hello" on UDP 54321 —
    // plus passive port evidence, and compute a confidence score. No control
    // commands, no exploit, no cloud login, no token brute force. Model and
    // firmware are NOT read here: they require an authenticated local API
    // (the device token), and newer Roborock devices use an encrypted TCP
    // 58867 protocol that needs the local key. Runs only for candidates, so
    // normal LAN scans are unaffected.
    if (r.isOnline && !opts.skipFingerprint
        && opts.mode != ScanMode::DiscoveryOnly
        && !cancel.load(std::memory_order_relaxed)) {

        auto lc = [](std::wstring s) {
            for (auto& c : s) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
            return s;
        };
        auto has = [&](const std::wstring& hay, const wchar_t* needle) {
            return lc(hay).find(needle) != std::wstring::npos;
        };

        const std::wstring& v  = r.vendor;
        const std::wstring& hn = r.hostname;
        const std::wstring& dt = r.deviceType;

        bool port58867 = false, otherIot = false;
        for (const auto& p : r.ports) {
            if (!p.isOpen) continue;
            if (p.port == 58867) port58867 = true;
            else if (p.port == 80 || p.port == 443 || p.port == 8080 || p.port == 8888)
                otherIot = true;
        }

        const bool vendorRoboXiaomi =
            has(v, L"roborock") || has(v, L"xiaomi") || has(v, L"lumi")
         || has(v, L"viomi")    || has(v, L"dreame");
        const bool hostMatch =
            has(hn, L"roborock") || has(hn, L"rockrobo") || has(hn, L"vacuum")
         || has(hn, L"miio")     || has(hn, L"xiaomi");
        const bool deviceVac = has(dt, L"vacuum") || has(dt, L"robot");

        // The parallel port sweep often misses 58867 on these minimal-TCP-stack
        // devices, so for a confirmed candidate do one dedicated connect with
        // the more generous fingerprint timeout.
        if (!port58867 && (vendorRoboXiaomi || hostMatch || deviceVac)
            && !cancel.load(std::memory_order_relaxed)) {
            port58867 = ServiceFingerprinter::tcpConnectable(
                r.ipAddress, 58867, opts.fingerprintTimeoutMs);
        }

        if (vendorRoboXiaomi || hostMatch || deviceVac || port58867) {
            auto hello = ServiceFingerprinter::queryMiioHello(
                r.ipAddress, opts.fingerprintTimeoutMs);

            int score = 0;
            std::vector<std::wstring> ev;
            ev.push_back(hello.responded
                ? L"miIO UDP 54321: responded"
                : L"miIO UDP 54321: no response (newer Roborock uses TCP 58867)");
            if (vendorRoboXiaomi) { score += 45; ev.push_back(L"MAC vendor in Roborock/Xiaomi family: " + v); }
            if (hello.responded)  { score += 30; }
            if (port58867)        { score += 25; ev.push_back(L"Roborock local-protocol port TCP 58867 open"); }
            if (hostMatch)        { score += 10; ev.push_back(L"Hostname matches robot-vacuum pattern: " + hn); }
            if (otherIot)         { score += 5; }
            if (score > 100) score = 100;

            if (hello.responded) {
                wchar_t b[80];
                swprintf_s(b, L"miIO device id: 0x%08x (stamp %u)",
                           hello.deviceId, hello.stamp);
                ev.push_back(b);
                if (hello.tokenExposed)
                    ev.push_back(L"SECURITY: device token exposed in miIO handshake "
                                 L"(old/unprovisioned firmware): " + hello.tokenHex);
            }
            ev.push_back(L"Model / firmware require the device local token / "
                         L"authenticated local API.");

            const wchar_t* label =
                  (score >= 90) ? L"Confirmed Roborock vacuum"
                : (score >= 70) ? L"Very likely Roborock/Xiaomi vacuum"
                : (score >= 40) ? L"Possible robot vacuum"
                :                 L"Low-confidence IoT candidate";

            if (score >= 40) {
                wchar_t hdr[80];
                swprintf_s(hdr, L"%d\t%s", score, label);
                std::wstring blob = hdr;
                for (const auto& line : ev) { blob += L"\r\n"; blob += line; }
                r.iotFingerprint = std::move(blob);
            }
        }
    }

    // ---- 5e.0b) Ubiquiti / UniFi fingerprint (v1.5.1) ----
    //
    // Defensive inventory only. Candidate = Ubiquiti MAC vendor, a UniFi-style
    // hostname, a dropbear SSH banner, or TCP 8080 (UniFi inform) open. Safe
    // read-only probes: UBNT Discovery on UDP 10001 (model/firmware/hostname
    // when the device answers — typically unadopted gear / controllers) + the
    // existing SSH banner + an 8080 inform check. No exploit, no config change.
    // Reuses the iotFingerprint field (a host is Roborock OR Ubiquiti, never
    // both), so only runs when the Roborock block didn't already claim it.
    if (r.iotFingerprint.empty() && r.isOnline && !opts.skipFingerprint
        && opts.mode != ScanMode::DiscoveryOnly
        && !cancel.load(std::memory_order_relaxed)) {

        auto lc = [](std::wstring s) {
            for (auto& c : s) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
            return s;
        };
        auto has = [&](const std::wstring& hay, const wchar_t* needle) {
            return lc(hay).find(needle) != std::wstring::npos;
        };

        const std::wstring& v  = r.vendor;
        const std::wstring& hn = r.hostname;

        bool port8080 = false;
        for (const auto& p : r.ports)
            if (p.isOpen && (p.port == 8080)) { port8080 = true; break; }

        bool sshDropbear = false;
        for (const auto& f : r.fingerprints) {
            if (lc(f.product).find(L"dropbear") != std::wstring::npos
             || lc(f.detail).find(L"dropbear")  != std::wstring::npos
             || lc(f.version).find(L"dropbear") != std::wstring::npos) {
                sshDropbear = true; break;
            }
        }

        const bool vendorUbnt = has(v, L"ubiquiti");
        const bool hostUbnt =
            has(hn, L"ubnt") || has(hn, L"unifi") || has(hn, L"uap")
         || has(hn, L"usw")  || has(hn, L"usg")   || has(hn, L"u6")
         || has(hn, L"u7");

        if (vendorUbnt || hostUbnt || sshDropbear || port8080) {
            // 8080 can be dropped by the parallel sweep on some gear —
            // confirm with a dedicated connect for a candidate.
            if (!port8080 && (vendorUbnt || hostUbnt || sshDropbear)
                && !cancel.load(std::memory_order_relaxed)) {
                port8080 = ServiceFingerprinter::tcpConnectable(
                    r.ipAddress, 8080, opts.fingerprintTimeoutMs);
            }
            auto ub = ServiceFingerprinter::queryUbntDiscovery(
                r.ipAddress, opts.fingerprintTimeoutMs);

            int score = 0;
            std::vector<std::wstring> ev;
            ev.push_back(ub.responded
                ? L"UBNT Discovery UDP 10001: responded"
                : L"UBNT Discovery UDP 10001: no response (likely controller-adopted)");
            if (vendorUbnt)   { score += 40; ev.push_back(L"MAC vendor Ubiquiti: " + v); }
            if (ub.responded) { score += 30; }
            if (port8080)     { score += 20; ev.push_back(L"TCP 8080 UniFi inform endpoint"); }
            if (sshDropbear)  { score += 15; ev.push_back(L"SSH dropbear banner (Ubiquiti firmware)"); }
            if (hostUbnt)     { score += 10; ev.push_back(L"Hostname matches UniFi pattern: " + hn); }
            if (score > 100) score = 100;

            bool haveModel = false;
            if (ub.responded) {
                if (!ub.modelCode.empty()) { ev.push_back(L"Model code: " + ub.modelCode); haveModel = true; }
                if (!ub.modelName.empty())   ev.push_back(L"Model: " + ub.modelName);
                if (!ub.firmware.empty())    ev.push_back(L"Firmware: " + ub.firmware);
                // Adopt the UBNT-reported hostname only when it's a genuine
                // custom name — never when it's just the model SKU (UniFi's
                // default hostname, e.g. "U6-LR"). The SKU is surfaced in the
                // Model column instead, so it doesn't masquerade as a hostname.
                if (!ub.hostname.empty() && r.hostname.empty()
                    && !ServiceFingerprinter::looksLikeUnifiModel(ub.hostname))
                    r.hostname = ub.hostname;
                if (ub.uptime > 0) {
                    wchar_t ub2[48];
                    swprintf_s(ub2, L"Uptime: %ud %uh",
                               ub.uptime / 86400, (ub.uptime % 86400) / 3600);
                    ev.push_back(ub2);
                }
            } else {
                ev.push_back(L"Exact model usually requires UBNT Discovery response, "
                             L"SNMP, or authenticated SSH read-only fingerprint.");
            }

            const wchar_t* label =
                  (score >= 90 && haveModel) ? L"Confirmed UniFi device"
                : (score >= 70)              ? L"Confirmed Ubiquiti / likely UniFi AP"
                : (score >= 40)              ? L"Possible Ubiquiti device"
                :                              L"Generic network device";

            if (score >= 40) {
                wchar_t hdr[80];
                swprintf_s(hdr, L"%d\t%s", score, label);
                std::wstring blob = hdr;
                for (const auto& line : ev) { blob += L"\r\n"; blob += line; }
                r.iotFingerprint = std::move(blob);
            }
        }
    }

    // ---- 5e) Web UI probe (online hosts, port 80 / 443 / 8443 open) ----
    // Eager Pass 2 of the engine-owned enrichment model: fetch the device
    // admin page on whatever HTTP(S) port is open, extract the model from
    // the DOM, store it on `r.webUiModel`. The EnrichmentEngine then folds
    // that into the brand-hint aggregate so the GUI sees a complete bundle.
    // Runs synchronously on the per-host worker thread — same parallelism
    // as the rest of the scan. ~1.5 s budget per probe, less than that
    // when the host returns quickly.
    if (r.isOnline && !opts.skipFingerprint) {
        std::set<int> openPorts;
        for (const auto& p : r.ports) if (p.isOpen) openPorts.insert(p.port);
        bool hasWeb = openPorts.count(80) || openPorts.count(443)
                   || openPorts.count(8443);
        if (hasWeb) {
            r.webUiModel = WebUiProbe::probe(r.ipAddress, openPorts,
                                              /*timeoutMs=*/1500);

            // v1.5.7 — per-device-type EXACT model for the Model column.
            // deriveExactModel handles iLO (/xmldata?item=All), Netgear
            // (switchInfo SKU), Thecus / Yealink (title), etc., reusing the
            // body just fetched and rejecting junk titles like "Loading...".
            auto lower = [](std::wstring s) {
                for (auto& c : s) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
                return s;
            };
            // Authoritative for web-capable hosts: deriveExactModel is a strict
            // per-vendor resolver (empty = "no reliable model"), so it OVERRIDES
            // the classifier's early best-effort guess. This is what suppresses
            // raw page titles ("Opening...", "Welcome to XAMPP", "Moved
            // Temporarily", verbose Synology/MikroTik banners, etc.) from the
            // Model column. Printer / ESXi / Ubiquiti models come from their own
            // authoritative sources in EnrichmentEngine::bestDeviceModel and are
            // unaffected by clearing r.deviceModel here.
            r.deviceModel = WebUiProbe::deriveExactModel(
                lower(r.deviceType), lower(r.vendor), openPorts,
                r.webUiModel, r.ipAddress, /*timeoutMs=*/1500);
        }
    }

    // ---- 5e.1) iLO baseboard exact model — VPN-resilient (v1.5.7) ----------
    // An iLO answers SSH instantly but its TLS-443 handshake is slow, so over
    // an L3 VPN the fast port sweep routinely marks 443 "closed" and the web
    // block above never runs. Detect the iLO from its distinctive "mpSSH"
    // (management-processor SSH) banner — or the device type / HPE vendor —
    // then do a dedicated 443 connect with a generous timeout and read the
    // authoritative /xmldata?item=All (PN + firmware). Only runs when 443/8443
    // weren't already handled above, so non-VPN iLOs don't double-probe.
    if (r.isOnline && !opts.skipFingerprint && r.deviceModel.empty()
        && !cancel.load(std::memory_order_relaxed)) {
        bool has443 = false, has8443 = false;
        for (const auto& p : r.ports) {
            if (!p.isOpen) continue;
            if (p.port == 443)  has443  = true;
            if (p.port == 8443) has8443 = true;
        }
        if (!has443 && !has8443) {
            auto lc = [](std::wstring s) {
                for (auto& c : s) if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
                return s;
            };
            bool iloLike = lc(r.deviceType).find(L"ilo") != std::wstring::npos
                        || lc(r.vendor).find(L"hpe") != std::wstring::npos;
            if (!iloLike) {
                for (const auto& f : r.fingerprints) {
                    std::wstring b = lc(f.product + L" " + f.version + L" "
                                       + f.detail + L" " + f.source);
                    if (b.find(L"mpssh") != std::wstring::npos
                     || b.find(L"hp-ilo") != std::wstring::npos
                     || b.find(L"proliant") != std::wstring::npos) {
                        iloLike = true; break;
                    }
                }
            }
            if (iloLike
                && ServiceFingerprinter::tcpConnectable(r.ipAddress, 443, 2500)) {
                std::wstring m = WebUiProbe::fetchIloModel(r.ipAddress, 443, 4000);
                if (!m.empty()) r.deviceModel = m;
            }
        }
    }

    // Push the enriched row to the UI once fingerprinting / classification ran.
    if (r.isOnline) emit();

    // ---- 6) Risk analysis (always runs, final pass) ----
    // Offline hosts get: Status=Offline / Risk=None / hint="Device unreachable".
    RiskAnalyzer::evaluate(r);

    // ---- 7) Enrichment finalisation (eager, scan-time) ----
    // Compute every display-ready string ONCE here, store it on the
    // ScanResult, so the GUI's row-click handler is a pure read of
    // already-computed values. Includes the vendor short tag, the
    // post-classification device label, the brand-hint aggregate, OS /
    // device hints, per-fingerprint version annotations, and (when the
    // host is local) per-port owner PID + exe path. This is what makes
    // `nl_scanner_get_result` / `nl_scanner_get_port` cheap.
    EnrichmentEngine::finalize(r);

    // ---- 8) Security findings (v1.3.2) ----
    // Heuristic CVE / lifecycle match against the now-fully-enriched
    // fingerprint set. Reads ONLY local state, no follow-up network
    // probe. Output is a multi-line TAB-separated string on
    // r.securityFindings that the GUI / HTML report parses.
    SecurityAdvisor::analyze(r);

    return r;
}

// =============================================================================
// ProgressThrottle
//
//   Reduces onProgress call pressure without hiding progress from the user.
//   A call fires when either:
//     - at least 100 ms passed since the last fired call, OR
//     - at least 10 hosts completed since the last fired call, OR
//     - this is the final (done == total) call (forced).
//
//   Thread-safe: workers race to fire a single update, the CAS picks one
//   winner per slot. The driver thread always issues a forced final call
//   after joining the workers so the user sees done=total exactly once.
// =============================================================================

class ProgressThrottle {
public:
    template <typename Fn>
    void send(int done, int total, Fn&& cb) {
        const bool isFinal = (done >= total);

        if (!isFinal) {
            int     prevDone = lastDone_.load(std::memory_order_relaxed);
            int64_t prevMs   = lastMs_.load(std::memory_order_relaxed);
            int64_t nowMs    = timer_.elapsedMs();

            const bool hostsThresh = (done - prevDone) >= 10;
            const bool timeThresh  = (nowMs - prevMs)  >= 100;
            if (!hostsThresh && !timeThresh) return;

            // Claim the slot. The CAS may race with another worker — loop
            // until we either win (publishing our own done) or observe a
            // newer value already published (drop our update as stale).
            // Previously a single CAS-fail dropped the update outright,
            // which under heavy parallelism produced visible progress
            // stalls until the next throttle window.
            while (!lastDone_.compare_exchange_weak(prevDone, done,
                                                    std::memory_order_acq_rel)) {
                if (prevDone >= done) return;  // someone published a fresher value
            }
            lastMs_.store(nowMs, std::memory_order_relaxed);
        }

        if (cb) {
            try { cb(done, total); }
            catch (...) { /* swallow — never let a callback kill the scan */ }
        }
    }

private:
    Stopwatch            timer_;
    std::atomic<int>     lastDone_{0};
    std::atomic<int64_t> lastMs_{0};
};

// =============================================================================
// PriorityWorkQueue — v1.3.6 dynamic four-tier dispatcher.
//
// Used only when ScanOptions::priorityCount > 0 (multi-/24 scans where the
// caller has already laid out [tier1 local /24 | tier2 scouts | rest]). The
// queue dispatches in this order, reacting live to host responses:
//
//   1. The `priorityCount` leading addresses (tier 1 + tier 2), in order.
//   2. As soon as ANY host in a remote /24 responds, that subnet's remaining
//      hosts are promoted to the "hot" band (tier 4) — dispatched before the
//      still-silent subnets.
//   3. Cold subnets (tier 3) — the long tail — dispatched last.
//
// Thread-safe. next() and markSubnetHot() are each one short critical section;
// with one call per HOST (not per probe) and per-host work dominated by
// connect()/select() timeouts, mutex contention is negligible even at 256
// workers. The plain atomic-counter path in executeScanLoop is still used when
// priorityCount == 0 (single-/24 or no gateway), so the cheap fast path is
// untouched for the common case.
class PriorityWorkQueue {
public:
    PriorityWorkQueue(const std::vector<uint32_t>& addrs, size_t priorityCount) {
        const size_t n = addrs.size();
        const size_t pc = std::min(priorityCount, n);
        for (size_t i = 0; i < pc; ++i) priority_.push_back(addrs[i]);
        // Group the remainder by /24, preserving ascending order within each
        // bucket. coldOrder_ records first-seen subnet order so the long tail
        // is dispatched in a stable, predictable sequence.
        for (size_t i = pc; i < n; ++i) {
            const uint32_t ip     = addrs[i];
            const uint32_t subnet = ip & 0xFFFFFF00u;
            auto it = buckets_.find(subnet);
            if (it == buckets_.end()) {
                buckets_.emplace(subnet, std::deque<uint32_t>{ip});
                coldOrder_.push_back(subnet);
            } else {
                it->second.push_back(ip);
            }
        }
    }

    // Pop the next IP to scan, or nullopt when fully drained.
    std::optional<uint32_t> next() {
        std::lock_guard<std::mutex> lk(mu_);
        if (!priority_.empty()) {
            uint32_t ip = priority_.front();
            priority_.pop_front();
            return ip;
        }
        // Hot band first (subnets whose scout already answered).
        while (!hotOrder_.empty()) {
            auto& dq = buckets_[hotOrder_.front()];
            if (dq.empty()) { hotOrder_.pop_front(); continue; }
            uint32_t ip = dq.front();
            dq.pop_front();
            return ip;
        }
        // Cold band — the long tail of silent subnets.
        while (!coldOrder_.empty()) {
            const uint32_t subnet = coldOrder_.front();
            if (hot_.count(subnet)) { coldOrder_.pop_front(); continue; }
            auto& dq = buckets_[subnet];
            if (dq.empty()) { coldOrder_.pop_front(); continue; }
            uint32_t ip = dq.front();
            dq.pop_front();
            return ip;
        }
        return std::nullopt;
    }

    // Promote the /24 containing `ip` into the hot band. Idempotent; no-op for
    // the local /24 (it has no bucket — all its hosts are in priority_).
    void markSubnetHot(uint32_t ip) {
        const uint32_t subnet = ip & 0xFFFFFF00u;
        std::lock_guard<std::mutex> lk(mu_);
        if (hot_.count(subnet)) return;
        auto it = buckets_.find(subnet);
        if (it == buckets_.end() || it->second.empty()) return;
        hot_.insert(subnet);
        hotOrder_.push_back(subnet);
    }

private:
    std::mutex                                              mu_;
    std::deque<uint32_t>                                    priority_;
    std::unordered_map<uint32_t, std::deque<uint32_t>>      buckets_;
    std::deque<uint32_t>                                    coldOrder_;
    std::deque<uint32_t>                                    hotOrder_;
    std::unordered_set<uint32_t>                            hot_;
};

// =============================================================================
// executeScanLoop — the driver-thread body.
//
//   Spawns N std::thread workers (N = clamped parallelism), each running a
//   tight loop:
//
//     for (;;) {
//         if (cancel) return;
//         idx = nextIndex.fetch_add(1);   // lock-free dispatch
//         if (idx >= total) return;
//         results[idx-slot] = scanOneHost(addresses[idx], ...);
//         onHost(result);                  // wrapped in try/catch
//         throttle.send(...)               // throttled onProgress
//     }
//
//   When ScanOptions::priorityCount > 0 the lock-free counter is replaced by
//   a PriorityWorkQueue (see above) so responsive /24s jump the queue.
//
//   Once all workers join we sort results by IP, compute the summary, and
//   fire onFinished once.
// =============================================================================

void executeScanLoop(const std::vector<uint32_t>& addresses,
                     const ScanOptions& options,
                     std::atomic<bool>& cancelFlag,
                     std::atomic<int64_t>& probesDone,
                     NetworkScanner::HostCallback     onHost,
                     NetworkScanner::ProgressCallback onProgress,
                     NetworkScanner::FinishedCallback onFinished)
{
    Stopwatch sw;
    const size_t total = addresses.size();

    std::vector<ScanResult> results;
    results.reserve(total);
    std::mutex resultsMu;

    int parallelInt = std::clamp(options.parallel, kMinParallel, kMaxParallel);
    if (total > 0 && static_cast<size_t>(parallelInt) > total) {
        parallelInt = static_cast<int>(total);
    }
    if (parallelInt < 1) parallelInt = 1;
    const size_t parallel = static_cast<size_t>(parallelInt);

    std::atomic<size_t> nextIndex{0};
    std::atomic<int>    doneCount{0};
    ProgressThrottle    throttle;

    // v1.3.6 — dynamic four-tier dispatch for multi-/24 scans. When inactive
    // (priorityCount == 0) the queue pointer stays null and workers use the
    // original lock-free atomic counter — zero overhead for the common case.
    const bool useQueue = options.priorityCount > 0
                       && options.priorityCount < total;
    std::unique_ptr<PriorityWorkQueue> queue =
        useQueue ? std::make_unique<PriorityWorkQueue>(addresses,
                                                       options.priorityCount)
                 : nullptr;

    auto worker = [&]() {
        for (;;) {
            if (cancelFlag.load(std::memory_order_relaxed)) return;

            uint32_t hostIp;
            if (queue) {
                auto ipOpt = queue->next();
                if (!ipOpt) return;          // queue drained
                hostIp = *ipOpt;
            } else {
                const size_t idx =
                    nextIndex.fetch_add(1, std::memory_order_relaxed);
                if (idx >= total) return;
                hostIp = addresses[idx];
            }

            ScanResult r;
            try {
                r = scanOneHost(hostIp, options, cancelFlag,
                                onHost, &probesDone);
            } catch (...) {
                // Defensive: scanOneHost is exception-free today, but if a
                // future change ever lets one slip, mark the host as a clean
                // offline rather than crashing the scan.
                r = ScanResult{};
                r.ipAddress = ip::formatDotted(hostIp);
                r.isOnline  = false;
                RiskAnalyzer::evaluate(r);
            }

            // v1.3.6 — promote this host's /24 the moment it answers, so the
            // rest of a live sibling subnet (tier 4) is scanned before the
            // dead subnets (tier 3). No-op for the local /24 and for the
            // non-queue path.
            if (queue && r.isOnline) queue->markSubnetHot(hostIp);

            // Publish into the shared results vector.
            {
                std::lock_guard<std::mutex> lk(resultsMu);
                results.push_back(r);
            }

            // Fire per-host callback. A throwing callback must NEVER take
            // the scan down, so we wrap it.
            if (onHost) {
                try { onHost(r); }
                catch (...) {}
            }

            const int d = ++doneCount;
            throttle.send(d, static_cast<int>(total), onProgress);
        }
    };

    std::vector<std::thread> workers;
    if (total > 0) {
        workers.reserve(parallel);
        for (size_t i = 0; i < parallel; ++i) {
            workers.emplace_back(worker);
        }
    }
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    // Final progress flush. The throttle may have dropped a sub-100 ms tail
    // call; emit one update so the UI lands on the real terminal value.
    // On Cancel, `doneCount` is the honest number of hosts actually scanned —
    // reporting `total` here would jump the KPI to 100% even when the user
    // stopped at 30%.
    if (onProgress) {
        const int finalDone = cancelFlag.load(std::memory_order_relaxed)
                              ? doneCount.load()
                              : static_cast<int>(total);
        try { onProgress(finalDone, static_cast<int>(total)); }
        catch (...) {}
    }

    // ---- Summary ----
    ScanSummary summary;
    summary.totalScanned = static_cast<int>(results.size());
    summary.rangeUsed    = options.rangeText;
    summary.adapterUsed  = options.adapterLabel;
    summary.presetUsed   = options.presetName;
    summary.timeoutUsed  = options.timeoutMs;
    summary.parallelUsed = options.parallel;
    summary.modeUsed     = options.mode;
    summary.startedAt    = nowLocalStamp();
    summary.durationMs   = sw.elapsedMs();

    // Final order is by numeric IPv4 so reports and exports are stable.
    std::sort(results.begin(), results.end(),
              [](const ScanResult& a, const ScanResult& b) {
        auto av = ip::parseDotted(a.ipAddress).value_or(0);
        auto bv = ip::parseDotted(b.ipAddress).value_or(0);
        return av < bv;
    });

    for (const auto& r : results) {
        if (r.isOnline) ++summary.onlineCount;
        else            ++summary.offlineCount;

        bool seenWeb = false;
        for (const auto& p : r.ports) {
            if (!p.isOpen) continue;
            if (p.port == 3389) ++summary.rdpOpenCount;
            if (p.port == 445)  ++summary.smbOpenCount;
            if (!seenWeb && (p.port == 80   || p.port == 443  ||
                             p.port == 8080 || p.port == 8443 ||
                             p.port == 8000 || p.port == 8888)) {
                ++summary.webOpenCount;
                seenWeb = true;
            }
        }
        if (r.riskLevel == RiskLevel::High)   ++summary.highRiskCount;
        if (r.riskLevel == RiskLevel::Medium) ++summary.mediumRiskCount;
    }

    // Device-type tally across the online hosts — ordered by count descending,
    // with "Unknown" pushed to the end. Surfaced in the CLI summary + HTML.
    for (const auto& r : results) {
        if (!r.isOnline) continue;
        const std::wstring t = r.deviceType.empty() ? std::wstring(L"Unknown")
                                                    : r.deviceType;
        bool found = false;
        for (auto& kv : summary.deviceTypeCounts) {
            if (kv.first == t) { ++kv.second; found = true; break; }
        }
        if (!found) summary.deviceTypeCounts.emplace_back(t, 1);
    }
    std::sort(summary.deviceTypeCounts.begin(), summary.deviceTypeCounts.end(),
              [](const std::pair<std::wstring,int>& a,
                 const std::pair<std::wstring,int>& b) {
        const bool au = (a.first == L"Unknown");
        const bool bu = (b.first == L"Unknown");
        if (au != bu)             return !au;            // "Unknown" sorts last
        if (a.second != b.second) return a.second > b.second;  // count desc
        return a.first < b.first;                        // then alphabetical
    });

    const bool wasCancelled = cancelFlag.load(std::memory_order_relaxed);
    summary.wasCancelled = wasCancelled;
    if (onFinished) {
        try { onFinished(wasCancelled, summary, results); }
        catch (...) {}
    }
}

} // anonymous namespace

// =============================================================================
// NetworkScanner::start
// =============================================================================

void NetworkScanner::start(const std::vector<uint32_t>& addresses,
                           const ScanOptions& options,
                           HostCallback     onHost,
                           ProgressCallback onProgress,
                           FinishedCallback onFinished)
{
    if (running_.exchange(true)) {
        return;  // already running — refuse a concurrent start.
    }
    // Join a previous run's driver before reassigning so we don't leak threads.
    if (impl_->driver && impl_->driver->joinable()) {
        impl_->driver->join();
    }
    impl_->cancel.store(false);
    probesDone_.store(0);

    try {
    impl_->driver = std::make_unique<std::thread>(
        [this, addresses, options, onHost, onProgress, onFinished]() {

        // RAII guard — running_ MUST flip back to false on every exit path,
        // including unexpected exceptions from third-party callbacks or
        // transient OS failures during thread startup.
        struct RunningGuard {
            std::atomic<bool>& flag;
            ~RunningGuard() { flag.store(false); }
        } guard{running_};

        try {
            executeScanLoop(addresses, options, impl_->cancel, probesDone_,
                            onHost, onProgress, onFinished);
        } catch (const std::exception&) {
            // executeScanLoop wraps every external call internally — landing
            // here means STL itself failed (e.g. std::thread constructor
            // couldn't create a worker). Surface the failure to the caller
            // so its wait-for-completion logic terminates cleanly.
            if (onFinished) {
                ScanSummary errSummary;
                errSummary.wasCancelled = true;
                try { onFinished(true, errSummary, std::vector<ScanResult>{}); }
                catch (...) {}
            }
        } catch (...) {
            if (onFinished) {
                ScanSummary errSummary;
                errSummary.wasCancelled = true;
                try { onFinished(true, errSummary, std::vector<ScanResult>{}); }
                catch (...) {}
            }
        }
    });
    } catch (...) {
        // The driver thread itself couldn't be created (std::system_error /
        // bad_alloc). The RAII guard lives INSIDE the lambda, so it never ran
        // — running_ would stay stuck true and the exception would unwind out
        // through the C ABI. Clear the flag so a retry is possible and notify
        // the caller's wait-for-completion logic.
        running_.store(false);
        if (onFinished) {
            ScanSummary errSummary;
            errSummary.wasCancelled = true;
            try { onFinished(true, errSummary, std::vector<ScanResult>{}); }
            catch (...) {}
        }
    }
}

} // namespace lanscope
