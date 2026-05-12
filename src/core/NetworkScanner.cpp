#include "NetworkScanner.h"

#include "../AppConstants.h"
#include "DnsResolver.h"
#include "IpAddressUtils.h"
#include "MacResolver.h"
#include "PingService.h"
#include "PortScanner.h"
#include "RiskAnalyzer.h"
#include "Stopwatch.h"
#include "UdpProbes.h"
#include "VendorPortProfiles.h"
#include "VendorResolver.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <exception>
#include <mutex>
#include <thread>
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

namespace netlens {

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
        auto p = PingService::ping(hostIp, opts.timeoutMs);
        if (p.success) {
            r.isOnline       = true;
            r.responseTimeMs = p.roundTripMs;
            r.discovery      = DiscoveryMethod::Icmp;
        }
    }

    // ---- 2) Early emit on ICMP-online ----
    // We push a partial result the moment ICMP confirms the host so the
    // "Online hosts" KPI + the new row appear immediately, even before the
    // (potentially minutes-long) port scan finishes.
    if (r.isOnline) emit();

    // ---- 3) MAC + Vendor (cheap on LAN, runs BEFORE the slow port scan) ---
    // Vendor lookup is a pure in-memory hash against the embedded OUI table.
    // MacResolver issues an ARP request — milliseconds on the same broadcast
    // domain. We do these first so the row shows real device info while the
    // long port sweep runs in the background.
    if (r.isOnline && !opts.skipMac && !cancel.load(std::memory_order_relaxed)) {
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

    // ---- 4b) UDP service enrichment (NBSTAT / mDNS / SSDP / SNMP / DNS-version / NTP)
    // Single shared-timeout fan-out across the six well-known UDP service
    // ports. Catches IoT, printers, NAS, VoIP boxes, network gear that TCP
    // scanning typically misses, and gives us a NetBIOS-name fallback when
    // reverse DNS is unhelpful.
    if (r.isOnline && !opts.skipUdp && !cancel.load(std::memory_order_relaxed)) {
        r.udp = UdpProbes::probe(hostIp, opts.timeoutMs, cancel, probesDone);
        if (r.udp.anyOpen()) emit();
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
        //
        // Vendor-priority bias: if the OUI lookup matched a profile (Dahua,
        // MikroTik, VMware, Synology, etc. — see VendorPortProfiles.cpp),
        // we promote that profile's ports to the front of THIS host's scan
        // list, then append the user's list with duplicates removed. The
        // user's overall port selection is preserved; only the per-host
        // order shifts so vendor-specific services appear first in the UI.
        if (wantPorts && !cancel.load(std::memory_order_relaxed)) {
            const std::vector<int>* portsToScan = &opts.ports;
            std::vector<int> merged;
            if (!r.vendor.empty()) {
                if (const auto* prof = VendorPortProfiles::match(r.vendor)) {
                    merged = VendorPortProfiles::mergePorts(prof->ports, opts.ports);
                    portsToScan = &merged;
                }
            }
            auto full = PortScanner::scanHost(hostIp, *portsToScan,
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
                    if (!opts.skipUdp && !cancel.load(std::memory_order_relaxed)) {
                        r.udp = UdpProbes::probe(hostIp, opts.timeoutMs, cancel, probesDone);
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
                    if (!opts.skipUdp && !cancel.load(std::memory_order_relaxed)) {
                        r.udp = UdpProbes::probe(hostIp, opts.timeoutMs, cancel, probesDone);
                    }
                }
                break;
            }
        }
    }

    // ---- 6) Risk analysis (always runs, final pass) ----
    // Offline hosts get: Status=Offline / Risk=None / hint="Device unreachable".
    RiskAnalyzer::evaluate(r);

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

            // Claim the slot. If another thread beat us, drop this call —
            // the winner published an equal-or-newer state.
            if (!lastDone_.compare_exchange_strong(prevDone, done,
                                                   std::memory_order_acq_rel)) {
                return;
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

    auto worker = [&]() {
        for (;;) {
            if (cancelFlag.load(std::memory_order_relaxed)) return;

            const size_t idx = nextIndex.fetch_add(1, std::memory_order_relaxed);
            if (idx >= total) return;

            ScanResult r;
            try {
                r = scanOneHost(addresses[idx], options, cancelFlag,
                                onHost, &probesDone);
            } catch (...) {
                // Defensive: scanOneHost is exception-free today, but if a
                // future change ever lets one slip, mark the host as a clean
                // offline rather than crashing the scan.
                r = ScanResult{};
                r.ipAddress = ip::formatDotted(addresses[idx]);
                r.isOnline  = false;
                RiskAnalyzer::evaluate(r);
            }

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

    // Always emit one final progress update with done == total. The throttle
    // may have dropped a sub-100 ms tail call.
    if (onProgress) {
        try { onProgress(static_cast<int>(total), static_cast<int>(total)); }
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
}

} // namespace netlens
