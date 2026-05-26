#pragma once

#include "../Models.h"

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace lanscope {

/// Coordinates the per-host pipeline (ping → ports → DNS → MAC → risk) with
/// bounded parallelism and cooperative cancellation. Used by both the GUI and
/// CLI front ends.
class NetworkScanner {
public:
    /// Callback fired once per host on a worker thread. Implementations must
    /// be thread-safe (the GUI marshals into the UI thread via PostMessage).
    using HostCallback     = std::function<void(const ScanResult&)>;
    /// Callback fired after each host completes: done count, total count.
    using ProgressCallback = std::function<void(int /*done*/, int /*total*/)>;
    /// Callback fired when the scan finishes (or is cancelled).
    using FinishedCallback = std::function<void(bool /*cancelled*/, const ScanSummary&,
                                                const std::vector<ScanResult>&)>;

    NetworkScanner();
    ~NetworkScanner();

    NetworkScanner(const NetworkScanner&)            = delete;
    NetworkScanner& operator=(const NetworkScanner&) = delete;

    /// Kicks off an asynchronous scan. Returns immediately; callbacks fire on
    /// worker threads as work progresses.
    void start(const std::vector<uint32_t>& addresses,
               const ScanOptions& options,
               HostCallback     onHost,
               ProgressCallback onProgress,
               FinishedCallback onFinished);

    /// Cooperative cancel. Safe to call from the UI thread while a scan is
    /// running. After it returns, the finished callback will still fire to
    /// flush partial results.
    void cancel();

    /// Returns true while a scan is in flight.
    [[nodiscard]] bool isRunning() const { return running_.load(); }

    /// Total number of TCP probes (open / closed / unreachable / timed-out)
    /// performed so far across all workers. Updated live during the scan.
    /// The GUI uses this to drive a work-progress % that stays meaningful for
    /// long-tailed scans like the All-Ports preset, where host-level progress
    /// flatlines at 95-ish % while online hosts grind through their ports.
    [[nodiscard]] int64_t probesDone() const { return probesDone_.load(); }

private:
    struct Impl;
    std::unique_ptr<Impl>  impl_;
    std::atomic<bool>      running_{false};
    std::atomic<int64_t>   probesDone_{0};
};

} // namespace lanscope
