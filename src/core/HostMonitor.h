#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace netlens {

// =============================================================================
// Continuous single-host monitor — used by the Monitor Window to track a
// chosen host with periodic probes (ICMP, TCP connect, HTTP TTFB) and keep
// a rolling buffer of latency samples for live charting and statistics.
// =============================================================================

enum class ProbeType {
    Icmp,     ///< ICMP echo (latency = RTT)
    Tcp,      ///< TCP connect to a port (latency = handshake time)
    Http,     ///< HTTP GET / on a port (latency = time-to-first-byte; reports status code)
    Https     ///< HTTPS (same as HTTP but over TLS)
};

inline const wchar_t* ProbeTypeToString(ProbeType t) {
    switch (t) {
        case ProbeType::Icmp:  return L"ICMP";
        case ProbeType::Tcp:   return L"TCP";
        case ProbeType::Http:  return L"HTTP";
        case ProbeType::Https: return L"HTTPS";
    }
    return L"ICMP";
}

struct MonitorSample {
    // Wall-clock relative-to-monitor-start ms (so the chart x-axis is stable
    // even when the OS clock skews).
    int64_t  tMs       = 0;
    bool     success   = false;
    int      latencyMs = -1;   ///< -1 on timeout / fail
    int      statusCode = 0;   ///< HTTP/HTTPS only
};

struct MonitorConfig {
    std::wstring ip;
    std::wstring hostname;     ///< display label
    ProbeType    type     = ProbeType::Icmp;
    int          port     = 80;
    int          intervalMs = 1000;
    int          timeoutMs = 800;
};

class HostMonitor {
public:
    /// Callback fired on the worker thread after each probe completes.
    /// Implementations must be thread-safe; the UI side typically PostMessages
    /// from here into the GUI thread for chart updates.
    using SampleCallback = std::function<void(const MonitorSample&)>;

    HostMonitor(MonitorConfig cfg, SampleCallback cb);
    ~HostMonitor();

    HostMonitor(const HostMonitor&)            = delete;
    HostMonitor& operator=(const HostMonitor&) = delete;

    void start();
    void stop();
    void pause();
    void resume();
    [[nodiscard]] bool isPaused()  const { return paused_.load(); }
    [[nodiscard]] bool isRunning() const { return running_.load(); }

    /// Live-update settings on a running monitor. Takes effect on the next
    /// probe iteration. Safe to call from the UI thread.
    void setConfig(const MonitorConfig& cfg);
    [[nodiscard]] MonitorConfig config() const;

    /// Last-N samples (newest at back). Caller may copy under our mutex.
    [[nodiscard]] std::deque<MonitorSample> snapshot() const;

    /// Rolling stats summary computed on demand.
    struct Stats {
        int     samples    = 0;
        int     successes  = 0;
        int     failures   = 0;
        int     lastMs     = -1;
        int     minMs      = -1;
        int     maxMs      = -1;
        double  avgMs      = 0.0;
        double  uptimePct  = 0.0;   ///< 0..100
    };
    [[nodiscard]] Stats stats() const;

    /// Wipe history without stopping the worker.
    void resetStats();

    /// Path to the auto-save CSV log for this monitor. Set on first start;
    /// empty if logging hasn't begun.
    [[nodiscard]] std::wstring logPath() const;

    /// Auto-saving: every probe sample is appended to a CSV under
    /// %APPDATA%\NetLens\monitors\<sanitized-ip>_<probe>_<timestamp>.csv
    /// Auto-save can't be disabled — the user explicitly wanted always-on
    /// logging so the data is always available without ceremony.

private:
    void workerLoop();
    MonitorSample probeOnce();
    void ensureLogOpen();
    void appendLogRow(const MonitorSample& s);
    static std::wstring sanitizeForFilename(const std::wstring& s);

    MonitorConfig                        cfg_;
    mutable std::mutex                   mu_;          // guards cfg_ + samples_
    std::deque<MonitorSample>            samples_;
    static constexpr size_t              kMaxSamples = 600;  // 10 min at 1Hz

    SampleCallback                       cb_;

    std::thread                          worker_;
    std::atomic<bool>                    running_{false};
    std::atomic<bool>                    paused_{false};
    std::atomic<bool>                    stop_{false};

    std::chrono::steady_clock::time_point startedAt_{};

    // Auto-save CSV log
    mutable std::mutex                   logMu_;
    std::wstring                         logPath_;
    void*                                logFile_ = nullptr;   // HANDLE; void* keeps the header winsock-free
};

} // namespace netlens
