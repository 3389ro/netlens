#include "HostMonitor.h"

#include "IpAddressUtils.h"
#include "PingService.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <shlobj.h>

#include <algorithm>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

namespace netlens {

namespace {

// -----------------------------------------------------------------------------
// Probe implementations
// -----------------------------------------------------------------------------

MonitorSample probeIcmp(const MonitorConfig& cfg) {
    MonitorSample out;
    out.success = false;
    out.latencyMs = -1;

    auto ipOpt = ip::parseDotted(cfg.ip);
    if (!ipOpt) return out;

    auto p = PingService::ping(ipOpt.value(), cfg.timeoutMs);
    out.success = p.success;
    if (p.success) out.latencyMs = static_cast<int>(p.roundTripMs);
    return out;
}

MonitorSample probeTcp(const MonitorConfig& cfg) {
    MonitorSample out;
    out.success = false;
    out.latencyMs = -1;

    auto ipOpt = ip::parseDotted(cfg.ip);
    if (!ipOpt) return out;

    const int timeoutMs = std::max(50, cfg.timeoutMs);
    auto t0 = std::chrono::steady_clock::now();

    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return out;

    u_long nonBlocking = 1;
    if (::ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        ::closesocket(s);
        return out;
    }

    sockaddr_in addr{};
    addr.sin_family           = AF_INET;
    addr.sin_port             = htons(static_cast<u_short>(cfg.port));
    addr.sin_addr.S_un.S_addr = htonl(ipOpt.value());

    int rc = ::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int err = (rc == 0) ? 0 : ::WSAGetLastError();
    if (rc != 0 && err != WSAEWOULDBLOCK) {
        ::closesocket(s);
        return out;
    }
    if (rc == 0) {
        // Instant connect — port open (loopback or very fast).
        auto t1 = std::chrono::steady_clock::now();
        out.success = true;
        out.latencyMs = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        ::closesocket(s);
        return out;
    }

    fd_set wset, eset;
    FD_ZERO(&wset);
    FD_ZERO(&eset);
    FD_SET(s, &wset);
    FD_SET(s, &eset);

    timeval tv{};
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int sel = ::select(0, nullptr, &wset, &eset, &tv);
    if (sel > 0 && FD_ISSET(s, &wset) && !FD_ISSET(s, &eset)) {
        int sockErr = 0;
        int len = static_cast<int>(sizeof(sockErr));
        if (::getsockopt(s, SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char*>(&sockErr), &len) == 0
            && sockErr == 0)
        {
            auto t1 = std::chrono::steady_clock::now();
            out.success = true;
            out.latencyMs = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        }
    }
    ::closesocket(s);
    return out;
}

MonitorSample probeHttpLike(const MonitorConfig& cfg, bool https) {
    MonitorSample out;
    out.success = false;
    out.latencyMs = -1;
    out.statusCode = 0;

    // WinHTTP wants host as a string, not an IP-as-uint, so we pass cfg.ip
    // directly. WinHttpConnect resolves through the system stack — for raw
    // numeric IPs that's an instant no-op.

    auto t0 = std::chrono::steady_clock::now();

    HINTERNET hSession = ::WinHttpOpen(L"NetLens-Monitor/1.0",
                                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS,
                                       0);
    if (!hSession) return out;

    int timeout = std::max(200, cfg.timeoutMs);
    ::WinHttpSetTimeouts(hSession, timeout, timeout, timeout, timeout);

    HINTERNET hConnect = ::WinHttpConnect(hSession, cfg.ip.c_str(),
                                          static_cast<INTERNET_PORT>(cfg.port),
                                          0);
    if (!hConnect) {
        ::WinHttpCloseHandle(hSession);
        return out;
    }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = ::WinHttpOpenRequest(hConnect, L"GET", L"/",
                                              nullptr,
                                              WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              flags);
    if (!hRequest) {
        ::WinHttpCloseHandle(hConnect);
        ::WinHttpCloseHandle(hSession);
        return out;
    }

    // For HTTPS we relax cert verification — the user is monitoring by IP,
    // which generally trips CN-mismatch on a valid cert. The semantic we
    // care about is "did the server answer?", not "is the cert trusted".
    if (https) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA       |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        ::WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                           &secFlags, sizeof(secFlags));
    }

    BOOL sent = ::WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                                      0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (sent) {
        BOOL got = ::WinHttpReceiveResponse(hRequest, nullptr);
        if (got) {
            auto t1 = std::chrono::steady_clock::now();
            out.latencyMs = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

            DWORD status = 0;
            DWORD sz = sizeof(status);
            if (::WinHttpQueryHeaders(hRequest,
                                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                       WINHTTP_HEADER_NAME_BY_INDEX,
                                       &status, &sz,
                                       WINHTTP_NO_HEADER_INDEX))
            {
                out.statusCode = static_cast<int>(status);
                // Anything from 100..599 means the server spoke HTTP. We
                // treat the probe as successful even on 4xx/5xx so the
                // chart still draws — the status code tells the user the
                // service is up but returning errors.
                out.success = (status >= 100 && status < 600);
            }
        }
    }

    ::WinHttpCloseHandle(hRequest);
    ::WinHttpCloseHandle(hConnect);
    ::WinHttpCloseHandle(hSession);
    return out;
}

} // anonymous namespace

// =============================================================================
// HostMonitor
// =============================================================================

HostMonitor::HostMonitor(MonitorConfig cfg, SampleCallback cb)
    : cfg_(std::move(cfg)), cb_(std::move(cb)) {}

HostMonitor::~HostMonitor() {
    stop();
}

void HostMonitor::start() {
    if (running_.exchange(true)) return;
    stop_.store(false);
    paused_.store(false);
    startedAt_ = std::chrono::steady_clock::now();
    ensureLogOpen();
    worker_ = std::thread(&HostMonitor::workerLoop, this);
}

void HostMonitor::stop() {
    if (!running_.exchange(false)) return;
    stop_.store(true);
    if (worker_.joinable()) worker_.join();

    std::lock_guard<std::mutex> lk(logMu_);
    if (logFile_) {
        ::CloseHandle(static_cast<HANDLE>(logFile_));
        logFile_ = nullptr;
    }
}

std::wstring HostMonitor::logPath() const {
    std::lock_guard<std::mutex> lk(logMu_);
    return logPath_;
}

std::wstring HostMonitor::sanitizeForFilename(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) {
        if ((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z') ||
            (c >= L'A' && c <= L'Z') || c == L'.' || c == L'-' || c == L'_')
        {
            out.push_back(c);
        } else {
            out.push_back(L'_');
        }
    }
    return out;
}

void HostMonitor::ensureLogOpen() {
    std::lock_guard<std::mutex> lk(logMu_);
    if (logFile_) return;

    // %APPDATA%\NetLens\monitors (path is built below).
    wchar_t appData[MAX_PATH] = {};
    if (FAILED(::SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr,
                                   SHGFP_TYPE_CURRENT, appData))) {
        return;
    }
    std::wstring dir = std::wstring(appData) + L"\\NetLens\\monitors";
    // Create both levels (NetLens and monitors) — ignore "already exists".
    ::CreateDirectoryW((std::wstring(appData) + L"\\NetLens").c_str(), nullptr);
    ::CreateDirectoryW(dir.c_str(), nullptr);

    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t ts[32];
    std::wcsftime(ts, 32, L"%Y%m%d-%H%M%S", &tm);

    std::wstring ipPart = sanitizeForFilename(cfg_.ip);
    const wchar_t* probe = ProbeTypeToString(cfg_.type);
    logPath_ = dir + L"\\" + ipPart + L"_" + probe + L"_" + ts + L".csv";

    HANDLE h = ::CreateFileW(logPath_.c_str(),
                              FILE_APPEND_DATA, FILE_SHARE_READ,
                              nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        logFile_ = nullptr;
        logPath_.clear();
        return;
    }
    logFile_ = h;

    // CSV header (UTF-8 with BOM so Excel detects encoding properly).
    const char hdr[] = "\xEF\xBB\xBFtimestamp_iso,t_ms,probe,target,port,success,latency_ms,status_code\r\n";
    DWORD written = 0;
    ::WriteFile(h, hdr, static_cast<DWORD>(sizeof(hdr) - 1), &written, nullptr);
}

void HostMonitor::appendLogRow(const MonitorSample& s) {
    HANDLE h = nullptr;
    MonitorConfig cfgCopy;
    {
        std::lock_guard<std::mutex> lk(logMu_);
        h = static_cast<HANDLE>(logFile_);
        if (!h) return;
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        cfgCopy = cfg_;
    }

    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    char isoBuf[32];
    std::strftime(isoBuf, 32, "%Y-%m-%dT%H:%M:%S", &tm);

    // Convert IP wstring → narrow ASCII (IPs are ASCII anyway).
    char ipNarrow[128] = {};
    {
        size_t n = std::min(cfgCopy.ip.size(), size_t(sizeof(ipNarrow) - 1));
        for (size_t i = 0; i < n; ++i) {
            wchar_t c = cfgCopy.ip[i];
            ipNarrow[i] = (c < 128) ? static_cast<char>(c) : '?';
        }
    }

    const char* probe = "ICMP";
    switch (cfgCopy.type) {
        case ProbeType::Icmp:  probe = "ICMP"; break;
        case ProbeType::Tcp:   probe = "TCP";  break;
        case ProbeType::Http:  probe = "HTTP"; break;
        case ProbeType::Https: probe = "HTTPS"; break;
    }

    char line[256];
    int len = std::snprintf(line, sizeof(line),
        "%s,%lld,%s,%s,%d,%d,%d,%d\r\n",
        isoBuf,
        static_cast<long long>(s.tMs),
        probe,
        ipNarrow,
        cfgCopy.port,
        s.success ? 1 : 0,
        s.latencyMs,
        s.statusCode);

    if (len > 0) {
        DWORD written = 0;
        std::lock_guard<std::mutex> lk(logMu_);
        if (logFile_) {
            ::WriteFile(static_cast<HANDLE>(logFile_),
                        line, static_cast<DWORD>(len),
                        &written, nullptr);
        }
    }
}

void HostMonitor::pause()  { paused_.store(true);  }
void HostMonitor::resume() { paused_.store(false); }

void HostMonitor::setConfig(const MonitorConfig& cfg) {
    std::lock_guard<std::mutex> lk(mu_);
    cfg_ = cfg;
}

MonitorConfig HostMonitor::config() const {
    std::lock_guard<std::mutex> lk(mu_);
    return cfg_;
}

std::deque<MonitorSample> HostMonitor::snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    return samples_;
}

HostMonitor::Stats HostMonitor::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    Stats st;
    if (samples_.empty()) return st;
    int64_t sum = 0;
    for (const auto& s : samples_) {
        ++st.samples;
        if (s.success) {
            ++st.successes;
            if (st.minMs < 0 || s.latencyMs < st.minMs) st.minMs = s.latencyMs;
            if (s.latencyMs > st.maxMs) st.maxMs = s.latencyMs;
            sum += s.latencyMs;
        } else {
            ++st.failures;
        }
    }
    if (st.successes > 0) {
        st.avgMs = static_cast<double>(sum) / st.successes;
    }
    st.lastMs = samples_.back().success ? samples_.back().latencyMs : -1;
    st.uptimePct = (st.samples > 0)
                   ? (100.0 * st.successes / st.samples)
                   : 0.0;
    return st;
}

void HostMonitor::resetStats() {
    std::lock_guard<std::mutex> lk(mu_);
    samples_.clear();
    startedAt_ = std::chrono::steady_clock::now();
}

void HostMonitor::workerLoop() {
    while (!stop_.load()) {
        // Snapshot config + interval at start of each iteration so live edits
        // from the UI propagate without us having to lock for the whole probe.
        MonitorConfig localCfg;
        {
            std::lock_guard<std::mutex> lk(mu_);
            localCfg = cfg_;
        }

        if (!paused_.load()) {
            MonitorSample s = probeOnce();
            s.tMs = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - startedAt_).count());

            {
                std::lock_guard<std::mutex> lk(mu_);
                samples_.push_back(s);
                while (samples_.size() > kMaxSamples) samples_.pop_front();
            }

            // Always-on CSV logging — every sample, every monitor.
            appendLogRow(s);

            if (cb_) {
                try { cb_(s); } catch (...) {}
            }
        }

        // Sleep in small slices so stop()/pause() responds quickly.
        const int interval = std::max(100, localCfg.intervalMs);
        for (int slept = 0; slept < interval && !stop_.load(); slept += 50) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

MonitorSample HostMonitor::probeOnce() {
    MonitorConfig localCfg;
    {
        std::lock_guard<std::mutex> lk(mu_);
        localCfg = cfg_;
    }
    switch (localCfg.type) {
        case ProbeType::Icmp:  return probeIcmp(localCfg);
        case ProbeType::Tcp:   return probeTcp(localCfg);
        case ProbeType::Http:  return probeHttpLike(localCfg, false);
        case ProbeType::Https: return probeHttpLike(localCfg, true);
    }
    return {};
}

} // namespace netlens
