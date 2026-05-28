#include "DnsResolver.h"

#include "IpAddressUtils.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

namespace lanscope {

namespace {

// Synchronously resolves the PTR record. Caller is responsible for bounding
// the wall-clock time — this function can block for several seconds when the
// OS resolver retries upstream servers.
std::wstring blockingLookup(uint32_t hostOrderIp) {
    sockaddr_in sa{};
    sa.sin_family            = AF_INET;
    sa.sin_addr.S_un.S_addr  = htonl(hostOrderIp);

    wchar_t host[NI_MAXHOST];
    host[0] = L'\0';

    // NI_NAMEREQD makes the call fail (rather than echo back the dotted form)
    // when no PTR record exists, so we don't have to test that case manually.
    int rc = ::GetNameInfoW(
        reinterpret_cast<const sockaddr*>(&sa), sizeof(sa),
        host, NI_MAXHOST,
        nullptr, 0,
        NI_NAMEREQD);
    if (rc != 0) return L"";

    std::wstring result(host);

    // Defensive: if the resolver still echoes the dotted form, treat as
    // "not resolved" rather than confusing the user with a fake hostname.
    if (result == ip::formatDotted(hostOrderIp)) return L"";
    return result;
}

// Bounded counter for detached reverse-DNS workers. GetNameInfoW has
// no native timeout, so the wait is time-bounded in the caller and
// the thread is abandoned when DNS is slow. Without a global cap, a /24 scan
// against a hostile / misconfigured resolver could spawn 250+ OS-resolver
// threads that linger 5–30 s after the scan finished — burning RAM and
// thread handles, and risking a dirty shutdown if the process exits
// while they're still mid-OS-call.
//
// Cap = 16 in-flight lookups. Sized for typical home LANs (5–30 online
// hosts) plus headroom. When saturated, new requests return "" right
// away — losing a hostname for that host is a fine trade for keeping
// the scanner's thread budget bounded.
constexpr int kMaxConcurrentLookups = 16;
std::atomic<int> g_inFlightLookups{0};

} // anonymous namespace

std::wstring DnsResolver::reverseLookup(uint32_t hostOrderIp, int timeoutMs) {
    // No cap requested → block the worker on the OS call directly. This is
    // the cheapest path; only used when callers explicitly opt out of the cap.
    if (timeoutMs <= 0) {
        return blockingLookup(hostOrderIp);
    }

    // Try to reserve a slot in the global in-flight pool. If we can't, the
    // pool is saturated; skip the lookup rather than queue indefinitely.
    int prev = g_inFlightLookups.fetch_add(1, std::memory_order_acq_rel);
    if (prev >= kMaxConcurrentLookups) {
        g_inFlightLookups.fetch_sub(1, std::memory_order_acq_rel);
        return L"";
    }

    // Hand the actual lookup off to a detached thread and time-bound the wait.
    // The thread keeps running on timeout, but the worker returns promptly.
    // The shared_ptr<promise> outlives the future, so set_value() never
    // touches freed memory even if the caller has already moved on.
    auto promise = std::make_shared<std::promise<std::wstring>>();
    auto future  = promise->get_future();

    // v1.3.5 — std::thread construction can throw std::system_error under
    // thread / memory exhaustion. We already fetch_add'd above; if the
    // thread never starts, the matching fetch_sub in the lambda never runs
    // and the in-flight counter drifts up by 1 — over time this would
    // permanently block reverse-DNS by exhausting the slot pool. Wrap the
    // construction in try/catch and roll the counter back on failure.
    try {
        std::thread([promise, hostOrderIp]() {
            try {
                promise->set_value(blockingLookup(hostOrderIp));
            } catch (...) {
                try { promise->set_value(std::wstring{}); }
                catch (...) { /* future already satisfied — ignore */ }
            }
            // Free the slot only after the OS call returns (or throws) so we
            // never undercount and let the pool over-commit.
            g_inFlightLookups.fetch_sub(1, std::memory_order_acq_rel);
        }).detach();
    } catch (...) {
        // OS refused to start a new thread. Roll back the slot reservation
        // and report "no hostname" — caller already handles empty results.
        g_inFlightLookups.fetch_sub(1, std::memory_order_acq_rel);
        return L"";
    }

    auto status = future.wait_for(std::chrono::milliseconds(timeoutMs));
    if (status == std::future_status::ready) {
        try { return future.get(); }
        catch (...) { return std::wstring{}; }
    }
    // Timed out — abandon the OS thread's result and report "no hostname".
    // The slot stays reserved until the detached thread actually returns
    // (which is exactly what we want: it's still consuming a thread handle).
    return std::wstring{};
}

} // namespace lanscope
