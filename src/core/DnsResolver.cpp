#include "DnsResolver.h"

#include "IpAddressUtils.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <future>
#include <memory>
#include <thread>

namespace netlens {

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

} // anonymous namespace

std::wstring DnsResolver::reverseLookup(uint32_t hostOrderIp, int timeoutMs) {
    // No cap requested → block the worker on the OS call directly. This is
    // the cheapest path; only used when callers explicitly opt out of the cap.
    if (timeoutMs <= 0) {
        return blockingLookup(hostOrderIp);
    }

    // Hand the actual lookup off to a detached thread and time-bound the wait.
    // The thread keeps running on timeout, but the worker returns promptly.
    auto promise = std::make_shared<std::promise<std::wstring>>();
    auto future  = promise->get_future();

    std::thread([promise, hostOrderIp]() {
        try {
            promise->set_value(blockingLookup(hostOrderIp));
        } catch (...) {
            try { promise->set_value(std::wstring{}); }
            catch (...) { /* future already satisfied — ignore */ }
        }
    }).detach();

    auto status = future.wait_for(std::chrono::milliseconds(timeoutMs));
    if (status == std::future_status::ready) {
        try { return future.get(); }
        catch (...) { return std::wstring{}; }
    }
    // Timed out — abandon the OS thread's result and report "no hostname".
    return std::wstring{};
}

} // namespace netlens
