#include "PingService.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <array>
#include <vector>

namespace netlens {

namespace {

// 32-byte payload identical to Windows ping.exe.
constexpr std::array<unsigned char, 32> kEchoPayload = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
};

// RAII wrapper for an ICMP handle, used as thread_local so each worker thread
// pays the IcmpCreateFile cost once and reuses the handle for every ping.
class IcmpHandleGuard {
public:
    IcmpHandleGuard() : h_(::IcmpCreateFile()) {}
    ~IcmpHandleGuard() {
        if (h_ != INVALID_HANDLE_VALUE) ::IcmpCloseHandle(h_);
    }
    IcmpHandleGuard(const IcmpHandleGuard&)            = delete;
    IcmpHandleGuard& operator=(const IcmpHandleGuard&) = delete;
    HANDLE get() const { return h_; }
private:
    HANDLE h_;
};

HANDLE getThreadIcmpHandle() {
    thread_local IcmpHandleGuard guard;
    return guard.get();
}

} // anonymous namespace

PingService::Result PingService::ping(uint32_t hostOrderIp, int timeoutMs) {
    Result out{};

    if (timeoutMs <= 0) timeoutMs = 400;

    HANDLE h = getThreadIcmpHandle();
    if (h == INVALID_HANDLE_VALUE) return out;

    const DWORD replySize = static_cast<DWORD>(
        sizeof(ICMP_ECHO_REPLY) + kEchoPayload.size() + 8);

    // Stack buffer — replySize is a small constant (~56 bytes) so we avoid
    // heap allocation per ping.
    unsigned char replyBuf[sizeof(ICMP_ECHO_REPLY) + 32 + 8];
    static_assert(sizeof(replyBuf) >= sizeof(ICMP_ECHO_REPLY) + 32 + 8,
                  "Reply buffer must accommodate full ICMP echo reply.");

    IPAddr dst = htonl(hostOrderIp);

    DWORD ret = ::IcmpSendEcho(
        h,
        dst,
        const_cast<LPVOID>(static_cast<LPCVOID>(kEchoPayload.data())),
        static_cast<WORD>(kEchoPayload.size()),
        nullptr,
        replyBuf,
        replySize,
        static_cast<DWORD>(timeoutMs));

    if (ret > 0) {
        auto* reply = reinterpret_cast<ICMP_ECHO_REPLY*>(replyBuf);
        if (reply->Status == IP_SUCCESS) {
            out.success     = true;
            out.roundTripMs = reply->RoundTripTime;
            if (out.roundTripMs == 0) out.roundTripMs = 1;
        }
    }
    return out;
}

} // namespace netlens
