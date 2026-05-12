#include "PortScanner.h"

#include "ScanPresetService.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>

namespace netlens {

namespace {

// Bound how many sockets we keep in flight at once. fd_set on Windows defaults
// to FD_SETSIZE = 64; 32 leaves room for the rest of the worker's overhead.
constexpr size_t kBatchSize = 32;

struct Probe {
    SOCKET sock;
    size_t outIndex;
};

} // anonymous namespace

// =============================================================================
// scanHost
//
//   For each batch of up to kBatchSize ports:
//     1) Open one non-blocking socket per port and issue connect().
//        Instant connects (loopback / very fast services) are recorded right
//        there and the socket is closed.
//     2) Sockets that returned WSAEWOULDBLOCK go into a probe table.
//     3) One select() call waits on every in-flight probe with a single
//        timeout window — this collapses N serial timeouts into 1.
//     4) Sockets that are writable AND have SO_ERROR == 0 are open; the rest
//        are closed.
//
//   This is the single biggest perf win over the previous "serial connect-
//   with-timeout" loop: an offline host with a 4-port discovery set now
//   takes one timeout window (~400 ms) instead of four (~1.6 s).
// =============================================================================
std::vector<PortStatus> PortScanner::scanHost(
    uint32_t hostOrderIp,
    const std::vector<int>& ports,
    int timeoutMs,
    const std::atomic<bool>& cancel,
    std::atomic<int64_t>* probesDone,
    const OpenPortsCallback& onOpenPorts)
{
    std::vector<PortStatus> out(ports.size());
    size_t openCount = 0;

    if (timeoutMs <= 0) timeoutMs = 400;

    // Pre-fill output with closed entries so partial cancellation still
    // returns one PortStatus per requested port.
    for (size_t i = 0; i < ports.size(); ++i) {
        out[i].port    = ports[i];
        out[i].service = ScanPresetService::serviceFor(ports[i]);
        out[i].isOpen  = false;
    }

    for (size_t batchStart = 0; batchStart < ports.size(); batchStart += kBatchSize) {
        if (cancel.load(std::memory_order_relaxed)) break;

        size_t batchEnd = std::min(batchStart + kBatchSize, ports.size());

        Probe probes[kBatchSize];
        size_t probeCount = 0;

        // ---- Phase 1: open sockets + issue connects ----
        for (size_t i = batchStart; i < batchEnd; ++i) {
            int port = ports[i];
            if (port < 1 || port > 65535) continue;

            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) continue;

            u_long nonBlocking = 1;
            if (::ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
                ::closesocket(s);
                continue;
            }

            sockaddr_in addr{};
            addr.sin_family           = AF_INET;
            addr.sin_port             = htons(static_cast<u_short>(port));
            addr.sin_addr.S_un.S_addr = htonl(hostOrderIp);

            int rc = ::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            if (rc == 0) {
                // Instant connect — port is definitely open.
                out[i].isOpen = true;
                ::closesocket(s);
                continue;
            }
            int err = ::WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                // Refused / unreachable — definitive closed.
                ::closesocket(s);
                continue;
            }

            probes[probeCount++] = Probe{s, i};
        }

        // ---- Phase 2: single select() over the whole probe batch ----
        if (probeCount > 0) {
            fd_set wset, eset;
            FD_ZERO(&wset);
            FD_ZERO(&eset);
            for (size_t i = 0; i < probeCount; ++i) {
                FD_SET(probes[i].sock, &wset);
                FD_SET(probes[i].sock, &eset);
            }

            timeval tv{};
            tv.tv_sec  = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;

            int sel = ::select(0, nullptr, &wset, &eset, &tv);

            if (sel > 0) {
                for (size_t i = 0; i < probeCount; ++i) {
                    SOCKET sk = probes[i].sock;
                    size_t idx = probes[i].outIndex;
                    if (FD_ISSET(sk, &eset)) continue;
                    if (FD_ISSET(sk, &wset)) {
                        int sockErr = 0;
                        int len     = static_cast<int>(sizeof(sockErr));
                        if (::getsockopt(sk, SOL_SOCKET, SO_ERROR,
                                         reinterpret_cast<char*>(&sockErr), &len) == 0
                            && sockErr == 0)
                        {
                            out[idx].isOpen = true;
                        }
                    }
                }
            }
            // sel == 0 (timeout) or SOCKET_ERROR → all remaining probes stay closed.
        }

        // ---- Phase 3: close every in-flight probe socket ----
        for (size_t i = 0; i < probeCount; ++i) {
            ::closesocket(probes[i].sock);
        }

        // ---- Phase 4: contribute to global probe counter ----
        // We count every port we attempted in this batch (including instant
        // connects and refused). When cancellation hits before the batch
        // starts, those ports stay closed in `out` and are NOT counted —
        // the caller's progress should reflect actual work performed, not
        // skipped work.
        if (probesDone) {
            probesDone->fetch_add(static_cast<int64_t>(batchEnd - batchStart),
                                  std::memory_order_relaxed);
        }

        // ---- Phase 5: emit open-ports snapshot if anything new ----
        // Only fire when the open count grows — closed ports are not news.
        // We pack into a small vector (open-only) so the receiver doesn't
        // shuttle 64KB+ of closed-port noise across the worker→UI boundary
        // every 400 ms on an All-Ports sweep.
        if (onOpenPorts) {
            size_t batchOpenAdded = 0;
            for (size_t i = batchStart; i < batchEnd; ++i) {
                if (out[i].isOpen) ++batchOpenAdded;
            }
            if (batchOpenAdded > 0) {
                openCount += batchOpenAdded;
                std::vector<PortStatus> openOnly;
                openOnly.reserve(openCount);
                for (size_t i = 0; i < batchEnd; ++i) {
                    if (out[i].isOpen) openOnly.push_back(out[i]);
                }
                try { onOpenPorts(openOnly); } catch (...) {}
            }
        }
    }

    return out;
}

} // namespace netlens
