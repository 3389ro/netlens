#include "LocalProcessResolver.h"

#include "NetworkAdapterService.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <psapi.h>

#include <chrono>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

namespace lanscope {

namespace {

struct Cache {
    std::mutex mu;
    std::unordered_map<int, uint32_t>     portToPid;   // port → PID
    std::unordered_map<uint32_t, LocalProcessResolver::PortOwner> pidCache;
    std::chrono::steady_clock::time_point lastRefresh{};
};

Cache& cache() {
    static Cache c;
    return c;
}

constexpr std::chrono::milliseconds kRefreshWindow{500};

void refreshTcpTable() {
    DWORD size = 0;
    ::GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                           TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (size < sizeof(DWORD)) return;

    std::vector<uint8_t> buf;
    for (int attempt = 0; attempt < 4; ++attempt) {
        buf.assign(size, 0);
        DWORD rc = ::GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                                           TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (rc == NO_ERROR) break;
        if (rc == ERROR_INSUFFICIENT_BUFFER) continue;
        return;
    }
    if (buf.size() < sizeof(DWORD)) return;

    auto& c = cache();
    c.portToPid.clear();

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    DWORD reported = table->dwNumEntries;
    size_t maxRows = (buf.size() - sizeof(DWORD)) / sizeof(MIB_TCPROW_OWNER_PID);
    DWORD n = static_cast<DWORD>(std::min<size_t>(reported, maxRows));
    for (DWORD i = 0; i < n; ++i) {
        const auto& row = table->table[i];
        int port = static_cast<int>(ntohs(static_cast<u_short>(row.dwLocalPort)));
        c.portToPid[port] = row.dwOwningPid;
    }
}

LocalProcessResolver::PortOwner resolvePid(uint32_t pid) {
    LocalProcessResolver::PortOwner out;
    out.pid = pid;
    if (pid == 0) { out.errorNote = L"System Idle";    return out; }
    if (pid == 4) { out.errorNote = L"System (kernel)"; return out; }

    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) { out.errorNote = L"needs admin"; return out; }

    std::vector<wchar_t> buf(1024);
    DWORD sz = static_cast<DWORD>(buf.size());
    if (::QueryFullProcessImageNameW(h, 0, buf.data(), &sz)) {
        out.exePath.assign(buf.data(), sz);
    } else {
        // Retry once at the extended-path limit.
        buf.assign(32768, 0);
        sz = static_cast<DWORD>(buf.size());
        if (::QueryFullProcessImageNameW(h, 0, buf.data(), &sz)) {
            out.exePath.assign(buf.data(), sz);
        } else {
            out.errorNote = L"path unavailable";
        }
    }
    ::CloseHandle(h);
    return out;
}

} // anonymous namespace

LocalProcessResolver::PortOwner LocalProcessResolver::lookup(int port) {
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mu);

    auto now = std::chrono::steady_clock::now();
    if ((now - c.lastRefresh) >= kRefreshWindow) {
        refreshTcpTable();
        c.lastRefresh = now;
    }

    PortOwner empty;
    auto it = c.portToPid.find(port);
    if (it == c.portToPid.end()) return empty;

    uint32_t pid = it->second;
    auto pit = c.pidCache.find(pid);
    if (pit != c.pidCache.end()) return pit->second;

    PortOwner po = resolvePid(pid);
    c.pidCache[pid] = po;
    return po;
}

void LocalProcessResolver::resetCache() {
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mu);
    c.portToPid.clear();
    c.pidCache.clear();
    c.lastRefresh = {};
}

namespace {

struct IpCache {
    std::mutex mu;
    std::unordered_set<std::wstring>  ips;
    std::chrono::steady_clock::time_point lastRefresh{};
};

IpCache& ipCache() {
    static IpCache c;
    return c;
}

constexpr std::chrono::seconds kIpRefreshWindow{5};

} // anonymous namespace

bool LocalProcessResolver::isLocalIp(const std::wstring& ip) {
    if (ip.empty()) return false;
    if (ip == L"127.0.0.1" || ip == L"0.0.0.0") return true;

    auto& c = ipCache();
    std::lock_guard<std::mutex> lk(c.mu);
    auto now = std::chrono::steady_clock::now();
    if ((now - c.lastRefresh) >= kIpRefreshWindow) {
        c.ips.clear();
        for (const auto& a : NetworkAdapterService::enumerate()) {
            if (!a.ipv4.empty()) c.ips.insert(a.ipv4);
        }
        c.lastRefresh = now;
    }
    return c.ips.count(ip) > 0;
}

} // namespace lanscope
