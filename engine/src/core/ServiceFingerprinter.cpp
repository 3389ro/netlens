#include "ServiceFingerprinter.h"

#include "../AppConstants.h"
#include "IpAddressUtils.h"

// winsock2.h must precede windows.h so the legacy winsock.h is never pulled in.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <lm.h>            // NetRemoteTOD, TIME_OF_DAY_INFO, NetApiBufferFree

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "netapi32.lib")

namespace lanscope {

namespace {

// =============================================================================
// String hygiene — every byte that comes off the wire is treated as hostile.
// =============================================================================

// Converts raw network bytes to a clean wstring: drops control characters and
// non-ASCII bytes, collapses whitespace runs to a single space, hard-caps the
// length. Real protocol banners are ASCII; anything else is noise or an
// injection attempt, so we discard rather than guess an encoding.
std::wstring sanitize(const char* data, size_t len, size_t maxLen) {
    std::wstring out;
    out.reserve(len < maxLen ? len : maxLen);
    for (size_t i = 0; i < len; ++i) {
        if (out.size() >= maxLen) break;
        unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\t' || c == ' ' || c == '\r' || c == '\n') {
            if (!out.empty() && out.back() != L' ') out.push_back(L' ');
        } else if (c >= 0x20 && c < 0x7F) {
            out.push_back(static_cast<wchar_t>(c));
        }
        // control characters and bytes >= 0x7F are dropped
    }
    while (!out.empty() && out.back() == L' ') out.pop_back();
    return out;
}
std::wstring sanitize(const std::string& s, size_t maxLen) {
    return sanitize(s.data(), s.size(), maxLen);
}

// Same hygiene pass for text that already arrived as a wide string (WinHTTP).
std::wstring sanitizeW(const std::wstring& in, size_t maxLen) {
    std::wstring out;
    out.reserve(in.size() < maxLen ? in.size() : maxLen);
    for (wchar_t wc : in) {
        if (out.size() >= maxLen) break;
        if (wc == L'\t' || wc == L' ' || wc == L'\r' || wc == L'\n') {
            if (!out.empty() && out.back() != L' ') out.push_back(L' ');
        } else if (wc >= 0x20 && wc < 0x7F) {
            out.push_back(wc);
        }
    }
    while (!out.empty() && out.back() == L' ') out.pop_back();
    return out;
}

std::string toLowerAscii(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// Case-insensitive substring test (ASCII).
bool containsCi(const std::wstring& hay, const wchar_t* needle) {
    std::wstring h = hay, n = needle;
    auto lo = [](std::wstring& s) {
        for (auto& c : s) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    };
    lo(h); lo(n);
    return h.find(n) != std::wstring::npos;
}

// Finds the first version-looking run ("2.4.58", "9.3", "10.0") in `s`.
std::wstring extractVersion(const std::wstring& s) {
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] < L'0' || s[i] > L'9') continue;
        size_t j = i;
        bool dot = false;
        while (j < s.size() && ((s[j] >= L'0' && s[j] <= L'9') || s[j] == L'.')) {
            if (s[j] == L'.') dot = true;
            ++j;
        }
        if (dot && (j - i) >= 3 && s[i] != L'.' && s[j - 1] != L'.') {
            return s.substr(i, j - i);
        }
        i = j;
    }
    return {};
}

// Narrow an ASCII-only wide string (used for the HTTP Host header).
std::string narrowAscii(const std::wstring& w) {
    std::string s;
    s.reserve(w.size());
    for (wchar_t c : w) if (c > 0 && c < 0x80) s.push_back(static_cast<char>(c));
    return s;
}

std::wstring detectFtpProduct(const std::wstring& b) {
    if (containsCi(b, L"vsFTPd"))        return L"vsftpd";
    if (containsCi(b, L"ProFTPD"))       return L"ProFTPD";
    if (containsCi(b, L"Pure-FTPd"))     return L"Pure-FTPd";
    if (containsCi(b, L"FileZilla"))     return L"FileZilla Server";
    if (containsCi(b, L"Microsoft FTP")) return L"Microsoft FTP";
    if (containsCi(b, L"Serv-U"))        return L"Serv-U";
    return {};
}
std::wstring detectSmtpProduct(const std::wstring& b) {
    if (containsCi(b, L"Postfix"))         return L"Postfix";
    if (containsCi(b, L"Exim"))            return L"Exim";
    if (containsCi(b, L"Sendmail"))        return L"Sendmail";
    if (containsCi(b, L"Exchange"))        return L"Microsoft Exchange";
    if (containsCi(b, L"Microsoft ESMTP")) return L"Microsoft Exchange";
    if (containsCi(b, L"hMailServer"))     return L"hMailServer";
    if (containsCi(b, L"MailEnable"))      return L"MailEnable";
    return {};
}

// =============================================================================
// Timed TCP probe — non-blocking connect + select, every call bounded.
// =============================================================================

class TcpProbe {
public:
    TcpProbe() = default;
    ~TcpProbe() { reset(); }
    TcpProbe(const TcpProbe&)            = delete;
    TcpProbe& operator=(const TcpProbe&) = delete;

    bool connect(uint32_t hostOrderIp, int port, int timeoutMs) {
        reset();
        if (port < 1 || port > 65535) return false;
        s_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s_ == INVALID_SOCKET) return false;

        u_long nb = 1;
        if (::ioctlsocket(s_, FIONBIO, &nb) != 0) { reset(); return false; }

        sockaddr_in addr{};
        addr.sin_family           = AF_INET;
        addr.sin_port             = htons(static_cast<u_short>(port));
        addr.sin_addr.S_un.S_addr = htonl(hostOrderIp);

        int rc = ::connect(s_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (rc == 0) return true;                       // instant connect
        if (::WSAGetLastError() != WSAEWOULDBLOCK) { reset(); return false; }
        if (!waitFd(timeoutMs, true))             { reset(); return false; }

        int err = 0, len = static_cast<int>(sizeof(err));
        if (::getsockopt(s_, SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char*>(&err), &len) != 0 || err != 0) {
            reset();
            return false;
        }
        return true;
    }

    bool sendAll(const std::string& data, int timeoutMs) {
        if (s_ == INVALID_SOCKET) return false;
        size_t sent = 0;
        ULONGLONG deadline = ::GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
        while (sent < data.size()) {
            ULONGLONG now = ::GetTickCount64();
            if (now >= deadline) return false;
            if (!waitFd(static_cast<int>(deadline - now), true)) return false;
            int n = ::send(s_, data.data() + sent,
                           static_cast<int>(data.size() - sent), 0);
            if (n == SOCKET_ERROR) {
                if (::WSAGetLastError() == WSAEWOULDBLOCK) continue;
                return false;
            }
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    // Single select + single recv. For protocols where the server emits a
    // greeting/response packet and then waits (SSH/FTP/SMTP banners, MySQL
    // handshake, TDS prelogin) this avoids burning the whole timeout budget
    // waiting for a connection close that never comes. Returns bytes read,
    // 0 on clean close, -1 on timeout/error.
    int recvChunk(char* buf, int cap, int timeoutMs) {
        if (s_ == INVALID_SOCKET || cap <= 0) return -1;
        if (!waitFd(timeoutMs, false)) return -1;
        int n = ::recv(s_, buf, cap, 0);
        return (n == SOCKET_ERROR) ? -1 : n;
    }

    // Reads into `out` until: stopMarker is seen, maxTotal is reached, the
    // peer closes, or the timeout budget is exhausted. Always bounded. Used
    // for HTTP, where "Connection: close" makes the server hang up after the
    // header block.
    void recvUntil(std::string& out, size_t maxTotal, int timeoutMs,
                   const char* stopMarker) {
        if (s_ == INVALID_SOCKET) return;
        ULONGLONG deadline = ::GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
        char buf[1024];
        for (;;) {
            if (out.size() >= maxTotal) return;
            ULONGLONG now = ::GetTickCount64();
            if (now >= deadline) return;
            if (!waitFd(static_cast<int>(deadline - now), false)) return;
            int want = static_cast<int>(
                std::min<size_t>(sizeof(buf), maxTotal - out.size()));
            int n = ::recv(s_, buf, want, 0);
            if (n == SOCKET_ERROR) {
                if (::WSAGetLastError() == WSAEWOULDBLOCK) continue;
                return;
            }
            if (n <= 0) return;                          // peer closed
            out.append(buf, static_cast<size_t>(n));
            if (stopMarker && out.find(stopMarker) != std::string::npos) return;
        }
    }

    void reset() {
        if (s_ != INVALID_SOCKET) { ::closesocket(s_); s_ = INVALID_SOCKET; }
    }

private:
    // Waits for the socket to become writable (write=true) or readable
    // (write=false), or for an error/timeout. Bounded by timeoutMs.
    bool waitFd(int timeoutMs, bool write) {
        if (s_ == INVALID_SOCKET) return false;
        if (timeoutMs < 0) timeoutMs = 0;
        fd_set fds, efds;
        FD_ZERO(&fds);  FD_ZERO(&efds);
        FD_SET(s_, &fds); FD_SET(s_, &efds);
        timeval tv{};
        tv.tv_sec  = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        int sel = ::select(0, write ? nullptr : &fds,
                              write ? &fds : nullptr, &efds, &tv);
        if (sel <= 0) return false;
        if (FD_ISSET(s_, &efds)) return false;
        return FD_ISSET(s_, &fds) != 0;
    }

    SOCKET s_ = INVALID_SOCKET;
};

// =============================================================================
// Timed UDP query — one datagram out, one datagram in, all bounded.
// =============================================================================

// Returns bytes received (0..respCap) or -1 on any failure. A connected UDP
// socket surfaces ICMP port-unreachable as a recv error, which we treat as
// "no service" (-1) — exactly what we want.
int udpQuery(uint32_t hostOrderIp, int port,
             const char* req, int reqLen,
             char* resp, int respCap, int timeoutMs) {
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return -1;

    sockaddr_in addr{};
    addr.sin_family           = AF_INET;
    addr.sin_port             = htons(static_cast<u_short>(port));
    addr.sin_addr.S_un.S_addr = htonl(hostOrderIp);

    int result = -1;
    do {
        if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
            break;
        if (::send(s, req, reqLen, 0) != reqLen)
            break;

        fd_set fds, efds;
        FD_ZERO(&fds);  FD_ZERO(&efds);
        FD_SET(s, &fds); FD_SET(s, &efds);
        timeval tv{};
        tv.tv_sec  = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        int sel = ::select(0, &fds, nullptr, &efds, &tv);
        if (sel <= 0 || FD_ISSET(s, &efds) || !FD_ISSET(s, &fds))
            break;

        int n = ::recv(s, resp, respCap, 0);
        if (n > 0) result = n;
    } while (false);

    ::closesocket(s);
    return result;
}

// =============================================================================
// NTP timestamp helpers. NTP epoch is 1900-01-01; a 64-bit timestamp is
// 32 bits of seconds + 32 bits of fractional seconds.
// =============================================================================

uint64_t ntpNow() {
    FILETIME ft;
    ::GetSystemTimeAsFileTime(&ft);   // UTC, 100 ns units since 1601-01-01
    uint64_t ft64 = (static_cast<uint64_t>(ft.dwHighDateTime) << 32)
                  | ft.dwLowDateTime;
    // Whole seconds between 1601-01-01 and 1900-01-01.
    constexpr uint64_t kEpochDelta = 9435484800ULL;
    uint64_t totalSec  = ft64 / 10000000ULL;
    uint64_t frac100ns = ft64 % 10000000ULL;
    uint64_t ntpSec    = totalSec - kEpochDelta;
    uint64_t ntpFrac   = (frac100ns << 32) / 10000000ULL;
    return (ntpSec << 32) | (ntpFrac & 0xFFFFFFFFULL);
}
uint64_t readBe64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
int64_t ntpToMs(uint64_t ts) {
    uint64_t sec  = ts >> 32;
    uint64_t frac = ts & 0xFFFFFFFFULL;
    return static_cast<int64_t>(sec * 1000ULL)
         + static_cast<int64_t>((frac * 1000ULL) >> 32);
}

// Local wall clock as milliseconds since the Unix epoch (UTC). Used to bracket
// the NetRemoteTOD call for the offset estimate.
int64_t unixMsNow() {
    FILETIME ft;
    ::GetSystemTimeAsFileTime(&ft);   // UTC, 100 ns units since 1601-01-01
    uint64_t ft64 = (static_cast<uint64_t>(ft.dwHighDateTime) << 32)
                  | ft.dwLowDateTime;
    constexpr uint64_t kUnixEpoch100ns = 116444736000000000ULL;  // 1601 -> 1970
    if (ft64 < kUnixEpoch100ns) return 0;
    return static_cast<int64_t>((ft64 - kUnixEpoch100ns) / 10000ULL);
}

// =============================================================================
// HTTP — raw-socket GET of the root page: response headers plus a bounded
// slice of the body, just enough for the <title>. One request, the root path
// only — never a followed link or a guessed path.
// =============================================================================

// Pulls <title>...</title> out of an HTML body. Bounded, case-insensitive,
// decodes a few common entities, drops stray angle brackets, hard-sanitised —
// the body is hostile input.
std::wstring extractHtmlTitle(const std::string& raw) {
    std::string lower = toLowerAscii(raw);
    size_t ts = lower.find("<title");
    if (ts == std::string::npos) return {};
    size_t gt = raw.find('>', ts);
    if (gt == std::string::npos) return {};
    size_t te  = lower.find("</title>", gt);
    size_t end = (te == std::string::npos)
                 ? (std::min)(raw.size(), gt + 1 + 200)   // bounded if unterminated
                 : te;
    if (end <= gt + 1) return {};
    std::string inner = raw.substr(gt + 1, end - gt - 1);
    if (inner.size() > 200) inner.resize(200);

    std::string decoded;
    decoded.reserve(inner.size());
    for (size_t i = 0; i < inner.size(); ) {
        char c = inner[i];
        if (c == '&') {
            if      (inner.compare(i, 5, "&amp;")  == 0) { decoded += '&';  i += 5; continue; }
            else if (inner.compare(i, 4, "&lt;")   == 0) { decoded += '<';  i += 4; continue; }
            else if (inner.compare(i, 4, "&gt;")   == 0) { decoded += '>';  i += 4; continue; }
            else if (inner.compare(i, 6, "&quot;") == 0) { decoded += '"';  i += 6; continue; }
            else if (inner.compare(i, 6, "&apos;") == 0) { decoded += '\''; i += 6; continue; }
            else if (inner.compare(i, 6, "&#039;") == 0) { decoded += '\''; i += 6; continue; }
            else if (inner.compare(i, 5, "&#39;")  == 0) { decoded += '\''; i += 5; continue; }
            else if (inner.compare(i, 6, "&nbsp;") == 0) { decoded += ' ';  i += 6; continue; }
        }
        if (c == '<' || c == '>') { ++i; continue; }   // drop stray markup
        decoded.push_back(c);
        ++i;
    }
    return sanitize(decoded, 80);
}

// Scans a bounded HTML/HTTP response body for known device / appliance
// management-UI signatures and returns {canonical product, best-effort
// version}, or {empty, empty}. Distinctive substrings only — chosen so they
// don't false-match ordinary web content. When a signature hits, the caller
// promotes it over the generic Server-header product, because "this is the
// VMware ESXi UI" identifies the device far better than "nginx".
std::pair<std::wstring, std::wstring> detectWebApp(const std::string& body) {
    const std::string lo = toLowerAscii(body);
    struct Sig { const char* needle; const wchar_t* name; };
    static const Sig kSigs[] = {
        { "vmware esxi",           L"VMware ESXi" },
        { "esxi",                  L"VMware ESXi" },
        { "vsphere",               L"VMware vSphere" },
        { "proxmox",               L"Proxmox VE" },
        { "idrac",                 L"Dell iDRAC" },
        { "integrated lights-out", L"HPE iLO" },
        { "pfsense",               L"pfSense" },
        { "opnsense",              L"OPNsense" },
        { "openwrt",               L"OpenWrt" },
        { "routeros",              L"MikroTik RouterOS" },
        { "mikrotik",              L"MikroTik" },
        { "diskstation",           L"Synology DSM" },
        { "synology",              L"Synology" },
        { "qnap",                  L"QNAP" },
        { "openmediavault",        L"OpenMediaVault" },
        { "truenas",               L"TrueNAS" },
        { "freenas",               L"TrueNAS" },
        { "home assistant",        L"Home Assistant" },
    };
    for (const auto& s : kSigs) {
        size_t pos = lo.find(s.needle);
        if (pos == std::string::npos) continue;
        std::wstring version;
        // Best-effort version: the first "N.N" run within ~64 chars of the
        // signature (catches "VMware ESXi 7.0", "RouterOS v7.11", …).
        size_t scanEnd = (std::min)(lo.size(), pos + 64);
        for (size_t i = pos; i + 2 < scanEnd; ) {
            if (lo[i] < '0' || lo[i] > '9') { ++i; continue; }
            size_t j = i;
            bool dot = false;
            while (j < scanEnd && ((lo[j] >= '0' && lo[j] <= '9') || lo[j] == '.')) {
                if (lo[j] == '.') dot = true;
                ++j;
            }
            if (dot && j - i >= 3) { version = sanitize(lo.substr(i, j - i), 16); break; }
            i = j;
        }
        return { s.name, version };
    }
    return {};
}

// Parses an HTTP response header block: status line, Server header,
// X-Powered-By. Splits "Apache/2.4.58" into product + version.
ServiceFingerprint parseHttpResponse(int port, const std::string& raw) {
    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"http";
    fp.source     = L"HTTP Server header";
    fp.confidence = L"Low";

    std::string headerBlock = raw;
    size_t blank = raw.find("\r\n\r\n");
    if (blank != std::string::npos) headerBlock = raw.substr(0, blank);

    std::wstring statusLine, serverHdr, poweredBy;
    size_t pos = 0;
    bool first = true;
    while (pos <= headerBlock.size()) {
        size_t eol = headerBlock.find("\r\n", pos);
        if (eol == std::string::npos) eol = headerBlock.size();
        std::string line = headerBlock.substr(pos, eol - pos);
        if (first) {
            statusLine = sanitize(line, 120);
            first = false;
        } else {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string name = toLowerAscii(line.substr(0, colon));
                std::string val  = line.substr(colon + 1);
                size_t v0 = val.find_first_not_of(" \t");
                val = (v0 == std::string::npos) ? std::string() : val.substr(v0);
                if      (name == "server")       serverHdr = sanitize(val, 120);
                else if (name == "x-powered-by") poweredBy = sanitize(val, 80);
            }
        }
        if (eol == headerBlock.size()) break;
        pos = eol + 2;
    }

    if (!serverHdr.empty()) {
        // First whitespace-delimited token, e.g. "Apache/2.4.58".
        std::wstring token = serverHdr;
        size_t sp = token.find(L' ');
        if (sp != std::wstring::npos) token = token.substr(0, sp);
        size_t slash = token.find(L'/');
        std::wstring prod = (slash == std::wstring::npos) ? token
                                                          : token.substr(0, slash);
        std::wstring ver  = (slash == std::wstring::npos) ? std::wstring()
                                                          : token.substr(slash + 1);
        if (prod == L"Microsoft-IIS") prod = L"Microsoft IIS";
        fp.product    = prod;
        fp.version    = extractVersion(ver.empty() ? serverHdr : ver);
        fp.detail     = L"Server: " + serverHdr;
        if (!poweredBy.empty()) fp.detail += L"; X-Powered-By: " + poweredBy;
        fp.confidence = L"High";
    } else if (!statusLine.empty()) {
        fp.detail     = statusLine;
        fp.confidence = L"Medium";
    } else {
        fp.port = 0;                 // not recognisable HTTP — caller drops it
    }
    return fp;
}

ServiceFingerprint fingerprintHttp(uint32_t ipHost, const std::wstring& ipText,
                                   int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};

    // Minimal, well-formed GET for the root page. "Connection: close" lets the
    // server hang up cleanly. We read a bounded chunk — enough for the response
    // headers (Server, X-Powered-By) plus the <head> of the body where <title>
    // lives — and never follow a link or request any other path.
    std::string req =
        "GET / HTTP/1.1\r\n"
        "Host: " + narrowAscii(ipText) + "\r\n"
        "User-Agent: " + narrowAscii(kAppName) + "/" + narrowAscii(kAppVersion)
                       + "\r\n"
        "Connection: close\r\n"
        "\r\n";
    if (!tcp.sendAll(req, timeoutMs)) return {};

    std::string resp;
    tcp.recvUntil(resp, 8192, timeoutMs, "</title>");   // stop early once title seen
    if (resp.compare(0, 5, "HTTP/") != 0) return {};    // not HTTP — fail closed

    ServiceFingerprint fp = parseHttpResponse(port, resp);
    if (fp.port == 0) return {};
    fp.title = extractHtmlTitle(resp);

    // A device management-UI signature in the body is a far better identity
    // than the generic web-server product — promote it.
    auto [webApp, webVer] = detectWebApp(resp);
    if (!webApp.empty()) {
        fp.product = webApp;
        if (!webVer.empty()) fp.version = webVer;
    }
    return fp;
}

// =============================================================================
// HTTPS — WinHTTP HEAD request (already linked; no OpenSSL, no raw Schannel).
// =============================================================================

// Conservative HTTPS fingerprint. WinHTTP terminates the TLS handshake for us
// and a HEAD request yields the status line + Server header just like the
// plaintext path. Certificate validation is intentionally relaxed: a scanner
// wants the banner of whatever is actually listening, including self-signed or
// expired-cert boxes. Any failure in the WinHTTP chain falls back to the
// minimal "TLS/HTTPS port open" fingerprint, so the build never breaks and a
// non-TLS port can't hang the worker.
// TODO(v1.3): surface server certificate subject/expiry via
//             WINHTTP_OPTION_SERVER_CERT_CONTEXT — out of scope for v1.2.
ServiceFingerprint fingerprintHttps(const std::wstring& ipText, int port,
                                    int timeoutMs) {
    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"https";
    fp.source     = L"TLS port probe";
    fp.confidence = L"Low";
    fp.detail     = L"TLS/HTTPS port open";

    const std::wstring userAgent = std::wstring(kAppName) + L"/" + kAppVersion;
    HINTERNET hSession = ::WinHttpOpen(userAgent.c_str(),
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return fp;
    ::WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = ::WinHttpConnect(hSession, ipText.c_str(),
                                          static_cast<INTERNET_PORT>(port), 0);
    if (!hConnect) { ::WinHttpCloseHandle(hSession); return fp; }

    HINTERNET hRequest = ::WinHttpOpenRequest(hConnect, L"GET", L"/",
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        ::WinHttpCloseHandle(hConnect);
        ::WinHttpCloseHandle(hSession);
        return fp;
    }

    // Accept self-signed / expired / wrong-host certs — we are reading a
    // banner, not establishing trust.
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    ::WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                       &secFlags, sizeof(secFlags));

    bool ok = ::WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) != FALSE
           && ::WinHttpReceiveResponse(hRequest, nullptr) != FALSE;

    if (ok) {
        fp.detail     = L"TLS/HTTPS service";
        fp.confidence = L"Medium";

        auto queryHeader = [&](DWORD info, const wchar_t* name) -> std::wstring {
            DWORD len = 0;
            ::WinHttpQueryHeaders(hRequest, info, name, WINHTTP_NO_OUTPUT_BUFFER,
                                  &len, WINHTTP_NO_HEADER_INDEX);
            if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0)
                return {};
            std::wstring buf(len / sizeof(wchar_t) + 1, L'\0');
            if (!::WinHttpQueryHeaders(hRequest, info, name, buf.data(), &len,
                                       WINHTTP_NO_HEADER_INDEX))
                return {};
            buf.resize(::wcslen(buf.c_str()));
            return buf;
        };

        std::wstring server = sanitizeW(
            queryHeader(WINHTTP_QUERY_SERVER, WINHTTP_HEADER_NAME_BY_INDEX), 120);
        std::wstring poweredBy = sanitizeW(
            queryHeader(WINHTTP_QUERY_CUSTOM, L"X-Powered-By"), 80);

        if (!server.empty()) {
            std::wstring token = server;
            size_t sp = token.find(L' ');
            if (sp != std::wstring::npos) token = token.substr(0, sp);
            size_t slash = token.find(L'/');
            std::wstring prod = (slash == std::wstring::npos) ? token
                                                              : token.substr(0, slash);
            if (prod == L"Microsoft-IIS") prod = L"Microsoft IIS";
            fp.product    = prod;
            fp.version    = extractVersion(server);
            fp.detail     = L"Server: " + server;
            if (!poweredBy.empty()) fp.detail += L"; X-Powered-By: " + poweredBy;
            fp.source     = L"HTTPS Server header";
            fp.confidence = L"High";
        }

        // Bounded slice of the body for the <title> — one page, the root,
        // never a followed link or guessed path. Stops as soon as </title>
        // is seen or 8 KB is read.
        std::string body;
        for (;;) {
            DWORD avail = 0;
            if (!::WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0)
                break;
            if (avail > 4096) avail = 4096;
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!::WinHttpReadData(hRequest, chunk.data(), avail, &read) ||
                read == 0)
                break;
            body.append(chunk.data(), read);
            if (body.size() >= 8192 ||
                body.find("</title>") != std::string::npos)
                break;
        }
        std::wstring title = extractHtmlTitle(body);
        if (!title.empty()) fp.title = title;

        auto [webApp, webVer] = detectWebApp(body);
        if (!webApp.empty()) {
            fp.product = webApp;
            if (!webVer.empty()) fp.version = webVer;
            if (fp.confidence == L"Medium") fp.confidence = L"High";
        }
    }

    ::WinHttpCloseHandle(hRequest);
    ::WinHttpCloseHandle(hConnect);
    ::WinHttpCloseHandle(hSession);
    return fp;
}

// =============================================================================
// TCP banner grabs — SSH / FTP / SMTP. These services greet on connect; we
// read only the greeting and send nothing capability-probing.
// =============================================================================

ServiceFingerprint fingerprintSsh(uint32_t ipHost, int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    char buf[512];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n <= 0) return {};
    std::wstring banner = sanitize(buf, static_cast<size_t>(n), 200);
    if (banner.compare(0, 4, L"SSH-") != 0) return {};

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"ssh";
    fp.source     = L"SSH banner";
    fp.confidence = L"High";
    fp.detail     = banner;

    // Software portion follows the second '-': "SSH-2.0-<software>".
    size_t dash2 = banner.find(L'-', 4);
    std::wstring software = (dash2 == std::wstring::npos)
                            ? std::wstring() : banner.substr(dash2 + 1);
    if (software.find(L"OpenSSH") != std::wstring::npos) {
        fp.product = L"OpenSSH";
        size_t us = software.find(L'_');
        if (us != std::wstring::npos) {
            std::wstring rest = software.substr(us + 1);
            size_t sp = rest.find(L' ');
            if (sp != std::wstring::npos) rest = rest.substr(0, sp);
            fp.version = rest;                       // e.g. "9.6p1"
        }
    } else if (!software.empty()) {
        std::wstring token = software;
        size_t sp = token.find(L' ');
        if (sp != std::wstring::npos) token = token.substr(0, sp);
        fp.product = token;
        fp.version = extractVersion(token);
    }
    return fp;
}

ServiceFingerprint fingerprintFtp(uint32_t ipHost, int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    char buf[512];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n <= 0) return {};
    std::wstring banner = sanitize(buf, static_cast<size_t>(n), 200);
    if (banner.compare(0, 3, L"220") != 0) return {};

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"ftp";
    fp.source     = L"FTP banner";
    fp.confidence = L"Medium";
    fp.detail     = banner;
    fp.product    = detectFtpProduct(banner);
    if (!fp.product.empty()) fp.version = extractVersion(banner);
    return fp;
}

ServiceFingerprint fingerprintSmtp(uint32_t ipHost, int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    char buf[512];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n <= 0) return {};
    std::wstring banner = sanitize(buf, static_cast<size_t>(n), 200);
    if (banner.compare(0, 3, L"220") != 0) return {};

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"smtp";
    fp.source     = L"SMTP banner";
    fp.confidence = L"Medium";
    fp.detail     = banner;
    fp.product    = detectSmtpProduct(banner);
    if (!fp.product.empty()) fp.version = extractVersion(banner);
    return fp;
}

// =============================================================================
// MySQL / MariaDB — read the unauthenticated handshake initialisation packet.
// We send nothing: no auth, no protocol continuation, no credentials.
//   [0..2] payload length (LE 24-bit)   [3] sequence id
//   [4]    protocol version (10, sometimes 9)
//   [5..]  NUL-terminated server version string
// =============================================================================

ServiceFingerprint fingerprintMysql(uint32_t ipHost, int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    char buf[512];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n < 6) return {};

    const unsigned char* p = reinterpret_cast<const unsigned char*>(buf);
    unsigned char protoVer = p[4];

    // Protocol byte 0xFF = an error packet ("host not allowed" etc.) — still a
    // MySQL-family server, but with no version string to read.
    if (protoVer == 0xFF) {
        ServiceFingerprint fp;
        fp.port       = port;
        fp.protocol   = L"tcp";
        fp.service    = L"mysql";
        fp.product    = L"MySQL";
        fp.source     = L"MySQL handshake";
        fp.confidence = L"Medium";
        fp.detail     = L"Server answered but refused the connection";
        return fp;
    }
    if (protoVer != 10 && protoVer != 9) return {};   // not a MySQL handshake

    std::string ver;
    for (int i = 5; i < n && buf[i] != '\0' && ver.size() < 80; ++i)
        ver.push_back(buf[i]);
    std::wstring vw = sanitize(ver, 80);
    if (vw.empty()) return {};

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"mysql";
    fp.source     = L"MySQL handshake";
    fp.confidence = L"High";
    fp.detail     = vw;
    fp.product    = containsCi(vw, L"MariaDB") ? L"MariaDB" : L"MySQL";

    // MariaDB prefixes a "5.5.5-" compatibility marker; strip it, then take
    // the version up to the first '-'.
    std::wstring v = vw;
    if (v.rfind(L"5.5.5-", 0) == 0) v = v.substr(6);
    size_t dash = v.find(L'-');
    if (dash != std::wstring::npos) v = v.substr(0, dash);
    fp.version = extractVersion(v);
    return fp;
}

// =============================================================================
// MSSQL — minimal TDS PRELOGIN request (MS-TDS section 2.2.6.5). The server's
// PRELOGIN response carries a VERSION token in cleartext regardless of its
// encryption policy. We read that and stop: no LOGIN packet, no credentials.
// =============================================================================

ServiceFingerprint fingerprintMssql(uint32_t ipHost, int port, int timeoutMs) {
    static const unsigned char kPrelogin[] = {
        // ---- 8-byte TDS packet header ----
        0x12,             // type: PRELOGIN
        0x01,             // status: EOM
        0x00, 0x2F,       // length = 47 (big-endian)
        0x00, 0x00,       // SPID
        0x00,             // packet id
        0x00,             // window
        // ---- option table (offsets are relative to start of this payload) --
        0x00, 0x00, 0x1A, 0x00, 0x06,   // VERSION    off=26 len=6
        0x01, 0x00, 0x20, 0x00, 0x01,   // ENCRYPTION off=32 len=1
        0x02, 0x00, 0x21, 0x00, 0x01,   // INSTOPT    off=33 len=1
        0x03, 0x00, 0x22, 0x00, 0x04,   // THREADID   off=34 len=4
        0x04, 0x00, 0x26, 0x00, 0x01,   // MARS       off=38 len=1
        0xFF,                           // TERMINATOR
        // ---- option data ----
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // VERSION (6 bytes, all zero)
        0x02,                                 // ENCRYPTION = ENCRYPT_NOT_SUP
        0x00,                                 // INSTOPT = "" (NUL)
        0x00, 0x00, 0x00, 0x00,               // THREADID
        0x00                                  // MARS = off
    };
    static_assert(sizeof(kPrelogin) == 47, "TDS prelogin packet must be 47 bytes");

    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    if (!tcp.sendAll(std::string(reinterpret_cast<const char*>(kPrelogin),
                                 sizeof(kPrelogin)), timeoutMs))
        return {};

    char buf[512];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n < 8) return {};

    const unsigned char* r = reinterpret_cast<const unsigned char*>(buf);
    if (r[0] != 0x04) return {};            // 0x04 = TDS server response

    // Payload begins after the 8-byte header. Walk the option table for the
    // VERSION token (0x00), bounds-checking every access — hostile input.
    const unsigned char* payload = r + 8;
    size_t payloadLen = static_cast<size_t>(n) - 8;
    std::wstring version;

    for (size_t i = 0; i + 5 <= payloadLen; i += 5) {
        unsigned char token = payload[i];
        if (token == 0xFF) break;           // terminator
        unsigned int off = (static_cast<unsigned int>(payload[i + 1]) << 8)
                         |  static_cast<unsigned int>(payload[i + 2]);
        unsigned int len = (static_cast<unsigned int>(payload[i + 3]) << 8)
                         |  static_cast<unsigned int>(payload[i + 4]);
        if (token == 0x00) {                // VERSION
            if (len >= 6 && off + 4u <= payloadLen) {
                unsigned major = payload[off];
                unsigned minor = payload[off + 1];
                unsigned build = (static_cast<unsigned>(payload[off + 2]) << 8)
                               |  static_cast<unsigned>(payload[off + 3]);
                version = std::to_wstring(major) + L"." +
                          std::to_wstring(minor) + L"." +
                          std::to_wstring(build);
            }
            break;
        }
    }

    ServiceFingerprint fp;
    fp.port     = port;
    fp.protocol = L"tcp";
    fp.service  = L"mssql";
    fp.product  = L"Microsoft SQL Server";
    fp.source   = L"TDS prelogin";
    if (!version.empty()) {
        fp.version    = version;
        fp.detail     = L"TDS prelogin version " + version;
        fp.confidence = L"High";
    } else {
        fp.detail     = L"TDS prelogin response received";
        fp.confidence = L"Medium";
    }
    return fp;
}

// =============================================================================
// PostgreSQL — send a minimal v3 StartupMessage and read the server's first
// reply. We send no password and never continue. Pre-authentication PostgreSQL
// does not reveal `server_version`, so this confirms "PostgreSQL is here" but
// the version stays blank — the same situation as a hardened HTTP server.
// =============================================================================

ServiceFingerprint fingerprintPostgres(uint32_t ipHost, int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};

    // StartupMessage: Int32 length, Int32 protocol(3.0), "user\0netlens\0\0".
    static const unsigned char kStartup[] = {
        0x00, 0x00, 0x00, 0x16,                  // length = 22
        0x00, 0x03, 0x00, 0x00,                  // protocol version 3.0
        'u','s','e','r', 0x00,                   // "user"
        'n','e','t','l','e','n','s', 0x00,       // "netlens" (probe user)
        0x00                                     // params terminator
    };
    static_assert(sizeof(kStartup) == 22, "PostgreSQL startup must be 22 bytes");
    if (!tcp.sendAll(std::string(reinterpret_cast<const char*>(kStartup),
                                 sizeof(kStartup)), timeoutMs))
        return {};

    char buf[256];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n < 1) return {};

    // First byte: 'R' Authentication request, 'E' ErrorResponse, 'N' Notice —
    // any of these is a PostgreSQL v3 backend answering.
    unsigned char type = static_cast<unsigned char>(buf[0]);
    if (type != 'R' && type != 'E' && type != 'N') return {};

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"postgresql";
    fp.product    = L"PostgreSQL";
    fp.source     = L"PostgreSQL handshake";
    fp.confidence = L"Medium";
    fp.detail     = L"PostgreSQL backend (version not disclosed pre-auth)";
    return fp;
}

// =============================================================================
// POP3 / IMAP — both greet on connect with a "+OK ..." / "* OK ..." line, the
// same shape as the SMTP/FTP banner grab.
// =============================================================================

ServiceFingerprint fingerprintMailBanner(uint32_t ipHost, int port, int timeoutMs,
                                         const wchar_t* service,
                                         const wchar_t* expectPrefix,
                                         const wchar_t* sourceLabel) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    char buf[512];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n <= 0) return {};
    std::wstring banner = sanitize(buf, static_cast<size_t>(n), 200);
    if (banner.rfind(expectPrefix, 0) != 0) return {};   // must start with prefix

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = service;
    fp.source     = sourceLabel;
    fp.confidence = L"Medium";
    fp.detail     = banner;
    // Mail servers that name themselves in the greeting.
    if      (containsCi(banner, L"Dovecot"))     fp.product = L"Dovecot";
    else if (containsCi(banner, L"Courier"))     fp.product = L"Courier";
    else if (containsCi(banner, L"Cyrus"))       fp.product = L"Cyrus IMAP";
    else if (containsCi(banner, L"Exchange"))    fp.product = L"Microsoft Exchange";
    else if (containsCi(banner, L"hMailServer")) fp.product = L"hMailServer";
    else if (containsCi(banner, L"Zimbra"))      fp.product = L"Zimbra";
    if (!fp.product.empty()) fp.version = extractVersion(banner);
    return fp;
}

// =============================================================================
// VNC — RFB servers send a 12-byte "RFB 003.00x\n" protocol-version string on
// connect. We read it and stop — we never send our version back, so the RFB
// handshake does not proceed.
// =============================================================================

ServiceFingerprint fingerprintVnc(uint32_t ipHost, int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    char buf[64];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n < 12) return {};
    std::wstring banner = sanitize(buf, static_cast<size_t>(n), 32);
    if (banner.rfind(L"RFB ", 0) != 0) return {};

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"vnc";
    fp.product    = L"VNC";
    fp.source     = L"VNC RFB banner";
    fp.confidence = L"Medium";
    // "RFB 003.008" is the RFB *protocol* version, not the server product
    // version — informative, but kept in detail rather than claimed as a
    // product version.
    fp.detail     = banner;
    return fp;
}

// =============================================================================
// Telnet — the server opens with IAC option-negotiation bytes, often followed
// by a banner / login prompt. We strip the IAC sequences and keep whatever
// readable text remains; no options are negotiated back.
// =============================================================================

ServiceFingerprint fingerprintTelnet(uint32_t ipHost, int port, int timeoutMs) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, port, timeoutMs)) return {};
    char buf[512];
    int n = tcp.recvChunk(buf, sizeof(buf), timeoutMs);
    if (n <= 0) return {};

    const bool sawIac = (static_cast<unsigned char>(buf[0]) == 0xFF);

    // Strip Telnet IAC sequences: IAC(0xFF)+cmd; WILL/WONT/DO/DONT carry a 3rd
    // option byte; SB...SE runs until IAC SE.
    std::string clean;
    clean.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ) {
        unsigned char c = static_cast<unsigned char>(buf[i]);
        if (c != 0xFF) { clean.push_back(buf[i]); ++i; continue; }
        if (i + 1 >= n) break;
        unsigned char cmd = static_cast<unsigned char>(buf[i + 1]);
        if (cmd >= 0xFB && cmd <= 0xFE) {            // WILL/WONT/DO/DONT + option
            i += 3;
        } else if (cmd == 0xFA) {                    // SB ... IAC SE
            i += 2;
            while (i + 1 < n && !(static_cast<unsigned char>(buf[i]) == 0xFF &&
                                  static_cast<unsigned char>(buf[i + 1]) == 0xF0))
                ++i;
            i += 2;
        } else {                                     // other 2-byte command
            i += 2;
        }
    }
    std::wstring banner = sanitize(clean, 200);
    if (banner.empty() && !sawIac) return {};        // not telnet-looking

    ServiceFingerprint fp;
    fp.port       = port;
    fp.protocol   = L"tcp";
    fp.service    = L"telnet";
    fp.product    = L"Telnet";
    fp.source     = L"Telnet banner";
    fp.confidence = L"Low";
    fp.detail     = banner.empty()
                    ? std::wstring(L"Telnet service (option negotiation, no banner)")
                    : banner;
    return fp;
}

int clampTimeout(int ms) {
    if (ms < kMinFingerprintTimeoutMs) return kMinFingerprintTimeoutMs;
    if (ms > kMaxFingerprintTimeoutMs) return kMaxFingerprintTimeoutMs;
    return ms;
}

// Shared state for the bounded NetRemoteTOD call. Reference-counted so that if
// the call overruns the timeout and we abandon (detach) the worker, the worker
// still holds the last reference: it writes its result where nobody reads it,
// frees its NetApi buffer, and the struct is destroyed cleanly when it exits.
struct TodCall {
    std::mutex              mu;
    std::condition_variable cv;
    bool                    done     = false;
    bool                    ok       = false;
    int64_t                 remoteMs = 0;   // remote clock, Unix ms UTC
    int64_t                 localT1  = 0;   // local Unix ms just before the call
    int64_t                 localT4  = 0;   // local Unix ms just after the call
};

// Shared state for the bounded NetServerGetInfo call — same abandon-safe,
// reference-counted pattern as TodCall.
struct ServerInfoCall {
    std::mutex              mu;
    std::condition_variable cv;
    bool                    done     = false;
    bool                    ok       = false;
    unsigned                verMajor = 0;
    unsigned                verMinor = 0;
    unsigned                svType   = 0;
    std::wstring            comment;
    std::wstring            name;        // SMB/NetBIOS computer name
};

// Shared state for the bounded NetShareEnum call — same abandon-safe pattern.
struct SharesCall {
    std::mutex                mu;
    std::condition_variable   cv;
    bool                      done = false;
    bool                      ok   = false;
    std::vector<std::wstring> shares;     // each "netname\ttype\tremark"
};

// =============================================================================
// Minimal DNS / mDNS helpers — used by the Apple device-class probe to issue
// a unicast PTR query for `_services._dns-sd._udp.local` on UDP 5353 and parse
// the answer. We do **not** join the multicast group; Bonjour responders on
// Apple devices reliably answer unicast queries to their own address on 5353.
// All parsing is bounded and fail-closed: any malformed pointer / oversized
// label yields no result rather than reading past the response buffer.
// =============================================================================

// Builds an RFC 1035 query packet: ID=0, flags=0 (standard query, RD=0),
// QDCOUNT=1, ANCOUNT/NSCOUNT/ARCOUNT=0. The single question is `name`
// (ASCII, dot-separated) encoded as DNS labels + null terminator, with the
// given QTYPE and QCLASS=IN(1).
std::string buildDnsQuery(const wchar_t* name, uint16_t qtype) {
    auto push16 = [](std::string& s, uint16_t v) {
        s.push_back(static_cast<char>((v >> 8) & 0xFF));
        s.push_back(static_cast<char>(v & 0xFF));
    };
    std::string out;
    out.reserve(64);
    push16(out, 0x0000);    // ID
    push16(out, 0x0000);    // flags (standard query)
    push16(out, 0x0001);    // QDCOUNT
    push16(out, 0x0000);    // ANCOUNT
    push16(out, 0x0000);    // NSCOUNT
    push16(out, 0x0000);    // ARCOUNT

    std::string label;
    auto flushLabel = [&] {
        if (label.empty()) return;
        if (label.size() > 63) label.resize(63);
        out.push_back(static_cast<char>(label.size()));
        out.append(label);
        label.clear();
    };
    for (const wchar_t* p = name; *p; ++p) {
        wchar_t wc = *p;
        if (wc == L'.') { flushLabel(); continue; }
        char c = (wc > 0 && wc < 128) ? static_cast<char>(wc) : '?';
        label.push_back(c);
    }
    flushLabel();
    out.push_back('\0');    // root label terminator
    push16(out, qtype);
    push16(out, 0x0001);    // QCLASS = IN
    return out;
}

// Decodes a (possibly-compressed) DNS name starting at `pos`. Advances `pos`
// past the name in the message (compression pointers don't advance past the
// pointer itself; the original `pos` only consumes the pointer's two bytes).
// `budget` caps the number of label hops to defeat cyclic pointers. Returns
// true on success and fills `out` with the dotted name (printable-ASCII only).
bool dnsReadName(const std::string& msg, size_t& pos, std::wstring& out,
                 int budget) {
    out.clear();
    size_t cursor = pos;
    bool followed = false;
    size_t advancedTo = pos;          // where the outer parser should continue
    for (int hops = 0; hops < budget; ++hops) {
        if (cursor >= msg.size()) return false;
        unsigned char len = static_cast<unsigned char>(msg[cursor]);
        if (len == 0) {
            ++cursor;
            if (!followed) advancedTo = cursor;
            pos = advancedTo;
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            if (cursor + 1 >= msg.size()) return false;
            size_t target =
                ((static_cast<size_t>(len) & 0x3F) << 8) |
                 static_cast<size_t>(static_cast<unsigned char>(msg[cursor + 1]));
            if (!followed) { advancedTo = cursor + 2; followed = true; }
            cursor = target;
            continue;
        }
        if ((len & 0xC0) != 0) return false;     // reserved label types
        ++cursor;
        if (cursor + len > msg.size()) return false;
        if (!out.empty()) out.push_back(L'.');
        for (unsigned i = 0; i < len; ++i) {
            unsigned char c = static_cast<unsigned char>(msg[cursor + i]);
            out.push_back(c < 0x20 || c > 0x7E ? L'?'
                                                : static_cast<wchar_t>(c));
        }
        cursor += len;
    }
    return false;     // ran out of budget — malformed
}

// Walks the answer section of a DNS reply, appending every PTR record's
// rdata name to `out`. Stops on any malformed field. Skips the question and
// other-type answers.
bool parseDnsPtrAnswers(const std::string& msg, std::vector<std::wstring>& out) {
    if (msg.size() < 12) return false;
    auto u16 = [&](size_t i) -> int {
        if (i + 1 >= msg.size()) return -1;
        return (static_cast<unsigned char>(msg[i]) << 8) |
                static_cast<unsigned char>(msg[i + 1]);
    };
    int qd = u16(4);
    int an = u16(6);
    if (qd < 0 || an < 0) return false;
    size_t pos = 12;
    std::wstring tmp;
    for (int i = 0; i < qd; ++i) {
        if (!dnsReadName(msg, pos, tmp, 32)) return false;
        if (pos + 4 > msg.size()) return false;
        pos += 4;                  // QTYPE + QCLASS
    }
    for (int i = 0; i < an; ++i) {
        if (!dnsReadName(msg, pos, tmp, 32)) return false;
        if (pos + 10 > msg.size()) return false;
        int atype = u16(pos);
        int rdlen = u16(pos + 8);
        if (atype < 0 || rdlen < 0) return false;
        pos += 10;
        size_t rdEnd = pos + static_cast<size_t>(rdlen);
        if (rdEnd > msg.size()) return false;
        if (atype == 12) {         // PTR
            size_t p = pos;
            std::wstring rdName;
            if (dnsReadName(msg, p, rdName, 32) && !rdName.empty())
                out.push_back(std::move(rdName));
        }
        pos = rdEnd;
    }
    return true;
}

// One-shot unicast mDNS service-meta query — asks the host for the list of
// Bonjour service types it advertises. Apple devices reliably answer this
// over unicast UDP 5353. Returns the decoded service-type names, empty on
// no/invalid answer.
std::vector<std::wstring> mdnsServiceTypes(uint32_t hostIp, int timeoutMs) {
    std::vector<std::wstring> out;
    std::string req = buildDnsQuery(L"_services._dns-sd._udp.local",
                                    12 /* PTR */);
    char resp[1500] = {};
    int n = udpQuery(hostIp, 5353,
                     req.data(), static_cast<int>(req.size()),
                     resp, sizeof(resp), timeoutMs);
    if (n > 0)
        parseDnsPtrAnswers(std::string(resp, static_cast<size_t>(n)), out);
    return out;
}

// True when any entry in `list` contains the substring `needle`.
bool servicesContain(const std::vector<std::wstring>& list,
                     const wchar_t* needle) {
    for (const auto& s : list)
        if (s.find(needle) != std::wstring::npos) return true;
    return false;
}

// Bounded TCP reachability check — a single non-blocking connect with a
// timeout, the socket is closed immediately on success. Used for the Apple
// out-of-band port follow-up (62078 / 7000 / 3689) outside the normal scan.
bool tcpPortReachable(uint32_t hostIp, int port, int timeoutMs) {
    TcpProbe tcp;
    return tcp.connect(hostIp, port, timeoutMs);
}

// Bounded HTTPS GET for the ESXi/vSphere version probe — fetches
// `/sdk/vimServiceVersions.xml` (anonymous, no API call required) and
// returns the highest `<version>` value from the urn:vim25 namespace. The
// vim25 version maps near-1:1 onto the ESXi/vSphere product version
// (8.0.x → ESXi 8.0, 7.0.x → ESXi 7.0, 6.7.x → ESXi 6.7, …). Empty on no
// answer / malformed body / no vim25 entry.
std::wstring fetchEsxiVimVersion(const std::wstring& ipText, int timeoutMs) {
    const std::wstring userAgent = std::wstring(kAppName) + L"/" + kAppVersion;
    HINTERNET hSession = ::WinHttpOpen(userAgent.c_str(),
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return {};
    ::WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = ::WinHttpConnect(hSession, ipText.c_str(),
                                          static_cast<INTERNET_PORT>(443), 0);
    if (!hConnect) { ::WinHttpCloseHandle(hSession); return {}; }

    HINTERNET hRequest = ::WinHttpOpenRequest(hConnect, L"GET",
        L"/sdk/vimServiceVersions.xml",
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        ::WinHttpCloseHandle(hConnect);
        ::WinHttpCloseHandle(hSession);
        return {};
    }
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    ::WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                       &secFlags, sizeof(secFlags));

    std::wstring out;
    bool ok = ::WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) != FALSE
           && ::WinHttpReceiveResponse(hRequest, nullptr) != FALSE;
    if (ok) {
        std::string body;
        for (;;) {
            DWORD avail = 0;
            if (!::WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0)
                break;
            if (avail > 4096) avail = 4096;
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!::WinHttpReadData(hRequest, chunk.data(), avail, &read) ||
                read == 0)
                break;
            body.append(chunk.data(), read);
            if (body.size() >= 16384) break;
        }

        // Scan EVERY <version>X.Y.Z</version> token that appears
        // inside the namespace block whose first child is
        // urn:vim25, then return the highest one by numeric
        // comparison. Earlier code took the first <version>, which
        // is correct on most ESXi but breaks on the small handful
        // of releases that serialise the current version inside
        // <priorVersions> with the legacy "6.0" out front — that
        // host showed up as ESXi 6.0 even though the actual server
        // was 7.0.x. Numeric pick is bulletproof: the highest token
        // is, by definition, the current API version.
        std::string lower = toLowerAscii(body);
        size_t v25 = lower.find("urn:vim25");
        if (v25 != std::string::npos) {
            // Constrain the scan to the rest of the document (the
            // urn:vim25 namespace block is always last in practice,
            // but ESXi 6.0 has been seen to list its own namespace
            // earlier with separate <version> entries — those would
            // pollute the result without this anchor).
            std::vector<std::wstring> versions;
            size_t cursor = v25;
            while (true) {
                size_t vs = lower.find("<version>", cursor);
                if (vs == std::string::npos) break;
                vs += 9;
                size_t ve = lower.find("</version>", vs);
                if (ve == std::string::npos || ve - vs >= 32) break;
                std::string raw = body.substr(vs, ve - vs);
                while (!raw.empty() && (raw.front() == ' ' ||
                       raw.front() == '\t' || raw.front() == '\r' ||
                       raw.front() == '\n')) raw.erase(raw.begin());
                while (!raw.empty() && (raw.back() == ' ' ||
                       raw.back() == '\t' || raw.back() == '\r' ||
                       raw.back() == '\n')) raw.pop_back();
                std::wstring v;
                for (char c : raw) {
                    if ((c >= '0' && c <= '9') || c == '.')
                        v.push_back(static_cast<wchar_t>(c));
                }
                if (!v.empty()) versions.push_back(std::move(v));
                cursor = ve + 10;
            }
            // Pick the highest by component-wise numeric comparison.
            auto cmp = [](const std::wstring& a, const std::wstring& b) {
                auto split = [](const std::wstring& s) {
                    std::vector<int> parts;
                    int cur = 0;
                    bool any = false;
                    for (wchar_t c : s) {
                        if (c >= L'0' && c <= L'9') {
                            cur = cur * 10 + (c - L'0');
                            any = true;
                        } else if (c == L'.') {
                            parts.push_back(any ? cur : 0);
                            cur = 0; any = false;
                        }
                    }
                    if (any) parts.push_back(cur);
                    return parts;
                };
                auto pa = split(a);
                auto pb = split(b);
                size_t n = std::max(pa.size(), pb.size());
                for (size_t i = 0; i < n; ++i) {
                    int ai = i < pa.size() ? pa[i] : 0;
                    int bi = i < pb.size() ? pb[i] : 0;
                    if (ai != bi) return ai < bi;
                }
                return false;
            };
            auto it = std::max_element(versions.begin(), versions.end(), cmp);
            if (it != versions.end()) out = *it;
        }
    }

    ::WinHttpCloseHandle(hRequest);
    ::WinHttpCloseHandle(hConnect);
    ::WinHttpCloseHandle(hSession);
    return out;
}

// vim25 API version → user-facing ESXi/vSphere product version. The vim25
// namespace follows the host's major.minor release (the trailing build
// digits drift independently), so we keep only the leading "X.Y".
std::wstring esxiProductFromVimVersion(const std::wstring& vim) {
    if (vim.empty()) return {};
    // Take "X.Y" prefix.
    std::wstring xy;
    int dots = 0;
    for (wchar_t c : vim) {
        if (c == L'.') {
            ++dots;
            if (dots > 1) break;
            xy.push_back(c);
        } else if (c >= L'0' && c <= L'9') {
            xy.push_back(c);
        } else {
            break;
        }
    }
    if (xy.empty()) return {};
    return L"VMware ESXi " + xy;
}

// Maps a Windows version-number pair to a human-readable OS name.
std::wstring windowsNameFor(unsigned major, unsigned minor) {
    if (major == 10) return L"Windows 10 / 11 or Server 2016+";
    if (major == 6) {
        if (minor == 3) return L"Windows 8.1 / Server 2012 R2";
        if (minor == 2) return L"Windows 8 / Server 2012";
        if (minor == 1) return L"Windows 7 / Server 2008 R2";
        if (minor == 0) return L"Windows Vista / Server 2008";
    }
    if (major == 5) {
        if (minor == 2) return L"Windows Server 2003 / XP x64";
        if (minor == 1) return L"Windows XP";
        if (minor == 0) return L"Windows 2000";
    }
    return L"Windows";
}

} // anonymous namespace

// =============================================================================
// Public API
// =============================================================================

std::vector<ServiceFingerprint> ServiceFingerprinter::fingerprintTcpServices(
    const std::wstring& ip,
    const std::vector<PortStatus>& openPorts,
    const Options& options,
    const std::atomic<bool>& cancel)
{
    std::vector<ServiceFingerprint> out;

    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return out;
    const uint32_t ipHost  = *ipHostOpt;
    const int      timeout = clampTimeout(options.timeoutMs);

    auto push = [&](ServiceFingerprint fp) {
        if (fp.port != 0 && !fp.service.empty()) out.push_back(std::move(fp));
    };

    for (const auto& p : openPorts) {
        if (cancel.load(std::memory_order_relaxed)) break;
        if (!p.isOpen) continue;

        // Each helper is wrapped — a single odd probe never aborts the host.
        try {
            switch (p.port) {
                case 80: case 8080: case 8000: case 8888:
                case 9191: case 9195:   // PaperCut NG/MF admin (HTTP)
                    if (options.enableHttp)
                        push(fingerprintHttp(ipHost, ip, p.port, timeout));
                    break;
                case 443: case 8443:
                case 9192:              // PaperCut NG/MF admin (HTTPS)
                    if (options.enableTls)
                        push(fingerprintHttps(ip, p.port, timeout));
                    break;
                case 22:
                    if (options.enableTcpBanners)
                        push(fingerprintSsh(ipHost, p.port, timeout));
                    break;
                case 21:
                    if (options.enableTcpBanners)
                        push(fingerprintFtp(ipHost, p.port, timeout));
                    break;
                case 25: case 587:
                    if (options.enableTcpBanners)
                        push(fingerprintSmtp(ipHost, p.port, timeout));
                    break;
                case 3306:
                    if (options.enableDatabases)
                        push(fingerprintMysql(ipHost, p.port, timeout));
                    break;
                case 1433:
                    if (options.enableDatabases)
                        push(fingerprintMssql(ipHost, p.port, timeout));
                    break;
                case 5432:
                    if (options.enableDatabases)
                        push(fingerprintPostgres(ipHost, p.port, timeout));
                    break;
                case 110:
                    if (options.enableTcpBanners)
                        push(fingerprintMailBanner(ipHost, p.port, timeout,
                                 L"pop3", L"+OK", L"POP3 banner"));
                    break;
                case 143:
                    if (options.enableTcpBanners)
                        push(fingerprintMailBanner(ipHost, p.port, timeout,
                                 L"imap", L"* OK", L"IMAP banner"));
                    break;
                case 5900: case 5901:
                    if (options.enableTcpBanners)
                        push(fingerprintVnc(ipHost, p.port, timeout));
                    break;
                case 23:
                    if (options.enableTcpBanners)
                        push(fingerprintTelnet(ipHost, p.port, timeout));
                    break;
                default:
                    break;
            }
        } catch (...) {
            // A fingerprint failure is informational, never fatal.
        }
    }

    // VMware ESXi / vSphere always listens on TCP 902 (the vSphere authd) in
    // addition to 443, and 902 is rarely in a scan preset — so a direct connect
    // to 902 when 443 is open is the signal. BUT a Windows box with VMware
    // Workstation/Player also opens 902 (same "VMware Authorization Service"),
    // so 902 alone is a false positive on those. A real ESXi host is a bare
    // hypervisor: it never runs the Windows SMB/RPC/RDP stack, and never serves
    // its 443 with Apache / nginx / IIS. Require both negatives before
    // concluding ESXi.
    bool has443 = false, hasWindowsStack = false;
    for (const auto& p : openPorts) {
        if (!p.isOpen) continue;
        if (p.port == 443) has443 = true;
        if (p.port == 135 || p.port == 139 || p.port == 445 ||
            p.port == 3389 || p.port == 5985 || p.port == 5986)
            hasWindowsStack = true;
    }
    bool normalWebServer = false;
    for (const auto& f : out) {
        if ((f.service == L"http" || f.service == L"https") &&
            (f.product == L"Apache" || f.product == L"nginx" ||
             f.product == L"Microsoft IIS" || f.product == L"lighttpd"))
            normalWebServer = true;
    }
    if (has443 && !hasWindowsStack && !normalWebServer &&
        !cancel.load(std::memory_order_relaxed)) {
        try {
            TcpProbe tcp;
            if (tcp.connect(ipHost, 902, timeout)) {
                ServiceFingerprint fp;
                fp.port       = 902;
                fp.protocol   = L"tcp";
                fp.service    = L"vsphere";
                fp.product    = L"VMware ESXi / vSphere";
                fp.source     = L"vSphere authd (TCP 902)";
                fp.confidence = L"High";
                fp.detail     = L"TCP 902 (vSphere authd) open, no Windows stack";

                // Now that we're confident the host is ESXi/vSphere, fetch
                // the anonymous /sdk/vimServiceVersions.xml document — the
                // urn:vim25 namespace version maps near-1:1 to the ESXi
                // product version (8.0.x → 8.0, 7.0.x → 7.0, …). Tracks
                // ESXi 6.0 onward.
                std::wstring vim = fetchEsxiVimVersion(ip, timeout);
                if (!vim.empty()) {
                    fp.version = vim;
                    std::wstring product = esxiProductFromVimVersion(vim);
                    if (!product.empty()) fp.product = product;
                    fp.source = L"vSphere authd (TCP 902) + /sdk/vimServiceVersions.xml";
                    fp.detail = L"vim25=" + vim;
                }
                out.push_back(std::move(fp));
            }
        } catch (...) {
            // never fatal
        }
    }

    return out;
}

std::vector<ServiceFingerprint> ServiceFingerprinter::queryMssqlBrowser(
    const std::wstring& ip, int timeoutMs)
{
    std::vector<ServiceFingerprint> out;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return out;
    const int timeout = clampTimeout(timeoutMs);

    // SQL Server Resolution Protocol: a single 0x02 byte asks the browser
    // service to enumerate its instances. No follow-up, no authentication.
    const char req = 0x02;
    char resp[1024] = {};
    int n = udpQuery(*ipHostOpt, 1434, &req, 1, resp, sizeof(resp), timeout);
    if (n < 3) return out;

    // Response: 0x05, 2-byte LE length, then a ';'-delimited key/value list.
    if (static_cast<unsigned char>(resp[0]) != 0x05) return out;
    int bodyLen = static_cast<unsigned char>(resp[1])
                | (static_cast<unsigned char>(resp[2]) << 8);
    int avail = n - 3;
    if (bodyLen > avail) bodyLen = avail;
    if (bodyLen <= 0) return out;

    std::wstring body = sanitize(resp + 3, static_cast<size_t>(bodyLen), 400);

    std::vector<std::wstring> toks;
    {
        std::wstring cur;
        for (wchar_t c : body) {
            if (c == L';') { toks.push_back(cur); cur.clear(); }
            else           { cur.push_back(c); }
        }
        if (!cur.empty()) toks.push_back(cur);
    }
    std::wstring instance, version, tcpPort;
    for (size_t i = 0; i + 1 < toks.size(); i += 2) {
        if      (toks[i] == L"InstanceName") instance = toks[i + 1];
        else if (toks[i] == L"Version")      version  = toks[i + 1];
        else if (toks[i] == L"tcp")          tcpPort  = toks[i + 1];
    }

    auto appendPart = [](std::wstring& d, const std::wstring& part) {
        if (part.empty()) return;
        if (!d.empty()) d += L", ";
        d += part;
    };
    std::wstring detail;
    if (!instance.empty()) appendPart(detail, L"instance " + instance);
    if (!version.empty())  appendPart(detail, L"version "  + version);
    if (!tcpPort.empty())  appendPart(detail, L"tcp "      + tcpPort);
    if (detail.empty())    detail = L"SQL Server Browser responded";

    ServiceFingerprint fp;
    fp.port       = 1434;
    fp.protocol   = L"udp";
    fp.service    = L"mssql-browser";
    fp.product    = L"Microsoft SQL Server Browser";
    fp.version    = extractVersion(version);
    fp.detail     = detail;
    fp.source     = L"SQL Server Browser";
    fp.confidence = (!instance.empty() || !version.empty()) ? L"High" : L"Medium";
    out.push_back(std::move(fp));
    return out;
}

ClockDriftInfo ServiceFingerprinter::queryNtpClock(const std::wstring& ip,
                                                   int timeoutMs)
{
    ClockDriftInfo info;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return info;
    const int timeout = clampTimeout(timeoutMs);

    // 48-byte NTP client request. Byte 0 = 0x1B: LI=0, VN=3, Mode=3 (client).
    unsigned char req[48] = {};
    req[0] = 0x1B;
    uint64_t t1 = ntpNow();
    for (int i = 0; i < 8; ++i)        // Transmit Timestamp (bytes 40..47)
        req[40 + i] = static_cast<unsigned char>((t1 >> (56 - i * 8)) & 0xFF);

    char resp[48] = {};
    int n = udpQuery(*ipHostOpt, 123, reinterpret_cast<const char*>(req), 48,
                     resp, sizeof(resp), timeout);
    uint64_t t4 = ntpNow();
    if (n < 48) return info;           // no / short answer — normal, not error

    const unsigned char* r = reinterpret_cast<const unsigned char*>(resp);
    unsigned char mode    = r[0] & 0x07;
    unsigned char stratum = r[1];
    // Mode 4 = server. Stratum 1..15 marks a usable synced source; 0 or >=16
    // means the box answered but is not a real time source — fail closed.
    if (mode != 4 || stratum < 1 || stratum > 15) return info;

    uint64_t t2raw = readBe64(r + 32);   // server receive timestamp
    uint64_t t3raw = readBe64(r + 40);   // server transmit timestamp
    if (t2raw == 0 || t3raw == 0) return info;

    int64_t t1ms = ntpToMs(t1);
    int64_t t2ms = ntpToMs(t2raw);
    int64_t t3ms = ntpToMs(t3raw);
    int64_t t4ms = ntpToMs(t4);

    info.responded   = true;
    info.offsetMs    = ((t2ms - t1ms) + (t3ms - t4ms)) / 2;
    info.roundTripMs = (t4ms - t1ms) - (t3ms - t2ms);
    if (info.roundTripMs < 0) info.roundTripMs = 0;
    info.source      = L"NTP";
    return info;
}

// v1.5.11 — global cap on abandonable SMB/RPC worker threads. NetRemoteTOD /
// NetServerGetInfo / NetShareEnum have no timeout parameter, so each runs on a
// thread we abandon (detach) when it overruns. On a big scan with many hosts
// that have 445 open but RPC filtered / black-holed, those detached threads
// pile up until their OS call finally returns (tens of seconds). Bound the
// in-flight total the same way DnsResolver bounds reverse-DNS: past the cap,
// skip the probe rather than spawn unbounded threads. The slot is released by
// the worker itself (RAII) when the OS call actually returns — so a detached,
// still-stuck thread keeps holding its slot, which is exactly what we want.
namespace {
std::atomic<int>  g_rpcWorkersInFlight{0};
constexpr int     kMaxRpcWorkers = 48;
}  // namespace

ClockDriftInfo ServiceFingerprinter::queryWindowsTimeOfDay(const std::wstring& ip,
                                                          int timeoutMs)
{
    ClockDriftInfo info;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return info;
    const int timeout = clampTimeout(timeoutMs);

    // NetRemoteTOD has no timeout parameter, so we run it on a worker thread we
    // can abandon. This is the same read-only, anonymous call `net time \\host`
    // makes — one Time-Of-Day struct, no enumeration, no credentials.
    auto state = std::make_shared<TodCall>();
    const std::wstring server = L"\\\\" + ip;

    if (g_rpcWorkersInFlight.fetch_add(1, std::memory_order_acq_rel) >= kMaxRpcWorkers) {
        g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel);
        return info;                   // RPC-worker budget exhausted — skip
    }
    std::thread worker;
    try {
    worker = std::thread([state, server]() {
        struct Rel { ~Rel(){ g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel); } } rel;
        int64_t        t1  = unixMsNow();
        LPBYTE         buf = nullptr;
        NET_API_STATUS rc  = ::NetRemoteTOD(server.c_str(), &buf);
        int64_t        t4  = unixMsNow();

        bool    ok     = false;
        int64_t remote = 0;
        if (rc == NERR_Success && buf) {
            const auto* tod = reinterpret_cast<const TIME_OF_DAY_INFO*>(buf);
            // tod_elapsedt: seconds since 1970-01-01 UTC; tod_hunds: hundredths.
            remote = static_cast<int64_t>(tod->tod_elapsedt) * 1000
                   + static_cast<int64_t>(tod->tod_hunds)    * 10;
            ok = true;
        }
        if (buf) ::NetApiBufferFree(buf);

        {
            std::lock_guard<std::mutex> lk(state->mu);
            state->ok       = ok;
            state->remoteMs = remote;
            state->localT1  = t1;
            state->localT4  = t4;
            state->done     = true;
        }
        state->cv.notify_one();
    });
    } catch (...) {
        g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel);
        return info;                   // thread didn't start — release slot
    }

    bool finished = false;
    {
        std::unique_lock<std::mutex> lk(state->mu);
        finished = state->cv.wait_for(lk, std::chrono::milliseconds(timeout),
                                      [&] { return state->done; });
        if (finished && state->ok) {
            // Single-timestamp offset estimate: compare the remote clock to the
            // midpoint of our local clock over the call window.
            int64_t localMid = (state->localT1 + state->localT4) / 2;
            info.responded   = true;
            info.offsetMs    = state->remoteMs - localMid;
            info.roundTripMs = state->localT4 - state->localT1;
            if (info.roundTripMs < 0) info.roundTripMs = 0;
            info.source      = L"net time";
        }
    }

    // Finished in time → join (instant). Overran → detach and let the worker
    // self-clean via the shared_ptr; never block the scan on a stuck RPC.
    if (finished) worker.join();
    else          worker.detach();
    return info;
}

ServiceFingerprinter::WindowsServerInfo
ServiceFingerprinter::queryWindowsServerInfo(const std::wstring& ip, int timeoutMs)
{
    WindowsServerInfo result;      // fingerprint.port stays 0 -> caller drops it
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return result;
    const int timeout = clampTimeout(timeoutMs);

    // NetServerGetInfo, like NetRemoteTOD, has no timeout parameter — run it on
    // an abandonable worker thread. Same read-only, anonymous SMB surface.
    auto state = std::make_shared<ServerInfoCall>();
    const std::wstring server = L"\\\\" + ip;

    if (g_rpcWorkersInFlight.fetch_add(1, std::memory_order_acq_rel) >= kMaxRpcWorkers) {
        g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel);
        return result;                 // RPC-worker budget exhausted — skip
    }
    std::thread worker;
    try {
    worker = std::thread([state, server]() {
        struct Rel { ~Rel(){ g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel); } } rel;
        LPBYTE buf = nullptr;
        NET_API_STATUS rc = ::NetServerGetInfo(
            const_cast<LPWSTR>(server.c_str()), 101, &buf);
        bool ok = false;
        unsigned major = 0, minor = 0, type = 0;
        std::wstring comment, name;
        if (rc == NERR_Success && buf) {
            const auto* si = reinterpret_cast<const SERVER_INFO_101*>(buf);
            major = si->sv101_version_major & 0x0F;   // low nibble = major
            minor = si->sv101_version_minor;
            type  = si->sv101_type;
            if (si->sv101_comment) comment = si->sv101_comment;
            if (si->sv101_name)    name    = si->sv101_name;
            ok = true;
        }
        if (buf) ::NetApiBufferFree(buf);
        {
            std::lock_guard<std::mutex> lk(state->mu);
            state->ok       = ok;
            state->verMajor = major;
            state->verMinor = minor;
            state->svType   = type;
            state->comment  = comment;
            state->name     = name;
            state->done     = true;
        }
        state->cv.notify_one();
    });
    } catch (...) {
        g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel);
        return result;                 // thread didn't start — release slot
    }

    bool finished = false;
    {
        std::unique_lock<std::mutex> lk(state->mu);
        finished = state->cv.wait_for(lk, std::chrono::milliseconds(timeout),
                                      [&] { return state->done; });
        if (finished && state->ok) {
            ServiceFingerprint& fp = result.fingerprint;
            fp.port       = 445;
            fp.protocol   = L"tcp";
            fp.service    = L"windows";
            fp.product    = L"Windows";
            fp.version    = std::to_wstring(state->verMajor) + L"."
                          + std::to_wstring(state->verMinor);
            fp.source     = L"NetServerGetInfo";
            fp.confidence = L"High";
            fp.detail     = windowsNameFor(state->verMajor, state->verMinor);
            // The one reliable role bit is "domain controller".
            if (state->svType & (SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL))
                fp.detail += L" (domain controller)";
            std::wstring c = sanitizeW(state->comment, 80);
            if (!c.empty()) fp.detail += L" - " + c;

            // The SMB computer name — a hostname fallback for the scanner.
            result.computerName = sanitizeW(state->name, 64);
        }
    }

    if (finished) worker.join();
    else          worker.detach();
    return result;
}

std::vector<std::wstring>
ServiceFingerprinter::queryShares(const std::wstring& ip, int timeoutMs)
{
    std::vector<std::wstring> out;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return out;
    const int timeout = clampTimeout(timeoutMs);

    auto state = std::make_shared<SharesCall>();
    const std::wstring server = L"\\\\" + ip;

    if (g_rpcWorkersInFlight.fetch_add(1, std::memory_order_acq_rel) >= kMaxRpcWorkers) {
        g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel);
        return out;                    // RPC-worker budget exhausted — skip
    }
    std::thread worker;
    try {
    worker = std::thread([state, server]() {
        struct Rel { ~Rel(){ g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel); } } rel;
        PSHARE_INFO_1 buf = nullptr;
        DWORD entriesRead = 0, totalEntries = 0, resume = 0;
        // Level 1 = SHARE_INFO_1 (netname + type + remark). Anonymous /
        // null-session enumeration — no credentials supplied.
        NET_API_STATUS rc = ::NetShareEnum(
            const_cast<LPWSTR>(server.c_str()), 1,
            reinterpret_cast<LPBYTE*>(&buf),
            MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resume);

        std::vector<std::wstring> shares;
        bool ok = false;
        if ((rc == NERR_Success || rc == ERROR_MORE_DATA) && buf) {
            ok = true;
            for (DWORD i = 0; i < entriesRead; ++i) {
                const SHARE_INFO_1& s = buf[i];
                if (!s.shi1_netname) continue;
                const DWORD base = s.shi1_type & 0xFFu;   // low bits = base type
                if (base == STYPE_IPC) continue;          // skip the IPC$ pipe
                std::wstring typeLbl =
                      (base == STYPE_PRINTQ) ? L"Printer"
                    : (base == STYPE_DEVICE) ? L"Device"
                    :                          L"Disk";
                if (s.shi1_type & STYPE_SPECIAL) typeLbl += L" (hidden)";
                std::wstring name   = s.shi1_netname;
                std::wstring remark = s.shi1_remark ? s.shi1_remark : L"";
                // Keep the blob clean: drop tabs/newlines from free text.
                for (auto& c : remark) if (c == L'\t' || c == L'\r' || c == L'\n') c = L' ';
                shares.push_back(name + L"\t" + typeLbl + L"\t" + remark);
            }
        }
        if (buf) ::NetApiBufferFree(buf);
        {
            std::lock_guard<std::mutex> lk(state->mu);
            state->ok     = ok;
            state->shares = std::move(shares);
            state->done   = true;
        }
        state->cv.notify_one();
    });
    } catch (...) {
        g_rpcWorkersInFlight.fetch_sub(1, std::memory_order_acq_rel);
        return out;                    // thread didn't start — release slot
    }

    bool finished = false;
    {
        std::unique_lock<std::mutex> lk(state->mu);
        finished = state->cv.wait_for(lk, std::chrono::milliseconds(timeout),
                                      [&] { return state->done; });
        if (finished && state->ok) out = std::move(state->shares);
    }
    if (finished) worker.join();
    else          worker.detach();
    return out;
}

ServiceFingerprinter::MiioHello
ServiceFingerprinter::queryMiioHello(const std::wstring& ip, int timeoutMs)
{
    MiioHello h;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return h;
    // miIO hello is also a single lossy UDP datagram — give it a generous wait
    // and retry, so an old/responsive Xiaomi device isn't missed on a dropped
    // packet. (Newer Roborock won't answer at all; the retries cost little.)
    const int perTry = (std::max)(clampTimeout(timeoutMs), 900);

    // 32-byte miIO "hello": magic 0x2131, length 0x0020, then 28 bytes 0xFF
    // (unknown + device-id + stamp + checksum placeholders).
    unsigned char hello[32];
    hello[0] = 0x21; hello[1] = 0x31; hello[2] = 0x00; hello[3] = 0x20;
    for (int i = 4; i < 32; ++i) hello[i] = 0xFF;

    char resp[64];
    int n = 0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        n = udpQuery(*ipHostOpt, 54321,
                     reinterpret_cast<const char*>(hello), 32,
                     resp, sizeof(resp), perTry);
        if (n >= 32 && static_cast<unsigned char>(resp[0]) == 0x21
                    && static_cast<unsigned char>(resp[1]) == 0x31)
            break;
        n = 0;
    }
    if (n < 32) return h;

    const unsigned char* r = reinterpret_cast<const unsigned char*>(resp);
    if (r[0] != 0x21 || r[1] != 0x31) return h;   // not a miIO header

    h.responded = true;
    h.deviceId = (static_cast<uint32_t>(r[8])  << 24)
               | (static_cast<uint32_t>(r[9])  << 16)
               | (static_cast<uint32_t>(r[10]) << 8)
               |  static_cast<uint32_t>(r[11]);
    h.stamp    = (static_cast<uint32_t>(r[12]) << 24)
               | (static_cast<uint32_t>(r[13]) << 16)
               | (static_cast<uint32_t>(r[14]) << 8)
               |  static_cast<uint32_t>(r[15]);

    bool allFF = true, allZero = true;
    for (int i = 16; i < 32; ++i) {
        if (r[i] != 0xFF) allFF   = false;
        if (r[i] != 0x00) allZero = false;
    }
    h.tokenExposed = !allFF && !allZero;
    if (h.tokenExposed) {
        wchar_t buf[40];
        for (int i = 0; i < 16; ++i) swprintf_s(buf + i * 2, 3, L"%02x", r[16 + i]);
        h.tokenHex.assign(buf, 32);
    }
    return h;
}

namespace {
// Map common UBNT model codes (TLV 0x0c) to friendly names. Not exhaustive —
// unknown codes are shown verbatim.
std::wstring ubntModelName(const std::wstring& code) {
    struct M { const wchar_t* code; const wchar_t* name; };
    static const M kModels[] = {
        { L"U7PG2",  L"UniFi AP AC Pro" },
        { L"U7LR",   L"UniFi AP AC LR" },
        { L"U7LT",   L"UniFi AP AC Lite" },
        { L"U7MSH",  L"UniFi AP AC Mesh" },
        { L"U7NHD",  L"UniFi nanoHD" },
        { L"U7HD",   L"UniFi AP HD" },
        { L"UAP6",   L"UniFi U6" },
        { L"U6LR",   L"UniFi U6 Long-Range" },
        { L"U6PRO",  L"UniFi U6 Pro" },
        { L"U6LITE", L"UniFi U6 Lite" },
        { L"U6M",    L"UniFi U6 Mesh" },
        { L"U6ENT",  L"UniFi U6 Enterprise" },
        { L"U7P",    L"UniFi U7 Pro" },
        { L"BZ2",    L"UniFi AP" },
        { L"U2HSR",  L"UniFi AP Outdoor+" },
        { L"US8P150",L"UniFi Switch 8 (150W)" },
        { L"USL16P", L"UniFi Switch Lite 16 PoE" },
        { L"USG",    L"UniFi Security Gateway" },
        { L"UGW3",   L"UniFi Security Gateway 3P" },
    };
    for (const auto& m : kModels) if (code == m.code) return m.name;
    return {};
}
} // namespace

bool ServiceFingerprinter::looksLikeUnifiModel(const std::wstring& s) {
    if (s.size() < 2 || s.size() > 24) return false;
    std::wstring u;
    u.reserve(s.size());
    for (wchar_t c : s) {
        if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
        // SKU charset only — a space or other punctuation means it's a
        // human-chosen name ("Living Room AP"), not a model code.
        if (!((c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ||
              c == L'-' || c == L'+'))
            return false;
        u.push_back(c);
    }
    static const wchar_t* kPrefix[] = {
        L"U6", L"U7", L"U8", L"UAP", L"USW", L"USG", L"UDM", L"UDR",
        L"UXG", L"UCK", L"USP", L"US-", L"UAL", L"UWB", L"UDW"
    };
    for (auto p : kPrefix) {
        size_t n = 0; while (p[n]) ++n;
        if (u.size() >= n && u.compare(0, n, p) == 0) return true;
    }
    return false;
}

ServiceFingerprinter::UbntInfo
ServiceFingerprinter::queryUbntDiscovery(const std::wstring& ip, int timeoutMs)
{
    UbntInfo info;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return info;

    // UBNT Discovery is a single, unacknowledged UDP datagram in each
    // direction, so a dropped request OR reply means "no response" — which is
    // why a one-shot probe is flaky. Mitigate with a generous per-attempt
    // wait and a few retries, and try both the v1 and v2 request bytes (some
    // firmware answers only one). All attempts target this one host (unicast),
    // so per-candidate worst case is bounded (~4 × perTry) and only runs for
    // Ubiquiti candidates.
    const int perTry = (std::max)(clampTimeout(timeoutMs), 900);

    auto parse = [&](const unsigned char* r, int n) -> bool {
        if (n < 4) return false;
        int i = 4;   // skip version/cmd + 2-byte payload length
        bool gotAny = false;
        while (i + 3 <= n) {
            const int t   = r[i];
            const int len = (r[i + 1] << 8) | r[i + 2];
            i += 3;
            if (len < 0 || i + len > n) break;
            const unsigned char* v = r + i;
            i += len;
            auto asText = [&]() {
                std::wstring s;
                for (int k = 0; k < len; ++k) {
                    unsigned char c = v[k];
                    if (c >= 0x20 && c < 0x7F) s.push_back(static_cast<wchar_t>(c));
                }
                return s;
            };
            switch (t) {
                case 0x03: info.firmware  = asText(); gotAny = true; break;
                case 0x0b: info.hostname  = asText(); gotAny = true; break;
                case 0x0c: info.modelCode = asText(); gotAny = true; break;
                case 0x14: { std::wstring m = asText(); if (!m.empty()) info.modelName = m; gotAny = true; } break;
                case 0x0a:
                    if (len >= 4)
                        info.uptime = (uint32_t(v[0])<<24)|(uint32_t(v[1])<<16)
                                    | (uint32_t(v[2])<<8)|uint32_t(v[3]);
                    break;
                default: break;
            }
        }
        return gotAny;
    };

    const unsigned char reqV1[4] = { 0x01, 0x00, 0x00, 0x00 };
    const unsigned char reqV2[4] = { 0x02, 0x08, 0x00, 0x00 };
    const unsigned char* reqs[4] = { reqV1, reqV1, reqV1, reqV2 };  // 3×v1, then v2

    char resp[1024];
    for (int attempt = 0; attempt < 4 && !info.responded; ++attempt) {
        int n = udpQuery(*ipHostOpt, 10001,
                         reinterpret_cast<const char*>(reqs[attempt]), 4,
                         resp, sizeof(resp), perTry);
        if (n >= 4 && parse(reinterpret_cast<const unsigned char*>(resp), n))
            info.responded = true;
    }

    // Resolve the cleanest display model. UniFi's free-text model TLV (0x14)
    // is unreliable — a real U6-LR has been seen to report it as
    // "Unifi-Protect-UAP-Bridge" — so prefer, in order: a mapped marketing
    // name from the model code; the device's self-reported hostname when it's
    // a UniFi SKU (the default hostname IS the model, e.g. "U6-LR"); a
    // SKU-shaped model code; and only then whatever the 0x14 TLV gave.
    std::wstring mapped = ubntModelName(info.modelCode);
    if (!mapped.empty())                          info.modelName = mapped;
    else if (looksLikeUnifiModel(info.hostname))  info.modelName = info.hostname;
    else if (looksLikeUnifiModel(info.modelCode)) info.modelName = info.modelCode;
    // else: keep the 0x14 free-text model already parsed (may be empty).
    return info;
}

bool ServiceFingerprinter::tcpConnectable(const std::wstring& ip, int port,
                                          int timeoutMs) {
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return false;
    TcpProbe tcp;
    return tcp.connect(*ipHostOpt, port, clampTimeout(timeoutMs));
}

std::wstring ServiceFingerprinter::localComputerName() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    if (::GetComputerNameW(buf, &len))
        return std::wstring(buf, len);
    return {};
}

// --- SMB dialect probe (SMB1 + SMB2/3) ----------------------------------
//
// Direct protocol-level dialect detector. Independent of NetServerGetInfo
// (which silently fails on hosts reachable only via routed paths such as
// IPSEC site-to-site tunnels — the Windows stack bakes an NBNS broadcast
// into its name-resolution step, and the broadcast never traverses the
// tunnel). This probe opens a bare TCP 445 socket and exchanges raw SMB
// negotiate frames -- no Windows session, no NetBIOS lookup -- so it
// reaches across any TCP-routable boundary.
//
// Two-step probe:
//   1) SMB2 NEGOTIATE with dialects 0x0202 .. 0x0311 + Negotiate
//      Contexts (preauth integrity + encryption capabilities). Modern
//      Windows hosts pick 0x0311; older boxes downgrade. Server may
//      also reply with DialectRevision 0x02FF meaning "I do SMB1 only,
//      ask me again with SMB1 framing" -- in which case we fall through
//      to step 2.
//   2) SMB1 SMB_COM_NEGOTIATE offering ten classic dialect strings
//      (PC NETWORK PROGRAM 1.0 ... NT LM 0.12). Server responds with
//      a 2-byte DialectIndex pointing at the offered string it picked.
//
// The fingerprint focuses on the SMB version itself: product=SMB,
// version=3.1.1 / 2.0.2 / 1.0, detail describes the dialect name and
// (parenthetically) the earliest Windows that ships it. SMB1 in
// production is itself a finding -- the report deliberately doesn't
// hide it behind a "Windows X" gloss.
namespace {

// Map an SMB2 dialect revision to a 3-tuple of strings:
// version-short / dialect-long / earliest-Windows-that-shipped-it.
struct SmbDialectInfo {
    const wchar_t* versionShort;   // "3.1.1"
    const wchar_t* dialectLong;    // "SMB 3.1.1"
    const wchar_t* windowsHint;    // "Win 10 / 11 or Server 2016+"
};

const SmbDialectInfo* smb2DialectInfo(uint16_t dialect) {
    static const SmbDialectInfo k0202{ L"2.0.2", L"SMB 2.0.2", L"Vista / Server 2008" };
    static const SmbDialectInfo k0210{ L"2.1",   L"SMB 2.1",   L"Win 7 / Server 2008 R2" };
    static const SmbDialectInfo k0300{ L"3.0",   L"SMB 3.0",   L"Win 8 / Server 2012" };
    static const SmbDialectInfo k0302{ L"3.0.2", L"SMB 3.0.2", L"Win 8.1 / Server 2012 R2" };
    static const SmbDialectInfo k0311{ L"3.1.1", L"SMB 3.1.1", L"Win 10 / 11 or Server 2016+" };
    switch (dialect) {
        case 0x0202: return &k0202;
        case 0x0210: return &k0210;
        case 0x0300: return &k0300;
        case 0x0302: return &k0302;
        case 0x0311: return &k0311;
    }
    return nullptr;
}

// SMB1 dialect strings we offer, indexed by the order we send them. The
// server replies with a 2-byte DialectIndex pointing back into this list
// (0xFFFF == none acceptable). NT LM 0.12 is the dialect that became
// "SMB 1.0" colloquially; the older ones are LAN Manager era.
struct Smb1DialectInfo {
    const char*    offered;       // exact dialect string we send
    const wchar_t* versionShort;  // what we report as fp.version
    const wchar_t* dialectLong;   // detail line
    const wchar_t* windowsHint;   // earliest Windows that shipped it
};
const Smb1DialectInfo kSmb1Dialects[] = {
    { "PC NETWORK PROGRAM 1.0",  L"core",    L"SMB Core (PC NETWORK PROGRAM 1.0)", L"DOS / OS/2 era" },
    { "MICROSOFT NETWORKS 1.03", L"1.03",    L"SMB Core+ (MICROSOFT NETWORKS 1.03)", L"DOS / OS/2 era" },
    { "MICROSOFT NETWORKS 3.0",  L"3.0",     L"SMB DOS LANMAN 1.0 (MICROSOFT NETWORKS 3.0)", L"DOS / OS/2 era" },
    { "LANMAN1.0",               L"1.0",     L"LAN Manager 1.0 (LANMAN1.0)",       L"OS/2 / Win NT 3.x" },
    { "LM1.2X002",               L"1.2X002", L"LAN Manager 2.0 (LM1.2X002)",       L"OS/2 / Win NT 3.x" },
    { "DOS LANMAN2.1",           L"2.1",     L"DOS LAN Manager 2.1",               L"OS/2 / Win NT 3.x" },
    { "LANMAN2.1",               L"2.1",     L"LAN Manager 2.1 (LANMAN2.1)",       L"Win NT 3.x" },
    { "NT LM 0.12",              L"1.0",     L"SMB 1.0 (NT LM 0.12)",              L"Win NT 4 / 2000 / XP / 2003" },
};
constexpr int kSmb1DialectCount = static_cast<int>(
    sizeof(kSmb1Dialects) / sizeof(kSmb1Dialects[0]));

// ---- Build and run an SMB2 NEGOTIATE. On success fills out `fp` and
// returns true. Returns false if the server didn't respond, refused the
// connection, or specifically indicated SMB1-only (the caller then falls
// through to the SMB1 negotiate). Caller owns the TcpProbe.
bool tryRunSmb2Negotiate(uint32_t ipHost, int timeout, ServiceFingerprint& fp) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, 445, timeout)) return false;

    constexpr int kReq = 180;
    unsigned char req[kReq] = {0};
    req[0] = 0x00;
    const int smbLen = kReq - 4;
    req[1] = static_cast<unsigned char>((smbLen >> 16) & 0xFF);
    req[2] = static_cast<unsigned char>((smbLen >> 8)  & 0xFF);
    req[3] = static_cast<unsigned char>( smbLen        & 0xFF);
    req[4] = 0xFE; req[5] = 'S'; req[6] = 'M'; req[7] = 'B';
    req[8] = 64;                                       // SMB2 StructureSize
    req[18] = 1;                                       // 1 credit
    constexpr int kBody = 68;
    req[kBody + 0] = 36;                               // body structure size
    req[kBody + 2] = 5;                                // 5 dialects
    req[kBody + 4] = 0x01;                             // SIGNING_ENABLED
    req[kBody + 28] = 112;                             // NegotiateContextOffset
    req[kBody + 32] = 2;                               // NegotiateContextCount
    auto putLE16 = [&](int off, uint16_t v) {
        req[off]     = static_cast<unsigned char>(v & 0xFF);
        req[off + 1] = static_cast<unsigned char>((v >> 8) & 0xFF);
    };
    int kDial = 104;
    putLE16(kDial + 0, 0x0202);
    putLE16(kDial + 2, 0x0210);
    putLE16(kDial + 4, 0x0300);
    putLE16(kDial + 6, 0x0302);
    putLE16(kDial + 8, 0x0311);
    int kCtx1 = 116;
    putLE16(kCtx1 + 0,  0x0001);  // PREAUTH_INTEGRITY_CAPABILITIES
    putLE16(kCtx1 + 2,  38);
    putLE16(kCtx1 + 8,  1);       // HashAlgorithmCount
    putLE16(kCtx1 + 10, 32);      // SaltLength
    putLE16(kCtx1 + 12, 0x0001);  // SHA-512
    int kCtx2 = 168;
    putLE16(kCtx2 + 0, 0x0002);   // ENCRYPTION_CAPABILITIES
    putLE16(kCtx2 + 2, 4);
    putLE16(kCtx2 + 8, 1);
    putLE16(kCtx2 + 10, 0x0001);  // AES-128-CCM

    std::string reqStr(reinterpret_cast<const char*>(req), kReq);
    if (!tcp.sendAll(reqStr, timeout)) return false;

    char rbuf[1024];
    int total = 0;
    ULONGLONG deadline = ::GetTickCount64() + static_cast<ULONGLONG>(timeout);
    while (total < 80) {
        ULONGLONG now = ::GetTickCount64();
        if (now >= deadline) break;
        int n = tcp.recvChunk(rbuf + total,
                              static_cast<int>(sizeof(rbuf)) - total,
                              static_cast<int>(deadline - now));
        if (n <= 0) break;
        total += n;
    }
    if (total < 4 + 64 + 6) return false;

    const unsigned char* rb = reinterpret_cast<const unsigned char*>(rbuf);
    if (rb[0] != 0x00) return false;
    if (rb[4] != 0xFE || rb[5] != 'S'
     || rb[6] != 'M'  || rb[7] != 'B') return false;
    uint32_t status = static_cast<uint32_t>(rb[12])
                    | (static_cast<uint32_t>(rb[13]) << 8)
                    | (static_cast<uint32_t>(rb[14]) << 16)
                    | (static_cast<uint32_t>(rb[15]) << 24);
    if (status != 0) return false;
    uint16_t dialect = static_cast<uint16_t>(rb[72])
                     | (static_cast<uint16_t>(rb[73]) << 8);

    if (dialect == 0x02FF) {
        // Server explicitly told us "I only do SMB1" -- bail to caller
        // so the SMB1 path runs and gives a more specific dialect.
        return false;
    }
    const SmbDialectInfo* info = smb2DialectInfo(dialect);
    if (!info) return false;

    fp.port       = 445;
    fp.protocol   = L"tcp";
    fp.service    = L"smb";
    fp.product    = L"SMB";
    fp.version    = info->versionShort;
    fp.source     = L"SMB NEGOTIATE";
    fp.confidence = L"High";
    fp.detail     = std::wstring(info->dialectLong)
                  + L" -- " + info->windowsHint;
    return true;
}

// ---- SMB1 SMB_COM_NEGOTIATE. Used only when the SMB2 path returned
// dialect 0x02FF or when the server refused SMB2 framing outright.
bool tryRunSmb1Negotiate(uint32_t ipHost, int timeout, ServiceFingerprint& fp) {
    TcpProbe tcp;
    if (!tcp.connect(ipHost, 445, timeout)) return false;

    // Build the negotiate request.
    //
    // SMB1 header: 32 bytes.
    //   0..3   Protocol: 0xFF 'S' 'M' 'B'
    //   4      Command: 0x72 (SMB_COM_NEGOTIATE)
    //   5..8   Status: 0
    //   9      Flags: 0x18 (CANONICALIZED_PATHS | CASELESS_PATHNAMES)
    //   10..11 Flags2: 0xC853 (UNICODE | NT_STATUS | EXTENDED_SECURITY |
    //                          LONG_NAMES | NT_STATUS | etc -- standard
    //                          modern client posture)
    //   12..13 PIDHigh: 0
    //   14..21 Signature: 0
    //   22..23 Reserved: 0
    //   24..25 TID: 0
    //   26..27 PIDLow: 0xFEFF (any value)
    //   28..29 UID: 0
    //   30..31 MID: 1
    // WordCount byte = 0
    // ByteCount uint16_le = length of dialect list
    // Dialect list: for each offered dialect, byte 0x02 then NUL-terminated string.
    std::string body;
    for (const auto& d : kSmb1Dialects) {
        body.push_back('\x02');
        body.append(d.offered);
        body.push_back('\0');
    }

    const int hdrAndBody = 32                       // SMB header
                         + 1                        // WordCount
                         + 2                        // ByteCount
                         + static_cast<int>(body.size());
    const int total      = 4 + hdrAndBody;          // + NetBIOS frame
    std::string req(total, '\0');

    auto* p = reinterpret_cast<unsigned char*>(&req[0]);
    // NetBIOS frame
    p[0] = 0x00;
    p[1] = static_cast<unsigned char>((hdrAndBody >> 16) & 0xFF);
    p[2] = static_cast<unsigned char>((hdrAndBody >> 8)  & 0xFF);
    p[3] = static_cast<unsigned char>( hdrAndBody        & 0xFF);
    // SMB1 header at offset 4
    p[4] = 0xFF; p[5] = 'S'; p[6] = 'M'; p[7] = 'B';
    p[8] = 0x72;                                    // SMB_COM_NEGOTIATE
    p[13] = 0x18;                                   // Flags
    p[14] = 0x53; p[15] = 0xC8;                     // Flags2 (LE)
    p[30] = 0xFF; p[31] = 0xFE;                     // PIDLow
    p[34] = 0;   p[35] = 0;                         // UID
    p[34] = 0;   p[35] = 0;
    p[34] = 0;   p[35] = 0;                         // (defensive duplicates a no-op)
    p[34] = 0;   p[35] = 0;
    p[34] = 0;   p[35] = 0;
    p[34] = 1;   p[35] = 0;                         // MID
    // WordCount (offset 4 + 32 = 36)
    p[36] = 0;
    // ByteCount uint16 LE (offset 37)
    p[37] = static_cast<unsigned char>(body.size() & 0xFF);
    p[38] = static_cast<unsigned char>((body.size() >> 8) & 0xFF);
    // Dialect list (offset 39)
    memcpy(p + 39, body.data(), body.size());

    if (!tcp.sendAll(req, timeout)) return false;

    char rbuf[1024];
    int read = 0;
    ULONGLONG deadline = ::GetTickCount64() + static_cast<ULONGLONG>(timeout);
    while (read < 50) {
        ULONGLONG now = ::GetTickCount64();
        if (now >= deadline) break;
        int n = tcp.recvChunk(rbuf + read,
                              static_cast<int>(sizeof(rbuf)) - read,
                              static_cast<int>(deadline - now));
        if (n <= 0) break;
        read += n;
    }
    if (read < 4 + 32 + 1 + 2 + 2) return false;

    const unsigned char* rb = reinterpret_cast<const unsigned char*>(rbuf);
    if (rb[0] != 0x00) return false;
    // Some servers reply with an SMB2 packet here even though we sent SMB1
    // (when they pick "SMB 2.???"). Detect and bail -- SMB2 path will
    // handle the next attempt (or has already).
    if (rb[4] == 0xFE) return false;
    if (rb[4] != 0xFF || rb[5] != 'S'
     || rb[6] != 'M'  || rb[7] != 'B') return false;

    // Selected DialectIndex is the first parameter word AFTER the
    // WordCount byte at offset 4 + 32 = 36. So it lives at offset 37.
    uint16_t idx = static_cast<uint16_t>(rb[37])
                 | (static_cast<uint16_t>(rb[38]) << 8);
    if (idx == 0xFFFF) return false;                // no dialect picked
    if (idx >= static_cast<uint16_t>(kSmb1DialectCount)) return false;

    const Smb1DialectInfo& info = kSmb1Dialects[idx];
    fp.port       = 445;
    fp.protocol   = L"tcp";
    fp.service    = L"smb";
    fp.product    = L"SMB";
    fp.version    = info.versionShort;
    fp.source     = L"SMB NEGOTIATE";
    fp.confidence = L"High";
    fp.detail     = std::wstring(info.dialectLong)
                  + L" -- " + info.windowsHint;
    return true;
}

}  // namespace

ServiceFingerprint
ServiceFingerprinter::queryWindowsSmbDialect(const std::wstring& ip,
                                             int timeoutMs)
{
    ServiceFingerprint fp;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return fp;
    const int timeout = clampTimeout(timeoutMs);

    // SMB2 first -- the modern protocol covers 99% of live hosts. If the
    // server only does SMB1 (Windows NT, 2000, 2003 / Samba in legacy
    // mode) tryRunSmb2Negotiate returns false and we fall through.
    if (tryRunSmb2Negotiate(*ipHostOpt, timeout, fp)) return fp;

    // SMB1 fallback. Used for SMB1-only hosts.
    if (tryRunSmb1Negotiate(*ipHostOpt, timeout, fp)) return fp;

    return fp;   // port stays 0 on failure
}

ServiceFingerprinter::ZebraStatus
ServiceFingerprinter::queryZebraStatus(const std::wstring& ip, int timeoutMs) {
    ZebraStatus z;
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return z;
    const int timeout = clampTimeout(timeoutMs);

    TcpProbe tcp;
    if (!tcp.connect(*ipHostOpt, 9100, timeout)) return z;

    // SGD getvar batch. Zebra answers each command with the value wrapped in
    // double quotes, in request order; an unsupported var comes back as "?".
    static const char* kReq =
        "! U1 getvar \"appl.name\"\r\n"
        "! U1 getvar \"device.product_name\"\r\n"
        "! U1 getvar \"odometer.total_label_count\"\r\n"
        "! U1 getvar \"odometer.total_print_length\"\r\n";
    if (!tcp.sendAll(kReq, timeout)) return z;

    // Drain the (small) reply. Zebra keeps 9100 open, so there's no clean
    // close to wait for — recvUntil collects whatever lands within the
    // timeout budget, plenty for four short quoted values.
    std::string resp;
    tcp.recvUntil(resp, 2048, timeout, nullptr);
    if (resp.empty()) return z;

    // Pull the quoted tokens out in order.
    std::vector<std::string> vals;
    size_t i = 0;
    while (vals.size() < 8) {
        size_t q1 = resp.find('"', i);
        if (q1 == std::string::npos) break;
        size_t q2 = resp.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        vals.push_back(resp.substr(q1 + 1, q2 - q1 - 1));
        i = q2 + 1;
    }
    if (vals.empty()) return z;

    auto field = [&](size_t idx) -> std::string {
        if (idx >= vals.size()) return {};
        std::string s = vals[idx];
        if (s == "?") return {};          // var not supported on this model
        return s;
    };

    z.responded   = true;
    z.firmware    = sanitize(field(0), 48);
    z.model       = sanitize(field(1), 64);
    z.printLength = sanitize(field(3), 48);

    const std::string labels = field(2);
    if (!labels.empty()) {
        bool numeric = true;
        int64_t n = 0;
        for (char c : labels) {
            if (c < '0' || c > '9') { numeric = false; break; }
            n = n * 10 + (c - '0');
            if (n > 1000000000LL) { numeric = false; break; }
        }
        if (numeric) z.labelCount = n;
    }
    return z;
}

std::wstring ServiceFingerprinter::queryNbnsName(const std::wstring& ip,
                                                 int timeoutMs)
{
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return {};
    const int timeout = clampTimeout(timeoutMs);

    // Wildcard NetBIOS node-status query — RFC 1002 §4.2.18. The encoded name
    // is "*\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" (16 bytes) — the wildcard that any
    // NetBIOS node answers regardless of its registered names. The 16 bytes
    // get expanded into the 32-byte half-ASCII "second-level encoding":
    // each byte is split into nibbles and each nibble + 'A' becomes one
    // ASCII character. For the wildcard that's "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    static const unsigned char kQuery[50] = {
        // Header — 12 bytes
        0x00, 0x00,             // Transaction ID
        0x00, 0x10,             // Flags: standard query, broadcast
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, // ANCOUNT / NSCOUNT
        0x00, 0x00,             // ARCOUNT
        // Question — 36 bytes
        0x20,                   // label length = 32
        'C','K',                // wildcard '*' (0x2A) encoded
        'A','A','A','A','A','A','A','A','A','A','A','A','A','A',
        'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
        0x00,                   // root label terminator
        0x00, 0x21,             // QTYPE = NBSTAT (0x21)
        0x00, 0x01              // QCLASS = IN
    };

    char resp[1500] = {};
    int n = udpQuery(*ipHostOpt, 137,
                     reinterpret_cast<const char*>(kQuery), sizeof(kQuery),
                     resp, sizeof(resp), timeout);
    // Header (12) + answer name (34) + type/class/ttl/rdlen (10) + min rdata (1
    // num_names byte) → 57 bytes minimum for any meaningful reply.
    if (n < 57) return {};

    const unsigned char* r = reinterpret_cast<const unsigned char*>(resp);
    // ANCOUNT must be > 0.
    if (((r[6] << 8) | r[7]) < 1) return {};

    // Skip the header (12) and the answer name (34 bytes: 1+32+1), then the
    // 10-byte answer prefix (TYPE, CLASS, TTL, RDLEN). After that the rdata
    // for NBSTAT starts with a one-byte NUM_NAMES, then 18 bytes per name
    // (15 chars + 1 type byte + 2 flag bytes).
    constexpr int kRdataStart = 12 + 34 + 10;
    if (n <= kRdataStart) return {};
    int numNames = r[kRdataStart];
    if (numNames < 1 || numNames > 32) return {};

    // Walk the name list. Each entry: 16 bytes name + 2 bytes flags.
    // Flags layout (big-endian, RFC 1002 §4.2.18):
    //   bit 15 (0x8000) = GROUP        — set for group names like \01\02__MSBROWSE__
    //   bits 14..13     = ONT          — 00 B-node, 01 P-node, 10 M-node, 11 H-node
    //   bit 12 (0x1000) = DRG          — deregister in progress
    //   bit 11 (0x0800) = CNF          — conflict
    //   bit 10 (0x0400) = ACT          — active
    //   bit  9 (0x0200) = PRM          — permanent
    // Pick the first UNIQUE (i.e. non-GROUP) name with suffix 0x00 (workstation).
    int pos = kRdataStart + 1;
    std::wstring chosen;
    for (int i = 0; i < numNames; ++i) {
        if (pos + 18 > n) break;
        const unsigned char* e = r + pos;
        unsigned char suffix   = e[15];
        unsigned char flagHi   = e[16];
        bool   isGroup = (flagHi & 0x80) != 0;
        // Decode the 15-char padded name, trim trailing spaces and controls.
        std::wstring name;
        for (int k = 0; k < 15; ++k) {
            unsigned char c = e[k];
            if (c >= 0x20 && c < 0x7F) name.push_back(static_cast<wchar_t>(c));
        }
        while (!name.empty() && (name.back() == L' ' || name.back() == 0))
            name.pop_back();

        if (!isGroup && suffix == 0x00 && !name.empty() && chosen.empty()) {
            chosen = name;       // workstation/computer name — keep first match
        }
        pos += 18;
    }
    return chosen;
}

std::wstring ServiceFingerprinter::queryMdnsReverseName(const std::wstring& ip,
                                                        int timeoutMs)
{
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return {};
    const int timeout = clampTimeout(timeoutMs);

    // Build the reverse-DNS arpa name: "d.c.b.a.in-addr.arpa" for IP a.b.c.d.
    uint32_t v = *ipHostOpt;
    int a = (v >> 24) & 0xFF, b = (v >> 16) & 0xFF;
    int c = (v >>  8) & 0xFF, d =  v        & 0xFF;
    wchar_t arpa[64];
    swprintf_s(arpa, L"%d.%d.%d.%d.in-addr.arpa", d, c, b, a);

    std::string req = buildDnsQuery(arpa, 12 /* PTR */);
    char resp[1500] = {};
    int n = udpQuery(*ipHostOpt, 5353,
                     req.data(), static_cast<int>(req.size()),
                     resp, sizeof(resp), timeout);
    if (n <= 0) return {};

    std::vector<std::wstring> answers;
    if (!parseDnsPtrAnswers(std::string(resp, static_cast<size_t>(n)), answers))
        return {};
    if (answers.empty()) return {};

    // Pick the first answer, strip the trailing ".local" / ".local." that
    // mDNS appends so the grid shows just the host label.
    std::wstring name = answers.front();
    auto endsWith = [&](const wchar_t* suf) {
        size_t L = wcslen(suf);
        if (name.size() < L) return false;
        return name.compare(name.size() - L, L, suf) == 0;
    };
    if (endsWith(L".local.")) name.resize(name.size() - 7);
    else if (endsWith(L".local")) name.resize(name.size() - 6);
    while (!name.empty() && name.back() == L'.') name.pop_back();
    // Sanitise — strip any leftover control chars / weirdness that survived
    // the DNS-label decoder.
    std::wstring clean;
    clean.reserve(name.size());
    for (wchar_t wc : name) {
        if (wc >= 0x20 && wc < 0x7F && wc != L' ')
            clean.push_back(wc);
    }
    return clean;
}

ServiceFingerprint ServiceFingerprinter::queryAppleDeviceInfo(
    const std::wstring& ip, int timeoutMs)
{
    ServiceFingerprint fp;                  // port=0 sentinel — caller drops it
    auto ipHostOpt = ip::parseDotted(ip);
    if (!ipHostOpt) return fp;
    const uint32_t host = *ipHostOpt;
    const int t = clampTimeout(timeoutMs);

    // Out-of-band TCP signals. These run in series here, but the whole probe
    // runs in parallel across the worker pool — a Mac/iPhone with three closed
    // ports costs three timeouts (worst case ~3·t), not three sweeps.
    const bool has62078 = tcpPortReachable(host, 62078, t);  // iOS lockdownd
    const bool has7000  = tcpPortReachable(host, 7000,  t);  // AirPlay
    const bool has3689  = tcpPortReachable(host, 3689,  t);  // DAAP (Apple TV)

    // Single unicast mDNS query for the service-meta record. Apple devices
    // answer this without joining the multicast group.
    auto services = mdnsServiceTypes(host, t);

    // Service-type → device-class signals. Each substring is matched against
    // the full PTR name so e.g. "_airplay._tcp.local" matches "_airplay".
    const bool sMobdev2     = servicesContain(services, L"_apple-mobdev2");
    const bool sCompanion   = servicesContain(services, L"_companion-link");
    const bool sRdlink      = servicesContain(services, L"_rdlink");
    const bool sWorkstation = servicesContain(services, L"_workstation");
    const bool sSmb         = servicesContain(services, L"_smb._tcp");
    const bool sAfp         = servicesContain(services, L"_afpovertcp");
    const bool sSshSvc      = servicesContain(services, L"_ssh._tcp");
    const bool sAirplay     = servicesContain(services, L"_airplay");
    const bool sRaop        = servicesContain(services, L"_raop");
    const bool sAtc         = servicesContain(services, L"_atc._tcp");
    const bool sAppleTv     = servicesContain(services, L"_appletv-v2") ||
                              servicesContain(services, L"_mediaremotetv");
    const bool sHomekit     = servicesContain(services, L"_homekit");
    const bool sRemotePair  = servicesContain(services, L"_remotepairing") ||
                              servicesContain(services, L"_remoted._tcp");

    // Composite classifications. Order of selection (below) goes most-specific
    // → least-specific, because e.g. an Apple TV also advertises _airplay, so
    // we test the AppleTV-specific signal first.
    const bool isMac =
        sRdlink || sWorkstation || sSmb || sAfp ||
        (sCompanion && sSshSvc);
    const bool isAppleTv =
        sAtc || sAppleTv || (has3689 && sAirplay);
    const bool isHomePod =
        (!isMac && !isAppleTv) && (
            (has7000 && sRaop && !sCompanion) ||
            (sAirplay && sRaop && !sCompanion && sHomekit));
    const bool isMobile =
        !isMac && !isAppleTv && !isHomePod && (
            has62078 || sMobdev2 || sRemotePair ||
            (sCompanion && !sRdlink && !sSshSvc && !sWorkstation));

    std::wstring label;
    if      (isAppleTv) label = L"Apple TV";
    else if (isHomePod) label = L"HomePod";
    else if (isMobile)  label = L"iPhone / iPad";
    else if (isMac)     label = L"Mac";
    else if (has7000 && sAirplay) label = L"AirPlay receiver";

    // Nothing positive anywhere → return an empty fingerprint so the existing
    // vendor-only "Mac" fallback in DeviceClassifier kicks in.
    if (label.empty() && services.empty() &&
        !has62078 && !has7000 && !has3689)
        return fp;

    // Evidence string — bounded, helps debugging in the host-details dialog.
    std::wstring detail;
    auto addEv = [&](const wchar_t* s) {
        if (!detail.empty()) detail += L", ";
        detail += s;
    };
    if (has62078) addEv(L"lockdownd/62078");
    if (has7000)  addEv(L"AirPlay/7000");
    if (has3689)  addEv(L"DAAP/3689");

    static const wchar_t* const kInterest[] = {
        L"_apple-mobdev2", L"_companion-link", L"_rdlink", L"_workstation",
        L"_smb._tcp", L"_afpovertcp", L"_ssh._tcp", L"_airplay",
        L"_raop", L"_atc._tcp", L"_appletv-v2", L"_mediaremotetv",
        L"_homekit", L"_remotepairing"
    };
    int shown = 0;
    for (const auto& s : services) {
        if (shown >= 5) break;
        for (const wchar_t* w : kInterest) {
            if (s.find(w) != std::wstring::npos) {
                addEv(w + 1);              // strip the leading underscore
                ++shown;
                break;
            }
        }
    }

    fp.port       = 5353;
    fp.protocol   = L"udp";
    fp.service    = L"apple";
    fp.product    = label.empty() ? L"Apple device" : label;
    fp.source     = L"mDNS + Apple TCP probes";
    fp.confidence = label.empty() ? L"Low" : L"Medium";
    fp.detail     = detail;
    return fp;
}

ServiceFingerprint ServiceFingerprinter::clockDriftFingerprint(
    const ClockDriftInfo& d)
{
    ServiceFingerprint fp;
    fp.service    = L"clock";
    fp.confidence = L"High";
    fp.detail     = L"Offset " + d.offsetText()
                  + L", RTT " + std::to_wstring(d.roundTripMs) + L" ms";
    if (d.source == L"net time") {
        fp.port     = 445;
        fp.protocol = L"tcp";
        fp.product  = L"Windows Time";
        fp.source   = L"NetRemoteTOD (net time)";
    } else {
        fp.port     = 123;
        fp.protocol = L"udp";
        fp.product  = L"NTP";
        fp.source   = L"NTP response";
    }
    return fp;
}

} // namespace lanscope
