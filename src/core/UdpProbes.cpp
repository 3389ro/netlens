#include "UdpProbes.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace netlens {

namespace {

// =============================================================================
// Helpers
// =============================================================================

std::wstring widenUtf8(const char* p, size_t n) {
    if (n == 0) return {};
    int needed = ::MultiByteToWideChar(CP_UTF8, 0, p, static_cast<int>(n), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, p, static_cast<int>(n), out.data(), needed);
    return out;
}

std::wstring widenAscii(const char* p, size_t n) {
    std::wstring out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(p[i]);
        out.push_back(c < 0x80 ? static_cast<wchar_t>(c) : L'?');
    }
    return out;
}

std::wstring trimWs(std::wstring s) {
    auto isWs = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
    while (!s.empty() && isWs(s.back()))  s.pop_back();
    size_t a = 0;
    while (a < s.size() && isWs(s[a])) ++a;
    return s.substr(a);
}

uint32_t randomUint32() {
    static thread_local std::mt19937 rng{ std::random_device{}() };
    return rng();
}

// =============================================================================
// Probe payload builders
// =============================================================================

// NBSTAT (UDP 137) — NetBIOS name service query for "*".
// The wildcard name "*" is encoded into the 32-char first-nibble form
// "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
std::vector<uint8_t> buildNbstat() {
    static const uint8_t kQuery[] = {
        0x00, 0x00,             // transaction id (we replace [0..1] below)
        0x00, 0x00,             // flags: standard query, no recursion
        0x00, 0x01,             // questions = 1
        0x00, 0x00,             // answer RRs
        0x00, 0x00,             // authority RRs
        0x00, 0x00,             // additional RRs
        0x20,                   // length of encoded name (0x20 = 32)
        'C','K','A','A','A','A','A','A',
        'A','A','A','A','A','A','A','A',
        'A','A','A','A','A','A','A','A',
        'A','A','A','A','A','A','A','A',
        0x00,                   // root label terminator
        0x00, 0x21,             // type = NBSTAT (0x21)
        0x00, 0x01              // class = IN
    };
    std::vector<uint8_t> q(std::begin(kQuery), std::end(kQuery));
    uint16_t txid = static_cast<uint16_t>(randomUint32());
    q[0] = static_cast<uint8_t>(txid >> 8);
    q[1] = static_cast<uint8_t>(txid & 0xff);
    return q;
}

// mDNS (UDP 5353) — DNS-SD service-enumeration query.
// Question: "_services._dns-sd._udp.local" type PTR.
// We set the class to 0x8001 (QU bit) so the responder unicasts the answer
// back to us instead of multicasting it.
std::vector<uint8_t> buildMdns() {
    static const uint8_t kPayload[] = {
        0x00, 0x00,             // txid
        0x00, 0x00,             // flags
        0x00, 0x01,             // qdcount = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // _services
        9, '_','s','e','r','v','i','c','e','s',
        // _dns-sd
        7, '_','d','n','s','-','s','d',
        // _udp
        4, '_','u','d','p',
        // local
        5, 'l','o','c','a','l',
        0x00,                   // terminator
        0x00, 0x0c,             // type = PTR
        0x80, 0x01              // class = IN with QU bit
    };
    return std::vector<uint8_t>(std::begin(kPayload), std::end(kPayload));
}

// SSDP (UDP 1900) — M-SEARCH for ssdp:all.
// Unicast send to host:1900; modern UPnP devices respond.
std::vector<uint8_t> buildSsdp() {
    static const char kReq[] =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n";
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(kReq),
                                reinterpret_cast<const uint8_t*>(kReq) + sizeof(kReq) - 1);
}

// SNMPv1 (UDP 161) — GetRequest sysDescr.0 with community "public".
// BER-encoded by hand because we only ever send this exact PDU.
std::vector<uint8_t> buildSnmp() {
    uint32_t reqId = randomUint32() & 0x7fffffff;
    std::vector<uint8_t> q = {
        0x30, 0x26,                                  // SEQUENCE, length 38
        0x02, 0x01, 0x00,                            // version (0 == SNMPv1)
        0x04, 0x06,'p','u','b','l','i','c',          // community "public"
        0xa0, 0x19,                                  // GetRequest PDU, length 25
            0x02, 0x04,                              // request-id (INTEGER, 4 bytes)
            static_cast<uint8_t>((reqId >> 24) & 0xff),
            static_cast<uint8_t>((reqId >> 16) & 0xff),
            static_cast<uint8_t>((reqId >>  8) & 0xff),
            static_cast<uint8_t>( reqId        & 0xff),
            0x02, 0x01, 0x00,                        // error-status = 0
            0x02, 0x01, 0x00,                        // error-index  = 0
            0x30, 0x0b,                              // var-binds SEQUENCE, length 11
                0x30, 0x09,                          //  var-bind SEQUENCE, length 9
                    0x06, 0x08,                      //   OID, 8 bytes
                    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // 1.3.6.1.2.1.1.1.0
                    0x05, 0x00                       //   NULL
    };
    return q;
}

// DNS version.bind CHAOS TXT (UDP 53).
std::vector<uint8_t> buildDnsVersion() {
    std::vector<uint8_t> q;
    q.reserve(32);
    uint16_t txid = static_cast<uint16_t>(randomUint32());
    q.push_back(static_cast<uint8_t>(txid >> 8));
    q.push_back(static_cast<uint8_t>(txid & 0xff));
    q.push_back(0x00); q.push_back(0x00);                 // flags
    q.push_back(0x00); q.push_back(0x01);                 // qdcount
    q.push_back(0x00); q.push_back(0x00);                 // ancount
    q.push_back(0x00); q.push_back(0x00);                 // nscount
    q.push_back(0x00); q.push_back(0x00);                 // arcount
    // name: 7 "version" 4 "bind" 0
    static const char kName[] = "\x07version\x04""bind";
    q.insert(q.end(),
             reinterpret_cast<const uint8_t*>(kName),
             reinterpret_cast<const uint8_t*>(kName) + sizeof(kName) - 1);
    q.push_back(0x00);                                    // root label
    q.push_back(0x00); q.push_back(0x10);                 // type = TXT (16)
    q.push_back(0x00); q.push_back(0x03);                 // class = CHAOS (3)
    return q;
}

// NTPv4 client request (UDP 123).
std::vector<uint8_t> buildNtp() {
    std::vector<uint8_t> q(48, 0);
    q[0] = 0x23;  // LI=0, VN=4, Mode=3 (client)
    return q;
}

// =============================================================================
// Response parsers
// =============================================================================

// Read a DNS-style name starting at buf[off]. Handles compression pointers
// (0xC0+) by following one level (RFC 1035). Writes the decoded text to
// `out` (labels joined by '.'). Returns the offset just past the name (for
// the caller to continue reading type/class), or -1 on parse error.
int readDnsName(const uint8_t* buf, int len, int off,
                std::string& out, int hops = 0) {
    if (hops > 8) return -1;  // protect against pointer loops
    if (off < 0 || off >= len) return -1;
    out.clear();
    int origOff = off;
    bool followedPointer = false;
    int safety = 256;
    while (safety-- > 0 && off < len) {
        uint8_t b = buf[off];
        if (b == 0) {
            off += 1;
            return followedPointer ? origOff + 2 : off;
        }
        if ((b & 0xc0) == 0xc0) {
            if (off + 1 >= len) return -1;
            int ptr = ((b & 0x3f) << 8) | buf[off + 1];
            std::string tail;
            if (readDnsName(buf, len, ptr, tail, hops + 1) < 0) return -1;
            if (!out.empty() && !tail.empty()) out.push_back('.');
            out += tail;
            return followedPointer ? origOff + 2 : (off + 2);
        }
        if (b > 63) return -1;
        if (off + 1 + b > len) return -1;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(buf + off + 1), b);
        off += 1 + b;
    }
    return -1;
}

// NBSTAT response parser.
void parseNbstat(const uint8_t* buf, int len, UdpServiceInfo& out) {
    if (len < 12 + 34 + 10 + 1) return;
    // Skip DNS header (12) + echoed answer name (34) + type/class/ttl/rdlength (10).
    int off = 12 + 34 + 10;
    if (off + 1 > len) return;
    int numNames = buf[off];
    ++off;
    if (off + numNames * 18 > len) return;

    for (int i = 0; i < numNames; ++i) {
        // 15 bytes padded name + 1 byte suffix + 2 bytes flags.
        const uint8_t* nameRaw  = buf + off + i * 18;
        uint8_t        suffix   = nameRaw[15];
        uint16_t       flags    = static_cast<uint16_t>(
                                      (nameRaw[16] << 8) | nameRaw[17]);
        bool           groupBit = (flags & 0x8000) != 0;

        // Trim trailing 0x20 spaces.
        int nameLen = 15;
        while (nameLen > 0 && nameRaw[nameLen - 1] == 0x20) --nameLen;
        std::wstring name = widenAscii(reinterpret_cast<const char*>(nameRaw), nameLen);
        if (name.empty()) continue;

        // 0x00 unique  => workstation / computer name
        // 0x00 group   => workgroup
        // 0x1B unique  => domain master browser
        // 0x1C group   => domain controller
        // 0x1D unique  => master browser
        // 0x1E group   => browser elections / workgroup
        // 0x20 unique  => file server service
        if (suffix == 0x00 && !groupBit && out.netbiosName.empty()) {
            out.netbiosName = name;
        } else if (suffix == 0x00 && groupBit && out.netbiosWorkgroup.empty()) {
            out.netbiosWorkgroup = name;
        } else if (suffix == 0x1E && out.netbiosWorkgroup.empty()) {
            out.netbiosWorkgroup = name;
        }
    }
}

// mDNS DNS-SD response parser. Walks the answer section and extracts PTR
// records (service-type names).
void parseMdns(const uint8_t* buf, int len, UdpServiceInfo& out) {
    if (len < 12) return;
    int qdcount = (buf[4] << 8) | buf[5];
    int ancount = (buf[6] << 8) | buf[7];
    if (ancount == 0) return;
    int off = 12;
    // Skip questions.
    for (int q = 0; q < qdcount; ++q) {
        std::string tmp;
        int next = readDnsName(buf, len, off, tmp);
        if (next < 0 || next + 4 > len) return;
        off = next + 4; // skip type+class
    }
    // Walk answers.
    for (int a = 0; a < ancount; ++a) {
        std::string nameStr;
        int next = readDnsName(buf, len, off, nameStr);
        if (next < 0 || next + 10 > len) return;
        int type     = (buf[next] << 8) | buf[next + 1];
        // class+ttl skipped
        int rdlength = (buf[next + 8] << 8) | buf[next + 9];
        int rdoff    = next + 10;
        if (rdoff + rdlength > len) return;

        if (type == 12 /* PTR */) {
            std::string ptrTarget;
            if (readDnsName(buf, len, rdoff, ptrTarget) > 0 && !ptrTarget.empty()) {
                // Limit how many service entries we surface (avoid blow-up
                // on chatty devices).
                if (out.mdnsServices.size() < 16) {
                    out.mdnsServices.push_back(widenUtf8(ptrTarget.data(), ptrTarget.size()));
                }
            }
        }
        off = rdoff + rdlength;
    }
}

// Case-insensitive header pluck from an SSDP/HTTP-style text block.
std::wstring pickHeader(const std::string& block, const char* headerName) {
    size_t pos = 0;
    while (pos < block.size()) {
        size_t eol = block.find('\n', pos);
        if (eol == std::string::npos) eol = block.size();
        size_t colon = block.find(':', pos);
        if (colon != std::string::npos && colon < eol) {
            std::string key = block.substr(pos, colon - pos);
            // Strip CR / trailing whitespace from key.
            while (!key.empty() && (key.back() == ' ' || key.back() == '\t' || key.back() == '\r')) {
                key.pop_back();
            }
            if (_stricmp(key.c_str(), headerName) == 0) {
                size_t vstart = colon + 1;
                while (vstart < eol && (block[vstart] == ' ' || block[vstart] == '\t')) ++vstart;
                size_t vend = eol;
                while (vend > vstart && (block[vend - 1] == ' ' || block[vend - 1] == '\t' || block[vend - 1] == '\r')) --vend;
                return widenUtf8(block.data() + vstart, vend - vstart);
            }
        }
        pos = eol + 1;
    }
    return {};
}

void parseSsdp(const uint8_t* buf, int len, UdpServiceInfo& out) {
    std::string s(reinterpret_cast<const char*>(buf),
                  reinterpret_cast<const char*>(buf) + len);
    // Sanity-check it looks like an HTTP response.
    if (s.size() < 8 || s.compare(0, 4, "HTTP") != 0) return;
    out.upnpServer   = pickHeader(s, "SERVER");
    out.upnpLocation = pickHeader(s, "LOCATION");
}

// BER tag-length-value reader: returns position past length, fills `lenOut`.
// Only handles short-form and 1-byte long-form (8x XX), which is enough for
// the SNMP responses we care about (<255 byte fields).
int berReadTL(const uint8_t* buf, int len, int off, uint8_t* tagOut, int* lenOut) {
    if (off + 2 > len) return -1;
    *tagOut = buf[off];
    uint8_t l = buf[off + 1];
    if (l < 0x80) {
        *lenOut = l;
        return off + 2;
    }
    int n = l & 0x7f;
    if (n < 1 || n > 4) return -1;
    if (off + 2 + n > len) return -1;
    int v = 0;
    for (int i = 0; i < n; ++i) v = (v << 8) | buf[off + 2 + i];
    *lenOut = v;
    return off + 2 + n;
}

void parseSnmp(const uint8_t* buf, int len, UdpServiceInfo& out) {
    // Walk: outer SEQUENCE -> version INT -> community OCTET -> PDU.
    uint8_t tag;
    int     l;
    int     off = berReadTL(buf, len, 0, &tag, &l);
    if (off < 0 || tag != 0x30) return;

    // Skip version (INTEGER) and community (OCTET STRING).
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x02) return;
    off += l;
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x04) return;
    off += l;

    // PDU: GetResponse tag is 0xA2; we accept any PDU tag.
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0) return;

    // Inside PDU: request-id, error-status, error-index, varbinds SEQUENCE.
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x02) return; off += l;
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x02) return; off += l;
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x02) return; off += l;

    // var-binds SEQUENCE OF SEQUENCE { OID, value }
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x30) return;
    // first var-bind
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x30) return;
    // OID
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0 || tag != 0x06) return;
    off += l;
    // value — only handle OCTET STRING (0x04) which is what sysDescr is.
    off = berReadTL(buf, len, off, &tag, &l); if (off < 0) return;
    if (tag != 0x04 || l < 1) return;
    if (off + l > len) return;
    // Trim to a sane single-line length.
    int copyLen = std::min(l, 240);
    std::wstring s = widenUtf8(reinterpret_cast<const char*>(buf + off), copyLen);
    // Replace control chars with spaces so single-line displays don't get gobbled.
    for (auto& c : s) {
        if (c == L'\r' || c == L'\n' || c == L'\t') c = L' ';
    }
    out.snmpSysDescr = trimWs(std::move(s));
}

void parseDnsVersion(const uint8_t* buf, int len, UdpServiceInfo& out) {
    if (len < 12) return;
    int qdcount = (buf[4] << 8) | buf[5];
    int ancount = (buf[6] << 8) | buf[7];
    if (ancount == 0) return;
    int off = 12;
    for (int q = 0; q < qdcount; ++q) {
        std::string tmp;
        int next = readDnsName(buf, len, off, tmp);
        if (next < 0 || next + 4 > len) return;
        off = next + 4;
    }
    for (int a = 0; a < ancount; ++a) {
        std::string nameStr;
        int next = readDnsName(buf, len, off, nameStr);
        if (next < 0 || next + 10 > len) return;
        int type     = (buf[next] << 8) | buf[next + 1];
        int rdlength = (buf[next + 8] << 8) | buf[next + 9];
        int rdoff    = next + 10;
        if (rdoff + rdlength > len) return;

        if (type == 16 /* TXT */ && rdlength >= 1) {
            int txtLen = buf[rdoff];
            if (txtLen >= 1 && rdoff + 1 + txtLen <= len) {
                out.dnsVersion = widenUtf8(
                    reinterpret_cast<const char*>(buf + rdoff + 1),
                    static_cast<size_t>(txtLen));
                return;
            }
        }
        off = rdoff + rdlength;
    }
}

void parseNtp(const uint8_t* buf, int len, UdpServiceInfo& out) {
    if (len < 48) return;
    uint8_t b0 = buf[0];
    int mode = b0 & 0x07;
    if (mode != 4 /* server */ && mode != 5 /* broadcast */) return;
    out.ntpVersion = (b0 >> 3) & 0x07;
    out.ntpStratum = buf[1];
    if (out.ntpStratum == 1) {
        // Reference ID is ASCII for stratum 1 servers ("GPS\0", "PPS\0", etc.).
        char rid[5] = {0};
        std::memcpy(rid, buf + 12, 4);
        for (int i = 0; i < 4; ++i) {
            if (rid[i] != 0 && (rid[i] < 0x20 || rid[i] > 0x7e)) {
                rid[i] = '?';
            }
        }
        out.ntpRefId = widenAscii(rid, std::strlen(rid));
    }
}

// =============================================================================
// Probe driver
// =============================================================================

struct Slot {
    SOCKET                s     = INVALID_SOCKET;
    int                   port  = 0;
    bool                  done  = false;
};

void dispatchParse(int port, const uint8_t* buf, int len, UdpServiceInfo& out) {
    switch (port) {
        case 137:  parseNbstat     (buf, len, out); break;
        case 5353: parseMdns       (buf, len, out); break;
        case 1900: parseSsdp       (buf, len, out); break;
        case 161:  parseSnmp       (buf, len, out); break;
        case 53:   parseDnsVersion (buf, len, out); break;
        case 123:  parseNtp        (buf, len, out); break;
        default: break;
    }
}

} // anonymous namespace

UdpServiceInfo UdpProbes::probe(uint32_t hostIp,
                                int timeoutMs,
                                const std::atomic<bool>& cancel,
                                std::atomic<int64_t>* probesDone)
{
    UdpServiceInfo out;
    if (cancel.load(std::memory_order_relaxed)) return out;

    constexpr int kCount = 6;
    Slot slots[kCount];
    const int ports[kCount] = { 137, 5353, 1900, 161, 53, 123 };

    std::vector<std::vector<uint8_t>> payloads(kCount);
    payloads[0] = buildNbstat();
    payloads[1] = buildMdns();
    payloads[2] = buildSsdp();
    payloads[3] = buildSnmp();
    payloads[4] = buildDnsVersion();
    payloads[5] = buildNtp();

    // Open + connect + send for each slot.
    for (int i = 0; i < kCount; ++i) {
        slots[i].port = ports[i];
        slots[i].s    = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (slots[i].s == INVALID_SOCKET) {
            slots[i].done = true;
            continue;
        }
        u_long nb = 1;
        ::ioctlsocket(slots[i].s, FIONBIO, &nb);

        sockaddr_in addr{};
        addr.sin_family           = AF_INET;
        addr.sin_port             = htons(static_cast<u_short>(ports[i]));
        addr.sin_addr.S_un.S_addr = htonl(hostIp);
        // connect() on UDP doesn't send a packet — it caches the remote so we
        // can use send()/recv() (and so the OS routes ICMP Unreachable back
        // as WSAECONNRESET on recv()).
        if (::connect(slots[i].s, reinterpret_cast<const sockaddr*>(&addr),
                      sizeof(addr)) != 0) {
            ::closesocket(slots[i].s);
            slots[i].s    = INVALID_SOCKET;
            slots[i].done = true;
            continue;
        }
        ::send(slots[i].s,
               reinterpret_cast<const char*>(payloads[i].data()),
               static_cast<int>(payloads[i].size()), 0);
        if (probesDone) probesDone->fetch_add(1, std::memory_order_relaxed);
    }

    // Wait for replies.
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + std::chrono::milliseconds(std::max(50, timeoutMs));

    while (!cancel.load(std::memory_order_relaxed)) {
        fd_set readSet;
        FD_ZERO(&readSet);
        int active = 0;
        for (auto& s : slots) {
            if (s.s != INVALID_SOCKET && !s.done) {
                FD_SET(s.s, &readSet);
                ++active;
            }
        }
        if (active == 0) break;

        auto now = clock::now();
        if (now >= deadline) break;
        auto remainMs = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        timeval tv;
        tv.tv_sec  = static_cast<long>(remainMs / 1000);
        tv.tv_usec = static_cast<long>((remainMs % 1000) * 1000);

        int r = ::select(0, &readSet, nullptr, nullptr, &tv);
        if (r <= 0) break;

        for (auto& s : slots) {
            if (s.s == INVALID_SOCKET || s.done) continue;
            if (!FD_ISSET(s.s, &readSet)) continue;

            uint8_t buf[2048];
            int     n = ::recv(s.s, reinterpret_cast<char*>(buf),
                                static_cast<int>(sizeof(buf)), 0);
            s.done = true;     // first reply (or error) settles this slot
            if (n <= 0) continue;
            dispatchParse(s.port, buf, n, out);
        }
    }

    for (auto& s : slots) {
        if (s.s != INVALID_SOCKET) ::closesocket(s.s);
    }
    return out;
}

// =============================================================================
// UdpServiceInfo::summaryLine — compact one-line digest for CSV / tooltips
// =============================================================================

std::wstring UdpServiceInfo::summaryLine() const {
    std::wstring out;
    auto add = [&](const std::wstring& s) {
        if (s.empty()) return;
        if (!out.empty()) out += L" \xB7 ";
        out += s;
    };
    if (!netbiosName.empty()) {
        std::wstring s = L"NetBIOS=" + netbiosName;
        if (!netbiosWorkgroup.empty()) s += L"\\" + netbiosWorkgroup;
        add(s);
    } else if (!netbiosWorkgroup.empty()) {
        add(L"Workgroup=" + netbiosWorkgroup);
    }
    if (!upnpServer.empty())   add(L"UPnP: " + upnpServer);
    if (!snmpSysDescr.empty()) {
        std::wstring s = L"SNMP: " + snmpSysDescr;
        if (s.size() > 96) s = s.substr(0, 93) + L"...";
        add(s);
    }
    if (!dnsVersion.empty())   add(L"DNS: " + dnsVersion);
    if (ntpStratum >= 0) {
        std::wstring s = L"NTP stratum " + std::to_wstring(ntpStratum);
        if (!ntpRefId.empty()) s += L" (" + ntpRefId + L")";
        add(s);
    }
    if (!mdnsServices.empty()) {
        add(std::to_wstring(mdnsServices.size()) + L" mDNS svc");
    }
    return out;
}

} // namespace netlens
