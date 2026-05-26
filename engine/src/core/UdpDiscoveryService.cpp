#include "UdpDiscoveryService.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>

namespace lanscope {

namespace {

// =============================================================================
// Probe payload builders
// =============================================================================

// NBNS node-status query for the wildcard name "*". Returns the well-known
// 50-byte query packet. The server replies with a NBSTAT answer listing
// every registered name on that host — we extract the unique workstation
// name and the workgroup/domain from it.
std::vector<uint8_t> buildNbnsQuery() {
    std::vector<uint8_t> p;
    p.reserve(50);
    // Header: TxnID, Flags, QDCount=1, ANCount/NSCount/ARCount=0
    static const uint8_t hdr[12] = {
        0x12, 0x34,             // arbitrary transaction id
        0x00, 0x00,             // flags = standard query, no recursion
        0x00, 0x01,             // qdcount = 1
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    p.insert(p.end(), hdr, hdr + 12);
    // Question name: NetBIOS "*" — 16 ASCII bytes padded with spaces,
    // each byte encoded as two nibbles offset by 'A' (0x41). Preceded by
    // a length byte of 32 and followed by the root label terminator 0x00.
    static const char rawName[16] = {
        '*', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
        ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
    };
    p.push_back(0x20); // length = 32
    for (int i = 0; i < 16; ++i) {
        uint8_t c = static_cast<uint8_t>(rawName[i]);
        p.push_back(static_cast<uint8_t>(0x41 + ((c >> 4) & 0x0F)));
        p.push_back(static_cast<uint8_t>(0x41 + (c & 0x0F)));
    }
    p.push_back(0x00); // root label terminator
    // QType = NBSTAT (0x0021), QClass = IN (0x0001)
    p.push_back(0x00); p.push_back(0x21);
    p.push_back(0x00); p.push_back(0x01);
    return p;
}

// NTPv4 mode-3 (client) request, 48 bytes of zero except the leading
// li_vn_mode = 0x23 (LI=0, Version=4, Mode=3).
std::vector<uint8_t> buildNtpQuery() {
    std::vector<uint8_t> p(48, 0);
    p[0] = 0x23;
    return p;
}

// SSDP M-SEARCH (HTTPU). Sent unicast to the target; well-behaved UPnP
// devices reply with their Server header.
std::vector<uint8_t> buildSsdpQuery(uint32_t hostOrderIp) {
    char ipBuf[INET_ADDRSTRLEN] = {0};
    in_addr a{}; a.S_un.S_addr = htonl(hostOrderIp);
    ::inet_ntop(AF_INET, &a, ipBuf, sizeof(ipBuf));
    std::string s;
    s += "M-SEARCH * HTTP/1.1\r\n";
    s += "HOST: ";
    s += ipBuf;
    s += ":1900\r\n";
    s += "MAN: \"ssdp:discover\"\r\n";
    s += "MX: 1\r\n";
    s += "ST: ssdp:all\r\n";
    s += "USER-AGENT: NetLens/1.0 UPnP/1.1\r\n";
    s += "\r\n";
    return std::vector<uint8_t>(s.begin(), s.end());
}

// mDNS unicast query for "_services._dns-sd._udp.local." PTR. The high
// bit set on QClass requests a unicast (rather than multicast) response,
// matching RFC 6762 §5.4.
std::vector<uint8_t> buildMdnsQuery() {
    std::vector<uint8_t> p;
    p.reserve(50);
    static const uint8_t hdr[12] = {
        0x00, 0x00,  // mDNS: transaction id MUST be 0 in queries
        0x00, 0x00,  // standard query
        0x00, 0x01,  // qdcount = 1
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    p.insert(p.end(), hdr, hdr + 12);
    auto pushLabel = [&p](const char* lbl) {
        size_t n = std::strlen(lbl);
        p.push_back(static_cast<uint8_t>(n));
        for (size_t i = 0; i < n; ++i) p.push_back(static_cast<uint8_t>(lbl[i]));
    };
    pushLabel("_services");
    pushLabel("_dns-sd");
    pushLabel("_udp");
    pushLabel("local");
    p.push_back(0x00);  // root label
    // QType = PTR (0x000C), QClass = IN with QU bit set (0x8001)
    p.push_back(0x00); p.push_back(0x0C);
    p.push_back(0x80); p.push_back(0x01);
    return p;
}

// SQL Server Browser — CLNT_UCAST_EX request is a single 0x03 byte.
// The server responds with its SVR_RESP payload listing all SQL Server
// instances on that host.
std::vector<uint8_t> buildSqlBrowserQuery() {
    return { 0x03 };
}

// DNS query: TXT class CHAOS for "version.bind." — well-known way to
// fingerprint the resolver software (BIND / Unbound / Knot / ...). Many
// hardened resolvers refuse, which still gives us "service detected"
// (the query went out, something on UDP/53 answered or RST'd).
std::vector<uint8_t> buildDnsVersionQuery() {
    std::vector<uint8_t> p;
    p.reserve(40);
    static const uint8_t hdr[12] = {
        0x12, 0x34,  // transaction id
        0x01, 0x00,  // flags = standard query, recursion desired
        0x00, 0x01,  // qdcount = 1
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    p.insert(p.end(), hdr, hdr + 12);
    auto pushLabel = [&p](const char* lbl) {
        size_t n = std::strlen(lbl);
        p.push_back(static_cast<uint8_t>(n));
        for (size_t i = 0; i < n; ++i) p.push_back(static_cast<uint8_t>(lbl[i]));
    };
    pushLabel("version");
    pushLabel("bind");
    p.push_back(0x00);                  // root
    p.push_back(0x00); p.push_back(0x10);  // QType = TXT (16)
    p.push_back(0x00); p.push_back(0x03);  // QClass = CHAOS (3)
    return p;
}

// LLMNR query — same wire format as DNS over UDP, sent to UDP/5355. We
// query the host's own name back at it ("WPAD" is a safe, widely-defined
// name to ask about). Windows hosts running LLMNR will answer.
std::vector<uint8_t> buildLlmnrQuery() {
    std::vector<uint8_t> p;
    p.reserve(30);
    static const uint8_t hdr[12] = {
        0xAB, 0xCD,
        0x00, 0x00,  // standard query
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    p.insert(p.end(), hdr, hdr + 12);
    static const uint8_t name[] = {
        0x04, 'w', 'p', 'a', 'd',
        0x00
    };
    p.insert(p.end(), name, name + sizeof(name));
    p.push_back(0x00); p.push_back(0x01);  // QType = A
    p.push_back(0x00); p.push_back(0x01);  // QClass = IN
    return p;
}

// IPMI / ASF Presence Ping over RMCP. 12-byte packet. Servers with a BMC
// (HP iLO, Dell iDRAC, Supermicro IPMI, …) reply with a Pong message
// containing OEM ID + supported entities — a strong "this is server-class
// hardware" signal.
std::vector<uint8_t> buildIpmiQuery() {
    return {
        0x06,                       // RMCP version 1.0
        0x00,                       // reserved
        0xFF,                       // sequence (no-ack)
        0x06,                       // RMCP class = ASF (0x06)
        0x00, 0x00, 0x11, 0xBE,     // ASF IANA enterprise number
        0x80,                       // message type = Presence Ping
        0x00,                       // message tag
        0x00,                       // reserved
        0x00                        // data length = 0
    };
}

// =============================================================================
// Response parsers
// =============================================================================

// Parse an NBSTAT response. The answer's RDATA contains a 1-byte name
// count followed by 18 bytes per name (15 NetBIOS chars + 1 suffix +
// 2 flags). Some responses use DNS name compression, so we don't assume
// a fixed header offset — we try the canonical layout first, then
// fall back to a brute-force scan.
std::wstring parseNbnsResponse(const uint8_t* buf, size_t len) {
    auto isPrintable = [](char c) { return c >= 32 && c <= 126; };

    auto extract = [&](size_t start) -> std::wstring {
        if (start >= len) return L"";
        uint8_t nameCount = buf[start];
        if (nameCount == 0 || nameCount > 20) return L"";  // sanity cap
        size_t pos = start + 1;
        std::wstring uniqueName, groupName;
        for (uint8_t i = 0; i < nameCount && pos + 18 <= len; ++i) {
            char nm[16];
            std::memcpy(nm, buf + pos, 15);
            nm[15] = 0;
            uint16_t flags = (static_cast<uint16_t>(buf[pos + 16]) << 8)
                           |  static_cast<uint16_t>(buf[pos + 17]);
            pos += 18;
            std::string name(nm, 15);
            while (!name.empty() && name.back() == ' ') name.pop_back();
            if (name.empty()) continue;
            bool ok = true;
            for (char c : name) {
                if (!isPrintable(c)) { ok = false; break; }
            }
            if (!ok) continue;
            const bool isGroup = (flags & 0x8000) != 0;
            std::wstring w(name.begin(), name.end());
            if (!isGroup && uniqueName.empty()) uniqueName = w;
            else if (isGroup && groupName.empty()) groupName = w;
        }
        if (uniqueName.empty() && groupName.empty()) return L"";
        std::wstring out = uniqueName;
        if (!groupName.empty()) {
            if (!out.empty()) out += L"\\";
            out += groupName;
        }
        return out;
    };

    // Canonical layout: 12 header + 38 question + 44 answer-header = 94
    auto r = extract(94);
    if (!r.empty()) return r;
    // Brute-force fallback when the response uses name compression or a
    // slightly different layout.
    for (size_t off = 12; off + 20 < len; ++off) {
        r = extract(off);
        if (!r.empty()) return r;
    }
    return L"detected";
}

std::wstring parseNtpResponse(const uint8_t* buf, size_t len) {
    if (len < 48) return L"";
    uint8_t version = (buf[0] >> 3) & 0x07;
    uint8_t stratum = buf[1];
    wchar_t out[64];
    if (stratum == 0) {
        swprintf_s(out, L"v%u, stratum 0 (kiss-of-death)", version);
    } else if (stratum == 1) {
        swprintf_s(out, L"v%u, stratum 1 (primary)", version);
    } else if (stratum >= 16) {
        swprintf_s(out, L"v%u, unsynchronized", version);
    } else {
        swprintf_s(out, L"v%u, stratum %u", version, stratum);
    }
    return out;
}

std::wstring parseSsdpResponse(const uint8_t* buf, size_t len) {
    std::string body(reinterpret_cast<const char*>(buf), len);
    std::string lower = body;
    for (auto& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    size_t pos = lower.find("server:");
    if (pos == std::string::npos) return L"detected";
    pos += 7;
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) ++pos;
    size_t eol = body.find_first_of("\r\n", pos);
    if (eol == std::string::npos) eol = body.size();
    std::string server = body.substr(pos, eol - pos);
    while (!server.empty() && (server.back() == ' ' || server.back() == '\t')) {
        server.pop_back();
    }
    if (server.empty()) return L"detected";
    if (server.size() > 80) server.resize(80);   // grid sanity
    return std::wstring(server.begin(), server.end());
}

std::wstring parseMdnsResponse(const uint8_t* /*buf*/, size_t /*len*/) {
    // We only check for a response; the PTR record payload is rarely useful
    // as a one-line summary and the full parser is significant code.
    return L"detected";
}

// Parse a DNS TXT response. Skips header + question and walks the answer
// section looking for a TXT record; returns the first quoted string.
std::wstring parseDnsVersionResponse(const uint8_t* buf, size_t len) {
    if (len < 12) return L"";
    uint16_t ancount = (static_cast<uint16_t>(buf[6]) << 8) | buf[7];
    if (ancount == 0) return L"detected";
    // Skip header + question
    size_t pos = 12;
    while (pos < len && buf[pos] != 0x00) {
        uint8_t lbl = buf[pos];
        if (lbl >= 0xC0) { pos += 2; break; }   // compression pointer
        pos += 1 + lbl;
    }
    pos += 1;       // root
    pos += 4;       // qtype + qclass
    if (pos + 12 > len) return L"detected";
    // Answer: name (often compression pointer, 2 bytes) + type(2)+class(2)+ttl(4)+rdlen(2)
    if ((buf[pos] & 0xC0) == 0xC0) pos += 2;
    else {
        while (pos < len && buf[pos] != 0x00) {
            uint8_t lbl = buf[pos];
            if (lbl >= 0xC0) { pos += 2; goto namedone; }
            pos += 1 + lbl;
        }
        pos += 1;
    }
namedone:
    if (pos + 10 > len) return L"detected";
    uint16_t rtype = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
    pos += 8;  // type(2)+class(2)+ttl(4)
    uint16_t rdlen = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
    pos += 2;
    if (rtype != 0x0010) return L"detected";    // not TXT
    if (pos + rdlen > len) return L"detected";
    // TXT rdata: <len> <bytes>
    uint8_t txtLen = buf[pos++];
    if (txtLen == 0 || pos + txtLen > len) return L"detected";
    std::string txt(reinterpret_cast<const char*>(buf + pos), txtLen);
    for (auto& c : txt) if (c < 32 || c > 126) c = '?';
    if (txt.size() > 80) txt.resize(80);
    return std::wstring(txt.begin(), txt.end());
}

// LLMNR response — same wire format as DNS over UDP. The presence of a
// response alone is meaningful (the host runs LLMNR; only Windows-family
// hosts do by default). The actual answer for "WPAD" is rarely useful;
// we just say "detected".
std::wstring parseLlmnrResponse(const uint8_t* /*buf*/, size_t /*len*/) {
    return L"Windows LLMNR responder";
}

// IPMI / ASF Pong. We don't need to parse the OEM ID to be useful — the
// fact that the box answered RMCP at all is a strong "server-class BMC"
// signal that surfaces machines invisible to TCP scans.
std::wstring parseIpmiResponse(const uint8_t* buf, size_t len) {
    // Pong is 28 bytes; header bytes 4..7 should be the ASF IANA number.
    if (len < 16) return L"detected";
    if (buf[3] == 0x06 && buf[4] == 0x00 && buf[5] == 0x00
        && buf[6] == 0x11 && buf[7] == 0xBE) {
        return L"BMC presence (RMCP/ASF Pong)";
    }
    return L"detected";
}

std::wstring parseSqlBrowserResponse(const uint8_t* buf, size_t len) {
    // SVR_RESP packet: byte 0 = 0x05, bytes 1-2 = LE length, then a body
    // of ";"-separated key/value pairs (...;ServerName;XX;InstanceName;YY;...)
    if (len < 3 || buf[0] != 0x05) return L"detected";
    std::string body(reinterpret_cast<const char*>(buf + 3), len - 3);
    // Find "InstanceName" field and extract its value.
    const char* key = "InstanceName;";
    size_t p = body.find(key);
    if (p == std::string::npos) return L"detected";
    p += std::strlen(key);
    size_t end = body.find(';', p);
    if (end == std::string::npos) end = body.size();
    std::string inst = body.substr(p, end - p);
    // Sanitize non-printable.
    for (auto& c : inst) {
        if (c < 32 || c > 126) c = '?';
    }
    if (inst.empty()) return L"detected";
    if (inst.size() > 60) inst.resize(60);
    std::wstring w(inst.begin(), inst.end());
    return L"instance " + w;
}

// =============================================================================
// Probe slot — one entry per UDP service
// =============================================================================
struct ProbeSlot {
    int                  port;
    const wchar_t*       name;
    std::vector<uint8_t> payload;
    SOCKET               sock = INVALID_SOCKET;
    bool                 responded = false;
    std::wstring         result;
};

} // anonymous namespace

std::wstring UdpDiscoveryService::discover(uint32_t hostOrderIp,
                                            int timeoutMs,
                                            const std::atomic<bool>& cancel) {
    if (cancel.load(std::memory_order_relaxed)) return L"";
    if (timeoutMs <= 0) timeoutMs = 600;

    // Eight targeted probes covering NetBIOS / Bonjour / SSDP / SQL
    // Browser / NTP / DNS / LLMNR / IPMI. All fire in parallel through
    // a single select() loop, so adding probes doesn't proportionally
    // increase scan time — the total stays bounded by the global timeout.
    std::vector<ProbeSlot> slots;
    slots.reserve(8);
    slots.push_back({ 137,  L"NBNS",        buildNbnsQuery(),            INVALID_SOCKET, false, L"" });
    slots.push_back({ 123,  L"NTP",         buildNtpQuery(),             INVALID_SOCKET, false, L"" });
    slots.push_back({ 1900, L"SSDP",        buildSsdpQuery(hostOrderIp), INVALID_SOCKET, false, L"" });
    slots.push_back({ 5353, L"mDNS",        buildMdnsQuery(),            INVALID_SOCKET, false, L"" });
    slots.push_back({ 1434, L"SQL Browser", buildSqlBrowserQuery(),      INVALID_SOCKET, false, L"" });
    slots.push_back({ 53,   L"DNS",         buildDnsVersionQuery(),      INVALID_SOCKET, false, L"" });
    slots.push_back({ 5355, L"LLMNR",       buildLlmnrQuery(),           INVALID_SOCKET, false, L"" });
    slots.push_back({ 623,  L"IPMI",        buildIpmiQuery(),            INVALID_SOCKET, false, L"" });

    sockaddr_in dst{};
    dst.sin_family            = AF_INET;
    dst.sin_addr.S_un.S_addr  = htonl(hostOrderIp);

    // Create one non-blocking UDP socket per probe, then sendto() in parallel.
    // No thread spawning — every probe shares the same select() loop below.
    for (auto& s : slots) {
        s.sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s.sock == INVALID_SOCKET) continue;
        u_long nb = 1;
        ::ioctlsocket(s.sock, FIONBIO, &nb);
        dst.sin_port = htons(static_cast<u_short>(s.port));
        ::sendto(s.sock,
                 reinterpret_cast<const char*>(s.payload.data()),
                 static_cast<int>(s.payload.size()),
                 0,
                 reinterpret_cast<const sockaddr*>(&dst),
                 sizeof(dst));
    }

    // Single shared select() loop. Bails as soon as every probe has either
    // responded or we hit the global deadline.
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cancel.load(std::memory_order_relaxed)) break;

        fd_set rset; FD_ZERO(&rset);
        bool anyPending = false;
        for (auto& s : slots) {
            if (s.sock == INVALID_SOCKET || s.responded) continue;
            FD_SET(s.sock, &rset);
            anyPending = true;
        }
        if (!anyPending) break;

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;

        timeval tv{};
        tv.tv_sec  = static_cast<long>(remaining / 1000);
        tv.tv_usec = static_cast<long>((remaining % 1000) * 1000);

        int n = ::select(0, &rset, nullptr, nullptr, &tv);
        if (n == 0) break;                // timeout — nothing more is coming
        if (n < 0)  continue;             // transient error — retry until deadline

        const uint32_t expectedAddr = htonl(hostOrderIp);
        for (auto& s : slots) {
            if (s.sock == INVALID_SOCKET || s.responded) continue;
            if (!FD_ISSET(s.sock, &rset)) continue;
            uint8_t buf[2048];
            sockaddr_in src{};
            int srcLen = static_cast<int>(sizeof(src));
            int rn = ::recvfrom(s.sock,
                                reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                reinterpret_cast<sockaddr*>(&src), &srcLen);
            if (rn <= 0) continue;
            // Drop responses that didn't originate from the target host —
            // another LAN device could be sniffing the probe port and
            // injecting bogus content. We require both AF_INET and the
            // expected source address.
            if (src.sin_family != AF_INET) continue;
            if (src.sin_addr.S_un.S_addr != expectedAddr) continue;
            s.responded = true;
            switch (s.port) {
                case 137:  s.result = parseNbnsResponse        (buf, rn); break;
                case 123:  s.result = parseNtpResponse         (buf, rn); break;
                case 1900: s.result = parseSsdpResponse        (buf, rn); break;
                case 5353: s.result = parseMdnsResponse        (buf, rn); break;
                case 1434: s.result = parseSqlBrowserResponse  (buf, rn); break;
                case 53:   s.result = parseDnsVersionResponse  (buf, rn); break;
                case 5355: s.result = parseLlmnrResponse       (buf, rn); break;
                case 623:  s.result = parseIpmiResponse        (buf, rn); break;
                default:   s.result = L"detected"; break;
            }
        }
    }

    // Cleanup + aggregate. Tab-separated format so the UI can
    // parse this back into a 3-column table (port | service | detail).
    // Lines are "\r\n"-separated; within a line "<port>\t<service>\t<detail>".
    // Tab separators are safer than '|' because some response detail
    // strings may contain pipes (URLs, version strings, ...).
    std::wstring out;
    wchar_t portBuf[16];
    for (auto& s : slots) {
        if (s.sock != INVALID_SOCKET) ::closesocket(s.sock);
        if (!s.responded) continue;
        if (!out.empty()) out += L"\r\n";
        swprintf_s(portBuf, L"%d", s.port);
        out += portBuf;
        out += L"\t";
        out += s.name;
        out += L"\t";
        out += s.result.empty() ? std::wstring(L"responded") : s.result;
    }
    return out;
}

} // namespace lanscope
