#include "SnmpClient.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>

namespace lanscope {
namespace snmp {

namespace {

// =============================================================================
// BER (Basic Encoding Rules) helpers — just enough for SNMPv2c GET/GETNEXT.
// =============================================================================

constexpr uint8_t TAG_INTEGER     = 0x02;
constexpr uint8_t TAG_OCTETSTRING = 0x04;
constexpr uint8_t TAG_NULL        = 0x05;
constexpr uint8_t TAG_OID         = 0x06;
constexpr uint8_t TAG_SEQUENCE    = 0x30;

// SNMP application tags (context-specific).
constexpr uint8_t TAG_COUNTER32   = 0x41;
constexpr uint8_t TAG_GAUGE32     = 0x42;
constexpr uint8_t TAG_TIMETICKS   = 0x43;

// SNMP PDU tags (context-specific, constructed).
constexpr uint8_t TAG_GET_REQUEST     = 0xA0;
constexpr uint8_t TAG_GETNEXT_REQUEST = 0xA1;
constexpr uint8_t TAG_GET_RESPONSE    = 0xA2;

// SNMPv2c exception markers inside a varbind (context-specific, primitive).
constexpr uint8_t TAG_NO_SUCH_OBJECT  = 0x80;
constexpr uint8_t TAG_NO_SUCH_INSTANCE= 0x81;
constexpr uint8_t TAG_END_OF_MIB_VIEW = 0x82;

// Encode a BER length into `out`. Short form for <128, long form otherwise.
void encLen(std::vector<uint8_t>& out, size_t len) {
    if (len < 128) {
        out.push_back(static_cast<uint8_t>(len));
        return;
    }
    uint8_t buf[5];
    int n = 0;
    while (len > 0) {
        buf[n++] = static_cast<uint8_t>(len & 0xFF);
        len >>= 8;
    }
    out.push_back(static_cast<uint8_t>(0x80 | n));
    for (int i = n - 1; i >= 0; --i) out.push_back(buf[i]);
}

// Backpatch the length field of the most recent constructed element. `lenPos`
// is the offset of the length byte (which we wrote as 0x00 placeholder).
// `endPos` is the current size of the buffer. We rewrite [lenPos..) so the
// length encoding is correct.
void backpatchLen(std::vector<uint8_t>& out, size_t lenPos, size_t endPos) {
    size_t contentLen = endPos - lenPos - 1;
    if (contentLen < 128) {
        out[lenPos] = static_cast<uint8_t>(contentLen);
        return;
    }
    // Need long form — insert extra bytes between lenPos and content.
    uint8_t buf[5];
    int n = 0;
    size_t tmp = contentLen;
    while (tmp > 0) {
        buf[n++] = static_cast<uint8_t>(tmp & 0xFF);
        tmp >>= 8;
    }
    // Replace the 1-byte placeholder with (1 + n) bytes.
    std::vector<uint8_t> insert;
    insert.push_back(static_cast<uint8_t>(0x80 | n));
    for (int i = n - 1; i >= 0; --i) insert.push_back(buf[i]);
    out.erase(out.begin() + lenPos);
    out.insert(out.begin() + lenPos, insert.begin(), insert.end());
}

// Emit a primitive element: tag + length + payload bytes.
void encTagLenBytes(std::vector<uint8_t>& out, uint8_t tag, const uint8_t* data, size_t n) {
    out.push_back(tag);
    encLen(out, n);
    out.insert(out.end(), data, data + n);
}

void encInteger(std::vector<uint8_t>& out, int64_t v) {
    // Minimum-length two's-complement encoding (BER rule).
    uint8_t buf[10]; int n = 0;
    if (v == 0) { buf[n++] = 0; }
    else {
        int64_t tmp = v;
        while (true) {
            uint8_t byte = static_cast<uint8_t>(tmp & 0xFF);
            buf[n++] = byte;
            tmp >>= 8;
            if ((tmp == 0 && (byte & 0x80) == 0)
             || (tmp == -1 && (byte & 0x80) != 0)) break;
        }
    }
    out.push_back(TAG_INTEGER);
    encLen(out, n);
    for (int i = n - 1; i >= 0; --i) out.push_back(buf[i]);
}

void encOctetString(std::vector<uint8_t>& out, const std::string& s) {
    encTagLenBytes(out, TAG_OCTETSTRING,
                   reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void encNull(std::vector<uint8_t>& out) {
    out.push_back(TAG_NULL);
    out.push_back(0x00);
}

// Parse a dotted OID into sub-identifiers. Returns empty on malformed input.
std::vector<uint32_t> parseOid(const std::string& s) {
    std::vector<uint32_t> out;
    uint64_t cur = 0;
    bool digit = false;
    for (char c : s) {
        if (c == '.') {
            if (!digit) return {};
            out.push_back(static_cast<uint32_t>(cur));
            cur = 0; digit = false;
        } else if (c >= '0' && c <= '9') {
            cur = cur * 10 + (c - '0');
            digit = true;
        } else {
            return {};
        }
    }
    if (digit) out.push_back(static_cast<uint32_t>(cur));
    return out;
}

void encOid(std::vector<uint8_t>& out, const std::string& dotted) {
    auto sub = parseOid(dotted);
    std::vector<uint8_t> body;
    if (sub.size() >= 2) {
        body.push_back(static_cast<uint8_t>(40 * sub[0] + sub[1]));
        for (size_t i = 2; i < sub.size(); ++i) {
            uint32_t v = sub[i];
            // 7-bit chunks; high bit set on all but last byte.
            uint8_t enc[5]; int n = 0;
            if (v == 0) { enc[n++] = 0; }
            else {
                while (v > 0) { enc[n++] = static_cast<uint8_t>(v & 0x7F); v >>= 7; }
            }
            for (int j = n - 1; j > 0; --j) body.push_back(enc[j] | 0x80);
            body.push_back(enc[0]);
        }
    }
    encTagLenBytes(out, TAG_OID, body.data(), body.size());
}

// Decode a BER length starting at `p`. Returns the length and advances `p`.
// Returns false on malformed input.
bool decLen(const uint8_t*& p, const uint8_t* end, size_t& outLen) {
    if (p >= end) return false;
    uint8_t b = *p++;
    if ((b & 0x80) == 0) { outLen = b; return true; }
    int n = b & 0x7F;
    if (n == 0 || n > 4) return false;
    if (p + n > end) return false;
    size_t len = 0;
    for (int i = 0; i < n; ++i) len = (len << 8) | *p++;
    outLen = len;
    return true;
}

// Decode an OID's BER body into the dotted form.
std::string decOidBody(const uint8_t* p, size_t n) {
    if (n == 0) return {};
    std::string out;
    char buf[32];
    // BER's first sub-id encodes `(arc1*40 + arc2)` where arc1 ∈ {0,1,2}.
    // For arc1 == 2 the combined value can exceed 127, so the first
    // sub-id may itself be a multi-byte varint with the high bit set on
    // continuation bytes. Real SNMP OIDs start with 1.3 or 2.x; handle
    // both single-byte (the common case) and multi-byte first sub-ids.
    uint64_t combined = 0;
    size_t i = 0;
    while (i < n) {
        uint8_t b = p[i++];
        combined = (combined << 7) | (b & 0x7F);
        if ((b & 0x80) == 0) break;
    }
    uint64_t arc1 = (combined < 80) ? (combined / 40) : 2;
    uint64_t arc2 = (combined < 80) ? (combined % 40) : (combined - 80);
    snprintf(buf, sizeof(buf), "%llu.%llu",
             static_cast<unsigned long long>(arc1),
             static_cast<unsigned long long>(arc2));
    out = buf;
    while (i < n) {
        uint64_t v = 0;
        while (i < n) {
            uint8_t b = p[i++];
            v = (v << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) break;
        }
        snprintf(buf, sizeof(buf), ".%llu", static_cast<unsigned long long>(v));
        out += buf;
    }
    return out;
}

int64_t decInteger(const uint8_t* p, size_t n) {
    if (n == 0) return 0;
    int64_t v = (p[0] & 0x80) ? -1 : 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

// Decode one varbind starting at `p` (which points at the inner SEQUENCE
// tag). Returns false on malformed input. Advances `p` past the varbind.
bool decVarbind(const uint8_t*& p, const uint8_t* end, Value& out) {
    if (p >= end || *p++ != TAG_SEQUENCE) return false;
    size_t vbLen = 0;
    if (!decLen(p, end, vbLen)) return false;
    const uint8_t* vbEnd = p + vbLen;
    if (vbEnd > end) return false;

    // OID
    if (p >= vbEnd || *p++ != TAG_OID) return false;
    size_t oidLen = 0;
    if (!decLen(p, vbEnd, oidLen) || p + oidLen > vbEnd) return false;
    out.oid = decOidBody(p, oidLen);
    p += oidLen;

    // Value
    if (p >= vbEnd) return false;
    uint8_t valTag = *p++;
    size_t valLen = 0;
    if (!decLen(p, vbEnd, valLen) || p + valLen > vbEnd) return false;
    const uint8_t* valData = p;
    p += valLen;

    switch (valTag) {
        case TAG_NULL:
            out.type = ValueType::Null;
            out.asText.clear();
            break;
        case TAG_INTEGER:
            out.type = ValueType::Integer;
            out.asInt = decInteger(valData, valLen);
            out.asText = std::to_string(out.asInt);
            break;
        case TAG_COUNTER32:
        case TAG_GAUGE32:
        case TAG_TIMETICKS: {
            out.type = (valTag == TAG_COUNTER32) ? ValueType::Counter32
                     : (valTag == TAG_GAUGE32)   ? ValueType::Gauge32
                                                  : ValueType::TimeTicks;
            uint64_t v = 0;
            for (size_t i = 0; i < valLen; ++i) v = (v << 8) | valData[i];
            out.asInt  = static_cast<int64_t>(v);
            out.asText = std::to_string(out.asInt);
            break;
        }
        case TAG_OCTETSTRING:
            out.type = ValueType::OctetString;
            out.asText.assign(reinterpret_cast<const char*>(valData), valLen);
            // Sanitize non-printables for safe display.
            for (auto& c : out.asText) {
                if ((c < 0x20 || c == 0x7F) && c != '\r' && c != '\n' && c != '\t') c = '?';
            }
            break;
        case TAG_OID:
            out.type = ValueType::ObjectId;
            out.asText = decOidBody(valData, valLen);
            break;
        case TAG_NO_SUCH_OBJECT:
        case TAG_NO_SUCH_INSTANCE:
        case TAG_END_OF_MIB_VIEW:
            out.isException = true;
            out.type = ValueType::Null;
            out.asText = (valTag == TAG_NO_SUCH_OBJECT)   ? "noSuchObject"
                       : (valTag == TAG_NO_SUCH_INSTANCE) ? "noSuchInstance"
                                                          : "endOfMibView";
            break;
        default:
            out.type = ValueType::Other;
            out.asText.assign(reinterpret_cast<const char*>(valData), valLen);
            break;
    }
    p = vbEnd;
    return true;
}

// Build an SNMPv2c request packet (GET or GETNEXT) for the given OIDs.
std::vector<uint8_t> buildRequest(uint8_t pduTag,
                                   const std::vector<std::string>& oids,
                                   uint32_t reqId) {
    std::vector<uint8_t> pkt;
    pkt.push_back(TAG_SEQUENCE);
    size_t outerLenPos = pkt.size();
    pkt.push_back(0x00);                     // placeholder
    // SNMP version (v2c = 1)
    encInteger(pkt, 1);
    // Community
    encOctetString(pkt, "public");
    // PDU
    pkt.push_back(pduTag);
    size_t pduLenPos = pkt.size();
    pkt.push_back(0x00);                     // placeholder
    encInteger(pkt, static_cast<int64_t>(reqId));
    encInteger(pkt, 0);                       // error-status
    encInteger(pkt, 0);                       // error-index
    // Varbind list (SEQUENCE OF SEQUENCE { OID, value=NULL })
    pkt.push_back(TAG_SEQUENCE);
    size_t vblLenPos = pkt.size();
    pkt.push_back(0x00);
    for (const auto& o : oids) {
        pkt.push_back(TAG_SEQUENCE);
        size_t vbPos = pkt.size();
        pkt.push_back(0x00);
        encOid(pkt, o);
        encNull(pkt);
        backpatchLen(pkt, vbPos, pkt.size());
    }
    backpatchLen(pkt, vblLenPos, pkt.size());
    backpatchLen(pkt, pduLenPos, pkt.size());
    backpatchLen(pkt, outerLenPos, pkt.size());
    return pkt;
}

// Parse an SNMPv2c response. Returns the varbinds; status = Ok if at least
// one varbind decoded, BadResponse otherwise.
Result parseResponse(const uint8_t* p, size_t n) {
    Result r;
    const uint8_t* end = p + n;
    if (p >= end || *p++ != TAG_SEQUENCE) { r.status = Status::BadResponse; return r; }
    size_t outerLen = 0;
    if (!decLen(p, end, outerLen)) { r.status = Status::BadResponse; return r; }
    if (p + outerLen > end) end = p + outerLen;

    // version
    if (p >= end || *p++ != TAG_INTEGER) { r.status = Status::BadResponse; return r; }
    size_t verLen = 0; if (!decLen(p, end, verLen) || p + verLen > end) { r.status = Status::BadResponse; return r; }
    p += verLen;
    // community
    if (p >= end || *p++ != TAG_OCTETSTRING) { r.status = Status::BadResponse; return r; }
    size_t comLen = 0; if (!decLen(p, end, comLen) || p + comLen > end) { r.status = Status::BadResponse; return r; }
    p += comLen;
    // PDU
    if (p >= end) { r.status = Status::BadResponse; return r; }
    uint8_t pduTag = *p++;
    if (pduTag != TAG_GET_RESPONSE) { r.status = Status::BadResponse; return r; }
    size_t pduLen = 0; if (!decLen(p, end, pduLen)) { r.status = Status::BadResponse; return r; }
    const uint8_t* pduEnd = p + pduLen;
    if (pduEnd > end) { r.status = Status::BadResponse; return r; }
    // request-id, error-status, error-index
    for (int i = 0; i < 3; ++i) {
        if (p >= pduEnd || *p++ != TAG_INTEGER) { r.status = Status::BadResponse; return r; }
        size_t l = 0; if (!decLen(p, pduEnd, l) || p + l > pduEnd) { r.status = Status::BadResponse; return r; }
        p += l;
    }
    // varbind list
    if (p >= pduEnd || *p++ != TAG_SEQUENCE) { r.status = Status::BadResponse; return r; }
    size_t vblLen = 0;
    if (!decLen(p, pduEnd, vblLen) || p + vblLen > pduEnd) { r.status = Status::BadResponse; return r; }
    const uint8_t* vblEnd = p + vblLen;
    while (p < vblEnd) {
        Value v{};
        if (!decVarbind(p, vblEnd, v)) { r.status = Status::BadResponse; return r; }
        r.values.push_back(std::move(v));
    }
    if (r.values.empty()) { r.status = Status::BadResponse; return r; }
    // If every varbind is an exception we still return Ok but with isException
    // flags — the caller decides whether to count this as "no data".
    r.status = Status::Ok;
    return r;
}

// Send a single SNMP request and wait for one response. The SOCKET is
// non-blocking + select()-driven so the timeout is honored cleanly.
Result txn(uint32_t hostOrderIp,
            const std::vector<uint8_t>& pkt,
            int timeoutMs) {
    Result r;
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { r.status = Status::Refused; return r; }

    u_long nb = 1;
    ::ioctlsocket(s, FIONBIO, &nb);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(161);
    dst.sin_addr.S_un.S_addr = htonl(hostOrderIp);

    int sent = ::sendto(s, reinterpret_cast<const char*>(pkt.data()),
                        static_cast<int>(pkt.size()), 0,
                        reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    if (sent <= 0) {
        ::closesocket(s);
        r.status = Status::Refused;
        return r;
    }

    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        fd_set rset; FD_ZERO(&rset); FD_SET(s, &rset);
        auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (rem <= 0) break;
        timeval tv{};
        tv.tv_sec  = static_cast<long>(rem / 1000);
        tv.tv_usec = static_cast<long>((rem % 1000) * 1000);
        int n = ::select(0, &rset, nullptr, nullptr, &tv);
        if (n <= 0) break;
        uint8_t buf[2048];
        sockaddr_in src{}; int slen = sizeof(src);
        int rn = ::recvfrom(s, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                            reinterpret_cast<sockaddr*>(&src), &slen);
        ::closesocket(s);
        if (rn <= 0) {
            r.status = Status::BadResponse;
            return r;
        }
        return parseResponse(buf, static_cast<size_t>(rn));
    }
    ::closesocket(s);
    r.status = Status::Timeout;
    return r;
}

} // anonymous namespace

Result get(uint32_t hostOrderIp,
            const std::vector<std::string>& oids,
            int timeoutMs) {
    if (oids.empty()) return {};
    uint32_t reqId = static_cast<uint32_t>(
        std::chrono::steady_clock::now().time_since_epoch().count() & 0x7FFFFFFF);
    auto pkt = buildRequest(TAG_GET_REQUEST, oids, reqId);
    return txn(hostOrderIp, pkt, timeoutMs);
}

Result walk(uint32_t hostOrderIp,
             const std::string& subtreeOid,
             int timeoutMs,
             int maxValues,
             const std::atomic<bool>& cancel) {
    Result agg;
    agg.status = Status::Ok;
    std::string current = subtreeOid;
    // Cap how many GETNEXT round-trips we do — bounds wall time even if the
    // remote sends one varbind per response.
    for (int step = 0; step < maxValues; ++step) {
        if (cancel.load(std::memory_order_relaxed)) break;
        uint32_t reqId = static_cast<uint32_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0x7FFFFFFF) + step;
        auto pkt = buildRequest(TAG_GETNEXT_REQUEST, { current }, reqId);
        Result r = txn(hostOrderIp, pkt, timeoutMs);
        if (r.status != Status::Ok || r.values.empty()) {
            if (step == 0) return r;             // first hop already failed
            break;                                // partial result is fine
        }
        const Value& v = r.values.front();
        if (v.isException) break;                 // endOfMibView etc.
        // Stop when the returned OID leaves the subtree.
        if (v.oid.size() < subtreeOid.size()
            || v.oid.compare(0, subtreeOid.size(), subtreeOid) != 0
            || (v.oid.size() > subtreeOid.size() && v.oid[subtreeOid.size()] != '.')) {
            break;
        }
        agg.values.push_back(v);
        current = v.oid;
    }
    return agg;
}

} // namespace snmp
} // namespace lanscope
