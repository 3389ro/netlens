#ifndef NETLENS_SNMP_CLIENT_H
#define NETLENS_SNMP_CLIENT_H

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace lanscope {

// Minimal SNMP v2c read-only client. Speaks just enough BER to do GET and
// GETNEXT requests over UDP/161 with the "public" community. NOT a general-
// purpose SNMP library — designed for the printer-MIB use case only.
//
// Why not a third-party lib: portability + EXE size. Net-SNMP would add
// several MB of static deps and a complex build. The wire format we need
// is ~300 lines of straightforward ASN.1 BER encoding.
namespace snmp {

enum class Status {
    Ok,           // valid response with at least one varbind
    Timeout,      // UDP send succeeded, no reply within budget
    Refused,      // ICMP unreachable or socket-level error
    NoSuchObject, // valid response but the varbind is an SNMP exception
    BadResponse   // received a packet we couldn't parse
};

enum class ValueType {
    Null,
    Integer,
    OctetString,
    ObjectId,
    Counter32,
    Gauge32,
    TimeTicks,
    Other        // type we don't decode, but data is preserved as raw octets
};

struct Value {
    std::string  oid;          // ASCII dotted "1.3.6.1.2.1.1.1.0"
    ValueType    type = ValueType::Null;
    int64_t      asInt = 0;
    std::string  asText;       // human-readable string (octet-string decoded,
                               // integer / counter formatted, OID dotted, ...)
    bool         isException = false;   // SNMP "noSuchObject", "endOfMibView", ...
};

struct Result {
    Status              status = Status::Timeout;
    std::vector<Value>  values;
};

// SNMPv2c GET. `oids` is a list of dotted OIDs (e.g. "1.3.6.1.2.1.1.1.0").
// Each will be returned as one Value in `result.values` (same order).
Result get(uint32_t hostOrderIp,
            const std::vector<std::string>& oids,
            int timeoutMs);

// SNMPv2c walk over the given subtree. Uses GETNEXT repeatedly. Stops when
// the returned OID no longer starts with `subtreeOid`, the response is an
// end-of-MIB exception, or `maxValues` entries are collected (safety cap).
Result walk(uint32_t hostOrderIp,
             const std::string& subtreeOid,
             int timeoutMs,
             int maxValues,
             const std::atomic<bool>& cancel);

} // namespace snmp
} // namespace lanscope

#endif
