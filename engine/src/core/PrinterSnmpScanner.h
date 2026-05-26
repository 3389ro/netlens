#ifndef NETLENS_PRINTER_SNMP_SCANNER_H
#define NETLENS_PRINTER_SNMP_SCANNER_H

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace lanscope {

// One consumable line — toner, drum, fuser, waste-toner, ...
struct PrinterSupply {
    std::wstring  description;   // engine-reported, e.g. "Black Cartridge HP 26X"
    std::wstring  color;         // normalized: Black / Cyan / Magenta / Yellow /
                                 // Drum / Fuser / Waste toner / Maintenance kit
    int64_t       level    = -1; // raw level value (-1 / -2 / 0 ⇒ unknown)
    int64_t       maxLevel = -1; // raw max-capacity (-1 / -2 / 0 ⇒ unknown)
    int           percent  = -1; // -1 ⇒ unknown
};

enum class PrinterSnmpStatus {
    NotProbed,         // device didn't look like a printer / preset skipped SNMP
    Unavailable,       // SNMP timed out or refused
    NoSupplies,        // SNMP works but Printer-MIB returned nothing
    Ok                 // at least one consumable readable
};

struct PrinterInfo {
    bool                          isPrinter   = false;
    std::wstring                  vendor;       // e.g. "HP", "Brother"
    std::wstring                  model;        // e.g. "HP LaserJet MFP M477fnw"
    std::wstring                  serial;       // best-effort
    std::wstring                  sysName;      // SNMP sysName
    std::wstring                  sysDescr;     // SNMP sysDescr (verbatim, truncated)
    PrinterSnmpStatus             snmpStatus = PrinterSnmpStatus::NotProbed;
    std::vector<PrinterSupply>    supplies;
};

// Single signal helper: did the engine see ANY classic printer signal on this
// host? Used by NetworkScanner to decide whether to spend SNMP budget. Defined
// here so callers don't have to pull the entire ScanResult dependency.
struct PrinterSignals {
    bool port9100   = false;
    bool port515    = false;
    bool port631    = false;
    bool snmpUdp161 = false;   // we already saw UDP/161 responding (rare on TCP scan)
    bool vendorMatch = false;  // OUI vendor is a known printer brand
    bool deviceClass = false;  // engine DeviceClassifier already said "Printer"

    bool any() const {
        return port9100 || port515 || port631 || snmpUdp161
            || vendorMatch || deviceClass;
    }
};

class PrinterSnmpScanner {
public:
    // Synchronous probe. Spends at most ~`timeoutMs` × few requests of wall
    // time. Always non-blocking sockets internally so the caller's thread is
    // never stuck inside a Winsock call without a deadline.
    //
    // `wantSupplies` gates the Printer-MIB walk. Set false for Quick-style
    // scans where we only want vendor/model from sysDescr.
    static PrinterInfo probe(uint32_t hostOrderIp,
                              const PrinterSignals& signals,
                              int timeoutMs,
                              bool wantSupplies,
                              const std::atomic<bool>& cancel);
};

} // namespace lanscope

#endif
