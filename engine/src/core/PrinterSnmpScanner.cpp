#include "PrinterSnmpScanner.h"
#include "SnmpClient.h"

#include <windows.h>   // MultiByteToWideChar / CP_UTF8

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>

namespace lanscope {

namespace {

// =============================================================================
// Standard Printer-MIB OIDs (RFC 3805 / 1759)
// =============================================================================
constexpr const char* kSysDescr   = "1.3.6.1.2.1.1.1.0";
constexpr const char* kSysObjID   = "1.3.6.1.2.1.1.2.0";
constexpr const char* kSysName    = "1.3.6.1.2.1.1.5.0";

// prtMarkerSupplies subtree — one row per consumable, columns under
// 1.3.6.1.2.1.43.11.1.1.<column>.<hrDeviceIndex>.<prtMarkerSuppliesIndex>.
constexpr const char* kPrtMarkerSuppliesTable = "1.3.6.1.2.1.43.11.1.1";
constexpr int kColMarkerType     = 5;   // prtMarkerSuppliesType  (INTEGER enum)
constexpr int kColMarkerColorIdx = 3;   // prtMarkerSuppliesColorantIndex
constexpr int kColMarkerDescr    = 6;   // prtMarkerSuppliesDescription (string)
constexpr int kColMarkerMaxCap   = 8;   // prtMarkerSuppliesMaxCapacity (int)
constexpr int kColMarkerLevel    = 9;   // prtMarkerSuppliesLevel (int)

// Serial number — best-effort, sometimes under hrDevice / prtGeneral.
constexpr const char* kPrtGeneralSerial = "1.3.6.1.2.1.43.5.1.1.17.1";

// =============================================================================
// String helpers
// =============================================================================

std::wstring utf8To(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                 static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        w.data(), n);
    return w;
}

bool icontains(const std::wstring& hay, const wchar_t* needle) {
    if (!needle || !*needle) return false;
    const size_t nl = wcslen(needle);
    if (hay.size() < nl) return false;
    auto lc = [](wchar_t c) -> wchar_t {
        if (c >= L'A' && c <= L'Z') return c + (L'a' - L'A');
        return c;
    };
    for (size_t i = 0; i + nl <= hay.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < nl; ++j) {
            if (lc(hay[i + j]) != lc(needle[j])) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
}

// Extract a vendor name from sysDescr / sysName text. Quick keyword match
// against the well-known printer-vendor list.
std::wstring guessVendor(const std::wstring& descr, const std::wstring& name) {
    struct V { const wchar_t* needle; const wchar_t* label; };
    static const V kVendors[] = {
        { L"hewlett", L"HP" },     { L"hp ",      L"HP" },
        { L"laserjet",L"HP" },     { L"officejet",L"HP" },
        { L"deskjet", L"HP" },     { L"jetdirect",L"HP" },
        { L"xerox",   L"Xerox" },
        { L"brother", L"Brother" },
        { L"canon",   L"Canon" },
        { L"epson",   L"Epson" },
        { L"ricoh",   L"Ricoh" },
        { L"kyocera", L"Kyocera" },
        { L"konica",  L"Konica Minolta" }, { L"bizhub",   L"Konica Minolta" },
        { L"minolta", L"Konica Minolta" },
        { L"lexmark", L"Lexmark" },
        { L"sharp",   L"Sharp" },
        { L"oki",     L"OKI" },
        { L"toshiba", L"Toshiba" },
        { L"samsung", L"Samsung" },
        { L"zebra",   L"Zebra" },
        { L"dymo",    L"Dymo" },
        { L"dell",    L"Dell" },
    };
    for (const auto& v : kVendors) {
        if (icontains(descr, v.needle) || icontains(name, v.needle))
            return v.label;
    }
    return {};
}

// Extract a model name. Heuristic: first space-delimited token after the
// vendor keyword in sysDescr. Falls back to the first line of sysDescr.
std::wstring guessModel(const std::wstring& descr, const std::wstring& vendor) {
    if (descr.empty()) return {};
    // Take just the first line (sysDescr often spans several with version info).
    std::wstring first = descr;
    size_t nl = first.find_first_of(L"\r\n");
    if (nl != std::wstring::npos) first.resize(nl);
    if (first.size() > 120) first.resize(120);
    if (vendor.empty()) return first;
    // If the first line starts with the vendor name, return it as-is; it's
    // usually the most useful single string.
    return first;
}

// Normalize prtMarkerSuppliesType enum value into a friendly label.
// RFC 3805 §3.3.2.5 enumerates ~30 supply types; we map the common ones.
std::wstring normalizeType(int64_t markerType, const std::wstring& descr) {
    switch (markerType) {
        case 3:  return L"Toner";
        case 4:  return L"Waste toner";
        case 5:  return L"Ink";
        case 6:  return L"Ink cartridge";
        case 7:  return L"Ink ribbon";
        case 8:  return L"Waste ink";
        case 9:  return L"Opc (drum)";
        case 10: return L"Developer";
        case 11: return L"Fuser oil";
        case 12: return L"Solid wax";
        case 13: return L"Ribbon wax";
        case 14: return L"Waste wax";
        case 15: return L"Fuser";
        case 16: return L"Corona wire";
        case 17: return L"Fuser oil wick";
        case 18: return L"Cleaner unit";
        case 19: return L"Fuser cleaning pad";
        case 20: return L"Transfer unit";
        case 21: return L"Toner cartridge";
        case 22: return L"Fuser oiler";
        case 23: return L"Maintenance kit";
        default: break;
    }
    // Fall back to keyword sniffing on the description.
    if (icontains(descr, L"drum"))   return L"Drum";
    if (icontains(descr, L"fuser"))  return L"Fuser";
    if (icontains(descr, L"waste"))  return L"Waste toner";
    if (icontains(descr, L"maintenance")) return L"Maintenance kit";
    if (icontains(descr, L"toner"))  return L"Toner";
    if (icontains(descr, L"ink"))    return L"Ink";
    return L"Supply";
}

// Map free-text description / colorant index into a normalized color tag.
std::wstring normalizeColor(const std::wstring& descr) {
    if (icontains(descr, L"black")   || icontains(descr, L" k ") || icontains(descr, L"(k)")) return L"Black";
    if (icontains(descr, L"cyan")    || icontains(descr, L" c ") || icontains(descr, L"(c)")) return L"Cyan";
    if (icontains(descr, L"magenta") || icontains(descr, L" m ") || icontains(descr, L"(m)")) return L"Magenta";
    if (icontains(descr, L"yellow")  || icontains(descr, L" y ") || icontains(descr, L"(y)")) return L"Yellow";
    if (icontains(descr, L"photo"))  return L"Photo";
    if (icontains(descr, L"drum"))   return L"Drum";
    if (icontains(descr, L"fuser"))  return L"Fuser";
    if (icontains(descr, L"waste"))  return L"Waste";
    if (icontains(descr, L"maintenance")) return L"Maintenance";
    return L"";
}

// Trim trailing whitespace + control chars.
void trimText(std::wstring& s) {
    while (!s.empty() && (s.back() == L' ' || s.back() == L'\t'
                       || s.back() == L'\r' || s.back() == L'\n')) {
        s.pop_back();
    }
}

// Extract the trailing ".<colIdx>.<row>" of a Printer-MIB OID into a row
// identifier. Returns -1 if parsing fails.
struct RowKey { int col; std::string suffix; };
bool parseSupplyRow(const std::string& oid, const std::string& tableOid, RowKey& out) {
    if (oid.size() < tableOid.size() + 2) return false;
    if (oid.compare(0, tableOid.size(), tableOid) != 0) return false;
    if (oid[tableOid.size()] != '.') return false;
    const char* p = oid.c_str() + tableOid.size() + 1;
    // First component after the table prefix = column.
    int col = 0;
    while (*p >= '0' && *p <= '9') { col = col * 10 + (*p - '0'); ++p; }
    if (col == 0) return false;
    out.col = col;
    // Rest (including the leading dot) identifies the row uniquely.
    out.suffix = (*p == '.') ? std::string(p + 1) : std::string{};
    return true;
}

} // anonymous namespace

PrinterInfo PrinterSnmpScanner::probe(uint32_t hostOrderIp,
                                       const PrinterSignals& signals,
                                       int timeoutMs,
                                       bool wantSupplies,
                                       const std::atomic<bool>& cancel) {
    PrinterInfo info;
    info.isPrinter = signals.any();
    if (!info.isPrinter) return info;
    info.snmpStatus = PrinterSnmpStatus::Unavailable;
    // Default 500ms (was 800ms). Healthy printers respond to SNMP GET in
    // < 50 ms; the larger budget mainly slowed Cancel response because
    // txn's select() blocks for the full timeout. 500ms bounds the
    // worst-case cancel latency to ~1s (two gets + first getnext) for
    // unresponsive printers while still leaving headroom for LAN jitter.
    if (timeoutMs <= 0) timeoutMs = 500;

    // ---- 1) System group: sysDescr / sysName / sysObjectID ----
    auto sys = snmp::get(hostOrderIp,
                          { kSysDescr, kSysName, kSysObjID },
                          timeoutMs);
    if (cancel.load(std::memory_order_relaxed)) return info;

    if (sys.status != snmp::Status::Ok) {
        // SNMP doesn't respond — bail with status = Unavailable. We still
        // return isPrinter = true so the UI can show the badge + a hint.
        return info;
    }

    // Map varbinds back to friendly fields.
    for (const auto& v : sys.values) {
        if (v.isException) continue;
        if (v.oid == kSysDescr) {
            info.sysDescr = utf8To(v.asText);
            trimText(info.sysDescr);
        } else if (v.oid == kSysName) {
            info.sysName = utf8To(v.asText);
            trimText(info.sysName);
        }
    }
    info.vendor = guessVendor(info.sysDescr, info.sysName);
    info.model  = guessModel (info.sysDescr, info.vendor);

    // ---- 2) Serial number (best-effort) ----
    auto sn = snmp::get(hostOrderIp, { kPrtGeneralSerial }, timeoutMs);
    if (sn.status == snmp::Status::Ok && !sn.values.empty()
        && !sn.values.front().isException) {
        info.serial = utf8To(sn.values.front().asText);
        trimText(info.serial);
    }

    // SNMP works → at worst we have "Ok with no supplies".
    info.snmpStatus = PrinterSnmpStatus::NoSupplies;

    // ---- 3) Walk the prtMarkerSupplies table for consumables ----
    if (!wantSupplies) {
        // Still mark ok if we have descr; otherwise the per-supply logic
        // would have promoted status.
        if (!info.sysDescr.empty()) info.snmpStatus = PrinterSnmpStatus::Ok;
        return info;
    }
    if (cancel.load(std::memory_order_relaxed)) return info;
    auto walk = snmp::walk(hostOrderIp, kPrtMarkerSuppliesTable,
                            timeoutMs, /*maxValues=*/128, cancel);
    if (walk.status != snmp::Status::Ok || walk.values.empty()) {
        return info;
    }

    // Group varbinds by row suffix.
    struct Row {
        std::string  suffix;
        int64_t      markerType = -1;
        std::wstring descr;
        int64_t      level    = -1;
        int64_t      maxCap   = -1;
    };
    std::map<std::string, Row> rows;
    std::string tableOid = kPrtMarkerSuppliesTable;
    for (const auto& v : walk.values) {
        RowKey rk;
        if (!parseSupplyRow(v.oid, tableOid, rk)) continue;
        Row& r = rows[rk.suffix];
        r.suffix = rk.suffix;
        switch (rk.col) {
            case kColMarkerType:
                if (v.type == snmp::ValueType::Integer) r.markerType = v.asInt;
                break;
            case kColMarkerDescr:
                if (v.type == snmp::ValueType::OctetString) {
                    r.descr = utf8To(v.asText);
                    trimText(r.descr);
                }
                break;
            case kColMarkerLevel:
                if (v.type == snmp::ValueType::Integer) r.level = v.asInt;
                break;
            case kColMarkerMaxCap:
                if (v.type == snmp::ValueType::Integer) r.maxCap = v.asInt;
                break;
            default: break;
        }
    }

    // Convert rows to supplies. Skip rows with no description AND no level
    // (likely truncated walks).
    for (auto& kv : rows) {
        const Row& r = kv.second;
        if (r.descr.empty() && r.level < 0) continue;
        PrinterSupply s;
        s.description = r.descr;
        // Type/color normalization. We compose "Toner Black" / "Drum" /
        // "Waste toner" depending on what we can derive.
        std::wstring typeLabel = normalizeType(r.markerType, r.descr);
        std::wstring colorLabel = normalizeColor(r.descr);
        if (colorLabel.empty() &&
            (typeLabel == L"Drum" || typeLabel == L"Fuser"
          || typeLabel == L"Waste toner" || typeLabel == L"Maintenance kit")) {
            s.color = typeLabel;
        } else if (!colorLabel.empty()) {
            s.color = colorLabel;
        } else {
            s.color = typeLabel;
        }
        s.level    = r.level;
        s.maxLevel = r.maxCap;
        // Compute % only when both are usable. -1/-2 are MIB sentinels.
        if (r.level >= 0 && r.maxCap > 0) {
            int p = static_cast<int>((r.level * 100) / r.maxCap);
            if (p < 0)   p = 0;
            if (p > 100) p = 100;
            s.percent = p;
        }
        info.supplies.push_back(std::move(s));
    }

    if (!info.supplies.empty()) info.snmpStatus = PrinterSnmpStatus::Ok;
    return info;
}

} // namespace lanscope
