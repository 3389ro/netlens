#pragma once

#include "../Models.h"

#include <string>

namespace lanscope {

/// Heuristic device-type classification.
///
/// Pure inference — no extra network probes. It looks at data the scan has
/// already gathered for a host (MAC/OUI vendor, open ports, service
/// fingerprints, hostname, and whether the host is the gateway) and makes a
/// best-effort guess at what the device *is*: "Windows PC", "IP Camera",
/// "Printer", "Router / Gateway", "NAS", "Linux/Unix host", … or "Unknown"
/// when the signals don't add up to anything. It also extracts a best-effort
/// model string, usually from the device's web page <title>.
///
/// This is a guess, not an assertion. The classification is deliberately
/// conservative: when in doubt it returns "Unknown" rather than mislabel.
class DeviceClassifier {
public:
    /// Sets result.deviceType and result.deviceModel. No-op for offline hosts.
    /// `gatewayIp` is the active adapter's default-gateway IPv4 (dotted), or
    /// empty when unknown — it is the single strongest "this is the router"
    /// signal when present.
    static void classify(ScanResult& result, const std::wstring& gatewayIp);
};

} // namespace lanscope
