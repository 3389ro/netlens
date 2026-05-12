#pragma once

#include <string>
#include <vector>

namespace netlens {

/// One vendor-family port-priority entry. The scanner uses these to bias the
/// per-host port order: when a host's MAC OUI maps to one of these profiles,
/// the profile's ports go FIRST in that host's scan list, so the user sees
/// vendor-specific services (e.g. Dahua RTSP 554 / 37777, MikroTik Winbox
/// 8291, ESXi 902) appear in the results almost immediately instead of after
/// the full common-port sweep finishes.
struct VendorPortProfile {
    /// Display label, e.g. "Video surveillance (Dahua, Hikvision, ...)"
    std::wstring                label;
    /// Case-insensitive substring patterns matched against the vendor name.
    std::vector<std::wstring>   matchers;
    /// Priority port list — scanned first for matched hosts.
    std::vector<int>            ports;
};

/// Static catalogue of vendor-family port profiles + resolver.
///
/// Match resolution is "first-hit wins" over the catalogue in declaration order,
/// so the data is arranged narrow-first (e.g. MikroTik / Ubiquiti come before
/// generic enterprise-networking). Vendors with no profile fall through.
class VendorPortProfiles {
public:
    /// Returns the profile that matches the given vendor name, or nullptr
    /// when there is no match. Case-insensitive substring against each
    /// matcher in declared order.
    static const VendorPortProfile* match(const std::wstring& vendor);

    /// Catalogue accessor (for UI / debug / tooltips).
    static const std::vector<VendorPortProfile>& profiles();

    /// Builds a per-host port list with priority ports first, then the user's
    /// scan list. Duplicates are dropped, the user-list relative order is
    /// preserved for everything not already promoted.
    static std::vector<int> mergePorts(const std::vector<int>& priority,
                                       const std::vector<int>& userPorts);
};

} // namespace netlens
