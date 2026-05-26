#pragma once

#include "../Models.h"

#include <set>
#include <string>

namespace lanscope {

/// Post-fingerprint enrichment — turns the raw banner/MAC/port data on a
/// ScanResult into a few short, display-ready strings:
///
///   * vendorPortHint   per-port "brand-aware" service label override
///                      (e.g. port 8291 on a Mikrotik becomes "WinBox")
///   * deviceHint       hostname / OUI-vendor IoT device guess
///                      (e.g. "Daikin air conditioner (Wi-Fi controller)")
///   * osHint           OS family + version sniffed from a banner detail
///                      (Apache "(Win64)", SSH "Ubuntu-…", FTP "MikroTik 6.49.1")
///   * enhancedDeviceLabel
///                      final classification override (promotes ESXi version,
///                      Cisco IP phone, HP iLO, Apple mobile, NAS-not-printer,
///                      hostname / IoT brand) over the engine's coarse
///                      DeviceClassifier output
///   * brandHintAggregate
///                      multi-line string for the GUI pane "Brand hints"
///                      section — port-hint lines + OS hint + device hint
///
/// All functions return empty strings (not optional / nullptr) when nothing
/// applies; callers can test for emptiness directly.
class EnrichmentEngine {
public:
    static std::wstring vendorPortHint(const std::wstring& vendor,
                                        const std::wstring& deviceType,
                                        int port);

    static std::wstring deviceHint(const std::wstring& vendor,
                                    const std::wstring& hostname);

    static std::wstring osHint(const std::wstring& detail);

    static std::wstring enhancedDeviceLabel(const ScanResult& r);

    static std::wstring brandHintAggregate(const ScanResult& r);

    /// First non-empty OS hint encountered across all fingerprint detail
    /// strings on the host. Pure derived field — exposed separately because
    /// the GUI also stores it on a dedicated property; the aggregate above
    /// folds it in too.
    static std::wstring osHintForHost(const ScanResult& r);

    /// Full device-hint blob for the host (vendor + hostname → IoT guess).
    /// Same return as deviceHint(r.vendor, r.hostname) — convenience.
    static std::wstring deviceHintForHost(const ScanResult& r);

    /// Computes every cached enrichment field on `r` in one pass and
    /// stores them on the result. After this returns, `nl_scanner_get_result`
    /// and `nl_scanner_get_port` become pure struct copies — no inference,
    /// no resolution, no Win32 calls on the FFI hot path. Called from
    /// `NetworkScanner::scanOneHost` after RiskAnalyzer when all input
    /// data is final.
    ///
    /// Side-effects on `r`:
    ///   - `vendorShort`              = VendorShortener::shorten(r.vendor)
    ///   - `enhancedDeviceType`       = enhancedDeviceLabel(r)
    ///   - `brandHint`                = brandHintAggregate(r)
    ///   - `osHintCached`             = osHintForHost(r)
    ///   - `deviceHintCached`         = deviceHintForHost(r)
    ///   - each `f.versionNote`       = VersionAnnotator::annotate(f.product, f.version)
    ///   - each `p.ownerPid/ownerExe` = LocalProcessResolver::lookup(p.port)
    ///                                  (only when r is a local host)
    static void finalize(ScanResult& r);
};

} // namespace lanscope
