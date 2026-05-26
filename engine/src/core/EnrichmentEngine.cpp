#include "EnrichmentEngine.h"

#include "LocalProcessResolver.h"
#include "VendorShortener.h"
#include "VersionAnnotator.h"

#include <algorithm>
#include <cwctype>
#include <set>

namespace lanscope {

namespace {

std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

bool contains(const std::wstring& s, const wchar_t* needle) {
    return s.find(needle) != std::wstring::npos;
}

bool startsWith(const std::wstring& s, const wchar_t* needle) {
    size_t n = 0; while (needle[n]) ++n;
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) if (s[i] != needle[i]) return false;
    return true;
}

bool vendorIs(const std::wstring& vLower, std::initializer_list<const wchar_t*> keys) {
    for (auto k : keys) if (vLower.find(k) != std::wstring::npos) return true;
    return false;
}

// Pull a brand name out of WebUiProbe's prefixed model string. Used when
// the MAC-OUI vendor lookup failed (remote subnet, ARP unreachable) so
// the GUI's Vendor column still shows SOMETHING and the router-brand
// override in enhancedDeviceLabel has a signal to fire on.
//
// Returns empty when the model string doesn't start with a recognised
// brand keyword. Matches:
//   "Web UI brand: TP-Link"        → "TP-Link"
//   "TP-Link (login page)"         → "TP-Link"
//   "TP-Link router"               → "TP-Link"
//   "MikroTik (RouterOS …)"        → "MikroTik"
//   "Xerox AltaLink C8130"         → "Xerox"
//   "Netgear GS724TPv2"            → "Netgear"
//   etc.
std::wstring deriveBrandFromWebUiModel(const std::wstring& m) {
    if (m.empty()) return {};
    static const wchar_t* kWebUiBrandPrefix = L"Web UI brand: ";
    if (m.find(kWebUiBrandPrefix) == 0) {
        return m.substr(14); // wcslen("Web UI brand: ")
    }
    // Body brand or device-from-title formats — match a leading whitelist.
    static const wchar_t* kBrands[] = {
        L"TP-Link", L"MikroTik", L"Netgear", L"D-Link", L"Mercusys",
        L"Tenda", L"Cudy", L"Reyee / Ruijie", L"ASUS Router", L"Xerox",
        L"HP", L"Synology", L"Ubiquiti", L"Brother", L"Canon", L"Epson",
        L"Lexmark", L"Konica Minolta", L"Ricoh", L"Kyocera", L"Zyxel",
        L"TRENDnet", L"Allied Telesis",
    };
    for (auto b : kBrands) {
        size_t bl = 0; while (b[bl]) ++bl;
        if (m.size() >= bl && m.substr(0, bl) == b) {
            // "ASUS Router" → "ASUS"
            if (std::wstring(b) == L"ASUS Router")      return L"ASUS";
            if (std::wstring(b) == L"Reyee / Ruijie")   return L"Reyee";
            return b;
        }
    }
    return {};
}

// Walks the engine's serviceSummary CSV for any "vmware esxi <ver>"-shaped
// token and returns the LONGEST dotted-digit run found. Used by
// enhancedDeviceLabel to promote "Hypervisor (ESXi)" to a concrete version.
std::wstring esxiVersionFromServices(const std::wstring& services) {
    std::wstring lower = toLower(services);
    size_t pos = lower.find(L"vmware esxi");
    if (pos == std::wstring::npos) return {};
    size_t tailStart = pos + 11; // wcslen("vmware esxi")
    std::wstring best;
    size_t i = tailStart;
    while (i < services.size()) {
        wchar_t c = services[i];
        if (c >= L'0' && c <= L'9') {
            size_t start = i;
            while (i < services.size()) {
                wchar_t d = services[i];
                if ((d >= L'0' && d <= L'9') || d == L'.') ++i;
                else break;
            }
            std::wstring tok = services.substr(start, i - start);
            if (tok.find(L'.') != std::wstring::npos && tok.size() > best.size()) {
                best = tok;
            }
        } else {
            ++i;
        }
    }
    return best;
}

} // anonymous namespace

// =============================================================================
// vendorPortHint — per-port brand-aware service label
// =============================================================================
//
// The engine's generic banner fingerprinter stays product-agnostic ("HTTP",
// "Apache 2.4") because it can't know that port 8291 on a Mikrotik means
// WinBox while 8291 on an HP MFP means web admin. This function fills the
// gap for cases where the OUI vendor IS the service operator — routers, NAS,
// cameras, printers, hypervisors. Matching is case-insensitive substring on
// the vendor string so OUI variants ("Hewlett Packard", "HP Inc.",
// "Aruba a Hewlett Packard Enterprise Company") all hit the same branch.
//
// Gated on `deviceType`: brand hints are suppressed for general-purpose
// computers because the OUI on a PC tells us the NIC chipset, not what the
// user installed. (The v1.0.22 bug surfaced "Gigabyte web mgmt" on a Windows
// PC running Apache because its NIC was Giga-byte; this gate fixes that.)

std::wstring EnrichmentEngine::vendorPortHint(const std::wstring& vendor,
                                                const std::wstring& deviceType,
                                                int port) {
    const std::wstring v  = toLower(vendor);
    const std::wstring dt = toLower(deviceType);

    bool generalPurpose =
        dt.find(L"windows pc")                 != std::wstring::npos ||
        dt.find(L"windows domain controller")  != std::wstring::npos ||
        dt.find(L"linux pc")                   != std::wstring::npos ||
        dt.find(L"workstation")                != std::wstring::npos ||
        dt.find(L"virtual machine")            != std::wstring::npos ||
        dt == L"unknown" || dt.empty();
    if (generalPurpose) return {};

    if (vendorIs(v, { L"mikrotik", L"routerboard" })) {
        switch (port) {
            case 22:   return L"RouterOS SSH";
            case 23:   return L"RouterOS Telnet";
            case 80:   return L"Webfig HTTP";
            case 443:  return L"Webfig HTTPS";
            case 8291: return L"WinBox";
            case 8728: return L"RouterOS API";
            case 8729: return L"RouterOS API SSL";
            default:   return {};
        }
    }
    if (vendorIs(v, { L"hewlett", L"hp inc", L"hp ", L"aruba" })) {
        switch (port) {
            case 80:     return L"HP web admin";
            case 443:    return L"HP web admin HTTPS";
            case 515:    return L"HP LPR print";
            case 631:    return L"HP IPP / AirPrint";
            case 2381:   return L"HP iLO web";
            case 8000:   return L"HP MFP web";
            case 8080:   return L"HP Web JetAdmin";
            case 8289:
            case 8291:
            case 8295:   return L"HP / Aruba web mgmt";
            case 9100:   return L"HP JetDirect raw print";
            case 17988:  return L"HP iLO Federation";
            default:     return {};
        }
    }
    if (vendorIs(v, { L"synology" })) {
        switch (port) {
            case 22:   return L"Synology SSH";
            case 80:   return L"DSM HTTP redirect";
            case 443:  return L"DSM HTTPS";
            case 5000: return L"DSM HTTP";
            case 5001: return L"DSM HTTPS";
            case 5005: return L"DSM mobile";
            case 6281: return L"Synology Drive";
            case 6690: return L"Synology CloudStation";
            default:   return {};
        }
    }
    if (vendorIs(v, { L"ubiquiti", L"ubnt" })) {
        switch (port) {
            case 22:    return L"UBNT SSH";
            case 80:    return L"UniFi web (redirect)";
            case 443:   return L"UniFi web";
            case 6789:  return L"UniFi STUN";
            case 8080:  return L"UniFi inform";
            case 8443:  return L"UniFi UI";
            case 8843:  return L"UniFi guest HTTPS";
            case 8880:  return L"UniFi guest HTTP";
            case 10001: return L"UBNT discovery";
            case 27117: return L"UniFi MongoDB";
            default:    return {};
        }
    }
    if (vendorIs(v, { L"dahua", L"zhejiang dahua" })) {
        switch (port) {
            case 37777: return L"Dahua DVR proto";
            case 80:    return L"Dahua web";
            case 443:   return L"Dahua web HTTPS";
            case 554:   return L"Dahua RTSP";
            default:    return {};
        }
    }
    if (vendorIs(v, { L"hikvision", L"hangzhou hikvision" })) {
        switch (port) {
            case 8000: return L"Hikvision SDK";
            case 80:   return L"Hikvision web";
            case 443:  return L"Hikvision web HTTPS";
            case 554:  return L"Hikvision RTSP";
            default:   return {};
        }
    }
    if (vendorIs(v, { L"sonos" })) {
        switch (port) {
            case 1400: return L"Sonos web";
            case 4070: return L"Sonos control";
            default:   return {};
        }
    }
    if (vendorIs(v, { L"apple" })) {
        switch (port) {
            case 548:   return L"AFP file sharing";
            case 3689:  return L"DAAP / iTunes share";
            case 5009:  return L"AirPort admin";
            case 5353:  return L"Bonjour";
            case 7000:  return L"AirPlay";
            case 7100:  return L"AirPlay-alt";
            case 62078: return L"iPhone lockdown";
            default:    return {};
        }
    }
    if (vendorIs(v, { L"zebra" })) {
        switch (port) {
            case 21:   return L"Zebra FTP";
            case 9100: return L"Zebra raw print";
            default:   return {};
        }
    }
    if (vendorIs(v, { L"vmware" })) {
        switch (port) {
            case 80:   return L"ESXi web redirect";
            case 443:  return L"ESXi vSphere Client";
            case 902:  return L"VMware Auth";
            case 912:  return L"VMware Workstation";
            case 8000: return L"ESXi vMotion";
            default:   return {};
        }
    }
    if (vendorIs(v, { L"axis communications" })) {
        switch (port) {
            case 80:  return L"Axis camera web";
            case 443: return L"Axis camera HTTPS";
            case 554: return L"Axis RTSP";
            default:  return {};
        }
    }
    if (vendorIs(v, { L"netgear" })) {
        switch (port) {
            case 22:  return L"Netgear SSH";
            case 23:  return L"Netgear Telnet";
            case 80:  return L"Netgear ProSAFE web admin";
            case 443: return L"Netgear ProSAFE web admin HTTPS";
            default:  return {};
        }
    }
    if (vendorIs(v, { L"tp-link", L"tplink" })) {
        switch (port) {
            case 22:    return L"TP-Link SSH";
            case 23:    return L"TP-Link Telnet";
            case 80:    return L"TP-Link web admin";
            case 443:   return L"TP-Link web admin HTTPS";
            case 1900:  return L"TP-Link SSDP";
            case 20002: return L"TP-Link discovery";
            default:    return {};
        }
    }
    return {};
}

// =============================================================================
// deviceHint — hostname / OUI-vendor IoT device guess
// =============================================================================
//
// IoT devices very often advertise themselves via DHCP hostname (Daikin
// Wi-Fi controllers register as "DaikinAP*", Sonos as "Sonos-…", Shelly as
// "shelly1-…" etc.). Hostname is tried first because it's almost always
// more specific than vendor (OUIs commonly resolve to the Wi-Fi module
// maker — Murata, AzureWave, Espressif — rather than the end-product brand).

std::wstring EnrichmentEngine::deviceHint(const std::wstring& vendor,
                                            const std::wstring& hostname) {
    const std::wstring h = toLower(hostname);
    const std::wstring v = toLower(vendor);

    // ---- Hostname patterns (specific) ---------------------------------------
    if (startsWith(h, L"daikin") || h.find(L"daikinap") != std::wstring::npos)
        return L"Daikin air conditioner  (Wi-Fi controller)";
    if (startsWith(h, L"shelly"))           return L"Shelly smart switch / sensor";
    if (startsWith(h, L"tasmota"))          return L"Tasmota-based smart device";
    if (startsWith(h, L"sonos") || h.find(L"-sonos") != std::wstring::npos)
                                            return L"Sonos speaker / soundbar";
    if (startsWith(h, L"roku") || h.find(L"-roku") != std::wstring::npos)
                                            return L"Roku streaming device";
    if (startsWith(h, L"chromecast") || h.find(L"chromecast-") != std::wstring::npos)
                                            return L"Google Chromecast";
    if (startsWith(h, L"eero") || h.find(L"-eero") != std::wstring::npos)
                                            return L"eero mesh router / node";
    if (startsWith(h, L"unifi") || h.find(L"-unifi") != std::wstring::npos
     || startsWith(h, L"ubnt"))             return L"UniFi access point / controller";
    if (startsWith(h, L"ring-") || h.find(L"-ring-") != std::wstring::npos
     || startsWith(h, L"ringcam"))          return L"Ring doorbell / camera";
    if (startsWith(h, L"tesla-") || h.find(L"-tesla-") != std::wstring::npos)
                                            return L"Tesla wall connector / Powerwall";
    // Anchor short tokens at start or after `-` so unrelated words containing
    // them (neuralnest, techo-server) don't trigger.
    if (startsWith(h, L"nest") || h.find(L"-nest") != std::wstring::npos)
        return L"Google Nest device";
    if (startsWith(h, L"echo") || h.find(L"-echo") != std::wstring::npos
     || h.find(L"amazon-") != std::wstring::npos)
        return L"Amazon Echo / Alexa device";
    if (h.find(L"homepod")   != std::wstring::npos) return L"Apple HomePod";
    if (h.find(L"appletv")   != std::wstring::npos || h.find(L"apple-tv") != std::wstring::npos)
                                                    return L"Apple TV";
    if (h.find(L"philips")   != std::wstring::npos || h.find(L"hue-") != std::wstring::npos)
                                                    return L"Philips Hue bridge / light";
    if (h.find(L"raspberrypi") != std::wstring::npos || startsWith(h, L"raspberry"))
                                                    return L"Raspberry Pi";
    if (h.find(L"homeassistant") != std::wstring::npos || startsWith(h, L"hassio"))
                                                    return L"Home Assistant host";
    if (h.find(L"octopi")    != std::wstring::npos || h.find(L"octoprint") != std::wstring::npos)
                                                    return L"OctoPrint (3D printer controller)";
    // Ubiquiti mFi — power-monitoring outlets / sensors, NOT a UniFi AP.
    if (startsWith(h, L"mfi") || h.find(L"-mfi") != std::wstring::npos || startsWith(h, L"mpower"))
        return L"Ubiquiti mFi (power / sensor controller)";
    // Printer hostname rule: `hp-` and brand tokens MUST anchor at start
    // (or after a separator) — "shop-1" used to trigger via the substring
    // search.
    if (h.find(L"printer")    != std::wstring::npos
     || startsWith(h, L"hp-") || h.find(L".hp-") != std::wstring::npos
     || startsWith(h, L"epson") || h.find(L"-epson") != std::wstring::npos
     || startsWith(h, L"canon") || h.find(L"-canon") != std::wstring::npos)
        return L"Network printer (from hostname)";
    if (h.find(L"camera")    != std::wstring::npos || h.find(L"ipcam") != std::wstring::npos
     || h.find(L"hikvision") != std::wstring::npos || h.find(L"dahua") != std::wstring::npos)
        return L"IP camera (from hostname)";
    if (h.find(L"nas-")      != std::wstring::npos || h.find(L"synology") != std::wstring::npos
     || h.find(L"diskstation") != std::wstring::npos || h.find(L"qnap") != std::wstring::npos)
        return L"NAS (from hostname)";

    // ---- Vendor patterns (less specific) ------------------------------------
    if (v.find(L"daikin")           != std::wstring::npos) return L"Daikin device";
    if (v.find(L"espressif")        != std::wstring::npos) return L"ESP-based IoT  (ESP32 / ESP8266 — Wi-Fi MCU)";
    if (v.find(L"nordic semi")      != std::wstring::npos) return L"Nordic-based IoT  (BLE / Wi-Fi MCU)";
    if (v.find(L"texas instruments")!= std::wstring::npos) return L"TI-based IoT  (CC32xx / SimpleLink)";
    if (v.find(L"murata")           != std::wstring::npos) return L"Murata Wi-Fi module  (commonly Daikin / IoT product)";
    if (v.find(L"azurewave")        != std::wstring::npos) return L"AzureWave Wi-Fi module  (commonly IoT product)";

    return {};
}

// =============================================================================
// osHint — OS family + version from a single fingerprint detail
// =============================================================================

std::wstring EnrichmentEngine::osHint(const std::wstring& detail) {
    if (detail.empty()) return {};
    const std::wstring d = toLower(detail);

    if (contains(d, L"(win64)") || contains(d, L"(win32)"))
        return L"Windows  (from Server header)";
    if (contains(d, L"microsoft-iis"))
        return L"Windows  (Microsoft IIS)";
    if (contains(d, L"(ubuntu)") || contains(d, L"ubuntu-") || contains(d, L"ubuntu/"))
        return L"Linux — Ubuntu";
    if (contains(d, L"(debian)") || contains(d, L"debian-") || contains(d, L"debian/"))
        return L"Linux — Debian";
    if (contains(d, L"raspbian") || contains(d, L"raspberry"))
        return L"Linux — Raspberry Pi OS";
    if (contains(d, L"(centos)") || contains(d, L"rhel-") || contains(d, L"(red hat)"))
        return L"Linux — RHEL / CentOS";
    if (contains(d, L"(fedora)"))      return L"Linux — Fedora";
    if (contains(d, L"(suse)") || contains(d, L"opensuse")) return L"Linux — SUSE";
    if (contains(d, L"(alpine)"))      return L"Linux — Alpine";
    if (contains(d, L"(freebsd)"))     return L"FreeBSD";
    if (contains(d, L"(openbsd)"))     return L"OpenBSD";
    if (contains(d, L"(unix)"))        return L"Unix-like  (from Server header)";

    // MikroTik RouterOS — version is plaintext in the FTP banner
    // ("220 MikroTik FTP server (MikroTik 6.29.1) ready") and SSH banner.
    if (contains(d, L"mikrotik") || contains(d, L"routeros")) {
        size_t p = d.find(L"mikrotik ");
        if (p != std::wstring::npos) {
            std::wstring tail = detail.substr(p + 9); // skip "mikrotik "
            std::wstring ver;
            for (wchar_t c : tail) {
                if ((c >= L'0' && c <= L'9') || c == L'.') ver.push_back(c);
                else break;
            }
            if (ver.find(L'.') != std::wstring::npos)
                return L"MikroTik RouterOS " + ver;
        }
        return L"MikroTik RouterOS";
    }
    return {};
}

std::wstring EnrichmentEngine::osHintForHost(const ScanResult& r) {
    for (const auto& f : r.fingerprints) {
        if (f.detail.empty()) continue;
        std::wstring h = osHint(f.detail);
        if (!h.empty()) return h;
    }
    return {};
}

std::wstring EnrichmentEngine::deviceHintForHost(const ScanResult& r) {
    return deviceHint(r.vendor, r.hostname);
}

// =============================================================================
// enhancedDeviceLabel — final, most-specific device classification
// =============================================================================
//
// Priority order:
//   1. ESXi / vSphere with a concrete vim25 version (from services summary)
//   2. Cisco IP phone (vendor=Cisco AND any of {2000, 5060, 5061, 69} open)
//   3a. HP iLO (vendor=HP AND port 17988 open)
//   3b. Apple mobile (vendor=Apple AND port 62078 open)
//   3c. NAS misclassified as Printer (printer + SMB/NFS/rsync/DSM open)
//   4. Hostname / IoT-vendor hint (short form, dropping "(...)" tail)
//   5. Engine's own classification, stripped of "Loading…" placeholder

std::wstring EnrichmentEngine::enhancedDeviceLabel(const ScanResult& r) {
    // 1) ESXi + concrete vim25 version.
    {
        const std::wstring engineDeviceLower = toLower(r.deviceType);
        const std::wstring services = r.serviceSummary();
        const std::wstring servicesLower = toLower(services);
        if (engineDeviceLower.find(L"hypervisor") != std::wstring::npos
         || servicesLower.find(L"vmware esxi")   != std::wstring::npos) {
            std::wstring ver = esxiVersionFromServices(services);
            if (!ver.empty()) return L"VMware ESXi " + ver;
        }
    }

    const std::wstring vl = toLower(r.vendor);
    const std::wstring dl = toLower(r.deviceType);

    // Build open-port set once.
    std::set<int> openPorts;
    for (const auto& p : r.ports) if (p.isOpen) openPorts.insert(p.port);

    // 2) Cisco IP phone.
    bool voicePort = openPorts.count(2000) || openPorts.count(5060)
                  || openPorts.count(5061) || openPorts.count(69);
    if ((vl.find(L"cisco") != std::wstring::npos) && voicePort)
        return L"Cisco IP phone";

    // 2b) 3CX PBX (v1.0.37). 3CX is a Windows / Linux software PBX —
    //     not a phone, but the box that drives them. Detection is hard
    //     because NetLens is TCP-only and SIP usually rides UDP/5060;
    //     plus 3CX shares its default TCP web ports (5000 / 5001) with
    //     Synology DSM, so port profile alone is ambiguous. Signals:
    //       - HTTP title / brand hint contains "3CX" (highest confidence)
    //       - Hostname contains "3cx" or "pbx" (typical naming)
    //       - SIP TCP (5060 / 5061) + a 3CX mgmt port (5001 / 5015 /
    //         5443 / 5090) — rare but unambiguous when it happens
    {
        const std::wstring webLower   = toLower(r.webUiModel);
        const std::wstring brandLower = toLower(r.brandHint);
        const std::wstring hostLower  = toLower(r.hostname);
        const bool webSays3cx   = webLower.find(L"3cx")    != std::wstring::npos;
        const bool brandSays3cx = brandLower.find(L"3cx")  != std::wstring::npos;
        const bool hostSays3cx  = hostLower.find(L"3cx")   != std::wstring::npos
                               || hostLower.find(L"pbx")   != std::wstring::npos;
        const bool sipOpen = openPorts.count(5060) || openPorts.count(5061);
        const bool tcxMgmtPort =
            openPorts.count(5001) || openPorts.count(5015) ||
            openPorts.count(5443) || openPorts.count(5090);
        if (webSays3cx || brandSays3cx)         return L"3CX PBX server";
        if (hostSays3cx)                        return L"3CX PBX server";
        if (sipOpen && tcxMgmtPort)             return L"3CX PBX server";
    }

    // 3a) HP iLO.
    if (openPorts.count(17988)
     && (vl.find(L"hewlett") != std::wstring::npos
      || vl.find(L"hp ")     != std::wstring::npos
      || vl.find(L"hp inc")  != std::wstring::npos))
        return L"HP iLO baseboard management";

    // 3b) Apple mobile device. Port 62078 is the iOS lockdown service
    //     (`com.apple.mobile.lockdown`, used by iTunes / Finder Wi-Fi
    //     sync). It's only opened by iPhone / iPad / iPod — no other
    //     OS ships that daemon. The vendor gate was removed in v1.0.51
    //     because modern iOS (14+) randomises the MAC by default, so
    //     the OUI no longer resolves to "Apple" for most iPhones on
    //     real networks. Port 62078 alone is a strong enough signal.
    //     `finalize` also sets r.vendor = "Apple" when this fires.
    if (openPorts.count(62078))
        return L"Apple iPhone / iPad";

    // 3c) NAS-not-Printer override.
    if (dl.find(L"printer") != std::wstring::npos) {
        bool nasSignal = openPorts.count(445) || openPorts.count(2049)
                      || openPorts.count(873) || openPorts.count(5000)
                      || openPorts.count(5001);
        if (nasSignal) return L"NAS";
    }

    // 3c2) IP-Camera-vs-Windows-server disambiguation. The engine's
    //      DeviceClassifier flags any port-554 (RTSP) host as "IP Camera"
    //      — but VMS servers (Genetec, Milestone, generic DVR back-ends)
    //      run on Windows and expose RTSP just to serve the camera streams
    //      they manage. When the host opens the canonical Windows triad
    //      (RPC 135 + SMB 445), or RDP, or WinRM, it's a Windows host
    //      *managing* cameras, not a camera itself. Preserve any (VM) /
    //      (virtual machine) suffix from the engine label or VMware OUI.
    //      Caught GENETECSERVER on 192.168.2.21 in user testing.
    {
        bool engineSaidCamera = dl.find(L"camera") != std::wstring::npos;
        if (engineSaidCamera) {
            bool windowsHost = (openPorts.count(135) && openPorts.count(445))
                            || openPorts.count(3389)   // RDP
                            || openPorts.count(5985)   // WinRM HTTP
                            || openPorts.count(5986)   // WinRM HTTPS
                            || openPorts.count(47001); // WinRM HTTP-alt
            if (windowsHost) {
                bool isVm = vl.find(L"vmware") != std::wstring::npos
                         || dl.find(L"(vm)")   != std::wstring::npos
                         || dl.find(L"virtual machine") != std::wstring::npos;
                return isVm ? L"Windows PC (VM)" : L"Windows PC";
            }
        }
    }

    // 3c3) IP-Camera-vs-router-brand demotion. Router OUIs (TP-Link,
    //      MikroTik, D-Link, Netgear, Tenda, Mercusys, ASUS, RouterBoard)
    //      virtually never ship standalone IP cameras under the same OUI.
    //      When the engine classified as camera but the vendor is a known
    //      router brand:
    //        - if block 3d below CAN promote to "<Brand> router" (router
    //          ports open or web-UI body matched the brand), fall through
    //          and let it run;
    //        - otherwise, refuse the camera label and return a neutral
    //          "<Brand> device" so the GUI doesn't lie.
    //      Caught MikroTik on 192.168.2.15 (ports 80+554 → was IP Camera)
    //      and TP-Link on 192.168.2.142 (no ports detected → was IP Camera).
    {
        bool engineSaidCamera = dl.find(L"camera") != std::wstring::npos;
        if (engineSaidCamera) {
            bool routerBrand = vl.find(L"mikrotik")    != std::wstring::npos
                            || vl.find(L"routerboard") != std::wstring::npos
                            || vl.find(L"tp-link")     != std::wstring::npos
                            || vl.find(L"tplink")      != std::wstring::npos
                            || vl.find(L"d-link")      != std::wstring::npos
                            || vl.find(L"netgear")     != std::wstring::npos
                            || vl.find(L"tenda")       != std::wstring::npos
                            || vl.find(L"mercusys")    != std::wstring::npos
                            || vl.find(L"asus")        != std::wstring::npos;
            if (routerBrand) {
                bool routerShape3d =
                    openPorts.count(53)   || openPorts.count(1723) ||
                    openPorts.count(8291) || openPorts.count(8728) ||
                    openPorts.count(8729);
                bool webUiBrandSignal = !r.webUiModel.empty();
                if (!routerShape3d && !webUiBrandSignal) {
                    std::wstring brand = VendorShortener::shorten(r.vendor);
                    if (!brand.empty()) return brand + L" device";
                }
            }
        }
    }

    // 3d) Router-brand override. Engine's DeviceClassifier can land on
    //     "IP Camera" for hosts that expose HTTP/HTTPS plus a DNS / PPTP /
    //     WinBox / RouterOS-API port — which is the canonical SOHO router
    //     profile, not a camera. When the vendor is a known router brand
    //     AND a router-shaped port is open, flip to "<Brand> router".
    //     Caught misclassifying TP-Link OUI 98-DA-C4 (port 53 + 1723
    //     open) as "IP Camera" in real-world testing.
    {
        bool routerVendor =
            vl.find(L"tp-link")  != std::wstring::npos ||
            vl.find(L"tplink")   != std::wstring::npos ||
            vl.find(L"mikrotik") != std::wstring::npos ||
            vl.find(L"d-link")   != std::wstring::npos ||
            vl.find(L"netgear")  != std::wstring::npos ||
            vl.find(L"tenda")    != std::wstring::npos ||
            vl.find(L"mercusys") != std::wstring::npos ||
            vl.find(L"asus")     != std::wstring::npos;
        bool routerShape =
            openPorts.count(53)   || openPorts.count(1723) ||
            openPorts.count(8291) || openPorts.count(8728) ||
            openPorts.count(8729);
        // Web-UI signal — when WebUiProbe matched a brand keyword in the
        // body (no productName / switchInfo, just the consumer-router
        // login page), the host is overwhelmingly a router. Combined with
        // a router-brand vendor that's a high-confidence override even
        // when none of the router-shaped TCP ports are open (192.168.2.142
        // for ex. exposes only port 80 — the login page — but is a
        // TP-Link router).
        bool webUiBrandSignal = !r.webUiModel.empty();
        // Don't override device-type if the engine already correctly
        // classified as router/gateway/access point.
        bool alreadyRouter =
            dl.find(L"router")        != std::wstring::npos ||
            dl.find(L"gateway")       != std::wstring::npos ||
            dl.find(L"access point")  != std::wstring::npos;
        // Netgear is both a SOHO-router brand AND a managed-switch
        // brand. On enterprise LANs Netgear devices are almost always
        // switches (GS / JGS / ProSafe / S3300 / …) exposing only the
        // web management UI. The `webUiBrandSignal` matched on those
        // because their HTTP title contains "Netgear", which produced
        // false "Netgear router" labels on switches. For Netgear we
        // require an actual router-shape port (DNS / PPTP /
        // RouterOS-API); without one the host falls through to the
        // generic vendor-based "Network device" classification.
        const bool isNetgear = vl.find(L"netgear") != std::wstring::npos;
        const bool allowWebUiSignal = !isNetgear;
        const bool promote = routerVendor
                          && (routerShape ||
                              (webUiBrandSignal && allowWebUiSignal))
                          && !alreadyRouter;
        if (promote) {
            std::wstring brand;
            if      (vl.find(L"tp-link") != std::wstring::npos || vl.find(L"tplink") != std::wstring::npos) brand = L"TP-Link";
            else if (vl.find(L"mikrotik") != std::wstring::npos) brand = L"MikroTik";
            else if (vl.find(L"d-link")   != std::wstring::npos) brand = L"D-Link";
            else if (vl.find(L"netgear")  != std::wstring::npos) brand = L"Netgear";
            else if (vl.find(L"tenda")    != std::wstring::npos) brand = L"Tenda";
            else if (vl.find(L"mercusys") != std::wstring::npos) brand = L"Mercusys";
            else if (vl.find(L"asus")     != std::wstring::npos) brand = L"ASUS";
            if (!brand.empty()) return brand + L" router";
        }
        // Netgear-specific fallback. When the host IS Netgear but
        // didn't get promoted to router (no DNS/PPTP/etc port), it's
        // far more likely a managed switch than a generic "Network
        // device". A switch typically exposes only HTTP/HTTPS, and
        // sometimes SSH/Telnet for CLI.
        if (isNetgear && !alreadyRouter) {
            bool mgmtShape =
                openPorts.count(80) || openPorts.count(443)
             || openPorts.count(22) || openPorts.count(23);
            if (mgmtShape) return L"Netgear switch";
            return L"Netgear device";
        }
    }

    // 3e) Samsung Smart TV / Tizen device.
    //     Ports 8001 / 8002 alone are HTTP-alt used by dozens of
    //     services (Tornado dev servers, monitoring UIs, embedded
    //     admin pages) — they're NOT Tizen-specific. A loose
    //     rule used to mislabel three hosts on a /24 as Samsung TVs
    //     when only one existed.
    //
    //     New rule:
    //       - Port 7676 alone → high-confidence Samsung TV.
    //         Port 7676 is the TizenRemote control channel; it's
    //         genuinely Tizen-only and rare in other contexts.
    //       - Ports 8001 AND 8002 BOTH open → high-confidence Samsung TV.
    //         The SmartView WebSocket pair fires together on real TVs;
    //         hitting both simultaneously on a non-Samsung host would
    //         be a remarkable coincidence.
    //       - Port 8001 or 8002 alone WITH Samsung-OUI vendor → also
    //         counts (corner case: ARP gave us the OUI).
    //       - Neither of those → don't claim Samsung TV; let other rules
    //         classify the host.
    {
        const bool p7676 = openPorts.count(7676) != 0;
        const bool p8001 = openPorts.count(8001) != 0;
        const bool p8002 = openPorts.count(8002) != 0;
        const bool samsungVendor = vl.find(L"samsung") != std::wstring::npos;
        if (p7676)                                  return L"Samsung Smart TV";
        if (p8001 && p8002)                         return L"Samsung Smart TV";
        if ((p8001 || p8002) && samsungVendor)      return L"Samsung Smart TV";
    }

    // 3e2) Less-specific Samsung TV signal: 9999 alone + Samsung OUI.
    //      Port 9999 is also used by some other vendors so we keep the
    //      vendor gate here.
    {
        bool samsungVendor = vl.find(L"samsung") != std::wstring::npos;
        if (samsungVendor && (openPorts.count(9090) || openPorts.count(9091)
                           || openPorts.count(9999)))
            return L"Samsung Smart TV";
    }

    // 3f) Android device with ADB wireless debugging enabled. Port 5555
    //     is the Android Debug Bridge listening socket when the user
    //     turns on "Wireless debugging" in developer options. ADB is
    //     Android-exclusive — no other OS ships it. Combined with a
    //     mobile-brand OUI (Samsung / Google / Xiaomi / OnePlus / Huawei
    //     / Oppo / Vivo / Realme / Motorola / Sony Mobile) this is a
    //     phone or tablet with debug on.
    {
        bool mobileBrand =
            vl.find(L"samsung")  != std::wstring::npos ||
            vl.find(L"google")   != std::wstring::npos ||
            vl.find(L"xiaomi")   != std::wstring::npos ||
            vl.find(L"oneplus")  != std::wstring::npos ||
            vl.find(L"huawei")   != std::wstring::npos ||
            vl.find(L"oppo")     != std::wstring::npos ||
            vl.find(L"vivo")     != std::wstring::npos ||
            vl.find(L"realme")   != std::wstring::npos ||
            vl.find(L"motorola") != std::wstring::npos;
        if (mobileBrand && openPorts.count(5555))
            return L"Android device (ADB wireless)";
    }

    // 3g) Chromecast / Google Cast device. Port 8009 is Cast HTTP, 8008
    //     plain HTTP for Cast discovery. Vendor "Google, Inc." → Pixel
    //     phone or Chromecast or Nest device. Without 8009 we can't
    //     pin it, so this rule only fires for the Cast port specifically.
    if (openPorts.count(8009) && vl.find(L"google,") != std::wstring::npos)
        return L"Chromecast / Google Cast";

    // 3h) Windows host by fingerprint. When the engine's
    //     ServiceFingerprinter caught a Microsoft-specific product
    //     (SQL Server Browser, MSSQL, IIS, Microsoft-HTTPAPI, NetBIOS-SSN
    //     name) the host is Windows — full stop, regardless of vendor
    //     or whether the TCP port scan actually got open-port responses.
    //     Useful for /24 scans where rate limiting drops most TCP ports
    //     but a UDP fingerprint (e.g. SQL Browser on UDP 1434) still
    //     arrives. Caught GENETECSERVER on 192.168.2.21 in /24 load.
    //
    //     Skip this override for NAS vendors. Synology / QNAP /
    //     TrueNAS / OpenMediaVault are Linux appliances that ship
    //     Samba to serve SMB shares; Samba's NetBIOS responses look
    //     identical to a real Windows server's at the wire level, so
    //     without this guard they were mis-classified as "Windows PC"
    //     — losing the correct "NAS" label from T2 / DSM keyword. The
    //     vendor signal here is stronger than the fingerprint signal.
    {
        const bool isKnownNasVendor =
              vl.find(L"synology")       != std::wstring::npos
           || vl.find(L"qnap")           != std::wstring::npos
           || vl.find(L"truenas")        != std::wstring::npos
           || vl.find(L"openmediavault") != std::wstring::npos
           || vl.find(L"netgear")        != std::wstring::npos      // ReadyNAS
           || vl.find(L"western digital")!= std::wstring::npos      // My Cloud
           || vl.find(L"buffalo")        != std::wstring::npos;     // TeraStation
        if (!isKnownNasVendor) {
            for (const auto& f : r.fingerprints) {
                const std::wstring& prod = f.product;
                bool isMicrosoft = prod.find(L"Microsoft")  != std::wstring::npos
                                || prod.find(L"IIS")        != std::wstring::npos
                                || prod.find(L"MSSQL")      != std::wstring::npos
                                || prod.find(L"SQL Server") != std::wstring::npos
                                || prod.find(L"NetBIOS")    != std::wstring::npos
                                || prod.find(L"Windows")    != std::wstring::npos;
                if (isMicrosoft) {
                    bool isVm = vl.find(L"vmware") != std::wstring::npos
                             || dl.find(L"(vm)")   != std::wstring::npos
                             || dl.find(L"virtual machine") != std::wstring::npos;
                    return isVm ? L"Windows PC (VM)" : L"Windows PC";
                }
            }
        }
    }

    // 4) Hostname / IoT-vendor hint (short form).
    {
        std::wstring hint = deviceHint(r.vendor, r.hostname);
        if (!hint.empty()) {
            // Drop the "  (...)" qualifier suffix so the grid Device
            // column shows the short form (everything before the
            // double-space + opening parenthesis).
            size_t cut = hint.find(L"  (");
            if (cut != std::wstring::npos) hint.erase(cut);
            // Trim trailing whitespace.
            while (!hint.empty() && (hint.back() == L' ' || hint.back() == L'\t'))
                hint.pop_back();
            if (!hint.empty()) return hint;
        }
    }

    // 5) Engine's classification, stripped of "Loading…" placeholder.
    std::wstring cleaned = r.deviceType;
    auto replaceAll = [](std::wstring& s, const std::wstring& a, const std::wstring& b) {
        size_t pos = 0;
        while ((pos = s.find(a, pos)) != std::wstring::npos) {
            s.replace(pos, a.size(), b);
            pos += b.size();
        }
    };
    replaceAll(cleaned, L" - Loading...", L"");
    replaceAll(cleaned, L" - Loading…", L""); // single-char ellipsis
    // Trim whitespace.
    while (!cleaned.empty() && (cleaned.back() == L' ' || cleaned.back() == L'\t'))
        cleaned.pop_back();
    while (!cleaned.empty() && (cleaned.front() == L' ' || cleaned.front() == L'\t'))
        cleaned.erase(cleaned.begin());

    // 6) IP-Camera-without-evidence final demotion. If we reached this
    //    far the engine's "IP Camera" survived all the earlier specific
    //    overrides — meaning we don't have a vendor / port / web-UI
    //    signal that points elsewhere. In that case, the engine's
    //    classifier guessed camera with thin justification (sometimes
    //    it lands there for hosts with just port 80 and no vendor).
    //    Refuse the camera label unless there's a real camera signal:
    //      - a camera-shape port (554 RTSP, 8000 SDK, 37777 Dahua, 34567 XMEye)
    //      - a camera-brand OUI (Sony / Hikvision / Dahua / Panasonic /
    //        Axis / Bosch / Pelco / Avigilon / Vivotek / Mobotix)
    //    Otherwise return a neutral "Network device". This catches
    //    192.168.2.15 in single-host scans where ARP doesn't reach.
    {
        std::wstring cl = toLower(cleaned);
        if (cl.find(L"camera") != std::wstring::npos) {
            bool cameraPort = openPorts.count(554)   || openPorts.count(8000)
                           || openPorts.count(37777) || openPorts.count(34567);
            bool cameraBrand =
                vl.find(L"sony")                != std::wstring::npos ||
                vl.find(L"hikvision")           != std::wstring::npos ||
                vl.find(L"dahua")               != std::wstring::npos ||
                vl.find(L"panasonic")           != std::wstring::npos ||
                vl.find(L"axis communications") != std::wstring::npos ||
                vl.find(L"bosch security")      != std::wstring::npos ||
                vl.find(L"pelco")               != std::wstring::npos ||
                vl.find(L"avigilon")            != std::wstring::npos ||
                vl.find(L"vivotek")             != std::wstring::npos ||
                vl.find(L"mobotix")             != std::wstring::npos;
            if (!cameraPort && !cameraBrand) {
                // Preserve "(VM)" suffix if the engine label had it.
                if (cl.find(L"(vm)") != std::wstring::npos) return L"Network device (VM)";
                return L"Network device";
            }
        }
    }

    return cleaned.empty() ? r.deviceType : cleaned;
}

// =============================================================================
// brandHintAggregate — multi-line aggregate for the pane "Brand hints" section
// =============================================================================
//
// Format (newline-separated):
//   "<port>: <vendor-port-hint>"   for each open port that has a brand label
//   "OS hint: <os-hint>"           when at least one fingerprint detail
//                                  yields an OS
//   "Device: <device-hint>"        when hostname / OUI vendor yields a hint
//
// Stage 3 will append "HTTP title: …" / "Web UI model: …" / "Model (web UI):
// …" lines from the WebUiProbe results; until then the aggregate is just
// the three pieces above.

// =============================================================================
// finalize — compute every cached field on `r` in one pass at scan time
// =============================================================================
//
// After this returns, the FFI surface is a pure struct copy:
//   nl_scanner_get_result  → just copies r.{vendorShort, enhancedDeviceType,
//                                            brandHint, osHintCached,
//                                            deviceHintCached, webUiModel}
//   nl_scanner_get_port    → just copies p.{service, ownerPid, ownerExe}
//                            and the matching fingerprint's versionNote
//
// No inference, no Win32 calls, no adapter enumeration on the click path.

void EnrichmentEngine::finalize(ScanResult& r) {
    // 1) When MAC-OUI vendor is missing (remote subnet → no ARP, or
    //    randomised local MAC → OUI doesn't resolve), try to derive a
    //    brand from a stronger signal:
    //    a) WebUiProbe's prefixed model string (consumer routers, NAS,
    //       printers — the body of the admin page leaks the brand).
    //    b) Apple-only TCP ports: 62078 (iOS lockdown, iPhone / iPad
    //       only) and the AirPlay / AFP combo (Mac / Apple TV).
    //    Fills `r.vendor` so the Vendor column shows SOMETHING and the
    //    brand-aware overrides in enhancedDeviceLabel have a vendor to
    //    gate on.
    if (r.vendor.empty()) {
        // (a) Web UI body.
        if (!r.webUiModel.empty()) {
            std::wstring derived = deriveBrandFromWebUiModel(r.webUiModel);
            if (!derived.empty()) r.vendor = derived;
        }
        // (b) Apple iOS lockdown port — iOS-exclusive, even with a
        //     randomised MAC the device is definitely Apple.
        if (r.vendor.empty()) {
            for (const auto& p : r.ports) {
                if (p.isOpen && p.port == 62078) { r.vendor = L"Apple"; break; }
            }
        }
        // (c) Samsung Smart TV ports — TizenOS-only, set vendor=Samsung
        //     so the Vendor column has a real value even on cross-subnet
        //     scans where ARP didn't reach.
        if (r.vendor.empty()) {
            for (const auto& p : r.ports) {
                if (!p.isOpen) continue;
                if (p.port == 7676 || p.port == 8001 || p.port == 8002) {
                    r.vendor = L"Samsung";
                    break;
                }
            }
        }
    }

    // 2) Top-level host enrichment — now that vendor may have been
    //    promoted from the web-UI signal.
    r.vendorShort        = VendorShortener::shorten(r.vendor);
    r.enhancedDeviceType = enhancedDeviceLabel(r);
    r.osHintCached       = osHintForHost(r);
    r.deviceHintCached   = deviceHintForHost(r);
    r.brandHint          = brandHintAggregate(r);

    // 3) Per-fingerprint version annotation.
    for (auto& f : r.fingerprints) {
        f.versionNote = VersionAnnotator::annotate(f.product, f.version);
    }

    // 4) Per-port local-process owner. Skipped entirely for remote hosts
    //    so we don't pay the TCP-table cost on /24 scans where most hosts
    //    are someone else's box.
    if (LocalProcessResolver::isLocalIp(r.ipAddress)) {
        for (auto& p : r.ports) {
            if (!p.isOpen) continue;
            auto owner = LocalProcessResolver::lookup(p.port);
            p.ownerPid = owner.pid;
            if (!owner.exePath.empty()) {
                p.ownerExe = owner.exePath;
            } else if (!owner.errorNote.empty()) {
                p.ownerExe = owner.errorNote;
            }
        }
    }
}

std::wstring EnrichmentEngine::brandHintAggregate(const ScanResult& r) {
    std::wstring out;
    auto pushLine = [&](const std::wstring& line) {
        if (line.empty()) return;
        if (!out.empty()) out.push_back(L'\n');
        out += line;
    };

    // Per-port vendor hints — iterate sorted by port number.
    std::set<int> openPorts;
    for (const auto& p : r.ports) if (p.isOpen) openPorts.insert(p.port);
    for (int port : openPorts) {
        std::wstring label = vendorPortHint(r.vendor, r.deviceType, port);
        if (!label.empty()) {
            pushLine(std::to_wstring(port) + L": " + label);
        }
    }

    std::wstring os = osHintForHost(r);
    if (!os.empty()) pushLine(L"OS hint: " + os);

    std::wstring dev = deviceHintForHost(r);
    if (!dev.empty()) pushLine(L"Device: " + dev);

    // Web UI probe result (Stage 3 — eager Pass 2). WebUiProbe returns one
    // of four prefixed forms which we surface verbatim, or an unprefixed
    // brand-matched model which gets the "Model (web UI): " wrapper here.
    if (!r.webUiModel.empty()) {
        const std::wstring& w = r.webUiModel;
        bool prefixed = false;
        static const wchar_t* kPrefixes[] = {
            L"HTTP title: ", L"Web UI model: ", L"Web UI brand: "
        };
        for (auto p : kPrefixes) {
            size_t pl = 0; while (p[pl]) ++pl;
            if (w.size() >= pl) {
                bool match = true;
                for (size_t i = 0; i < pl; ++i) if (w[i] != p[i]) { match = false; break; }
                if (match) { prefixed = true; break; }
            }
        }
        pushLine(prefixed ? w : (std::wstring(L"Model (web UI): ") + w));
    }

    return out;
}

} // namespace lanscope
