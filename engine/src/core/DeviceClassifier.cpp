#include "DeviceClassifier.h"

#include <initializer_list>

namespace lanscope {

namespace {

// =============================================================================
// Small helpers
// =============================================================================

std::wstring toLower(std::wstring s) {
    for (auto& c : s)
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    return s;
}
bool has(const std::wstring& hay, const wchar_t* needle) {
    return hay.find(needle) != std::wstring::npos;
}
bool hasAny(const std::wstring& hay, std::initializer_list<const wchar_t*> needles) {
    for (auto n : needles)
        if (hay.find(n) != std::wstring::npos) return true;
    return false;
}
bool startsWith(const std::wstring& s, const wchar_t* prefix) {
    return s.rfind(prefix, 0) == 0;
}
bool portOpen(const ScanResult& r, int port) {
    for (const auto& p : r.ports)
        if (p.isOpen && p.port == port) return true;
    return false;
}
bool anyPortOpen(const ScanResult& r, std::initializer_list<int> ports) {
    for (int p : ports)
        if (portOpen(r, p)) return true;
    return false;
}
bool hasFpService(const ScanResult& r, const wchar_t* service) {
    for (const auto& f : r.fingerprints)
        if (f.service == service) return true;
    return false;
}
bool isWindowsDC(const ScanResult& r) {
    for (const auto& f : r.fingerprints)
        if (f.service == L"windows" &&
            f.detail.find(L"domain controller") != std::wstring::npos)
            return true;
    return false;
}

// A lowercased blob of every keyword-bearing field — vendor, hostname, and the
// product/title/service/detail of each fingerprint — for substring matching.
std::wstring gatherBlob(const ScanResult& r) {
    std::wstring s = toLower(r.vendor);
    s += L' '; s += toLower(r.hostname);
    for (const auto& f : r.fingerprints) {
        s += L' '; s += toLower(f.product);
        s += L' '; s += toLower(f.title);
        s += L' '; s += toLower(f.service);
        s += L' '; s += toLower(f.detail);
    }
    return s;
}

// =============================================================================
// The curated "database" — vendor groups and management-UI / product keywords.
// Substrings are matched case-insensitively against the OUI vendor or the
// gathered blob. Kept deliberately general: it is meant to recognise device
// *classes*, not every model on earth.
// =============================================================================

// Management-UI / product keyword -> device type. Highest-confidence signal:
// the device's own web UI (or a service banner) named itself.
struct KeywordType { const wchar_t* keyword; const wchar_t* type; };
const KeywordType kKeywordTypes[] = {
    // hypervisors / server management
    { L"vmware esxi",   L"Hypervisor (ESXi)" },
    { L"vsphere",       L"Hypervisor (ESXi)" },
    { L"proxmox",       L"Hypervisor" },
    { L"dell idrac",    L"Server (management)" },
    { L"idrac",         L"Server (management)" },
    { L"hpe ilo",       L"Server (management)" },
    { L"lights-out",    L"Server (management)" },
    // firewalls / routers
    { L"pfsense",       L"Firewall" },
    { L"opnsense",      L"Firewall" },
    { L"mikrotik",      L"Network device" },
    { L"routeros",      L"Network device" },
    { L"openwrt",       L"Network device" },
    { L"dd-wrt",        L"Network device" },
    { L"unifi",         L"Access Point" },
    // NAS
    { L"synology",      L"NAS" },
    { L"diskstation",   L"NAS" },
    { L"qnap",          L"NAS" },
    { L"truenas",       L"NAS" },
    { L"openmediavault",L"NAS" },
    // cameras
    { L"hikvision",     L"IP Camera" },
    { L"dahua",         L"IP Camera" },
    { L"network camera",L"IP Camera" },
    { L"ip camera",     L"IP Camera" },
    { L"ipcam",         L"IP Camera" },
    { L"webcam",        L"IP Camera" },
    { L"nvr",           L"IP Camera" },
    { L"dvr",           L"IP Camera" },
    // printers (model-name keywords printers put in their web UI)
    { L"laserjet",      L"Printer" },
    { L"officejet",     L"Printer" },
    { L"deskjet",       L"Printer" },
    { L"pagewide",      L"Printer" },
    { L"pixma",         L"Printer" },
    { L"imageclass",    L"Printer" },
    { L"workforce",     L"Printer" },
    { L"ecotank",       L"Printer" },
    { L"printer",       L"Printer" },
    // IoT hubs / smart home
    { L"home assistant",L"IoT / smart home" },
    { L"homebridge",    L"IoT / smart home" },
};

// Vendor groups. The OUI vendor string is matched as a substring (lowercased).
const wchar_t* kCameraVendors[] = {
    L"hikvision", L"dahua", L"axis comm", L"hanwha", L"vivotek", L"reolink",
    L"amcrest", L"foscam", L"uniview", L"mobotix", L"geovision", L"wyze",
    L"lorex", L"swann", L"annke" };
// TP-Link Tapo cams aren't listed: TP-Link OUIs are overwhelmingly
// routers/APs and a Tapo cam alone (RTSP/554) used to misclassify the
// far more common router into "IP Camera". Tapo cams still surface
// correctly via webUiModel / device-specific port profiles.
const wchar_t* kPrinterVendors[] = {
    L"brother", L"canon", L"epson", L"seiko epson", L"lexmark", L"xerox",
    L"kyocera", L"ricoh", L"konica", L"zebra", L"sato corp", L"oki ",
    L"sharp corp", L"pantum", L"toshiba tec" };
const wchar_t* kNasVendors[] = {
    L"synology", L"qnap", L"western digital", L"buffalo", L"drobo",
    L"terramaster", L"asustor" };
const wchar_t* kNetworkVendors[] = {
    L"mikrotik", L"tp-link", L"netgear", L"d-link", L"zyxel", L"draytek",
    L"cisco", L"aruba", L"ruckus", L"juniper", L"fortinet", L"engenius",
    L"cambium", L"tenda", L"cudy", L"linksys", L"ruijie", L"extreme network",
    L"hewlett packard enterprise" };
const wchar_t* kVoipVendors[] = {
    L"polycom", L"yealink", L"grandstream", L"snom", L"sangoma", L"avaya",
    L"mitel", L"fanvil", L"gigaset", L"audiocodes" };
const wchar_t* kVacuumVendors[] = {
    L"roborock", L"irobot", L"ecovacs", L"neato", L"dreame", L"roidmi" };
const wchar_t* kMediaVendors[] = {
    L"sonos", L"roku", L"harman", L"nintendo", L"sony interactive" };
const wchar_t* kIotVendors[] = {
    L"espressif", L"tuya", L"shelly", L"sonoff", L"itead", L"belkin",
    L"signify", L"philips lighting", L"nest labs", L"google nest", L"ring",
    L"ecobee", L"sengled", L"lifx", L"govee", L"wiz connected", L"sengled" };
const wchar_t* kVmVendors[] = {
    L"vmware", L"virtualbox", L"parallels", L"qemu", L"xensource",
    L"oracle virtual", L"nutanix" };

bool vendorIn(const std::wstring& vendor, const wchar_t* const* list, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (vendor.find(list[i]) != std::wstring::npos) return true;
    return false;
}
template <size_t N>
bool vendorIn(const std::wstring& vendor, const wchar_t* const (&list)[N]) {
    return vendorIn(vendor, list, N);
}

// =============================================================================
// Model extraction
// =============================================================================

// Device classes whose web page genuinely identifies the *device* (its model
// or management product). For a general-purpose host — a Windows PC, a Linux
// box — the web page is just a website it happens to host (e.g. "Welcome to
// XAMPP"), never the machine's model, so we don't pull a model for those.
bool isDeviceCategory(const std::wstring& t) {
    return t == L"Printer" || t == L"IP Camera" || t == L"Router / Gateway" ||
           t == L"Firewall" || t == L"Access Point" || t == L"Network device" ||
           t == L"NAS" || t == L"VoIP phone" || t == L"Media device" ||
           t == L"Robot vacuum" || t == L"IoT / smart home" ||
           t == L"IoT / embedded" || t == L"Hypervisor (ESXi)" ||
           t == L"Hypervisor" || t == L"Server (management)";
}

// True for the management-UI products detectWebApp() promotes into fp.product —
// for those, "<product> <version>" is the model, not the page <title>.
bool isManagementUiProduct(const std::wstring& p) {
    std::wstring lo = toLower(p);
    return hasAny(lo, { L"esxi", L"vsphere", L"proxmox", L"idrac", L"ilo",
                        L"routeros", L"mikrotik", L"pfsense", L"opnsense",
                        L"openwrt", L"synology", L"qnap", L"truenas",
                        L"openmediavault", L"home assistant" });
}

// Strips an IPv4-looking token, the host's own hostname, empty brackets and
// stray separators out of a candidate model string, then length-caps it.
std::wstring cleanModel(std::wstring m, const std::wstring& hostname,
                        const std::wstring& ip) {
    auto removeAll = [&](const std::wstring& needle) {
        if (needle.size() < 3) return;
        std::wstring lo = toLower(m), ln = toLower(needle);
        size_t pos;
        while ((pos = lo.find(ln)) != std::wstring::npos) {
            m.erase(pos, needle.size());
            lo.erase(pos, needle.size());
        }
    };
    if (!ip.empty()) removeAll(ip);
    if (hostname.size() >= 3) {
        removeAll(hostname);
        size_t dot = hostname.find(L'.');               // also the short name
        if (dot != std::wstring::npos && dot >= 3)
            removeAll(hostname.substr(0, dot));
    }
    // Drop any remaining IPv4-shaped run (digits and dots, >= 7 chars, 2+ dots).
    for (size_t i = 0; i < m.size(); ) {
        if (m[i] < L'0' || m[i] > L'9') { ++i; continue; }
        size_t j = i; int dots = 0;
        while (j < m.size() && ((m[j] >= L'0' && m[j] <= L'9') || m[j] == L'.')) {
            if (m[j] == L'.') ++dots;
            ++j;
        }
        if (dots >= 2 && j - i >= 7) { m.erase(i, j - i); }
        else i = j;
    }
    // Collapse whitespace and clean up separators / empty brackets.
    std::wstring out;
    out.reserve(m.size());
    for (wchar_t c : m) {
        if (c == L'\t') c = L' ';
        if (c == L' ' && (out.empty() || out.back() == L' ')) continue;
        out.push_back(c);
    }
    // Remove "()" / "[]" left empty, and trim junk separators from both ends.
    auto strip = [](std::wstring& s) {
        const std::wstring junk = L" -_:|()[]";
        while (!s.empty() && junk.find(s.front()) != std::wstring::npos)
            s.erase(s.begin());
        while (!s.empty() && junk.find(s.back()) != std::wstring::npos)
            s.pop_back();
    };
    size_t e;
    while ((e = out.find(L"()")) != std::wstring::npos) out.erase(e, 2);
    while ((e = out.find(L"[]")) != std::wstring::npos) out.erase(e, 2);
    strip(out);
    if (out.size() > 48) { out.resize(48); strip(out); }
    return out;
}

// Best-effort device model. Empty for host-OS types (a PC has no web "model")
// and for titles that are generic boilerplate or a bare serial/asset code.
std::wstring extractModel(const ScanResult& r, const std::wstring& type) {
    if (!isDeviceCategory(type)) return {};

    // 1) A promoted management-UI product (ESXi, RouterOS, DSM, …) — that, with
    //    its version, *is* the model.
    for (const auto& f : r.fingerprints) {
        if ((f.service == L"http" || f.service == L"https") &&
            isManagementUiProduct(f.product)) {
            std::wstring m = f.product;
            if (!f.version.empty()) m += L" " + f.version;
            return m;
        }
    }

    // 2) Otherwise the cleaned web page <title>.
    static const wchar_t* kGeneric[] = {
        L"login", L"welcome", L"index", L"home", L"home page", L"sign in",
        L"document", L"untitled", L"web", L"admin", L"dashboard", L"error",
        L"page", L"loading", L"redirect", L"please wait", L"welcome to xampp",
        L"xampp", L"it works", L"apache2 ubuntu default page", L"test page",
        L"apache http server test page", L"default web site page",
        L"site under construction", L"coming soon", L"401 unauthorized",
        L"401 authorization required", L"403 forbidden", L"404 not found",
        L"web server", L"setup", L"configuration"
    };
    for (const auto& f : r.fingerprints) {
        if (f.title.empty()) continue;
        std::wstring t = cleanModel(f.title, r.hostname, r.ipAddress);
        if (t.empty()) continue;

        std::wstring lo = toLower(t);
        // Normalise trailing punctuation so "Loading..." / "Login." collapse
        // onto the bare placeholder keyword below — a switch admin SPA whose
        // static title is "Loading..." was otherwise surfaced as the model.
        while (!lo.empty()) {
            wchar_t c = lo.back();
            if (c == L'.' || c == L' ' || c == L'\x2026' || c == L'!'
                || c == L':' || c == L'|')
                lo.pop_back();
            else break;
        }
        bool generic = false;
        for (auto g : kGeneric) if (lo == g) { generic = true; break; }
        if (generic) continue;

        // Skip a numeric-only title and a bare serial/asset code — one token,
        // all uppercase + digits, no spaces (e.g. "ZBR10509331").
        bool numericOnly = true, serialish = (t.size() > 6);
        bool hasSpace = false;
        for (wchar_t c : t) {
            if (c == L' ') hasSpace = true;
            if (!((c >= L'0' && c <= L'9') || c == L'.')) numericOnly = false;
            if (!((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z')))
                serialish = false;
        }
        if (numericOnly) continue;
        if (serialish && !hasSpace) continue;

        return t;
    }
    return {};
}

} // anonymous namespace

// =============================================================================
// classify — ordered, first-match-wins. Specific signals (gateway, the device's
// own web UI, a class-defining vendor) are checked *before* the generic host-OS
// rules, so e.g. a Ubiquiti box that happens to run SSH is an Access Point,
// not just "Linux/Unix host".
// =============================================================================

void DeviceClassifier::classify(ScanResult& r, const std::wstring& gatewayIp) {
    r.deviceType.clear();
    r.deviceModel.clear();
    if (!r.isOnline) return;

    const std::wstring vendor = toLower(r.vendor);
    const std::wstring host   = toLower(r.hostname);
    const std::wstring blob   = gatherBlob(r);
    std::wstring& type = r.deviceType;

    // ---- T0: the default gateway ------------------------------------------
    if (!gatewayIp.empty() && r.ipAddress == gatewayIp)
        type = L"Router / Gateway";

    // ---- T0.5: HPE iLO via its "mpSSH" management-processor SSH banner -----
    // Reliable even over an L3 VPN, where there's no ARP / MAC-OUI vendor and
    // the box would otherwise fall through to "Linux/Unix host" (SSH open).
    if (type.empty()) {
        for (const auto& f : r.fingerprints) {
            std::wstring b = toLower(f.product + L" " + f.version + L" " + f.detail);
            if (b.find(L"mpssh") != std::wstring::npos) {
                type = L"HPE iLO baseboard";
                break;
            }
        }
    }

    // ---- T1: management-UI / product keywords (the device named itself) ----
    if (type.empty()) {
        for (const auto& kt : kKeywordTypes) {
            if (has(blob, kt.keyword)) { type = kt.type; break; }
        }
    }

    // ---- T2: class-defining OUI vendor ------------------------------------
    if (type.empty()) {
        if      (vendorIn(vendor, kCameraVendors))  type = L"IP Camera";
        else if (vendorIn(vendor, kPrinterVendors)) type = L"Printer";
        else if (vendorIn(vendor, kNasVendors))     type = L"NAS";
        else if (vendorIn(vendor, kVacuumVendors))  type = L"Robot vacuum";
        else if (has(vendor, L"ubiquiti") || has(vendor, L"ubnt"))
                                                    type = L"Access Point";
        else if (vendorIn(vendor, kVoipVendors))    type = L"VoIP phone";
        else if (vendorIn(vendor, kMediaVendors))   type = L"Media device";
        else if (vendorIn(vendor, kNetworkVendors)) type = L"Network device";
        else if (vendorIn(vendor, kIotVendors))     type = L"IoT / smart home";
    }

    // ---- T3: open-port profile --------------------------------------------
    if (type.empty()) {
        // 9100 (JetDirect) and 515 (LPR) are printer-exclusive on real
        // networks. 631 (IPP/CUPS) ships on every Linux/Mac with shared
        // printing enabled — gate it on a printer-shape co-signal or
        // skip it entirely here (the SNMP probe + vendor table catches
        // real printers via stronger signals).
        if      (anyPortOpen(r, {9100, 515}))               type = L"Printer";
        else if (portOpen(r, 631) && !portOpen(r, 22))      type = L"Printer";
        else if (portOpen(r, 554))                          type = L"IP Camera";
        else if (anyPortOpen(r, {5060, 5061}))              type = L"VoIP phone";
        else if (anyPortOpen(r, {5000, 5001}) && portOpen(r, 445))
                                                            type = L"NAS";
        else if (anyPortOpen(r, {8009, 32400, 8200}))       type = L"Media device";
    }

    // ---- T3.5: device-ish hostnames ---------------------------------------
    if (type.empty()) {
        if (startsWith(host, L"npi") || startsWith(host, L"brn") ||
            startsWith(host, L"brw") || has(host, L"printer"))
            type = L"Printer";
    }

    // ---- T4: host operating system ----------------------------------------
    if (type.empty()) {
        const bool windowsStack =
            anyPortOpen(r, {445, 139, 135, 3389, 5985, 5986});
        const bool windowsFp = hasFpService(r, L"windows");
        const bool sshFp     = hasFpService(r, L"ssh");

        if (has(vendor, L"apple")) {
            // Prefer the synthesized Apple device-class fingerprint when the
            // mDNS + 62078/7000/3689 probe came back with a confident answer
            // (see ServiceFingerprinter::queryAppleDeviceInfo). It can tell
            // iPhone/iPad from Mac from Apple TV from HomePod, none of which
            // the visible TCP services usually distinguish on their own.
            std::wstring appleProduct;
            for (const auto& fp : r.fingerprints) {
                if (fp.service == L"apple" && !fp.product.empty()) {
                    appleProduct = fp.product;
                    break;
                }
            }
            if      (appleProduct == L"iPhone / iPad")    type = L"Mobile device (iOS)";
            else if (appleProduct == L"Mac")              type = L"Mac";
            else if (appleProduct == L"Apple TV")         type = L"Apple TV";
            else if (appleProduct == L"HomePod")          type = L"HomePod";
            else if (appleProduct == L"AirPlay receiver") type = L"AirPlay receiver";
            else if (!appleProduct.empty())               type = appleProduct;
            else if (portOpen(r, 62078) || has(host, L"iphone") || has(host, L"ipad"))
                type = L"Mobile device (iOS)";
            else
                type = L"Mac";
        }
        else if (has(host, L"android")) {
            type = L"Mobile device (Android)";
        }
        else if (windowsStack || windowsFp ||
                 startsWith(host, L"desktop-") || startsWith(host, L"laptop-")) {
            // `win-` (default WSUS / Server-Core hostname) is intentionally
            // NOT a standalone signal — WinCC SCADA, Wincor-Nixdorf ATMs,
            // generic "win-prod-01" service hosts all collide. If it's
            // really Windows the stack/fingerprint signals will fire.
            type = isWindowsDC(r) ? L"Windows domain controller" : L"Windows PC";
        }
        else if ((portOpen(r, 22) && !windowsStack) || (sshFp && !windowsStack)) {
            type = L"Linux/Unix host";
        }
    }

    // ---- T5: weak fallbacks ------------------------------------------------
    if (type.empty()) {
        if (vendorIn(vendor, kVmVendors)) {
            type = L"Virtual machine";
        } else if (hasAny(blob, { L"goahead", L"mini_httpd", L"thttpd",
                                  L"lighttpd", L"uc-httpd", L"boa", L"embedthis" })) {
            type = L"IoT / embedded";
        }
    }

    if (type.empty()) type = L"Unknown";

    // Model extraction is keyed on the *base* type, so it must run before the
    // "(VM)" tag is appended below — otherwise "Printer (VM)" wouldn't match
    // the isDeviceCategory("Printer") check.
    r.deviceModel = extractModel(r, type);

    // VM modifier — when a hypervisor OUI vendor (VMware / VirtualBox / …) is
    // paired with a detected host type, surface that the host is virtual so
    // VMs read consistently in the table. The "Virtual machine" fallback (used
    // when the guest OS genuinely can't be told from the visible ports) and
    // "Unknown" stay as-is.
    if (type != L"Virtual machine" && type != L"Unknown" &&
        vendorIn(vendor, kVmVendors)) {
        type += L" (VM)";
    }
}

} // namespace lanscope
