#include "VendorPortProfiles.h"

#include <algorithm>
#include <cwctype>
#include <unordered_set>

namespace netlens {

namespace {

std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

// Ordered narrow-first so a more specific family (e.g. MikroTik) wins over a
// generic one (e.g. "enterprise networking") when both could plausibly match.
const std::vector<VendorPortProfile>& allProfiles() {
    static const std::vector<VendorPortProfile> kProfiles = {

        // --- Video surveillance / IP cameras / NVR / DVR ---
        { L"Video surveillance (Dahua, Hikvision, Axis, Hanwha, ...)",
          { L"Dahua", L"Hikvision", L"Axis Communications", L"Hanwha", L"Bosch Security",
            L"Honeywell Vision", L"Pelco", L"Mobotix", L"Avigilon", L"Uniview",
            L"Vivotek", L"Ezviz", L"Tiandy", L"Reolink", L"Amcrest", L"Lorex",
            L"Foscam", L"Geovision", L"ACTi", L"Arlo" },
          { 554, 80, 443, 8000, 8080, 8443, 9000, 37777, 37778, 34567, 8554, 1935, 5000, 5001 } },

        // --- VoIP phones / SIP endpoints ---
        { L"VoIP / IP phone (Polycom, Yealink, Snom, Grandstream, ...)",
          { L"Polycom", L"Yealink", L"Snom", L"Grandstream", L"AudioCodes", L"Avaya",
            L"Mitel", L"Sangoma" },
          { 5060, 5061, 80, 443, 5004, 5005, 16384, 22, 23 } },

        // --- VMware / virtualization hosts ---
        { L"VMware / virtualization host",
          { L"VMware", L"Parallels", L"Citrix Systems" },
          { 443, 902, 903, 5480, 9443, 8000, 80, 22, 3389, 5985, 5986 } },

        // --- MikroTik (Winbox 8291 + API 8728/8729 are the giveaway services) ---
        { L"MikroTik router / switch",
          { L"MikroTik", L"Routerboard" },
          { 8291, 22, 23, 80, 443, 8728, 8729, 21, 53 } },

        // --- Ubiquiti (UniFi controller, EdgeRouter, AmpliFi) ---
        { L"Ubiquiti (UniFi / EdgeRouter / AmpliFi)",
          { L"Ubiquiti" },
          { 22, 80, 443, 8080, 8443, 8843, 8880, 6789 } },

        // --- Cisco enterprise networking gear ---
        { L"Cisco enterprise networking",
          { L"Cisco Systems", L"Cisco Tech", L"Cisco-Linksys" },
          { 22, 23, 80, 443, 161, 8443, 8080, 9443 } },

        // --- Juniper / Aruba / HPE / Arista / Extreme / Brocade ---
        { L"Enterprise networking (Juniper, Aruba, Extreme, Arista, ...)",
          { L"Juniper", L"Aruba", L"Extreme Networks", L"Brocade", L"Arista" },
          { 22, 23, 80, 443, 161, 8443, 9443 } },

        // --- NAS appliances ---
        { L"NAS storage (Synology, QNAP, Drobo, WD, Buffalo)",
          { L"Synology", L"QNAP", L"Drobo", L"Buffalo", L"Western Digital", L"WDC",
            L"Netgear ReadyNAS", L"Iomega", L"Thecus", L"Asustor" },
          { 5000, 5001, 8080, 8443, 80, 443, 22, 21, 137, 138, 139, 445, 548, 2049, 8200, 9000 } },

        // --- Network printers / MFPs ---
        { L"Network printer / MFP",
          { L"Hewlett Packard", L"HP Inc", L"Canon", L"Brother", L"Seiko Epson", L"EPSON",
            L"Xerox", L"Konica Minolta", L"Kyocera", L"Ricoh", L"Lexmark", L"Sharp",
            L"OKI Electric", L"Zebra Tech", L"Toshiba TEC" },
          { 9100, 631, 515, 80, 443, 21, 8080, 161, 23 } },

        // --- Server BMC (iDRAC / iLO / IPMI / IMM) ---
        { L"Server BMC / out-of-band (iDRAC, iLO, IPMI, IMM)",
          { L"Dell EMC", L"Dell Inc", L"Hewlett Packard Enterprise", L"HPE", L"Supermicro",
            L"Super Micro", L"Lenovo", L"IBM Corp" },
          { 22, 80, 443, 623, 5900, 5901, 17988, 2381, 161, 3389, 5985, 5986 } },

        // --- Apple devices ---
        { L"Apple device (Mac / iPhone / iPad / Apple TV)",
          { L"Apple, Inc", L"Apple Inc", L"Apple Operations" },
          { 22, 80, 443, 88, 548, 5353, 7000, 49152, 62078 } },

        // --- Smart-home / streaming / IoT consumer ---
        { L"Smart-home / IoT (Sonos, Chromecast, Roku, Nest, Hue, ...)",
          { L"Sonos", L"Google, Inc", L"Roku", L"Nest Labs", L"Ring LLC", L"Philips Lighting",
            L"Signify", L"Amazon Tech", L"Wyze", L"TP-Link Smart", L"Tuya Smart" },
          { 80, 443, 1400, 1410, 1443, 5353, 8008, 8009, 8060, 1900 } },

        // --- Consumer routers / WiFi APs ---
        { L"Consumer router / AP (TP-Link, Netgear, ASUS, D-Link, ...)",
          { L"TP-Link", L"Tp-Link", L"Netgear", L"ASUSTek", L"D-Link", L"Belkin", L"Linksys",
            L"Tenda", L"Huawei Device", L"Zyxel", L"Mercusys", L"Totolink" },
          { 22, 23, 53, 80, 443, 1900, 5000, 8080, 8443 } },

        // --- ICS / SCADA / building automation ---
        { L"Industrial / SCADA (Siemens, Schneider, Rockwell, ...)",
          { L"Siemens", L"Schneider Electric", L"Rockwell Automation", L"Allen-Bradley",
            L"Honeywell Industrial", L"ABB", L"Yokogawa", L"Beckhoff", L"Phoenix Contact",
            L"Mitsubishi Electric" },
          { 102, 502, 47808, 22, 80, 443, 20000, 44818 } },

        // --- Embedded / dev boards ---
        { L"Embedded / dev board (Raspberry Pi, ESP32, Arduino, ...)",
          { L"Raspberry Pi", L"Espressif", L"Arduino", L"Particle Industries", L"BeagleBoard" },
          { 22, 80, 443, 8080, 5900, 1883, 8883, 8888 } },

        // --- Microsoft (Windows server / Hyper-V / Surface / Xbox NIC OUIs) ---
        { L"Microsoft device (Windows host / Hyper-V / Surface / Xbox)",
          { L"Microsoft Corp", L"Microsoft Mobile" },
          { 135, 139, 445, 3389, 5985, 5986, 80, 443, 53, 88, 389, 636, 3268, 3269 } },

        // --- Hypervisor virtual NIC OUIs (PCS / Innotek = VirtualBox, etc.) ---
        { L"Hypervisor virtual NIC (VirtualBox, Hyper-V, QEMU, Xen)",
          { L"PCS Systemtechnik", L"Cadmus Computer", L"Xen Source", L"QEMU", L"Innotek" },
          { 22, 80, 443, 3389, 5900, 5985, 5986, 902 } },
    };
    return kProfiles;
}

} // anonymous namespace

const VendorPortProfile* VendorPortProfiles::match(const std::wstring& vendor) {
    if (vendor.empty()) return nullptr;
    const auto vlower = toLower(vendor);
    for (const auto& p : allProfiles()) {
        for (const auto& needle : p.matchers) {
            if (vlower.find(toLower(needle)) != std::wstring::npos) {
                return &p;
            }
        }
    }
    return nullptr;
}

const std::vector<VendorPortProfile>& VendorPortProfiles::profiles() {
    return allProfiles();
}

std::vector<int> VendorPortProfiles::mergePorts(const std::vector<int>& priority,
                                                 const std::vector<int>& userPorts) {
    std::vector<int> out;
    std::unordered_set<int> seen;
    out.reserve(priority.size() + userPorts.size());
    for (int p : priority) {
        if (p >= 1 && p <= 65535 && seen.insert(p).second) out.push_back(p);
    }
    for (int p : userPorts) {
        if (p >= 1 && p <= 65535 && seen.insert(p).second) out.push_back(p);
    }
    return out;
}

} // namespace netlens
