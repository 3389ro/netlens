// MockData.cpp -- curated 15-host demo fleet (hand-maintained).
//
// Backs `NetLens.exe --mock`: feeds a 15-host fleet straight into App's host
// vector and serves an embedded HTML report for the Export HTML button.

#include "MockData.h"

namespace nl::mock {

std::vector<HostRow> BuildHosts() {
    std::vector<HostRow> hosts;
    hosts.reserve(15);

    {
        // 192.168.1.1 -- MikroTik router
        HostRow h;
        h.engineIndex   = 0;
        h.ipV4          = 0xC0A80101;
        h.ip            = L"192.168.1.1";
        h.hostname      = L"ROUTER-01";
        h.vendor        = L"MikroTik";
        h.mac           = L"4C-5E-0C-00-01-01";
        h.deviceType    = L"MikroTik router";
        h.deviceModel   = L"RouterOS 7.13";
        h.openPorts     = L"22, 80, 443, 8291";
        h.services      = L"SSH, HTTP, HTTPS, WinBox";
        h.brandHint     = L"22/tcp ssh: MikroTik RouterOS 7.13\n80: MikroTik Webfig\n443: MikroTik Webfig HTTPS\n8291: MikroTik WinBox";
        h.webUiModel    = L"HTTP title: RouterOS";
        h.udpDiscovery  = L"123 NTP \x2014 stratum 2, ref MikroTik\n53 DNS \x2014 Domain Name Server";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 4;
        h.serviceCount  = 4;
        h.firstOpenPort = 22;
        { PortRow pr; pr.port = 22; pr.isOpen = true; pr.service = L"ssh"; pr.product = L"MikroTik RouterOS"; pr.version = L"7.13"; pr.detail = L"SSH-2.0-ROSSSH"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L"MikroTik Webfig"; pr.version = L""; pr.detail = L"HTTP title: RouterOS"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L"MikroTik Webfig"; pr.version = L""; pr.detail = L"HTTPS + HTTP title: RouterOS"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8291; pr.isOpen = true; pr.service = L"winbox"; pr.product = L"MikroTik WinBox"; pr.version = L""; pr.detail = L"Native config protocol"; h.ports.push_back(std::move(pr)); }
        { SecurityFinding sfRow; sfRow.severity = FindingSeverity::Critical; sfRow.id = L"CVE-2018-14847"; sfRow.title = L"MikroTik RouterOS WinBox path traversal -- credential database read (pre-auth, port 8291)"; sfRow.url = L"https://nvd.nist.gov/vuln/detail/CVE-2018-14847"; h.findings.push_back(std::move(sfRow)); }
        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.5 -- UniFi gateway
        HostRow h;
        h.engineIndex   = 1;
        h.ipV4          = 0xC0A80105;
        h.ip            = L"192.168.1.5";
        h.hostname      = L"GATEWAY-01";
        h.vendor        = L"Ubiquiti";
        h.mac           = L"24-A4-3C-00-02-01";
        h.deviceType    = L"UniFi gateway";
        h.deviceModel   = L"UniFi Dream Machine Pro";
        h.openPorts     = L"22, 80, 443, 8080";
        h.services      = L"SSH, HTTP, HTTPS, HTTP-alt";
        h.brandHint     = L"22/tcp ssh: OpenSSH 8.4p1 Ubiquiti\n443: UniFi OS 3.2";
        h.webUiModel    = L"HTTP title: UniFi OS";
        h.udpDiscovery  = L"53 DNS \x2014 Domain Name Server";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 4;
        h.serviceCount  = 4;
        h.firstOpenPort = 22;
        { PortRow pr; pr.port = 22; pr.isOpen = true; pr.service = L"ssh"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8080; pr.isOpen = true; pr.service = L"http-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.10 -- HPE iLO baseboard
        HostRow h;
        h.engineIndex   = 2;
        h.ipV4          = 0xC0A8010A;
        h.ip            = L"192.168.1.10";
        h.hostname      = L"ilo-primary";
        h.vendor        = L"HPE";
        h.mac           = L"EC-1C-7B-00-03-01";
        h.deviceType    = L"HPE iLO baseboard";
        h.deviceModel   = L"iLO 5";
        h.openPorts     = L"80, 443, 17988";
        h.services      = L"HTTP, HTTPS, iLO Virtual Media";
        h.brandHint     = L"443: HPE iLO 5 / Server: HPE-iLO-Server\n17988: iLO Virtual Media";
        h.webUiModel    = L"HTTP title: iLO 5";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 2;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 3;
        h.serviceCount  = 3;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 17988; pr.isOpen = true; pr.service = L"ilo-vm"; pr.product = L"HPE iLO Virtual Media"; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.11 -- Dell iDRAC baseboard
        HostRow h;
        h.engineIndex   = 3;
        h.ipV4          = 0xC0A8010B;
        h.ip            = L"192.168.1.11";
        h.hostname      = L"idrac-db01";
        h.vendor        = L"Dell";
        h.mac           = L"84-2B-2B-00-04-01";
        h.deviceType    = L"Dell iDRAC baseboard";
        h.deviceModel   = L"iDRAC 9";
        h.openPorts     = L"80, 443, 5900, 5901";
        h.services      = L"HTTP, HTTPS, VNC, VNC-1";
        h.brandHint     = L"443: Dell iDRAC 9 / 6.10.00\n5900: Dell iDRAC vConsole (RFB 003.008)";
        h.webUiModel    = L"HTTP title: Integrated Dell Remote Access Controller 9";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 2;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 4;
        h.serviceCount  = 4;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 5900; pr.isOpen = true; pr.service = L"vnc"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 5901; pr.isOpen = true; pr.service = L"vnc"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.20 -- VMware ESXi 6.7
        HostRow h;
        h.engineIndex   = 4;
        h.ipV4          = 0xC0A80114;
        h.ip            = L"192.168.1.20";
        h.hostname      = L"esx-01";
        h.vendor        = L"VMware";
        h.mac           = L"00-50-56-00-05-01";
        h.deviceType    = L"VMware ESXi 6.7";
        h.deviceModel   = L"ESXi 6.7.0";
        h.openPorts     = L"80, 443, 902, 8000, 8100, 8443";
        h.services      = L"HTTP, HTTPS, VMware-auth, VM HBR, VM mig, HTTPS-alt";
        h.brandHint     = L"443: VMware ESXi 6.7.0 (general availability past end-of-support Oct 2022)\n902/tcp vsphere: vim25=6.7.0";
        h.webUiModel    = L"HTTP title: VMware ESXi";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 6;
        h.serviceCount  = 6;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L"VMware ESXi"; pr.version = L"6.7.0"; pr.detail = L"HTTP title: VMware ESXi; build 6.7.0-20842708"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 902; pr.isOpen = true; pr.service = L"vsphere"; pr.product = L"VMware vSphere authd"; pr.version = L"6.7.0"; pr.detail = L"vim25=6.7.0"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8000; pr.isOpen = true; pr.service = L"http-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8100; pr.isOpen = true; pr.service = L"vm-mig"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8443; pr.isOpen = true; pr.service = L"https-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { SecurityFinding sfRow; sfRow.severity = FindingSeverity::Critical; sfRow.id = L"CVE-2021-21974"; sfRow.title = L"VMware ESXi 6.x/7.0 -- OpenSLP heap overflow pre-auth RCE (ransomware vector, port 427)"; sfRow.url = L"https://nvd.nist.gov/vuln/detail/CVE-2021-21974"; h.findings.push_back(std::move(sfRow)); }
        { SecurityFinding sfRow; sfRow.severity = FindingSeverity::High; sfRow.id = L"EOL-ESXi-6.7"; sfRow.title = L"VMware ESXi 6.7 -- general end-of-support October 2022; no further security patches"; sfRow.url = L"https://blogs.vmware.com/vsphere/2022/10/announcing-extended-general-support-for-vsphere-6-7.html"; h.findings.push_back(std::move(sfRow)); }
        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.21 -- VMware ESXi 7.0
        HostRow h;
        h.engineIndex   = 5;
        h.ipV4          = 0xC0A80115;
        h.ip            = L"192.168.1.21";
        h.hostname      = L"esx-02";
        h.vendor        = L"VMware";
        h.mac           = L"00-50-56-00-05-02";
        h.deviceType    = L"VMware ESXi 7.0";
        h.deviceModel   = L"ESXi 7.0.3";
        h.openPorts     = L"80, 443, 902, 8000, 8100, 8443";
        h.services      = L"HTTP, HTTPS, VMware-auth, VM HBR, VM mig, HTTPS-alt";
        h.brandHint     = L"443: VMware ESXi 7.0.3 (Update 3 - mainstream EoS April 2025)\n902/tcp vsphere: vim25=7.0.3";
        h.webUiModel    = L"HTTP title: VMware ESXi";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 6;
        h.serviceCount  = 6;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L"VMware ESXi"; pr.version = L"7.0.3"; pr.detail = L"HTTP title: VMware ESXi; Update 3"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 902; pr.isOpen = true; pr.service = L"vsphere"; pr.product = L"VMware vSphere authd"; pr.version = L"7.0.3"; pr.detail = L"vim25=7.0.3"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8000; pr.isOpen = true; pr.service = L"http-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8100; pr.isOpen = true; pr.service = L"vm-mig"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8443; pr.isOpen = true; pr.service = L"https-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { SecurityFinding sfRow; sfRow.severity = FindingSeverity::Critical; sfRow.id = L"CVE-2021-21974"; sfRow.title = L"VMware ESXi 6.x/7.0 -- OpenSLP heap overflow pre-auth RCE (ransomware vector, port 427)"; sfRow.url = L"https://nvd.nist.gov/vuln/detail/CVE-2021-21974"; h.findings.push_back(std::move(sfRow)); }
        { SecurityFinding sfRow; sfRow.severity = FindingSeverity::Medium; sfRow.id = L"EOL-ESXi-7.0"; sfRow.title = L"VMware ESXi 7.0 -- general support ended April 2025; transition planning required"; sfRow.url = L"https://www.vmware.com/info/lifecycle-policy"; h.findings.push_back(std::move(sfRow)); }
        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.22 -- VMware ESXi 8.0
        HostRow h;
        h.engineIndex   = 6;
        h.ipV4          = 0xC0A80116;
        h.ip            = L"192.168.1.22";
        h.hostname      = L"esx-03";
        h.vendor        = L"VMware";
        h.mac           = L"00-50-56-00-05-03";
        h.deviceType    = L"VMware ESXi 8.0";
        h.deviceModel   = L"ESXi 8.0.2";
        h.openPorts     = L"80, 443, 902, 8000, 8100, 8443";
        h.services      = L"HTTP, HTTPS, VMware-auth, VM HBR, VM mig, HTTPS-alt";
        h.brandHint     = L"443: VMware ESXi 8.0.2 (Update 2 - mainstream support active)\n902/tcp vsphere: vim25=8.0.2";
        h.webUiModel    = L"HTTP title: VMware ESXi";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 6;
        h.serviceCount  = 6;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L"VMware ESXi"; pr.version = L"8.0.2"; pr.detail = L"HTTP title: VMware ESXi; Update 2"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 902; pr.isOpen = true; pr.service = L"vsphere"; pr.product = L"VMware vSphere authd"; pr.version = L"8.0.2"; pr.detail = L"vim25=8.0.2"; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8000; pr.isOpen = true; pr.service = L"http-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8100; pr.isOpen = true; pr.service = L"vm-mig"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8443; pr.isOpen = true; pr.service = L"https-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.30 -- NAS
        HostRow h;
        h.engineIndex   = 7;
        h.ipV4          = 0xC0A8011E;
        h.ip            = L"192.168.1.30";
        h.hostname      = L"NAS-01";
        h.vendor        = L"Synology";
        h.mac           = L"00-11-32-00-06-01";
        h.deviceType    = L"NAS";
        h.deviceModel   = L"DiskStation DS920+";
        h.openPorts     = L"80, 139, 443, 445, 548, 5357";
        h.services      = L"HTTP, NetBIOS-SSN, HTTPS, SMB, AFP, WSDAPI";
        h.brandHint     = L"80/443: Synology DSM 7.2 (nginx)\n445: Samba 4.15 (Linux/Samba)";
        h.webUiModel    = L"HTTP title: Synology DiskStation";
        h.udpDiscovery  = L"137 NBNS \x2014 NAS-01\\\\WORKGROUP\n1900 SSDP \x2014 Synology/DSM/192.168.1.30\n5353 mDNS \x2014 _smb._tcp, _afpovertcp._tcp";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 6;
        h.serviceCount  = 6;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 139; pr.isOpen = true; pr.service = L"netbios-ssn"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 445; pr.isOpen = true; pr.service = L"smb"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 548; pr.isOpen = true; pr.service = L"afp"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 5357; pr.isOpen = true; pr.service = L"wsdapi"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.40 -- Printer
        HostRow h;
        h.engineIndex   = 8;
        h.ipV4          = 0xC0A80128;
        h.ip            = L"192.168.1.40";
        h.hostname      = L"PRINTER-01";
        h.vendor        = L"HP";
        h.mac           = L"C8-D9-D2-00-07-01";
        h.deviceType    = L"Printer";
        h.deviceModel   = L"HP Color LaserJet MFP M477fnw";
        h.openPorts     = L"80, 443, 515, 631, 9100";
        h.services      = L"HTTP, HTTPS, LPR, IPP, JetDirect";
        h.brandHint     = L"80/443: HP EWS / HP Color LaserJet MFP M477fnw\n9100: HP JetDirect";
        h.webUiModel    = L"HTTP title: HP Color LaserJet MFP M477fnw";
        h.udpDiscovery  = L"137 NBNS \x2014 PRINTER-01\\\\WORKGROUP\n5353 mDNS \x2014 _ipp._tcp, _printer._tcp";
        h.isOnline      = true;
        h.responseMs    = 2;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 5;
        h.serviceCount  = 5;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 515; pr.isOpen = true; pr.service = L"lpr"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 631; pr.isOpen = true; pr.service = L"ipp"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 9100; pr.isOpen = true; pr.service = L"jetdirect"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.50 -- IP Camera
        HostRow h;
        h.engineIndex   = 9;
        h.ipV4          = 0xC0A80132;
        h.ip            = L"192.168.1.50";
        h.hostname      = L"CAM-01";
        h.vendor        = L"Hikvision";
        h.mac           = L"28-57-BE-00-08-01";
        h.deviceType    = L"IP Camera";
        h.openPorts     = L"80, 443, 554, 8000";
        h.services      = L"HTTP, HTTPS, RTSP, HTTP-alt";
        h.brandHint     = L"80: Hikvision Web (App-webs/)\n554: Hikvision RTSP";
        h.webUiModel    = L"HTTP title: Hikvision";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 3;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 4;
        h.serviceCount  = 4;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 554; pr.isOpen = true; pr.service = L"rtsp"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8000; pr.isOpen = true; pr.service = L"http-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { SecurityFinding sfRow; sfRow.severity = FindingSeverity::Critical; sfRow.id = L"CVE-2017-7921"; sfRow.title = L"Hikvision IP camera reachable on HTTP -- check firmware for CVE-2017-7921 auth bypass (credential disclosure)"; sfRow.url = L"https://nvd.nist.gov/vuln/detail/CVE-2017-7921"; h.findings.push_back(std::move(sfRow)); }
        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.51 -- IP Camera
        HostRow h;
        h.engineIndex   = 10;
        h.ipV4          = 0xC0A80133;
        h.ip            = L"192.168.1.51";
        h.hostname      = L"CAM-02";
        h.vendor        = L"Sony";
        h.mac           = L"00-25-E1-00-08-02";
        h.deviceType    = L"IP Camera";
        h.openPorts     = L"80, 443, 554";
        h.services      = L"HTTP, HTTPS, RTSP";
        h.brandHint     = L"80: Sony IPELA (Server: Sony)\n554: Sony RTSP";
        h.webUiModel    = L"HTTP title: Sony Network Camera";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 3;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 3;
        h.serviceCount  = 3;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 554; pr.isOpen = true; pr.service = L"rtsp"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.100 -- Ubiquiti mFi (sensor)
        HostRow h;
        h.engineIndex   = 11;
        h.ipV4          = 0xC0A80164;
        h.ip            = L"192.168.1.100";
        h.hostname      = L"";
        h.vendor        = L"Ubiquiti";
        h.mac           = L"04-18-D6-00-09-01";
        h.deviceType    = L"Ubiquiti mFi (sensor)";
        h.openPorts     = L"22, 80, 443, 6080";
        h.services      = L"SSH, HTTP, HTTPS, mFi";
        h.brandHint     = L"22: dropbear 2020.81\n443: Ubiquiti mFi (HTTP title: mFi - Ubiquiti Networks)";
        h.webUiModel    = L"HTTP title: mFi - Ubiquiti Networks";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 2;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 4;
        h.serviceCount  = 4;
        h.firstOpenPort = 22;
        { PortRow pr; pr.port = 22; pr.isOpen = true; pr.service = L"ssh"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 443; pr.isOpen = true; pr.service = L"https"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 6080; pr.isOpen = true; pr.service = L"mfi"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.120 -- Apple iPhone / iPad
        HostRow h;
        h.engineIndex   = 12;
        h.ipV4          = 0xC0A80178;
        h.ip            = L"192.168.1.120";
        h.hostname      = L"";
        h.vendor        = L"Apple";
        h.mac           = L"F0-18-98-00-0A-01";
        h.deviceType    = L"Apple iPhone / iPad";
        h.openPorts     = L"62078";
        h.services      = L"iPhone lockdown";
        h.brandHint     = L"62078: lockdownd (Apple mDNS + TCP probes)";
        h.webUiModel    = L"";
        h.udpDiscovery  = L"5353 mDNS \x2014 _apple-mobdev2._tcp, _airplay._tcp";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 1;
        h.serviceCount  = 1;
        h.firstOpenPort = 62078;
        { PortRow pr; pr.port = 62078; pr.isOpen = true; pr.service = L"lockdown"; pr.product = L"Apple iPhone / iPad"; pr.version = L""; pr.detail = L"lockdownd"; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.130 -- Daikin AC (Wi-Fi)
        HostRow h;
        h.engineIndex   = 13;
        h.ipV4          = 0xC0A80182;
        h.ip            = L"192.168.1.130";
        h.hostname      = L"daikinap-01";
        h.vendor        = L"AzureWave";
        h.mac           = L"D0-C5-D3-00-0B-01";
        h.deviceType    = L"Daikin AC (Wi-Fi)";
        h.openPorts     = L"80";
        h.services      = L"HTTP";
        h.brandHint     = L"80: HTTP/1.0 200 OK";
        h.webUiModel    = L"";
        h.udpDiscovery  = L"5353 mDNS \x2014 _daikin._tcp";
        h.isOnline      = true;
        h.responseMs    = 5;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 1;
        h.serviceCount  = 1;
        h.firstOpenPort = 80;
        { PortRow pr; pr.port = 80; pr.isOpen = true; pr.service = L"http"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }
    {
        // 192.168.1.185 -- UniFi AP
        HostRow h;
        h.engineIndex   = 14;
        h.ipV4          = 0xC0A801B9;
        h.ip            = L"192.168.1.185";
        h.hostname      = L"";
        h.vendor        = L"Ubiquiti";
        h.mac           = L"78-8A-20-00-0C-01";
        h.deviceType    = L"UniFi AP";
        h.deviceModel   = L"UniFi AP AC Pro";
        h.openPorts     = L"22, 8080";
        h.services      = L"SSH, HTTP-alt";
        h.brandHint     = L"22: dropbear 2020.81\n8080: UniFi AP (HTTP title: UniFi)";
        h.webUiModel    = L"HTTP title: UniFi";
        h.udpDiscovery  = L"";
        h.isOnline      = true;
        h.responseMs    = 1;
        h.discovery     = DiscoveryMethod::ArpIcmp;
        h.portCount     = 2;
        h.serviceCount  = 2;
        h.firstOpenPort = 22;
        { PortRow pr; pr.port = 22; pr.isOpen = true; pr.service = L"ssh"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }
        { PortRow pr; pr.port = 8080; pr.isOpen = true; pr.service = L"http-alt"; pr.product = L""; pr.version = L""; pr.detail = L""; h.ports.push_back(std::move(pr)); }

        hosts.push_back(std::move(h));
    }

    return hosts;
}

ScanStats BuildStats() {
    ScanStats s;
    s.totalScanned          = 254;
    s.onlineCount           = 15;
    s.offlineCount          = 239;
    s.durationMs            = 13500;
    s.progressDone          = 254;
    s.progressTotal         = 254;
    s.probesDone            = 58674;
    s.probesTotalEstimate   = 58674;
    s.isScanning            = false;
    s.progress01            = 1.0f;
    s.statusText            = L"Done";
    s.recentHostsPerSec     = 0.0;
    s.hasRecentRate         = false;
    s.recentProbesPerSec    = 0.0;
    return s;
}

namespace {
// UTF-8 -- mirrors the engine's exportHtml output for the mock fleet.
constexpr char kHtml[] = R"NETLENS(<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>NetLens - Scan Report</title><style>
* { box-sizing: border-box; }
body { margin:0; font-family: 'Segoe UI', Tahoma, Arial, sans-serif; font-size:14px;
       color:#1f2937; background:#f3f4f6; }
header.app-header { background:#1e3a8a; color:#fff; padding:24px 32px; }
header.app-header h1 { margin:0; font-size:22px; font-weight:600; }
header.app-header .subtitle { opacity:.85; margin-top:4px; font-size:13px; }
header.app-header .meta { margin-top:14px; display:flex; flex-wrap:wrap; gap:24px;
                          font-size:13px; opacity:.92; }
header.app-header .meta .label { opacity:.7; margin-right:4px; }
.summary { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px,1fr));
           gap:12px; padding:20px 32px 0; }
.card { background:#fff; border-radius:8px; padding:16px;
        box-shadow:0 1px 2px rgba(0,0,0,.05); border-left:4px solid #94a3b8; }
.card.total   { border-left-color:#1e3a8a; }
.card.online  { border-left-color:#10b981; }
.card.offline { border-left-color:#9ca3af; }
.card.high    { border-left-color:#dc2626; }
.card.rdp     { border-left-color:#dc2626; }
.card.smb     { border-left-color:#dc2626; }
.card.web     { border-left-color:#2563eb; }
.card.duration{ border-left-color:#6b7280; }
.card-value { font-size:24px; font-weight:700; }
.card-label { font-size:12px; text-transform:uppercase; color:#6b7280;
              letter-spacing:.04em; margin-top:4px; }
section.results { padding:20px 32px; }
section.results h2 { margin:8px 0 12px 0; font-size:16px; }
table { width:100%; border-collapse:collapse; background:#fff; border-radius:8px;
        overflow:hidden; box-shadow:0 1px 2px rgba(0,0,0,.05); font-size:13px; }
thead th { background:#f9fafb; text-align:left; font-weight:600; color:#374151;
           padding:10px 12px; border-bottom:1px solid #e5e7eb; white-space:nowrap; }
tbody td { padding:8px 12px; border-bottom:1px solid #f3f4f6; vertical-align:top; }
tbody tr:last-child td { border-bottom:0; }
tbody tr.row-offline td { color:#9ca3af; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
td.ip, td.mac { font-family: Consolas,'Courier New',monospace; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px;
         font-weight:600; text-transform:uppercase; letter-spacing:.04em; }
.badge-online  { background:#d1fae5; color:#065f46; }
.badge-offline { background:#e5e7eb; color:#4b5563; }
.risk { display:inline-block; padding:3px 9px; border-radius:4px; font-size:11px;
        font-weight:600; text-transform:uppercase; letter-spacing:.04em; }
.risk-none   { background:#f3f4f6; color:#6b7280; }
.risk-low    { background:#dbeafe; color:#1e40af; }
.risk-medium { background:#fef3c7; color:#92400e; }
.risk-high   { background:#fee2e2; color:#991b1b; }
.hints span.h { display:inline-block; padding:2px 8px; border-radius:4px;
                margin-right:4px; margin-bottom:2px; font-size:11px;
                background:#f3f4f6; color:#374151; white-space:nowrap; }
.hints span.h.high   { background:#fee2e2; color:#991b1b; font-weight:600; }
.hints span.h.web    { background:#dbeafe; color:#1e40af; }
.hints span.h.muted  { background:#f3f4f6; color:#6b7280; }
section.legend { padding:0 32px 24px; color:#4b5563; font-size:13px; }
section.legend .row { display:flex; gap:24px; flex-wrap:wrap; align-items:center;
                      margin-top:8px; }
section.legend .row .swatch { display:inline-block; padding:2px 9px; border-radius:4px;
                              font-size:11px; font-weight:600; margin-right:6px;
                              text-transform:uppercase; letter-spacing:.04em; }
section.notes { padding:0 32px 24px; color:#4b5563; font-size:13px; }
section.notes p { background:#fff; border-left:4px solid #fbbf24; padding:12px 16px;
                  margin:0; border-radius:6px; }
.scan-banner { margin:0 32px; padding:14px 18px; border-radius:8px;
               background:#fef3c7; color:#92400e; border-left:6px solid #d97706;
               font-size:14px; font-weight:600; margin-top:18px; }
.scan-banner .small { display:block; font-weight:400; font-size:12.5px;
                      margin-top:4px; color:#78350f; }
.status-completed { color:#10b981; font-weight:600; }
.status-cancelled { color:#fbbf24; font-weight:600; }
section.fingerprints { padding:8px 32px 4px; }
section.fingerprints h2 { margin:8px 0 4px 0; font-size:16px; }
.fp-note { color:#4b5563; font-size:12.5px; margin:0 0 14px 0;
           background:#fff; border-left:4px solid #94a3b8; padding:10px 14px;
           border-radius:6px; }
.fp-host { background:#fff; border-radius:8px; margin-bottom:14px;
           overflow:hidden; box-shadow:0 1px 2px rgba(0,0,0,.05); }
.fp-host-head { padding:9px 14px; background:#f9fafb;
                border-bottom:1px solid #e5e7eb; font-weight:600; }
.fp-host-head .ip { font-family:Consolas,'Courier New',monospace; }
.fp-host-head .hn { color:#6b7280; font-weight:400; margin-left:10px; }
table.fp-table { box-shadow:none; border-radius:0; }
table.fp-table th { font-size:12px; }
table.fp-table td { font-size:12.5px; word-break:break-word; }
table.fp-table td.conf-high   { color:#065f46; font-weight:600; }
table.fp-table td.conf-medium { color:#92400e; }
table.fp-table td.conf-low    { color:#6b7280; }
.fp-empty { color:#6b7280; font-size:13px; background:#fff; border-radius:8px;
            padding:14px; box-shadow:0 1px 2px rgba(0,0,0,.05); }
section.devices { padding:14px 32px 0; }
section.devices h2 { margin:8px 0 10px 0; font-size:16px; }
.dev-row { display:flex; flex-wrap:wrap; gap:8px; }
.dev-chip { background:#fff; border:1px solid #e5e7eb; border-radius:14px;
            padding:5px 12px; font-size:12.5px; color:#374151;
            box-shadow:0 1px 2px rgba(0,0,0,.04); }
.dev-chip b { color:#1e3a8a; }
footer { text-align:center; padding:18px; color:#6b7280; font-size:12px; }
p.hidden-note { padding:8px 32px 0; margin:0; color:#6b7280;
                font-size:12.5px; font-style:italic; }
section.results h2, section.fingerprints h2, section.devices h2,
section.printers h2, section.udp h2 {
    margin:24px 0 12px 0; font-size:15px; font-weight:600;
    color:#1e3a8a; letter-spacing:.01em;
}
section.results h2::before,
section.printers h2::before,
section.udp h2::before,
section.fingerprints h2::before,
section.devices h2::before {
    content:""; display:inline-block; width:3px; height:14px;
    background:#1e3a8a; border-radius:2px; margin-right:8px;
    vertical-align:-2px;
}
td.num { white-space:nowrap; }
td.num .unit { color:#6b7280; font-size:11px; font-weight:400; }
td.num .disc { display:block; color:#9ca3af; font-size:10.5px;
               font-weight:400; text-transform:lowercase; margin-top:1px; }
td.num .muted { color:#cbd5e1; }
section.printers { padding:8px 32px 4px; }
.printer-card { background:#fff; border-radius:8px; margin-bottom:14px;
                box-shadow:0 1px 2px rgba(0,0,0,.05); overflow:hidden; }
.printer-head { padding:10px 14px; background:#f9fafb;
                border-bottom:1px solid #e5e7eb; }
.printer-head .ip { font-family:Consolas,'Courier New',monospace; font-weight:600; }
.printer-head .hn { color:#6b7280; margin-left:10px; }
.printer-meta { margin-top:6px; display:flex; flex-wrap:wrap; gap:18px;
                font-size:12.5px; color:#374151; }
.printer-meta b { color:#6b7280; font-weight:500; margin-right:4px;
                  font-size:11px; text-transform:uppercase;
                  letter-spacing:.04em; }
table.supplies { box-shadow:none; border-radius:0; }
table.supplies th { font-size:12px; }
table.supplies td.sup-color { font-weight:600; width:120px; }
table.supplies td.sup-color.sup-black   { color:#0f172a; }
table.supplies td.sup-color.sup-cyan    { color:#0891b2; }
table.supplies td.sup-color.sup-magenta { color:#be185d; }
table.supplies td.sup-color.sup-yellow  { col)NETLENS"
    R"NETLENS(or:#a16207; }
table.supplies td.sup-color.sup-drum    { color:#7c3aed; }
table.supplies td.sup-color.sup-waste   { color:#6b7280; }
table.supplies td.sup-bar { width:240px; }
table.supplies .bar-wrap { display:inline-block; width:160px; height:8px;
                           background:#e5e7eb; border-radius:4px;
                           vertical-align:middle; overflow:hidden; }
table.supplies .bar      { height:8px; border-radius:4px; }
table.supplies .sup-pct  { display:inline-block; width:46px;
                           margin-left:10px; text-align:right;
                           font-variant-numeric:tabular-nums;
                           color:#374151; font-weight:500; }
table.supplies .sup-desc { color:#6b7280; font-size:12.5px; }
.sup-empty { color:#6b7280; padding:12px 14px; font-size:13px; margin:0; }
section.udp { padding:8px 32px 4px; }
.udp-card { background:#fff; border-radius:8px; margin-bottom:14px;
            box-shadow:0 1px 2px rgba(0,0,0,.05); overflow:hidden; }
.udp-head { padding:10px 14px; background:#f9fafb;
            border-bottom:1px solid #e5e7eb; font-weight:600; }
.udp-head .ip { font-family:Consolas,'Courier New',monospace; }
.udp-head .hn { color:#6b7280; font-weight:400; margin-left:10px; }
table.udp-table { box-shadow:none; border-radius:0; }
table.udp-table th { font-size:12px; }
table.udp-table td.port { font-family:Consolas,'Courier New',monospace;
                          width:60px; color:#6b7280;
                          font-variant-numeric:tabular-nums; }
table.udp-table td.svc  { width:130px; font-weight:600; color:#1e3a8a; }
table.udp-table td.detail { color:#374151; word-break:break-word; }
@media (max-width:600px) { header.app-header,.summary,section.results,
                           section.fingerprints,section.devices,
                           section.printers,section.udp,
                           section.notes { padding-left:16px;
                           padding-right:16px; } }
</style></head><body><header class="app-header"><h1>NetLens</h1><div class="subtitle">Portable LAN Scanner for Small Business Networks</div><div class="meta"><div><span class="label">Scan date:</span> 2026-05-26 18:53</div><div><span class="label">Range:</span> 192.168.1.1-192.168.1.254</div><div><span class="label">Adapter:</span> Ethernet</div><div><span class="label">Preset:</span> Full Common</div><div><span class="label">Duration:</span> 13.5 s</div><div><span class="label">Status:</span> <span class="status-completed">Completed</span></div></div></header><section class="summary"><div class="card online"><div class="card-value">15</div><div class="card-label">Online hosts</div></div><div class="card rdp"><div class="card-value">0</div><div class="card-label">RDP open</div></div><div class="card smb"><div class="card-value">1</div><div class="card-label">SMB open</div></div><div class="card web"><div class="card-value">14</div><div class="card-label">Web open</div></div><div class="card duration"><div class="card-value">13.5 s</div><div class="card-label">Duration</div></div></section><p class="hidden-note">239 offline hosts not listed in this report.</p><section class="results"><h2>Hosts</h2><table><thead><tr><th>IP</th><th>Status</th><th>Hostname</th><th>Device</th><th>MAC</th><th>Vendor</th><th>Open TCP ports</th><th>Services</th><th class="num">RTT</th></tr></thead><tbody><tr class="row-online"><td class="ip">192.168.1.1</td><td><span class="badge badge-online">Online</span></td><td>ROUTER-01</td><td>MikroTik router</td><td class="mac">4C-5E-0C-00-01-01</td><td>MikroTik</td><td>22, 80, 443, 8291</td><td>SSH, HTTP, HTTPS, WinBox</td><td class="num">1<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.5</td><td><span class="badge badge-online">Online</span></td><td>GATEWAY-01</td><td>UniFi gateway</td><td class="mac">24-A4-3C-00-02-01</td><td>Ubiquiti</td><td>22, 80, 443, 8080</td><td>SSH, HTTP, HTTPS, HTTP-alt</td><td class="num">1<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.10</td><td><span class="badge badge-online">Online</span></td><td>ilo-primary</td><td>HPE iLO baseboard</td><td class="mac">EC-1C-7B-00-03-01</td><td>HPE</td><td>80, 443, 17988</td><td>HTTP, HTTPS, iLO Virtual Media</td><td class="num">2<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.11</td><td><span class="badge badge-online">Online</span></td><td>idrac-db01</td><td>Dell iDRAC baseboard</td><td class="mac">84-2B-2B-00-04-01</td><td>Dell</td><td>80, 443, 5900, 5901</td><td>HTTP, HTTPS, VNC, VNC-1</td><td class="num">2<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.20</td><td><span class="badge badge-online">Online</span></td><td>esx-01</td><td>VMware ESXi 6.7</td><td class="mac">00-50-56-00-05-01</td><td>VMware</td><td>80, 443, 902, 8000, 8100, 8443</td><td>HTTP, HTTPS, VMware-auth, VM HBR, VM mig, HTTPS-alt</td><td class="num">1<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.21</td><td><span class="badge badge-online">Online</span></td><td>esx-02</td><td>VMware ESXi 7.0</td><td class="mac">00-50-56-00-05-02</td><td>VMware</td><td>80, 443, 902, 8000, 8100, 8443</td><td>HTTP, HTTPS, VMware-auth, VM HBR, VM mig, HTTPS-alt</td><td class="num">1<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.22</td><td><span class="badge badge-online">Online</span></td><td>esx-03</td><td>VMware ESXi 8.0</td><td class="mac">00-50-56-00-05-03</td><td>VMware</td><td>80, 443, 902, 8000, 8100, 8443</td><td>HTTP, HTTPS, VMware-auth, VM HBR, VM mig, HTTPS-alt</td><td class="num">1<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.30</td><td><span class="badge badge-online">Online</span></td><td>NAS-01</td><td>NAS</td><td class="mac">00-11-32-00-06-01</td><td>Synology</td><td>80, 139, 443, 445, 548, 5357</td><td>HTTP, NetBIOS-SSN, HTTPS, SMB, AFP, WSDAPI</td><td class="num">1<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.40</td><td><span class="badge badge-online">Online</span></td><td>PRINTER-01</td><td>Printer</td><td class="mac">C8-D9-D2-00-07-01</td><td>HP</td><td>80, 443, 515, 631, 9100</td><td>HTTP, HTTPS, LPR, IPP, JetDirect</td><td class="num">2<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.50</td><td><span class="badge badge-online">Online</span></td><td>CAM-01</td><td>IP Camera</td><td class="mac">28-57-BE-00-08-01</td><td>Hikvision</td><td>80, 443, 554, 8000</td><td>HTTP, HTTPS, RTSP, HTTP-alt</td><td class="num">3<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.51</td><td><span class="badge badge-online">Online</span></td><td>CAM-02</td><td>IP Camera</td><td class="mac">00-25-E1-00-08-02</td><td>Sony</td><td>80, 443, 554</td><td>HTTP, HTTPS, RTSP</td><td class="num">3<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.100</td><td><span class="badge badge-online">Online</span></td><td></td><td>Ubiquiti mFi (sensor)</td><td class="mac">04-18-D6-00-09-01</td><td>Ubiquiti</td><td>22, 80, 443, 6080</td><td>SSH, HTTP, HTTPS, mFi</td><td class="num">2<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.120</td><td><span class="badge badge-online">Online</span></td><td></td><td>Apple iPhone / iPad</td><td class="mac">F0-18-98-00-0A-01</td><td>Apple</td><td>62078</td><td>iPhone lockdown</td><td class="num">1<span class="unit"> ms</span><span class="disc">TC)NETLENS"
    R"NETLENS(P fallback</span></td></tr><tr class="row-online"><td class="ip">192.168.1.130</td><td><span class="badge badge-online">Online</span></td><td>daikinap-01</td><td>Daikin AC (Wi-Fi)</td><td class="mac">D0-C5-D3-00-0B-01</td><td>AzureWave</td><td>80</td><td>HTTP</td><td class="num">5<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr><tr class="row-online"><td class="ip">192.168.1.185</td><td><span class="badge badge-online">Online</span></td><td></td><td>UniFi AP</td><td class="mac">78-8A-20-00-0C-01</td><td>Ubiquiti</td><td>22, 8080</td><td>SSH, HTTP-alt</td><td class="num">1<span class="unit"> ms</span><span class="disc">ICMP</span></td></tr></tbody></table></section><section class="fingerprints"><h2>Service fingerprints</h2><p class="fp-note">Service fingerprinting uses lightweight, non-authenticated protocol banners and headers. It does not perform vulnerability checks or credential testing.</p><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.1</span><span class="hn">ROUTER-01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>22/tcp</td><td>ssh</td><td>MikroTik RouterOS</td><td>7.13</td><td>SSH-2.0-ROSSSH</td><td>SSH banner</td><td class="conf-high">High</td></tr><tr><td>80/tcp</td><td>http</td><td>MikroTik Webfig</td><td></td><td>HTTP title: RouterOS</td><td>HTTP body</td><td class="conf-high">High</td></tr><tr><td>443/tcp</td><td>https</td><td>MikroTik Webfig</td><td></td><td>TLS + HTTP title: RouterOS</td><td>HTTPS body</td><td class="conf-high">High</td></tr><tr><td>8291/tcp</td><td>winbox</td><td>MikroTik WinBox</td><td></td><td>Native config protocol</td><td>Port heuristic</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.5</span><span class="hn">GATEWAY-01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>22/tcp</td><td>ssh</td><td>OpenSSH</td><td>8.4p1</td><td>SSH-2.0-OpenSSH_8.4p1 Ubiquiti</td><td>SSH banner</td><td class="conf-high">High</td></tr><tr><td>443/tcp</td><td>https</td><td>UniFi OS</td><td>3.2</td><td>Server: UniFi; HTTP title: UniFi OS</td><td>HTTPS body</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.10</span><span class="hn">ilo-primary</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>443/tcp</td><td>https</td><td>HPE iLO 5</td><td>2.78</td><td>Server: HPE-iLO-Server/1.30; HTTP title: iLO 5</td><td>HTTPS body</td><td class="conf-high">High</td></tr><tr><td>17988/tcp</td><td>ilo-vm</td><td>HPE iLO Virtual Media</td><td></td><td>iLO remote console</td><td>Port heuristic</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.11</span><span class="hn">idrac-db01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>443/tcp</td><td>https</td><td>Dell iDRAC 9</td><td>6.10.00</td><td>Server: iDRAC9; HTTP title: Integrated Dell Remote Access Controller 9</td><td>HTTPS body</td><td class="conf-high">High</td></tr><tr><td>5900/tcp</td><td>vnc</td><td>Dell iDRAC vConsole</td><td></td><td>RFB 003.008</td><td>VNC banner</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.20</span><span class="hn">esx-01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>443/tcp</td><td>https</td><td>VMware ESXi</td><td>6.7.0</td><td>HTTP title: VMware ESXi; build 6.7.0-20842708 (general availability past end-of-support October 2022)</td><td>HTTPS body + version annotator</td><td class="conf-high">High</td></tr><tr><td>902/tcp</td><td>vsphere</td><td>VMware vSphere authd</td><td>6.7.0</td><td>vim25=6.7.0</td><td>vSphere authd + /sdk/vimServiceVersions.xml</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.21</span><span class="hn">esx-02</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>443/tcp</td><td>https</td><td>VMware ESXi</td><td>7.0.3</td><td>HTTP title: VMware ESXi; ESXi 7.0 Update 3 - mainstream end-of-support April 2025</td><td>HTTPS body + version annotator</td><td class="conf-high">High</td></tr><tr><td>902/tcp</td><td>vsphere</td><td>VMware vSphere authd</td><td>7.0.3</td><td>vim25=7.0.3</td><td>vSphere authd + /sdk/vimServiceVersions.xml</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.22</span><span class="hn">esx-03</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>443/tcp</td><td>https</td><td>VMware ESXi</td><td>8.0.2</td><td>HTTP title: VMware ESXi; ESXi 8.0 Update 2 - mainstream support active</td><td>HTTPS body + version annotator</td><td class="conf-high">High</td></tr><tr><td>902/tcp</td><td>vsphere</td><td>VMware vSphere authd</td><td>8.0.2</td><td>vim25=8.0.2</td><td>vSphere authd + /sdk/vimServiceVersions.xml</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.30</span><span class="hn">NAS-01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>80/tcp</td><td>http</td><td>Synology DSM</td><td>7.2</td><td>Server: nginx; HTTP title: Synology DiskStation</td><td>HTTP body</td><td class="conf-high">High</td></tr><tr><td>443/tcp</td><td>https</td><td>Synology DSM</td><td>7.2</td><td>Server: nginx; HTTP title: Synology DiskStation</td><td>HTTPS body</td><td class="conf-high">High</td></tr><tr><td>445/tcp</td><td>smb</td><td>Samba</td><td>4.15</td><td>Linux/Samba</td><td>SMB negotiate</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.40</span><span class="hn">PRINTER-01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>80/tcp</td><td>http</td><td>HP EWS</td><td></td><td>Server: HP HTTP Server; HTTP title: HP Color LaserJet MFP M477fnw</td><td>HTTP body</td><td class="conf-high">High</td></tr><tr><td>443/tcp</td><td>https</td><td>HP EWS</td><td></td><td>Server: HP HTTP Server</td><td>HTTPS body</td><td class="conf-high">High</td></tr><tr><td>9100/tcp</td><td>jetdirect</td><td>HP JetDirect</td><td></td><td>Raw print queue</td><td>Port heuristic</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.50</span><span class="hn">CAM-01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>80/tcp</td><td>http</td><td>Hikvision Web</td><td></td><td>Server: App-webs/; HTTP title: Hikvision</td><td>HTTP body</td><td class="conf-high">High</td><)NETLENS"
    R"NETLENS(/tr><tr><td>554/tcp</td><td>rtsp</td><td>Hikvision RTSP</td><td></td><td>RTSP/1.0 200 OK; Server: Hikvision</td><td>RTSP banner</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.51</span><span class="hn">CAM-02</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>80/tcp</td><td>http</td><td>Sony IPELA</td><td></td><td>Server: Sony; HTTP title: Sony Network Camera</td><td>HTTP body</td><td class="conf-high">High</td></tr><tr><td>554/tcp</td><td>rtsp</td><td>Sony RTSP</td><td></td><td>RTSP/1.0 200 OK; Server: Sony</td><td>RTSP banner</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.100</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>22/tcp</td><td>ssh</td><td>dropbear</td><td>2020.81</td><td>SSH-2.0-dropbear_2020.81</td><td>SSH banner</td><td class="conf-high">High</td></tr><tr><td>443/tcp</td><td>https</td><td>Ubiquiti mFi</td><td></td><td>HTTP title: mFi - Ubiquiti Networks</td><td>HTTPS body</td><td class="conf-high">High</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.120</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>5353/udp</td><td>apple</td><td>iPhone / iPad</td><td></td><td>lockdownd/62078</td><td>mDNS + Apple TCP probes</td><td class="conf-medium">Medium</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.130</span><span class="hn">daikinap-01</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>80/tcp</td><td>http</td><td></td><td></td><td>HTTP/1.0 200 OK</td><td>HTTP Server header</td><td class="conf-medium">Medium</td></tr></tbody></table></div><div class="fp-host"><div class="fp-host-head"><span class="ip">192.168.1.185</span></div><table class="fp-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Detail</th><th>Source</th><th>Confidence</th></tr></thead><tbody><tr><td>22/tcp</td><td>ssh</td><td>dropbear</td><td>2020.81</td><td>SSH-2.0-dropbear_2020.81</td><td>SSH banner</td><td class="conf-high">High</td></tr><tr><td>8080/tcp</td><td>http</td><td>UniFi AP</td><td></td><td>HTTP title: UniFi</td><td>HTTP body</td><td class="conf-medium">Medium</td></tr></tbody></table></div></section><section class="printers"><h2>Printer supplies</h2><p class="fp-note">Consumable levels read from the standard Printer-MIB (RFC 3805) over SNMP v2c (community <code>public</code>).</p><div class="printer-card"><div class="printer-head"><span class="ip">192.168.1.40</span><span class="hn">PRINTER-01</span><div class="printer-meta"><span><b>Vendor</b> HP</span><span><b>Model</b> HP Color LaserJet MFP M477fnw</span><span><b>Serial</b> VNBKL8H9W2</span><span><b>SNMP</b> ok</span></div></div><table class="supplies"><thead><tr><th>Consumable</th><th>Level</th><th>Description</th></tr></thead><tbody><tr><td class="sup-color sup-black">Black</td><td class="sup-bar"><div class="bar-wrap"><div class="bar" style="width:54%;background:#0f172a"></div></div><span class="sup-pct">54%</span></td><td class="sup-desc">Black Cartridge HP CF410X</td></tr><tr><td class="sup-color sup-cyan">Cyan</td><td class="sup-bar"><div class="bar-wrap"><div class="bar" style="width:45%;background:#0891b2"></div></div><span class="sup-pct">45%</span></td><td class="sup-desc">Cyan Cartridge HP CF411X</td></tr><tr><td class="sup-color sup-magenta">Magenta</td><td class="sup-bar"><div class="bar-wrap"><div class="bar" style="width:81%;background:#be185d"></div></div><span class="sup-pct">81%</span></td><td class="sup-desc">Magenta Cartridge HP CF413X</td></tr><tr><td class="sup-color sup-yellow">Yellow</td><td class="sup-bar"><div class="bar-wrap"><div class="bar" style="width:81%;background:#ca8a04"></div></div><span class="sup-pct">81%</span></td><td class="sup-desc">Yellow Cartridge HP CF412X</td></tr></tbody></table></div></section><section class="udp"><h2>UDP discovery</h2><p class="fp-note">Best-effort UDP probes (NBNS, NTP, SSDP, mDNS, SQL Server Browser, DNS, LLMNR, IPMI). Missing rows mean no response within the per-probe budget &mdash; not &ldquo;closed&rdquo;.</p><div class="udp-card"><div class="udp-head"><span class="ip">192.168.1.1</span><span class="hn">ROUTER-01</span></div><table class="udp-table"><thead><tr><th>Port</th><th>Service</th><th>Detail</th></tr></thead><tbody><tr><td class="port">53</td><td class="svc">DNS</td><td class="detail">Domain Name Server</td></tr><tr><td class="port">123</td><td class="svc">NTP</td><td class="detail">stratum 2, ref MikroTik</td></tr></tbody></table></div><div class="udp-card"><div class="udp-head"><span class="ip">192.168.1.5</span><span class="hn">GATEWAY-01</span></div><table class="udp-table"><thead><tr><th>Port</th><th>Service</th><th>Detail</th></tr></thead><tbody><tr><td class="port">53</td><td class="svc">DNS</td><td class="detail">Domain Name Server</td></tr></tbody></table></div><div class="udp-card"><div class="udp-head"><span class="ip">192.168.1.30</span><span class="hn">NAS-01</span></div><table class="udp-table"><thead><tr><th>Port</th><th>Service</th><th>Detail</th></tr></thead><tbody><tr><td class="port">137</td><td class="svc">NBNS</td><td class="detail">NAS-01\WORKGROUP</td></tr><tr><td class="port">1900</td><td class="svc">SSDP</td><td class="detail">Synology/DSM/192.168.1.30</td></tr><tr><td class="port">5353</td><td class="svc">mDNS</td><td class="detail">_smb._tcp, _afpovertcp._tcp</td></tr></tbody></table></div><div class="udp-card"><div class="udp-head"><span class="ip">192.168.1.40</span><span class="hn">PRINTER-01</span></div><table class="udp-table"><thead><tr><th>Port</th><th>Service</th><th>Detail</th></tr></thead><tbody><tr><td class="port">137</td><td class="svc">NBNS</td><td class="detail">PRINTER-01\WORKGROUP</td></tr><tr><td class="port">5353</td><td class="svc">mDNS</td><td class="detail">_ipp._tcp, _printer._tcp</td></tr></tbody></table></div><div class="udp-card"><div class="udp-head"><span class="ip">192.168.1.120</span></div><table class="udp-table"><thead><tr><th>Port</th><th>Service</th><th>Detail</th></tr></thead><tbody><tr><td class="port">5353</td><td class="svc">mDNS</td><td class="detail">_apple-mobdev2._tcp, _airplay._tcp</td></tr></tbody></table></div><div class="udp-card"><div class="udp-head"><span class="ip">192.168.1.130</span><span class="hn">daikinap-01</span></div><table class="udp-table"><thead><tr><th>Port</th><th>Service</th><th>Detail</th></tr></thead><tbody><tr><td class="port">5353</td><td class="svc">mDNS</td><td class="detail">_daikin._tcp</td></tr></tbody></table></div></section><section class="notes"><p>This report is a network-visibility snapshot &mdash; it lists what hosts answer TCP probes and what their canonical service labels are. It does not confirm vulnerabilities. Use it alongside a proper vulnerability scanner if you need configuration findings.</p></section><footer>Generated by NetLens 1.3.0</footer></body></html>)NETLENS";
}  // namespace

const char* ExportHtmlBytes() { return kHtml; }
size_t      ExportHtmlSize()  { return sizeof(kHtml) - 1; }

}  // namespace nl::mock
