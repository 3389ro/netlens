#include "SecurityAdvisor.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace lanscope {

namespace {

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

bool icontains(const std::wstring& hay, const wchar_t* needle) {
    if (!needle || !*needle) return false;
    auto tolow = [](wchar_t c) -> wchar_t {
        return (c >= L'A' && c <= L'Z')
                 ? static_cast<wchar_t>(c - L'A' + L'a') : c;
    };
    const size_t hn = hay.size();
    const size_t nn = wcslen(needle);
    if (nn == 0 || nn > hn) return false;
    for (size_t i = 0; i + nn <= hn; ++i) {
        bool match = true;
        for (size_t j = 0; j < nn; ++j) {
            if (tolow(hay[i + j]) != tolow(needle[j])) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

bool icontainsAny(const std::wstring& hay,
                  std::initializer_list<const wchar_t*> needles) {
    for (const wchar_t* n : needles) if (icontains(hay, n)) return true;
    return false;
}

// Parse "MAJOR.MINOR[.PATCH]" into 3 ints. Returns false on malformed.
// Anything past the third dot is ignored, anything non-digit-or-dot
// terminates parsing — so "8.5p1" parses as (8,5,0), "2.4.49" parses
// as (2,4,49), "7.0.3.0" parses as (7,0,3).
bool parseVersionTriplet(const std::wstring& v, int* maj, int* min, int* pat) {
    *maj = 0; *min = 0; *pat = 0;
    int* slots[3] = { maj, min, pat };
    int slot = 0;
    int cur = 0;
    bool any = false;
    for (wchar_t c : v) {
        if (c >= L'0' && c <= L'9') {
            cur = cur * 10 + (c - L'0');
            if (cur > 1000000) return false;
            any = true;
        } else if (c == L'.') {
            if (slot < 3) *slots[slot] = cur;
            ++slot;
            cur = 0;
            if (slot >= 3) break;
        } else {
            break;
        }
    }
    if (slot < 3) *slots[slot] = cur;
    return any;
}

int cmpVersion(int aMaj, int aMin, int aPat,
               int bMaj, int bMin, int bPat) {
    if (aMaj != bMaj) return aMaj < bMaj ? -1 : 1;
    if (aMin != bMin) return aMin < bMin ? -1 : 1;
    if (aPat != bPat) return aPat < bPat ? -1 : 1;
    return 0;
}

bool versionLessThan(const std::wstring& version,
                     int cutMaj, int cutMin, int cutPat) {
    int a, b, c;
    if (!parseVersionTriplet(version, &a, &b, &c)) return false;
    return cmpVersion(a, b, c, cutMaj, cutMin, cutPat) < 0;
}

bool versionEquals(const std::wstring& version,
                   int wantMaj, int wantMin, int wantPat) {
    int a, b, c;
    if (!parseVersionTriplet(version, &a, &b, &c)) return false;
    return a == wantMaj && b == wantMin && c == wantPat;
}

bool versionInRange(const std::wstring& version,
                    int loMaj, int loMin, int loPat,
                    int hiMaj, int hiMin, int hiPat) {
    int a, b, c;
    if (!parseVersionTriplet(version, &a, &b, &c)) return false;
    return cmpVersion(a, b, c, loMaj, loMin, loPat) >= 0
        && cmpVersion(a, b, c, hiMaj, hiMin, hiPat) < 0;
}

// ---------------------------------------------------------------------------
// Finding accumulator.
// ---------------------------------------------------------------------------

struct Finding {
    int           rank;     // 0=critical, 1=high, 2=medium, 3=low — primary sort key
    std::wstring  severity; // "critical" / "high" / "medium" / "low"
    std::wstring  id;       // CVE-2017-0144 / EOL-SMB1 / ...
    std::wstring  title;
    std::wstring  url;
};

constexpr int kCrit = 0;
constexpr int kHigh = 1;
constexpr int kMed  = 2;
// (kLow defined for symmetry; no rules emit it today.)
// constexpr int kLow  = 3;

void add(std::vector<Finding>& out, int rank, const wchar_t* sev,
         const wchar_t* id, std::wstring title, const wchar_t* url) {
    // Dedup by id — a host can match two rules pointing at the same CVE
    // (e.g. SMB1 protocol + an SMB1-only specific banner). Keep the
    // higher severity / first hit.
    for (const auto& f : out) {
        if (f.id == id) return;
    }
    out.push_back({ rank, sev, id, std::move(title), url ? url : L"" });
}

// ---------------------------------------------------------------------------
// Rule dispatch — walks `host` and pushes matches into `out`.
// ---------------------------------------------------------------------------

void applyRules(const ScanResult& host, std::vector<Finding>& out) {
    // The fingerprint vector is the primary input for product+version
    // matches. Some heuristic rules also read vendor + deviceType from
    // the host header (for vendor-only signals like "Hikvision camera
    // reachable on 80").

    bool sawSmb1 = false;
    bool sawEsxi67 = false;
    bool sawEsxi70 = false;
    bool sawEsxi65 = false;
    bool sawEsxiAny = false;
    // Windows version brackets seen across the host's fingerprints — used
    // by host-level rules at the end (e.g. BlueKeep needs Win NT 6.1 +
    // open RDP, SMBGhost needs Win NT 10 + open 445).
    int sawWinMajor = 0, sawWinMinor = 0;

    for (const auto& f : host.fingerprints) {
        const auto& svc  = f.service;
        const auto& prod = f.product;
        const auto& ver  = f.version;
        const auto& det  = f.detail;

        // ---- SMB family --------------------------------------------------
        //
        // The SMB NEGOTIATE probe emits service="smb", product="SMB",
        // version="1.0" / "2.0.2" / ... / "3.1.1". SMB1 is the heavy
        // hitter — it's the protocol family targeted by EternalBlue
        // (MS17-010), the substrate of WannaCry and NotPetya.
        if (svc == L"smb" && prod == L"SMB") {
            // SMB1-ONLY signals. NOTE: do NOT list "2.1" here — that string is
            // the versionShort of *modern SMB 2.1* (dialect 0x0210: Win 7 /
            // Server 2008 R2 / Win 8 / Server 2012 / many NAS). It collides
            // with the SMB1 LANMAN2.1 dialect, but those SMB1 cases are caught
            // by the "LAN Manager" detail substring below. Listing "2.1" here
            // wrongly flagged every SMB2.1 host as EternalBlue (CVE-2017-0144).
            if (ver == L"1.0" || ver == L"core" || ver == L"1.03"
             || ver == L"1.2X002"
             || icontains(f.detail, L"NT LM 0.12")
             || icontains(f.detail, L"LAN Manager"))
            {
                // EternalBlue family. Pre-auth RCE. Wormable.
                add(out, kCrit, L"critical",
                    L"CVE-2017-0144",
                    L"SMB1 server speaks NT LM 0.12 -- EternalBlue / MS17-010 pre-auth RCE (WannaCry, NotPetya)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2017-0144");
                add(out, kHigh, L"high",
                    L"EOL-SMB1",
                    L"SMB1 protocol -- disabled by default since Windows 10 1709 / Server 2019; remove it",
                    L"https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3");
                sawSmb1 = true;
            }
        }

        // ---- MikroTik RouterOS -------------------------------------------
        //
        // WinBox path traversal (CVE-2018-14847) lets unauthenticated
        // attackers read /flash/rw/store/user.dat which contains all
        // user credentials. Affected: RouterOS < 6.42.1, plus a long
        // tail of 6.43.x betas. The 7.x line is unaffected.
        if (icontains(prod, L"MikroTik")
         || icontains(prod, L"RouterOS")
         || icontains(host.vendor, L"MikroTik"))
        {
            if (!ver.empty() && versionLessThan(ver, 6, 42, 1)
                && ver[0] != L'7') {
                add(out, kCrit, L"critical",
                    L"CVE-2018-14847",
                    L"MikroTik RouterOS WinBox path traversal -- credential database read (pre-auth, port 8291)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2018-14847");
            }
        }

        // ---- Apache httpd ------------------------------------------------
        //
        // The 2.4.49 / 2.4.50 path-traversal pair is the canonical
        // "version banner alone is enough" RCE. Both CVEs are RCE when
        // mod_cgi is on (default in many distros) and disclose
        // arbitrary file contents otherwise.
        if (icontains(prod, L"Apache")) {
            if (versionEquals(ver, 2, 4, 49)) {
                add(out, kCrit, L"critical",
                    L"CVE-2021-41773",
                    L"Apache httpd 2.4.49 -- path traversal; RCE via mod_cgi (CVSS 9.8)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2021-41773");
            } else if (versionEquals(ver, 2, 4, 50)) {
                add(out, kCrit, L"critical",
                    L"CVE-2021-42013",
                    L"Apache httpd 2.4.50 -- path traversal + RCE (incomplete fix of CVE-2021-41773, CVSS 9.8)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2021-42013");
            }
        }

        // ---- OpenSSH 'regreSSHion' ---------------------------------------
        //
        // CVE-2024-6387 -- pre-auth RCE in portable OpenSSH 8.5p1
        // through 9.7p1 (race in SIGALRM handler). Fixed in 9.8p1.
        if (icontains(prod, L"OpenSSH")) {
            if (versionInRange(ver, 8, 5, 0, 9, 8, 0)) {
                add(out, kCrit, L"critical",
                    L"CVE-2024-6387",
                    L"OpenSSH 8.5p1-9.7p1 'regreSSHion' -- pre-auth RCE via SIGALRM race",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2024-6387");
            }
            // v1.3.10 — CVE-2023-38408 (OpenSSH < 9.3p2): ssh-agent
            // PKCS#11 forwarding RCE. Exploitation needs agent forwarding
            // exposure NetLens can't observe, and distro backports muddy
            // the banner version, so this is MEDIUM informational only.
            if (!ver.empty() && versionLessThan(ver, 9, 3, 2)) {
                add(out, kMed, L"medium",
                    L"CVE-2023-38408",
                    L"OpenSSH < 9.3p2 -- ssh-agent PKCS#11 code execution risk (verify distro backport)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2023-38408");
            }
        }

        // ---- VMware ESXi -------------------------------------------------
        //
        // OpenSLP heap overflow CVE-2021-21974 -- pre-auth RCE on
        // ESXi 6.5 U3, 6.7 U3, 7.0 U2-pre. We don't know the exact
        // patch level from the dialect-revision banner so we flag any
        // ESXi 6.x / 7.0 host (heuristic). Worst-case false positive
        // on a patched 7.0 box where the operator should already know
        // the patch baseline -- worth the noise for unpatched 6.7
        // boxes that are the actual ransomware victims.
        if (icontains(prod, L"ESXi") || icontains(prod, L"VMware ESXi")) {
            sawEsxiAny = true;
            if (versionInRange(ver, 6, 0, 0, 7, 1, 0)) {
                add(out, kCrit, L"critical",
                    L"CVE-2021-21974",
                    L"VMware ESXi 6.x/7.0 -- if unpatched, OpenSLP heap-overflow pre-auth RCE (ransomware vector, port 427); verify the ESXi build/patch level",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2021-21974");
            }
            if (versionInRange(ver, 6, 5, 0, 6, 6, 0)) sawEsxi65 = true;
            if (versionInRange(ver, 6, 7, 0, 6, 8, 0)) sawEsxi67 = true;
            if (versionInRange(ver, 7, 0, 0, 7, 1, 0)) sawEsxi70 = true;
        }

        // ---- HPE iLO 4 ---------------------------------------------------
        //
        // CVE-2017-12542 -- the famous "29 letter A's in the Connection
        // header" auth bypass. Affects iLO 4 firmware before 2.53.
        // Pre-auth admin user creation + RCE.
        if ((icontains(prod, L"iLO") && (ver.find(L"4") == 0))
         || icontains(f.detail, L"iLO 4")) {
            // We surface the warning regardless of patch level — most
            // iLO 4 fleets stayed on whatever shipped, and the "is
            // your iLO 4 < 2.53?" check is exactly the question we
            // want to surface.
            add(out, kCrit, L"critical",
                L"CVE-2017-12542",
                L"HPE iLO 4 < 2.53 -- 'A' x 29 auth bypass; remote admin account creation + RCE",
                L"https://nvd.nist.gov/vuln/detail/CVE-2017-12542");
        }

        // ---- Dell iDRAC9 -------------------------------------------------
        //
        // CVE-2018-1207 -- pre-auth path traversal in iDRAC9 web UI
        // disclosing configuration files including credential hashes.
        // CVSS 9.8. Affects firmware before 3.21.21.21.
        if (icontains(prod, L"iDRAC") || icontains(det, L"iDRAC9")) {
            add(out, kCrit, L"critical",
                L"CVE-2018-1207",
                L"Dell iDRAC9 < 3.21 -- pre-auth path traversal disclosing config + credential hashes",
                L"https://nvd.nist.gov/vuln/detail/CVE-2018-1207");
        }

        // ---- Microsoft IIS -----------------------------------------------
        //
        // Two famous IIS RCEs:
        //   CVE-2017-7269 -- IIS 6.0 WebDAV ScStoragePathFromUrl pre-auth
        //                    RCE. CVSS 9.8. Windows Server 2003 / R2.
        //   CVE-2015-1635 (MS15-034) -- HTTP.sys range header RCE.
        //                    CVSS 10.0. IIS 7.5/8.0/8.5 on Win 7+/
        //                    Server 2008 R2+. Largely patched by 2016
        //                    but unpatched boxes still appear in
        //                    industrial / utility networks.
        if (icontains(prod, L"Microsoft-IIS") || icontains(det, L"Microsoft-IIS")
         || icontains(prod, L"IIS")) {
            if (versionEquals(ver, 6, 0, 0)
             || icontains(det, L"IIS/6.0")
             || icontains(det, L"Microsoft-IIS/6.0")) {
                add(out, kCrit, L"critical",
                    L"CVE-2017-7269",
                    L"Microsoft IIS 6.0 WebDAV (ScStoragePathFromUrl) -- pre-auth RCE (Server 2003)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2017-7269");
                add(out, kHigh, L"high",
                    L"EOL-Server-2003",
                    L"Windows Server 2003 -- extended support ended July 2015; no security patches",
                    L"https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003-r2");
            }
            // Heuristic: IIS 7.5/8.0/8.5 without patch confirmation gets
            // a medium-severity HTTP.sys ping. Worst case false-positive
            // on patched boxes; operators will know if they applied
            // MS15-034 in 2015. Skip 10.0+ (Win10/Server 2016+).
            if ((versionInRange(ver, 7, 5, 0, 9, 0, 0)
                 || icontains(det, L"IIS/7.5")
                 || icontains(det, L"IIS/8.0")
                 || icontains(det, L"IIS/8.5"))
                && !versionInRange(ver, 10, 0, 0, 99, 0, 0)) {
                add(out, kHigh, L"high",
                    L"CVE-2015-1635",
                    L"Microsoft IIS 7.5/8.x -- HTTP.sys range header RCE (MS15-034); verify patch",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2015-1635");
            }
        }

        // ---- FTP servers -------------------------------------------------
        //
        // Two banner-only "you have it = you're owned" finds:
        //   ProFTPD 1.3.5 -- CVE-2015-3306 mod_copy unauthenticated file
        //                    copy/move/exec. CVSS 10.0.
        //   vsftpd 2.3.4 -- the infamous backdoor (smiley face username
        //                    triggers shell on 6200). CVE-2011-2523.
        if (svc == L"ftp" || icontains(prod, L"ProFTPD") || icontains(prod, L"vsftpd")
         || icontains(det, L"ProFTPD") || icontains(det, L"vsftpd")) {
            if (icontains(prod, L"ProFTPD")
             || icontains(det, L"ProFTPD 1.3.5")) {
                if (icontains(det, L"1.3.5") || versionEquals(ver, 1, 3, 5)) {
                    add(out, kCrit, L"critical",
                        L"CVE-2015-3306",
                        L"ProFTPD 1.3.5 mod_copy -- unauthenticated arbitrary file copy/RCE",
                        L"https://nvd.nist.gov/vuln/detail/CVE-2015-3306");
                }
            }
            if (icontains(det, L"vsftpd 2.3.4") || versionEquals(ver, 2, 3, 4)) {
                add(out, kCrit, L"critical",
                    L"CVE-2011-2523",
                    L"vsftpd 2.3.4 backdoor -- smiley-face login opens root shell on TCP 6200",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2011-2523");
            }
        }

        // ---- Exim mail transfer agent -----------------------------------
        //
        // CVE-2019-10149 'Return of the Wizard' -- Exim 4.87-4.91
        // local-and-remote RCE via crafted recipient address. CVSS 9.8.
        if (icontains(prod, L"Exim") || icontains(det, L"Exim ")) {
            if (versionInRange(ver, 4, 87, 0, 4, 92, 0)
             || icontains(det, L"Exim 4.87")
             || icontains(det, L"Exim 4.88")
             || icontains(det, L"Exim 4.89")
             || icontains(det, L"Exim 4.90")
             || icontains(det, L"Exim 4.91")) {
                add(out, kCrit, L"critical",
                    L"CVE-2019-10149",
                    L"Exim 4.87-4.91 'Return of the Wizard' -- crafted recipient address RCE",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2019-10149");
            }
            // v1.3.10 — CVE-2023-42115 (Exim < 4.96.1): SMTP AUTH
            // out-of-bounds write, pre-auth RCE class (ZDI Aug 2023).
            // Banner-version gated; only fires when a parseable version
            // below 4.96.1 leaks.
            if (!ver.empty() && versionLessThan(ver, 4, 96, 1)) {
                add(out, kHigh, L"high",
                    L"CVE-2023-42115",
                    L"Exim < 4.96.1 -- SMTP service out-of-bounds write, RCE class",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2023-42115");
            }
        }

        // ---- Apache Tomcat AJP GhostCat ----------------------------------
        //
        // CVE-2020-1938 -- Apache Tomcat AJP protocol file inclusion +
        // RCE. CVSS 9.8. AJP service on port 8009. We don't speak AJP
        // but if banner / port pattern matches we can flag.
        if (icontains(prod, L"Tomcat") || icontains(det, L"Tomcat")) {
            // Flag regardless of version — operators commonly missed
            // the patch line (Tomcat 9.0.31, 8.5.51, 7.0.100). The
            // host-level rule below also looks for raw AJP on 8009.
            add(out, kCrit, L"critical",
                L"CVE-2020-1938",
                L"Apache Tomcat -- GhostCat AJP file inclusion / RCE; verify patch and disable AJP if unused",
                L"https://nvd.nist.gov/vuln/detail/CVE-2020-1938");
        }

        // ---- VMware vSphere / vCenter Server -----------------------------
        //
        // CVE-2021-21972 -- vCenter Server vSAN plugin pre-auth file
        // upload + RCE. CVSS 9.8. Affected vCenter 6.5 / 6.7 / 7.0
        // before specific U-patches.
        if (icontains(prod, L"vCenter") || icontains(prod, L"vSphere")
         || icontains(det, L"vCenter") || icontains(det, L"vSphere Client")) {
            add(out, kCrit, L"critical",
                L"CVE-2021-21972",
                L"VMware vCenter Server vSAN plugin -- pre-auth file upload + RCE; verify U-patch level",
                L"https://nvd.nist.gov/vuln/detail/CVE-2021-21972");
            // v1.3.10 — CVE-2021-21985: vCenter vSAN Health Check plugin
            // default-enabled pre-auth RCE (CVSS 9.8).
            add(out, kCrit, L"critical",
                L"CVE-2021-21985",
                L"VMware vCenter Server vSAN Health Check plugin -- default-enabled pre-auth RCE",
                L"https://nvd.nist.gov/vuln/detail/CVE-2021-21985");
        }

        // ---- Fortinet FortiOS / FortiGate --------------------------------
        //
        // SSL VPN pre-auth RCEs that have shipped ransomware payloads:
        //   CVE-2022-42475 -- FortiOS sslvpnd heap overflow. CVSS 9.8.
        //   CVE-2024-21762 -- FortiOS out-of-bounds write. CVSS 9.6.
        if (icontains(prod, L"FortiGate") || icontains(prod, L"FortiOS")
         || icontains(det, L"FortiGate") || icontains(det, L"FortiOS")
         || icontains(f.title, L"FortiGate")) {
            add(out, kCrit, L"critical",
                L"CVE-2024-21762",
                L"Fortinet FortiOS SSL-VPN -- out-of-bounds write pre-auth RCE",
                L"https://nvd.nist.gov/vuln/detail/CVE-2024-21762");
            add(out, kCrit, L"critical",
                L"CVE-2022-42475",
                L"Fortinet FortiOS sslvpnd -- heap overflow pre-auth RCE (active ransomware vector)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2022-42475");
            // v1.3.10 — CVE-2023-27997 'XORtigate': FortiOS/FortiProxy
            // SSL-VPN heap overflow, pre-auth RCE (CVSS 9.8).
            add(out, kCrit, L"critical",
                L"CVE-2023-27997",
                L"Fortinet FortiOS/FortiProxy SSL-VPN -- 'XORtigate' heap overflow pre-auth RCE",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-27997");
        }

        // ---- Palo Alto PAN-OS GlobalProtect ------------------------------
        //
        // CVE-2024-3400 -- GlobalProtect command injection pre-auth RCE.
        // CVSS 10.0. Active exploitation in the wild.
        if (icontains(prod, L"PAN-OS") || icontains(prod, L"GlobalProtect")
         || icontains(det, L"GlobalProtect") || icontains(f.title, L"GlobalProtect")) {
            add(out, kCrit, L"critical",
                L"CVE-2024-3400",
                L"Palo Alto PAN-OS GlobalProtect -- pre-auth command injection RCE (active ITW exploitation)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2024-3400");
        }

        // ---- Citrix NetScaler ADC / Gateway ------------------------------
        //
        //   CVE-2023-3519 -- NetScaler pre-auth RCE. CVSS 9.8.
        //   CVE-2023-4966 -- 'Citrix Bleed' -- session token disclosure
        //                    enabling session hijack. CVSS 7.5 but
        //                    catastrophic in practice (used by ransomware
        //                    operators in 2023-2024).
        if (icontains(prod, L"NetScaler") || icontains(prod, L"Citrix")
         || icontains(det, L"NetScaler") || icontains(f.title, L"Citrix")
         || icontains(f.title, L"NetScaler")) {
            add(out, kCrit, L"critical",
                L"CVE-2023-3519",
                L"Citrix NetScaler ADC/Gateway -- pre-auth RCE (CVSS 9.8)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-3519");
            add(out, kCrit, L"critical",
                L"CVE-2023-4966",
                L"Citrix Bleed -- NetScaler session token disclosure; session hijack / credential takeover",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-4966");
        }

        // ---- Cisco IOS XE Web UI ----------------------------------------
        //
        // CVE-2023-20198 -- Cisco IOS XE Web UI privilege escalation to
        // administrator. CVSS 10.0. Tens of thousands of devices
        // compromised in October 2023.
        if (icontains(prod, L"Cisco IOS XE") || icontains(det, L"Cisco IOS XE")
         || icontains(f.title, L"Cisco") || icontains(prod, L"IOS XE")) {
            add(out, kCrit, L"critical",
                L"CVE-2023-20198",
                L"Cisco IOS XE Web UI -- privilege escalation to admin (CVSS 10.0; active mass-exploitation)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-20198");
        }

        // ---- F5 BIG-IP iControl REST ------------------------------------
        //
        // CVE-2022-1388 -- iControl REST authentication bypass + RCE.
        // CVSS 9.8.
        if (icontains(prod, L"BIG-IP") || icontains(prod, L"F5 BIG-IP")
         || icontains(det, L"BIG-IP") || icontains(f.title, L"BIG-IP")) {
            add(out, kCrit, L"critical",
                L"CVE-2022-1388",
                L"F5 BIG-IP iControl REST -- pre-auth bypass + RCE (CVSS 9.8)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2022-1388");
        }

        // ---- Atlassian Confluence Server / Data Center ------------------
        //
        // CVE-2023-22515 -- Broken Access Control allowing unauthenticated
        // admin user creation. CVSS 10.0.
        if (icontains(prod, L"Confluence") || icontains(f.title, L"Confluence")
         || icontains(det, L"Confluence")) {
            add(out, kCrit, L"critical",
                L"CVE-2023-22515",
                L"Atlassian Confluence Server / Data Center -- unauth admin user creation (CVSS 10.0)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-22515");
            // v1.3.10 — CVE-2022-26134: Confluence OGNL injection,
            // unauth RCE (CVSS 9.8, mass-exploited June 2022).
            add(out, kCrit, L"critical",
                L"CVE-2022-26134",
                L"Atlassian Confluence -- OGNL injection unauth RCE (CVSS 9.8); verify patch level",
                L"https://nvd.nist.gov/vuln/detail/CVE-2022-26134");
        }

        // ---- Ivanti Connect Secure / Pulse Secure -----------------------
        //
        // CVE-2024-21887 -- command injection. Combined with CVE-2023-46805
        // chains to pre-auth RCE. CVSS 9.1.
        if (icontains(prod, L"Pulse Secure") || icontains(prod, L"Ivanti")
         || icontains(f.title, L"Ivanti Connect Secure")
         || icontains(f.title, L"Pulse Secure")
         || icontains(det, L"ivanti")) {
            add(out, kCrit, L"critical",
                L"CVE-2024-21887",
                L"Ivanti Connect Secure / Policy Secure -- command injection (chains to pre-auth RCE)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2024-21887");
        }

        // ---- ConnectWise ScreenConnect ----------------------------------
        //
        // CVE-2024-1709 -- authentication bypass via SetupWizard. CVSS
        // 10.0. Active ransomware vector early 2024.
        if (icontains(prod, L"ScreenConnect") || icontains(f.title, L"ScreenConnect")
         || icontains(det, L"ScreenConnect")) {
            add(out, kCrit, L"critical",
                L"CVE-2024-1709",
                L"ConnectWise ScreenConnect -- SetupWizard authentication bypass (CVSS 10.0)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2024-1709");
            // v1.3.10 — CVE-2024-1708: ScreenConnect path traversal,
            // chained with 1709 for RCE. <= 23.9.7 affected.
            add(out, kHigh, L"high",
                L"CVE-2024-1708",
                L"ConnectWise ScreenConnect -- path traversal (chains with CVE-2024-1709 for RCE)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2024-1708");
        }

        // ---- Samba ------------------------------------------------------
        //
        // CVE-2017-7494 'SambaCry' -- Linux/Samba 3.5.0-4.5.x writable
        // share RCE. CVSS 9.8.
        if (icontains(prod, L"Samba") || icontains(det, L"Samba ")) {
            // Versions 3.5.0 to 4.6.3 are vulnerable. Check banner.
            if (versionInRange(ver, 3, 5, 0, 4, 6, 4)
             || icontains(det, L"Samba 3.5")
             || icontains(det, L"Samba 3.6")
             || icontains(det, L"Samba 4.0")
             || icontains(det, L"Samba 4.1")
             || icontains(det, L"Samba 4.2")
             || icontains(det, L"Samba 4.3")
             || icontains(det, L"Samba 4.4")
             || icontains(det, L"Samba 4.5")) {
                add(out, kCrit, L"critical",
                    L"CVE-2017-7494",
                    L"Samba 3.5.0-4.5.x 'SambaCry' -- writable share unauth RCE",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2017-7494");
            }
        }

        // ---- QNAP NAS ---------------------------------------------------
        //
        // QNAP boxes have been heavy ransomware targets (DeadBolt,
        // Qlocker etc.). Two recent RCEs:
        //   CVE-2022-27593 -- DeadBolt ransomware Photo Station vector.
        //   CVE-2023-23368 -- QTS pre-auth command injection RCE.
        if (icontains(prod, L"QNAP") || icontains(prod, L"QTS")
         || icontains(f.title, L"QNAP") || icontains(f.title, L"QTS")
         || icontains(host.vendor, L"QNAP")) {
            add(out, kCrit, L"critical",
                L"CVE-2023-23368",
                L"QNAP QTS / QuTS hero -- pre-auth command injection RCE; patch immediately",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-23368");
            add(out, kHigh, L"high",
                L"CVE-2022-27593",
                L"QNAP Photo Station -- external reference attack used by DeadBolt ransomware",
                L"https://nvd.nist.gov/vuln/detail/CVE-2022-27593");
        }

        // ---- Synology DSM -----------------------------------------------
        //
        // CVE-2023-47214 -- DSM 7.x pre-auth media-server RCE via
        // crafted file metadata. CVSS 8.8.
        if (icontains(prod, L"DSM") || icontains(f.title, L"DiskStation")
         || icontains(host.vendor, L"Synology")) {
            // Heuristic — affects DSM 7.x media server. Surface as
            // high-severity (configuration-dependent) rather than the
            // critical-by-default we use for fully-confirmed RCEs.
            if (versionInRange(ver, 7, 0, 0, 8, 0, 0)
             || icontains(det, L"DSM 7")
             || icontains(f.title, L"DSM 7")) {
                add(out, kHigh, L"high",
                    L"CVE-2023-47214",
                    L"Synology DSM 7.x -- crafted file metadata RCE in media server; patch DSM",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2023-47214");
            }
        }

        // ====================================================================
        // v1.3.10 — managed-file-transfer / collaboration / mail web apps.
        //
        // These are all identified from the HTTP(S) fingerprint: the product
        // name lands in the page <title> (f.title) or the Server / X-Powered-By
        // detail (f.detail). The exact build almost never leaks over the wire,
        // so the default is HIGH "verify patch level" on detection, escalating
        // to CRITICAL only when a parseable version in the affected range is
        // present. This matches the appliance rules above (Fortinet/Citrix/…)
        // which flag on product detection alone.
        // ====================================================================

        // ---- PaperCut NG/MF (CVE-2023-27350 / -27351) --------------------
        //
        // 27350 is an unauth access-control bypass to RCE (CVSS 9.8), very
        // heavily exploited in 2023. The admin UI lives on 9191 (http) /
        // 9192 (https) — added to the FullCommon preset in v1.3.10 — and
        // puts "PaperCut" in the page title.
        if (icontains(prod, L"PaperCut") || icontains(f.title, L"PaperCut")
         || icontains(det, L"PaperCut")) {
            // Affected: NG/MF 8.0+ before 20.1.7 / 21.2.11 / 22.0.9.
            const bool affectedVer = !ver.empty()
                && (versionInRange(ver, 8,  0, 0, 20, 1,  7)
                 || versionInRange(ver, 21, 0, 0, 21, 2, 11)
                 || versionInRange(ver, 22, 0, 0, 22, 0,  9));
            if (affectedVer) {
                add(out, kCrit, L"critical", L"CVE-2023-27350",
                    L"PaperCut NG/MF -- unauth access-control bypass to RCE (affected build, CVSS 9.8)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2023-27350");
            } else {
                add(out, kHigh, L"high", L"CVE-2023-27350",
                    L"PaperCut NG/MF detected -- verify patch for CVE-2023-27350 auth-bypass RCE (>= 20.1.7 / 21.2.11 / 22.0.9)",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2023-27350");
            }
            add(out, kMed, L"medium", L"CVE-2023-27351",
                L"PaperCut NG/MF -- verify patch for CVE-2023-27351 unauthenticated information disclosure",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-27351");
        }

        // ---- Progress MOVEit Transfer (CVE-2023-34362) -------------------
        //
        // Pre-auth SQL injection to RCE / mass data theft (Cl0p, mid-2023).
        // The web UI title / sign-in page says "MOVEit".
        if (icontains(prod, L"MOVEit") || icontains(f.title, L"MOVEit")
         || icontains(det, L"MOVEit")) {
            add(out, kHigh, L"high", L"CVE-2023-34362",
                L"Progress MOVEit Transfer detected -- verify patch for CVE-2023-34362 SQL injection RCE (Cl0p mass exploitation)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-34362");
        }

        // ---- Fortra GoAnywhere MFT (CVE-2023-0669) -----------------------
        //
        // Pre-auth command injection (exploited by Cl0p). Affected < 7.1.2.
        // Admin console title / body says "GoAnywhere".
        if (icontains(prod, L"GoAnywhere") || icontains(f.title, L"GoAnywhere")
         || icontains(det, L"GoAnywhere")) {
            if (!ver.empty() && versionLessThan(ver, 7, 1, 2)) {
                add(out, kCrit, L"critical", L"CVE-2023-0669",
                    L"Fortra GoAnywhere MFT < 7.1.2 -- pre-auth command injection RCE",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2023-0669");
            } else {
                add(out, kHigh, L"high", L"CVE-2023-0669",
                    L"Fortra GoAnywhere MFT detected -- verify patch for CVE-2023-0669 pre-auth command injection",
                    L"https://nvd.nist.gov/vuln/detail/CVE-2023-0669");
            }
        }

        // ---- Microsoft Exchange OWA / ECP --------------------------------
        //
        // ProxyLogon (2021), ProxyShell (2021) and ProxyNotShell (2022) are
        // three pre-auth RCE chains, all heavily exploited. The exact CU/SU
        // build that determines vulnerability isn't exposed over plain HTTP,
        // so detection of the Outlook Web App login → HIGH "verify patch".
        if (icontains(f.title, L"Outlook Web App")
         || icontains(f.title, L"Outlook")
         || icontains(det, L"X-OWA-Version")) {
            add(out, kHigh, L"high", L"CVE-2021-26855",
                L"Microsoft Exchange OWA/ECP detected -- verify patch for ProxyLogon (CVE-2021-26855) pre-auth SSRF->RCE chain",
                L"https://nvd.nist.gov/vuln/detail/CVE-2021-26855");
            add(out, kHigh, L"high", L"CVE-2021-34473",
                L"Microsoft Exchange detected -- verify patch for ProxyShell (CVE-2021-34473) pre-auth RCE chain",
                L"https://nvd.nist.gov/vuln/detail/CVE-2021-34473");
            add(out, kHigh, L"high", L"CVE-2022-41082",
                L"Microsoft Exchange detected -- verify patch for ProxyNotShell (CVE-2022-41082) authenticated RCE",
                L"https://nvd.nist.gov/vuln/detail/CVE-2022-41082");
        }

        // ---- Jenkins (CVE-2024-23897) ------------------------------------
        //
        // args4j CLI arbitrary file read; chains to RCE. Jenkins titles its
        // dashboard "... [Jenkins]" and sets an X-Jenkins response header.
        // Version rarely on the landing page → MEDIUM "verify".
        if (icontains(prod, L"Jenkins") || icontains(f.title, L"Jenkins")
         || icontains(det, L"X-Jenkins")) {
            add(out, kMed, L"medium", L"CVE-2024-23897",
                L"Jenkins detected -- verify version for CVE-2024-23897 CLI arbitrary file read (LTS <= 2.426.2 / weekly <= 2.441)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2024-23897");
        }

        // ---- GitLab CE/EE ------------------------------------------------
        //
        //   CVE-2023-7028  -- zero-click account takeover via password reset
        //                     to attacker email (CVSS 10.0).
        //   CVE-2021-22205 -- pre-auth ExifTool RCE (CVSS 10.0).
        // Title / body says "GitLab".
        if (icontains(prod, L"GitLab") || icontains(f.title, L"GitLab")
         || icontains(det, L"GitLab")) {
            add(out, kHigh, L"high", L"CVE-2023-7028",
                L"GitLab detected -- verify version for CVE-2023-7028 zero-click account takeover (16.x before Jan-2024 patches)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2023-7028");
            add(out, kHigh, L"high", L"CVE-2021-22205",
                L"GitLab detected -- verify version for CVE-2021-22205 pre-auth ExifTool RCE (CVSS 10.0)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2021-22205");
        }

        // ---- Track Windows version for host-level rules ------------------
        //
        // The "windows" fingerprint emitted by NetServerGetInfo carries
        // the Major.Minor of the OS (e.g. 6.1 = Win 7 / Server 2008 R2,
        // 10.0 = Win 10/11/Server 2016+). Remember for the rules below
        // that key off Windows version + open port.
        if (svc == L"windows" && prod == L"Windows") {
            int wMaj = 0, wMin = 0, wPat = 0;
            if (parseVersionTriplet(ver, &wMaj, &wMin, &wPat)) {
                sawWinMajor = wMaj;
                sawWinMinor = wMin;
            }
        }
    }

    // ---- Heuristic host-level rules (don't need a specific fingerprint) -

    // Hikvision IP camera with a web UI exposed -- a substantial fleet
    // is still vulnerable to CVE-2017-7921 (auth bypass via crafted URL
    // disclosing user list + password hashes). The check is firmware-
    // version-dependent and we don't have the firmware; surface a
    // medium-confidence hint when the device matches "Hikvision camera
    // with port 80 open" so the operator at least knows to look.
    if (icontains(host.vendor, L"Hikvision")
     || icontainsAny(host.deviceType, { L"Hikvision" }))
    {
        bool web = false;
        for (const auto& p : host.ports) {
            if (p.isOpen && (p.port == 80 || p.port == 8000)) {
                web = true; break;
            }
        }
        if (web) {
            add(out, kCrit, L"critical",
                L"CVE-2017-7921",
                L"Hikvision IP camera reachable on HTTP -- check firmware for CVE-2017-7921 auth bypass (credential disclosure)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2017-7921");
        }
    }

    // ---- Host-level rules that combine port state + Windows version ----

    // Open-port helpers — keep the loops local so we don't bloat the
    // ScanResult interface with cached "is port N open" booleans for
    // a handful of rules.
    auto portOpen = [&](int port) -> bool {
        for (const auto& p : host.ports) {
            if (p.isOpen && p.port == port) return true;
        }
        return false;
    };
    const bool rdpOpen = portOpen(3389);
    const bool smbOpen = portOpen(445);
    const bool ajpOpen = portOpen(8009);

    // BlueKeep (CVE-2019-0708) -- RDP pre-auth RCE on Win 7 / Server
    // 2008 R2 / Server 2003 / XP. Surface as critical when RDP is
    // open AND the host self-identifies as a pre-Win-8 Windows.
    // Even fully patched modern Windows is too far removed from the
    // wormable surface to flag, so we gate strictly on version.
    if (rdpOpen && sawWinMajor != 0
        && (sawWinMajor < 6
            || (sawWinMajor == 6 && sawWinMinor <= 1))) {
        add(out, kCrit, L"critical",
            L"CVE-2019-0708",
            L"BlueKeep -- RDP pre-auth RCE on Win 7 / Server 2008 R2 / XP / Server 2003 (wormable, MS19-0708)",
            L"https://nvd.nist.gov/vuln/detail/CVE-2019-0708");
    }

    // SMBGhost (CVE-2020-0796) -- Win 10 1903/1909 with SMB 3.1.1.
    // We don't know the build number from negotiate alone; surface a
    // high-severity ping when the host speaks SMB 3.1.1 AND identifies
    // as Win 10/11 (NetServerGetInfo major=10). False positives on
    // patched 1903/1909 and on later Win 10 / 11 are accepted as the
    // cost of catching unpatched 1903/1909 boxes.
    if (smbOpen && sawWinMajor == 10) {
        bool sawSmb311 = false;
        for (const auto& f : host.fingerprints) {
            if (f.service == L"smb" && f.product == L"SMB"
             && f.version == L"3.1.1") { sawSmb311 = true; break; }
        }
        if (sawSmb311) {
            add(out, kHigh, L"high",
                L"CVE-2020-0796",
                L"SMBGhost -- Win 10 1903/1909 SMB 3.1.1 compression RCE; check OS build is post-patch",
                L"https://nvd.nist.gov/vuln/detail/CVE-2020-0796");
        }
    }

    // Apache Tomcat AJP on default port 8009 without a corresponding
    // version-tagged Tomcat fingerprint -- still flag the AJP surface
    // itself as GhostCat (CVE-2020-1938) since most operators don't
    // realise AJP is exposed to anyone who can reach 8009.
    if (ajpOpen) {
        add(out, kHigh, L"high",
            L"CVE-2020-1938",
            L"Apache Tomcat AJP on port 8009 -- GhostCat file inclusion / RCE; disable AJP or bind to localhost",
            L"https://nvd.nist.gov/vuln/detail/CVE-2020-1938");
    }

    // ---- Hikvision IP camera with a web UI exposed (heuristic) ----------
    //
    // (Was previously down below; consolidated here for the host-level
    // rules block.) A substantial fleet is still vulnerable to
    // CVE-2017-7921 (auth bypass via crafted URL disclosing user list +
    // password hashes). Surface a hint when Hikvision + 80/8000 open.
    if (icontains(host.vendor, L"Hikvision")
     || icontainsAny(host.deviceType, { L"Hikvision" }))
    {
        bool hikWeb = false;
        for (const auto& p : host.ports) {
            if (p.isOpen && (p.port == 80 || p.port == 8000)) {
                hikWeb = true; break;
            }
        }
        if (hikWeb) {
            add(out, kCrit, L"critical",
                L"CVE-2017-7921",
                L"Hikvision IP camera reachable on HTTP -- check firmware for CVE-2017-7921 auth bypass (credential disclosure)",
                L"https://nvd.nist.gov/vuln/detail/CVE-2017-7921");
            // v1.3.10 — CVE-2021-36260: unauth command injection RCE in a
            // huge range of Hikvision firmware (CVSS 9.8). Firmware version
            // isn't reliably exposed → HIGH "verify firmware".
            add(out, kHigh, L"high",
                L"CVE-2021-36260",
                L"Hikvision IP camera/NVR on HTTP -- verify firmware for CVE-2021-36260 unauth command injection RCE",
                L"https://nvd.nist.gov/vuln/detail/CVE-2021-36260");
        }
    }

    // ---- EOL lifecycle hits (only if not already implied) ---------------

    if (sawEsxi65) {
        add(out, kHigh, L"high",
            L"EOL-ESXi-6.5",
            L"VMware ESXi 6.5 -- end-of-support October 2022; no security patches",
            L"https://www.vmware.com/info/lifecycle-policy");
    }
    if (sawEsxi67) {
        add(out, kHigh, L"high",
            L"EOL-ESXi-6.7",
            L"VMware ESXi 6.7 -- general end-of-support October 2022; no further security patches",
            L"https://blogs.vmware.com/vsphere/2022/10/announcing-extended-general-support-for-vsphere-6-7.html");
    }
    if (sawEsxi70) {
        add(out, kMed, L"medium",
            L"EOL-ESXi-7.0",
            L"VMware ESXi 7.0 -- general support ended April 2025; transition planning required",
            L"https://www.vmware.com/info/lifecycle-policy");
    }

    // Windows EOL hits — derived from the NetServerGetInfo Major.Minor.
    //   5.1 = Windows XP                  (extended support ended Apr 2014)
    //   5.2 = Server 2003 / R2 / XP x64   (extended support ended Jul 2015)
    //   6.0 = Vista / Server 2008         (extended support ended Apr 2017/Jan 2020)
    //   6.1 = Win 7 / Server 2008 R2      (extended support ended Jan 2020;
    //                                       ESU through Jan 2023)
    //   6.2 = Win 8 / Server 2012         (extended support ended Oct 2023)
    //   6.3 = Win 8.1 / Server 2012 R2    (extended support ended Oct 2023)
    //   10.0 = Win 10 / 11 / Server 2016+ (still in support; no EOL hit)
    if (sawWinMajor == 5 && sawWinMinor == 1) {
        add(out, kCrit, L"critical",
            L"EOL-Windows-XP",
            L"Windows XP -- extended support ended April 2014; no security patches in 11+ years",
            L"https://learn.microsoft.com/en-us/lifecycle/products/windows-xp");
    }
    if (sawWinMajor == 5 && sawWinMinor == 2) {
        add(out, kCrit, L"critical",
            L"EOL-Server-2003",
            L"Windows Server 2003 -- extended support ended July 2015; no security patches",
            L"https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003-r2");
    }
    if (sawWinMajor == 6 && sawWinMinor == 0) {
        add(out, kHigh, L"high",
            L"EOL-Windows-Vista",
            L"Windows Vista / Server 2008 -- extended support ended Apr 2017 (client) / Jan 2020 (server)",
            L"https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008");
    }
    if (sawWinMajor == 6 && sawWinMinor == 1) {
        add(out, kHigh, L"high",
            L"EOL-Windows-7",
            L"Windows 7 / Server 2008 R2 -- extended support ended Jan 2020 (ESU through Jan 2023)",
            L"https://learn.microsoft.com/en-us/lifecycle/products/windows-7");
    }
    if (sawWinMajor == 6 && (sawWinMinor == 2 || sawWinMinor == 3)) {
        add(out, kMed, L"medium",
            L"EOL-Windows-8",
            L"Windows 8 / 8.1 / Server 2012 / 2012 R2 -- extended support ended October 2023",
            L"https://learn.microsoft.com/en-us/lifecycle/products/windows-8");
    }

    (void)sawSmb1;    // already enrolled via SMB1 rule above
    (void)sawEsxiAny; // reserved for future generic ESXi advisories
}

// ---------------------------------------------------------------------------
// Format Findings to the TAB-line layout the GUI / report consumer parses.
// ---------------------------------------------------------------------------

std::wstring serialize(std::vector<Finding> findings) {
    // Stable sort by severity rank (critical < high < medium < low).
    std::stable_sort(findings.begin(), findings.end(),
                     [](const Finding& a, const Finding& b) {
                         return a.rank < b.rank;
                     });
    std::wstring out;
    for (const auto& f : findings) {
        if (!out.empty()) out += L"\n";
        out += f.severity;
        out += L"\t";
        out += f.id;
        out += L"\t";
        out += f.title;
        out += L"\t";
        out += f.url;
    }
    return out;
}

}  // namespace

void SecurityAdvisor::analyze(ScanResult& host) {
    host.securityFindings.clear();
    if (!host.isOnline) return;

    std::vector<Finding> findings;
    findings.reserve(8);
    applyRules(host, findings);
    if (findings.empty()) return;

    host.securityFindings = serialize(std::move(findings));
}

}  // namespace lanscope
