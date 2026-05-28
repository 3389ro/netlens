# NetLens — Changelog

All notable changes to the project, version by version. Each entry maps to
the matching tag and `release/<version>/NetLens.exe` binary on the
[Releases page](https://github.com/3389ro/netlens/releases).

## [1.5.14] — 2026-05-28

### Fixed

- Deep / All-Ports scans no longer appear to restart: the full sweep builds on the initial discovery (open ports, services, SMB shares, printer supplies and security findings are preserved), the scan duration no longer resets, and the sweep skips the ports discovery already covered.
- Custom Ports: the port-entry box now appears immediately when the preset is selected, with an inline format hint (e.g. `22,80,443,8000-8100`).

## [1.5.13] — 2026-05-28

**Theme: deeper device fingerprinting, security findings, and large-scan stability.**

This release adds a security-findings layer, much richer device
identification (including a dedicated Model column), and a round of
performance and reliability work for large ranges and long-running scans.

### Added

- **Security findings** panel with curated CVE / EOL heuristics derived from
  observable service banners, fingerprints and version hints. Surfaced in the
  details pane and the HTML report.
- **SMB dialect detection** through direct SMB negotiation, covering SMB 1.0 /
  2.x / 3.x, plus **anonymous SMB share enumeration** when the host permits it.
- **Printer enrichment over SNMP**: vendor / model / serial, per-cartridge
  supply levels with colour-coded progress bars, and lifetime page / scan
  counters. Label printers that keep SNMP disabled are read over native
  **Zebra SGD (TCP 9100)** for model, firmware and odometer.
- **Device fingerprinting** for Roborock / Xiaomi, Ubiquiti / UniFi,
  VMware ESXi, HPE iLO, Netgear switches, Yealink phones, Thecus / Synology
  NAS and TP-Link / MikroTik routers.
- **Model column** in the host grid, HTML report and CSV export — with
  Device Type and exact Model shown as separate fields.
- **Exact model / version reading** for selected device classes from
  read-only, unauthenticated endpoints: HPE iLO product + firmware
  (`/xmldata`), TP-Link business routers (LuCI locale API), MikroTik RouterOS
  version, and the VMware ESXi build.

### Improved

- **Faster useful results on large ranges** (/22–/20): local-subnet priority,
  gateway / scout ordering, and dynamic promotion of subnets that show signs
  of life — so populated segments surface first.
- **Responsive UI on big scans**: an O(1) result accumulator and repaint
  throttling keep the grid fluid with thousands of online hosts; grid and
  details-panel scrolling, KPI updates and selection stay stable during live
  updates, with selection following the host's IP across mid-scan re-sorts
  and the end-of-scan reshuffle.
- **More accurate classification** by separating Device Type from exact Model,
  backed by a strict, manufacturer-driven model resolver that never presents a
  raw or placeholder web-page title as a model.
- **Broader Full Common coverage** for common admin, printer, IoT, VPN, MFT
  and web-management ports.
- **Faster Stop** on slow, firewalled or VPN hosts.

### Fixed

- Several scan-engine stability issues around DNS-worker limits, snapshot
  back-pressure, cancel handling, restart and result-clearing races, and
  thread-creation / shutdown safety.
- Removed an incorrect "critical" SMB1 / EternalBlue finding that could fire on
  ordinary SMB 2.1 hosts (Windows 7 / Server 2008 R2 / 2012 and many NAS
  devices).
- Removed incorrect printer classification on HPE iLO and server / switch
  hardware.
- Stopped misleading model strings sourced from placeholder web titles or
  generic HTTP server headers.
- Corrected Ubiquiti model handling so a device SKU no longer leaks into the
  Hostname field, and made UDP discovery retries more reliable.
- Hardened report and export safety: HTML escaping across every field, a CSV
  formula-injection guard, and codepoint-safe UTF-8 handling at the engine
  boundary.

### Notes

- All fingerprinting is **read-only and defensive**: no brute force, no exploit
  attempts, no configuration changes.
- Security findings are **heuristic** indicators based on banners, service
  fingerprints and observable version hints — they show where to look, not
  proof of exploitability.
- Single self-contained x64 `.exe`: static CRT, no installer, no registry or
  `%APPDATA%` writes, no telemetry.

## [1.3.0] — 2026-05-26

**Theme: native Win32 rewrite + scan-engine fork.**

NetLens 1.3 is a from-scratch native Win32 UI sitting on an updated
scan engine. The application is now a single 2.5 MB statically-linked
`NetLens.exe` (LTCG / static CRT) with PerMonitorV2 DPI awareness and
zero runtime dependencies. Engine and UI live in the same tree
(`engine/`, `src/`) and link as one binary.

### UI

- **New shell.** Native Win32 + GDI. Custom-painted brand bar, toolbar,
  status bar and KPI cards; native `SysListView32` host grid; custom
  details panel with a draggable splitter. PerMonitorV2 DPI manifest;
  a `kForce96Dpi` opt-in for compact 4K rendering.
- **Real-time scan view.** Live host grid + per-row open-port deltas
  during the sweep, throttled to ~10 Hz to keep selection stable. Sort
  on any column survives mid-scan snapshots; selection follows the IP
  rather than the row index so re-sorts and end-of-scan re-shuffles
  preserve the user's pick.
- **Three-state toolbar.** Start → red Cancel → red disabled
  "Cancelling…" while engine workers wind down → back to Start. The
  "Cancelling…" mid-state bridges the ~400 ms window between
  `nl_scanner_cancel()` and the workers actually returning, so a
  follow-up Start click can't race the engine.
- **Status pill states.** Ready / Scanning · X% / Cancelling… /
  Cancelled · X% / Done / Error. The cancel percent is captured once
  on the first ESC and frozen — repeated ESCs are no-ops.
- **Filter row.** Filter dropdown · search box · live "X of Y hosts"
  chip. View-menu toggle for offline hosts. Search matches IP /
  hostname / vendor / ports / service.
- **Per-host details pane.** Action bar (Ping / Browser / RDP / SSH /
  Copy report — Telnet/VNC moved to right-click), then IDENTITY,
  INFERRED, PRINTER SUPPLIES (when applicable), OPEN TCP PORTS,
  SECURITY FINDINGS, RECOMMENDED ACTIONS, UDP DISCOVERY. Each field
  has a copy affordance.
- **About dialog rewrite.** Real `IDI_NETLENS` icon (the same artwork
  shown in title bar / taskbar), 5 bullets of "what it won't do",
  3389 publisher card, MIT license line, hot URL.
- **Port Lists dialog.** Summary listview at top (5 rows: Preset /
  Ports / Extra probes / Description), detail card below showing the
  selected preset's full port → service breakdown. One copy button
  that always targets the current selection.
- **Settings / Adapters / About** all close on ESC. Ctrl+T captures a
  full PNG sweep of every visible top-level window (main + dialogs);
  black-screenshot fallback via `BitBlt` from screen DC when
  `PrintWindow` doesn't drive the destination DC on double-buffered
  paint paths.

### Engine

- **Forked in-tree** under `engine/` as a static library with a C ABI
  in `engine/include/netlens_engine.h`. Same engine could be consumed
  by any other C-ABI binding.
- **UDP discovery widened from 6 to 8 probes:** NBNS / NTP / SSDP /
  mDNS / SQL Browser / DNS version.bind / LLMNR / IPMI (RMCP ASF
  Ping/Pong). One shared `select()` loop with a 600 ms global budget;
  source-IP-verified responses (drops LAN spoofs).
- **Printer SNMP module (new).** Minimal SNMPv2c BER client in
  `SnmpClient.cpp`; printer-specific walker in `PrinterSnmpScanner.cpp`
  reads sysDescr / sysName / serial + walks `prtMarkerSupplies` for
  per-cartridge level + colour + description. Surfaces as a PRINTER
  SUPPLIES section in the GUI and as its own card in the HTML report.
- **Enrichment overhaul.** Vendor → device classification rewritten:
  - `win-` hostname is no longer a standalone Windows-PC signal (was
    misclassifying WinCC / Wincor-Nixdorf / generic service hosts).
  - TP-Link removed from camera-vendor list (was misclassifying
    routers as IP cameras).
  - IPP/CUPS port 631 alone no longer flags Printer (Linux / Mac with
    shared printing exposes 631).
  - Netgear-specific switch detection (no router-shape ports +
    management triad → switch, not router).
  - 3CX PBX detection from hostname / web-UI brand signals.
  - Synology-NAS guard against the Samba-NetBIOS → Windows-PC override.
  - Android-ADB rule matches plain `"google"` instead of `"google,"`.
  - Hostname device-hint rules anchored at start / `-` boundaries —
    `nest`, `echo`, `hp-`, `epson`, `canon` no longer match anywhere
    in the string.
- **Version annotator extended:** OpenSSH through 9.7 (incl. pre-
  regreSSHion CVE-2024-6387 marker), nginx 1.20–1.27 buckets, Apache
  CVE-2021-41773 narrowed to 2.4.49 / 2.4.50 only.
- **VendorShortener** filled out: Sonos, Netgear, D-Link, Brother,
  Canon, Epson, Lexmark, Kyocera, Ricoh, Konica Minolta, Samsung, LG,
  Zyxel, Fortinet, Juniper, Google, Amazon, Sony, Dell, Lenovo,
  Raspberry Pi, Espressif, Nordic, QNAP — alongside the existing HPE /
  HP / Cisco / Apple / Microsoft / Hikvision / Dahua / TP-Link /
  MikroTik / Xerox / Xiaomi / ASUS / Intel / Realtek / Synology /
  Ubiquiti set.
- **Device-hint coverage:** Roku, Chromecast, eero, UniFi AP /
  controller, Ring doorbell / camera, Tesla wall connector / Powerwall.
- **WebUiProbe:** HTTP → HTTPS scheme guard on JS redirects (was
  sending TLS handshake to the original plain-HTTP socket); extended
  fallback probe order to cover PBX / NAS / iLO / dev-admin ports;
  brand extraction tightened.

### Engine reliability (from internal + external audits)

- **FFI restart race fixed.** `nl_scanner_start` used to check only the
  FFI's `running` flag, which flips false inside the `onFinished`
  callback; the engine's internal `running_` only clears when the
  driver thread fully exits. Both are now consulted on start and on
  `is_running`.
- **`nl_scanner_clear_results` is no longer racy.** `engine.cancel()`
  just sets a flag — workers can keep firing `onHost` callbacks for
  up to `timeoutMs`, which used to repopulate `results` AFTER the
  clear. The FFI now refuses to clear while a scan is running.
- **Progress no longer jumps to 100 % on Cancel.** The final
  `onProgress` flush reports the real `doneCount` on cancel instead
  of unconditionally `total`.
- **UTF-8 truncation respects codepoint boundaries.** `copyUtf8` used
  to cut at the byte cap regardless of multibyte sequences, producing
  stray continuation bytes (and replacement characters in the UI) at
  the tail of long vendor strings.
- **UDP discovery survives transient `select()` errors** — only a
  zero return (timeout) ends the batch loop; negative-return errors
  are retried until the deadline.
- **ProgressThrottle CAS-loser retries** instead of dropping its
  update — eliminates momentary progress stalls under heavy
  parallelism.
- **SNMP OID decoder** handles multi-byte first sub-id correctly
  (malformed peers with the high bit set on `p[0]` no longer
  produce nonsense first-arc values).
- **PortScanner counter** only increments per port that actually
  produced a probe outcome — invalid port numbers and socket-creation
  failures no longer push the displayed total past the estimate.
- **DNS reverse-lookup workers** capped at 16 concurrent detached
  threads (was unbounded — a /24 against a misconfigured resolver
  used to spawn 250+ threads that linger 5–30 s after scan end).
- **NBNS hostname promotion** from UDP discovery actually works again.
  The promotion code was still searching for the old `"NBNS: "` colon
  prefix instead of the tab-separated format, so NBNS-only hosts had
  empty hostnames despite the data being right there in
  `udpDiscovery`.
- **SNMP cancel responsiveness** improved: default per-call timeout
  reduced from 800 ms to 500 ms; combined with workers checking
  cancel between GETNEXT iterations the worst-case cancel-to-idle
  latency on unresponsive printers is now ~1 s.

### Reports

- **HTML report redesign.** Offline hosts hidden by default with an
  inline note ("N offline hosts not listed"); KPI cards re-balanced
  to Online hosts / RDP / SMB / Web / Duration; header trimmed to 6
  fields (Scan date / Range / Adapter / Preset / Duration / Status);
  Risk column and Risk legend removed; new sections for Printer
  supplies (per-cartridge progress bars in cartridge colour) and
  UDP discovery (per-host card with port / service / detail table);
  section headings carry a small left-bar accent in the brand blue.
- **CSV export** unchanged from 1.2 except for the printer / UDP
  columns that now reflect engine v1.3 data.

### Platform / build

- **Windows Server 2012 / Windows 7 / 8 / 8.1 compatibility.** All
  Win10-only user32 exports (`GetDpiForWindow`, `GetDpiForSystem`,
  `SetProcessDpiAwarenessContext`, `SystemParametersInfoForDpi`)
  resolved via `GetProcAddress` at runtime, with documented fallback
  tiers (Win 8.1 shcore → Vista+ legacy). Binary loads cleanly on
  legacy Windows; previously the static import table would refuse to
  load.
- **Single self-contained 2.5 MB executable.** Static CRT (no
  `vcruntime` / `msvcp` DLL dependency), LTCG / `/OPT:ICF` /
  `/OPT:REF`, no installer, no registry writes, no `%APPDATA%`
  footprint.
- **MIT License** preserved.

### Removed

- The old GUI shell (replaced by the native Win32 UI).
- `cli/` standalone CLI subsystem — the GUI is the only entry point in
  1.3. The engine still exposes the full scan API via its C ABI for
  any consumer that needs scripted scans.
- HostMonitor / BaselineStore from the runtime path — code still
  compiled in the engine but no UI surface in 1.3.

## [1.2.0] — 2026-04-12

**Theme: UDP service enrichment.**

Six parallel UDP probes per online host — NetBIOS 137, mDNS 5353, SSDP 1900,
SNMP 161, DNS-version 53, NTP 123 — surface the services TCP-only scanners
miss. NetBIOS name now feeds a Hostname fallback when reverse DNS is empty.
Risk model picks up SNMP-`public` reads (Medium), UPnP and NetBIOS exposure
(Low). New CSV columns and a UDP section in the HTML report. Auto-disabled
for ranges above 1024 hosts.

## [1.1.2] — 2026-03-15

**Theme: licence-clean OUI source.**

OUI registry swapped to the IEEE Registration Authority's public CSV
registries (MA-L, MA-M, MA-S) — ~52,790 entries, free public use, no
attribution required. The previous source carried a copyleft licence; the
new one is unencumbered, so it can be bundled directly into the binary.
Generator script rewritten for IEEE's tab / CSV format. Vendor port-priority
profiles unchanged (they hit IEEE-formal organisation names already).

## [1.1.1] — 2026-02-25

**Theme: richer OUI, vendor port-priority, preset manager.**

OUI database upgraded to 57,140 entries. New `VendorPortProfiles` module:
video surveillance, MikroTik, VMware, NAS, printers, server BMC, Ubiquiti,
Cisco, VoIP phones, Apple, smart-home IoT, ICS / SCADA — each gets a
tailored port order so vendor-typical services appear first. New
**Tools → Manage port presets** dialog (view, rename, edit, add, delete)
with in-memory edits per session.

## [1.1.0] — 2026-02-05

**Theme: project rename to NetLens.**

Binary now ships as `NetLens.exe`. Internal namespace renamed to
`netlens::`. Resource files renamed. APPDATA folder now
`%APPDATA%\NetLens\`. No functional changes — scan engine, risk model, GUI,
CLI, exports, baseline format and monitor logic are identical to v1.0.8.

## [1.0.8] — 2026-01-15

**Theme: review-driven hardening.**

Scan default flipped to Deep so Windows boxes that block ICMP no longer get
silently missed. Concurrency dropped from 2048 to 1024 to play nicely with
consumer-router rate-limits. Scanner-to-UI handoff is now strictly UI-thread
(heap payload + `PostMessage`). Cancelled-scan progress bug fixed. DNS
auto-off for ranges above 1024 hosts. HTML export shows scan state
explicitly with an amber banner for cancelled runs.
