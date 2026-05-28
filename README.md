# NetLens

**Portable LAN scanner for small business networks.**
Native Windows · C++20 · Single `.exe` · No installer · No telemetry · No cloud.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.txt)
[![Platform: Windows 7 → 11 x64](https://img.shields.io/badge/Platform-Windows%207%20%E2%86%92%2011%20x64-0078D6)](https://3389.ro/tools/netlens)
[![Latest: 1.5.13](https://img.shields.io/badge/Latest-1.5.13-B4E04A)](https://github.com/3389ro/netlens/releases/latest)

Maintained by [3389 Software Outsourcing](https://3389.ro). Open source under
the MIT License — see [`LICENSE.txt`](LICENSE.txt) for terms and
[`NOTICE.txt`](NOTICE.txt) for third-party attributions (IEEE OUI registry).

**Latest binary:** [Releases page](https://github.com/3389ro/netlens/releases/latest) → `NetLens.exe`
**Product page:** [3389.ro/tools/netlens](https://3389.ro/tools/netlens)

---

## What it does

NetLens maps your subnet, identifies who's on it, identifies what's exposed,
and produces a consultant-quality HTML report. It is built for **IT admins,
consultants and small businesses** who want a fast LAN sweep and a clean
deliverable to attach to an email — without dragging in a full security-audit
toolchain or a vendor's installer.

NetLens is **not** a vulnerability scanner. It enumerates hosts and surfaces
exposure hints; it never asserts a confirmed CVE on any host.

---

## Highlights (1.5)

- **One 2.5 MB self-contained .exe.** Native Win32 + GDI. Static CRT —
  no `vcruntime` / `msvcp` DLL dependency. PerMonitorV2 DPI awareness.
  Loads on Windows 7 / 8 / 8.1 / 10 / 11 / Server 2012+.
- **Security findings.** Curated CVE / EOL heuristics derived from
  observable banners, fingerprints and version hints — surfaced in the
  details pane and the HTML report. Heuristic hints, never a confirmed CVE.
- **Device Type + exact Model.** A dedicated Model column (grid, HTML and
  CSV) reads the precise model only from manufacturer-driven, read-only
  endpoints — HPE iLO, TP-Link, MikroTik RouterOS, VMware ESXi, Ubiquiti,
  Netgear, Yealink, Synology / Thecus — and never shows a raw page title.
- **SMB dialect + shares.** Direct SMB negotiation reports SMB 1.0 / 2.x /
  3.x, with anonymous share enumeration where the host permits it.
- **Live host grid.** Sortable on every column; selection follows the
  IP across mid-scan re-sorts and end-of-scan reshuffles.
- **Eight UDP discovery probes** per online host (Full Common preset
  and above): NBNS / NTP / SSDP / mDNS / SQL Browser / DNS / LLMNR /
  IPMI. One shared `select()` loop with a 600 ms global budget; source-
  IP-verified responses (drops LAN spoofs).
- **Printer SNMP.** SNMPv2c Printer-MIB walker reports vendor + model
  + serial + per-cartridge supply levels with colour-coded progress
  bars. Surfaces both in the GUI and in the HTML report.
- **Real-time pill state.** Ready · Scanning X% · Cancelling… ·
  Cancelled · X% · Done · Error.
- **Per-host details pane.** Identity / inferred OS + device hint /
  web-UI brand / open TCP ports + service + version annotation / UDP
  discovery responses / risk hints / recommended actions. Each field
  has a copy affordance, plus a single "Copy report" button that
  emits a plain-text block ready to paste into a ticket.
- **HTML export.** Single self-contained file (embedded CSS, no
  CDN). Offline hosts hidden by default with an inline note;
  per-printer supply cards; per-host UDP discovery cards.
- **CSV export** with the same data, UTF-8 BOM, RFC-4180-escaped.
- **No telemetry, no cloud, no auto-update, no registry writes, no
  installer, no admin rights, no `%APPDATA%` footprint.**

---

## Scan modes

| Mode | ICMP-online hosts | ICMP-silent hosts |
|---|---|---|
| **Deep** *(default)* | Full TCP scan + DNS + MAC + service fingerprint | Full TCP scan against the configured port list. Catches Windows boxes that block ICMP echo (SMB default) and devices that drop ICMP on purpose. |
| **Fast** | Full TCP scan + DNS + MAC | Probe only 26 discovery ports. If any answers, mark online via TCP fallback; otherwise mark offline. |
| **Discovery-only** | DNS + MAC only — no TCP | Marked offline. |

---

## Port presets

| Preset | Ports |
|---|---|
| **Quick** | 61 ports — fastest, web + remote-access + common shares |
| **Standard** *(default)* | 132 ports — daily LAN inventory |
| **Full Common** | 231 ports — adds DB / mgmt / VoIP / IoT / dev tooling |
| **All Ports — Fast** | 1 – 65535 (Fast mode) |
| **All Ports — Deep** | 1 – 65535 (Deep mode) |
| **Custom** | Whatever you type into the toolbar's Ports box |

UDP discovery runs on **Full Common / All Ports / Custom** presets.
Printer SNMP runs on all presets except **Quick** (it stops at the
sysDescr GET so vendor + model still come through; the `prtMarkerSupplies`
walk is skipped).

---

## Repo layout

```
NetLens/
├── CHANGELOG.md
├── CMakeLists.txt
├── LICENSE.txt
├── NOTICE.txt
├── README.md
├── SECURITY.md
├── VERSION                          ← single source of truth (1.5.13)
├── app.manifest
├── app.rc
├── build.ps1                        ← one-shot Configure + Build
├── docs/
│   └── ARCHITECTURE.md
├── engine/                          ← C++ scan engine (static lib)
│   ├── CMakeLists.txt
│   ├── include/
│   │   └── netlens_engine.h         ← C ABI surface
│   └── src/
│       ├── ffi.cpp
│       ├── core/                    ← NetworkScanner, PortScanner,
│       │                              EnrichmentEngine, WebUiProbe, …
│       └── …
├── resources/
│   ├── app.ico
│   └── 3389-logo.bmp
├── src/                             ← Native Win32 UI
│   ├── App.cpp / App.h              ← engine bridge + filter / sort state
│   ├── MainWindow.cpp / .h
│   ├── Theme.cpp / .h
│   ├── Dpi.cpp / .h                 ← runtime-resolved DPI helpers
│   ├── Capture.cpp / .h             ← Ctrl+T full-UI screenshot
│   ├── Controls/                    ← StatCard, HostTable, DetailsPanel
│   └── Dialogs/                     ← About, Settings, Adapters, PortLists
└── tools/                           ← dev helpers (PowerShell)
```

---

## Build

Prerequisites:

- Visual Studio 2022 (Desktop development with C++) or the matching
  Build Tools (`cl.exe` on PATH).
- CMake 3.20+.

One-shot Release build:

```powershell
.\build.ps1
```

Output:

```
build\bin\Release\NetLens.exe        ~2.5 MB
```

If `Z:\Release` exists the script also copies a versioned mirror as
`Z:\Release\NetLens_<version>.exe`.

---

## License

MIT — see [`LICENSE.txt`](LICENSE.txt). Third-party attributions in
[`NOTICE.txt`](NOTICE.txt) (IEEE OUI registry, Windows system APIs).
