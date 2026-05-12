# NetLens

**Portable LAN scanner & host monitor for small business networks.**
Native Windows · C++20 · Single `.exe` · No installer · No telemetry · No cloud.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.txt)
[![Platform: Windows 10/11 x64](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20x64-0078D6)](https://3389.ro/tools/netlens)
[![Latest: 1.2.0](https://img.shields.io/badge/Latest-1.2.0-B4E04A)](https://github.com/3389ro/netlens/releases/latest)

Maintained by [3389 Software Outsourcing](https://3389.ro). Open source under the MIT License — see [`LICENSE.txt`](LICENSE.txt) for terms and [`NOTICE.txt`](NOTICE.txt) for third-party attributions (IEEE OUI registry).

**Latest binary:** [Releases page](https://github.com/3389ro/netlens/releases/latest) → `NetLens.exe`
**Product page:** [3389.ro/tools/netlens](https://3389.ro/tools/netlens)

---

## What it does

NetLens is a small, modern, native-Windows alternative for **IT admins, consultants and small businesses** who need a fast LAN sweep and a clean report to attach to an email — without dragging in a full security-audit toolchain or a vendor's installer.

It is **not** a vulnerability scanner. It maps your subnet, sees who's there, sees what's exposed, and produces a consultant-quality HTML report. That's it.

---

## Features

- **Adapter auto-detection** — picks up every Ethernet / Wi-Fi IPv4 adapter via `GetAdaptersAddresses`, suggests a scan range from the on-link prefix, and warns about big ranges (>1024 hosts).
- **Flexible IP ranges** — `192.168.1.1-254`, `192.168.1.10-192.168.1.50`, or `192.168.1.0/24`.
- **Three scan modes** — Deep (default), Fast, Discovery-only.
- **Five port presets** plus Custom.
- **Host discovery** — ICMP ping with **TCP fallback** so hosts that block ping still get found.
- **Concurrent TCP port scanning** — non-blocking `connect()` + `select()` across all ports in a batch.
- **Reverse DNS** — `GetNameInfo` with PTR records, hard-capped at 800 ms per host.
- **MAC lookup + vendor identification** — `SendARP` for local-subnet hosts, then the embedded IEEE OUI registry (~52,790 entries across MA-L / MA-M / MA-S) resolves the vendor name. Vendor-detected hosts also get **per-vendor port-priority profiles** (Dahua / Hikvision / VMware / MikroTik / Cisco / Synology / printers / NAS / IoT / …) so vendor-typical services scan first.
- **UDP service enrichment (v1.2.0)** — six parallel service-specific UDP probes per online host (NetBIOS 137, mDNS 5353, SSDP 1900, SNMP 161, DNS-version 53, NTP 123). Catches IoT, printers, NAS, VoIP, network gear that TCP-only scanning typically misses. NetBIOS name feeds a Hostname fallback when reverse DNS is empty. Disable per scan with `--no-udp` or via Tools → Settings; auto-disabled for ranges > 1024 hosts.
- **Risk hints** — coarse exposure analysis (None / Low / Medium / High) with explicit hint text. Never claims a confirmed vulnerability.
- **CSV export** — UTF-8 with BOM, RFC-4180 escaped, opens cleanly in Excel.
- **HTML export** — single file, embedded CSS, no CDN. Results sorted by risk.
- **GUI + CLI in one binary** — double-click for the GUI, or pass arguments for headless / scripted scans.
- **Parallel scanning** — thread pool with configurable concurrency (default 256).
- **Safe cancellation** — Stop at any time; partial results remain valid.
- **No telemetry, no cloud, no auto-update, no registry writes, no installer, no admin rights.**

---

## Scan modes

| Mode | ICMP-online hosts | ICMP-silent hosts |
|---|---|---|
| **Deep** *(default)* | Full TCP scan + DNS + MAC | Full TCP scan against the configured port list. Catches Windows boxes that block ICMP echo (SMB default) and devices that drop ICMP on purpose. |
| **Fast** | Full TCP scan + DNS + MAC | Probe only 20 discovery ports. If any answers, mark online via TCP fallback; otherwise mark offline. |
| **Discovery-only** | DNS + MAC only — no TCP | Marked offline. |

---

## Port presets

| Preset | Ports |
|---|---|
| **Quick LAN Scan** *(default)* | 80, 443, 445, 3389 |
| Windows Exposure | 135, 139, 445, 3389, 5985, 5986 |
| Remote Access | 22, 23, 3389, 5900, 5901, 5985, 5986 |
| Web Devices | 80, 443, 8080, 8443, 8000, 8888 |
| Full Common | 20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9200, 9300 |
| Custom | Whatever you type in the Ports field |

---

## CLI usage

Same `NetLens.exe` becomes a CLI when scan arguments are present.

```text
NetLens.exe --help
NetLens.exe --list-adapters
NetLens.exe --range 192.168.6.1-254 --preset quick
NetLens.exe --range 192.168.6.0/24 --mode deep --csv report.csv --html report.html
NetLens.exe --range 192.168.6.1-254 --no-dns --no-udp --online-only
```

| Flag | Default | Description |
|---|---|---|
| `--range <expr>` | — | `a.b.c.d-n`, `a.b.c.d-a.b.c.d`, or `a.b.c.d/n`. |
| `--adapter <index>` | — | Use the suggested range from the given adapter index. |
| `--preset <id>` | `quick` | `quick`, `windows`, `remote`, `web`, `common`. |
| `--mode <id>` | `deep` | `fast`, `deep`, `discovery`. |
| `--ports <csv>` | — | Custom ports, overrides `--preset`. |
| `--timeout <ms>` | `400` | Per-probe timeout. Clamped to `[50, 10000]`. |
| `--parallel <n>` | `256` | Max concurrent host probes. Clamped to `[1, 1024]`. |
| `--csv <path>` | — | Write CSV. |
| `--html <path>` | — | Write HTML. |
| `--online-only` | off | Skip offline hosts in output / reports. |
| `--no-dns` | off | Disable reverse DNS. |
| `--no-mac` | off | Disable MAC lookup. |
| `--no-udp` | off | Disable UDP service probes. |
| `--allow-large-range` | off | Permit ranges above 65,535 hosts. |

Exit codes: `0` success · `1` invalid arguments · `2` scan error · `3` export error.

---

## Build from source

Requires Visual Studio 2022 Build Tools (or full IDE) and CMake 3.20+.

```bat
build-release.bat
```

The script configures and builds in `build\` and emits `build\Release\NetLens.exe`. The `build\` directory is intentionally not committed — it's intermediate MSVC output (~57 MB).

Verify the binary against the SHA-256 sidecar published on the [Releases page](https://github.com/3389ro/netlens/releases) with:

```powershell
Get-FileHash NetLens.exe -Algorithm SHA256
```

---

## Repository layout

```
netlens/
├── README.md            ← you are here
├── CHANGELOG.md         ← version-by-version notes
├── LICENSE.txt          ← MIT
├── NOTICE.txt           ← third-party attributions (IEEE OUI registry)
├── SECURITY.md          ← reporting a security issue
├── CONTRIBUTING.md      ← how to contribute
├── CMakeLists.txt
├── build-release.bat
├── src/                 ← C++ sources
└── tools/               ← OUI data generation helpers
```

Versions are tracked through Git tags (`v1.0.8`, `v1.1.0`, …, `v1.2.0`). Each tag has a corresponding [GitHub Release](https://github.com/3389ro/netlens/releases) with the binary, SHA-256 sidecar and release notes.

---

## Built by

[3389 Software Outsourcing](https://3389.ro) — senior-level custom software, IT infrastructure and data platforms. Bucharest, Romania.

NetLens is a free, open-source tool. If your team needs a customised variant (different protocols, custom report layout, on-prem integration, branded output, embedded use inside a larger product), [get in touch](https://3389.ro/contact).
