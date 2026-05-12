# NetLens — Changelog

All notable changes to the project, version by version. Each entry maps to
the matching `src\<version>\` snapshot and `release\<version>\NetLens.exe`
binary.

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
