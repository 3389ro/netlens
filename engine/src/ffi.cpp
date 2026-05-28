// ffi.cpp — C ABI implementation for the NetLens scan engine.
//
// All public functions are declared in netlens_engine.h. This file
// contains the C++ → C bridge: it owns the scanner state, marshals
// std::wstring fields to UTF-8 buffers, and exposes the engine to the
// Win32 UI (or any other C-ABI consumer linking the static lib).

#include "../include/netlens_engine.h"

#include "AppConstants.h"
#include "Models.h"
#include "core/EnrichmentEngine.h"
#include "core/IpAddressUtils.h"
#include "core/IpRangeParser.h"
#include "core/LocalProcessResolver.h"
#include "core/NetworkAdapterService.h"
#include "core/NetworkScanner.h"
#include "core/ReportExporter.h"
#include "core/ScanPresetService.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

using namespace lanscope;

// ---------------------------------------------------------------------------
// Helpers — string conversion (wstring ↔ UTF-8).
// ---------------------------------------------------------------------------

namespace {

std::string wToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                       static_cast<int>(w.size()),
                                       nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                          static_cast<int>(w.size()),
                          out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring utf8ToW(const char* s) {
    if (!s || !*s) return {};
    int needed = ::MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (needed <= 1) return {};
    std::wstring out(static_cast<size_t>(needed - 1), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), needed);
    return out;
}

void copyUtf8(char* dst, int cap, const std::wstring& w) {
    if (!dst || cap <= 0) return;
    std::string s = wToUtf8(w);
    int n = static_cast<int>(s.size());
    if (n > cap - 1) {
        n = cap - 1;
        // We truncated. Only fix up the cut when it lands in the MIDDLE of a
        // multi-byte codepoint — i.e. the first DROPPED byte (s[n]) is a UTF-8
        // continuation byte (10xxxxxx). Then walk back over that codepoint's
        // bytes and drop it whole, so the decoder never sees a dangling
        // partial sequence. When the cut already sits on a codepoint boundary
        // (s[n] is ASCII or a lead byte) we keep everything as-is.
        //
        // The previous version ran this fix-up UNCONDITIONALLY, so a string
        // that fit completely but ended in a non-ASCII character (e.g. "Café")
        // had its last codepoint stripped ("Caf"). Keying off the dropped byte
        // — and only when truncation happened — avoids that.
        if ((static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) {
            while (n > 0 &&
                   (static_cast<unsigned char>(s[n - 1]) & 0xC0) == 0x80)
                --n;                       // back over continuation bytes
            if (n > 0 && static_cast<unsigned char>(s[n - 1]) >= 0xC0)
                --n;                       // drop the now-orphaned lead byte
        }
    }
    std::memcpy(dst, s.data(), static_cast<size_t>(n));
    dst[n] = '\0';
}

int  discoveryToInt(DiscoveryMethod m) {
    switch (m) {
        case DiscoveryMethod::None:        return 0;
        case DiscoveryMethod::Icmp:        return 1;
        case DiscoveryMethod::Arp:         return 2;
        case DiscoveryMethod::TcpFallback: return 3;
    }
    return 0;
}

int  riskToInt(RiskLevel r) {
    switch (r) {
        case RiskLevel::None:   return 0;
        case RiskLevel::Low:    return 1;
        case RiskLevel::Medium: return 2;
        case RiskLevel::High:   return 3;
    }
    return 0;
}

ScanMode modeFromInt(int v) {
    switch (v) {
        case 1: return ScanMode::Deep;
        case 2: return ScanMode::DiscoveryOnly;
        default: return ScanMode::Fast;
    }
}

// v1.3.4 — Gateway-first reordering for multi-/24 ranges.
// v1.3.6 — extended into a four-tier scheme. The reorder here arranges the
//          STATIC portion (tiers 1 + 2 — always scanned first, in order); the
//          DYNAMIC portion (tiers 4 + 3) is handled at scan time by the
//          PriorityWorkQueue in NetworkScanner, which promotes a /24 to the
//          front the moment any host in it responds. Execution order:
//
//   Tier 1: the local /24 (every host of the subnet the OS gateway is in).
//           Skipped when no gateway IP is provided.
//   Tier 2: scout candidates (.1 / .254 / .255) of every OTHER /24 — a fast
//           "is anything alive here?" probe across all sibling subnets.
//   Tier 4: (dynamic) the rest of any /24 whose tier-2 scout responded —
//           promoted ahead of the dead subnets as soon as the scout answers.
//   Tier 3: (dynamic) everything else — the long tail of silent subnets.
//
// This function lays out [tier1 | tier2 | rest] and returns the size of the
// (tier1 + tier2) prefix. That prefix becomes ScanOptions::priorityCount, the
// split point the work queue uses to separate "dispatch immediately, in
// order" from "dispatch by hotness". Single-/24 ranges return 0 (no tiering —
// the natural .1 → .254 order is already ideal and the cheap atomic path runs).
size_t prioritizeGatewayCandidates(std::vector<uint32_t>& addresses,
                                   uint32_t localGatewayHostOrder = 0) {
    if (addresses.size() < 2) return 0;

    // Count distinct /24 subnets (top 24 bits).
    std::vector<uint32_t> subnets;
    subnets.reserve(addresses.size());
    for (uint32_t ip : addresses) subnets.push_back(ip & 0xFFFFFF00u);
    std::sort(subnets.begin(), subnets.end());
    subnets.erase(std::unique(subnets.begin(), subnets.end()), subnets.end());
    if (subnets.size() < 2) return 0;   // single /24 — natural order is fine

    const uint32_t localSubnet24 = localGatewayHostOrder & 0xFFFFFF00u;
    const bool hasLocalSubnet = (localGatewayHostOrder != 0)
        && std::binary_search(subnets.begin(), subnets.end(), localSubnet24);

    // Tier 1 is anything in the local /24. Tier 2 is scouts (.1 / .254 / .255)
    // outside the local /24. Everything else is the dynamic remainder.
    auto isTier1 = [&](uint32_t ip) {
        return hasLocalSubnet && (ip & 0xFFFFFF00u) == localSubnet24;
    };
    auto isScout = [&](uint32_t ip) {
        if (hasLocalSubnet && (ip & 0xFFFFFF00u) == localSubnet24) return false;
        const uint32_t lastOctet = ip & 0xFFu;
        return lastOctet == 1u || lastOctet == 254u || lastOctet == 255u;
    };
    auto isPriority = [&](uint32_t ip) { return isTier1(ip) || isScout(ip); };

    // Two passes of stable_partition give us [tier1 | tier2 | rest]. Each
    // partition preserves the input order, which is ascending IP — so within
    // the local /24 we still scan .1 first (gateway), then .2, .3, etc.,
    // and the remainder stays sorted (so the queue can group it by /24).
    auto t1End = std::stable_partition(addresses.begin(), addresses.end(), isTier1);
    auto t2End = std::stable_partition(t1End, addresses.end(), isScout);
    return static_cast<size_t>(std::distance(addresses.begin(), t2End));
}

} // namespace

// ---------------------------------------------------------------------------
// Global init / shutdown.
// ---------------------------------------------------------------------------

// Serialise init/shutdown so the ref-count and WSAStartup/WSACleanup pairing
// are atomic as a unit. A bare atomic counter has a TOCTOU window — a second
// nl_init() could observe count>0 and return "ready" before the first
// WSAStartup() actually completed — and lets nl_shutdown() underflow below
// zero if called more times than nl_init(). This is a public C ABI, so make
// it correct for concurrent callers, not just the single-threaded UI.
static std::mutex g_initMu;
static int        g_initCount = 0;

extern "C" int nl_init(void) {
    std::lock_guard<std::mutex> lk(g_initMu);
    if (g_initCount == 0) {
        WSADATA wsa{};
        int rc = ::WSAStartup(MAKEWORD(2, 2), &wsa);
        if (rc != 0) return rc;        // stay at 0 — not initialised
    }
    ++g_initCount;
    return 0;
}

extern "C" void nl_shutdown(void) {
    std::lock_guard<std::mutex> lk(g_initMu);
    if (g_initCount > 0 && --g_initCount == 0) {
        ::WSACleanup();
    }
}

extern "C" const char* nl_engine_version(void) {
    // Mirror the AppConstants version. The wstring -> utf8 conversion runs
    // exactly once; the returned pointer is to a function-local static.
    static const std::string ver = wToUtf8(kAppVersion);
    return ver.c_str();
}

// ---------------------------------------------------------------------------
// Scanner — owns NetworkScanner + a thread-safe result accumulator.
// ---------------------------------------------------------------------------

struct nl_scanner {
    // ---- DECLARATION ORDER MATTERS — DO NOT REORDER ----
    //
    // The data members below are touched by NetworkScanner's worker-thread
    // callbacks (`onHost` locks `mu` and writes `results`; `onProgress`
    // writes `done`/`total`; `onFinished` locks `mu`, writes `results`,
    // `scan_finished` and `running`). Those callbacks run on worker
    // threads that the engine owns and only joins inside ~NetworkScanner.
    //
    // C++ destroys members in REVERSE declaration order. We therefore put
    // `engine` LAST so it is destroyed FIRST, which means its destructor
    // (which cancels + joins the driver/worker threads) completes before
    // the mutex, vector and atomics it references are destroyed. Any
    // other order is a use-after-destroy waiting to happen on
    // `nl_scanner_destroy` while a scan is still running. (Audit M5.18.)
    std::mutex                      mu;
    std::vector<ScanResult>         results;            // grows live during scan
    // IP -> index into `results`, kept in lockstep so the per-emit upsert is
    // O(1) instead of O(N). The engine fires onHost ~4-6x per online host, so
    // a linear scan was O(N^2) under `mu` on large ranges. Cleared/rebuilt
    // wherever `results` is cleared or wholesale-replaced.
    std::unordered_map<std::wstring, size_t> ipIndex;
    std::atomic<int>                done{0};
    std::atomic<int>                total{0};
    std::atomic<bool>               running{false};
    std::chrono::steady_clock::time_point scan_started{};
    std::chrono::steady_clock::time_point scan_finished{};

    // Must be LAST. ~NetworkScanner cancels + joins workers; while it
    // does so, the workers still need `mu` / `results` / atomics above
    // to exist.
    NetworkScanner                  engine;
};

extern "C" nl_scanner_t* nl_scanner_create(void) {
    return new (std::nothrow) nl_scanner_t();
}

extern "C" void nl_scanner_destroy(nl_scanner_t* s) {
    if (!s) return;
    s->engine.cancel();
    delete s;
}

extern "C" int nl_scanner_start(nl_scanner_t* s, const char* range,
                                const nl_scan_opts_t* opts) {
    if (!s || !range) return -1;
    // Two flags can disagree mid-shutdown: `s->running` flips false inside
    // the `onFinished` callback, but `engine.running_` only clears when
    // the driver thread actually exits (via RAII guard). A start during
    // that window used to succeed at the FFI level then silently no-op
    // inside `engine.start()`. Check both — caller retries cleanly.
    if (s->running.load() || s->engine.isRunning()) return -2;

    auto parsed = IpRangeParser::parse(utf8ToW(range), /*allowLarge=*/true);
    if (!parsed.ok || parsed.addresses.empty()) return -3;

    // v1.3.4 — For multi-/24 ranges, hoist typical gateway IPs (.1 / .254 /
    // .255) to the front of the work queue. v1.3.6 — additionally hoist the
    // entire /24 containing the OS's default gateway to the very front, so
    // the local LAN is scanned super-fast before any unrelated /24 in a
    // /20+ range. The returned prefix length feeds ScanOptions::priorityCount,
    // which switches executeScanLoop to the dynamic priority queue (responsive
    // sibling /24s jump ahead of dead ones). 0 = single-/24, no tiering.
    uint32_t gwHostOrder = 0;
    if (opts && opts->gateway_ip && opts->gateway_ip[0]) {
        if (auto parsedGw = ip::parseDotted(utf8ToW(opts->gateway_ip))) {
            gwHostOrder = *parsedGw;
        }
    }
    const size_t priorityCount =
        prioritizeGatewayCandidates(parsed.addresses, gwHostOrder);

    ScanOptions sop;
    sop.priorityCount    = priorityCount;
    sop.rangeText        = utf8ToW(range);
    sop.timeoutMs        = (opts && opts->timeout_ms       > 0) ? opts->timeout_ms       : kDefaultTimeoutMs;
    sop.parallel         = (opts && opts->parallel        > 0) ? opts->parallel         : kDefaultParallel;
    sop.mode             = (opts) ? modeFromInt(opts->mode) : ScanMode::Deep;
    sop.skipDns          = opts ? opts->skip_dns          : 0;
    sop.skipMac          = opts ? opts->skip_mac          : 0;
    sop.skipPorts        = opts ? opts->skip_ports        : 0;
    sop.skipFingerprint  = opts ? opts->skip_fingerprint  : 0;
    sop.skipClockDrift   = opts ? opts->skip_clock_drift  : 0;
    sop.skipUdpDiscovery = opts ? opts->skip_udp_discovery : 0;
    sop.skipPrinterSnmp  = opts ? opts->skip_printer_snmp  : 0;
    // wantPrinterSupplies defaults to true; the field flips to "false"
    // only when the caller explicitly sets want_printer_supplies = 0.
    sop.wantPrinterSupplies = opts ? (opts->want_printer_supplies != 0) : true;
    sop.fingerprintTimeoutMs = (opts && opts->fingerprint_timeout_ms > 0)
                              ? opts->fingerprint_timeout_ms
                              : kDefaultFingerprintTimeoutMs;
    if (opts && opts->gateway_ip)
        sop.gatewayIp    = utf8ToW(opts->gateway_ip);

    // Ports: prefer the explicit CSV if the caller provided one, else fall
    // back to the engine's "common" preset.
    if (opts && opts->ports_csv && *opts->ports_csv) {
        sop.ports = ScanPresetService::parsePortList(utf8ToW(opts->ports_csv));
    } else if (const auto* p = ScanPresetService::find(L"common")) {
        sop.ports = p->ports;
        sop.presetName = p->displayName;
    }

    {
        std::lock_guard<std::mutex> lk(s->mu);
        s->results.clear();
        s->ipIndex.clear();
    }
    s->done.store(0);
    s->total.store(static_cast<int>(parsed.addresses.size()));
    s->running.store(true);
    s->scan_started  = std::chrono::steady_clock::now();
    s->scan_finished = {};

    try {
    s->engine.start(
        parsed.addresses, sop,
        // onHost — upserts by IP. The engine fires this callback multiple
        // times per host as new info arrives (ICMP → ports → fingerprint
        // → risk → web-UI probe → risk analysis). We run
        // `EnrichmentEngine::finalize` on EVERY emit so the GUI sees the
        // shortened vendor ("TP-Link" not "TP-LINK TECHNOLOGIES CO.,LTD."),
        // the enhanced device label, and the brand-hint aggregate from the
        // FIRST frame the row appears — never the raw OUI string with a
        // later flicker to the short form. `finalize` is string-only work
        // plus a cached TCP-table lookup, so calling it 4× per host
        // (intermediate emits) costs <1 ms total.
        [s](const ScanResult& r) {
            ScanResult enriched = r;
            EnrichmentEngine::finalize(enriched);
            std::lock_guard<std::mutex> lk(s->mu);
            const std::wstring ip = enriched.ipAddress;   // key before move
            auto it = s->ipIndex.find(ip);
            if (it != s->ipIndex.end()) {
                s->results[it->second] = std::move(enriched);
            } else {
                s->ipIndex.emplace(ip, s->results.size());
                s->results.push_back(std::move(enriched));
            }
        },
        // onProgress — done/total counter.
        [s](int done, int total) {
            s->done.store(done);
            s->total.store(total);
        },
        // onFinished — flush summary, clear running flag.
        [s](bool /*cancelled*/, const ScanSummary& /*sum*/,
            const std::vector<ScanResult>& finalResults) {
            std::lock_guard<std::mutex> lk(s->mu);
            // Replace the live results with the final summary list so the
            // ordering matches the canonical scan output.
            s->results = finalResults;
            s->ipIndex.clear();   // upsert map not needed once results are final
            s->scan_finished = std::chrono::steady_clock::now();
            s->running.store(false);
        });
    } catch (...) {
        // Engine refused/aborted the start (e.g. OS thread-creation failure).
        // Don't let a C++ exception cross the C ABI, and don't leave the
        // scanner wedged in the "busy" state. NetworkScanner::start also
        // self-heals (clears running_ + fires onFinished), so this is the
        // belt-and-suspenders ABI guard.
        s->running.store(false);
        return -4;
    }

    return 0;
}

extern "C" void nl_scanner_cancel(nl_scanner_t* s) {
    if (s) s->engine.cancel();
}

extern "C" int nl_scanner_is_running(nl_scanner_t* s) {
    // Report busy until BOTH the FFI flag and the engine's internal flag
    // clear, so a poll right after `onFinished` doesn't briefly read idle
    // while the driver thread is still winding down.
    return (s && (s->running.load() || s->engine.isRunning())) ? 1 : 0;
}

extern "C" int nl_scanner_progress_done(nl_scanner_t* s) {
    return s ? s->done.load() : 0;
}

extern "C" int nl_scanner_progress_total(nl_scanner_t* s) {
    return s ? s->total.load() : 0;
}

extern "C" int64_t nl_scanner_probes_done(nl_scanner_t* s) {
    return s ? s->engine.probesDone() : 0;
}

extern "C" void nl_scanner_get_summary(nl_scanner_t* s, nl_summary_t* out) {
    if (!out) return;
    std::memset(out, 0, sizeof(*out));
    if (!s) return;
    std::lock_guard<std::mutex> lk(s->mu);
    out->total_scanned = static_cast<int32_t>(s->results.size());
    for (const auto& r : s->results) {
        if (r.isOnline) ++out->online_count;
        else             ++out->offline_count;
        switch (r.riskLevel) {
            case RiskLevel::High:   ++out->high_risk_count;   break;
            case RiskLevel::Medium: ++out->medium_risk_count; break;
            case RiskLevel::Low:    ++out->low_risk_count;    break;
            default: break;
        }
    }
    if (s->scan_started.time_since_epoch().count() != 0) {
        auto end = (s->scan_finished.time_since_epoch().count() != 0)
                   ? s->scan_finished
                   : std::chrono::steady_clock::now();
        out->duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               end - s->scan_started).count();
    }
}

extern "C" void nl_scanner_clear_results(nl_scanner_t* s) {
    if (!s) return;
    // Refuse to clear while a scan is running. `engine.cancel()` only
    // sets the cancel flag; workers may keep emitting `onHost` callbacks
    // for up to timeoutMs as their in-flight sockets unwind, and those
    // callbacks would repopulate `results` AFTER `results.clear()` ran
    // — producing rows that re-materialise the moment the user hit Clear.
    // Callers should cancel + wait for is_running to flip false before
    // clearing. (The void return is preserved for ABI stability; we just
    // no-op here.)
    if (s->running.load() || s->engine.isRunning()) return;

    std::lock_guard<std::mutex> lk(s->mu);
    s->results.clear();
    s->ipIndex.clear();
    s->done.store(0);
    s->total.store(0);
    s->scan_started  = {};
    s->scan_finished = {};
    // Drop the local-process snapshot too — between scans the user might
    // have started / stopped servers we'd otherwise mis-report.
    LocalProcessResolver::resetCache();
}

extern "C" int nl_scanner_export_csv(nl_scanner_t* s, const char* path) {
    if (!s || !path || !*path) return -1;
    std::vector<ScanResult> snapshot;
    {
        std::lock_guard<std::mutex> lk(s->mu);
        snapshot = s->results;
    }
    return ReportExporter::exportCsv(utf8ToW(path), snapshot) ? 0 : -2;
}

extern "C" int nl_scanner_export_html(nl_scanner_t* s, const char* path) {
    if (!s || !path || !*path) return -1;
    std::vector<ScanResult> snapshot;
    ScanSummary summary;
    {
        std::lock_guard<std::mutex> lk(s->mu);
        snapshot = s->results;
        summary.totalScanned  = static_cast<int>(snapshot.size());
        for (const auto& r : snapshot) {
            if (r.isOnline) ++summary.onlineCount;
            else             ++summary.offlineCount;
        }
        if (s->scan_started.time_since_epoch().count() != 0) {
            auto end = (s->scan_finished.time_since_epoch().count() != 0)
                       ? s->scan_finished
                       : std::chrono::steady_clock::now();
            summary.durationMs =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    end - s->scan_started).count();
        }
    }
    return ReportExporter::exportHtml(utf8ToW(path), snapshot, summary) ? 0 : -2;
}

extern "C" int nl_scanner_result_count(nl_scanner_t* s) {
    if (!s) return 0;
    std::lock_guard<std::mutex> lk(s->mu);
    return static_cast<int>(s->results.size());
}

extern "C" int nl_scanner_get_result(nl_scanner_t* s, int index, nl_result_t* out) {
    if (!s || !out) return -1;
    std::lock_guard<std::mutex> lk(s->mu);
    if (index < 0 || index >= static_cast<int>(s->results.size())) return -2;
    const ScanResult& r = s->results[static_cast<size_t>(index)];

    std::memset(out, 0, sizeof(*out));
    copyUtf8(out->ip,            sizeof(out->ip),            r.ipAddress);
    copyUtf8(out->hostname,      sizeof(out->hostname),      r.hostname);

    // Cached enrichment (v1.0.49) — `EnrichmentEngine::finalize` ran at the
    // end of scanOneHost and stored every display-ready string on the
    // ScanResult. This FFI call is now a pure struct copy: zero inference,
    // zero Win32 calls, no shared resolver locks.
    copyUtf8(out->vendor,        sizeof(out->vendor),
             r.vendorShort.empty() ? r.vendor : r.vendorShort);
    copyUtf8(out->mac,           sizeof(out->mac),           r.macAddress);
    copyUtf8(out->device_type,   sizeof(out->device_type),
             r.enhancedDeviceType.empty() ? r.deviceType : r.enhancedDeviceType);
    copyUtf8(out->device_model,  sizeof(out->device_model),  r.deviceModel);
    copyUtf8(out->open_ports,    sizeof(out->open_ports),    r.openPortsText());
    copyUtf8(out->services,      sizeof(out->services),      r.serviceSummary());
    copyUtf8(out->risk_hints,    sizeof(out->risk_hints),    r.riskHints);
    copyUtf8(out->brand_hint,    sizeof(out->brand_hint),    r.brandHint);
    copyUtf8(out->os_hint,       sizeof(out->os_hint),       r.osHintCached);
    copyUtf8(out->device_hint,   sizeof(out->device_hint),   r.deviceHintCached);
    copyUtf8(out->web_ui_model,  sizeof(out->web_ui_model),  r.webUiModel);
    copyUtf8(out->udp_discovery, sizeof(out->udp_discovery), r.udpDiscovery);
    out->is_printer = r.isPrinter ? 1 : 0;
    copyUtf8(out->printer_vendor,      sizeof(out->printer_vendor),      r.printerVendor);
    copyUtf8(out->printer_model,       sizeof(out->printer_model),       r.printerModel);
    copyUtf8(out->printer_serial,      sizeof(out->printer_serial),      r.printerSerial);
    copyUtf8(out->printer_snmp_status, sizeof(out->printer_snmp_status), r.printerSnmpStatus);
    copyUtf8(out->printer_supplies,    sizeof(out->printer_supplies),    r.printerSupplies);
    copyUtf8(out->printer_pages,       sizeof(out->printer_pages),       r.printerPages);
    copyUtf8(out->smb_shares,          sizeof(out->smb_shares),          r.smbShares);
    copyUtf8(out->iot_fingerprint,     sizeof(out->iot_fingerprint),     r.iotFingerprint);

    out->is_online       = r.isOnline ? 1 : 0;
    out->risk_level      = riskToInt(r.riskLevel);
    out->response_ms     = static_cast<int32_t>(r.responseTimeMs);
    out->discovery       = discoveryToInt(r.discovery);
    out->port_count      = static_cast<int32_t>(r.ports.size());
    out->service_count   = static_cast<int32_t>(r.fingerprints.size());
    out->clock_responded = r.clockDrift.responded ? 1 : 0;
    out->clock_offset_ms = r.clockDrift.offsetMs;
    copyUtf8(out->security_findings, sizeof(out->security_findings),
             r.securityFindings);
    return 0;
}

extern "C" int nl_scanner_format_report(nl_scanner_t* s, int index,
                                        char* out, int cap) {
    if (!s || !out || cap <= 0) return 0;
    std::lock_guard<std::mutex> lk(s->mu);
    if (index < 0 || index >= static_cast<int>(s->results.size())) {
        out[0] = '\0';
        return 0;
    }
    const ScanResult& r = s->results[static_cast<size_t>(index)];

    // Mirror the GUI's "Copy report" text exactly so both consumers agree.
    std::wstring w;
    w += L"Host: " + r.ipAddress + L"\r\n";
    if (!r.hostname.empty())   w += L"Hostname: "        + r.hostname + L"\r\n";
    w += L"Status: ";
    w += r.isOnline ? L"Online" : L"Offline";
    w += L"\r\n";
    w += L"Risk: ";
    w += RiskLevelToString(r.riskLevel);
    w += L"\r\n";
    if (!r.deviceType.empty()) w += L"Estimated device: " + r.deviceType + L"\r\n";
    if (!r.vendor.empty())     w += L"Vendor: "          + r.vendor + L"\r\n";
    if (!r.macAddress.empty()) w += L"MAC: "             + r.macAddress + L"\r\n";
    if (r.isOnline && r.responseTimeMs >= 0)
        w += L"RTT: " + std::to_wstring(r.responseTimeMs) + L" ms\r\n";

    if (!r.ports.empty()) {
        w += L"\r\nOpen ports:\r\n";
        for (const auto& p : r.ports) {
            if (!p.isOpen) continue;
            w += L"- " + std::to_wstring(p.port) + L"/tcp";
            if (!p.service.empty()) w += L" " + p.service;
            w += L"\r\n";
        }
    }
    if (!r.fingerprints.empty()) {
        w += L"\r\nDetected services:\r\n";
        for (const auto& f : r.fingerprints) {
            w += L"- ";
            w += f.product.empty() ? f.service : f.product;
            if (!f.version.empty()) w += L" " + f.version;
            if (!f.title.empty())   w += L" — " + f.title;
            else if (!f.detail.empty()) w += L" — " + f.detail;
            w += L"  [" + std::to_wstring(f.port) + L"/";
            w += f.protocol.empty() ? L"tcp" : f.protocol;
            w += L"]\r\n";
        }
    }
    if (!r.riskHints.empty()) {
        w += L"\r\nRisk hints:\r\n";
        std::wstring cur;
        for (wchar_t c : r.riskHints) {
            if (c == L',' || c == L';') {
                if (!cur.empty()) w += L"- " + cur + L"\r\n";
                cur.clear();
            } else if (c != L' ' || !cur.empty()) {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) w += L"- " + cur + L"\r\n";
    }

    std::string utf8 = wToUtf8(w);
    int n = static_cast<int>(utf8.size());
    int copy = n;
    if (copy > cap - 1) {
        copy = cap - 1;
        // Don't cut mid-codepoint (same rule as copyUtf8): if the first dropped
        // byte is a UTF-8 continuation byte, drop the whole partial codepoint.
        if ((static_cast<unsigned char>(utf8[copy]) & 0xC0) == 0x80) {
            while (copy > 0 &&
                   (static_cast<unsigned char>(utf8[copy - 1]) & 0xC0) == 0x80)
                --copy;
            if (copy > 0 && static_cast<unsigned char>(utf8[copy - 1]) >= 0xC0)
                --copy;
        }
    }
    std::memcpy(out, utf8.data(), static_cast<size_t>(copy));
    out[copy] = '\0';
    return n;   // full length so the caller can detect truncation / resize
}

extern "C" int nl_scanner_port_count(nl_scanner_t* s, int index) {
    if (!s) return 0;
    std::lock_guard<std::mutex> lk(s->mu);
    if (index < 0 || index >= static_cast<int>(s->results.size())) return 0;
    return static_cast<int>(s->results[static_cast<size_t>(index)].ports.size());
}

extern "C" int nl_scanner_get_port(nl_scanner_t* s, int index, int port_index,
                                   nl_port_t* out) {
    if (!s || !out) return -1;
    std::lock_guard<std::mutex> lk(s->mu);
    if (index < 0 || index >= static_cast<int>(s->results.size())) return -2;
    const ScanResult& r = s->results[static_cast<size_t>(index)];
    if (port_index < 0 || port_index >= static_cast<int>(r.ports.size())) return -3;

    std::memset(out, 0, sizeof(*out));
    const PortStatus& p = r.ports[static_cast<size_t>(port_index)];
    out->port    = p.port;
    out->is_open = p.isOpen ? 1 : 0;

    // ServiceDetector has already filled p.service from the well-known map;
    // if it's still empty (closed port, or one we don't know about) we
    // fall back to a direct lookup so the GUI never sees "" for a labelled
    // port.
    std::wstring serviceLabel = p.service;
    if (serviceLabel.empty()) serviceLabel = ScanPresetService::serviceFor(p.port);
    copyUtf8(out->service,  sizeof(out->service),  serviceLabel);
    copyUtf8(out->protocol, sizeof(out->protocol), std::wstring(L"tcp"));

    // Attach the fingerprint when one matches this port. Engine
    // pre-computed `versionNote` during scanOneHost so this is a pure
    // struct read.
    for (const auto& f : r.fingerprints) {
        if (f.port == p.port && f.protocol == L"tcp") {
            copyUtf8(out->product,      sizeof(out->product),      f.product);
            copyUtf8(out->version,      sizeof(out->version),      f.version);
            copyUtf8(out->version_note, sizeof(out->version_note), f.versionNote);
            copyUtf8(out->detail,       sizeof(out->detail),
                     f.title.empty() ? f.detail : f.title);
            break;
        }
    }

    // Local-process owner (v1.0.49): `EnrichmentEngine::finalize` already
    // resolved this during scanOneHost when the host is local. Pure read.
    out->owner_pid = p.ownerPid;
    if (!p.ownerExe.empty()) {
        copyUtf8(out->owner_exe, sizeof(out->owner_exe), p.ownerExe);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Adapters.
// ---------------------------------------------------------------------------

extern "C" int nl_adapters_count(void) {
    return static_cast<int>(NetworkAdapterService::enumerate().size());
}

extern "C" int nl_adapters_get(int index, nl_adapter_t* out) {
    if (!out) return -1;
    auto list = NetworkAdapterService::enumerate();
    if (index < 0 || index >= static_cast<int>(list.size())) return -2;
    const NetworkAdapter& a = list[static_cast<size_t>(index)];

    std::memset(out, 0, sizeof(*out));
    out->index = static_cast<int32_t>(a.index);
    copyUtf8(out->friendly_name,   sizeof(out->friendly_name),
             a.friendlyName.empty() ? a.description : a.friendlyName);
    copyUtf8(out->description,     sizeof(out->description),     a.description);
    copyUtf8(out->ip,              sizeof(out->ip),              a.ipv4);
    copyUtf8(out->subnet,          sizeof(out->subnet),          a.subnetMask);
    copyUtf8(out->gateway,         sizeof(out->gateway),         a.gateway);
    copyUtf8(out->suggested_range, sizeof(out->suggested_range), a.suggestedScanRange);
    out->type        = static_cast<int32_t>(a.type);
    out->operational = a.operational ? 1 : 0;
    return 0;
}
