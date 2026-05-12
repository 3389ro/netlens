#include "CliApp.h"

#include "../AppConstants.h"
#include "../Models.h"
#include "../core/IpRangeParser.h"
#include "../core/NetworkAdapterService.h"
#include "../core/NetworkScanner.h"
#include "../core/ReportExporter.h"
#include "../core/ScanPresetService.h"
#include "../core/Stopwatch.h"
#include "CommandLineParser.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cwchar>
#include <iostream>
#include <mutex>
#include <vector>

namespace netlens {

namespace {

void writeOut(const std::wstring& s) {
    // stdout is already in text mode; fputws works for both real consoles and
    // the parent's stdout when AttachConsole'd.
    std::fputws(s.c_str(), stdout);
    std::fflush(stdout);
}

void writeOutLine(const std::wstring& s) {
    // The CRT runs stdout in text mode (we set _O_U8TEXT in main), so a bare
    // '\n' is already translated to '\r\n' on the wire. Don't double-emit.
    writeOut(s + L"\n");
}

void writeErrLine(const std::wstring& s) {
    std::fputws((s + L"\n").c_str(), stderr);
    std::fflush(stderr);
}

std::wstring formatDuration(int64_t ms) {
    if (ms < 1000) return std::to_wstring(ms) + L" ms";
    if (ms < 60 * 1000) {
        wchar_t b[32]; std::swprintf(b, 32, L"%.1f s", ms / 1000.0);
        return b;
    }
    int mins = static_cast<int>(ms / 60000);
    int secs = static_cast<int>((ms / 1000) % 60);
    wchar_t b[32]; std::swprintf(b, 32, L"%d min %02d s", mins, secs);
    return b;
}

void printAdapter(const NetworkAdapter& a) {
    writeOutLine(a.guiLine());
    if (!a.suggestedScanRange.empty()) {
        writeOutLine(L"      suggested range: " + a.suggestedScanRange);
    }
    if (!a.macAddress.empty()) {
        writeOutLine(L"      mac:             " + a.macAddress);
    }
}

void printResultRow(const ScanResult& r) {
    wchar_t buf[64];

    // IP (16) | Status (8) | RTT (6) | Risk (8) | Ports
    std::swprintf(buf, 64, L"  %-15ls %-8ls %5lldms %-8ls",
                  r.ipAddress.c_str(),
                  r.statusText().c_str(),
                  static_cast<long long>(r.responseTimeMs),
                  RiskLevelToString(r.riskLevel));
    std::wstring line = buf;

    std::wstring ports = r.openPortsText();
    if (!ports.empty()) {
        line += L"  ports: " + ports;
    }
    if (!r.hostname.empty()) {
        line += L"  (" + r.hostname + L")";
    }
    writeOutLine(line);

    if (!r.riskHints.empty()) {
        writeOutLine(L"        hints: " + r.riskHints);
    }
}

ScanMode parseMode(const std::wstring& id) {
    if (id == L"fast")      return ScanMode::Fast;
    if (id == L"discovery") return ScanMode::DiscoveryOnly;
    // Default (and fallback for unknown ids) is Deep as of v1.0.8 — see
    // ScanOptions::mode comment in Models.h.
    return ScanMode::Deep;
}

ScanOptions buildOptions(const CommandLineParser::Args& a, const std::wstring& rangeLabel,
                         const std::wstring& adapterLabel)
{
    ScanOptions o;
    o.rangeText      = rangeLabel;
    o.adapterLabel   = adapterLabel;
    o.timeoutMs      = a.timeoutMs;
    o.parallel       = a.parallel;
    o.mode           = parseMode(a.modeId);
    o.onlineOnly     = a.onlineOnly;
    o.skipDns        = a.noDns;
    o.skipMac        = a.noMac;
    o.skipUdp        = a.noUdp;
    // Discovery-only mode implies no port scanning regardless of user flags.
    o.skipPorts      = a.noPorts || o.mode == ScanMode::DiscoveryOnly;

    if (!a.portsCsv.empty()) {
        o.ports      = ScanPresetService::parsePortList(a.portsCsv);
        o.presetName = L"Custom";
    } else if (!a.presetId.empty()) {
        if (const auto* p = ScanPresetService::find(a.presetId)) {
            o.ports      = p->ports;
            o.presetName = p->displayName;
        }
    }
    if (o.ports.empty() && !o.skipPorts) {
        if (const auto* p = ScanPresetService::find(L"quick")) {
            o.ports      = p->ports;
            o.presetName = p->displayName;
        }
    }
    return o;
}

} // anonymous namespace

int CliApp::run(int argc, wchar_t** argv) {
    auto args = CommandLineParser::parse(argc, argv);

    if (args.hasError) {
        writeErrLine(L"Error: " + args.error);
        writeErrLine(L"Run with --help for usage.");
        return kExitInvalidArgs;
    }

    if (args.showHelp) {
        writeOut(CommandLineParser::helpText());
        return kExitOk;
    }

    if (args.listAdapters) {
        auto adapters = NetworkAdapterService::enumerate();
        if (adapters.empty()) {
            writeOutLine(L"No IPv4 adapters detected.");
            return kExitOk;
        }
        writeOutLine(L"Detected adapters:");
        for (const auto& a : adapters) printAdapter(a);
        return kExitOk;
    }

    // ---- Resolve range -----------------------------------------------------
    std::wstring rangeText  = args.range;
    std::wstring adapterLbl = L"Manual";

    if (rangeText.empty() && args.adapterIndex >= 0) {
        auto adapters = NetworkAdapterService::enumerate();
        bool found = false;
        for (const auto& a : adapters) {
            if (static_cast<int>(a.index) == args.adapterIndex) {
                rangeText  = a.suggestedScanRange;
                adapterLbl = a.friendlyName.empty() ? a.description : a.friendlyName;
                if (adapterLbl.empty()) adapterLbl = L"Adapter";
                found = true;
                break;
            }
        }
        if (!found) {
            writeErrLine(L"Adapter index " + std::to_wstring(args.adapterIndex) + L" not found.");
            return kExitInvalidArgs;
        }
    }

    if (rangeText.empty()) {
        writeErrLine(L"No --range or --adapter provided. Run with --help for usage.");
        return kExitInvalidArgs;
    }

    auto parsed = IpRangeParser::parse(rangeText, args.allowLargeRange);
    if (!parsed.ok) {
        writeErrLine(L"Invalid range: " + parsed.error);
        return kExitInvalidArgs;
    }

    // ---- Build options & banner -------------------------------------------
    auto options = buildOptions(args, rangeText, adapterLbl);
    if (options.ports.empty() && !options.skipPorts) {
        writeErrLine(L"No ports to scan and --no-ports not set. Provide --ports or --preset.");
        return kExitInvalidArgs;
    }

    writeOutLine(std::wstring(L"NetLens ") + kAppVersion + L" - starting scan");
    writeOutLine(L"  Mode:     " + std::wstring(ScanModeToString(options.mode)));
    writeOutLine(L"  Range:    " + rangeText
                 + L"   (" + std::to_wstring(parsed.addresses.size()) + L" host"
                 + (parsed.addresses.size() == 1 ? L"" : L"s") + L")");
    writeOutLine(L"  Adapter:  " + adapterLbl);
    writeOutLine(L"  Preset:   " + (options.presetName.empty() ? std::wstring(L"-") : options.presetName));
    if (options.skipPorts) {
        writeOutLine(L"  Ports:    (none — TCP probing disabled)");
    } else {
        writeOutLine(L"  Ports:    " + ScanPresetService::formatPortList(options.ports));
    }
    writeOutLine(L"  Timeout:  " + std::to_wstring(options.timeoutMs) + L" ms");
    writeOutLine(L"  Parallel: " + std::to_wstring(options.parallel));
    writeOutLine(L"  DNS:      " + std::wstring(args.noDns ? L"off" : L"on"));
    writeOutLine(L"  MAC:      " + std::wstring(args.noMac ? L"off" : L"on"));
    writeOutLine(L"  UDP:      " + std::wstring(args.noUdp ? L"off" : L"on"));
    writeOutLine(L"");

    // ---- Run scan ----------------------------------------------------------
    NetworkScanner scanner;
    std::mutex                 doneMu;
    std::condition_variable    doneCv;
    bool                       finished = false;
    bool                       cancelled = false;
    ScanSummary                summary;
    std::vector<ScanResult>    results;
    std::atomic<int>           lastProgress{0};
    const int                  total = static_cast<int>(parsed.addresses.size());

    auto onHost = [&](const ScanResult& r) {
        if (args.onlineOnly && !r.isOnline) return;
        // Lock to serialise stdout writes.
        static std::mutex stdoutMu;
        std::lock_guard<std::mutex> lk(stdoutMu);
        printResultRow(r);
    };
    auto onProgress = [&](int done, int total_in) {
        int prev = lastProgress.exchange(done);
        if (args.debug && done != prev) {
            wchar_t b[64];
            std::swprintf(b, 64, L"[debug] progress %d/%d", done, total_in);
            writeErrLine(b);
        }
    };
    auto onFinished = [&](bool wasCancelled, const ScanSummary& s,
                          const std::vector<ScanResult>& res) {
        {
            std::lock_guard<std::mutex> lk(doneMu);
            cancelled = wasCancelled;
            summary   = s;
            results   = res;
            finished  = true;
        }
        doneCv.notify_one();
    };

    Stopwatch wall;
    scanner.start(parsed.addresses, options, onHost, onProgress, onFinished);

    {
        std::unique_lock<std::mutex> lk(doneMu);
        doneCv.wait(lk, [&] { return finished; });
    }
    summary.durationMs = wall.elapsedMs();
    (void)total;

    writeOutLine(L"");
    writeOutLine(L"---- Scan summary ----------------------------------");
    writeOutLine(L"  Mode:          " + std::wstring(ScanModeToString(summary.modeUsed)));
    writeOutLine(L"  Total scanned: " + std::to_wstring(summary.totalScanned));
    writeOutLine(L"  Online:        " + std::to_wstring(summary.onlineCount));
    writeOutLine(L"  Offline:       " + std::to_wstring(summary.offlineCount));
    writeOutLine(L"  RDP open:      " + std::to_wstring(summary.rdpOpenCount));
    writeOutLine(L"  SMB open:      " + std::to_wstring(summary.smbOpenCount));
    writeOutLine(L"  Web open:      " + std::to_wstring(summary.webOpenCount));
    writeOutLine(L"  High risk:     " + std::to_wstring(summary.highRiskCount));
    writeOutLine(L"  Medium risk:   " + std::to_wstring(summary.mediumRiskCount));
    writeOutLine(L"  Duration:      " + formatDuration(summary.durationMs));
    if (cancelled) writeOutLine(L"  (Scan was cancelled.)");

    if (args.debug) {
        writeErrLine(L"[debug] scan finished, summary.durationMs="
                     + std::to_wstring(summary.durationMs));
    }

    // ---- Export ------------------------------------------------------------
    int rc = kExitOk;

    auto resultsForExport = results;
    if (args.onlineOnly) {
        resultsForExport.erase(std::remove_if(resultsForExport.begin(),
                                              resultsForExport.end(),
                                              [](const ScanResult& r) { return !r.isOnline; }),
                               resultsForExport.end());
    }

    if (!args.csvPath.empty()) {
        if (ReportExporter::exportCsv(args.csvPath, resultsForExport)) {
            writeOutLine(L"  CSV written:   " + args.csvPath);
        } else {
            writeErrLine(L"  CSV export FAILED: " + args.csvPath);
            rc = kExitExportError;
        }
    }
    if (!args.htmlPath.empty()) {
        if (ReportExporter::exportHtml(args.htmlPath, resultsForExport, summary)) {
            writeOutLine(L"  HTML written:  " + args.htmlPath);
        } else {
            writeErrLine(L"  HTML export FAILED: " + args.htmlPath);
            rc = kExitExportError;
        }
    }
    return rc;
}

} // namespace netlens
