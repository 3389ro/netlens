#ifndef NETLENS_APP_H
#define NETLENS_APP_H

#include <windows.h>
#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "Models.h"

namespace nl {

// Engine-to-UI snapshot. The scanner worker thread builds one of these
// per poll tick and PostMessage's it (heap-allocated) to the UI via
// WM_NL_APPLY_SNAPSHOT. UI thread takes ownership and feeds it to
// App::ApplySnapshot, then deletes it. This is the entire data contract
// between scanner thread and UI thread — no shared mutable App state.
struct EngineSnapshot {
    bool                 isRunning      = false;
    int                  progressDone   = 0;
    int                  progressTotal  = 0;
    int                  resultCount    = 0;
    int                  totalScanned   = 0;
    int                  onlineCount    = 0;
    int                  offlineCount   = 0;
    int64_t              durationMs     = 0;
    int64_t              probesDone     = 0;
    int64_t              probesTotalEstimate = 0;
    double               recentHostsPerSec   = 0.0;
    double               recentProbesPerSec  = 0.0;
    bool                 hasRecentRate       = false;
    std::vector<HostRow> hosts;            // full host list, ready to swap into App
    std::wstring         statusText;        // pre-formatted "Scanning · X%" / "Done" / etc
};

// Forward declaration — implementation in App.cpp anon namespace.
class ScanSession;

// Process-wide singleton. Owns the engine handle, the live result snapshot,
// the filter state, and the session settings.
//
// The engine's C ABI (netlens_engine.h) is included only by App.cpp — the UI
// sees nothing but C++ types from this header.
class App {
public:
    static App& Instance();

    bool Init(HINSTANCE hInst);    // returns false if engine init failed
    void Shutdown();

    HINSTANCE Inst() const { return inst_; }
    bool      EngineOk() const { return engineOk_; }

    // `--mock` from the command line — Start scan injects a hard-coded
    // 15-host fleet instead of calling the engine, and Export HTML writes
    // an embedded report that mirrors the engine's output. Used only to
    // generate screenshots for docs / the 3389.ro tool page.
    void      SetMockMode(bool v) { mockMode_ = v; }
    bool      IsMockMode() const  { return mockMode_; }

    // Live data — refreshed by RefreshFromEngine().
    const std::vector<HostRow>& Hosts() const { return hosts_; }
    const ScanStats&            Stats() const { return stats_; }

    // Filter state.
    HostFilter           Filter() const             { return filter_; }
    void                 SetFilter(HostFilter f);
    const std::wstring&  Search() const             { return search_; }
    void                 SetSearch(std::wstring s);
    bool                 ViewOffline() const        { return viewOffline_; }
    void                 SetViewOffline(bool v);
    // v1.3.3 — orthogonal severity filter for CVE / lifecycle findings.
    SeverityFilter       MinSeverity() const        { return minSeverity_; }
    void                 SetMinSeverity(SeverityFilter s);

    const std::vector<int>& FilteredIndex() const { return filteredIndex_; }

    // Selection (index into Hosts(), not FilteredIndex()).
    // Identified by IP under the hood so a re-sort or end-of-scan host
    // reshuffle doesn't break it. The raw index is recomputed on every
    // snapshot inside ApplySnapshot.
    int  SelectedIndex() const { return selectedIndex_; }
    void SetSelected(int hostIndex) {
        selectedIndex_ = hostIndex;
        if (hostIndex >= 0 && hostIndex < static_cast<int>(hosts_.size())) {
            selectedIp_ = hosts_[hostIndex].ip;
        } else {
            selectedIp_.clear();
        }
    }
    const std::wstring& SelectedIp() const { return selectedIp_; }

    // Sort state (which column the host grid is sorted by + direction).
    enum class SortColumn : uint8_t {
        IpV4 = 0, Hostname, Vendor, Device, OpenPortCount, Rtt, Status, Mac,
        Services,       // sort by serviceCount
        Model           // sort by deviceModel
    };
    SortColumn SortCol()      const { return sortCol_; }
    bool       SortAscending() const { return sortAsc_; }
    void       SetSort(SortColumn col, bool ascending);
    // Clicking a header: toggle direction if same column, else switch column
    // with ascending=true (descending for RTT/Rtt where bigger ≠ first).
    void       ToggleSort(SortColumn col);

    // Live adapter snapshot from the engine. Cheap — synchronous Win32 call.
    std::vector<AdapterInfo> Adapters();

    // Per-host port detail (one PortRow per open port). Cached for the
    // currently-selected host so the DetailsPanel paint loop doesn't hit the
    // engine on every WM_PAINT.
    const std::vector<PortRow>& PortsForHost(int hostIndex);

    // Session settings (no disk persistence; defaults until Settings dialog ships in M3).
    AppSettings&       Settings()       { return settings_; }
    const AppSettings& Settings() const { return settings_; }

    // Preset selection (port set the next Start will use).
    ScanPreset   CurrentPreset() const                 { return preset_; }
    void         SetCurrentPreset(ScanPreset p)        { preset_ = p; }
    const std::wstring& CustomPortsCsv() const          { return customPortsCsv_; }
    void         SetCustomPortsCsv(std::wstring s)     { customPortsCsv_ = std::move(s); }

    // Engine operations. uiHwnd is where the scanner thread will PostMessage
    // snapshots — owned by MainWindow (passed at StartScan time so App doesn't
    // need to track window state).
    int  StartScan(const std::wstring& range, HWND uiHwnd);
    void CancelScan();
    void ClearScan();
    bool IsScanning() const;
    int  ExportCsv (const std::wstring& path);  // 0 on success
    int  ExportHtml(const std::wstring& path);

    // Apply a snapshot built by the scanner thread. Mutates hosts_,
    // filteredIndex_, stats_; rebuilds sort order. Called from the UI
    // thread only (WM_NL_APPLY_SNAPSHOT handler). Returns true if hosts
    // changed.
    bool ApplySnapshot(EngineSnapshot&& snap);

    // Back-pressure handshake for ScanSession::runLoop. On a big scan the
    // worker thread builds snapshots faster than the UI can apply them;
    // without this, WM_NL_APPLY_SNAPSHOT messages pile up in the queue,
    // each holding a heap-allocated full-host vector. The worker calls
    // TryMarkSnapshotPending() before posting — if it returns false a
    // previous snapshot is still in the queue, so we drop this one.
    // ClearSnapshotPending() is called by the UI handler once it has
    // moved the snapshot's data into App.
    bool TryMarkSnapshotPending() {
        return !snapshotPending_.exchange(true, std::memory_order_acq_rel);
    }
    void ClearSnapshotPending() {
        snapshotPending_.store(false, std::memory_order_release);
    }

    // Called from the UI thread when the scanner thread posted
    // WM_NL_SCAN_FINISHED. Handles tiered phase 1→2 transition (kicks
    // a new ScanSession for the All-Ports pass) or cleanup.
    void OnScanFinished(HWND uiHwnd);

    // First operational adapter's suggested range, or a sane fallback.
    std::wstring DefaultRange();
    std::wstring EngineVersion();

    // Preset reference data — single source of truth shared between the
    // scanner (which builds the CSV passed to nl_scan_opts_t.ports_csv) and
    // the Port Lists dialog (which renders the same data per card).
    static std::vector<uint16_t> PortsForPreset(ScanPreset p);
    static const wchar_t*        ServiceForPort(uint16_t port);          // long form
    static const wchar_t*        CanonicalServiceForPort(uint16_t port); // SHORT protocol name (HTTP, HTTPS, SMB, RDP, ...) — drives the host-table badges
    static const wchar_t*        PresetDisplayName(ScanPreset p);
    static const wchar_t*        PresetDescription(ScanPreset p);

private:
    App() = default;
    App(const App&) = delete;
    App& operator=(const App&) = delete;

    void RebuildFilter();
    int  startScanInternal(const std::wstring& range, ScanPreset effPreset, HWND uiHwnd);

    HINSTANCE             inst_         = nullptr;
    bool                  engineOk_     = false;
    AppSettings           settings_;
    std::vector<HostRow>  hosts_;
    ScanStats             stats_;
    int                   selectedIndex_ = -1;
    std::wstring          selectedIp_;     // IP-tracked selection
    HostFilter            filter_        = HostFilter::All;
    SeverityFilter        minSeverity_   = SeverityFilter::None;
    std::wstring          search_;
    bool                  viewOffline_   = false;
    std::vector<int>      filteredIndex_;

    ScanPreset            preset_           = ScanPreset::FullCommon;
    std::wstring          customPortsCsv_;

    SortColumn            sortCol_          = SortColumn::IpV4;
    bool                  sortAsc_          = true;

    // Cached "what we last saw" — used by RefreshFromEngine to decide if
    // a snapshot pull + UI repaint is needed this tick.
    int                   lastResultCount_  = -1;
    bool                  lastIsScanning_   = false;
    int                   lastProgressDone_ = -1;

    // Rate samplers + portsPerHostEstimate live inside ScanSession (in
    // App.cpp). App holds an opaque pointer because the type is forward-
    // declared above. unique_ptr drops the thread cleanly on CancelScan
    // / ClearScan / dtor.
    std::unique_ptr<ScanSession> scanSession_;

    // Tiered "Full Scan": phase 1 = FullCommon, phase 2 = the user's
    // chosen All-Ports preset. Driven on the UI thread by OnScanFinished
    // — when phase 1 ends the session is replaced with a fresh one
    // running the All-Ports preset, and the phase-1 host snapshot is
    // merged into hosts_ during phase 2 pulls.
    //
    // v1.3.4 re-enabled this with a stable cross-phase ETA: the ScanSession
    // estimator projects phase-2 cost upfront during phase 1, and adds the
    // captured phase-1 final probe count as a baseline during phase 2.
    // tieredPhase1Probes_ is the frozen phase-1 nl_scanner_probes_done()
    // value captured by OnScanFinished right before clearing the engine.
    int                   tieredPhase_           = 0;
    ScanPreset            tieredOriginalPreset_  = ScanPreset::AllPortsFast;
    std::wstring          tieredRange_;
    std::vector<HostRow>  tieredPhase1Hosts_;
    int64_t               tieredPhase1Probes_    = 0;
    // Frozen phase-1 elapsed ms, added as a baseline during phase 2 so the
    // DURATION card keeps counting up across the engine flip instead of
    // resetting to 0 (mirrors tieredPhase1Probes_ for the probe counter).
    int64_t               tieredPhase1DurationMs_ = 0;

    // Cancel-vs-finish race: if the user clicks Cancel while a
    // WM_NL_SCAN_FINISHED is already queued by the worker, the dispatcher
    // would still run OnScanFinished and (in tiered mode) kick phase 2.
    // CancelScan flips this flag; OnScanFinished checks it before
    // starting phase 2 and clears it.
    bool                  userCancelled_         = false;

    // Single-slot cache of per-host port detail.
    int                   portsCacheHostIdx_ = -1;
    std::vector<PortRow>  portsCache_;

    // `--mock` injects a hardcoded fleet from MockData.cpp instead of
    // calling the engine. Off by default.
    bool                  mockMode_ = false;

    // See TryMarkSnapshotPending / ClearSnapshotPending above.
    std::atomic<bool>     snapshotPending_{false};
};

}  // namespace nl

#endif // NETLENS_APP_H
