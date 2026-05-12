#pragma once

#include <windows.h>
#include <commctrl.h>

#include "../Models.h"
#include "../core/NetworkScanner.h"

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace netlens::gui {

/// The application's main window. Owns all child controls and the scanner.
///
/// Layout (post-flatten refactor):
///   - Top row: IP range (wide) + icon-only adapter button + Profile combo +
///     Start/Stop toggle. Custom Ports input appears below only when the
///     Profile is "Custom Ports".
///   - Scan results region with a 3-card KPI strip (Online / % scanned /
///     Duration) that materialises only after Start is pressed.
///   - Themed ListView with subtle risk-row colouring.
///   - Bottom action bar (status, progress, Clear, Export CSV, Export HTML).
///   - Sidebar code is preserved but gated off — see kSidebarEnabled.
///   - Network adapter selection lives in a modal dialog (Tools → Select
///     adapter, or the icon button). Engine settings live in another modal
///     dialog (Tools → Settings).
class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    bool create(HINSTANCE hInst);
    void show(int nShowCmd);
    [[nodiscard]] HWND hwnd() const { return hwnd_; }

private:
    static LRESULT CALLBACK staticWndProc(HWND, UINT, WPARAM, LPARAM);
    LRESULT instanceWndProc(UINT msg, WPARAM wParam, LPARAM lParam);

    // ---- Lifecycle / message handlers ---------------------------------------
    void onCreate();
    void onSize(int width, int height);
    void onCommand(WORD id, WORD notifyCode, HWND hCtl);
    LRESULT onNotify(LPNMHDR nm);
    LRESULT onDrawItem(LPDRAWITEMSTRUCT dis);
    void onClose();
    void onPaint();

    // ---- Scan flow ----------------------------------------------------------
    void refreshAdapters();
    void selectAdapter(int adapterIndex);    ///< applied from the adapter dialog
    void onPresetChanged();
    void onPortsEdited();
    void startScan();
    void stopScan();

    // ---- UI batching --------------------------------------------------------
    void flushPending();
    void onScanFinished(bool cancelled);

    // ---- Helpers ------------------------------------------------------------
    void setStatus(const std::wstring& text);
    void setStartStopEnabled(bool scanning);
    void clearResults();
    void exportCsv();
    void exportHtml();
    void showAbout();
    void updateKpiStrip();                   ///< Online / % / Duration
    void updateResultsCountLabel();
    void layoutChildren();

    // ---- Modal dialogs (Tools menu / inline buttons) ------------------------
    void showAdapterDialog();
    void showSettingsDialog();
    void showHostDetailsDialog(const ScanResult& r);
    void showPresetManager();
    static INT_PTR CALLBACK adapterDlgProc(HWND, UINT, WPARAM, LPARAM);
    static INT_PTR CALLBACK presetMgrDlgProc(HWND, UINT, WPARAM, LPARAM);
    // Settings dialog and host-details dialog use captureless lambda DLGPROCs
    // declared inline inside their show* methods.

    // ---- Preset combo plumbing ---------------------------------------------
    // Rebuilds the top-row Profile dropdown from ScanPresetService::presets()
    // and selects the given index (default: the first preset). Used after the
    // preset manager dialog mutates the underlying catalogue.
    void rebuildPresetCombo(int selectIndex = 0);

    // ---- Results toolbar / filter -------------------------------------------
    void onFilterChanged();
    void onSearchChanged();
    void onMenuToggleHideOffline();
    void onHideOfflineToggled();
    void onColumnHeaderClicked(int column);
    void applyListSort();

    void rebuildVisibleRows();
    int  upsertVisibleRow(const ScanResult& r);

    [[nodiscard]] bool shouldShowResult(const ScanResult& r) const;
    [[nodiscard]] bool resultMatchesSearch(const ScanResult& r) const;

    LRESULT handleListCustomDraw(LPNMLVCUSTOMDRAW cd);
    void showRowContextMenu(int row);
    void handleContextAction(int cmd, const ScanResult& r);
    [[nodiscard]] const ScanResult* resultForRow(int row) const;

    // ---- Painting helpers ---------------------------------------------------
    void paintCardBackground(HDC dc, const RECT& rc, bool drawAccent,
                             COLORREF accent);
    void paintKpiCard(HDC dc, int index, const RECT& rc);
    void paintSidebar(HDC dc, const RECT& rc);
    void drawNavButton(LPDRAWITEMSTRUCT dis, const wchar_t* glyph,
                       const wchar_t* label, bool active);
    void drawAdapterButton(LPDRAWITEMSTRUCT dis);

private:
    HINSTANCE       hInst_ = nullptr;
    HWND            hwnd_  = nullptr;

    // Owned fonts.
    HFONT           bodyFont_         = nullptr;
    HFONT           labelFont_        = nullptr;
    HFONT           kpiLabelFont_     = nullptr;
    HFONT           kpiValueFont_     = nullptr;
    HFONT           buttonFont_       = nullptr;
    HFONT           primaryBtnFont_   = nullptr;
    HFONT           sectionFont_      = nullptr;
    HFONT           sidebarBrandFont_ = nullptr;
    HFONT           sidebarNavFont_   = nullptr;
    HFONT           sidebarFootFont_  = nullptr;
    HFONT           iconFontMed_      = nullptr;
    HFONT           iconFontLarge_    = nullptr;

    // ---- Sidebar (compiled but hidden via kSidebarEnabled) ----
    HWND            btnNavScanner_    = nullptr;
    HWND            btnNavSettings_   = nullptr;
    HWND            btnNavAbout_      = nullptr;

    // ---- Top row: IP range + adapter button + Profile + Start ----
    HWND            edRange_          = nullptr;
    HWND            btnAdapter_       = nullptr;   ///< owner-drawn icon button
    HWND            cbPreset_         = nullptr;
    HWND            btnStart_         = nullptr;   ///< Start/Stop toggle

    // ---- Custom-ports row (visible only when Profile == "Custom Ports") ----
    HWND            lblPorts_         = nullptr;
    HWND            edPorts_          = nullptr;

    // ---- Tooltip for the adapter button ----
    HWND            tipAdapter_       = nullptr;

    // ---- KPI strip (4 cards, hidden until first scan): Online / Progress /
    //      ETA / Duration ----
    HWND            cards_[4]         = {};
    HWND            cardLbls_[4]      = {};

    // ---- Results toolbar ----
    HWND            lblResultsTitle_  = nullptr;
    HWND            lblResultsCount_  = nullptr;
    HWND            lblFilter_        = nullptr;
    HWND            cbFilter_         = nullptr;
    HWND            edSearch_         = nullptr;
    HWND            chkHideOffline_   = nullptr;

    // ---- Results ListView ----
    HWND            list_             = nullptr;

    // ---- Bottom action bar ----
    HWND            progress_         = nullptr;
    HWND            status_           = nullptr;
    HWND            btnExportCsv_     = nullptr;
    HWND            btnExportHtml_    = nullptr;
    HWND            btnClear_         = nullptr;

    // ---- Cached layout rectangles ----
    RECT            rectSidebar_      = {};
    RECT            rectTopRow_       = {};   // IP range + adapter + profile + start
    RECT            rectCustomRow_    = {};   // custom-ports row (when shown)
    RECT            rectKpiBand_      = {};
    RECT            rectKpiCard_[4]   = {};
    RECT            rectResultsBar_   = {};
    RECT            rectBottomBar_    = {};

    // Engine + state.
    std::unique_ptr<NetworkScanner>           scanner_;
    std::vector<NetworkAdapter>               adapters_;
    int                                       adapterIndex_ = -1;  ///< -1 = manual
    std::vector<ScanResult>                   lastResults_;
    ScanSummary                               lastSummary_;
    int                                       totalCount_   = 0;
    bool                                      scanning_     = false;
    bool                                      hasScannedOnce_ = false; ///< gates KPI strip
    std::chrono::steady_clock::time_point     scanStartedAt_{};

    // Sliding-window samples for the ETA calculation. Each entry pairs an
    // elapsed-ms timestamp with the corresponding probesDone counter, so we
    // can compute "probes/sec over the last N seconds" instead of the
    // cumulative average. The cumulative average is biased by the fast
    // ICMP-discovery phase and makes ETA balloon when the slower port-scan
    // phase kicks in.
    struct ProbeSample { int64_t tMs; int64_t probes; };
    std::deque<ProbeSample>                   probeSamples_;

    // Snapshot of the scan options at start — used to compute work-progress %.
    // portsPerHost_ counts the ports actually scanned per online host;
    // fallbackPortsPerHost_ counts the discovery probe used for ICMP-silent
    // hosts (Fast mode). DiscoveryOnly mode = 0 for both.
    int                                       portsPerHost_         = 0;
    int                                       fallbackPortsPerHost_ = 0;
    bool                                      suppressPortsEdit_ = false;
    bool                                      customPortsMode_ = false;

    // Display source-of-truth.
    std::vector<ScanResult>                   displayedResults_;
    std::unordered_map<std::wstring, size_t>  ipToDisplayIndex_;

    // Worker-to-UI handoff queue.
    std::mutex                                pendingMu_;
    std::vector<ScanResult>                   pendingResults_;
    std::atomic<int>                          doneCount_{0};

    // ---- Engine settings (mutable via Settings dialog) ----
    int                                       settingsTimeoutMs_ = 400;
    int                                       settingsParallel_  = 256;
    ScanMode                                  settingsMode_      = ScanMode::Deep;
    bool                                      settingsResolveDns_ = true;
    bool                                      settingsResolveMac_ = true;
    bool                                      settingsResolveUdp_ = true;

    // ---- GUI filter / sort state ----
    bool                                      hideOffline_   = true;
    int                                       filterIndex_   = 0;
    std::wstring                              searchText_;
    int                                       sortColumn_    = -1;
    bool                                      sortAscending_ = true;
};

} // namespace netlens::gui
