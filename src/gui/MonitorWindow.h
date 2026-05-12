#pragma once

#include <windows.h>
#include <commctrl.h>

#include "../core/HostMonitor.h"

#include <memory>
#include <string>
#include <vector>

namespace netlens::gui {

// =============================================================================
// MonitorWindow — top-level non-modal window that hosts one or more host
// monitors as tabs. Spawned on first "Monitor host..." action; auto-destroyed
// when the last tab is closed.
//
// Each tab corresponds to a HostMonitor running its own probe thread; the
// body controls (probe type, port, interval, pause) and the live line chart
// are shared and reflect the currently selected tab.
// =============================================================================
class MonitorWindow {
public:
    /// Open a monitor window if needed and append a new tab for the host.
    /// Returns the MonitorWindow instance (callers usually ignore it — they
    /// just want the side effect).
    static MonitorWindow* addMonitor(HINSTANCE hInst, HWND parent,
                                     const MonitorConfig& cfg);

    /// Bring the existing monitor window to front (if any).
    static void bringToFront();

    /// True if the monitor window is alive (has at least one tab).
    static bool isOpen();

    /// Number of active monitor tabs across the singleton window.
    static int  activeCount();

    ~MonitorWindow();

private:
    static MonitorWindow* s_instance_;

    MonitorWindow(HINSTANCE hInst, HWND parent);
    bool createWindow();
    void addTab(const MonitorConfig& cfg);
    void removeTab(int index);
    void selectTab(int index);
    void closeIfEmpty();
    void refreshActiveBody();
    void refreshChart();

    static LRESULT CALLBACK staticWndProc(HWND, UINT, WPARAM, LPARAM);
    LRESULT wndProc(UINT msg, WPARAM wParam, LPARAM lParam);

    void onCreate();
    void onSize(int w, int h);
    void onPaint();
    void onCommand(WORD id, WORD code, HWND ctl);
    LRESULT onNotify(LPNMHDR nm);
    void onDestroy();

    void paintChart(HDC dc, const RECT& rc);

    // Helpers
    void onNewMonitorClicked();
    void onCloseTabClicked();
    void onPauseToggle();
    void onProbeTypeChanged();
    void onPortChanged();
    void onIntervalChanged();

    HINSTANCE hInst_;
    HWND      parent_;
    HWND      hwnd_      = nullptr;
    HWND      hTab_      = nullptr;
    HWND      btnNew_    = nullptr;
    HWND      btnCloseTab_ = nullptr;
    HWND      lblProbe_  = nullptr;
    HWND      cbProbe_   = nullptr;
    HWND      lblPort_   = nullptr;
    HWND      edPort_    = nullptr;
    HWND      lblInterval_ = nullptr;
    HWND      cbInterval_= nullptr;
    HWND      btnPause_  = nullptr;
    HWND      btnReset_  = nullptr;
    HWND      btnExport_ = nullptr;
    HWND      lblStatus_ = nullptr;
    HWND      lblStats_  = nullptr;
    HWND      lblLog_    = nullptr;

    HFONT     bodyFont_  = nullptr;
    HFONT     labelFont_ = nullptr;
    HFONT     statusFont_= nullptr;
    HFONT     statsFont_ = nullptr;

    UINT_PTR  refreshTimer_ = 0;

    struct Tab {
        std::unique_ptr<HostMonitor> monitor;
        std::wstring                 title;
    };
    std::vector<Tab> tabs_;
    int              active_ = -1;

    RECT             rectChart_ = {};

    // Double-buffer for the chart — repainting onto a memory bitmap avoids
    // the flicker that the user reported as "updates greu cu mouse".
    HBITMAP          chartBmp_   = nullptr;
    HDC              chartMemDC_ = nullptr;
    int              chartBmpW_  = 0;
    int              chartBmpH_  = 0;

    void ensureChartBuffer(int w, int h);
    void releaseChartBuffer();
    void onExportClicked();

    static constexpr int kMaxMonitors = 16;
};

} // namespace netlens::gui
