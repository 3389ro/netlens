#ifndef NETLENS_RESOURCE_H
#define NETLENS_RESOURCE_H

// -----------------------------------------------------------------------------
// Resource IDs shared between C++ source and app.rc.
// Keep numeric ranges grouped: menus = 1000s, controls = 2000s, timers = 10000s.
// -----------------------------------------------------------------------------

// Application icon (.ico in resources/)
#define IDI_NETLENS                100

// 3389 publisher logo (.bmp in resources/, composited over SurfaceAlt #F0F3F7)
#define IDB_3389_LOGO              110

// Accelerator table
#define IDR_ACCEL                  101

// File menu
#define IDM_FILE_START             1001
#define IDM_FILE_CANCEL            1002
#define IDM_FILE_CLEAR             1003
#define IDM_FILE_EXPORT_HTML       1004
#define IDM_FILE_EXPORT_CSV        1005
#define IDM_FILE_EXIT              1006

// Tools menu
#define IDM_TOOLS_SETTINGS         1101
#define IDM_TOOLS_ADAPTERS         1102
#define IDM_TOOLS_PORT_LISTS       1103
#define IDM_TOOLS_CAPTURE          1104

// View menu (M5.9 — moved from the inline filter bar)
#define IDM_VIEW_OFFLINE           1150

// Help menu
#define IDM_HELP_ABOUT             1201
#define IDM_HELP_VISIT_3389        1202

// Accelerator-only commands (not in any menu)
#define IDM_FOCUS_SEARCH           1300

// M5.13 — Host-grid right-click context menu commands.
#define IDM_CTX_PING               1400
#define IDM_CTX_BROWSER            1401
#define IDM_CTX_RDP                1402
#define IDM_CTX_SSH                1403
#define IDM_CTX_TELNET             1404
#define IDM_CTX_VNC                1405
#define IDM_CTX_COPY_IP            1410
#define IDM_CTX_COPY_MAC           1411
#define IDM_CTX_COPY_HOSTNAME      1412
#define IDM_CTX_COPY_REPORT        1413
#define IDM_CTX_OPEN_FOLDER        1420  // \\ip\

// Toolbar controls
#define IDC_RANGE_EDIT             2001
#define IDC_ADAPTER_BTN            2002
#define IDC_PRESET_COMBO           2003
#define IDC_CUSTOM_PORTS_EDIT      2004
#define IDC_START_BTN              2005
#define IDC_CLEAR_BTN              2006
#define IDC_EXPORT_CSV_BTN         2007
#define IDC_EXPORT_HTML_BTN        2008
#define IDC_SETTINGS_BTN           2009
#define IDC_ABOUT_BTN              2010

// Filter row
#define IDC_FILTER_COMBO           2101
#define IDC_SEARCH_EDIT            2102
#define IDC_VIEW_OFFLINE_CHK       2103

// Main child controls
#define IDC_KPI_ONLINE             2201
#define IDC_KPI_PROGRESS           2202
#define IDC_KPI_DURATION           2203
#define IDC_KPI_TIME_LEFT          2204
#define IDC_HOST_LISTVIEW          2301
#define IDC_DETAILS_PANEL          2302
#define IDC_PROGRESS_BAR           2303

// Timers
#define IDT_POLL                   10001
#define IDT_SEARCH                 10002

#endif // NETLENS_RESOURCE_H
