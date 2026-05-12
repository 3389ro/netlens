#pragma once

// -----------------------------------------------------------------------------
// Resource identifiers
// Kept in one header so both the .rc compiler and the C++ code agree on values.
// -----------------------------------------------------------------------------

#define IDR_MAINFRAME             100
#define IDR_MANIFEST              101
#define IDI_APP_ICON              102

// Menu
#define IDR_MAIN_MENU             200
#define IDM_FILE_EXPORT_CSV       201
#define IDM_FILE_EXPORT_HTML      202
#define IDM_FILE_EXIT             203
#define IDM_VIEW_TOGGLE_ADVANCED  205
#define IDM_VIEW_HIDE_OFFLINE     206
#define IDM_TOOLS_REFRESH         210
#define IDM_TOOLS_CLEAR           211
#define IDM_HELP_ABOUT            220

// Controls
#define IDC_ADAPTER_COMBO         300
#define IDC_REFRESH_BTN           301
#define IDC_RANGE_EDIT            302
#define IDC_PRESET_COMBO          303
#define IDC_PORTS_EDIT            304
#define IDC_TIMEOUT_EDIT          305
#define IDC_PARALLEL_EDIT         306
#define IDC_START_BTN             307
#define IDC_STOP_BTN              308
#define IDC_EXPORT_CSV_BTN        309
#define IDC_EXPORT_HTML_BTN       310
#define IDC_CLEAR_BTN             311
#define IDC_PROGRESS              312
#define IDC_STATUS                313
#define IDC_RESULTS_LIST          314
#define IDC_HEADER                315
#define IDC_SUBHEADER             316
#define IDC_ADAPTER_INFO          317
#define IDC_MODE_COMBO            318
#define IDC_DNS_CHECK             319
#define IDC_MAC_CHECK             320
#define IDC_HIDE_OFFLINE_CHECK    321
#define IDC_ADVANCED_TOGGLE       322
#define IDC_ADVANCED_HINT         323
#define IDC_FILTER_COMBO          324
#define IDC_SEARCH_EDIT           325
#define IDC_RESULTS_TITLE         326
#define IDC_RESULTS_COUNT         327
#define IDC_SCAN_SETUP_TITLE      328
#define IDC_BADGE_1               329
#define IDC_BADGE_2               330
#define IDC_BADGE_3               331
#define IDC_VERSION_BADGE         332

// Sidebar navigation (owner-drawn buttons) — kept compiled but hidden.
#define IDC_NAV_SCANNER           340
#define IDC_NAV_SETTINGS          341
#define IDC_NAV_ABOUT             342

// Top-row adapter selector (icon-only button + tooltip)
#define IDC_ADAPTER_BTN           360

// Menu additions
#define IDM_TOOLS_SETTINGS        212
#define IDM_TOOLS_ADAPTERS        213
#define IDM_TOOLS_PRESETS         214

// Settings modal dialog template + controls
#define IDD_SETTINGS_DIALOG       500
#define IDC_SET_TIMEOUT           501
#define IDC_SET_PARALLEL          502
#define IDC_SET_MODE              503
#define IDC_SET_DNS               504
#define IDC_SET_MAC               505
#define IDC_SET_UDP               506

// Adapter-selection modal dialog template + controls
#define IDD_ADAPTER_DIALOG        510
#define IDC_ADA_LIST              511
#define IDC_ADA_REFRESH           512
#define IDC_ADA_INFO              513

// Host-details modal dialog (double-click a result row)
#define IDD_HOST_DETAILS          520
#define IDC_HD_IP                 521
#define IDC_HD_STATUS             522
#define IDC_HD_HOSTNAME           523
#define IDC_HD_VENDOR             524
#define IDC_HD_MAC                525
#define IDC_HD_DISCOVERY          526
#define IDC_HD_RISK               527
#define IDC_HD_RISK_HINTS         528
#define IDC_HD_PORTS_LIST         529
#define IDC_HD_OPEN_BROWSER       530
#define IDC_HD_OPEN_RDP           531
#define IDC_HD_COPY_IP            532
#define IDC_HD_OPEN_SSH           533
#define IDC_HD_OPEN_TELNET        534
#define IDC_HD_OPEN_VNC           535
#define IDC_HD_PING               536

// Preset manager modal dialog (Tools → Manage port presets)
#define IDD_PRESET_MANAGER        550
#define IDC_PM_LIST               551
#define IDC_PM_NAME               552
#define IDC_PM_PORTS              553
#define IDC_PM_NEW                554
#define IDC_PM_DELETE             555
#define IDC_PM_APPLY              556
#define IDC_PM_RESET              557
#define IDC_PM_HINT               558

// Per-row copy-to-clipboard buttons (one per detail label).
#define IDC_HD_COPY_BTN_IP        540
#define IDC_HD_COPY_BTN_STATUS    541
#define IDC_HD_COPY_BTN_HOSTNAME  542
#define IDC_HD_COPY_BTN_VENDOR    543
#define IDC_HD_COPY_BTN_MAC       544
#define IDC_HD_COPY_BTN_DISC      545
#define IDC_HD_COPY_BTN_RISK      546
#define IDC_HD_COPY_BTN_HINTS     547

// Timer IDs
#define IDT_FLUSH                 1
#define IDT_SEARCH_DEBOUNCE       2

// Summary cards (labels)
#define IDC_CARD_TOTAL            350
#define IDC_CARD_ONLINE           351
#define IDC_CARD_OFFLINE          352
#define IDC_CARD_HIGH             353
#define IDC_CARD_RDP              354
#define IDC_CARD_SMB              355
#define IDC_CARD_DURATION         356

// Custom window messages — posted from worker threads to the GUI thread.
#define WM_NL_HOST_RESULT         (WM_APP + 1)   // wParam: unused, lParam: ScanResult*
#define WM_NL_PROGRESS            (WM_APP + 2)   // wParam: done, lParam: total
#define WM_NL_SCAN_FINISHED       (WM_APP + 3)   // wParam: cancelled (0/1)
#define WM_NL_STATUS              (WM_APP + 4)   // lParam: const wchar_t* (heap-allocated)
