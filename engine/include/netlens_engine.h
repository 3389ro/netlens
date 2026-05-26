// netlens_engine.h — C ABI for the NetLens scan engine.
//
// This header is the *only* contract between the C++ engine and any
// consumer (the Win32 UI in this tree, or any other C-ABI binding).
// Everything crossing the boundary is C ABI: no C++ types, no STL,
// no exceptions. All strings are null-terminated UTF-8. Numeric fields
// use fixed-width integer types from <stdint.h>.

#ifndef NETLENS_ENGINE_H
#define NETLENS_ENGINE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Initialises Winsock + any global state. Call once at program startup.
// Returns 0 on success, non-zero on failure.
int  nl_init(void);

// Shutdown — cleans up Winsock. Call once at program exit.
void nl_shutdown(void);

// Returns the engine version string (e.g. "1.3.8"). Pointer is static —
// do not free.
const char* nl_engine_version(void);

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

typedef struct nl_scanner nl_scanner_t;

typedef struct {
    int32_t timeout_ms;             // per-host probe timeout (default 400)
    int32_t parallel;               // worker count (default 256)
    int32_t mode;                   // 0=Fast 1=Deep 2=Discovery
    int32_t skip_dns;
    int32_t skip_mac;
    int32_t skip_ports;
    int32_t skip_fingerprint;
    int32_t skip_clock_drift;
    int32_t skip_udp_discovery;     // v1.0.30 — 0=run NBNS/NTP/SSDP/mDNS/SQL-Browser probes
    int32_t skip_printer_snmp;      // v1.0.33 — 0=run Printer-MIB SNMP probe on printer-like hosts
    int32_t want_printer_supplies;  // v1.0.33 — 1=walk the prtMarkerSupplies table (slower)
    int32_t fingerprint_timeout_ms; // default 600
    // Comma-separated TCP ports to probe (e.g. "22,80,443"). When NULL or
    // empty the engine uses the built-in "common" preset.
    const char* ports_csv;
    // Gateway IP — strongest "this host is the router" signal for the
    // device classifier. Optional; pass NULL to skip.
    const char* gateway_ip;
} nl_scan_opts_t;

// Creates a scanner instance. Returns NULL on failure.
nl_scanner_t* nl_scanner_create(void);

// Destroys the scanner. Cancels any running scan first.
void nl_scanner_destroy(nl_scanner_t* s);

// Starts a scan over `range` (e.g. "192.168.1.0/24", "192.168.1.1-254").
// Returns 0 on success, non-zero on failure (invalid range, already running).
int  nl_scanner_start(nl_scanner_t* s, const char* range,
                       const nl_scan_opts_t* opts);

// Cooperative cancel. Safe to call when not running.
void nl_scanner_cancel(nl_scanner_t* s);

// Returns 1 if a scan is in flight, 0 otherwise.
int  nl_scanner_is_running(nl_scanner_t* s);

// Progress counters.
int  nl_scanner_progress_done(nl_scanner_t* s);
int  nl_scanner_progress_total(nl_scanner_t* s);

// Number of TCP probes (open / closed / unreachable / timed-out) performed
// across all workers — used by the GUI to drive an accurate ETA.
int64_t nl_scanner_probes_done(nl_scanner_t* s);

// Compact scan summary — derived live from the result accumulator.
typedef struct {
    int32_t total_scanned;
    int32_t online_count;
    int32_t offline_count;
    int32_t high_risk_count;
    int32_t medium_risk_count;
    int32_t low_risk_count;
    int64_t duration_ms;       // 0 until finished
} nl_summary_t;

void nl_scanner_get_summary(nl_scanner_t* s, nl_summary_t* out);

// Clears the engine-side results buffer. Cancels any running scan first.
void nl_scanner_clear_results(nl_scanner_t* s);

// Writes the current results to disk. Returns 0 on success.
int  nl_scanner_export_csv(nl_scanner_t* s, const char* path);
int  nl_scanner_export_html(nl_scanner_t* s, const char* path);

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// Number of results currently available. May grow during the scan.
int  nl_scanner_result_count(nl_scanner_t* s);

// Flat result struct — strings are null-terminated UTF-8 in the buffers.
typedef struct {
    char     ip[16];
    char     hostname[256];
    char     vendor[128];         // SHORT form ("HPE", "Cisco") via VendorShortener
    char     mac[18];
    char     device_type[128];    // FINAL classification (post enhancedDeviceLabel)
    char     device_model[128];
    char     open_ports[256];     // CSV summary: "80, 443, 445"
    char     services[256];       // CSV: "http, https, smb"
    char     risk_hints[1024];    // comma-list of risk findings
    char     brand_hint[1024];    // multi-line: port hints + OS + device hint + web UI
    char     os_hint[128];        // first OS marker across fingerprints, or empty
    char     device_hint[160];    // hostname / OUI IoT guess (full form)
    char     web_ui_model[256];   // Stage 3 — WebUiProbe model, prefixed
    char     udp_discovery[512];  // v1.0.30 — UDP probe summary, multi-line
    int32_t  is_printer;          // v1.0.33 — 0/1
    char     printer_vendor[64];
    char     printer_model[128];
    char     printer_serial[64];
    char     printer_snmp_status[32]; // "ok" / "unavailable" / "no supplies" / "not probed"
    char     printer_supplies[1536];  // multi-line: "<color>\t<type>\t<pct>\t<lvl>\t<max>\t<desc>"
    int32_t  is_online;           // 0/1
    int32_t  risk_level;          // 0=None 1=Low 2=Medium 3=High 4=Critical
    int32_t  response_ms;
    int32_t  discovery;           // 0=Unknown 1=ICMP 2=ARP 3=TCP 4=ARP+ICMP
    int32_t  port_count;
    int32_t  service_count;
    int32_t  clock_responded;     // 0/1
    int64_t  clock_offset_ms;
} nl_result_t;

// Copies result[index] into `out`. Returns 0 on success.
int  nl_scanner_get_result(nl_scanner_t* s, int index, nl_result_t* out);

// Full plain-text host report (matches the GUI's "Copy report"). Writes
// up to `cap` bytes including the null terminator into `out`. Returns
// the total length (excluding null) the engine would have written —
// callers can grow the buffer and retry if the returned value > cap.
int  nl_scanner_format_report(nl_scanner_t* s, int index,
                               char* out, int cap);

// Per-port detail row — fetched separately to keep nl_result_t compact.
typedef struct {
    int32_t  port;
    int32_t  is_open;             // 0/1
    char     service[32];         // friendly name from the well-known map
    char     protocol[8];         // "tcp" / "udp"
    char     product[64];         // best-effort fingerprint product
    char     version[32];
    char     version_note[160];   // VersionAnnotator output ("ESXi 7.0 U3", ...)
    char     detail[160];
    // Stage 4 — local-process ownership (Windows). Populated only when the
    // result's IP matches one of this machine's adapter IPs / 127.0.0.1.
    // owner_pid = 0 means "no listener" or "not local". owner_exe is the
    // image path, or a sentinel ("needs admin" / "System Idle" /
    // "System (kernel)" / "path unavailable") when QueryFullProcessImageName
    // failed.
    uint32_t owner_pid;
    char     owner_exe[260];      // MAX_PATH (extended paths truncated)
} nl_port_t;

// Returns the count of port entries for result[index].
int  nl_scanner_port_count(nl_scanner_t* s, int index);

// Copies port[port_index] of result[index] into `out`. Returns 0 on success.
int  nl_scanner_get_port(nl_scanner_t* s, int index, int port_index,
                         nl_port_t* out);

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

typedef struct {
    int32_t  index;
    char     friendly_name[128];
    char     description[160];
    char     ip[16];
    char     subnet[16];
    char     gateway[16];
    char     suggested_range[40];
    int32_t  type;                // 0=Unknown 1=Ethernet 2=WiFi 3=Loopback ...
    int32_t  operational;         // 0/1
} nl_adapter_t;

// Returns the number of adapters detected.
int  nl_adapters_count(void);

// Copies adapter[index] into `out`. Returns 0 on success.
int  nl_adapters_get(int index, nl_adapter_t* out);

#ifdef __cplusplus
}
#endif

#endif // NETLENS_ENGINE_H
