#pragma once

#include "../Models.h"

#include <set>
#include <string>

namespace lanscope {

/// Web-UI probe — fetches the device admin page on HTTP / HTTPS and
/// extracts a brand/model identifier from the DOM.
///
/// Two transport paths:
///   * `fetchHttp`   — plain HTTP/1.1 over TCP, Chrome UA, ~64 KB cap
///   * `fetchHttps`  — WinHTTP with cert validation disabled (LAN gear
///                     ships self-signed / expired certs by default),
///                     Chrome UA, ~64 KB cap
///
/// Three extraction layers in `extractModelFromBody`:
///   1. `<title>` + brand keyword match (Xerox / HP / MikroTik / UniFi /
///      Synology / Brother / Canon / Netgear / TP-Link / D-Link / …)
///   2. Named element body extraction — `id="X"` or `class="X"` for any
///      tag (div / label / span / h*) — covers `productName` (Xerox,
///      Netgear old UI), `switchInfo` (Netgear ProSAFE current UI),
///      `device-name`, `header-product`, `productinfo`, `model-name`.
///   3. Body-level brand keyword fallback when title + named elements
///      both fail (TP-Link login.cgi, bare WAP landing pages).
///
/// Plus `detectJsRedirect` for stub root pages (Xerox `/` is a 672-byte
/// page that JS-redirects to `/stat/welcome.php?tab=status`).
///
/// Called from `NetworkScanner::scanOneHost` after fingerprinting +
/// device classification (eager Pass 2) when at least one of ports
/// {80, 443, 8443} is open. Result lands on `ScanResult::webUiModel`.
class WebUiProbe {
public:
    /// Top-level orchestrator. Tries HTTPS (443 / 8443) first, falls back
    /// to plain HTTP (80). Returns the extracted model string already
    /// prefixed for direct display:
    ///   "<Brand> (<title>)"         — brand keyword matched in title
    ///   "HTTP title: <text>"        — non-brand title found
    ///   "Web UI model: <text>"      — productName / switchInfo element
    ///   "Web UI brand: <X>"         — body keyword fallback
    /// or empty string if nothing useful was found.
    static std::wstring probe(const std::wstring& ip,
                                const std::set<int>& openPorts,
                                int timeoutMs);

    // ---- internal building blocks (exposed for testing) -------------------
    static std::wstring fetchHttp(const std::wstring& ip, int port,
                                   const std::wstring& path, int timeoutMs);
    static std::wstring fetchHttps(const std::wstring& ip, int port,
                                    const std::wstring& path, int timeoutMs);
    static std::wstring detectJsRedirect(const std::wstring& body);
    /// Resolves a redirect string. On success returns true and fills `outPath`
    /// + `outSecure` (true if scheme is HTTPS). Returns false for cross-host
    /// redirects (we keep probes same-origin).
    static bool resolveRedirectPath(const std::wstring& redirect,
                                     const std::wstring& myIp,
                                     std::wstring& outPath,
                                     bool& outSecure);
    static std::wstring extractNamedElementText(const std::wstring& body,
                                                  const std::wstring& name);
    static std::wstring stripHtmlTags(const std::wstring& s);
    static std::wstring extractModelFromBody(const std::wstring& body);
    static std::wstring parseDeviceFromTitle(const std::wstring& title);

    /// v1.5.7 — HP/HPE iLO exact model + firmware via the anonymous
    /// `/xmldata?item=All` endpoint (RIBCL XML, no credentials). Parses
    /// `<PN>` (e.g. "Integrated Lights-Out 4 (iLO 4)") and `<FWRI>` (e.g.
    /// "2.40"), returning a clean "iLO 4 (fw 2.40)". Empty when the host
    /// isn't an iLO or the document is unavailable. This is the correct
    /// source for the iLO firmware — the HTTP `Server: HP-iLO-Server/x.yz`
    /// header carries the embedded web-server version, NOT the firmware.
    static std::wstring fetchIloModel(const std::wstring& ip, int port,
                                       int timeoutMs);

    /// v1.5.9 — plain-HTTP POST (TCP socket, Chrome UA, ~64 KB cap). Mirrors
    /// `fetchHttp` but sends `body` with a form Content-Type. Used by probes
    /// that read a model from a small JSON API rather than the page DOM.
    static std::wstring fetchHttpPost(const std::wstring& ip, int port,
                                       const std::wstring& path,
                                       const std::string& body, int timeoutMs);

    /// v1.5.9 — TP-Link business/Omada router (ER-series, etc.) exact model
    /// via the anonymous LuCI locale endpoint
    /// `POST /cgi-bin/luci/;stok=/locale?form=lang` (body `operation=read`),
    /// which returns JSON containing `"model":"TL-ER6120 v3.0"`. This is the
    /// ONLY way to read the model on these devices without a browser: the
    /// login page's static `<title>` is just "Opening...", and JavaScript
    /// rewrites it to the model at runtime — so a static GET never sees it.
    /// Empty when the host isn't a LuCI TP-Link or the endpoint is absent.
    static std::wstring fetchTpLinkModel(const std::wstring& ip, int port,
                                          int timeoutMs);

    /// v1.5.10 — MikroTik RouterOS version from the device's plain landing
    /// page, which carries it in a static `<h1>RouterOS v6.29.1</h1>` heading
    /// (no JavaScript). Returns the heading text when it contains "RouterOS"
    /// (e.g. "RouterOS v6.29.1"), else empty. A valid static GET — unlike the
    /// JS-rendered TP-Link title.
    static std::wstring fetchMikrotikModel(const std::wstring& ip, int port,
                                            int timeoutMs);

    /// v1.5.7 — Per-device-type EXACT model for the host-grid Model column.
    /// Dispatches on the already-classified device type / vendor: an iLO is
    /// read from `/xmldata`; everything else is distilled from the web-UI
    /// probe string (`webUiModel`) with the display prefixes and junk titles
    /// (e.g. "Loading...") stripped. Returns empty when no confident model is
    /// available so the caller keeps the classifier's value untouched.
    static std::wstring deriveExactModel(const std::wstring& deviceTypeLower,
                                          const std::wstring& vendorLower,
                                          const std::set<int>& openPorts,
                                          const std::wstring& webUiModel,
                                          const std::wstring& ip,
                                          int timeoutMs);
};

} // namespace lanscope
