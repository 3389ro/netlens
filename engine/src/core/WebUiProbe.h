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
};

} // namespace lanscope
