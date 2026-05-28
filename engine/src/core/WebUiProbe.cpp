#include "WebUiProbe.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

namespace lanscope {

namespace {

// Chrome-on-Windows-10 UA — embedded LAN gear (older TP-Link / D-Link /
// Tenda / Mercusys consumer routers) ships naive anti-scanner filtering
// that drops requests whose UA looks like a scanner / curl / wget.
const wchar_t* kBrowserUserAgent =
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    L"AppleWebKit/537.36 (KHTML, like Gecko) "
    L"Chrome/120.0.0.0 Safari/537.36";

std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::string toUtf8Narrow(const std::wstring& w) {
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

std::wstring fromUtf8Lossy(const char* data, size_t len) {
    if (len == 0) return {};
    // Convert as best-effort. ::MultiByteToWideChar with CP_UTF8 and no
    // MB_ERR_INVALID_CHARS replaces invalid bytes with U+FFFD silently.
    int needed = ::MultiByteToWideChar(CP_UTF8, 0, data,
                                        static_cast<int>(len), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, data, static_cast<int>(len),
                           out.data(), needed);
    return out;
}

bool isValidIpv4(const std::wstring& ip) {
    if (ip.empty()) return false;
    int octets = 0;
    int curVal = -1;
    for (size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == L'.') {
            if (curVal < 0 || curVal > 255) return false;
            ++octets;
            curVal = -1;
            if (i == ip.size()) break;
        } else if (ip[i] >= L'0' && ip[i] <= L'9') {
            if (curVal < 0) curVal = 0;
            curVal = curVal * 10 + (ip[i] - L'0');
            if (curVal > 999) return false;
        } else {
            return false;
        }
    }
    return octets == 4;
}

bool contains(const std::wstring& s, const wchar_t* needle) {
    return s.find(needle) != std::wstring::npos;
}

bool startsWith(const std::wstring& s, const wchar_t* needle) {
    size_t n = 0; while (needle[n]) ++n;
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) if (s[i] != needle[i]) return false;
    return true;
}

void trimWs(std::wstring& s) {
    while (!s.empty() && std::iswspace(static_cast<wint_t>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::iswspace(static_cast<wint_t>(s.back())))  s.pop_back();
}

// A page <title> that's a generic placeholder rather than a real device model.
// The input is already lowercased. We strip trailing punctuation / dots first
// so "Loading...", "Login.", "Sign in…" all normalise onto the bare keyword —
// this is the fix for switch admin SPAs whose static title is literally
// "Loading..." (it was being surfaced as the model).
bool titleIsJunk(std::wstring tl) {
    // Drop trailing dots, ellipsis, spaces, punctuation.
    while (!tl.empty()) {
        wchar_t c = tl.back();
        if (c == L'.' || c == L' ' || c == L'\t' || c == L'\x2026'
            || c == L'!' || c == L'-' || c == L':' || c == L'|')
            tl.pop_back();
        else break;
    }
    trimWs(tl);
    if (tl.empty()) return true;
    static const wchar_t* kJunk[] = {
        L"loading", L"login", L"log in", L"sign in", L"signin", L"please wait",
        L"welcome", L"index", L"home", L"home page", L"dashboard", L"redirect",
        L"redirecting", L"error", L"page", L"document", L"untitled", L"web",
        L"admin", L"setup", L"configuration", L"authentication required",
        L"401 unauthorized", L"401 authorization required", L"403 forbidden",
        L"404 not found", L"web server", L"management console", L"web management",
        L"it works", L"main", L"start",
        // HTTP status / transient-state titles that are never a device model.
        L"opening", L"moved temporarily", L"moved permanently", L"found",
        L"not found", L"bad request", L"forbidden", L"unauthorized",
        L"service unavailable", L"302 found", L"welcome to xampp", L"xampp"
    };
    for (auto j : kJunk) if (tl == j) return true;
    return false;
}

} // anonymous namespace

// =============================================================================
// fetchHttp — plain HTTP/1.1 via TCP socket
// =============================================================================

std::wstring WebUiProbe::fetchHttp(const std::wstring& ip, int port,
                                     const std::wstring& path, int timeoutMs) {
    if (!isValidIpv4(ip)) return {};

    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return {};

    // Set send + recv timeouts so we don't hang on slow embedded servers.
    DWORD to = static_cast<DWORD>(timeoutMs);
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                  reinterpret_cast<const char*>(&to), sizeof(to));
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                  reinterpret_cast<const char*>(&to), sizeof(to));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<u_short>(port));
    {
        std::string ipNarrow = toUtf8Narrow(ip);
        if (::inet_pton(AF_INET, ipNarrow.c_str(), &addr.sin_addr) != 1) {
            ::closesocket(sock);
            return {};
        }
    }

    // Use non-blocking connect with select() so we honor timeoutMs even on
    // hosts that drop the SYN silently (no RST). Otherwise blocking connect
    // would wait for the OS TCP stack's default 21s.
    u_long nb = 1;
    ::ioctlsocket(sock, FIONBIO, &nb);
    int rc = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == SOCKET_ERROR && ::WSAGetLastError() != WSAEWOULDBLOCK) {
        ::closesocket(sock);
        return {};
    }
    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    timeval tv; tv.tv_sec = timeoutMs / 1000; tv.tv_usec = (timeoutMs % 1000) * 1000;
    rc = ::select(0, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) { ::closesocket(sock); return {}; }
    int sockErr = 0; int sockErrLen = sizeof(sockErr);
    if (::getsockopt(sock, SOL_SOCKET, SO_ERROR,
                      reinterpret_cast<char*>(&sockErr), &sockErrLen) != 0 || sockErr != 0) {
        ::closesocket(sock);
        return {};
    }
    nb = 0;
    ::ioctlsocket(sock, FIONBIO, &nb);

    std::string ipNarrow   = toUtf8Narrow(ip);
    std::string pathNarrow = toUtf8Narrow(path.empty() ? std::wstring(L"/") : path);
    std::string uaNarrow   = toUtf8Narrow(kBrowserUserAgent);
    std::string req =
        "GET " + pathNarrow + " HTTP/1.1\r\n"
        "Host: " + ipNarrow + "\r\n"
        "User-Agent: " + uaNarrow + "\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n"
        "\r\n";

    int sent = 0;
    const int reqLen = static_cast<int>(req.size());
    while (sent < reqLen) {
        int n = ::send(sock, req.data() + sent, reqLen - sent, 0);
        if (n <= 0) { ::closesocket(sock); return {}; }
        sent += n;
    }

    std::vector<char> body;
    body.reserve(8192);
    char chunk[4096];
    while (body.size() < 65536) {
        int n = ::recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) break;
        body.insert(body.end(), chunk, chunk + n);
    }

    ::closesocket(sock);

    if (body.empty()) return {};
    return fromUtf8Lossy(body.data(), body.size());
}

// =============================================================================
// fetchHttps — WinHTTP, cert validation disabled, Chrome UA
// =============================================================================

std::wstring WebUiProbe::fetchHttps(const std::wstring& ip, int port,
                                      const std::wstring& path, int timeoutMs) {
    if (!isValidIpv4(ip)) return {};

    HINTERNET session = ::WinHttpOpen(kBrowserUserAgent,
                                        WINHTTP_ACCESS_TYPE_NO_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return {};

    ::WinHttpSetTimeouts(session, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET connect = ::WinHttpConnect(session, ip.c_str(),
                                           static_cast<INTERNET_PORT>(port), 0);
    if (!connect) { ::WinHttpCloseHandle(session); return {}; }

    std::wstring object = path.empty() ? std::wstring(L"/") : path;
    HINTERNET request = ::WinHttpOpenRequest(connect, L"GET", object.c_str(),
                                               nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               WINHTTP_FLAG_SECURE);
    if (!request) {
        ::WinHttpCloseHandle(connect);
        ::WinHttpCloseHandle(session);
        return {};
    }

    // LAN appliances ship self-signed / expired / hostname-mismatched certs
    // by default. We're a scanner, not a browser — accept and read the body.
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    ::WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS,
                        &secFlags, sizeof(secFlags));

    std::vector<char> body;
    body.reserve(8192);
    if (::WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && ::WinHttpReceiveResponse(request, nullptr)) {
        DWORD avail = 0;
        while (::WinHttpQueryDataAvailable(request, &avail) && avail > 0) {
            if (avail > 4096) avail = 4096;
            std::vector<char> chunk(avail);
            DWORD read = 0;
            if (!::WinHttpReadData(request, chunk.data(), avail, &read) || read == 0)
                break;
            body.insert(body.end(), chunk.data(), chunk.data() + read);
            if (body.size() >= 65536) break;
        }
    }

    ::WinHttpCloseHandle(request);
    ::WinHttpCloseHandle(connect);
    ::WinHttpCloseHandle(session);

    if (body.empty()) return {};
    return fromUtf8Lossy(body.data(), body.size());
}

// =============================================================================
// detectJsRedirect — stub-page JS or <meta refresh> redirect target
// =============================================================================

std::wstring WebUiProbe::detectJsRedirect(const std::wstring& body) {
    if (body.size() > 4096) return {}; // real pages are large; stubs are tiny
    std::wstring lower = toLower(body);

    // <meta http-equiv="refresh" content="N; url=...">
    {
        size_t p = lower.find(L"http-equiv=\"refresh\"");
        if (p != std::wstring::npos) {
            size_t u = lower.find(L"url=", p);
            if (u != std::wstring::npos) {
                size_t start = u + 4;
                size_t end = start;
                while (end < body.size()) {
                    wchar_t c = body[end];
                    if (c == L'"' || c == L'\'' || c == L'>') break;
                    ++end;
                }
                std::wstring url = body.substr(start, end - start);
                // Trim whitespace.
                while (!url.empty() && std::iswspace(static_cast<wint_t>(url.front())))
                    url.erase(url.begin());
                while (!url.empty() && std::iswspace(static_cast<wint_t>(url.back())))
                    url.pop_back();
                if (!url.empty() && url.size() < 256) return url;
            }
        }
    }

    // document.location='...' / window.location.href="..." / location.replace('...')
    static const wchar_t* kJsNeedles[] = {
        L"document.location",
        L"window.location",
        L"location.href",
        L"location.replace",
    };
    for (auto needle : kJsNeedles) {
        size_t p = lower.find(needle);
        if (p == std::wstring::npos) continue;
        size_t i = p;
        wchar_t quote = 0;
        size_t qpos = 0;
        while (i < body.size()) {
            wchar_t c = body[i];
            if (c == L'\'' || c == L'"') { quote = c; qpos = i + 1; break; }
            if (c == L';' || c == L'\n') break;
            ++i;
        }
        if (quote == 0) continue;
        size_t end = qpos;
        while (end < body.size() && body[end] != quote) ++end;
        std::wstring url = body.substr(qpos, end - qpos);
        // Trim whitespace.
        while (!url.empty() && std::iswspace(static_cast<wint_t>(url.front())))
            url.erase(url.begin());
        while (!url.empty() && std::iswspace(static_cast<wint_t>(url.back())))
            url.pop_back();
        if (!url.empty() && url.size() < 256) return url;
    }
    return {};
}

// =============================================================================
// resolveRedirectPath — same-origin only
// =============================================================================

bool WebUiProbe::resolveRedirectPath(const std::wstring& redirect,
                                       const std::wstring& myIp,
                                       std::wstring& outPath,
                                       bool& outSecure) {
    std::wstring r = redirect;
    while (!r.empty() && std::iswspace(static_cast<wint_t>(r.front())))
        r.erase(r.begin());
    while (!r.empty() && std::iswspace(static_cast<wint_t>(r.back())))
        r.pop_back();

    // Protocol-relative — assume https.
    if (startsWith(r, L"//")) {
        return resolveRedirectPath(L"https:" + r, myIp, outPath, outSecure);
    }

    auto split = [&](const std::wstring& rest, bool secure) -> bool {
        size_t slash = rest.find(L'/');
        std::wstring host;
        std::wstring path;
        if (slash == std::wstring::npos) {
            host = rest; path = L"";
        } else {
            host = rest.substr(0, slash);
            path = rest.substr(slash + 1);
        }
        if (host == myIp || startsWith(host, myIp.c_str())) {
            outPath = L"/" + path;
            outSecure = secure;
            return true;
        }
        return false;
    };

    if (startsWith(r, L"https://"))
        return split(r.substr(8), true);
    if (startsWith(r, L"http://"))
        return split(r.substr(7), false);

    if (startsWith(r, L"/")) {
        outPath = r;
        outSecure = false; // caller keeps its own scheme
        return true;
    }
    outPath = L"/" + r;
    outSecure = false;
    return true;
}

// =============================================================================
// extractNamedElementText — find first id="X" / class="X" element body
// =============================================================================

std::wstring WebUiProbe::extractNamedElementText(const std::wstring& body,
                                                    const std::wstring& name) {
    std::wstring lower     = toLower(body);
    std::wstring nameLower = toLower(name);

    std::wstring needles[] = {
        L"id=\""    + nameLower + L"\"",
        L"id='"     + nameLower + L"'",
        L"class=\"" + nameLower + L"\"",
        L"class='"  + nameLower + L"'",
    };

    size_t attrPos = std::wstring::npos;
    for (auto& n : needles) {
        size_t p = lower.find(n);
        if (p != std::wstring::npos && p < attrPos) attrPos = p;
    }
    if (attrPos == std::wstring::npos) return {};

    // Walk left for '<'.
    size_t tagOpen = body.rfind(L'<', attrPos);
    if (tagOpen == std::wstring::npos) return {};

    // Element type — first whitespace / '>' delimited token after '<'.
    size_t i = tagOpen + 1;
    size_t tagNameEnd = i;
    while (tagNameEnd < body.size()) {
        wchar_t c = body[tagNameEnd];
        if (std::iswspace(static_cast<wint_t>(c)) || c == L'>') break;
        ++tagNameEnd;
    }
    if (tagNameEnd <= i) return {};
    std::wstring tagName = toLower(body.substr(i, tagNameEnd - i));
    if (tagName.empty()) return {};

    size_t gt = body.find(L'>', tagOpen);
    if (gt == std::wstring::npos) return {};
    size_t innerStart = gt + 1;

    std::wstring closeNeedle = L"</" + tagName + L">";
    size_t endRel = lower.find(closeNeedle, innerStart);
    if (endRel == std::wstring::npos) return {};
    std::wstring inner = body.substr(innerStart, endRel - innerStart);
    return stripHtmlTags(inner);
}

// =============================================================================
// stripHtmlTags — drop tags, decode named entities, collapse whitespace
// =============================================================================

std::wstring WebUiProbe::stripHtmlTags(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    bool inTag = false;
    for (wchar_t c : s) {
        if (c == L'<') inTag = true;
        else if (c == L'>') inTag = false;
        else if (!inTag) out.push_back(c);
    }

    auto replaceAll = [](std::wstring& dst, const std::wstring& a, const std::wstring& b) {
        size_t pos = 0;
        while ((pos = dst.find(a, pos)) != std::wstring::npos) {
            dst.replace(pos, a.size(), b);
            pos += b.size();
        }
    };
    replaceAll(out, L"&reg;",  L"®");
    replaceAll(out, L"&copy;", L"©");
    replaceAll(out, L"&amp;",  L"&");
    replaceAll(out, L"&nbsp;", L" ");
    replaceAll(out, L"&lt;",   L"<");
    replaceAll(out, L"&gt;",   L">");
    replaceAll(out, L"&#174;", L"®");

    // Collapse whitespace runs to single spaces. Trim ends.
    std::wstring res;
    res.reserve(out.size());
    bool lastSpace = true;
    for (wchar_t c : out) {
        if (std::iswspace(static_cast<wint_t>(c))) {
            if (!lastSpace) { res.push_back(L' '); lastSpace = true; }
        } else {
            res.push_back(c);
            lastSpace = false;
        }
    }
    while (!res.empty() && res.back() == L' ') res.pop_back();
    return res;
}

// =============================================================================
// parseDeviceFromTitle — brand keyword → "<Brand> (<title>)" or empty
// =============================================================================

std::wstring WebUiProbe::parseDeviceFromTitle(const std::wstring& title) {
    if (title.empty()) return {};
    const std::wstring& t = title;
    std::wstring tl = toLower(t);

    auto takeModelTail = [](const std::wstring& tail, bool allowSlash) {
        std::wstring out;
        out.reserve(40);
        for (size_t i = 0; i < tail.size() && out.size() < 40; ++i) {
            wchar_t c = tail[i];
            bool ok = (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z')
                   || (c >= L'0' && c <= L'9')
                   || c == L' ' || c == L'-' || (allowSlash && c == L'/');
            if (!ok) break;
            out.push_back(c);
        }
        // Trim.
        while (!out.empty() && out.back() == L' ') out.pop_back();
        while (!out.empty() && out.front() == L' ') out.erase(out.begin());
        return out;
    };

    static const wchar_t* kXeroxFamilies[] = {
        L"AltaLink", L"VersaLink", L"WorkCentre", L"ColorQube", L"Phaser"
    };
    for (auto family : kXeroxFamilies) {
        size_t pos = t.find(family);
        if (pos != std::wstring::npos) {
            std::wstring tail = t.substr(pos);
            std::wstring model = takeModelTail(tail, /*allowSlash=*/true);
            return L"Xerox " + model;
        }
    }
    static const wchar_t* kHpFamilies[] = {
        L"LaserJet", L"OfficeJet", L"DesignJet", L"PageWide", L"ColorJet"
    };
    for (auto family : kHpFamilies) {
        size_t pos = t.find(family);
        if (pos != std::wstring::npos) {
            std::wstring tail = t.substr(pos);
            std::wstring model = takeModelTail(tail, /*allowSlash=*/false);
            return L"HP " + model;
        }
    }
    if (contains(tl, L"routeros") || contains(tl, L"mikrotik"))
        return L"MikroTik (" + t + L")";
    if (contains(tl, L"unifi network") || contains(tl, L"unifi controller"))
        return L"Ubiquiti " + t;
    if (contains(tl, L"synology") || contains(tl, L"diskstation"))
        return L"Synology (" + t + L")";
    if (contains(tl, L"brother"))
        return L"Brother (" + t + L")";
    // Yealink IP phones — the SPA root JS-redirects to /api whose title is
    // "Yealink T58 Phone" / "Yealink SIP-T46G". Keep "Yealink <model>", drop
    // the trailing "... Phone" descriptor.
    if (contains(tl, L"yealink")) {
        std::wstring m = t;
        static const wchar_t* kTail[] = {
            L" enterprise ip phone", L" media phone", L" ip phone", L" phone"
        };
        std::wstring ml = toLower(m);
        for (auto tail : kTail) {
            size_t tln = 0; while (tail[tln]) ++tln;
            if (ml.size() >= tln && ml.compare(ml.size() - tln, tln, tail) == 0) {
                m.erase(m.size() - tln);
                break;
            }
        }
        trimWs(m);
        return m.empty() ? std::wstring(L"Yealink") : m;
    }

    static const wchar_t* kGenericBrands[] = {
        L"Canon", L"Epson", L"Lexmark", L"Konica Minolta", L"Ricoh", L"Kyocera"
    };
    for (auto brand : kGenericBrands) {
        std::wstring bl = toLower(std::wstring(brand));
        if (contains(tl, bl.c_str())) return std::wstring(brand) + L" (" + t + L")";
    }

    // Netgear ProSAFE family — pull leading uppercase+digit token.
    if (contains(tl, L"prosafe") || contains(tl, L"netgear")
     || contains(tl, L"smart managed switch")) {
        // Tokenise on whitespace.
        size_t start = 0;
        for (size_t i = 0; i <= t.size(); ++i) {
            if (i == t.size() || std::iswspace(static_cast<wint_t>(t[i]))) {
                if (i > start) {
                    std::wstring tok = t.substr(start, i - start);
                    if (tok.size() >= 4) {
                        wchar_t first = tok[0];
                        bool startsUpper = (first >= L'A' && first <= L'Z');
                        bool hasDigit  = false;
                        bool allValid  = true;
                        for (wchar_t c : tok) {
                            if (c >= L'0' && c <= L'9') hasDigit = true;
                            bool isAlnum = (c >= L'A' && c <= L'Z')
                                        || (c >= L'a' && c <= L'z')
                                        || (c >= L'0' && c <= L'9');
                            if (!isAlnum && c != L'-' && c != L'_') { allValid = false; break; }
                        }
                        if (startsUpper && hasDigit && allValid)
                            return L"Netgear " + tok;
                    }
                }
                start = i + 1;
            }
        }
        return L"Netgear (" + t + L")";
    }

    static const wchar_t* kBrands2[] = {
        L"D-Link", L"Zyxel", L"TRENDnet", L"Allied Telesis"
    };
    for (auto brand : kBrands2) {
        std::wstring bl = toLower(std::wstring(brand));
        if (contains(tl, bl.c_str())) return std::wstring(brand) + L" (" + t + L")";
    }
    if (contains(tl, L"tp-link") || contains(tl, L"tp link") || contains(tl, L"tplink"))
        return L"TP-Link (" + t + L")";
    static const wchar_t* kTpPrefixes[] = {
        L"TL-", L"Archer ", L"Deco ", L"Omada ", L"JetStream", L"EAP"
    };
    for (auto prefix : kTpPrefixes) {
        if (contains(t, prefix)) return L"TP-Link (" + t + L")";
    }
    if (contains(tl, L"mercusys")) return L"Mercusys (" + t + L")";
    if (contains(tl, L"tenda"))    return L"Tenda (" + t + L")";
    if (contains(tl, L"cudy"))     return L"Cudy (" + t + L")";
    if (contains(tl, L"reyee") || contains(tl, L"ruijie"))
        return L"Reyee / Ruijie (" + t + L")";
    if (contains(tl, L"asus router") || contains(tl, L"asuswrt") || contains(t, L"RT-"))
        return L"ASUS Router (" + t + L")";
    return {};
}

// =============================================================================
// extractModelFromBody — title → productName/switchInfo → body brand fallback
// =============================================================================

std::wstring WebUiProbe::extractModelFromBody(const std::wstring& body) {
    if (body.empty()) return {};
    std::wstring lower = toLower(body);

    // 1) Named model elements FIRST when they yield a brand+SKU. switchInfo
    //    (Netgear) / productName carry the exact SKU that the generic page
    //    <title> ("NETGEAR Web Managed Switch") lacks. The raw element text is
    //    remembered as a weak fallback used only after the title.
    static const wchar_t* kElementNames[] = {
        L"productName", L"switchInfo", L"device-name",
        L"header-product", L"productinfo", L"model-name"
    };
    std::wstring rawElement;
    for (auto name : kElementNames) {
        std::wstring text = extractNamedElementText(body, name);
        if (text.empty()) continue;
        if (rawElement.empty() && text.size() < 200) rawElement = text;
        std::wstring m = parseDeviceFromTitle(text);
        if (!m.empty()) return m;            // e.g. "Netgear XS716E"
    }

    // 2) <title>…</title>
    {
        size_t start = lower.find(L"<title");
        if (start != std::wstring::npos) {
            size_t gt = body.find(L'>', start);
            if (gt != std::wstring::npos) {
                size_t titleStart = gt + 1;
                size_t endRel = lower.find(L"</title>", titleStart);
                if (endRel != std::wstring::npos) {
                    std::wstring raw = body.substr(titleStart, endRel - titleStart);
                    std::wstring title = stripHtmlTags(raw);
                    if (!title.empty() && title.size() < 200) {
                        std::wstring m = parseDeviceFromTitle(title);
                        if (!m.empty()) return m;
                        // Only surface a bare title when it's a plausible model
                        // — never generic placeholders like "Loading..." /
                        // "Login" (would otherwise become the device's model).
                        if (!titleIsJunk(toLower(title)))
                            return L"HTTP title: " + title;
                    }
                }
            }
        }
    }

    // 3) Weak fallback — raw named-element text (no brand keyword matched).
    if (!rawElement.empty())
        return L"Web UI model: " + rawElement;

    // 4) Body-level brand keyword fallback.
    static const struct { const wchar_t* needle; const wchar_t* label; } kBrandPairs[] = {
        { L"tp-link",  L"TP-Link" },
        { L"tplink",   L"TP-Link" },
        { L"mikrotik", L"MikroTik" },
        { L"routeros", L"MikroTik / RouterOS" },
        { L"netgear",  L"Netgear" },
        { L"ubiquiti", L"Ubiquiti" },
        { L"unifi",    L"Ubiquiti UniFi" },
        { L"synology", L"Synology" },
        { L"qnap",     L"QNAP" },
        { L"xerox",    L"Xerox" },
        { L"brother",  L"Brother" },
        { L"hewlett",  L"HP" },
        { L"cisco",    L"Cisco" },
        { L"d-link",   L"D-Link" },
        { L"zyxel",    L"Zyxel" },
        { L"mercusys", L"Mercusys" },
        { L"tenda",    L"Tenda" },
    };
    for (const auto& kv : kBrandPairs) {
        if (contains(lower, kv.needle))
            return std::wstring(L"Web UI brand: ") + kv.label;
    }
    return {};
}

// =============================================================================
// probe — top-level orchestrator
// =============================================================================

std::wstring WebUiProbe::probe(const std::wstring& ip,
                                 const std::set<int>& openPorts,
                                 int timeoutMs) {
    if (!isValidIpv4(ip)) return {};
    if (openPorts.empty()) return {};

    // Try HTTPS (443 / 8443) first; fall back to plain HTTP (80). Mirrors the
    // GUI's previous on-click probe order. 1500 ms per fetch — TLS handshake
    // on embedded stacks (Xerox printers, legacy iLO, bargain switches)
    // routinely takes >500 ms to first byte.
    const int kTimeoutMs = timeoutMs > 0 ? timeoutMs : 1500;

    struct PortChoice { int port; bool secure; };
    // Fallback list. Standard 443/8443/80 first; if those don't give
    // us a body, try the common management-UI ports used by PBX (3CX
    // 5001/5443/5015), NAS (Synology DSM 5000/5001), iLO/iDRAC (623
    // RMCP isn't HTTP — skip), and dev/admin UIs (8080, 8081). The
    // loop breaks on first match so the extra ports only get queried
    // when the well-known ones are silent.
    static const PortChoice kProbeOrder[] = {
        { 443,  true },
        { 8443, true },
        { 80,   false },
        { 5001, true  },     // Synology DSM HTTPS, 3CX HTTPS
        { 5443, true  },     // 3CX HTTPS alt
        { 5000, false },     // Synology DSM HTTP, 3CX HTTP
        { 8081, false },     // common admin alt
        { 8080, false },     // common admin alt
    };

    for (const auto& ch : kProbeOrder) {
        if (!openPorts.count(ch.port)) continue;
        std::wstring body = ch.secure
            ? fetchHttps(ip, ch.port, L"/", kTimeoutMs)
            : fetchHttp(ip, ch.port, L"/", kTimeoutMs);
        if (body.empty()) continue;

        // Stub-page JS redirect — follow once on the same scheme.
        std::wstring target = detectJsRedirect(body);
        if (!target.empty()) {
            std::wstring path;
            bool secure = ch.secure;
            if (resolveRedirectPath(target, ip, path, secure)) {
                // Only refetch when the scheme matches the channel we're
                // on. A redirect that flips http→https on the same port
                // would send a TLS handshake to a plain HTTP socket;
                // skip in that case (the device may surface a model on
                // its dedicated 443/8443 probe anyway).
                if (secure == ch.secure) {
                    std::wstring refetched = ch.secure
                        ? fetchHttps(ip, ch.port, path, kTimeoutMs)
                        : fetchHttp(ip, ch.port, path, kTimeoutMs);
                    if (!refetched.empty()) body = std::move(refetched);
                }
            }
        }

        std::wstring model = extractModelFromBody(body);
        if (!model.empty()) return model;
    }
    return {};
}

// =============================================================================
// fetchHttpPost — plain HTTP/1.1 POST via TCP socket (form body)
// =============================================================================

std::wstring WebUiProbe::fetchHttpPost(const std::wstring& ip, int port,
                                        const std::wstring& path,
                                        const std::string& body, int timeoutMs) {
    if (!isValidIpv4(ip)) return {};

    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return {};

    DWORD to = static_cast<DWORD>(timeoutMs);
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                  reinterpret_cast<const char*>(&to), sizeof(to));
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                  reinterpret_cast<const char*>(&to), sizeof(to));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<u_short>(port));
    {
        std::string ipNarrow = toUtf8Narrow(ip);
        if (::inet_pton(AF_INET, ipNarrow.c_str(), &addr.sin_addr) != 1) {
            ::closesocket(sock);
            return {};
        }
    }

    u_long nb = 1;
    ::ioctlsocket(sock, FIONBIO, &nb);
    int rc = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == SOCKET_ERROR && ::WSAGetLastError() != WSAEWOULDBLOCK) {
        ::closesocket(sock);
        return {};
    }
    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    timeval tv; tv.tv_sec = timeoutMs / 1000; tv.tv_usec = (timeoutMs % 1000) * 1000;
    rc = ::select(0, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) { ::closesocket(sock); return {}; }
    int sockErr = 0; int sockErrLen = sizeof(sockErr);
    if (::getsockopt(sock, SOL_SOCKET, SO_ERROR,
                      reinterpret_cast<char*>(&sockErr), &sockErrLen) != 0 || sockErr != 0) {
        ::closesocket(sock);
        return {};
    }
    nb = 0;
    ::ioctlsocket(sock, FIONBIO, &nb);

    std::string ipNarrow   = toUtf8Narrow(ip);
    std::string pathNarrow = toUtf8Narrow(path.empty() ? std::wstring(L"/") : path);
    std::string uaNarrow   = toUtf8Narrow(kBrowserUserAgent);
    // Embedded admin backends (TP-Link LuCI, etc.) route AJAX POSTs only when
    // the request carries the same-origin Referer / Origin and the
    // X-Requested-With marker a browser's XHR sends — without them the CGI
    // dispatcher returns 404. These are benign on any POST target.
    std::string req =
        "POST " + pathNarrow + " HTTP/1.1\r\n"
        "Host: " + ipNarrow + "\r\n"
        "User-Agent: " + uaNarrow + "\r\n"
        "Accept: application/json,text/plain,*/*\r\n"
        "Referer: http://" + ipNarrow + "/\r\n"
        "Origin: http://" + ipNarrow + "\r\n"
        "X-Requested-With: XMLHttpRequest\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" + body;

    int sent = 0;
    const int reqLen = static_cast<int>(req.size());
    while (sent < reqLen) {
        int n = ::send(sock, req.data() + sent, reqLen - sent, 0);
        if (n <= 0) { ::closesocket(sock); return {}; }
        sent += n;
    }

    std::vector<char> resp;
    resp.reserve(8192);
    char chunk[4096];
    while (resp.size() < 65536) {
        int n = ::recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) break;
        resp.insert(resp.end(), chunk, chunk + n);
    }
    ::closesocket(sock);

    if (resp.empty()) return {};
    return fromUtf8Lossy(resp.data(), resp.size());
}

// =============================================================================
// fetchTpLinkModel — TP-Link LuCI router model via the anonymous locale API
// =============================================================================

std::wstring WebUiProbe::fetchTpLinkModel(const std::wstring& ip, int port,
                                           int timeoutMs) {
    std::wstring r = fetchHttpPost(
        ip, port, L"/cgi-bin/luci/;stok=/locale?form=lang",
        "operation=read", timeoutMs);
    if (r.empty()) return {};

    // Response is JSON: {"id":..,"result":{...,"model":"TL-ER6120 v3.0",..},..}.
    size_t k = r.find(L"\"model\"");
    if (k == std::wstring::npos) return {};
    size_t colon = r.find(L':', k + 7);
    if (colon == std::wstring::npos) return {};
    size_t q1 = r.find(L'"', colon);
    if (q1 == std::wstring::npos) return {};
    size_t q2 = r.find(L'"', q1 + 1);
    if (q2 == std::wstring::npos) return {};
    std::wstring model = r.substr(q1 + 1, q2 - q1 - 1);
    trimWs(model);
    if (model.empty() || model.size() > 48) return {};
    return model;
}

// =============================================================================
// fetchMikrotikModel — RouterOS version from the static <h1> landing heading
// =============================================================================

std::wstring WebUiProbe::fetchMikrotikModel(const std::wstring& ip, int port,
                                             int timeoutMs) {
    std::wstring body = (port == 443 || port == 8443)
        ? fetchHttps(ip, port, L"/", timeoutMs)
        : fetchHttp(ip, port, L"/", timeoutMs);
    if (body.empty()) return {};

    // Scan every <h1>…</h1> heading; return the first that names RouterOS.
    std::wstring lower = toLower(body);
    size_t pos = 0;
    while (true) {
        size_t h = lower.find(L"<h1", pos);
        if (h == std::wstring::npos) break;
        size_t gt = body.find(L'>', h);
        if (gt == std::wstring::npos) break;
        size_t end = lower.find(L"</h1>", gt);
        if (end == std::wstring::npos) break;
        std::wstring inner = stripHtmlTags(body.substr(gt + 1, end - (gt + 1)));
        trimWs(inner);
        if (toLower(inner).find(L"routeros") != std::wstring::npos
            && !inner.empty() && inner.size() < 48)
            return inner;                         // e.g. "RouterOS v6.29.1"
        pos = end + 5;
    }
    return {};
}

// =============================================================================
// fetchIloModel — HP/HPE iLO exact model + firmware from /xmldata?item=All
// =============================================================================

std::wstring WebUiProbe::fetchIloModel(const std::wstring& ip, int port,
                                        int timeoutMs) {
    std::wstring body = fetchHttps(ip, port, L"/xmldata?item=All", timeoutMs);
    if (body.empty()) return {};

    auto tag = [&](const wchar_t* name) -> std::wstring {
        std::wstring open  = std::wstring(L"<") + name + L">";
        std::wstring close = std::wstring(L"</") + name + L">";
        size_t a = body.find(open);
        if (a == std::wstring::npos) return {};
        a += open.size();
        size_t b = body.find(close, a);
        if (b == std::wstring::npos) return {};
        std::wstring v = body.substr(a, b - a);
        trimWs(v);
        return v;
    };

    std::wstring pn = tag(L"PN");      // "Integrated Lights-Out 4 (iLO 4)"
    if (pn.empty()) return {};
    std::wstring fw = tag(L"FWRI");    // "2.40"

    // Prefer the short "(iLO N)" parenthetical; else map "Lights-Out N".
    std::wstring model;
    size_t lp = pn.find(L"(iLO");
    if (lp == std::wstring::npos) lp = pn.find(L"(iLo");
    if (lp != std::wstring::npos) {
        size_t rp = pn.find(L')', lp);
        size_t from = lp + 1;
        size_t to   = (rp == std::wstring::npos) ? pn.size() : rp;
        model = pn.substr(from, to - from);          // "iLO 4"
    } else {
        size_t lo = pn.find(L"Lights-Out");
        if (lo != std::wstring::npos) {
            std::wstring num;
            for (size_t i = lo; i < pn.size() && num.empty(); ++i)
                if (pn[i] >= L'0' && pn[i] <= L'9') num.push_back(pn[i]);
            model = num.empty() ? std::wstring(L"iLO") : (L"iLO " + num);
        } else {
            model = pn;   // unknown format — fall back to the raw product name
        }
    }
    trimWs(model);
    if (model.empty()) return {};
    if (!fw.empty()) model += L" (fw " + fw + L")";
    return model;
}

// =============================================================================
// deriveExactModel — per-device-type model resolution for the Model column
// =============================================================================

std::wstring WebUiProbe::deriveExactModel(const std::wstring& deviceTypeLower,
                                           const std::wstring& vendorLower,
                                           const std::set<int>& openPorts,
                                           const std::wstring& webUiModel,
                                           const std::wstring& ip,
                                           int timeoutMs) {
    const bool has443  = openPorts.count(443)  != 0;
    const bool has8443 = openPorts.count(8443) != 0;
    auto tryIlo = [&]() -> std::wstring {
        if (!(has443 || has8443)) return {};
        return fetchIloModel(ip, has443 ? 443 : 8443, timeoutMs);
    };

    // ---- 1) Explicit iLO (device type / vendor) — authoritative /xmldata ----
    const bool iloLike =
        deviceTypeLower.find(L"ilo") != std::wstring::npos ||
        (vendorLower.find(L"hpe") != std::wstring::npos && (has443 || has8443) &&
         deviceTypeLower.find(L"printer") == std::wstring::npos);
    if (iloLike) {
        std::wstring m = tryIlo();
        if (!m.empty()) return m;
    }

    // ---- 1b) TP-Link business/Omada — anonymous LuCI locale API ------------
    // The page <title> is JS-rendered ("Opening..." in the static HTML), so a
    // static GET can't read the model. The locale endpoint returns it as JSON.
    if (vendorLower.find(L"tp-link") != std::wstring::npos
        || vendorLower.find(L"tplink") != std::wstring::npos
        || vendorLower.find(L"tp link") != std::wstring::npos) {
        int tport = openPorts.count(80) ? 80
                  : (openPorts.count(8080) ? 8080 : 0);
        if (tport) {
            std::wstring m = fetchTpLinkModel(ip, tport, timeoutMs);
            if (!m.empty()) return m;
        }
    }

    // ---- 1c) MikroTik — RouterOS version from the static <h1> heading ------
    if (vendorLower.find(L"mikrotik") != std::wstring::npos
        || vendorLower.find(L"routerboard") != std::wstring::npos
        || deviceTypeLower.find(L"mikrotik") != std::wstring::npos) {
        int mport = openPorts.count(80) ? 80
                  : (has443 ? 443 : (openPorts.count(8080) ? 8080 : 0));
        if (mport) {
            std::wstring m = fetchMikrotikModel(ip, mport, timeoutMs);
            if (!m.empty()) return m;
        }
    }

    // ---- 2) Per-VENDOR web model (never a raw page title) ------------------
    // The Model column must carry a real hardware model, identified by the
    // device's manufacturer — NOT whatever the admin page's <title> happens to
    // say. A generic title fallback produced junk like "Opening...", "Welcome
    // to XAMPP", "Moved Temporarily", "Not Found" and verbose login banners,
    // and even leaked one device's model onto another. So a web-derived model
    // is accepted ONLY for vendors/types where the page reliably exposes the
    // SKU. Everything else (TP-Link, MikroTik, Synology, Cisco, plain servers)
    // is intentionally left blank here.
    std::wstring w = webUiModel;
    if (!w.empty()) {
        if (startsWith(w, L"Web UI brand: "))      w.clear();   // brand only
        else if (startsWith(w, L"HTTP title: "))   w = w.substr(12);
        else if (startsWith(w, L"Web UI model: ")) w = w.substr(14);
        trimWs(w);
        if (!w.empty() && !titleIsJunk(toLower(w))) {
            // Whitelist of manufacturers whose web UI carries the exact model:
            //   Netgear (switchInfo SKU), Thecus (NAS model in title),
            //   Yealink (phone model in title), Panasonic (camera model),
            //   Xerox (printer model). Easy to extend as more are verified.
            std::wstring hay = vendorLower + L" " + deviceTypeLower + L" "
                             + toLower(w);
            static const wchar_t* kAllow[] = {
                L"netgear", L"thecus", L"yealink", L"panasonic", L"xerox"
            };
            bool allow = false;
            for (auto a : kAllow)
                if (hay.find(a) != std::wstring::npos) { allow = true; break; }
            if (allow) {
                if (w.size() > 64) { w.resize(64); trimWs(w); }
                return w;
            }
        }
    }
    return {};
}

} // namespace lanscope
