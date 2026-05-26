#include "VendorShortener.h"

#include <algorithm>
#include <cwctype>

namespace lanscope {

namespace {

std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

bool startsWith(const std::wstring& s, const wchar_t* needle) {
    size_t n = 0; while (needle[n]) ++n;
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) if (s[i] != needle[i]) return false;
    return true;
}

bool contains(const std::wstring& s, const wchar_t* needle) {
    return s.find(needle) != std::wstring::npos;
}

bool endsWithCi(const std::wstring& s, const std::wstring& suffix) {
    if (s.size() < suffix.size()) return false;
    std::wstring tail = s.substr(s.size() - suffix.size());
    return toLower(tail) == toLower(suffix);
}

// Right-trim trailing comma/space/dot from a vendor name after a known
// suffix has been stripped. "Foo, Inc." -> remove " Inc." -> "Foo," ->
// trim -> "Foo".
void rtrimSeparators(std::wstring& s) {
    while (!s.empty()) {
        wchar_t c = s.back();
        if (c == L',' || c == L'.' || c == L' ' || c == L'\t') s.pop_back();
        else break;
    }
}

} // anonymous namespace

std::wstring VendorShortener::shorten(const std::wstring& vendor) {
    if (vendor.empty()) return {};
    const std::wstring v = toLower(vendor);

    // Order matters: longer specific prefixes first ("Hewlett Packard
    // Enterprise" before "Hewlett Packard"), otherwise the broader
    // match wins and we lose the HPE/HP distinction.
    if (startsWith(v, L"hewlett packard enterprise")
     || startsWith(v, L"hewlett-packard enterprise"))      return L"HPE";
    if (startsWith(v, L"hewlett packard")
     || startsWith(v, L"hewlett-packard")
     || startsWith(v, L"hp inc"))                          return L"HP";
    if (startsWith(v, L"cisco systems") || v == L"cisco")  return L"Cisco";
    if (startsWith(v, L"apple"))                           return L"Apple";
    if (startsWith(v, L"microsoft"))                       return L"Microsoft";
    if (startsWith(v, L"vmware"))                          return L"VMware";
    if (startsWith(v, L"ubiquiti"))                        return L"Ubiquiti";
    if (startsWith(v, L"synology"))                        return L"Synology";
    if (startsWith(v, L"giga-byte") || startsWith(v, L"gigabyte")) return L"Gigabyte";
    if (contains(v, L"hikvision"))                         return L"Hikvision";
    if (contains(v, L"dahua"))                             return L"Dahua";
    if (startsWith(v, L"tp-link") || startsWith(v, L"tplink")) return L"TP-Link";
    if (startsWith(v, L"azurewave"))                       return L"AzureWave";
    if (startsWith(v, L"murata"))                          return L"Murata";
    if (startsWith(v, L"asustek") || v == L"asus" || startsWith(v, L"asus "))
        return L"ASUS";
    if (startsWith(v, L"intel"))                           return L"Intel";
    if (startsWith(v, L"realtek"))                         return L"Realtek";
    if (startsWith(v, L"mikrotik") || startsWith(v, L"routerboard"))
        return L"Mikrotik";
    if (startsWith(v, L"zebra"))                           return L"Zebra";
    if (startsWith(v, L"xerox"))                           return L"Xerox";
    if (startsWith(v, L"hangzhou xiaomi") || startsWith(v, L"xiaomi"))
        return L"Xiaomi";
    if (startsWith(v, L"sonos"))                           return L"Sonos";
    if (startsWith(v, L"netgear"))                         return L"Netgear";
    if (startsWith(v, L"d-link") || startsWith(v, L"dlink") || startsWith(v, L"d link"))
        return L"D-Link";
    if (startsWith(v, L"brother"))                         return L"Brother";
    if (startsWith(v, L"canon"))                           return L"Canon";
    if (startsWith(v, L"seiko epson") || startsWith(v, L"epson"))
        return L"Epson";
    if (startsWith(v, L"lexmark"))                         return L"Lexmark";
    if (startsWith(v, L"kyocera"))                         return L"Kyocera";
    if (startsWith(v, L"ricoh"))                           return L"Ricoh";
    if (startsWith(v, L"konica"))                          return L"Konica Minolta";
    if (startsWith(v, L"samsung"))                         return L"Samsung";
    if (startsWith(v, L"lg electronics") || startsWith(v, L"lg "))
        return L"LG";
    if (startsWith(v, L"zyxel"))                           return L"Zyxel";
    if (startsWith(v, L"fortinet"))                        return L"Fortinet";
    if (startsWith(v, L"juniper"))                         return L"Juniper";
    if (startsWith(v, L"google"))                          return L"Google";
    if (startsWith(v, L"amazon"))                          return L"Amazon";
    if (startsWith(v, L"sony"))                            return L"Sony";
    if (startsWith(v, L"dell"))                            return L"Dell";
    if (startsWith(v, L"lenovo"))                          return L"Lenovo";
    if (startsWith(v, L"raspberry pi"))                    return L"Raspberry Pi";
    if (startsWith(v, L"espressif"))                       return L"Espressif";
    if (startsWith(v, L"nordic semi"))                     return L"Nordic";
    if (startsWith(v, L"qnap"))                            return L"QNAP";

    // Generic suffix trim: drop trailing legal boilerplate so
    // "Foo Corporation" / "Foo, Inc." / "Foo Co.,Ltd." all collapse to "Foo".
    std::wstring t = vendor;
    // Strip leading/trailing whitespace.
    while (!t.empty() && std::iswspace(static_cast<wint_t>(t.front()))) t.erase(t.begin());
    rtrimSeparators(t);

    static const std::wstring kSuffixes[] = {
        L", Inc.", L", Inc",  L" Inc.",  L" Inc",
        L", Ltd.", L", Ltd",  L" Ltd.",  L" Ltd",
        L" Corp.", L" Corp",  L" Corporation",
        L", Co.,Ltd.", L" Co.,Ltd.", L" Co., Ltd.", L" Co.,Ltd",
        L" GmbH",  L" S.A.",  L" S.r.l.",
    };

    bool stripped = true;
    while (stripped) {
        stripped = false;
        for (const auto& sfx : kSuffixes) {
            if (endsWithCi(t, sfx)) {
                t.erase(t.size() - sfx.size());
                rtrimSeparators(t);
                stripped = true;
                break;
            }
        }
    }
    return t;
}

} // namespace lanscope
