#pragma once

#include <string>

namespace lanscope {

/// Compacts an OUI vendor string into a short, display-friendly form.
///
/// The Nmap OUI database returns the registered company name verbatim:
/// "Hewlett Packard Enterprise", "Hangzhou Hikvision Digital Technology
/// Co.,Ltd.", "Cisco Systems, Inc." — fine for legal disclosure, terrible
/// for a 110-px-wide Vendor column. This class collapses the few dozen
/// brands the user actually scans into a short tag ("HPE", "Hikvision",
/// "Cisco") and trims trailing legal boilerplate from anything else.
///
/// Matching is case-insensitive substring / prefix on a hand-curated table.
/// The fallback path strips ", Inc.", " Corp.", " Co.,Ltd.", " GmbH", etc.
/// so "Foo Corporation" → "Foo".
class VendorShortener {
public:
    static std::wstring shorten(const std::wstring& vendor);
};

} // namespace lanscope
