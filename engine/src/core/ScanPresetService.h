#pragma once

#include "../Models.h"

#include <string>
#include <vector>

namespace lanscope {

/// Resolves preset names to port lists and exposes the full preset catalogue
/// for the GUI dropdown and the CLI --preset flag.
class ScanPresetService {
public:
    /// Returns the canonical list of presets in display order.
    static const std::vector<ScanPreset>& presets();

    /// Looks up a preset by its machine id. Case-insensitive match.
    /// Returns nullptr if not found.
    static const ScanPreset* find(const std::wstring& id);

    /// Parses a comma-separated port list ("22, 80, 443") into a vector.
    /// Duplicates and invalid entries are skipped silently.
    /// Returns empty when the string contains no valid ports.
    static std::vector<int> parsePortList(const std::wstring& csv);

    /// Formats a port list back into "22,80,443" form.
    static std::wstring formatPortList(const std::vector<int>& ports);

    /// Returns the friendly service name for a well-known port, or an empty
    /// string when unknown.
    static std::wstring serviceFor(int port);
};

} // namespace lanscope
