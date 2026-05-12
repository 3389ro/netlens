#pragma once

#include "../Models.h"

#include <string>
#include <vector>

namespace netlens {

/// Resolves preset names to port lists and exposes the full preset catalogue
/// for the GUI dropdown and the CLI --preset flag.
///
/// The GUI-visible preset list is mutable (the Tools → Manage port presets
/// dialog can add / edit / delete entries). Changes are kept in memory only;
/// they do not persist across app restarts in this build. Legacy CLI-only
/// presets (windows / remote / web) are immutable and remain searchable via
/// find() so existing scripts keep working.
class ScanPresetService {
public:
    /// Returns the GUI-visible preset list, in display order. The reference
    /// is invalidated by any call to setPresets() — re-fetch after edits.
    static const std::vector<ScanPreset>& presets();

    /// Looks up a preset by its machine id. Case-insensitive match. Searches
    /// the GUI list first, then the immutable legacy CLI catalogue. Returns
    /// nullptr if not found.
    static const ScanPreset* find(const std::wstring& id);

    /// Replaces the GUI-visible preset list. The "all" and "custom" sentinel
    /// presets are auto-appended at the tail if missing, so the editor and
    /// dropdown keep working consistently after edits.
    static void setPresets(std::vector<ScanPreset> presets);

    /// Returns the user-editable default presets (excludes the auto-managed
    /// "all" and "custom" sentinels). Used by the preset manager's Reset
    /// button to restore the out-of-box list.
    static std::vector<ScanPreset> defaultPresets();

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

} // namespace netlens
