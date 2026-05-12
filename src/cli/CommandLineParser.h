#pragma once

#include <string>
#include <vector>

namespace netlens {

/// CLI argument parser. Only the NetLens-specific options are recognised;
/// anything unknown produces an error.
class CommandLineParser {
public:
    struct Args {
        bool         showHelp           = false;
        bool         listAdapters       = false;

        std::wstring range;
        int          adapterIndex       = -1;       ///< -1 = not set
        std::wstring presetId           = L"quick"; ///< default preset
        std::wstring modeId             = L"deep";  ///< default mode (v1.0.8: was "fast")
        std::wstring portsCsv;
        int          timeoutMs          = 400;      ///< v1 perf-tuned default
        int          parallel           = 128;      ///< v1 perf-tuned default

        std::wstring csvPath;
        std::wstring htmlPath;

        bool         onlineOnly         = false;
        bool         noDns              = false;
        bool         noMac              = false;
        bool         noUdp              = false;
        bool         noPorts            = false;
        bool         allowLargeRange    = false;
        bool         debug              = false;

        bool         hasError           = false;
        std::wstring error;

        /// True if the parsed args indicate the user wants CLI mode.
        bool wantsCli() const {
            return showHelp || listAdapters || !range.empty() || adapterIndex >= 0;
        }
    };

    /// argv[0] is treated as the program name and ignored.
    static Args parse(int argc, wchar_t** argv);

    /// Renders the help text. Pure function — useful for tests.
    static std::wstring helpText();
};

} // namespace netlens
