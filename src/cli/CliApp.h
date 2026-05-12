#pragma once

namespace netlens {

/// CLI entry point. Returns one of the AppConstants exit codes.
/// argv is wide so we handle Unicode paths correctly.
class CliApp {
public:
    static int run(int argc, wchar_t** argv);
};

} // namespace netlens
