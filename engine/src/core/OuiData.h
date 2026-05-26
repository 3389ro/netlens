#pragma once

#include <cstddef>

namespace lanscope {

/// Raw Nmap OUI database, embedded into the executable.
/// One entry per line in the form "HEXPREFIX VENDOR NAME\n". Prefix is 6, 7
/// or 9 hex chars (24-, 28- or 36-bit OUI assignments). Comments and blank
/// lines are stripped at generation time.
extern const char* const kOuiBlob;
extern const std::size_t  kOuiBlobSize;

} // namespace lanscope
