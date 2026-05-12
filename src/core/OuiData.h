#pragma once

#include <cstddef>

namespace netlens {

/// Raw IEEE Registration Authority OUI assignment data, embedded into the
/// executable. One entry per line in the form "HEXPREFIX VENDOR NAME\n".
/// Prefix is 6, 7 or 9 hex chars (MA-L /24, MA-M /28, MA-S /36 assignments).
/// Public IEEE records — no copyright claim, no attribution required.
extern const char* const kOuiBlob;
extern const std::size_t  kOuiBlobSize;

} // namespace netlens
