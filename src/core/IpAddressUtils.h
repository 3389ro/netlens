#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace netlens {

/// IPv4 utility helpers — no exceptions, all functions return optional or bool.
namespace ip {

/// Parses a dotted-decimal IPv4 string. Returns the address in HOST byte order
/// (i.e. for "192.168.1.1" returns 0xC0A80101). std::nullopt on bad input.
std::optional<uint32_t> parseDotted(const std::wstring& s);

/// Same as above for narrow strings (handy for CLI parsing).
std::optional<uint32_t> parseDotted(const std::string& s);

/// Formats a host-order uint32 as "a.b.c.d".
std::wstring formatDotted(uint32_t hostOrder);

/// Returns the netmask for a /n prefix as a host-order uint32.
/// prefix must be in [0, 32]; values outside that range produce 0.
uint32_t prefixToMask(int prefix);

/// Computes the prefix length implied by a contiguous mask (e.g. 255.255.255.0 -> 24).
/// Returns std::nullopt for non-contiguous masks.
std::optional<int> maskToPrefix(uint32_t hostOrderMask);

/// Returns the network base (host-order ip & mask).
uint32_t networkAddress(uint32_t hostOrderIp, uint32_t hostOrderMask);

/// Returns the broadcast address for the given network.
uint32_t broadcastAddress(uint32_t hostOrderIp, uint32_t hostOrderMask);

/// Converts a MAC byte array (6 bytes) to "AA-BB-CC-DD-EE-FF".
std::wstring formatMac(const uint8_t* bytes, size_t len);

} // namespace ip
} // namespace netlens
