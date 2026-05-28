#ifndef NETLENS_MOCK_DATA_H
#define NETLENS_MOCK_DATA_H

// Mock-data feed for `NetLens.exe --mock`.
//
// Used only for documentation screenshots / the 3389.ro tool page. Lets us
// capture a populated main window and a clean HTML export without ever
// touching a real subnet. The mock fleet uses RFC-1918 IPs (192.168.1.0/24)
// and real public IEEE OUI prefixes for vendor lookups — every MAC suffix
// is fabricated.

#include <string>
#include <vector>

#include "Models.h"

namespace nl::mock {

// Returns the 15-host fleet that the screenshots show. Each row is a fully
// populated HostRow (open ports, services, brand/web/UDP hints, etc.).
std::vector<HostRow> BuildHosts();

// Completed-scan stats matching BuildHosts(). Sets duration / online count /
// progress to the values shown in the captures.
ScanStats BuildStats();

// UTF-8 HTML payload the mock-mode "Export HTML" button writes to disk —
// mirrors the engine's output format. Pointer is into static const storage;
// the caller must NOT free it.
const char* ExportHtmlBytes();
size_t      ExportHtmlSize();

}  // namespace nl::mock

#endif // NETLENS_MOCK_DATA_H
