#pragma once

#include "../Models.h"

#include <vector>

namespace netlens {

/// Lightweight service-label decorator. v1 keeps it strictly port-based —
/// no banner grabbing — to avoid the latency and reliability problems of
/// active probing during a fast LAN sweep.
class ServiceDetector {
public:
    /// Fills the `service` field on every open port using the canonical
    /// port→service map. No-op for closed ports.
    static void annotate(std::vector<PortStatus>& ports);
};

} // namespace netlens
