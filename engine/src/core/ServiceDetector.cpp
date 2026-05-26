#include "ServiceDetector.h"

#include "ScanPresetService.h"

namespace lanscope {

void ServiceDetector::annotate(std::vector<PortStatus>& ports) {
    for (auto& p : ports) {
        if (p.service.empty()) {
            p.service = ScanPresetService::serviceFor(p.port);
        }
    }
}

} // namespace lanscope
