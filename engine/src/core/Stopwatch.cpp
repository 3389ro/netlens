#include "Stopwatch.h"

namespace lanscope {

Stopwatch::Stopwatch() : start_(std::chrono::steady_clock::now()) {}

void Stopwatch::restart() {
    start_ = std::chrono::steady_clock::now();
}

int64_t Stopwatch::elapsedMs() const {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now() - start_).count();
}

} // namespace lanscope
