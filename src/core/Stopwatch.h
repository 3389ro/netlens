#pragma once

#include <chrono>
#include <cstdint>

namespace netlens {

/// Lightweight wall-clock stopwatch built on std::chrono::steady_clock.
class Stopwatch {
public:
    Stopwatch();
    void restart();
    [[nodiscard]] int64_t elapsedMs() const;

private:
    std::chrono::steady_clock::time_point start_;
};

} // namespace netlens
