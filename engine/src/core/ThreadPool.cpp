#include "ThreadPool.h"

namespace lanscope {

ThreadPool::ThreadPool(size_t numThreads) {
    if (numThreads == 0) numThreads = 1;
    workers_.reserve(numThreads);
    for (size_t i = 0; i < numThreads; ++i) {
        workers_.emplace_back([this] {
            for (;;) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lk(mu_);
                    cv_.wait(lk, [this] { return stop_.load() || !tasks_.empty(); });

                    if (stop_.load() && tasks_.empty()) return;

                    task = std::move(tasks_.front());
                    tasks_.pop();
                }

                try {
                    task();
                } catch (...) {
                    // Tasks must never propagate exceptions across the pool boundary;
                    // a packaged_task already captures the exception into its future.
                }

                const size_t remaining = inflight_.fetch_sub(1) - 1;
                if (remaining == 0) {
                    std::lock_guard<std::mutex> dk(mu_);
                    doneCv_.notify_all();
                }
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::requestCancel() {
    cancel_.store(true);
}

void ThreadPool::waitAll() {
    std::unique_lock<std::mutex> lk(mu_);
    doneCv_.wait(lk, [this] { return inflight_.load() == 0; });
}

void ThreadPool::shutdown() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stop_.store(true);
    }
    cv_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
}

} // namespace lanscope
