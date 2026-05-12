#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace netlens {

/// Small fixed-size thread pool with cooperative cancellation.
/// Workers pull tasks from a shared queue; cancellation simply signals the
/// queue to stop dispensing new work and lets in-flight tasks finish.
class ThreadPool {
public:
    explicit ThreadPool(size_t numThreads);
    ~ThreadPool();

    ThreadPool(const ThreadPool&)            = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /// Submit a task. Returns a future for the result.
    /// If shutdown has been requested, the task is dropped and the future
    /// receives a cancelled state via a broken promise.
    template <typename F>
    auto submit(F&& fn) -> std::future<decltype(fn())>;

    /// Signal cooperative cancellation. Tasks queued after this call return
    /// immediately. In-flight tasks should check cancelRequested() themselves.
    void requestCancel();

    [[nodiscard]] bool cancelRequested() const { return cancel_.load(); }

    /// Block until every queued task has finished, then join workers.
    void waitAll();

    [[nodiscard]] size_t threadCount() const { return workers_.size(); }

private:
    void shutdown();

    std::vector<std::thread>                 workers_;
    std::queue<std::function<void()>>        tasks_;
    std::mutex                               mu_;
    std::condition_variable                  cv_;
    std::atomic<bool>                        stop_{false};
    std::atomic<bool>                        cancel_{false};
    std::atomic<size_t>                      inflight_{0};
    std::condition_variable                  doneCv_;
};

template <typename F>
auto ThreadPool::submit(F&& fn) -> std::future<decltype(fn())> {
    using R = decltype(fn());
    auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(fn));
    auto fut = task->get_future();
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stop_.load() || cancel_.load()) {
            // Drop the task. The future will produce a broken_promise.
            return fut;
        }
        ++inflight_;
        tasks_.emplace([task]() { (*task)(); });
    }
    cv_.notify_one();
    return fut;
}

} // namespace netlens
