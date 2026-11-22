#ifndef REB_SERVICES_STOP_SIGNAL_HPP_
#define REB_SERVICES_STOP_SIGNAL_HPP_

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <initializer_list>

namespace reb::services {

// A stop request that every blocking wait observes.
//
// A handler that only sets a flag loses a signal that arrives after a wait
// checked the flag and before it blocked, or while the service was busy and
// not blocked at all: the service then waits for its peer's next byte,
// connection or session deadline, which an idle browser never sends. The
// handler therefore also writes to a pipe that every wait polls beside its
// descriptor. Nothing drains the pipe, so once written it wakes every later
// wait too.
class StopSignal final {
 public:
  enum class Wait { kReady, kStopped, kTimedOut, kInterrupted, kFailed };

  // Routes each signal to the stop request. False, with errno set, when the
  // pipe or a handler cannot be installed. Call once, before any wait.
  static bool Install(const std::initializer_list<int> signals) noexcept {
    int descriptors[2] = {-1, -1};
    if (pipe(descriptors) != 0) {
      return false;
    }
    for (const int descriptor : descriptors) {
      const int flags = fcntl(descriptor, F_GETFL);
      if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0 ||
          fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        const int error = errno;
        close(descriptors[0]);
        close(descriptors[1]);
        errno = error;
        return false;
      }
    }
    read_end_.store(descriptors[0], std::memory_order_relaxed);
    write_end_.store(descriptors[1], std::memory_order_relaxed);
    struct sigaction action {};
    action.sa_handler = Request;
    // Waits learn of a stop from the pipe, never from EINTR, so every other
    // interrupted call can restart.
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    for (const int number : signals) {
      if (sigaction(number, &action, nullptr) != 0) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] static bool Requested() noexcept { return requested_ != 0; }

  // Waits until `descriptor` is readable or has hung up, `timeout_ms` passes
  // (-1 waits without a deadline) or a stop is requested. A stop wins when
  // both are ready. kInterrupted lets the caller recompute its deadline.
  [[nodiscard]] static Wait Readable(const int descriptor, const int timeout_ms) noexcept {
    if (Requested()) {
      return Wait::kStopped;
    }
    pollfd waits[2] = {{descriptor, static_cast<short>(POLLIN), 0},
                       {read_end_.load(std::memory_order_relaxed), static_cast<short>(POLLIN), 0}};
    const int ready = poll(waits, 2, timeout_ms);
    if (ready > 0) {
      return Requested() || waits[1].revents != 0 ? Wait::kStopped : Wait::kReady;
    }
    if (ready == 0) {
      return Wait::kTimedOut;
    }
    return errno == EINTR ? Wait::kInterrupted : Wait::kFailed;
  }

 private:
  static void Request(int) noexcept {
    const int saved = errno;
    requested_ = 1;
    // The write end is nonblocking: a full pipe already wakes every wait.
    static_cast<void>(write(write_end_.load(std::memory_order_relaxed), "", 1));
    errno = saved;
  }

  // Lock-free atomics are the objects besides sig_atomic_t that a signal
  // handler may read. Install stores both before it installs the handler.
  static_assert(std::atomic<int>::is_always_lock_free);
  static inline volatile std::sig_atomic_t requested_ = 0;
  static inline std::atomic<int> read_end_{-1};
  static inline std::atomic<int> write_end_{-1};
};

}  // namespace reb::services

#endif  // REB_SERVICES_STOP_SIGNAL_HPP_
