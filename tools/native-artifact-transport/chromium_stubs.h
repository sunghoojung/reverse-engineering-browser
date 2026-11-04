// Narrow Chromium platform adapters for the production browser socket
// clients. Locks, threads and task runners are real std:: primitives so the
// writer threads, reconnect waits and stop joins actually run concurrently.
// The probe session and capture sinks are recording doubles.
#pragma once

#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <mutex>
#include <new>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"

#define BUILDFLAG(flag) (flag)
#define IS_POSIX 1
#define GUARDED_BY(lock)
#define FROM_HERE ::base::Location()

// Not reference counted: every runner here outlives the test.
template <class T>
class scoped_refptr {
 public:
  scoped_refptr() = default;
  scoped_refptr(T* value) : value_(value) {}  // NOLINT: mirrors implicit raw conversion.
  T* operator->() const { return value_; }
  explicit operator bool() const { return value_ != nullptr; }
  void reset() { value_ = nullptr; }

 private:
  T* value_ = nullptr;
};

namespace base {

template <class T>
class NoDestructor {
 public:
  NoDestructor() { ::new (static_cast<void*>(storage_.data())) T; }
  T& operator*() { return *std::launder(reinterpret_cast<T*>(storage_.data())); }
  T* operator->() { return &**this; }

 private:
  alignas(T) std::array<std::byte, sizeof(T)> storage_;
};

// Preserve std::span deduction guides instead of alias-template CTAD.
using std::span;
template <class T>
std::span<const std::uint8_t> byte_span_from_ref(const T& value) {
  return {reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)};
}
template <class T>
std::span<std::uint8_t> byte_span_from_ref(T& value) {
  return {reinterpret_cast<std::uint8_t*>(&value), sizeof(value)};
}
template <class Container>
std::span<const std::uint8_t> as_byte_span(const Container& container) {
  return {reinterpret_cast<const std::uint8_t*>(std::data(container)),
          std::size(container) * sizeof(*std::data(container))};
}
template <class T, std::size_t N>
std::span<const std::uint8_t> as_bytes(std::span<T, N> values) {
  return {reinterpret_cast<const std::uint8_t*>(values.data()), values.size_bytes()};
}

struct Location {};

class TimeDelta {
 public:
  constexpr TimeDelta() = default;
  constexpr explicit TimeDelta(std::int64_t ns) : ns_(ns) {}
  constexpr std::int64_t InNanoseconds() const { return ns_; }
  constexpr bool is_positive() const { return ns_ > 0; }
  std::chrono::nanoseconds ToChrono() const { return std::chrono::nanoseconds(ns_); }

 private:
  std::int64_t ns_ = 0;
};
constexpr TimeDelta Milliseconds(std::int64_t value) {
  return TimeDelta(value * 1'000'000);
}

class TimeTicks {
 public:
  static TimeTicks Now() {
    return TimeTicks(std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count());
  }
  TimeDelta since_origin() const { return TimeDelta(ns_); }
  TimeTicks operator+(const TimeDelta delta) const {
    return TimeTicks(ns_ + delta.InNanoseconds());
  }
  TimeDelta operator-(const TimeTicks other) const { return TimeDelta(ns_ - other.ns_); }

 private:
  explicit TimeTicks(std::int64_t ns) : ns_(ns) {}
  std::int64_t ns_ = 0;
};

// The browser process ID every browser-owned record must carry.
inline constexpr int kTestBrowserProcessId = 42;
inline int GetCurrentProcId() {
  return kTestBrowserProcessId;
}
struct TestThreadId {
  std::uint64_t raw() const { return 7; }
};
struct PlatformThread {
  static TestThreadId CurrentId() { return {}; }
};

class FilePath {
 public:
  FilePath() = default;
  explicit FilePath(std::string value) : value_(std::move(value)) {}
  bool empty() const { return value_.empty(); }
  const std::string& value() const { return value_; }
  FilePath AppendASCII(std::string_view component) const {
    return FilePath(value_ + "/" + std::string(component));
  }

 private:
  std::string value_;
};
inline FilePath MakeAbsoluteFilePath(const FilePath& path) {
  return path;
}

inline bool StringToUint64(std::string_view text, std::uint64_t* value) {
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), *value);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

class CommandLine {
 public:
  static CommandLine* ForCurrentProcess() {
    static CommandLine command_line;
    return &command_line;
  }
  bool HasSwitch(std::string_view name) const { return switches.contains(name); }
  std::string GetSwitchValueASCII(std::string_view name) const {
    const auto found = switches.find(name);
    return found == switches.end() ? std::string() : found->second;
  }
  FilePath GetSwitchValuePath(std::string_view name) const {
    return FilePath(GetSwitchValueASCII(name));
  }
  std::map<std::string, std::string, std::less<>> switches;
};

class LogLine {
 public:
  explicit LogLine(const char* severity) { stream_ << "[" << severity << "] "; }
  ~LogLine() { std::cerr << stream_.str() << '\n'; }
  std::ostream& stream() { return stream_; }

 private:
  std::ostringstream stream_;
};
#define LOG(severity) ::base::LogLine(#severity).stream()

template <class T>
T* Unretained(T* value) {
  return value;
}
using OnceClosure = std::function<void()>;
template <class Function, class... Arguments>
OnceClosure BindOnce(Function function, Arguments... arguments) {
  return [function, arguments...]() mutable { std::invoke(function, arguments...); };
}

class Lock {
 public:
  std::mutex mutex;
};
class AutoLock {
 public:
  explicit AutoLock(Lock& lock) : lock_(lock.mutex) {}

 private:
  std::lock_guard<std::mutex> lock_;
};
class ConditionVariable {
 public:
  explicit ConditionVariable(Lock* lock) : lock_(lock) {}
  void Wait() { condition_.wait(lock_->mutex); }
  void TimedWait(const TimeDelta& delay) {
    static_cast<void>(condition_.wait_for(lock_->mutex, delay.ToChrono()));
  }
  void Signal() { condition_.notify_one(); }
  void Broadcast() { condition_.notify_all(); }

 private:
  Lock* lock_;
  std::condition_variable_any condition_;
};

class WaitableEvent {
 public:
  enum class ResetPolicy { AUTOMATIC };
  enum class InitialState { NOT_SIGNALED };
  WaitableEvent(ResetPolicy, InitialState) {}
  void Signal() {
    {
      std::lock_guard lock(mutex_);
      signaled_ = true;
    }
    condition_.notify_one();
  }
  bool TimedWait(const TimeDelta& delay) {
    std::unique_lock lock(mutex_);
    const bool signaled = condition_.wait_for(lock, delay.ToChrono(), [this] { return signaled_; });
    signaled_ = false;
    return signaled;
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  bool signaled_ = false;
};

// A serial queue. The test thread is the browser sequence: it runs posted
// completions only inside RunUntil, as Chromium's run loop would between tasks.
class SequencedTaskRunner {
 public:
  static scoped_refptr<SequencedTaskRunner> GetCurrentDefault() {
    static SequencedTaskRunner browser;
    return &browser;
  }
  void PostTask(const Location&, OnceClosure task) {
    {
      std::lock_guard lock(mutex_);
      tasks_.push_back(std::move(task));
    }
    condition_.notify_all();
  }
  // Runs tasks until `done` holds; false on timeout.
  bool RunUntil(const std::function<bool()>& done, const std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
      if (done()) {
        return true;
      }
      OnceClosure task;
      {
        std::unique_lock lock(mutex_);
        if (!condition_.wait_until(lock, deadline, [this] { return !tasks_.empty(); })) {
          return done();
        }
        task = std::move(tasks_.front());
        tasks_.pop_front();
      }
      task();
    }
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  std::deque<OnceClosure> tasks_;
};

class Thread {
 public:
  explicit Thread(std::string) {}
  ~Thread() { Stop(); }
  bool Start() {
    std::lock_guard lock(mutex_);
    if (thread_.joinable()) {
      return false;
    }
    quit_ = false;
    thread_ = std::thread([this] { Loop(); });
    started_count.fetch_add(1);
    return true;
  }
  void Stop() {
    {
      std::lock_guard lock(mutex_);
      if (!thread_.joinable()) {
        return;
      }
      quit_ = true;
    }
    condition_.notify_all();
    thread_.join();
    std::lock_guard lock(mutex_);
    thread_ = std::thread();
  }
  bool IsRunning() {
    std::lock_guard lock(mutex_);
    return thread_.joinable();
  }
  void DetachFromSequence() {}
  Thread* task_runner() { return this; }
  void PostTask(const Location&, OnceClosure task) {
    {
      std::lock_guard lock(mutex_);
      tasks_.push_back(std::move(task));
    }
    condition_.notify_all();
  }
  static inline std::atomic<int> started_count{0};

 private:
  void Loop() {
    for (;;) {
      OnceClosure task;
      {
        std::unique_lock lock(mutex_);
        condition_.wait(lock, [this] { return quit_ || !tasks_.empty(); });
        if (tasks_.empty()) {
          return;
        }
        task = std::move(tasks_.front());
        tasks_.pop_front();
      }
      task();
    }
  }
  std::mutex mutex_;
  std::condition_variable condition_;
  std::deque<OnceClosure> tasks_;
  bool quit_ = false;
  std::thread thread_;
};

struct MayBlock {};
struct WithBaseSyncPrimitives {};
struct TaskTraits {
  TaskTraits(MayBlock, WithBaseSyncPrimitives) {}
};
class ThreadPool {
 public:
  static void PostTaskAndReply(const Location&, TaskTraits, OnceClosure task, OnceClosure reply) {
    const scoped_refptr<SequencedTaskRunner> origin = SequencedTaskRunner::GetCurrentDefault();
    std::lock_guard lock(mutex());
    workers().emplace_back([task = std::move(task), reply = std::move(reply), origin]() mutable {
      task();
      origin->PostTask(Location(), std::move(reply));
    });
  }
  static void JoinAllForTesting() {
    std::vector<std::thread> joining;
    {
      std::lock_guard lock(mutex());
      joining.swap(workers());
    }
    for (std::thread& worker : joining) {
      worker.join();
    }
  }

 private:
  static std::mutex& mutex() {
    static std::mutex value;
    return value;
  }
  static std::vector<std::thread>& workers() {
    static std::vector<std::thread> value;
    return value;
  }
};

}  // namespace base

namespace reb {

// Records what the production clients hand to the session; Emit forwards to
// the downstream emitter for the current session, as the real one does.
class NativeProbeSession {
 public:
  static NativeProbeSession& Get() {
    static base::NoDestructor<NativeProbeSession> session;
    return *session;
  }
  bool StartSession(std::uint64_t session_id,
                    std::uint64_t category_mask,
                    std::uint64_t,
                    bool,
                    NativeProbeEmitter downstream,
                    bool) noexcept {
    ++start_calls;
    if (!start_result) {
      return false;
    }
    session_id_ = session_id;
    category_mask_ = category_mask;
    downstream_.store(downstream);
    return true;
  }
  void StopSession() noexcept {
    downstream_.store(nullptr);
    session_id_ = 0;
    category_mask_ = 0;
    ++stop_calls;
  }
  bool capture_request_content() const noexcept { return false; }
  std::uint64_t session_id() const noexcept { return session_id_; }
  std::uint64_t category_mask() const noexcept { return category_mask_; }
  std::uint64_t NextBrowserSequence() noexcept { return next_browser_sequence_.fetch_add(1); }
  void Emit(const NativeProbeEvent& event) const noexcept {
    const NativeProbeEmitter downstream = downstream_.load();
    if (downstream && event.header.session_id == session_id_ &&
        (category_mask_ & NativeProbeCategoryMask(event.header.category)) != 0) {
      downstream(event);
    }
  }
  NativeProbeEmitter downstream() const noexcept { return downstream_.load(); }

  bool start_result = true;
  int start_calls = 0;
  std::atomic<int> stop_calls{0};
  // Far above any renderer sequence used by the tests, so attribution shows.
  static constexpr std::uint64_t kFirstBrowserSequence = 1'000'000;

 private:
  std::atomic<NativeProbeEmitter> downstream_{nullptr};
  std::uint64_t session_id_ = 0;
  std::uint64_t category_mask_ = 0;
  std::atomic<std::uint64_t> next_browser_sequence_{kFirstBrowserSequence};
};

struct TestCompletion {
  std::uint64_t artifact_id;
  NativeArtifactReceiveStatus status;
};

class NativeArtifactCaptureSink {
 public:
  // Runs on the browser sequence, which is the test thread.
  static void TransferCompleted(std::uint64_t artifact_id,
                                NativeArtifactReceiveStatus status) noexcept {
    completions.push_back({artifact_id, status});
  }
  static inline std::vector<TestCompletion> completions;
};

class NativeNetworkCaptureSink {
 public:
  static NativeNetworkCaptureSink& Get() {
    static NativeNetworkCaptureSink sink;
    return sink;
  }
  void SetOwnedProfilePath(const base::FilePath&) {}
};

}  // namespace reb
