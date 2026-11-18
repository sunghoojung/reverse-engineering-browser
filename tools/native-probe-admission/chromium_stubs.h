// Test-only Chromium/Mojo boundaries. The sink, transport and queue under test
// are compiled from the real overlay sources, without replacing their logic.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

#define COMPONENT_EXPORT(component)
#define UNSAFE_BUFFERS(...) __VA_ARGS__
#if defined(__has_cpp_attribute) && __has_cpp_attribute(clang::lifetimebound)
#define REB_STUB_LIFETIME_BOUND [[clang::lifetimebound]]
#else
#define REB_STUB_LIFETIME_BOUND
#endif

namespace base {
inline std::atomic<std::int64_t> test_now_ns{100};
inline std::atomic<unsigned> test_clock_reads{0};
struct TestDelta {
  std::int64_t InNanoseconds() const { return test_now_ns.load(); }
};
struct TimeTicks {
  static TimeTicks Now() {
    ++test_clock_reads;
    return {};
  }
  TestDelta since_origin() const { return {}; }
};
inline int GetCurrentProcId() {
  return 1;
}
struct TestThreadId {
  int raw() const { return 1; }
};
struct PlatformThread {
  static TestThreadId CurrentId() { return {}; }
};
class WritableSharedMemoryMapping {
 public:
  WritableSharedMemoryMapping(void* data, std::size_t size) : data_(data), size_(size) {}
  bool IsValid() const { return data_ != nullptr; }
  std::size_t size() const { return size_; }
  void* memory() const { return data_; }

 private:
  void* data_;
  std::size_t size_;
};
class UnsafeSharedMemoryRegion {
 public:
  UnsafeSharedMemoryRegion(void* data, std::size_t size) : data_(data), size_(size) {}
  bool IsValid() const { return data_ != nullptr; }
  std::size_t GetSize() const { return size_; }
  WritableSharedMemoryMapping Map() const { return {data_, size_}; }

 private:
  void* data_;
  std::size_t size_;
};
template <class T>
class NoDestructor {
 public:
  NoDestructor() { new (storage_) T; }
  T& operator*() { return *reinterpret_cast<T*>(storage_); }

 private:
  alignas(T) std::byte storage_[sizeof(T)];
};
template <class T>
class ThreadLocalOwnedPointer {
 public:
  T* Get() { return value_.get(); }
  void Set(std::unique_ptr<T> value) { value_ = std::move(value); }

 private:
  inline static thread_local std::unique_ptr<T> value_;
};
struct SequencedTaskRunner {
  static int GetCurrentDefault() { return 0; }
};
template <class... Args>
int BindOnce(Args&&...) {
  return 0;
}
template <class T>
T* Unretained(T* value) {
  return value;
}
class Lock {
 public:
  void Acquire() { mutex_.lock(); }
  void Release() { mutex_.unlock(); }

 private:
  std::mutex mutex_;
};
class AutoLock {
 public:
  explicit AutoLock(Lock& lock) : lock_(lock) { lock_.Acquire(); }
  ~AutoLock() { lock_.Release(); }

 private:
  Lock& lock_;
};
struct UnguessableToken {
  std::uint64_t high = 1;
  std::uint64_t low = 2;
  std::uint64_t GetHighForSerialization() const { return high; }
  std::uint64_t GetLowForSerialization() const { return low; }
};
}  // namespace base

namespace mojo_base {
struct BigBuffer {
  explicit BigBuffer(std::span<const std::uint8_t> bytes) : data(bytes.begin(), bytes.end()) {}
  std::vector<std::uint8_t> data;
};
}  // namespace mojo_base

namespace reb::mojom {
struct NativeWatchRequestRule {
  std::string url_contains;
  std::string method;
};
struct NativeWatchScope {
  std::uint64_t serial = 0;
  std::string origin;
  bool top_frame = false;
  std::vector<std::unique_ptr<NativeWatchRequestRule>> requests;
  std::vector<std::string> events;
  bool timers = false;
  bool csp = false;
  bool uncaught = false;
  bool caught = false;
};
using NativeWatchScopePtr = std::unique_ptr<NativeWatchScope>;
struct NativeProbeClient {
  virtual ~NativeProbeClient() = default;
  virtual void Configure(std::uint64_t,
                         std::uint64_t,
                         std::uint64_t,
                         bool,
                         base::UnsafeSharedMemoryRegion,
                         std::uint64_t,
                         const std::string&,
                         const std::vector<std::uint8_t>&,
                         const std::vector<std::uint8_t>&,
                         bool,
                         bool,
                         bool) = 0;
  virtual void SetWasmSampleBudget(const std::vector<std::uint8_t>&) = 0;
  virtual void ResetWasmSampleBudgets() = 0;
  virtual void SetDebuggerWatchScope(NativeWatchScopePtr) = 0;
  virtual void Disable() = 0;
  virtual void NativeGuestModuleStatus(std::uint64_t, std::uint64_t, bool) = 0;
  virtual void NativeStackArtifactRefused(std::uint64_t) = 0;
};
struct NativeProbeHost {
  inline static std::atomic<unsigned> notifications{0};
  inline static std::atomic<unsigned> artifacts{0};
  void EventsAvailable() { ++notifications; }
  template <class... Args>
  void CaptureWasmDispatch(Args&&...) {
    ++artifacts;
  }
  template <class... Args>
  void CaptureWasmIndirect(Args&&...) {
    ++artifacts;
  }
  template <class... Args>
  void CaptureWasmExecution(Args&&...) {
    ++artifacts;
  }
  template <class... Args>
  void CaptureNativeGuest(Args&&...) {
    ++artifacts;
  }
  template <class... Args>
  void CaptureNativeGuestHost(Args&&...) {
    ++artifacts;
  }
  // The newest request_target child sent with its whole target.
  inline static std::vector<std::uint8_t> target_record;
  inline static std::string target_origin;
  inline static std::string target_text;
  inline static std::atomic<unsigned> targets{0};
  void CaptureRendererTarget(std::vector<std::uint8_t> record,
                             std::string origin,
                             std::string text) {
    ++targets;
    target_record = std::move(record);
    target_origin = std::move(origin);
    target_text = std::move(text);
  }
  // The newest stack artifact (capture origin 12), for content checks.
  inline static std::vector<std::uint8_t> generated;
  inline static std::uint64_t generated_creator = 0;
  template <class... Args>
  void CaptureGeneratedArtifact(std::uint16_t,
                                std::uint16_t origin,
                                std::uint64_t creator,
                                std::uint64_t,
                                std::uint64_t,
                                std::string,
                                mojo_base::BigBuffer content,
                                Args&&...) {
    ++artifacts;
    if (origin == 12) {
      generated = std::move(content.data);
      generated_creator = creator;
    }
  }
};
}  // namespace reb::mojom

namespace mojo {
template <class T>
class PendingRemote {
 public:
  explicit PendingRemote(T* value) : value_(value) {}
  bool is_valid() const { return value_ != nullptr; }
  T* value_;
};
template <class T>
class SharedRemote {
 public:
  bool is_bound() const { return value_ != nullptr; }
  void Bind(PendingRemote<T> pending, int) { value_ = pending.value_; }
  void set_disconnect_handler(int, int) {}
  T* operator->() const { return value_; }
  explicit operator bool() const { return value_ != nullptr; }

 private:
  T* value_ = nullptr;
};
template <class T>
struct PendingAssociatedReceiver {};
template <class T>
struct AssociatedReceiver {
  explicit AssociatedReceiver(T*) {}
  void reset() {}
  void Bind(PendingAssociatedReceiver<T>) {}
};
}  // namespace mojo

namespace blink {
// Only test threads opt into a deterministic pause between sink claim and
// transport admission. Production frame lookup is not replaced in the sources.
inline thread_local void (*test_frame_hook)() = nullptr;
// Default absence keeps every unrelated case at an unattributed frame. A test
// opts in to model a caller that runs with an entered script context.
inline thread_local bool test_frame_present = false;
// Blink returns the frame token by value and value() refers into it, so a
// reference kept past the full expression dangles. Chromium leaves value()
// unannotated; marking it here makes Clang reject that reference (-Wdangling).
struct FrameToken {
  base::UnguessableToken token;
  const base::UnguessableToken& value() const REB_STUB_LIFETIME_BOUND { return token; }
};
struct WebLocalFrame {
  static WebLocalFrame* FrameForCurrentContext() {
    if (test_frame_hook) {
      test_frame_hook();
    }
    if (!test_frame_present) {
      return nullptr;
    }
    static WebLocalFrame frame;
    return &frame;
  }
  FrameToken GetLocalFrameToken() const { return {}; }
};
}  // namespace blink
