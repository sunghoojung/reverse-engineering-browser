// Test-only Chromium/Mojo boundaries. The sink, transport and queue under test
// are compiled from the real overlay sources, without replacing their logic.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
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
struct Location {};
#define FROM_HERE ::base::Location()
using OnceClosure = std::function<void()>;
// A thread's posted tasks wait until the test runs them, as they would wait
// for the task that posted them to end.
inline thread_local std::vector<OnceClosure> test_posted_tasks;
inline thread_local bool test_has_task_runner = true;
struct SequencedTaskRunner {
  static bool HasCurrentDefault() { return test_has_task_runner; }
  static SequencedTaskRunner* GetCurrentDefault() {
    static SequencedTaskRunner runner;
    return &runner;
  }
  void PostTask(Location, OnceClosure task) { test_posted_tasks.push_back(std::move(task)); }
};
// The renderer's threads each have their own runner, so the test's is both.
using SingleThreadTaskRunner = SequencedTaskRunner;
inline void RunPostedTasks() {
  auto tasks = std::move(test_posted_tasks);
  test_posted_tasks.clear();
  for (auto& task : tasks)
    task();
}
template <class... Args>
OnceClosure BindOnce(Args&&... args) {
  return std::bind_front(std::forward<Args>(args)...);
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
  enum class StorageType { kBytes, kSharedMemory, kInvalidBuffer };
  explicit BigBuffer(std::span<const std::uint8_t> content)
      : bytes(content.begin(), content.end()) {}
  // Converts like the real BigBuffer, so tests pass record vectors directly.
  BigBuffer(const std::vector<std::uint8_t>& content) : bytes(content) {}
  BigBuffer(std::vector<std::uint8_t>&& content) : bytes(std::move(content)) {}
  StorageType storage_type() const { return storage; }
  const std::uint8_t* data() const { return bytes.data(); }
  std::size_t size() const { return bytes.size(); }
  // A contiguous range, as the real one is, so it converts to a span.
  const std::uint8_t* begin() const { return bytes.data(); }
  const std::uint8_t* end() const { return bytes.data() + bytes.size(); }
  std::vector<std::uint8_t> bytes;
  StorageType storage = StorageType::kBytes;
};
}  // namespace mojo_base

#include "native_wasm_records_stub.h"

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
                         std::optional<mojo_base::BigBuffer>,
                         bool,
                         bool,
                         bool) = 0;
  virtual void SetWasmSampleBudget(const std::vector<std::uint8_t>&) = 0;
  virtual void ResetWasmSampleBudgets() = 0;
  virtual void UpdateJsInvocationSites(mojo_base::BigBuffer) = 0;
  virtual void SetDebuggerWatchScope(NativeWatchScopePtr) = 0;
  virtual void Disable() = 0;
  virtual void NativeGuestModuleStatus(std::uint64_t, std::uint64_t, bool) = 0;
  virtual void NativeStackArtifactRefused(std::uint64_t) = 0;
  virtual void ReleaseArtifactCredit(std::uint64_t) = 0;
};
struct NativeProbeHost {
  inline static std::atomic<unsigned> notifications{0};
  inline static std::atomic<unsigned> artifacts{0};
  // Each message in the order it was sent: a CaptureWasmRecords batch as its
  // records' sequence numbers, any other message as an empty entry.
  inline static std::mutex sent_lock;
  inline static std::vector<std::vector<std::uint64_t>> sent;
  void EventsAvailable() { ++notifications; }
  void CaptureWasmRecords(std::uint64_t, std::vector<NativeWasmRecordPtr> records) {
    std::vector<std::uint64_t> batch;
    for (auto& record : records) {
      switch (record->which()) {
        case NativeWasmRecord::Tag::kDispatch:
          batch.push_back(record->get_dispatch()->sequence_number);
          break;
        case NativeWasmRecord::Tag::kIndirect:
          batch.push_back(record->get_indirect()->sequence_number);
          break;
        case NativeWasmRecord::Tag::kExecution:
          batch.push_back(record->get_execution()->sequence_number);
          break;
      }
    }
    artifacts += static_cast<unsigned>(batch.size());
    const std::lock_guard<std::mutex> hold(sent_lock);
    sent.push_back(std::move(batch));
  }
  static void Sent() {
    const std::lock_guard<std::mutex> hold(sent_lock);
    sent.emplace_back();
  }
  template <class... Args>
  void CaptureNativeGuest(Args&&...) {
    ++artifacts;
    Sent();
  }
  template <class... Args>
  void CaptureNativeGuestHost(Args&&...) {
    ++artifacts;
    Sent();
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
    Sent();
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
    Sent();
    if (origin == 12) {
      generated = std::move(content.bytes);
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
  template <class... Args>
  void set_disconnect_handler(Args&&...) {}
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
// The transport binds its host remote to the IO thread's runner; the stub
// remote takes any runner.
struct Platform {
  static Platform* Current() {
    static Platform platform;
    return &platform;
  }
  int GetIOTaskRunner() const { return 0; }
};
}  // namespace blink
