// Test-only Chromium/Mojo boundaries. The sink, transport and queue under test
// are compiled from the real overlay sources, without replacing their logic.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <utility>

#define COMPONENT_EXPORT(component)

namespace base {
inline std::atomic<std::int64_t> test_now_ns{100};
struct TestDelta {
  std::int64_t InNanoseconds() const { return test_now_ns.load(); }
};
struct TimeTicks {
  static TimeTicks Now() { return {}; }
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
struct UnguessableToken {
  std::uint64_t GetHighForSerialization() const { return 1; }
  std::uint64_t GetLowForSerialization() const { return 2; }
};
}  // namespace base

namespace mojo_base {
struct BigBuffer {
  explicit BigBuffer(std::span<const std::uint8_t>) {}
};
}  // namespace mojo_base

namespace reb::mojom {
struct NativeProbeClient {
  virtual ~NativeProbeClient() = default;
  virtual void Configure(std::uint64_t,
                         std::uint64_t,
                         std::uint64_t,
                         bool,
                         base::UnsafeSharedMemoryRegion) = 0;
  virtual void Disable() = 0;
};
struct NativeProbeHost {
  inline static std::atomic<unsigned> notifications{0};
  inline static std::atomic<unsigned> artifacts{0};
  void BindClient(int) {}
  void EventsAvailable() { ++notifications; }
  template <class... Args>
  void CaptureGeneratedArtifact(Args&&...) {
    ++artifacts;
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
struct Receiver {
  explicit Receiver(T*) {}
  int BindNewPipeAndPassRemote() { return 0; }
};
}  // namespace mojo

namespace blink {
// Only test threads opt into a deterministic pause between sink claim and
// transport admission. Production frame lookup is not replaced in the sources.
inline thread_local void (*test_frame_hook)() = nullptr;
struct FrameToken {
  const base::UnguessableToken& value() const {
    static const base::UnguessableToken token;
    return token;
  }
};
struct WebLocalFrame {
  static WebLocalFrame* FrameForCurrentContext() {
    if (test_frame_hook) {
      test_frame_hook();
    }
    return nullptr;
  }
  FrameToken GetLocalFrameToken() const { return {}; }
};
}  // namespace blink
