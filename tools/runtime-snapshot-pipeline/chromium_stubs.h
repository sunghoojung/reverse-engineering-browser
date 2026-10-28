// Only platform and I/O boundaries are substituted. Both capture sinks and the
// event queue are compiled unchanged. This is not a V8/Blink or Mojo runtime test.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"

#define COMPONENT_EXPORT(component)
#define UNSAFE_BUFFERS(...) __VA_ARGS__

namespace base {
template <class T>
class NoDestructor {
 public:
  NoDestructor() { ::new (static_cast<void*>(storage_.data())) T; }
  T& operator*() { return *std::launder(reinterpret_cast<T*>(storage_.data())); }

 private:
  alignas(T) std::array<std::byte, sizeof(T)> storage_;
};
inline std::int64_t test_now_ns = 100;
inline int test_process_id = 101;
struct TestDelta {
  std::int64_t InNanoseconds() const { return test_now_ns; }
};
struct TimeTicks {
  static TimeTicks Now() { return {}; }
  TestDelta since_origin() const { return {}; }
};
inline int GetCurrentProcId() {
  return test_process_id;
}
struct TestThreadId {
  int raw() const { return 1; }
};
struct PlatformThread {
  static TestThreadId CurrentId() { return {}; }
};
template <class... Args>
int BindOnce(Args&&...) {
  return 0;
}
template <class T>
T* Unretained(T* value) {
  return value;
}
class WritableSharedMemoryMapping {
 public:
  bool IsValid() const { return false; }
  std::size_t size() const { return 0; }
  void* memory() const { return nullptr; }
};
class UnsafeSharedMemoryRegion {
 public:
  bool IsValid() const { return false; }
  std::size_t GetSize() const { return 0; }
  WritableSharedMemoryMapping Map() const { return {}; }
};
template <class T>
class ThreadLocalOwnedPointer {};
struct Location {};
struct TimeDelta {
  std::int64_t ns = 0;
};
inline TimeDelta Nanoseconds(std::int64_t value) {
  return {value};
}
// This pipeline never reaches session expiry; no task is ever posted.
struct SequencedTaskRunner {
  static bool HasCurrentDefault() { return false; }
  static SequencedTaskRunner* GetCurrentDefault() {
    static SequencedTaskRunner runner;
    return &runner;
  }
  template <class Task>
  void PostDelayedTask(const Location&, Task&&, TimeDelta) {}
};
}  // namespace base
#define FROM_HERE ::base::Location()

namespace mojo_base {
class BigBuffer {
 public:
  explicit BigBuffer(std::span<const std::uint8_t> bytes) : bytes_(bytes.begin(), bytes.end()) {}
  std::size_t size() const { return bytes_.size(); }
  const std::uint8_t* data() const { return bytes_.data(); }
  auto begin() const { return bytes_.begin(); }
  auto end() const { return bytes_.end(); }

 private:
  std::vector<std::uint8_t> bytes_;
};
}  // namespace mojo_base
namespace mojo {
struct ScopedDataPipeConsumerHandle {
  bool is_valid() const { return false; }
};
template <class T>
class PendingRemote {
 public:
  bool is_valid() const { return false; }
};
template <class T>
class SharedRemote {
 public:
  bool is_bound() const { return false; }
  explicit operator bool() const { return false; }
};
template <class T>
class Receiver {
 public:
  explicit Receiver(T*) {}
  PendingRemote<T> BindNewPipeAndPassRemote() { return {}; }
};
}  // namespace mojo

class GURL {
 public:
  const std::string& spec() const { return value_; }

 private:
  std::string value_;
};
namespace network {
struct ResourceRequest {
  int resource_type = 0;
  GURL url;
};
namespace mojom {
class URLResponseHead {
 public:
  std::string mime_type;
  std::int64_t content_length = 0;
};
}  // namespace mojom
}  // namespace network

namespace reb {
namespace mojom {
class NativeProbeHost {};
class NativeProbeClient {
 public:
  virtual ~NativeProbeClient() = default;
  virtual void Configure(std::uint64_t,
                         std::uint64_t,
                         std::uint64_t,
                         bool,
                         base::UnsafeSharedMemoryRegion,
                         std::uint64_t) = 0;
  virtual void Disable() = 0;
};
}  // namespace mojom
struct NativeArtifactTransfer final {
  NativeArtifactHeader header;
  std::string url;
  std::string mime_type;
  std::vector<std::uint8_t> content;
};
class NativeArtifactSocketClient {
 public:
  static NativeArtifactSocketClient& Get() {
    static NativeArtifactSocketClient value;
    return value;
  }
  bool IsConnected() const { return connected; }
  bool Enqueue(std::unique_ptr<NativeArtifactTransfer> transfer) noexcept {
    if (!connected || reject_next) {
      reject_next = false;
      return false;
    }
    transfers.push_back(std::move(transfer));
    return true;
  }
  bool connected = true;
  bool reject_next = false;
  std::vector<std::unique_ptr<NativeArtifactTransfer>> transfers;
};
class NativeArtifactBodyTee {
 public:
  static mojo::ScopedDataPipeConsumerHandle Create(mojo::ScopedDataPipeConsumerHandle body,
                                                   std::size_t,
                                                   std::size_t,
                                                   int,
                                                   bool& started) {
    started = false;
    return body;
  }
};
class NativeProbeSession {
 public:
  static NativeProbeSession& Get() {
    static NativeProbeSession value;
    return value;
  }
  std::uint64_t NextBrowserSequence() { return next_++; }

 private:
  std::uint64_t next_ = 1;
};
}  // namespace reb
