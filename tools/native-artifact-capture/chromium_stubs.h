// Platform/Mojo/socket scheduling adapters only. Capture sinks and receiver are real.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest.h"

namespace base {
template <class T>
class NoDestructor {
 public:
  NoDestructor() { ::new (static_cast<void*>(storage_.data())) T; }
  T& operator*() { return *std::launder(reinterpret_cast<T*>(storage_.data())); }

 private:
  alignas(T) std::array<std::byte, sizeof(T)> storage_;
};
using std::span;
inline std::int64_t test_now_ns = 100;
inline unsigned test_clock_reads = 0;
struct TestDelta {
  std::int64_t InNanoseconds() const { return test_now_ns; }
};
struct TimeTicks {
  static TimeTicks Now() {
    ++test_clock_reads;
    return {};
  }
  TestDelta since_origin() const { return {}; }
};
inline int GetCurrentProcId() {
  return 42;
}
struct TestThreadId {
  int raw() const { return 7; }
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
  bool operator==(const FilePath&) const = default;

 private:
  std::string value_;
};
template <class T>
T* Unretained(T* value) {
  return value;
}
template <class Function, class Argument>
auto BindOnce(Function function, Argument argument) {
  return [function, argument]() mutable { function(argument); };
}
struct Location {};
struct TimeDelta {
  std::int64_t ns = 0;
};
inline TimeDelta Nanoseconds(std::int64_t value) {
  return {value};
}
// Records posted work so tests can run the pre-expiry flush deterministically.
struct SequencedTaskRunner {
  static bool HasCurrentDefault() { return true; }
  static SequencedTaskRunner* GetCurrentDefault() {
    static SequencedTaskRunner runner;
    return &runner;
  }
  template <class Task>
  void PostDelayedTask(const Location&, Task&& task, TimeDelta delay) {
    tasks.push_back({delay.ns, std::function<void()>(std::forward<Task>(task))});
  }
  std::vector<std::pair<std::int64_t, std::function<void()>>> tasks;
};
template <class Method, class Owner, class Context>
auto BindOnce(Method method, Owner* owner, Context context) {
  return [method, owner, context = std::move(context)](bool complete,
                                                       std::vector<std::uint8_t> bytes) mutable {
    (owner->*method)(std::move(context), complete, std::move(bytes));
  };
}
}  // namespace base
#define FROM_HERE ::base::Location()

namespace content {
class BrowserContext {
 public:
  BrowserContext(base::FilePath path, bool otr) : path_(std::move(path)), otr_(otr) {}
  base::FilePath GetPath() const { return path_; }
  bool IsOffTheRecord() const { return otr_; }

 private:
  base::FilePath path_;
  bool otr_;
};
}  // namespace content
class GURL {
 public:
  GURL() : value_("https://fixture.test/stack.js") {}
  explicit GURL(std::string value) : value_(std::move(value)) {}
  const std::string& spec() const { return value_; }
  std::string host() const { return "fixture.test"; }

 private:
  std::string value_;
};
namespace net {
struct HttpResponseHeaders {
  int response_code() const { return 200; }
};
struct RedirectInfo {
  std::string new_method = "GET";
  GURL new_url;
};
}  // namespace net
namespace network {
struct ResourceRequest {
  int resource_type = 3;
  bool originated_from_service_worker = false;
  std::string method = "GET";
  GURL url;
};
struct URLLoaderCompletionStatus {
  int error_code = 0;
  std::int64_t encoded_data_length = 0;
  std::int64_t decoded_body_length = 0;
};
namespace mojom {
class URLResponseHead {
 public:
  std::shared_ptr<net::HttpResponseHeaders> headers = std::make_shared<net::HttpResponseHeaders>();
  std::int64_t content_length = 0;
  std::int64_t encoded_data_length = 0;
  bool was_fetched_via_cache = false;
  bool was_fetched_via_service_worker = false;
  std::string mime_type = "text/javascript";
  std::string alpn_negotiated_protocol = "h2";
};
}  // namespace mojom
}  // namespace network
namespace mojo {
struct ScopedDataPipeConsumerHandle {
  int id = 0;
  bool is_valid() const { return id != 0; }
};
}  // namespace mojo
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
namespace reb {
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
    const auto id = transfer->header.artifact_id;
    transfers.emplace(id, std::move(transfer));
    return true;
  }
  bool connected = true;
  bool reject_next = false;
  std::map<std::uint64_t, std::unique_ptr<NativeArtifactTransfer>> transfers;
};
class NativeArtifactBodyTee {
 public:
  using Completion = std::packaged_task<void(bool, std::vector<std::uint8_t>)>;
  template <class Callback>
  static mojo::ScopedDataPipeConsumerHandle Create(mojo::ScopedDataPipeConsumerHandle body,
                                                   std::size_t capture_limit,
                                                   std::size_t reserve_size,
                                                   Callback callback,
                                                   bool& started) {
    if (unavailable) {
      started = false;
      return body;
    }
    if (capture_limit != kNativeArtifactMaxContentBytes || reserve_size > capture_limit) {
      throw std::runtime_error("Invalid tee admission bounds");
    }
    pending.emplace(body.id, Completion(std::move(callback)));
    started = true;
    return body;
  }
  static void Complete(int id, bool complete, std::vector<std::uint8_t> content) {
    auto callback = std::move(pending.at(id));
    pending.erase(id);
    auto result = callback.get_future();
    callback(complete, std::move(content));
    result.get();
  }
  static inline bool unavailable = false;
  static inline std::map<int, Completion> pending;
};
class NativeProbeHost;
// Session boundary seen by NativeProbeHost; the policy is set by each test.
class NativeProbeSession {
 public:
  static NativeProbeSession& Get() {
    static NativeProbeSession value;
    return value;
  }
  // A native uint64 sequence beyond JS safe-integer range, never rewritten later.
  std::uint64_t NextBrowserSequence() { return ++sequence_; }
  bool IsActive() const { return active; }
  std::uint64_t session_id() const { return id; }
  std::uint64_t category_mask() const { return mask; }
  std::uint64_t expires_at_monotonic_ns() const { return expires; }
  bool capture_canvas_images() const { return false; }
  const std::string& guest_adapter_json() const { return adapter_json; }
  void Emit(const NativeProbeEvent& event) const {
    if (emitted)
      emitted(event);
  }
  void AddHost(NativeProbeHost&) {}
  void RemoveHost(NativeProbeHost&) {}
  bool active = false;
  std::uint64_t id = 0, mask = 0, expires = 0;
  std::string adapter_json;
  std::function<void(const NativeProbeEvent&)> emitted;

 private:
  std::uint64_t sequence_ = 9'007'199'254'740'992ULL;
};
// The real adapter parser needs Chromium JSON; host tests supply the parsed form.
inline std::shared_ptr<const NativeWasmGuestAdapter> test_guest_adapter;
inline std::shared_ptr<const NativeWasmGuestAdapter> ParseNativeWasmGuestAdapter(
    std::string_view json) {
  return test_guest_adapter && test_guest_adapter->json == json ? test_guest_adapter : nullptr;
}
}  // namespace reb

// NativeProbeHost boundaries: ownership, shared memory, Mojo and frames.
template <class T>
using raw_ptr = T*;
template <class T>
class raw_ref {
 public:
  explicit raw_ref(T& value) : value_(&value) {}
  T* operator->() const { return value_; }
  T& operator*() const { return *value_; }

 private:
  T* value_;
};
namespace base {
class WritableSharedMemoryMapping {
 public:
  WritableSharedMemoryMapping() = default;
  explicit WritableSharedMemoryMapping(std::shared_ptr<std::byte[]> storage)
      : storage_(std::move(storage)) {}
  bool IsValid() const { return storage_ != nullptr; }
  void* memory() const { return storage_.get(); }

 private:
  std::shared_ptr<std::byte[]> storage_;
};
class UnsafeSharedMemoryRegion {
 public:
  static UnsafeSharedMemoryRegion Create(std::size_t size) {
    UnsafeSharedMemoryRegion region;
    region.storage_ = std::shared_ptr<std::byte[]>(
        static_cast<std::byte*>(::operator new[](size, std::align_val_t{64})),
        [](std::byte* bytes) { ::operator delete[](bytes, std::align_val_t{64}); });
    return region;
  }
  bool IsValid() const { return storage_ != nullptr; }
  UnsafeSharedMemoryRegion Duplicate() const { return *this; }
  WritableSharedMemoryMapping Map() const { return WritableSharedMemoryMapping(storage_); }

 private:
  std::shared_ptr<std::byte[]> storage_;
};
template <class T>
class WeakPtr {
 public:
  WeakPtr() = default;
  explicit WeakPtr(std::weak_ptr<T*> cell) : cell_(std::move(cell)) {}
  explicit operator bool() const { return !cell_.expired() && *cell_.lock(); }
  T* operator->() const { return *cell_.lock(); }

 private:
  std::weak_ptr<T*> cell_;
};
template <class T>
class WeakPtrFactory {
 public:
  explicit WeakPtrFactory(T* owner) : cell_(std::make_shared<T*>(owner)) {}
  ~WeakPtrFactory() { *cell_ = nullptr; }
  WeakPtr<T> GetWeakPtr() { return WeakPtr<T>(cell_); }

 private:
  std::shared_ptr<T*> cell_;
};
struct UnguessableToken {
  std::uint64_t high = 0, low = 0;
  std::uint64_t GetHighForSerialization() const { return high; }
  std::uint64_t GetLowForSerialization() const { return low; }
};
}  // namespace base
namespace mojo {
template <class T>
struct PendingRemote {
  T* target = nullptr;
};
template <class T>
class Remote {
 public:
  bool is_bound() const { return target_ != nullptr; }
  void Bind(PendingRemote<T> pending) { target_ = pending.target; }
  T* operator->() const { return target_; }

 private:
  T* target_ = nullptr;
};
}  // namespace mojo
namespace reb::mojom {
class NativeProbeClient {
 public:
  virtual ~NativeProbeClient() = default;
  virtual void Configure(std::uint64_t,
                         std::uint64_t,
                         std::uint64_t,
                         bool,
                         base::UnsafeSharedMemoryRegion,
                         std::uint64_t,
                         const std::string&) = 0;
  virtual void Disable() = 0;
  virtual void NativeGuestModuleStatus(std::uint64_t, std::uint64_t, bool) = 0;
};
class NativeProbeHost {
 public:
  virtual ~NativeProbeHost() = default;
  virtual void BindClient(mojo::PendingRemote<NativeProbeClient>) = 0;
  virtual void EventsAvailable() = 0;
  virtual void CaptureWasmDispatch(std::uint64_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::uint32_t,
                                   std::uint32_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::uint32_t,
                                   std::uint32_t,
                                   std::uint32_t,
                                   std::uint32_t,
                                   std::uint32_t,
                                   const std::string&,
                                   mojo_base::BigBuffer) = 0;
  virtual void CaptureNativeGuest(std::uint64_t,
                                  const std::vector<std::uint8_t>&,
                                  const std::vector<std::uint8_t>&,
                                  std::uint64_t,
                                  std::uint64_t,
                                  std::uint64_t,
                                  const std::string&,
                                  const std::string&,
                                  mojo_base::BigBuffer,
                                  mojo_base::BigBuffer) = 0;
  virtual void CaptureNativeGuestHost(std::uint64_t, const std::vector<std::uint8_t>&) = 0;
  virtual void CaptureGeneratedArtifact(std::uint16_t,
                                        std::uint16_t,
                                        std::uint64_t,
                                        std::uint64_t,
                                        std::uint64_t,
                                        const std::string&,
                                        mojo_base::BigBuffer,
                                        std::uint64_t,
                                        bool,
                                        mojo_base::BigBuffer,
                                        std::uint64_t) = 0;
};
}  // namespace reb::mojom
namespace content {
struct FrameTreeNodeId {
  int id = 0;
  int value() const { return id; }
  explicit operator bool() const { return id != 0; }
};
struct TestToken {
  base::UnguessableToken token;
  const base::UnguessableToken& value() const { return token; }
};
class RenderFrameHost;
class WeakDocumentPtr {
 public:
  explicit WeakDocumentPtr(RenderFrameHost* frame = nullptr) : frame_(frame) {}
  RenderFrameHost* AsRenderFrameHostIfValid() const { return frame_; }

 private:
  RenderFrameHost* frame_;
};
class RenderFrameHost {
 public:
  bool IsActive() const { return active; }
  // Chromium returns these tokens by reference; so must the adapter.
  const TestToken& GetFrameToken() const {
    frame_token_ = {frame};
    return frame_token_;
  }
  const TestToken& GetDocumentToken() const {
    document_token_ = {document};
    return document_token_;
  }
  WeakDocumentPtr GetWeakDocumentPtr() { return WeakDocumentPtr(this); }
  FrameTreeNodeId GetFrameTreeNodeId() const { return {tree_node}; }
  bool active = true;
  base::UnguessableToken frame, document;
  int tree_node = 1;

 private:
  mutable TestToken frame_token_, document_token_;
};
class WebContents {
 public:
  static WebContents* FromRenderFrameHost(RenderFrameHost* frame) {
    static WebContents contents;
    contents.main_ = frame;
    return &contents;
  }
  RenderFrameHost* GetPrimaryMainFrame() const { return main_; }

 private:
  RenderFrameHost* main_ = nullptr;
};
struct TestProcess {
  int pid = 0;
  int Pid() const { return pid; }
};
class RenderProcessHost {
 public:
  static RenderProcessHost* FromID(int id) {
    auto& process = Instance();
    return id == process.id && process.present ? &process : nullptr;
  }
  static RenderProcessHost& Instance() {
    static RenderProcessHost process;
    return process;
  }
  const TestProcess& GetProcess() const { return process_; }
  template <class Callback>
  void ForEachRenderFrameHost(Callback&& callback) {
    for (auto* frame : frames)
      callback(frame);
  }
  int id = 1;
  bool present = true;
  std::vector<RenderFrameHost*> frames;
  TestProcess process_{123};
};
}  // namespace content
