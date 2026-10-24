// Platform/Mojo/socket scheduling adapters only. Capture sinks and receiver are real.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"

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
template <class Method, class Owner, class Context>
auto BindOnce(Method method, Owner* owner, Context context) {
  return [method, owner, context = std::move(context)](bool complete,
                                                       std::vector<std::uint8_t> bytes) mutable {
    (owner->*method)(std::move(context), complete, std::move(bytes));
  };
}
}  // namespace base

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
class NativeProbeSession {
 public:
  static NativeProbeSession& Get() {
    static NativeProbeSession value;
    return value;
  }
  // A native uint64 sequence beyond JS safe-integer range, never rewritten later.
  std::uint64_t NextBrowserSequence() { return ++sequence_; }

 private:
  std::uint64_t sequence_ = 9'007'199'254'740'992ULL;
};
}  // namespace reb
