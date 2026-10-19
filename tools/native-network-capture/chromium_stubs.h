// Narrow Chromium type boundaries; the sink/lifecycle/queue are production code.
#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#define BUILDFLAG(flag) (flag)
#define IS_POSIX 1
namespace base {
template <class T>
using span = std::span<T>;
template <class T>
std::span<const std::uint8_t> byte_span_from_ref(const T& value) {
  return {reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)};
}
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
}  // namespace base
namespace content {
class BrowserContext {
 public:
  BrowserContext(base::FilePath path, bool otr) : path_(std::move(path)), otr_(otr) {}
  base::FilePath GetPath() const { return path_; }
  bool IsOffTheRecord() { return otr_; }

 private:
  base::FilePath path_;
  bool otr_;
};
}  // namespace content
struct TestURL {
  std::string hostname = "fixture.test";
  const std::string& host() const { return hostname; }
};
namespace net {
struct HttpResponseHeaders {
  int code = 200;
  int response_code() const { return code; }
};
struct RedirectInfo {
  std::string new_method = "GET";
  TestURL new_url;
};
}  // namespace net
namespace network {
struct ResourceRequest {
  int resource_type = 1;
  bool originated_from_service_worker = false;
  std::string method = "GET";
  TestURL url;
};
struct URLLoaderCompletionStatus {
  int error_code = 0;
  std::int64_t encoded_data_length = 0;
  std::int64_t decoded_body_length = 0;
};
namespace mojom {
class URLResponseHead {
 public:
  std::shared_ptr<net::HttpResponseHeaders> headers;
  std::int64_t encoded_data_length = 0;
  bool was_fetched_via_cache = false;
  bool was_fetched_via_service_worker = false;
  std::string mime_type = "text/plain";
  std::string alpn_negotiated_protocol = "h2";
};
}  // namespace mojom
}  // namespace network
namespace reb {
class NativeProbeSession {
 public:
  static NativeProbeSession& Get() {
    static NativeProbeSession session;
    return session;
  }
  std::uint64_t NextBrowserSequence() { return ++sequence_; }

 private:
  std::uint64_t sequence_ = 0;
};
}  // namespace reb
