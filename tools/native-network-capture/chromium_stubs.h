// Narrow Chromium type boundaries; the sink/lifecycle/queue are production code.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "network_headers_stub.h"
#include "network_request_body_stub.h"
#define BUILDFLAG(flag) (flag)
#define IS_POSIX 1
namespace base {
template <class T>
class NoDestructor {
 public:
  NoDestructor() { ::new (static_cast<void*>(storage_.data())) T; }
  T& operator*() { return *std::launder(reinterpret_cast<T*>(storage_.data())); }

 private:
  alignas(T) std::array<std::byte, sizeof(T)> storage_;
};
// Preserve std::span deduction guides instead of alias-template CTAD.
using std::span;
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
// Views into owned strings, like the pinned GURL accessors.
class GURL {
 public:
  GURL() = default;
  GURL(std::string scheme,
       std::string host,
       std::string path,
       std::string query = {},
       int port = -1,
       bool has_query = false)
      : scheme_(std::move(scheme)),
        host_(std::move(host)),
        path_(std::move(path)),
        query_(std::move(query)),
        port_(port),
        has_query_(has_query || !query_.empty()) {}
  bool is_valid() const { return valid_; }
  bool SchemeIs(std::string_view scheme) const { return scheme_ == scheme; }
  std::string_view host() const { return host_; }
  std::string_view path() const { return path_; }
  bool has_query() const { return has_query_; }
  std::string_view query() const { return query_; }
  int IntPort() const { return port_; }
  bool valid_ = true;

 private:
  std::string scheme_ = "https";
  std::string host_ = "fixture.test";
  std::string path_ = "/";
  std::string query_;
  int port_ = -1;
  bool has_query_ = false;
};
namespace net {
// Lines in received order, as EnumerateHeaderLines returns them.
class HttpResponseHeaders {
 public:
  int code = 200;
  std::vector<std::pair<std::string, std::string>> lines;
  int response_code() const { return code; }
  bool EnumerateHeaderLines(std::size_t* iter, std::string* name, std::string* value) const {
    if (*iter >= lines.size())
      return false;
    *name = lines[*iter].first;
    *value = lines[*iter].second;
    ++*iter;
    return true;
  }
};

struct RedirectInfo {
  std::string new_method = "GET";
  GURL new_url;
};
}  // namespace net
namespace network {
struct ResourceRequest {
  int resource_type = 1;
  bool originated_from_service_worker = false;
  std::string method = "GET";
  GURL url;
  net::ReferrerPolicy referrer_policy = net::ReferrerPolicy::NEVER_CLEAR;
  net::HttpRequestHeaders headers;
  net::HttpRequestHeaders cors_exempt_headers;
  std::shared_ptr<ResourceRequestBody> request_body;
  std::optional<std::string> devtools_request_id;
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
  net::IPEndPoint remote_endpoint;
  bool emitted_extra_info = false;
  std::int64_t encoded_data_length = 0;
  bool was_fetched_via_cache = false;
  bool was_fetched_via_service_worker = false;
  std::string mime_type = "text/plain";
  std::string alpn_negotiated_protocol = "h2";
};
}  // namespace mojom
}  // namespace network
namespace reb {
// Records what the network sink hands to the artifact channel; the real
// artifact sink and receiver run in tools/check-native-artifact-capture.py.
class NativeArtifactCaptureSink {
 public:
  struct Call {
    std::uint64_t request_id = 0, frame_id = 0, creator_event_id = 0;
    std::string url, mime_type;
    std::vector<std::uint8_t> content;
  };
  static NativeArtifactCaptureSink& Get() {
    static NativeArtifactCaptureSink sink;
    return sink;
  }
  bool IsEnabled() const { return enabled; }
  std::uint64_t CaptureRequestBody(std::uint64_t request_id,
                                   std::uint64_t frame_id,
                                   std::uint64_t creator_event_id,
                                   std::string url,
                                   std::string mime_type,
                                   std::vector<std::uint8_t> content) {
    if (refuse)
      return 0;
    calls.push_back({request_id, frame_id, creator_event_id, std::move(url), std::move(mime_type),
                     std::move(content)});
    return next_artifact_id++;
  }
  // Header blocks are kept apart so body assertions see only bodies.
  struct HeaderCall {
    NativeArtifactKind kind = NativeArtifactKind::kUnknown;
    std::uint64_t request_id = 0, frame_id = 0, creator_event_id = 0;
    std::string url;
    std::vector<std::uint8_t> content;
  };
  std::uint64_t CaptureHeaderBlock(NativeArtifactKind kind,
                                   std::uint64_t request_id,
                                   std::uint64_t frame_id,
                                   std::uint64_t creator_event_id,
                                   std::string url,
                                   std::vector<std::uint8_t> content) {
    if (refuse)
      return 0;
    header_calls.push_back(
        {kind, request_id, frame_id, creator_event_id, std::move(url), std::move(content)});
    return next_artifact_id++;
  }
  std::vector<HeaderCall> header_calls;
  bool enabled = true;
  bool refuse = false;
  std::uint64_t next_artifact_id = 900;
  std::vector<Call> calls;
};
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
