// Narrow Chromium type boundaries; the sink/lifecycle/queue are production code.
#pragma once
#include <algorithm>
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
struct HttpResponseHeaders {
  int code = 200;
  std::optional<std::string> content_encoding;
  int response_code() const { return code; }
  std::optional<std::string> GetNormalizedHeader(std::string_view name) const {
    return name == "Content-Encoding" ? content_encoding : std::nullopt;
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
  net::HttpRequestHeaders headers;
  std::shared_ptr<ResourceRequestBody> request_body;
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
struct NativeRequestContent final {
  NativeArtifactKind kind = NativeArtifactKind::kUnknown;
  std::uint64_t request_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t creator_event_id = 0;
  std::string url;
  std::string mime_type;
  std::size_t size = 0;
  std::shared_ptr<network::ResourceRequestBody> body;
  std::string text;
};
enum class NativeRequestContentAdmission : std::uint8_t {
  kQueued,
  kUnavailable,
  kSessionBudget,
  kRefused,
};
// Records what the network sink hands to the artifact channel; the real
// artifact sink, its budget and pool, and the receiver run in
// tools/check-native-artifact-capture.py.
class NativeArtifactCaptureSink {
 public:
  struct Call {
    NativeArtifactKind kind = NativeArtifactKind::kUnknown;
    std::uint64_t request_id = 0, frame_id = 0, creator_event_id = 0;
    std::string url, mime_type;
    std::vector<std::uint8_t> content;
  };
  static NativeArtifactCaptureSink& Get() {
    static NativeArtifactCaptureSink sink;
    return sink;
  }
  bool IsEnabled() const { return enabled; }
  NativeRequestContentAdmission CaptureRequestContent(NativeRequestContent content,
                                                      std::uint64_t& artifact_id) {
    artifact_id = 0;
    if (admission != NativeRequestContentAdmission::kQueued)
      return admission;
    Call call{content.kind,
              content.request_id,
              content.frame_id,
              content.creator_event_id,
              std::move(content.url),
              std::move(content.mime_type),
              {}};
    if (content.body) {
      for (const auto& element : *content.body->elements()) {
        const auto& bytes = element.As<network::DataElementBytes>().bytes();
        const auto count = std::min(bytes.size(), content.size - call.content.size());
        call.content.insert(call.content.end(), bytes.begin(),
                            bytes.begin() + static_cast<std::ptrdiff_t>(count));
      }
    } else {
      call.content.assign(content.text.begin(),
                          content.text.begin() + static_cast<std::ptrdiff_t>(content.size));
    }
    calls.push_back(std::move(call));
    artifact_id = next_artifact_id++;
    return NativeRequestContentAdmission::kQueued;
  }
  std::size_t Count(NativeArtifactKind kind) const {
    return static_cast<std::size_t>(std::count_if(
        calls.begin(), calls.end(), [kind](const Call& call) { return call.kind == kind; }));
  }
  bool enabled = true;
  NativeRequestContentAdmission admission = NativeRequestContentAdmission::kQueued;
  std::uint64_t next_artifact_id = 900;
  std::vector<Call> calls;
};
// Records the response-body hand-offs; the real capture runs in
// tools/check-native-artifact-capture.py.
class NativeResponseBodyCapture {
 public:
  static NativeResponseBodyCapture& Get() {
    static NativeResponseBodyCapture capture;
    return capture;
  }
  bool IsEnabled() const { return enabled; }
  void NoteResponseStarted(const NativeProbeHeader& header) { noted.push_back(header); }
  void OnCompleted(std::uint64_t request_id, std::uint64_t frame_id, int error_code) {
    completions.push_back({request_id, frame_id, error_code});
  }
  struct Completion {
    std::uint64_t request_id = 0, frame_id = 0;
    int error_code = 0;
  };
  bool enabled = true;
  std::vector<NativeProbeHeader> noted;
  std::vector<Completion> completions;
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
