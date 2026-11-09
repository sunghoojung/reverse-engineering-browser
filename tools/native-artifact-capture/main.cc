// Native response artifact linkage component integration test.
// No event, artifact metadata, creator sequence or ACK status is repaired in this driver.
#include <algorithm>
#include <bit>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <ranges>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_resolver.h"
#include "brave/components/reverse_engineering_browser/common/native_js_dispatch.h"
#include "brave/components/reverse_engineering_browser/common/native_js_invocation.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "chromium_stubs.h"
#include "crypto/hash.h"
#include "reb/artifact.hpp"
#include "reb/event.hpp"
#include "reb/network_headers.hpp"
#include "reb/network_request.hpp"
#include "reb/network_response_body.hpp"
#include "reb/wasm_dispatch.hpp"
#include "reb/wasm_guest.hpp"

static_assert(sizeof(reb::NativeArtifactStreamFrame) == sizeof(reb::ArtifactStreamFrame) &&
              reb::kNativeArtifactStreamMagic == reb::kArtifactStreamMagic &&
              reb::kNativeArtifactStreamProtocolVersion == reb::kArtifactStreamProtocolVersion &&
              reb::kNativeArtifactStreamChunkBytes == reb::kMaxArtifactStreamChunkBytes &&
              reb::kNativeArtifactMaxOpenStreams == reb::kMaxOpenArtifactStreams &&
              offsetof(reb::NativeArtifactStreamFrame, expected_sha256) ==
                  offsetof(reb::ArtifactStreamFrame, expected_sha256));

namespace {
using reb::NativeArtifactBodyTee;
using reb::NativeArtifactCaptureSink;
using reb::NativeArtifactSocketClient;
using reb::NativeProbeEvent;
using reb::NativeProbeType;
constexpr std::uint64_t kSession = 101;
constexpr std::uint64_t kFrame = 11;
constexpr auto kMask = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kArtifact) |
                       reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork) |
                       reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm);
std::vector<NativeProbeEvent> events;
std::ofstream event_wire;
std::ofstream artifact_wire;
std::ofstream ack_wire;
bool record_corpus = true;
std::vector<std::uint8_t> source;
int next_pipe = 1;
std::size_t assertions = 0;

void Check(bool condition, const std::string& label) {
  ++assertions;
  if (!condition) {
    throw std::runtime_error(label);
  }
}
template <class T>
void Write(std::ostream& out, const T& value) {
  out.write(reinterpret_cast<const char*>(&value), sizeof(value));
}
void Emit(const NativeProbeEvent& event) noexcept {
  events.push_back(event);
  if (record_corpus) {
    Write(event_wire, event);
  }
}
std::string Payload(const NativeProbeEvent& event) {
  return {reinterpret_cast<const char*>(event.inline_payload.data()), event.header.payload_size};
}
void Configure(std::uint64_t session = kSession, std::uint64_t mask = kMask) {
  base::test_now_ns = 100;
  NativeArtifactSocketClient::Get().connected = true;
  NativeArtifactCaptureSink::Get().SetEmitter(Emit, session, mask, 200);
  reb::NativeNetworkCaptureSink::Get().SetEmitter(Emit, session, mask, 200);
}
struct Request {
  std::uint64_t id;
  std::uint64_t root;
  std::uint64_t response;
};
Request Start(std::uint64_t id, std::uint64_t context = 11) {
  network::ResourceRequest request;
  network::mojom::URLResponseHead head;
  auto& sink = reb::NativeNetworkCaptureSink::Get();
  sink.RecordRequestStarted(id, 0, 0, 1, kFrame, context, context + 1, request);
  // The start record is followed by its request_body child.
  const auto root = std::find_if(events.rbegin(), events.rend(), [](const auto& event) {
                      return event.header.type == NativeProbeType::kRequestStarted;
                    })->header.sequence_number;
  const auto response = sink.RecordResponseStarted(id, 0, 0, 1, kFrame, context, context + 1, head);
  Check(response == events.back().header.sequence_number, "Response returns its emitted sequence");
  return {id, root, response};
}
int Begin(const Request& request,
          bool has_creator = true,
          const network::ResourceRequest& resource = {},
          const network::mojom::URLResponseHead& head = {}) {
  const int pipe = next_pipe++;
  const auto returned = NativeArtifactCaptureSink::Get().MaybeCaptureResponse(
      request.id, kFrame, has_creator ? request.response : 0, resource, head, {pipe});
  Check(returned.id == pipe, "Adapter preserves the original response body handle");
  return pipe;
}
bool Settled(const reb::NativeArtifactTransfer& transfer) {
  return transfer.stream_id == 0 &&
         (transfer.op == reb::NativeArtifactTransferOp::kWhole || transfer.ended);
}
// The artifact a body completion queued whole or ended, or zero.
std::uint64_t Finish(int pipe, bool complete = true, std::span<const std::uint8_t> body = source) {
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  std::set<std::uint64_t> settled;
  for (const auto& [id, transfer] : transfers) {
    if (Settled(*transfer)) {
      settled.insert(id);
    }
  }
  NativeArtifactBodyTee::Complete(pipe, complete, body);
  for (const auto& [id, transfer] : transfers) {
    if (Settled(*transfer) && !settled.contains(id)) {
      return id;
    }
  }
  return 0;
}
// One producer frame, byte for byte as the socket writer sends it.
std::string Wire(const reb::NativeArtifactTransfer& transfer) {
  std::ostringstream serialized(std::ios::binary);
  if (transfer.op == reb::NativeArtifactTransferOp::kStream) {
    Write(serialized, transfer.frame);
  } else {
    Write(serialized, transfer.header);
    serialized << transfer.url << transfer.mime_type;
  }
  serialized.write(reinterpret_cast<const char*>(transfer.content.data()),
                   static_cast<std::streamsize>(transfer.content.size()));
  return serialized.str();
}
reb::ArtifactAck ReceiveFrame(reb::ArtifactReceiver& receiver, const std::string& bytes) {
  if (record_corpus) {
    artifact_wire.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  std::istringstream stream(bytes, std::ios::binary);
  reb::ArtifactAck ack;
  ack.status = receiver.ReceiveOne(stream);
  ack.artifact_id = receiver.LastArtifactId();
  ack.protocol_version = receiver.ProtocolVersion();
  return ack;
}
// Delivers a whole transfer, or a stream's frames through its end or through
// the named checkpoint, and reports the writer's one result for that ID: the
// final ACK, or the stream's first refusal.
reb::NativeArtifactAck Receive(
    reb::ArtifactReceiver& receiver,
    std::uint64_t id,
    bool deliver = true,
    reb::ArtifactReceiveStatus expected = reb::ArtifactReceiveStatus::kAccepted) {
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const std::uint64_t snapshot_of = transfers.at(id)->stream_id;
  const bool snapshot = snapshot_of != 0;
  const std::uint64_t stream_id = snapshot ? snapshot_of : id;
  auto& stream = *transfers.at(stream_id);
  reb::ArtifactAck actual_ack;
  if (stream.op == reb::NativeArtifactTransferOp::kWhole) {
    actual_ack = ReceiveFrame(receiver, Wire(stream));
    transfers.erase(id);
  } else {
    Check(snapshot || stream.ended, "A stream is received after it ended");
    bool failed = false;
    while (stream.delivered < stream.frames.size()) {
      const auto& frame = *stream.frames[stream.delivered++];
      actual_ack = ReceiveFrame(receiver, Wire(frame));
      const bool last = frame.op == reb::NativeArtifactTransferOp::kStream &&
                        (snapshot ? frame.frame.op == reb::NativeArtifactStreamOp::kCheckpoint &&
                                        frame.frame.value == id
                                  : frame.frame.op == reb::NativeArtifactStreamOp::kEnd);
      if (last) {
        break;
      }
      if (actual_ack.status != reb::ArtifactReceiveStatus::kAccepted) {
        failed = true;
        actual_ack.artifact_id = id;
        break;
      }
    }
    if (snapshot) {
      transfers.erase(id);
    }
    if (failed || !snapshot) {
      transfers.erase(stream_id);
    }
  }
  Check(actual_ack.status == expected, "Production receiver status: " + receiver.LastError());
  Check(actual_ack.artifact_id == id, "ACK identity comes from ReceiveOne LastArtifactId");
  const auto native_ack = std::bit_cast<reb::NativeArtifactAck>(actual_ack);
  Check(native_ack.magic == reb::kNativeArtifactAckMagic &&
            (native_ack.protocol_version == reb::kNativeArtifactProtocolVersion ||
             native_ack.protocol_version == reb::kNativeArtifactStreamProtocolVersion) &&
            native_ack.ack_size == sizeof(native_ack),
        "Production ACK bytes match native ACK protocol");
  if (record_corpus) {
    Write(ack_wire, native_ack);
  }
  if (deliver) {
    NativeArtifactCaptureSink::TransferCompleted(native_ack.artifact_id, native_ack.status);
  }
  return native_ack;
}
void CheckCapture(std::uint64_t id, std::uint64_t parent, std::uint64_t request) {
  const auto& header = events.back().header;
  Check(header.type == NativeProbeType::kArtifactCaptured && header.artifact_id == id &&
            header.parent_event_id == parent && header.request_id == request,
        "Accepted ACK retains the exact response sequence and request identity");
}
struct Case {
  std::string name;
  Request request;
  std::vector<std::uint64_t> expected;
};
void WriteCases(const std::filesystem::path& output, const std::vector<Case>& cases) {
  std::ofstream stream(output / "cases.json");
  stream << "[";
  for (std::size_t index = 0; index < cases.size(); ++index) {
    const auto& item = cases[index];
    stream
        << (index ? ",\n" : "\n") << "{\"name\":\"" << item.name
        << "\",\"selection\":{\"kind\":\"request\",\"request_id\":\"" << item.request.id
        << "\",\"root_event\":{\"session_id\":\"101\",\"process_id\":42,\"sequence_number\":\""
        << item.request.root
        << "\"},\"edge_semantics\":\"exact-captured-response-body\"},\"expected_artifact_ids\":[";
    for (std::size_t artifact = 0; artifact < item.expected.size(); ++artifact) {
      stream << (artifact ? "," : "") << '"' << item.expected[artifact] << '"';
    }
    stream << "]}";
  }
  stream << "\n]\n";
}
const NativeProbeEvent& LastOf(NativeProbeType type) {
  const auto found = std::find_if(events.rbegin(), events.rend(),
                                  [type](const auto& event) { return event.header.type == type; });
  Check(found != events.rend(), "Expected event type was emitted");
  return *found;
}
reb::RequestBodyPayload BodyPayload(const NativeProbeEvent& event) {
  reb::RequestBodyPayload value;
  Check(reb::DecodeRequestBodyPayload(event.inline_payload, value) &&
            reb::IsValidEvent(std::bit_cast<reb::EventRecord>(event)),
        "Produced request_body record passes the core validator");
  return value;
}
std::string Hex(std::span<const std::uint8_t> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string text;
  for (const auto byte : bytes) {
    text.push_back(kDigits[byte >> 4U]);
    text.push_back(kDigits[byte & 15U]);
  }
  return text;
}
std::vector<std::uint8_t> Bytes(const std::string& text) {
  return {text.begin(), text.end()};
}
std::shared_ptr<network::ResourceRequestBody> BodyOf(const std::string& text) {
  auto body = std::make_shared<network::ResourceRequestBody>();
  body->elements_mutable()->emplace_back(
      network::DataElementBytes(std::vector<std::uint8_t>(text.begin(), text.end())));
  return body;
}

// Content-mode request bodies through the real network and artifact sinks to
// the production receiver; the Python stage replays them through the broker.
void RequestBodies(reb::ArtifactReceiver& receiver, const std::filesystem::path& output) {
  base::test_now_ns = 100;
  NativeArtifactSocketClient::Get().connected = true;
  NativeArtifactCaptureSink::Get().SetEmitter(Emit, kSession, kMask, 200);
  auto& network = reb::NativeNetworkCaptureSink::Get();
  network.SetEmitter(Emit, kSession, kMask, 200, true);
  struct Body {
    std::uint64_t request_id;
    std::string url;
    std::string content;
  };
  const std::string json = "{\"v\":\"1\",\"host\":\"accounts.hcaptcha.test\",\"sitekey\":\"" +
                           std::string(740, 's') + "\"}";
  // The second body is past the 4 MiB record digest; its artifact digest is
  // computed off the UI sequence and checked by the receiver.
  const Body bodies[] = {
      {401, "https://api.hcaptcha.test/checksiteconfig?v=1&host=accounts.hcaptcha.test", json},
      {402, "https://api.hcaptcha.test/getcaptcha/site",
       "{\"data\":\"" + std::string(5U * 1024U * 1024U, 'm') + "\"}"},
  };
  std::ofstream expected(output / "request-bodies.json");
  std::ofstream expected_headers(output / "request-headers.json");
  std::uint64_t first_header_artifact = 0;
  expected << "[";
  expected_headers << "[";
  for (std::size_t index = 0; index < std::size(bodies); ++index) {
    const auto& body = bodies[index];
    network::ResourceRequest request;
    request.method = "POST";
    request.resource_type = 13;
    request.url = GURL(body.url);
    request.headers.SetHeader("Content-Type", "application/json;charset=UTF-8");
    request.request_body = BodyOf(body.content);
    network.RecordRequestStarted(body.request_id, 0, 0, 1, kFrame, 11, 12, request);
    Check(base::ThreadPool::RunPending() == 1, "The body is copied off the UI sequence");
    const auto started = LastOf(NativeProbeType::kRequestStarted);
    const auto target = LastOf(NativeProbeType::kRequestTarget);
    const auto record = LastOf(NativeProbeType::kRequestBody);
    const auto payload = BodyPayload(record);
    Check(target.header.parent_event_id == started.header.sequence_number &&
              record.header.parent_event_id == started.header.sequence_number &&
              reb::IsValidEvent(std::bit_cast<reb::EventRecord>(target)),
          "Target and body are exact children of the start record");
    const auto artifact_id = record.header.artifact_id;
    const auto& transfer = *NativeArtifactSocketClient::Get().transfers.at(artifact_id);
    Check(transfer.header.kind == reb::NativeArtifactKind::kRequestBody &&
              transfer.header.capture_origin == reb::NativeArtifactCaptureOrigin::kNetworkRequest &&
              (transfer.header.flags & reb::kNativeArtifactFlagSensitive) != 0 &&
              transfer.header.creator_event_id == record.header.sequence_number &&
              transfer.url == body.url && transfer.mime_type == "application/json" &&
              std::equal(transfer.content.begin(), transfer.content.end(), body.content.begin(),
                         body.content.end()),
          "Request body artifact header names its body record, full URL and type");
    const auto digest = crypto::hash::Sha256(body.content);
    Check(transfer.header.expected_sha256 == digest, "The artifact carries its exact digest");
    Receive(receiver, artifact_id);
    CheckCapture(artifact_id, record.header.sequence_number, body.request_id);
    const bool hashed = body.content.size() <= reb::kNativeRequestBodyDigestBytes;
    Check((hashed ? payload.sha256 == digest : payload.sha256 == decltype(digest){}) &&
              payload.body_length == body.content.size() &&
              payload.state == static_cast<std::uint8_t>(reb::RequestBodyState::kCaptured),
          "Body record describes the whole body; past 4 MiB the artifact holds the digest");
    // The provisional header block follows the body as its own sensitive
    // artifact; the second request's identical block names the first one.
    const NativeProbeEvent headers = LastOf(NativeProbeType::kRequestHeaders);
    reb::HeaderBlockPayload header_payload;
    Check(headers.header.parent_event_id == started.header.sequence_number &&
              reb::IsValidEvent(std::bit_cast<reb::EventRecord>(headers)) &&
              reb::DecodeHeaderBlockPayload(headers.inline_payload, header_payload),
          "Request header record is a valid child of the start record");
    if (index != 0) {
      Check(header_payload.state == static_cast<std::uint8_t>(reb::HeaderState::kCapturedShared) &&
                headers.header.artifact_id == first_header_artifact &&
                !NativeArtifactSocketClient::Get().transfers.contains(headers.header.artifact_id),
            "An identical header block is retained once and shared by artifact ID");
    } else {
      first_header_artifact = headers.header.artifact_id;
      const auto& header_transfer =
          *NativeArtifactSocketClient::Get().transfers.at(headers.header.artifact_id);
      Check(header_transfer.header.kind == reb::NativeArtifactKind::kRequestHeaders &&
                header_transfer.header.creator_event_id == headers.header.sequence_number &&
                header_transfer.mime_type == "text/plain" && header_transfer.url == body.url,
            "Request header artifact names its header record, URL and text type");
      Receive(receiver, headers.header.artifact_id);
      CheckCapture(headers.header.artifact_id, headers.header.sequence_number, body.request_id);
      expected_headers << "\n{\"start_sequence\":\"" << started.header.sequence_number
                       << "\",\"header_sequence\":\"" << headers.header.sequence_number
                       << "\",\"artifact_id\":\"" << headers.header.artifact_id << "\",\"url\":\""
                       << body.url << "\"}";
    }
    expected << (index ? ",\n" : "\n") << "{\"request_id\":\"" << body.request_id
             << "\",\"start_sequence\":\"" << started.header.sequence_number
             << "\",\"body_sequence\":\"" << record.header.sequence_number
             << "\",\"artifact_id\":\"" << artifact_id << "\",\"url\":\"" << body.url
             << "\",\"mime_type\":\"application/json\",\"body_length\":" << payload.body_length
             << ",\"captured_length\":" << payload.captured_length
             << ",\"state\":" << static_cast<unsigned>(payload.state) << ",\"sha256\":\""
             << Hex(digest) << "\"}";
  }
  // A multipart upload with a file and a stream-body fetch are read off the UI
  // sequence; each record follows its read and creates its artifact.
  struct ReadBody {
    std::uint64_t request_id;
    std::string url;
    std::string content_type;
    std::string mime_type;
    std::vector<network::DataElement> (*parts)();
    std::string content;
  };
  const ReadBody reads[] = {
      {404, "https://api.hcaptcha.test/upload", "multipart/form-data; boundary=b",
       "multipart/form-data",
       [] {
         std::vector<network::DataElement> parts;
         parts.emplace_back(
             network::DataElementBytes(Bytes("--b\r\nContent-Type: image/png\r\n\r\n")));
         parts.emplace_back(network::DataElementFile{});
         parts.emplace_back(network::DataElementBytes(Bytes("\r\n--b--\r\n")));
         return parts;
       },
       "--b\r\nContent-Type: image/png\r\n\r\n" + std::string(3000, '\x89') + "\r\n--b--\r\n"},
      {405, "https://api.hcaptcha.test/stream", "application/x-ndjson", "application/x-ndjson",
       [] {
         std::vector<network::DataElement> parts;
         parts.emplace_back(network::DataElementChunkedDataPipe{});
         return parts;
       },
       "{\"n\":1}\n{\"n\":2}\n"},
  };
  for (const auto& read : reads) {
    network::ResourceRequest request;
    request.method = "POST";
    request.resource_type = 13;
    request.url = GURL(read.url);
    request.headers.SetHeader("Content-Type", read.content_type);
    request.request_body = std::make_shared<network::ResourceRequestBody>();
    *request.request_body->elements_mutable() = read.parts();
    const auto records_before = std::ranges::count_if(
        events, [](const auto& e) { return e.header.type == NativeProbeType::kRequestBody; });
    network.RecordRequestStarted(read.request_id, 0, 0, 1, kFrame, 11, 12, request);
    const auto started = LastOf(NativeProbeType::kRequestStarted);
    Check(std::ranges::count_if(events,
                                [](const auto& e) {
                                  return e.header.type == NativeProbeType::kRequestBody;
                                }) == records_before,
          "A body with file, blob or stream parts waits for its read");
    reb::NativeRequestBodyReader::reads.clear();
    network.TeeRequestBody(read.request_id, request);
    Check(reb::NativeRequestBodyReader::reads.size() == 1, "The read starts at the hook");
    reb::NativeRequestBodyReader::Finish(0, base::as_byte_span(read.content),
                                         reb::NativeRequestBodyReadEnd::kComplete,
                                         read.content.size());
    const auto record = LastOf(NativeProbeType::kRequestBody);
    const auto payload = BodyPayload(record);
    const auto digest = crypto::hash::Sha256(read.content);
    const auto& transfer =
        *NativeArtifactSocketClient::Get().transfers.at(record.header.artifact_id);
    Check(record.header.parent_event_id == started.header.sequence_number &&
              payload.state == static_cast<std::uint8_t>(reb::RequestBodyState::kCaptured) &&
              (payload.flags & reb::kRequestBodyRead) != 0 &&
              (payload.flags & reb::kRequestBodyLengthPartial) == 0 &&
              payload.body_length == read.content.size() &&
              payload.captured_length == read.content.size() && payload.sha256 == digest &&
              transfer.ended && transfer.header.creator_event_id == record.header.sequence_number &&
              transfer.header.expected_sha256 == digest && transfer.mime_type == read.mime_type &&
              std::string(transfer.content.begin(), transfer.content.end()) == read.content,
          "A read body is retained with its exact bytes, length and digest, created by its record");
    Receive(receiver, record.header.artifact_id);
    CheckCapture(record.header.artifact_id, record.header.sequence_number, read.request_id);
    expected << ",\n{\"request_id\":\"" << read.request_id << "\",\"start_sequence\":\""
             << started.header.sequence_number << "\",\"body_sequence\":\""
             << record.header.sequence_number << "\",\"artifact_id\":\""
             << record.header.artifact_id << "\",\"url\":\"" << read.url << "\",\"mime_type\":\""
             << read.mime_type << "\",\"body_length\":" << payload.body_length
             << ",\"captured_length\":" << payload.captured_length
             << ",\"state\":" << static_cast<unsigned>(payload.state) << ",\"sha256\":\""
             << Hex(digest) << "\"}";
  }
  expected << "\n]\n";
  expected_headers << "\n]\n";

  // A GraphQL GET whose target is far past the inline prefix.
  const std::string query =
      "operationName=Search&variables=" + std::string(7900, 'v') + "&extensions=%7B%7D";
  network::ResourceRequest graphql;
  graphql.url = GURL("https://api.hcaptcha.test/graphql?" + query);
  network.RecordRequestStarted(403, 0, 0, 1, kFrame, 11, 12, graphql);
  Check(base::ThreadPool::RunPending() == 1, "The full target is copied off the UI sequence");
  const auto started = LastOf(NativeProbeType::kRequestStarted);
  const auto target = LastOf(NativeProbeType::kRequestTarget);
  reb::RequestTargetPayload decoded;
  Check(reb::DecodeRequestTargetPayload(target.inline_payload, decoded) &&
            reb::IsValidEvent(std::bit_cast<reb::EventRecord>(target)) &&
            decoded.reserved0 ==
                static_cast<std::uint8_t>(reb::NativeRequestTargetRetention::kRetained) &&
            target.header.artifact_id != 0,
        "A long target names its retained full-target artifact");
  const std::string full = "/graphql?" + query;
  const auto& transfer = *NativeArtifactSocketClient::Get().transfers.at(target.header.artifact_id);
  Check(transfer.header.kind == reb::NativeArtifactKind::kRequestTarget &&
            transfer.header.capture_origin == reb::NativeArtifactCaptureOrigin::kNetworkRequest &&
            (transfer.header.flags & reb::kNativeArtifactFlagSensitive) != 0 &&
            transfer.header.creator_event_id == target.header.sequence_number &&
            transfer.url == "https://api.hcaptcha.test" && transfer.mime_type == "text/plain" &&
            std::string(transfer.content.begin(), transfer.content.end()) == full &&
            decoded.target_length == full.size(),
        "The full target is retained byte for byte under its origin");
  const auto target_id = target.header.artifact_id;
  Receive(receiver, target_id);
  CheckCapture(target_id, target.header.sequence_number, 403);
  std::ofstream targets(output / "request-targets.json");
  targets << "[{\"request_id\":\"403\",\"start_sequence\":\"" << started.header.sequence_number
          << "\",\"target_sequence\":\"" << target.header.sequence_number << "\",\"artifact_id\":\""
          << target_id << "\",\"origin\":\"https://api.hcaptcha.test\""
          << ",\"target_length\":" << full.size() << ",\"sha256\":\""
          << Hex(crypto::hash::Sha256(full)) << "\"}]\n";
  std::cout << "PASS request bodies: content-mode target/body/header children, sensitive "
               "request_body and request_headers artifacts with full URL and off-thread digest "
               "past 4 MiB, an 8 KB target retained whole, receiver ACK joined to each creator "
               "record\n";
}

reb::RequestTargetPayload TargetPayload(const NativeProbeEvent& event) {
  reb::RequestTargetPayload value;
  Check(reb::DecodeRequestTargetPayload(event.inline_payload, value) &&
            reb::IsValidEvent(std::bit_cast<reb::EventRecord>(event)),
        "Produced request_target record passes the core validator");
  return value;
}

// Byte budget, digest dedupe, the in-flight pool and the background copy, all
// through the real network and artifact sinks.
void RequestContentLimits() {
  auto& network = reb::NativeNetworkCaptureSink::Get();
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  std::uint64_t next_request = 600;
  const auto configure = [&](std::uint64_t budget) {
    Configure();
    sink.SetEmitter(Emit, kSession, kMask, 200, budget);
    network.SetEmitter(Emit, kSession, kMask, 200, true);
    transfers.clear();
  };
  // No request headers, so every transfer and pool share here is request content.
  const auto post = [&](network::ResourceRequest request) {
    request.method = "POST";
    network.RecordRequestStarted(next_request++, 0, 0, 1, kFrame, 11, 12, request);
    return LastOf(NativeProbeType::kRequestBody);
  };
  const auto state_of = [](const NativeProbeEvent& event) {
    return static_cast<reb::RequestBodyState>(BodyPayload(event).state);
  };
  const auto with_body = [](std::string content) {
    network::ResourceRequest request;
    request.url = GURL("https://api.fixture.test/collect");
    request.request_body = BodyOf(content);
    return request;
  };

  // 5,000 small distinct bodies all fit a 1 MiB budget; the next one does not.
  configure(reb::kNativeRequestContentMinBudgetBytes);
  for (int index = 0; index < 5000; ++index) {
    std::string content(200, 'b');
    const std::string number = std::to_string(index);
    std::copy(number.begin(), number.end(), content.begin());
    Check(state_of(post(with_body(std::move(content)))) == reb::RequestBodyState::kCaptured,
          "Every small body is retained until the budget is used");
  }
  Check(base::ThreadPool::RunPending() == 5000 && transfers.size() == 5000 &&
            sink.in_flight_bytes() == 5000U * 200U,
        "5,000 bodies are queued, each holding exactly its bytes");
  Check(state_of(post(with_body(std::string(64 * 1024, 'x')))) ==
                reb::RequestBodyState::kNotCapturedSessionBudget &&
            base::ThreadPool::pending.empty(),
        "The body past the budget is named, not copied");

  // Identical bytes are charged once: the receiver keeps one blob per digest.
  configure(reb::kNativeRequestContentMinBudgetBytes);
  const std::string repeated(400 * 1024, 'r');
  Check(state_of(post(with_body(repeated))) == reb::RequestBodyState::kCaptured &&
            state_of(post(with_body(repeated))) == reb::RequestBodyState::kCaptured,
        "Both copies are admitted before their digests are known");
  base::ThreadPool::RunPending();
  Check(state_of(post(with_body(std::string(400 * 1024, 's')))) == reb::RequestBodyState::kCaptured,
        "The repeat was refunded, so a distinct body still fits");
  base::ThreadPool::RunPending();
  Check(state_of(post(with_body(std::string(400 * 1024, 't')))) ==
            reb::RequestBodyState::kNotCapturedSessionBudget,
        "Distinct bytes past the budget are refused");
  Check(transfers.size() == 3, "The repeat is still transferred and joined to its own record");

  // A large body is copied whole up to 16 MiB; a larger one keeps that prefix.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  const std::string large(reb::kNativeArtifactMaxContentBytes + 5, 'L');
  const auto truncated = post(with_body(large));
  const auto truncated_payload = BodyPayload(truncated);
  Check(truncated_payload.state ==
                static_cast<std::uint8_t>(reb::RequestBodyState::kCapturedTruncated) &&
            truncated_payload.captured_length == reb::kNativeArtifactMaxContentBytes,
        "A body past 16 MiB keeps its first 16 MiB and its length");
  Check(transfers.size() == 1 && !transfers.begin()->second->ended && sink.in_flight_bytes() == 0,
        "Nothing is copied on the UI sequence; the opened stream holds nothing yet");
  base::ThreadPool::RunPending();
  const auto& copy = *transfers.at(truncated.header.artifact_id);
  Check(copy.content.size() == reb::kNativeArtifactMaxContentBytes &&
            copy.header.expected_sha256 == crypto::hash::Sha256(std::span(copy.content)),
        "The prefix and its digest are exact");
  // The pool is shared with response tees: a full pool fails the copy, joined
  // to the record.
  {
    auto held = reb::NativeArtifactReservation::Acquire(
        sink.memory_pool(), reb::kNativeArtifactInFlightBytes - sink.in_flight_bytes());
    const auto starved = post(with_body("{}"));
    base::ThreadPool::RunPending();
    Check(Payload(events.back()) == "active_memory_limit" &&
              events.back().header.parent_event_id == starved.header.sequence_number,
          "A full in-flight pool fails the copy visibly");
  }
  transfers.clear();
  Check(sink.in_flight_bytes() == 0, "Dropped transfers return their share");

  // The copy reads the body after the record: a body that changed is a failure
  // joined to its record, never a short artifact.
  auto changing = with_body("{\"a\":1}");
  const auto record = post(changing);
  changing.request_body->elements_mutable()->clear();
  base::ThreadPool::RunPending();
  Check(transfers.empty() && events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            Payload(events.back()) == "request_content_changed" &&
            events.back().header.parent_event_id == record.header.sequence_number &&
            events.back().header.artifact_id == record.header.artifact_id,
        "A changed body is a visible failure");
  base::ThreadPool::refuse = true;
  Check(state_of(post(with_body("{}"))) == reb::RequestBodyState::kNotCapturedTransferRefused,
        "A refused background task is named");
  base::ThreadPool::refuse = false;
  NativeArtifactSocketClient::Get().reject_next = true;
  Check(state_of(post(with_body("{}"))) == reb::RequestBodyState::kNotCapturedTransferRefused,
        "A refused open header is named");
  const auto queued = post(with_body("{\"b\":2}"));
  NativeArtifactSocketClient::Get().reject_next = true;
  base::ThreadPool::RunPending();
  Check(Payload(events.back()) == "transfer_queue_full_or_disconnected" &&
            events.back().header.parent_event_id == queued.header.sequence_number,
        "A full queue after the copy is a failure joined to the record");

  // The copy path names the artifact in its record before the copy runs, so a
  // stream lost in that window is one failure joined to the record, and the end
  // frame the writer would drop is never sent.
  configure(reb::kNativeRequestContentMinBudgetBytes);
  const auto copying = post(with_body(std::string(reb::kNativeRequestContentMinBudgetBytes, 'c')));
  const auto failures_of_copy = [] {
    return std::ranges::count_if(events, [](const auto& e) {
      return e.header.type == NativeProbeType::kArtifactCaptureFailed;
    });
  };
  const auto copy_failures_before = failures_of_copy();
  NativeArtifactCaptureSink::TransferCompleted(copying.header.artifact_id,
                                               reb::NativeArtifactReceiveStatus::kIoError);
  Check(failures_of_copy() == copy_failures_before + 1 &&
            events.back().header.parent_event_id == copying.header.sequence_number &&
            events.back().header.artifact_id == copying.header.artifact_id,
        "A stream lost while its body is copied is a failure joined to the record");
  const auto copy_events_before = events.size();
  base::ThreadPool::RunPending();
  Check(events.size() == copy_events_before && !transfers.contains(copying.header.artifact_id),
        "The copy that follows a reported loss emits nothing more and ends nothing");
  NativeArtifactCaptureSink::TransferCompleted(copying.header.artifact_id,
                                               reb::NativeArtifactReceiveStatus::kAccepted);
  Check(events.size() == copy_events_before, "The lost copy leaves no pending entry behind");
  Check(state_of(post(with_body(std::string(reb::kNativeRequestContentMinBudgetBytes, 'g')))) ==
            reb::RequestBodyState::kCaptured,
        "The lost copy returned its budget share");
  base::ThreadPool::RunPending();
  transfers.clear();
  configure(reb::kNativeRequestContentDefaultBudgetBytes);

  // Targets: the inline prefix is the whole target up to 116 bytes; past it the
  // full target is retained, or the record names why not.
  const auto get = [&](const std::string& url) {
    network::ResourceRequest request;
    request.url = GURL(url);
    network.RecordRequestStarted(next_request++, 0, 0, 1, kFrame, 11, 12, request);
    return LastOf(NativeProbeType::kRequestTarget);
  };
  const auto retention = [](const reb::RequestTargetPayload& value) {
    return static_cast<reb::NativeRequestTargetRetention>(value.reserved0);
  };
  const std::string exact = "/" + std::string(reb::kNativeRequestTargetPrefixBytes - 1, 'e');
  const auto inline_target = get("https://api.fixture.test" + exact);
  Check(retention(TargetPayload(inline_target)) == reb::NativeRequestTargetRetention::kComplete &&
            inline_target.header.artifact_id == 0 && base::ThreadPool::pending.empty(),
        "A 116-byte target is complete inline");
  const auto long_target = get("https://api.fixture.test" + exact + "?q");
  Check(retention(TargetPayload(long_target)) == reb::NativeRequestTargetRetention::kRetained &&
            long_target.header.artifact_id != 0 && base::ThreadPool::RunPending() == 1,
        "A 117-byte target is retained in full");
  Check(retention(TargetPayload(get("ftp://files.fixture.test" + exact + "?q"))) ==
            reb::NativeRequestTargetRetention::kNotRetainedUrl,
        "A scheme without an origin is named");
  configure(reb::kNativeRequestContentMinBudgetBytes);
  post(with_body(std::string(reb::kNativeRequestContentMinBudgetBytes - 64, 'f')));
  Check(retention(TargetPayload(get("https://api.fixture.test" + exact + "?budget"))) ==
            reb::NativeRequestTargetRetention::kNotRetainedSessionBudget,
        "A target past the budget is named");
  base::ThreadPool::RunPending();
  NativeArtifactSocketClient::Get().connected = false;
  Check(retention(TargetPayload(get("https://api.fixture.test" + exact + "?off"))) ==
            reb::NativeRequestTargetRetention::kNotRetainedArtifactUnavailable,
        "A target without the artifact channel is named");
  NativeArtifactSocketClient::Get().connected = true;
  Configure();
  transfers.clear();
  Check(sink.in_flight_bytes() == 0 && base::ThreadPool::pending.empty(),
        "No request content is left in flight");
  std::cout << "PASS request content: 5,000 bodies within a byte budget, digest dedupe, 16 MiB "
               "prefix copied off the UI sequence, shared pool, changed and refused copies, "
               "full targets and every retention state\n";
}

// File, blob and stream bodies: the deferred record, truncation, the budget
// allowance, incomplete reads, capture end, a missing hook and refusals.
void ReadRequestBodies(const std::filesystem::path& output) {
  auto& network = reb::NativeNetworkCaptureSink::Get();
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  auto& reads = reb::NativeRequestBodyReader::reads;
  using Read = reb::NativeRequestBodyReadEnd;
  std::uint64_t next_request = 950;
  const auto configure = [&](std::uint64_t budget) {
    Configure();
    sink.SetEmitter(Emit, kSession, kMask, 200, budget);
    network.SetEmitter(Emit, kSession, kMask, 200, true);
    transfers.clear();
    reads.clear();
  };
  const auto upload = [&](network::DataElement part) {
    network::ResourceRequest request;
    request.method = "POST";
    request.url = GURL("https://api.fixture.test/upload");
    request.request_body = std::make_shared<network::ResourceRequestBody>();
    request.request_body->elements_mutable()->push_back(std::move(part));
    return request;
  };
  const auto bodies = [] {
    return std::ranges::count_if(
        events, [](const auto& e) { return e.header.type == NativeProbeType::kRequestBody; });
  };
  const auto start = [&](network::ResourceRequest& request, const bool hook = true) {
    const auto id = next_request++;
    network.RecordRequestStarted(id, 0, 0, 1, kFrame, 11, 12, request);
    if (hook) {
      network.TeeRequestBody(id, request);
    }
    return LastOf(NativeProbeType::kRequestStarted).header.sequence_number;
  };
  const auto record = [](const NativeProbeEvent& event) { return BodyPayload(event); };
  const auto state = [](const reb::RequestBodyPayload& value) {
    return static_cast<reb::RequestBodyState>(value.state);
  };

  // Past 16 MiB the prefix is kept and the whole length recorded.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  auto blob = upload(network::DataElement(network::DataElementDataPipe{}));
  start(blob);
  std::vector<std::uint8_t> large(reb::kNativeArtifactMaxContentBytes + 77);
  for (std::size_t index = 0; index < large.size(); ++index) {
    large[index] = static_cast<std::uint8_t>(index * 5U);
  }
  reb::NativeRequestBodyReader::Finish(0, large, Read::kComplete, large.size());
  const auto truncated = record(LastOf(NativeProbeType::kRequestBody));
  const auto& prefix = *transfers.at(LastOf(NativeProbeType::kRequestBody).header.artifact_id);
  Check(state(truncated) == reb::RequestBodyState::kCapturedTruncated &&
            truncated.body_length == large.size() &&
            truncated.captured_length == reb::kNativeArtifactMaxContentBytes &&
            (truncated.flags & reb::kRequestBodyDigestSizeLimit) != 0 &&
            prefix.content.size() == reb::kNativeArtifactMaxContentBytes &&
            prefix.header.expected_sha256 ==
                crypto::hash::Sha256(std::span(large).first(reb::kNativeArtifactMaxContentBytes)),
        "A read body past 16 MiB keeps its prefix, its exact length and the prefix digest");
  transfers.clear();

  // A body of exactly the cap, or one byte past it, read in aligned chunks: the
  // reader stops at the cap either way, so only the length tells them apart.
  const auto aligned = [&](const std::size_t length) {
    configure(reb::kNativeRequestContentDefaultBudgetBytes);
    auto body = upload(network::DataElement(network::DataElementFile{}));
    start(body);
    reb::NativeRequestBodyReader::Finish(0, std::span(large).first(length), Read::kComplete,
                                         length);
    return LastOf(NativeProbeType::kRequestBody);
  };
  const auto cap = reb::kNativeArtifactMaxContentBytes;
  const NativeProbeEvent whole_event = aligned(cap);
  const auto whole = record(whole_event);
  Check(state(whole) == reb::RequestBodyState::kCaptured && whole.body_length == cap &&
            whole.captured_length == cap && (whole.flags & reb::kRequestBodyDigestPresent) != 0 &&
            reb::IsValidRequestBodyPayload(whole, whole_event.header.artifact_id != 0) &&
            transfers.at(whole_event.header.artifact_id)->content.size() == cap,
        "A body of exactly 16 MiB read in aligned chunks is captured whole, with its digest");
  const NativeProbeEvent over_event = aligned(cap + 1);
  const auto one_over = record(over_event);
  Check(state(one_over) == reb::RequestBodyState::kCapturedTruncated &&
            one_over.body_length == cap + 1 && one_over.captured_length == cap &&
            (one_over.flags & reb::kRequestBodyDigestSizeLimit) != 0 &&
            (one_over.flags & reb::kRequestBodyDigestPresent) == 0 &&
            reb::IsValidRequestBodyPayload(one_over, over_event.header.artifact_id != 0) &&
            transfers.at(over_event.header.artifact_id)->content.size() == cap,
        "A body of 16 MiB + 1 read in aligned chunks records truncation the broker accepts");
  transfers.clear();

  // The budget gives a read an allowance; past it the record names the budget.
  configure(reb::kNativeRequestContentMinBudgetBytes);
  auto stream = upload(network::DataElement(network::DataElementChunkedDataPipe{}));
  start(stream);
  auto second = upload(network::DataElement(network::DataElementFile{}));
  start(second);
  Check(reads.size() == 1 && state(record(LastOf(NativeProbeType::kRequestBody))) ==
                                 reb::RequestBodyState::kNotCapturedSessionBudget,
        "A read holds the remaining budget while it runs; the next read is refused visibly");
  const std::vector<std::uint8_t> over(reb::kNativeRequestContentMinBudgetBytes + 1, 's');
  reb::NativeRequestBodyReader::Finish(0, over, Read::kComplete, over.size());
  const auto budget = record(LastOf(NativeProbeType::kRequestBody));
  Check(state(budget) == reb::RequestBodyState::kNotCapturedSessionBudget &&
            (budget.flags & reb::kRequestBodyRead) != 0 &&
            (budget.flags & reb::kRequestBodyLengthPartial) != 0 && transfers.empty() &&
            LastOf(NativeProbeType::kRequestBody).header.artifact_id == 0,
        "A read past its allowance is refused by the budget and its stream aborted");
  start(second);
  const std::vector<std::uint8_t> fits(1000, 'f');
  reb::NativeRequestBodyReader::Finish(1, fits, Read::kComplete, fits.size());
  Check(state(record(LastOf(NativeProbeType::kRequestBody))) == reb::RequestBodyState::kCaptured,
        "The refused read returned its allowance");

  // A pool that stays full refuses the read.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  auto pooled = upload(network::DataElement(network::DataElementDataPipe{}));
  start(pooled);
  reb::NativeRequestBodyReader::Finish(0, fits, Read::kRefused, fits.size());
  Check(state(record(LastOf(NativeProbeType::kRequestBody))) ==
                reb::RequestBodyState::kNotCapturedTransferRefused &&
            transfers.empty(),
        "A read the pool kept waiting is refused visibly");

  // A part that changed or failed is incomplete; nothing is published.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  auto file = upload(network::DataElement(network::DataElementFile{}));
  start(file);
  reb::NativeRequestBodyReader::Finish(0, fits, Read::kIncomplete, fits.size());
  const auto incomplete = record(LastOf(NativeProbeType::kRequestBody));
  Check(state(incomplete) == reb::RequestBodyState::kNotCapturedReadIncomplete &&
            incomplete.body_length == fits.size() && transfers.empty(),
        "An incomplete read is named, with what it read, and its stream is aborted");

  // An empty file is an empty body with the digest of nothing.
  start(file);
  reb::NativeRequestBodyReader::Finish(1, {}, Read::kComplete, 0);
  const auto empty = record(LastOf(NativeProbeType::kRequestBody));
  Check(state(empty) == reb::RequestBodyState::kEmpty &&
            empty.sha256 == crypto::hash::Sha256(std::span<const std::uint8_t>()) &&
            transfers.empty(),
        "An empty read is an empty body, not an artifact");

  // Capture end records a read that is still running; its result is dropped.
  start(file);
  const auto before_end = bodies();
  Configure();
  Check(bodies() == before_end + 1 && state(record(LastOf(NativeProbeType::kRequestBody))) ==
                                          reb::RequestBodyState::kNotCapturedReadIncomplete,
        "Capture end records an unfinished read as incomplete");
  const auto after_end = events.size();
  reb::NativeRequestBodyReader::Finish(2, fits, Read::kComplete, fits.size());
  Check(events.size() == after_end && transfers.empty(),
        "A read finishing after capture end emits nothing and publishes nothing");

  // Without the hook the body is recorded unread, never lost.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  start(file, false);
  const auto unread_before = bodies();
  start(file, false);
  Check(bodies() == unread_before + 1 &&
            state(record(LastOf(NativeProbeType::kRequestBody))) ==
                reb::RequestBodyState::kNotCapturedBodyKind &&
            reads.empty(),
        "A body never handed to the reader is recorded as described, not read");
  Configure();

  // Refusals before any read keep the record immediate.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  reb::NativeRequestBodyReader::refuse = true;
  start(file);
  reb::NativeRequestBodyReader::refuse = false;
  Check(state(record(LastOf(NativeProbeType::kRequestBody))) ==
                reb::RequestBodyState::kNotCapturedTransferRefused &&
            transfers.empty(),
        "A reader that cannot start is named");
  NativeArtifactSocketClient::Get().connected = false;
  start(file);
  NativeArtifactSocketClient::Get().connected = true;
  Check(state(record(LastOf(NativeProbeType::kRequestBody))) ==
            reb::RequestBodyState::kNotCapturedArtifactUnavailable,
        "Without the artifact channel the record says so at once");
  auto unknown = upload(network::DataElement());
  start(unknown);
  Check(state(record(LastOf(NativeProbeType::kRequestBody))) ==
                reb::RequestBodyState::kNotCapturedBodyKind &&
            reads.empty(),
        "A part the browser cannot identify is described, not read");

  // The writer reports a stream it lost once, whenever it notices, and later
  // frames for it are dropped without a report. That report must reach the record.
  const auto newest_stream = [&] { return std::ranges::max(transfers | std::views::keys); };
  const auto failures = [] {
    return std::ranges::count_if(events, [](const auto& e) {
      return e.header.type == NativeProbeType::kArtifactCaptureFailed;
    });
  };
  start(file);
  const std::uint64_t lost_stream = newest_stream();
  const auto failures_before_loss = failures();
  const auto bodies_before_loss = bodies();
  NativeArtifactCaptureSink::TransferCompleted(lost_stream,
                                               reb::NativeArtifactReceiveStatus::kIoError);
  Check(bodies() == bodies_before_loss && failures() == failures_before_loss,
        "A stream lost during its read waits for the read to end");
  reb::NativeRequestBodyReader::Finish(reads.size() - 1, fits, Read::kComplete, fits.size());
  const auto lost_event = LastOf(NativeProbeType::kRequestBody);
  const auto lost_record = record(lost_event);
  Check(state(lost_record) == reb::RequestBodyState::kNotCapturedTransferRefused &&
            lost_event.header.artifact_id == 0 && lost_record.captured_length == 0 &&
            (lost_record.flags & reb::kRequestBodyDigestPresent) == 0 &&
            reb::IsValidRequestBodyPayload(lost_record, false) &&
            !transfers.contains(lost_stream) && failures() == failures_before_loss,
        "A stream lost during its read is recorded refused, never captured");
  const auto events_after_lost = events.size();
  NativeArtifactCaptureSink::TransferCompleted(lost_stream,
                                               reb::NativeArtifactReceiveStatus::kIoError);
  Check(events.size() == events_after_lost, "The settled read leaves no pending entry behind");
  transfers.clear();

  // Lost after the record went out: that record already names the artifact, so
  // a failure parented to it is what corrects it.
  start(file);
  const std::uint64_t ended_stream = newest_stream();
  reb::NativeRequestBodyReader::Finish(reads.size() - 1, fits, Read::kComplete, fits.size());
  const auto ended = LastOf(NativeProbeType::kRequestBody);
  Check(ended.header.artifact_id == ended_stream &&
            state(record(ended)) == reb::RequestBodyState::kCaptured,
        "A read whose stream is still open records its artifact");
  const auto failures_after_end = failures();
  NativeArtifactCaptureSink::TransferCompleted(ended_stream,
                                               reb::NativeArtifactReceiveStatus::kIoError);
  Check(failures() == failures_after_end + 1 &&
            events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            events.back().header.parent_event_id == ended.header.sequence_number &&
            events.back().header.artifact_id == ended_stream,
        "A stream lost after its read ended is a failure joined to the record");
  const auto events_after_failure = events.size();
  NativeArtifactCaptureSink::TransferCompleted(ended_stream,
                                               reb::NativeArtifactReceiveStatus::kAccepted);
  Check(events.size() == events_after_failure, "A loss is reported for its stream once");
  transfers.clear();

  // A file part its renderer may not read is never opened, and the record says
  // the read did not complete.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  reb::NativeRequestBodyReader::refuse_files = true;
  const auto reads_before_refusal = reads.size();
  start(file);
  reb::NativeRequestBodyReader::refuse_files = false;
  const auto refused_file = LastOf(NativeProbeType::kRequestBody);
  const auto refused_file_record = record(refused_file);
  Check(state(refused_file_record) == reb::RequestBodyState::kNotCapturedReadIncomplete &&
            refused_file.header.artifact_id == 0 && reads.size() == reads_before_refusal &&
            transfers.empty() && (refused_file_record.flags & reb::kRequestBodyRead) != 0 &&
            (refused_file_record.flags & reb::kRequestBodyLengthPartial) != 0 &&
            reb::IsValidRequestBodyPayload(refused_file_record, false),
        "A file part the renderer may not read is not read and the record says so");

  // A receiver without --allow-sensitive refuses the stream after its record.
  configure(reb::kNativeRequestContentDefaultBudgetBytes);
  start(file);
  reb::NativeRequestBodyReader::Finish(reads.size() - 1, fits, Read::kComplete, fits.size());
  const auto refused_record = LastOf(NativeProbeType::kRequestBody);
  reb::ArtifactReceiver refusing(
      output / "refusing-read-body-receiver",
      {.max_artifact_bytes = 1024 * 1024, .max_store_bytes = 1024 * 1024});
  Receive(refusing, refused_record.header.artifact_id, true,
          reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled);
  Check(events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            events.back().header.parent_event_id == refused_record.header.sequence_number,
        "The receiver's refusal of a read body joins its record");
  Configure();
  transfers.clear();
  reads.clear();
  Check(sink.in_flight_bytes() == 0, "No read leaves a pool share behind");
  std::cout << "PASS read request bodies: 16 MiB prefix with exact length, budget allowance and "
               "refund, incomplete and empty reads, capture end, missing hook, refusals and "
               "receiver refusal joined to the deferred record\n";
}

void RequestBodyPolicy(const std::filesystem::path& output) {
  record_corpus = false;
  Configure();
  auto& network = reb::NativeNetworkCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  network::ResourceRequest request;
  request.method = "POST";
  request.url = GURL("https://api.hcaptcha.test/checkcaptcha/site/key");
  request.headers.SetHeader("Content-Type", "application/x-www-form-urlencoded");
  request.request_body = BodyOf("answers=1");
  // Metadata-only configuration: no target record and no bytes leave the browser.
  const auto before = events.size();
  network.RecordRequestStarted(501, 0, 0, 1, kFrame, 11, 12, request);
  Check(transfers.empty() && events.size() == before + 2 &&
            BodyPayload(events.back()).state ==
                static_cast<std::uint8_t>(reb::RequestBodyState::kMetadataOnly),
        "Metadata-only session records digest, length and type but no body or target");
  // A receiver without --allow-sensitive refuses the bytes; the refusal is an event.
  network.SetEmitter(Emit, kSession, kMask, 200, true);
  network.RecordRequestStarted(502, 0, 0, 1, kFrame, 11, 12, request);
  base::ThreadPool::RunPending();
  const auto& record = LastOf(NativeProbeType::kRequestBody);
  const auto body_sequence = record.header.sequence_number;
  reb::ArtifactReceiver refusing(
      output / "refusing-request-body-receiver",
      {.max_artifact_bytes = 1024 * 1024, .max_store_bytes = 1024 * 1024});
  Receive(refusing, record.header.artifact_id, true,
          reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled);
  Check(events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            Payload(events.back()) == "sensitive_capture_disabled" &&
            events.back().header.parent_event_id == body_sequence &&
            events.back().header.request_id == 502,
        "Receiver refusal of request content is explicit and joined to the body record");
  const auto header_sequence = LastOf(NativeProbeType::kRequestHeaders).header.sequence_number;
  Receive(refusing, LastOf(NativeProbeType::kRequestHeaders).header.artifact_id, true,
          reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled);
  Check(events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            events.back().header.parent_event_id == header_sequence,
        "Receiver refusal of a header block is joined to its header record");
  // Artifact category off: the body record says the channel was unavailable.
  Configure(kSession, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork));
  network.SetEmitter(Emit, kSession,
                     reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork), 200, true);
  network.RecordRequestStarted(503, 0, 0, 1, kFrame, 11, 12, request);
  Check(transfers.empty() &&
            BodyPayload(LastOf(NativeProbeType::kRequestBody)).state ==
                static_cast<std::uint8_t>(reb::RequestBodyState::kNotCapturedArtifactUnavailable),
        "Content session without the artifact category names the missing channel");
  Configure();
  std::cout << "PASS request body policy: metadata-only, receiver sensitive refusal and missing "
               "artifact channel are explicit\n";
  RequestContentLimits();
  ReadRequestBodies(output);
}

#include "response_bodies_test.h"

void Corpus(reb::ArtifactReceiver& receiver, const std::filesystem::path& output) {
  Configure();
  std::vector<Case> cases;
  const auto exact = Start(101);
  const auto exact_id = Finish(Begin(exact));
  Check(NativeArtifactSocketClient::Get().transfers.at(exact_id)->header.creator_event_id ==
            exact.response,
        "Artifact header preserves actual response creator sequence");
  const auto before_ack = events.size();
  Receive(receiver, exact_id);
  Check(events.size() == before_ack + 1, "Success is emitted only after receiver ACK");
  CheckCapture(exact_id, exact.response, exact.id);
  cases.push_back({"exact", exact, {exact_id}});

  const auto no_ack = Start(102);
  const auto no_ack_id = Finish(Begin(no_ack));
  const auto before_missing_ack = events.size();
  Receive(receiver, no_ack_id, false);
  Check(events.size() == before_missing_ack,
        "Stored artifact without delivered ACK has no success event");
  cases.push_back({"no_ack", no_ack, {}});

  const auto missing_creator = Start(103);
  const auto missing_id = Finish(Begin(missing_creator, false));
  Receive(receiver, missing_id);
  CheckCapture(missing_id, 0, missing_creator.id);
  cases.push_back({"missing_creator", missing_creator, {}});

  const auto generated = Start(104);
  const auto generated_id = NativeArtifactCaptureSink::Get().CaptureGeneratedArtifact(
      reb::NativeArtifactKind::kJavaScript, reb::NativeArtifactCaptureOrigin::kDynamicJavaScript,
      generated.response, 71, kFrame, "https://fixture.test/stack.js",
      mojo_base::BigBuffer(source));
  Receive(receiver, generated_id);
  CheckCapture(generated_id, 0, 0);
  cases.push_back({"generated", generated, {}});

  const auto runtime = Start(105);
  std::vector<std::uint8_t> initialized(32, 0);
  initialized[0] = 1;
  initialized[1] = 7;
  NativeArtifactCaptureSink::Get().CaptureRuntimeTypedArray(
      42, kSession, 22, false, runtime.response, 71, kFrame, "https://fixture.test/stack.js",
      mojo_base::BigBuffer(source), mojo_base::BigBuffer(initialized));
  while (!NativeArtifactSocketClient::Get().transfers.empty()) {
    const auto id = NativeArtifactSocketClient::Get().transfers.begin()->first;
    Receive(receiver, id);
    CheckCapture(id, 0, 0);
  }
  cases.push_back({"runtime", runtime, {}});

  const auto ambiguous_a = Start(106, 11);
  const auto ambiguous_b = Start(106, 21);
  const auto ambiguous_id = Finish(Begin(ambiguous_a));
  Receive(receiver, ambiguous_id);
  CheckCapture(ambiguous_id, ambiguous_a.response, ambiguous_a.id);
  cases.push_back({"ambiguous_a", ambiguous_a, {}});
  cases.push_back({"ambiguous_b", ambiguous_b, {}});

  const auto first = Start(107);
  const auto second = Start(108);
  const int first_pipe = Begin(first);
  const int second_pipe = Begin(second);
  const auto second_id = Finish(second_pipe);
  const auto first_id = Finish(first_pipe);
  // Body completion order differs from admission, and ACK order differs from body order.
  Receive(receiver, first_id);
  CheckCapture(first_id, first.response, first.id);
  Receive(receiver, second_id);
  CheckCapture(second_id, second.response, second.id);
  cases.push_back({"out_of_order_a", first, {first_id}});
  cases.push_back({"out_of_order_b", second, {second_id}});
  WriteCases(output, cases);
  RequestBodies(receiver, output);
  ResponseBodies(receiver, output);
  record_corpus = false;
  std::cout << "PASS actual sinks/receiver ACK: exact, missing ACK/creator, generated/runtime, "
               "BrowserContext request reuse, out-of-order body and ACK; uint64 roots > 2^53\n";
}
void Lifecycle(reb::ArtifactReceiver& receiver) {
  for (const bool same_session : {false, true}) {
    Configure();
    const auto request = Start(201);
    const int pipe = Begin(request);
    Configure(same_session ? kSession : kSession + 1);
    const auto event_count = events.size();
    Check(Finish(pipe) == 0 && events.size() == event_count,
          "Stale body after emitter reconfiguration cannot enqueue or emit under new generation");

    Configure();
    const auto ack_request = Start(202);
    const auto id = Finish(Begin(ack_request));
    const auto ack = Receive(receiver, id, false);
    Configure(same_session ? kSession : kSession + 1);
    const auto count = events.size();
    NativeArtifactCaptureSink::TransferCompleted(ack.artifact_id, ack.status);
    Check(events.size() == count, "Stale receiver ACK cannot cross emitter generation");
  }
  Configure();
  const auto request = Start(203);
  const int body = Begin(request);
  const auto queued = Finish(Begin(request));
  const auto ack = Receive(receiver, queued, false);
  NativeArtifactCaptureSink::Get().SetEmitter(nullptr, 0, 0, 0);
  Configure();
  const auto count = events.size();
  Check(Finish(body) == 0, "Disabled/re-enabled body is stale even for same session");
  NativeArtifactCaptureSink::TransferCompleted(ack.artifact_id, ack.status);
  Check(events.size() == count, "Disabled/re-enabled ACK cannot create success");

  Configure();
  const int expired_body = Begin(request);
  const auto expired_id = Finish(Begin(request));
  const auto expired_ack = Receive(receiver, expired_id, false);
  const auto before_expiry = events.size();
  base::test_now_ns = 200;
  Check(Finish(expired_body) == 0, "Expired body must not enqueue");
  NativeArtifactCaptureSink::TransferCompleted(expired_ack.artifact_id, expired_ack.status);
  Check(events.size() == before_expiry, "Expiry suppresses body and ACK events");
  std::cout << "PASS same/different-session stale bodies and ACKs, disable/re-enable and expiry\n";
}
// Delivers what a stream has queued so far, as the writer would while the
// body is still open, so those frames return their pool share.
void Drain(reb::ArtifactReceiver& receiver, const std::uint64_t id) {
  auto& stream = *NativeArtifactSocketClient::Get().transfers.at(id);
  for (; stream.delivered < stream.frames.size(); ++stream.delivered) {
    Check(ReceiveFrame(receiver, Wire(*stream.frames[stream.delivered])).status ==
              reb::ArtifactReceiveStatus::kAccepted,
          "A drained stream frame is accepted");
    stream.frames[stream.delivered]->reservation.Reset();
  }
}

// The pool bounds bytes in flight, never bodies: a stream holds at most its
// pending chunk plus frames the writer has not sent.
void InFlightPool(NativeArtifactCaptureSink& sink,
                  NativeArtifactSocketClient& client,
                  const std::filesystem::path& output) {
  constexpr std::size_t kMiB = 1024U * 1024U;
  constexpr std::size_t kChunk = reb::kNativeArtifactStreamChunkBytes;
  const Request request{301, 0, 9};
  reb::ArtifactReceiver receiver(
      output / "in-flight-receiver",
      {.max_artifact_bytes = reb::kNativeArtifactMaxContentBytes, .max_store_bytes = 64U * kMiB});
  std::vector<int> parallel;
  for (int index = 0; index < 40; ++index) {
    parallel.push_back(Begin(request));
  }
  Check(NativeArtifactBodyTee::pending.size() == 40 && sink.in_flight_bytes() == 0,
        "40 parallel responses are open and hold nothing before their bytes");
  for (const int pipe : parallel) {
    NativeArtifactBodyTee::Deliver(pipe, std::span(source).first(100));
  }
  Check(sink.in_flight_bytes() == 40 * 100, "Each holds exactly the bytes it has");
  std::vector<std::uint64_t> parallel_ids;
  for (const int pipe : parallel) {
    parallel_ids.push_back(Finish(pipe, true, std::span(source).subspan(100)));
  }
  Check(std::ranges::none_of(parallel_ids, [](std::uint64_t id) { return id == 0; }) &&
            sink.in_flight_bytes() == 40 * source.size(),
        "All 40 are streamed, each frame holding exactly its bytes until written");
  for (const auto id : parallel_ids) {
    Receive(receiver, id);
    CheckCapture(id, request.response, request.id);
  }
  Check(sink.in_flight_bytes() == 0, "Written frames return their share");

  // A 3 MiB body streams through one chunk at a time once the writer drains.
  std::vector<std::uint8_t> grown(3 * kMiB + 17);
  for (std::size_t index = 0; index < grown.size(); ++index) {
    grown[index] = static_cast<std::uint8_t>(index * 31U);
  }
  const int growing = Begin(request);
  const auto growing_id = client.transfers.rbegin()->first;
  std::size_t peak = 0;
  for (std::size_t offset = 0; offset < grown.size(); offset += kChunk) {
    NativeArtifactBodyTee::Deliver(
        growing, std::span(grown).subspan(offset, std::min(kChunk, grown.size() - offset)));
    peak = std::max(peak, sink.in_flight_bytes());
    Drain(receiver, growing_id);
  }
  Check(peak <= kChunk && sink.in_flight_bytes() < kChunk,
        "An open body never holds more than one chunk once its frames are written");
  const auto grown_id = Finish(growing, true, {});
  Check(grown_id == growing_id && client.transfers.at(grown_id)->content == grown,
        "The streamed body keeps exactly its bytes");
  Receive(receiver, grown_id);
  CheckCapture(grown_id, request.response, request.id);

  // A declared length reserves nothing; a full pool refuses the next chunk.
  network::mojom::URLResponseHead head;
  head.content_length = static_cast<std::int64_t>(reb::kNativeArtifactMaxContentBytes);
  const int declared = Begin(request, true, {}, head);
  Check(sink.in_flight_bytes() == 0, "A declared 16 MiB body holds nothing yet");
  {
    auto held = reb::NativeArtifactReservation::Acquire(
        sink.memory_pool(), reb::kNativeArtifactInFlightBytes - kChunk / 2);
    const auto queued = client.transfers.size();
    Check(Finish(declared, true, std::span(source)) != 0, "A small body still fits");
    const int starved = Begin(request);
    const std::vector<std::uint8_t> quarter(256 * 1024, 'q');
    Check(Finish(starved, true, quarter) == 0 && Payload(events.back()) == "active_memory_limit" &&
              client.transfers.size() == queued,
          "A body the pool cannot take is refused and aborted, not truncated");
  }
  client.transfers.clear();
  Check(sink.in_flight_bytes() == 0, "Refused and dropped streams return their share");
  const int stale = Begin(request);
  NativeArtifactBodyTee::Deliver(stale, source);
  Configure();
  Check(Finish(stale) == 0 && sink.in_flight_bytes() == 0 && client.transfers.empty(),
        "A stale stream is aborted and returns its share after reconfiguration");

  const std::vector<std::uint8_t> oversized(reb::kNativeArtifactMaxContentBytes + 1, 'o');
  Check(Finish(Begin(request), true, oversized) == 0 &&
            Payload(events.back()) == "body_too_large" && client.transfers.empty(),
        "A body past 16 MiB is refused as too large");
  client.transfers.clear();
  Check(sink.in_flight_bytes() == 0, "No share is left");
  std::cout << "PASS in-flight pool: 40 parallel streams, one chunk held per open body once "
               "written, declared lengths reserve nothing, full-pool refusal, stale abort, size "
               "bound\n";
}

void Admission(const std::filesystem::path& output) {
  Configure();
  const Request request{301, 0, 9};
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& client = NativeArtifactSocketClient::Get();
  const auto no_admission = [&](const std::string& reason, const auto& action) {
    const auto queued = client.transfers.size();
    const auto pending = NativeArtifactBodyTee::pending.size();
    action();
    Check(client.transfers.size() == queued && NativeArtifactBodyTee::pending.size() == pending,
          reason);
  };
  sink.SetEmitter(nullptr, 0, 0, 0);
  auto reads = base::test_clock_reads;
  no_admission("Disabled path cannot allocate a tee", [&] { Begin(request); });
  Check(base::test_clock_reads == reads, "Disabled artifact path avoids reading the clock");
  Configure(kSession, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork));
  no_admission("Category gate", [&] { Begin(request); });
  Configure();
  client.connected = false;
  no_admission("Disconnected gate", [&] { Begin(request); });
  client.connected = true;
  no_admission("Invalid body gate", [&] {
    Check(!sink.MaybeCaptureResponse(301, kFrame, 9, {}, {}, {}).is_valid(),
          "Invalid handle unchanged");
  });
  network::ResourceRequest unknown;
  unknown.resource_type = 1;
  network::mojom::URLResponseHead head;
  head.mime_type = "image/png";
  no_admission("Unclassified response gate", [&] { Begin(request, true, unknown, head); });
  head.mime_type = "text/javascript";
  head.content_length = static_cast<std::int64_t>(reb::kNativeArtifactMaxContentBytes) + 1;
  no_admission("Declared size bound", [&] { Begin(request, true, {}, head); });
  Check(Payload(events.back()) == "declared_size_limit", "Oversize failure is visible");
  head.content_length = 0;
  unknown.url = GURL(std::string(reb::kNativeArtifactMaxUrlBytes + 1, 'x'));
  no_admission("URL metadata bound", [&] { Begin(request, true, unknown, head); });
  Check(Payload(events.back()) == "metadata_limit", "Metadata failure is visible");
  NativeArtifactBodyTee::unavailable = true;
  no_admission("Mojo tee creation failure", [&] { Begin(request); });
  Check(Payload(events.back()) == "tee_unavailable", "Tee failure is visible");
  NativeArtifactBodyTee::unavailable = false;
  Check(Finish(Begin(request), false) == 0 && Payload(events.back()) == "body_incomplete",
        "Incomplete body never enqueues");
  client.reject_next = true;
  no_admission("Queue rejection of the open header", [&] { Begin(request); });
  Check(Payload(events.back()) == "transfer_queue_full_or_disconnected",
        "Queue rejection is visible");
  const int refused_data = Begin(request);
  client.reject_next = true;
  Check(Finish(refused_data) == 0 &&
            Payload(events.back()) == "transfer_queue_full_or_disconnected" &&
            client.transfers.empty(),
        "A refused data frame aborts its stream visibly");
  Check(sink.in_flight_bytes() == 0, "Failed and refused bodies return their pool share");
  InFlightPool(sink, client, output);
  const std::vector<std::uint8_t> empty;
  Check(sink.CaptureGeneratedArtifact(reb::NativeArtifactKind::kJavaScript,
                                      reb::NativeArtifactCaptureOrigin::kDynamicJavaScript, 9, 1,
                                      kFrame, "fixture://source", mojo_base::BigBuffer(empty)) == 0,
        "Generated empty input rejected");
  const std::vector<std::uint8_t> too_short(31, 0);
  Check(sink.CaptureGeneratedArtifact(reb::NativeArtifactKind::kBytecodeBuffer,
                                      reb::NativeArtifactCaptureOrigin::kRuntimeTypedArray, 9, 1,
                                      kFrame, "fixture://source", mojo_base::BigBuffer(too_short),
                                      1) == 0,
        "Runtime snapshot minimum enforced");

  // A real receiver rejects this otherwise admitted body by its configured size limit.
  reb::ArtifactReceiver rejecting(output / "rejecting-receiver",
                                  {.max_artifact_bytes = 1, .max_store_bytes = 1024});
  const auto rejected = Finish(Begin(request));
  Receive(rejecting, rejected, true, reb::ArtifactReceiveStatus::kTooLarge);
  Check(events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            Payload(events.back()) == "too_large",
        "Real negative ACK yields failure, not exact success");
  const auto event_count = events.size();
  NativeArtifactCaptureSink::TransferCompleted(rejected,
                                               reb::NativeArtifactReceiveStatus::kAccepted);
  Check(events.size() == event_count, "Duplicate/unknown ACK cannot upgrade a failed transfer");
  Check(NativeArtifactBodyTee::pending.empty() && client.transfers.empty(),
        "No pending adapter work");
  std::cout << "PASS disabled/category/disconnected admission, metadata/size/memory bounds, "
               "incomplete body, tee/queue failures, real receiver rejection and duplicate ACK\n";
}
void NativeWasmDispatch(reb::ArtifactReceiver& receiver) {
  record_corpus = false;
  Configure();
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const std::vector<std::uint8_t> module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 1, 0, 0};
  reb::NativeWasmDispatchObservation observation;
  observation.header.session_id = kSession;
  observation.header.frame_id = kFrame;
  observation.header.sequence_number = 999;
  observation.header.monotonic_time_ns = 99;
  observation.header.process_id = 123;
  observation.header.thread_id = 7;
  observation.execution_context_id = 81;
  observation.document_token_high = 72;
  observation.document_token_low = 73;
  observation.module_byte_offset = 8;
  observation.selector = 42;
  observation.table_count = 1;
  observation.source_url = "fixture://native-wasm";
  bool current = true;
  const auto count = [] {
    return std::count_if(events.begin(), events.end(), [](const auto& e) {
      return e.header.type == NativeProbeType::kWasmDispatchObservation;
    });
  };
  Check(sink.CaptureGeneratedArtifact(reb::NativeArtifactKind::kWasm,
                                      reb::NativeArtifactCaptureOrigin::kUnknown, 0, 81, kFrame,
                                      observation.source_url, mojo_base::BigBuffer(module)) == 0,
        "Generic unknown origin cannot bypass dedicated validation");
  const auto before = count();
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [&] { return current; });
  Check(transfers.size() == 1 && count() == before,
        "No dispatch record before module acknowledgement");
  const auto id = transfers.begin()->first;
  Receive(receiver, id);
  Check(count() == before + 1, "Accepted exact module emits typed dispatch");
  const auto found = std::find_if(events.rbegin(), events.rend(), [](const auto& e) {
    return e.header.type == NativeProbeType::kWasmDispatchObservation;
  });
  Check(found->header.artifact_id == id && found->header.sequence_number == 999 &&
            found->header.process_id == 123 && found->header.thread_id == 7 &&
            !found->header.navigation_id && !found->header.parent_event_id,
        "Runtime provenance preserved without guest or causal claims");
  reb::WasmDispatchObservationPayload payload;
  Check(reb::DecodeWasmDispatchObservationPayload(found->inline_payload, payload),
        "Payload decodes");
  Check(payload.selector == 42 && payload.module_byte_offset == 8 && payload.table_count == 1,
        "Explicit little endian physical dispatch fields retained");
  observation.header.sequence_number = 1000;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [&] { return current; });
  Check(transfers.empty() && count() == before + 2 && events.back().header.artifact_id == id,
        "Accepted module is reused, not transferred again, for the same document");
  observation.document_token_low = 74;
  observation.header.sequence_number = 1001;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [&] { return current; });
  Check(transfers.size() == 1, "Another document gets its own module artifact");
  current = false;
  Receive(receiver, transfers.begin()->first);
  Check(count() == before + 2, "Navigated document cannot emit delayed observation");
  Check(std::any_of(events.begin(), events.end(),
                    [](const auto& e) {
                      return e.header.type == NativeProbeType::kGap &&
                             e.header.sequence_number == 1001 && e.header.process_id == 123;
                    }),
        "Lost observation fills its own sequence slot with a gap");
  current = true;
  observation.document_token_low = 75;
  observation.header.sequence_number = 1002;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [&] { return current; });
  const auto retired = transfers.begin()->first;
  Configure();
  Receive(receiver, retired);
  Check(count() == before + 2, "Same session reconfiguration retires old acknowledgement");
  observation.table_count = 2;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.empty(), "Mismatched br_table immediate rejected");
  observation.table_count = 1;
  Configure();
  const auto before_budget = count();
  for (unsigned i = 0; i < 17; ++i) {
    observation.header.sequence_number = 2000 + i;
    sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  }
  Check(transfers.size() == 1, "Sixteen observations of one module share one artifact");
  Check(Payload(events.back()) == "native_wasm_dispatch_browser_budget_incomplete" &&
            events.back().header.sequence_number == 2016 && events.back().header.process_id == 123,
        "Cross-renderer browser budget fills the refused observation's own slot");
  const auto after_budget_gap = events.size();
  observation.header.sequence_number = 2017;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(events.size() == after_budget_gap + 1 && events.back().header.sequence_number == 2017,
        "Every observation past the browser budget fills its own slot");
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  Check(count() == before_budget + 16, "Every admitted observation is published after one ACK");
  Configure();
  NativeArtifactSocketClient::Get().connected = false;
  observation.header.sequence_number = 2100;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  NativeArtifactSocketClient::Get().connected = true;
  Check(transfers.empty() &&
            Payload(events.back()) == "native_wasm_dispatch_artifact_unavailable" &&
            events.back().header.sequence_number == 2100,
        "A lost artifact channel fills the observation's own slot");
  Configure(kSession, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kArtifact));
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.empty(), "Artifact permission alone cannot admit runtime observation");
  std::cout << "PASS native Wasm artifact ACK, physical typed payload, document/generation "
               "retirement and bounds\n";
}

void NativeWasmDirectCaller(reb::ArtifactReceiver& receiver) {
  using reb::WasmDirectCallerFrame;
  const WasmDirectCallerFrame direct_call[] = {{1, 1, true}, {1, 0, true}};
  const auto caller = reb::ResolveWasmDirectCaller(1, 2, direct_call);
  Check(caller.kind == reb::kWasmDirectCallerSameInstance && caller.function_index == 0,
        "Direct call from function 0 into function 1 names caller 0");
  const WasmDirectCallerFrame function_zero[] = {{1, 4, true}, {1, 0, true}};
  const auto zero = reb::ResolveWasmDirectCaller(1, 5, function_zero);
  Check(zero.kind == reb::kWasmDirectCallerSameInstance && zero.function_index == 0,
        "Function index 0 is a real caller, not the unknown sentinel");
  const WasmDirectCallerFrame host_call[] = {{1, 0, true}, {0, -1, false}};
  const auto host = reb::ResolveWasmDirectCaller(1, 2, host_call);
  Check(host.kind == reb::kWasmDirectCallerUnknown && host.function_index == 0,
        "A host frame is unknown rather than a guessed index");
  const WasmDirectCallerFrame host_between[] = {{1, 2, true}, {0, -1, false}, {1, 9, true}};
  const auto hidden = reb::ResolveWasmDirectCaller(1, 16, host_between);
  Check(hidden.kind == reb::kWasmDirectCallerUnknown && hidden.function_index == 0,
        "An older same-instance frame behind the host is not the caller");
  const WasmDirectCallerFrame foreign[] = {{1, 2, true}, {2, 9, true}};
  const auto other = reb::ResolveWasmDirectCaller(1, 16, foreign);
  Check(other.kind == reb::kWasmDirectCallerUnknown,
        "Another instance is not this module's caller");
  const WasmDirectCallerFrame tier[] = {{1, 2, true}, {1, 3, false}};
  Check(reb::ResolveWasmDirectCaller(1, 16, tier).kind == reb::kWasmDirectCallerUnknown,
        "A non-Liftoff caller is unknown");
  const WasmDirectCallerFrame past[] = {{1, 2, true}, {1, 16, true}};
  Check(reb::ResolveWasmDirectCaller(1, 16, past).kind == reb::kWasmDirectCallerUnknown,
        "An index past the module's function count is unknown");
  const WasmDirectCallerFrame instance_a[] = {{1, 1, true}, {1, 4, true}};
  const WasmDirectCallerFrame instance_b[] = {{2, 1, true}, {2, 7, true}};
  const auto a = reb::ResolveWasmDirectCaller(1, 8, instance_a);
  const auto b = reb::ResolveWasmDirectCaller(2, 8, instance_b);
  Check(a.kind == reb::kWasmDirectCallerSameInstance && a.function_index == 4 &&
            b.kind == reb::kWasmDirectCallerSameInstance && b.function_index == 7,
        "Two instances keep the caller from their own activation");
  const WasmDirectCallerFrame mixed[] = {{1, 1, true}, {2, 7, true}, {1, 4, true}};
  const auto interleaved = reb::ResolveWasmDirectCaller(1, 8, mixed);
  Check(interleaved.kind == reb::kWasmDirectCallerUnknown && interleaved.function_index == 0,
        "A foreign frame between two same-instance frames is not skipped");

  record_corpus = false;
  Configure();
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const std::vector<std::uint8_t> module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 1, 0, 0};
  reb::NativeWasmDispatchObservation observation;
  observation.header.session_id = kSession;
  observation.header.frame_id = kFrame;
  observation.header.sequence_number = 5000;
  observation.header.monotonic_time_ns = 99;
  observation.header.process_id = 123;
  observation.header.thread_id = 7;
  observation.execution_context_id = 81;
  observation.document_token_high = 72;
  observation.document_token_low = 90;
  observation.function_index = 1;
  observation.module_byte_offset = 8;
  observation.table_count = 1;
  observation.source_url = "fixture://native-wasm-caller";
  observation.caller_observed = true;
  observation.caller_kind = reb::kWasmDirectCallerSameInstance;
  observation.caller_function_index = 0;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.size() == 1, "Caller-bearing dispatch still transfers its module");
  Receive(receiver, transfers.begin()->first);
  const auto dispatch = [](std::uint64_t sequence) {
    return std::find_if(events.begin(), events.end(), [&](const auto& event) {
      return event.header.type == NativeProbeType::kWasmDispatchObservation &&
             event.header.sequence_number == sequence;
    });
  };
  const auto same = dispatch(5000);
  Check(same != events.end() && !same->header.parent_event_id,
        "Direct caller is not a parent event");
  reb::WasmDispatchObservationPayload payload;
  Check(reb::DecodeWasmDispatchObservationPayload(same->inline_payload, payload),
        "Same-instance caller payload decodes");
  Check(payload.protocol_version == 3 && payload.function_index == 1 &&
            payload.caller_kind == reb::kWasmDirectCallerSameInstance &&
            payload.caller_function_index == 0,
        "Function B's br_table names direct caller A, including function index 0");
  observation.header.sequence_number = 5001;
  observation.caller_kind = reb::kWasmDirectCallerUnknown;
  observation.caller_function_index = 0;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  const auto unknown = dispatch(5001);
  Check(unknown != events.end() &&
            reb::DecodeWasmDispatchObservationPayload(unknown->inline_payload, payload) &&
            payload.protocol_version == 3 && payload.caller_kind == reb::kWasmDirectCallerUnknown &&
            payload.caller_function_index == 0 && payload.function_index == 1,
        "A host caller stays unknown and does not reuse the previous function index");
  observation.header.sequence_number = 5002;
  observation.caller_function_index = 9;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(dispatch(5002) == events.end() &&
            Payload(events.back()) == "native_wasm_dispatch_module_invalid" &&
            events.back().header.sequence_number == 5002,
        "Unknown with a guessed index is a gap, not function 9");
  observation.header.sequence_number = 5003;
  observation.caller_observed = false;
  observation.caller_kind = reb::kWasmDirectCallerUnknown;
  observation.caller_function_index = 0;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  const auto unwalked = dispatch(5003);
  Check(unwalked != events.end() &&
            reb::DecodeWasmDispatchObservationPayload(unwalked->inline_payload, payload) &&
            payload.protocol_version == 2 && payload.caller_kind == 0 &&
            payload.caller_function_index == 0,
        "An unwalked record stays version 2 and is not a host caller");
  std::cout << "PASS direct-call caller on br_table, host unknown, and separate instance walks\n";
}

void NativeWasmIndirect(reb::ArtifactReceiver& receiver) {
  record_corpus = false;
  Configure();
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  // br_table with one arm at 8, then call_indirect type 0 table 0 at 12.
  const std::vector<std::uint8_t> module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 1, 0, 0, 0x11, 0, 0};
  reb::NativeWasmIndirectObservation observation;
  observation.header.session_id = kSession;
  observation.header.frame_id = kFrame;
  observation.header.sequence_number = 3000;
  observation.header.monotonic_time_ns = 99;
  observation.header.process_id = 123;
  observation.header.thread_id = 7;
  observation.execution_context_id = 81;
  observation.document_token_high = 72;
  observation.document_token_low = 73;
  observation.function_index = 1;
  observation.module_byte_offset = 12;
  observation.slot = 3;
  observation.callee_function_index = 2;
  observation.resolution = reb::NativeWasmIndirectResolution::kResolved;
  observation.source_url = "fixture://native-wasm-indirect";
  reb::NativeWasmDispatchObservation physical;
  physical.header = observation.header;
  physical.header.sequence_number = 3001;
  physical.execution_context_id = 81;
  physical.document_token_high = 72;
  physical.document_token_low = 73;
  physical.module_byte_offset = 8;
  physical.table_count = 1;
  physical.source_url = observation.source_url;
  bool current = true;
  const auto count = [](NativeProbeType type) {
    return std::count_if(events.begin(), events.end(),
                         [type](const auto& e) { return e.header.type == type; });
  };
  const auto indirect = [&] { return count(NativeProbeType::kWasmIndirectObservation); };
  const auto before = indirect();
  const auto before_physical = count(NativeProbeType::kWasmDispatchObservation);
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [&] { return current; });
  Check(transfers.size() == 1 && indirect() == before,
        "No call_indirect record before module acknowledgement");
  sink.CaptureWasmDispatch(physical, mojo_base::BigBuffer(module), [&] { return current; });
  Check(transfers.size() == 1, "br_table and call_indirect share one module artifact");
  const auto id = transfers.begin()->first;
  Receive(receiver, id);
  Check(indirect() == before + 1 &&
            count(NativeProbeType::kWasmDispatchObservation) == before_physical + 1,
        "Accepted module publishes both physical streams");
  const auto found = std::find_if(events.rbegin(), events.rend(), [](const auto& e) {
    return e.header.type == NativeProbeType::kWasmIndirectObservation;
  });
  Check(found->header.artifact_id == id && found->header.sequence_number == 3000 &&
            found->header.category == reb::NativeProbeCategory::kVm &&
            !found->header.navigation_id && !found->header.parent_event_id,
        "call_indirect provenance preserved without causal claims");
  reb::WasmIndirectObservationPayload payload;
  Check(reb::DecodeWasmIndirectObservationPayload(found->inline_payload, payload),
        "Indirect payload decodes");
  Check(payload.protocol_version == 2 && payload.function_index == 1 &&
            payload.module_byte_offset == 12 && payload.table_index == 0 && payload.slot == 3 &&
            payload.callee_function_index == 2 && payload.resolution == 0 &&
            payload.sample_index == 0,
        "Explicit little endian call_indirect fields retained");
  Check(reb::IsValidWasmIndirectObservation(std::bit_cast<reb::EventRecord>(*found)),
        "Broker accepts the produced record");
  observation.header.sequence_number = 3002;
  observation.table_index = 1;
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.empty() && Payload(events.back()) == "native_wasm_indirect_module_invalid",
        "Mismatched table immediate is an explicit omission");
  observation.table_index = 0;
  observation.document_token_low = 74;
  observation.header.sequence_number = 3003;
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [&] { return current; });
  Check(transfers.size() == 1, "Another document gets its own module artifact");
  current = false;
  Receive(receiver, transfers.begin()->first);
  Check(std::any_of(events.begin(), events.end(),
                    [](const auto& e) {
                      return e.header.type == NativeProbeType::kGap &&
                             e.header.sequence_number == 3003 && e.header.process_id == 123;
                    }),
        "A navigated document's observation fills its sequence slot with a gap");
  current = true;
  observation.document_token_low = 73;
  Configure();
  const auto before_budget = indirect();
  for (unsigned i = 0; i < 17; ++i) {
    observation.header.sequence_number = 4000 + i;
    sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  }
  Check(transfers.size() == 1, "Sixteen observations of one module share one artifact");
  Check(Payload(events.back()) == "native_wasm_indirect_browser_budget_incomplete" &&
            events.back().header.sequence_number == 4016,
        "The browser call_indirect budget fills the refused observation's own slot");
  const auto after_budget_gap = events.size();
  observation.header.sequence_number = 4017;
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(events.size() == after_budget_gap + 1 && events.back().header.sequence_number == 4017,
        "Every observation past the budget fills its own slot");
  physical.header.sequence_number = 4100;
  sink.CaptureWasmDispatch(physical, mojo_base::BigBuffer(module), [] { return true; });
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  Check(indirect() == before_budget + 16, "Every admitted observation is published after one ACK");
  Check(std::any_of(events.begin(), events.end(),
                    [](const auto& e) {
                      return e.header.type == NativeProbeType::kWasmDispatchObservation &&
                             e.header.sequence_number == 4100;
                    }),
        "An exhausted call_indirect budget leaves br_table observation open");
  // A record still waiting for its module ACK becomes a gap before expiry.
  auto& runner = *base::SequencedTaskRunner::GetCurrentDefault();
  runner.tasks.clear();
  Configure();
  observation.header.sequence_number = 4200;
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.size() == 1 && runner.tasks.size() == 1, "Pending record and flush scheduled");
  runner.tasks.back().second();
  Check(std::any_of(events.begin(), events.end(),
                    [](const auto& e) {
                      return e.header.type == NativeProbeType::kGap &&
                             e.header.sequence_number == 4200 &&
                             Payload(e) == "native_wasm_dispatch_pending_at_expiry";
                    }),
        "A held call_indirect record is an explicit gap at expiry");
  Receive(receiver, transfers.begin()->first);
  observation.header.sequence_number = 4201;
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.empty() &&
            events.back().header.type == NativeProbeType::kWasmIndirectObservation &&
            events.back().header.sequence_number == 4201,
        "A module accepted after its observations were flushed is reused, not resent");
  runner.tasks.clear();
  transfers.clear();
  Configure(kSession, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kArtifact));
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.empty(), "Artifact permission alone cannot admit call_indirect observation");
  // Canvas images follow the session's opt-in, whatever the renderer sends.
  Configure(kSession, kMask);
  const std::string image = "data:image/png;base64,AAAA";
  const auto canvas = [&] {
    return sink.CaptureGeneratedArtifact(
        reb::NativeArtifactKind::kCanvasDataUrl, reb::NativeArtifactCaptureOrigin::kCanvasToDataUrl,
        5, 0, kFrame, "canvas://readback",
        mojo_base::BigBuffer(
            std::span(reinterpret_cast<const std::uint8_t*>(image.data()), image.size())));
  };
  Check(canvas() == 0 && transfers.empty() &&
            Payload(events.back()) == "canvas_image_capture_disabled",
        "A Canvas image without the session opt-in is refused explicitly");
  reb::NativeProbeSession::Get().canvas_images = true;
  Check(canvas() != 0 && transfers.size() == 1, "A Canvas image with the session opt-in is kept");
  reb::NativeProbeSession::Get().canvas_images = false;
  transfers.clear();
  std::cout << "PASS native Wasm call_indirect artifact ACK, shared module artifact, typed "
               "payload, document retirement, pre-expiry flush and separate budget\n";
}

void NativeWasmSampleBudget(reb::ArtifactReceiver& receiver) {
  record_corpus = false;
  Configure();
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const std::vector<std::uint8_t> allowed{0,    97, 115,  109, 1, 0,    0, 0,
                                          0x0e, 2,  0x11, 0,   0, 0x11, 0, 0};
  auto blocked = allowed;
  blocked.push_back(0x7f);
  reb::NativeWasmSampleBudgetPolicy policy;
  policy.samples_per_function = 2;
  policy.module_allow_count = 1;
  policy.module_allow[0] = reb::NativeGuestDigest(allowed);
  sink.SetWasmSampleBudgetPolicy(policy);
  reb::NativeWasmDispatchObservation dispatch;
  dispatch.header.session_id = kSession;
  dispatch.header.frame_id = kFrame;
  dispatch.header.monotonic_time_ns = 99;
  dispatch.header.process_id = 123;
  dispatch.header.thread_id = 7;
  dispatch.execution_context_id = 81;
  dispatch.document_token_high = 72;
  dispatch.document_token_low = 73;
  dispatch.module_byte_offset = 8;
  dispatch.table_count = 2;
  dispatch.selector = 1;
  dispatch.source_url = "fixture://wasm-budget";
  reb::NativeWasmIndirectObservation indirect;
  indirect.header = dispatch.header;
  indirect.execution_context_id = dispatch.execution_context_id;
  indirect.document_token_high = dispatch.document_token_high;
  indirect.document_token_low = dispatch.document_token_low;
  indirect.module_byte_offset = 10;
  indirect.resolution = reb::NativeWasmIndirectResolution::kOutOfBounds;
  indirect.source_url = dispatch.source_url;
  const auto observations = [](NativeProbeType type) {
    return std::count_if(events.begin(), events.end(),
                         [type](const auto& event) { return event.header.type == type; });
  };
  const auto dispatch_count = [&] {
    return observations(NativeProbeType::kWasmDispatchObservation);
  };
  const auto indirect_count = [&] {
    return observations(NativeProbeType::kWasmIndirectObservation);
  };
  const auto before_dispatch = dispatch_count();
  const auto before_indirect = indirect_count();
  dispatch.header.sequence_number = 6000;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(blocked), [] { return true; });
  Check(transfers.empty() && Payload(events.back()) == "native_wasm_dispatch_browser_filtered",
        "A module outside the allowlist does not transfer or take a br_table slot");
  indirect.header.sequence_number = 6001;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(blocked), [] { return true; });
  Check(transfers.empty() && Payload(events.back()) == "native_wasm_indirect_browser_filtered",
        "A module outside the allowlist does not take a call_indirect slot");
  dispatch.header.sequence_number = 6002;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(transfers.size() == 1, "The allowed module transfers once");
  Receive(receiver, transfers.begin()->first);
  Check(dispatch_count() == before_dispatch + 1, "First sample of a function is retained");
  dispatch.header.sequence_number = 6003;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(transfers.empty() && dispatch_count() == before_dispatch + 2,
        "Second sample of that function is retained");
  dispatch.header.sequence_number = 6004;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(dispatch_count() == before_dispatch + 2 &&
            Payload(events.back()) == "native_wasm_dispatch_browser_function_budget_incomplete",
        "A later sample of that function is a per-function gap");
  dispatch.function_index = 1;
  dispatch.header.sequence_number = 6005;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(transfers.empty() && dispatch_count() == before_dispatch + 3,
        "A different function continues to be recorded");
  indirect.header.sequence_number = 6006;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(allowed), [] { return true; });
  indirect.header.sequence_number = 6007;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(indirect_count() == before_indirect + 2,
        "The br_table per-function cap does not consume the call_indirect budget");
  indirect.header.sequence_number = 6008;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(indirect_count() == before_indirect + 2 &&
            Payload(events.back()) == "native_wasm_indirect_browser_function_budget_incomplete",
        "call_indirect keeps its own per-function cap");
  dispatch.function_index = 2;
  dispatch.header.sequence_number = 6009;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(dispatch_count() == before_dispatch + 4,
        "A full call_indirect per-function cap leaves br_table recording");

  Configure();
  policy.samples_per_function = 0;
  sink.SetWasmSampleBudgetPolicy(policy);
  const auto reset_dispatch = dispatch_count();
  const auto reset_indirect = indirect_count();
  dispatch.function_index = 0;
  dispatch.header.sequence_number = 6100;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(blocked), [] { return true; });
  indirect.header.sequence_number = 6101;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(blocked), [] { return true; });
  Check(Payload(events.back()) == "native_wasm_indirect_browser_filtered",
        "The fresh configuration still excludes the other module");
  for (unsigned index = 0; index < 16; ++index) {
    dispatch.header.sequence_number = 6200 + index;
    sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
    if (index == 0)
      Receive(receiver, transfers.begin()->first);
  }
  Check(dispatch_count() == reset_dispatch + 16 && transfers.empty(),
        "A filtered module did not consume one of the 16 br_table slots");
  dispatch.header.sequence_number = 6216;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(Payload(events.back()) == "native_wasm_dispatch_browser_budget_incomplete",
        "The seventeenth br_table sample is still the global browser budget");
  for (unsigned index = 0; index < 16; ++index) {
    indirect.header.sequence_number = 6300 + index;
    sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(allowed), [] { return true; });
  }
  Check(indirect_count() == reset_indirect + 16 && transfers.empty(),
        "A filtered module did not consume one of the 16 call_indirect slots");
  indirect.header.sequence_number = 6316;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(Payload(events.back()) == "native_wasm_indirect_browser_budget_incomplete",
        "Exhausting br_table did not exhaust call_indirect");
  sink.ResetWasmSampleBudgets();
  dispatch.header.sequence_number = 6400;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  indirect.header.sequence_number = 6401;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(transfers.empty() && dispatch_count() == reset_dispatch + 17 &&
            indirect_count() == reset_indirect + 17 &&
            events.back().header.type == NativeProbeType::kWasmIndirectObservation,
        "Reset accepts both streams again without a new configuration or transfer");

  Configure();
  policy = {};
  policy.samples_per_function = 1;
  sink.SetWasmSampleBudgetPolicy(policy);
  const auto invalid_dispatch = dispatch_count();
  const auto invalid_indirect = indirect_count();
  dispatch.function_index = 4;
  dispatch.header.sequence_number = 6500;
  const std::vector<std::uint8_t> invalid_module{1, 2, 3, 4};
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(invalid_module), [] { return true; });
  Check(transfers.empty() && Payload(events.back()) == "native_wasm_dispatch_limit_or_invalid",
        "A short module is an explicit br_table limit gap and does not transfer");
  dispatch.header.sequence_number = 6501;
  sink.CaptureWasmDispatch(dispatch, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(transfers.size() == 1, "The valid module still transfers after the invalid one");
  Receive(receiver, transfers.begin()->first);
  Check(dispatch_count() == invalid_dispatch + 1,
        "An invalid module did not consume the per-function br_table budget");
  indirect.function_index = 4;
  indirect.header.sequence_number = 6502;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(invalid_module), [] { return true; });
  Check(transfers.empty() && Payload(events.back()) == "native_wasm_indirect_limit_or_invalid",
        "A short module is an explicit call_indirect limit gap and does not transfer");
  indirect.header.sequence_number = 6503;
  sink.CaptureWasmIndirect(indirect, mojo_base::BigBuffer(allowed), [] { return true; });
  Check(indirect_count() == invalid_indirect + 1 && transfers.empty(),
        "An invalid module did not consume the per-function call_indirect budget");
  std::cout << "PASS native Wasm sample budget controls; per function, module allowlist, "
               "independent streams and reset\n";
}

#include "guest_dependencies_test.h"
#include "probe_host_test.h"
}  // namespace

void NativeWasmExecutionOutcomes(reb::ArtifactReceiver& receiver) {
  record_corpus = false;
  Configure();
  static_assert(static_cast<std::uint16_t>(reb::EventType::kWasmExecutionOutcome) == 27);
  static_assert(static_cast<std::uint16_t>(reb::EventType::kWasmExecutionOutcome) ==
                static_cast<std::uint16_t>(reb::NativeProbeType::kWasmExecutionOutcome));
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const std::vector<std::uint8_t> module{0, 97, 115, 109, 1, 0, 0, 0, 0x11, 0, 0};
  reb::NativeWasmIndirectObservation observation;
  observation.header.session_id = kSession;
  observation.header.frame_id = kFrame;
  observation.header.sequence_number = 3200;
  observation.header.monotonic_time_ns = 99;
  observation.header.process_id = 123;
  observation.header.thread_id = 7;
  observation.execution_context_id = 81;
  observation.document_token_high = 72;
  observation.document_token_low = 73;
  observation.function_index = 1;
  observation.module_byte_offset = 8;
  observation.callee_function_index = 2;
  observation.resolution = reb::NativeWasmIndirectResolution::kResolved;
  observation.source_url = "fixture://native-wasm-execution";
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.size() == 1, "Execution fixture transfers its module");
  const auto id = transfers.begin()->first;
  Receive(receiver, id);
  observation.header.sequence_number = 3201;
  observation.resolution = reb::NativeWasmIndirectResolution::kNull;
  observation.callee_function_index = 0;
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(module), [] { return true; });
  reb::NativeWasmExecutionObservation outcome;
  outcome.header.session_id = kSession;
  outcome.header.frame_id = kFrame;
  outcome.header.sequence_number = 3202;
  outcome.header.monotonic_time_ns = 99;
  outcome.header.process_id = 123;
  outcome.header.thread_id = 7;
  outcome.execution_context_id = 81;
  outcome.document_token_high = 72;
  outcome.document_token_low = 73;
  outcome.invocation_id = 11;
  outcome.function_index = 9;
  outcome.module_byte_offset = 8;
  outcome.related_sample_index = 0;
  outcome.kind = reb::NativeWasmExecutionKind::kTrap;
  outcome.reason = reb::NativeWasmExecutionReason::kSignatureMismatch;
  outcome.known = reb::kNativeWasmExecutionFunctionKnown | reb::kNativeWasmExecutionOffsetKnown;
  outcome.related_stream = reb::NativeWasmExecutionStream::kCallIndirect;
  outcome.source_url = observation.source_url;
  sink.CaptureWasmExecution(outcome, mojo_base::BigBuffer(module), [] { return true; });
  const auto find = [](NativeProbeType type, std::uint64_t sequence) {
    return std::find_if(events.begin(), events.end(), [&](const auto& event) {
      return event.header.type == type && event.header.sequence_number == sequence;
    });
  };
  const auto resolved = find(NativeProbeType::kWasmIndirectObservation, 3200);
  const auto null_entry = find(NativeProbeType::kWasmIndirectObservation, 3201);
  const auto trap = find(NativeProbeType::kWasmExecutionOutcome, 3202);
  Check(resolved != events.end() && null_entry != events.end() && trap != events.end(),
        "Resolved, null and signature-mismatch records are all retained");
  reb::WasmIndirectObservationPayload resolved_payload;
  reb::WasmIndirectObservationPayload null_payload;
  reb::WasmExecutionOutcomePayload trap_payload;
  Check(reb::DecodeWasmIndirectObservationPayload(resolved->inline_payload, resolved_payload) &&
            reb::DecodeWasmIndirectObservationPayload(null_entry->inline_payload, null_payload) &&
            reb::DecodeWasmExecutionOutcomePayload(trap->inline_payload, trap_payload),
        "Execution fixture payloads decode");
  Check(resolved_payload.resolution == 0 && null_payload.resolution == 1 &&
            trap_payload.reason ==
                static_cast<std::uint8_t>(reb::WasmExecutionReason::kSignatureMismatch) &&
            trap_payload.kind == static_cast<std::uint8_t>(reb::WasmExecutionKind::kTrap) &&
            trap_payload.function_index == 9 && trap->header.artifact_id == id &&
            reb::IsValidWasmExecutionOutcome(std::bit_cast<reb::EventRecord>(*trap)),
        "Signature mismatch is a trap record, not resolution null");
  outcome.header.sequence_number = 3203;
  outcome.invocation_id = 12;
  outcome.kind = reb::NativeWasmExecutionKind::kStillExecuting;
  outcome.reason = reb::NativeWasmExecutionReason::kUnknown;
  outcome.function_index = 1;
  sink.CaptureWasmExecution(outcome, mojo_base::BigBuffer(std::span<const std::uint8_t>{}),
                            [] { return true; });
  const auto still = find(NativeProbeType::kWasmExecutionOutcome, 3203);
  Check(still != events.end() && still->header.artifact_id == id,
        "Still-executing binds the one module");
  reb::WasmExecutionOutcomePayload still_payload;
  Check(reb::DecodeWasmExecutionOutcomePayload(still->inline_payload, still_payload) &&
            still_payload.kind ==
                static_cast<std::uint8_t>(reb::WasmExecutionKind::kStillExecuting) &&
            still_payload.reason == 0,
        "Still-executing carries no trap reason");
  outcome.header.sequence_number = 3204;
  outcome.document_token_low = 99;
  outcome.invocation_id = 13;
  sink.CaptureWasmExecution(outcome, mojo_base::BigBuffer(std::span<const std::uint8_t>{}),
                            [] { return true; });
  Check(Payload(events.back()) == "native_wasm_execution_module_unavailable",
        "No module for the document is an explicit gap");
  outcome.document_token_low = 73;
  std::vector<std::uint8_t> other = module;
  other.push_back(1);
  observation.header.sequence_number = 3205;
  observation.resolution = reb::NativeWasmIndirectResolution::kResolved;
  observation.callee_function_index = 2;
  observation.document_token_low = 73;
  sink.CaptureWasmIndirect(observation, mojo_base::BigBuffer(other), [] { return true; });
  Check(transfers.size() == 1, "A second module is its own artifact");
  Receive(receiver, transfers.begin()->first);
  outcome.header.sequence_number = 3206;
  outcome.invocation_id = 14;
  sink.CaptureWasmExecution(outcome, mojo_base::BigBuffer(std::span<const std::uint8_t>{}),
                            [] { return true; });
  Check(Payload(events.back()) == "native_wasm_execution_module_unresolved",
        "Two modules for one document are not guessed");
  std::cout << "PASS native Wasm execution outcome artifact binding\n";
}

int main(int argc, char** argv) {
  try {
    Check(argc == 3, "Usage: native-artifact-capture OUTPUT AUTHORED_SOURCE");
    const std::filesystem::path output(argv[1]);
    std::filesystem::create_directories(output);
    std::ifstream fixture(argv[2], std::ios::binary);
    Check(static_cast<bool>(fixture), "Authored source fixture opens");
    const std::string text{std::istreambuf_iterator<char>(fixture),
                           std::istreambuf_iterator<char>()};
    source.assign(text.begin(), text.end());
    Check(!source.empty(), "Fixture is not empty");
    static_assert(sizeof(reb::NativeProbeEvent) == sizeof(reb::EventRecord));
    event_wire.open(output / "events.bin", std::ios::binary);
    artifact_wire.open(output / "artifacts.bin", std::ios::binary);
    ack_wire.open(output / "acks.bin", std::ios::binary);
    // Mirrors the production receiver replay, which runs with --allow-sensitive
    // so content-mode request bodies are retained.
    reb::ArtifactReceiver receiver(output / "in-process-artifacts",
                                   {.max_artifact_bytes = reb::kNativeArtifactMaxContentBytes,
                                    .max_store_bytes = 256U * 1024U * 1024U,
                                    .allow_sensitive = true});
    Corpus(receiver, output);
    Lifecycle(receiver);
    Admission(output);
    NativeWasmDispatch(receiver);
    NativeWasmIndirect(receiver);
    NativeWasmSampleBudget(receiver);
    NativeWasmDirectCaller(receiver);
    NativeWasmExecutionOutcomes(receiver);
    NativeGuestDependencies(receiver);
    NativeProbeHostGuestBoundary(receiver);
    NativeProbeHostJsDispatchForwarding();
    NativeProbeHostBrowserInternalScope();
    NativeProbeHostWorkerTabLinks();
    RequestBodyPolicy(output);
    ResponseBodyLimits(receiver, output);
    event_wire.flush();
    artifact_wire.flush();
    ack_wire.flush();
    Check(event_wire.good() && artifact_wire.good() && ack_wire.good(),
          "Native wire files flushed");
    std::cout << "PASS " << assertions
              << " component assertions. Chromium platform/Mojo scheduling "
                 "and socket writer are adapters, not a Brave runtime.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL native artifact capture: " << error.what() << '\n';
    return 1;
  }
}
