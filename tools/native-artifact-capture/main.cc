// Native response artifact linkage component integration test.
// No event, artifact metadata, creator sequence or ACK status is repaired in this driver.
#include <bit>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "chromium_stubs.h"
#include "reb/artifact.hpp"
#include "reb/event.hpp"
#include "reb/wasm_dispatch.hpp"

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
  const auto root = events.back().header.sequence_number;
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
std::uint64_t Finish(int pipe, bool complete = true) {
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  std::set<std::uint64_t> existing;
  for (const auto& [id, transfer] : transfers) {
    static_cast<void>(transfer);
    existing.insert(id);
  }
  NativeArtifactBodyTee::Complete(pipe, complete, source);
  for (const auto& [id, transfer] : transfers) {
    static_cast<void>(transfer);
    if (!existing.contains(id)) {
      return id;
    }
  }
  return 0;
}
reb::NativeArtifactAck Receive(
    reb::ArtifactReceiver& receiver,
    std::uint64_t id,
    bool deliver = true,
    reb::ArtifactReceiveStatus expected = reb::ArtifactReceiveStatus::kAccepted) {
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const auto& transfer = *transfers.at(id);
  std::ostringstream serialized(std::ios::binary);
  Write(serialized, transfer.header);
  serialized << transfer.url << transfer.mime_type;
  serialized.write(reinterpret_cast<const char*>(transfer.content.data()),
                   static_cast<std::streamsize>(transfer.content.size()));
  const std::string bytes = serialized.str();
  if (record_corpus) {
    artifact_wire.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  std::istringstream stream(bytes, std::ios::binary);
  reb::ArtifactAck actual_ack;
  actual_ack.status = receiver.ReceiveOne(stream);
  actual_ack.artifact_id = receiver.LastArtifactId();
  Check(actual_ack.status == expected, "Production receiver status: " + receiver.LastError());
  Check(actual_ack.artifact_id == id, "ACK identity comes from ReceiveOne LastArtifactId");
  const auto native_ack = std::bit_cast<reb::NativeArtifactAck>(actual_ack);
  Check(native_ack.magic == reb::kNativeArtifactAckMagic &&
            native_ack.protocol_version == reb::kNativeArtifactProtocolVersion &&
            native_ack.ack_size == sizeof(native_ack),
        "Production ACK bytes match native ACK protocol");
  if (record_corpus) {
    Write(ack_wire, native_ack);
  }
  if (deliver) {
    NativeArtifactCaptureSink::TransferCompleted(native_ack.artifact_id, native_ack.status);
  }
  transfers.erase(id);
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
  Check(Finish(Begin(request), false) == 0 &&
            Payload(events.back()) == "body_incomplete_or_too_large",
        "Incomplete body never enqueues");
  client.reject_next = true;
  Check(Finish(Begin(request)) == 0 &&
            Payload(events.back()) == "transfer_queue_full_or_disconnected",
        "Queue rejection is visible");

  const int first = Begin(request);
  const int second = Begin(request);
  no_admission("32 MiB active-body memory bound", [&] { Begin(request); });
  Check(Payload(events.back()) == "active_memory_limit", "Memory rejection is visible");
  Check(Finish(first, false) == 0, "Failed body releases reservation");
  const int replacement = Begin(request);
  Check(NativeArtifactBodyTee::pending.contains(replacement),
        "Released reservation admits next body");
  Configure();
  Check(Finish(second) == 0 && Finish(replacement) == 0,
        "Old reservations release on stale callbacks");
  const int after_stale_a = Begin(request);
  const int after_stale_b = Begin(request);
  Check(NativeArtifactBodyTee::pending.size() == 2,
        "Both reservations reusable after stale retirement");
  Finish(after_stale_a, false);
  Finish(after_stale_b, false);

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
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [&] { return current; });
  current = false;
  Receive(receiver, transfers.begin()->first);
  Check(count() == before + 1, "Navigated document cannot emit delayed observation");
  current = true;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [&] { return current; });
  const auto retired = transfers.begin()->first;
  Configure();
  Receive(receiver, retired);
  Check(count() == before + 1, "Same session reconfiguration retires old acknowledgement");
  observation.table_count = 2;
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.empty(), "Mismatched br_table immediate rejected");
  observation.table_count = 1;
  Configure();
  for (unsigned i = 0; i < 17; ++i)
    sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.size() == 16, "Browser admission bounded independently to sixteen modules");
  Check(Payload(events.back()) == "native_wasm_dispatch_browser_budget_incomplete",
        "Cross-renderer browser budget reports incompleteness");
  const auto after_budget_gap = events.size();
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(events.size() == after_budget_gap, "Browser budget marker is bounded per configuration");
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  Configure(kSession, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kArtifact));
  sink.CaptureWasmDispatch(observation, mojo_base::BigBuffer(module), [] { return true; });
  Check(transfers.empty(), "Artifact permission alone cannot admit runtime observation");
  std::cout << "PASS native Wasm artifact ACK, physical typed payload, document/generation "
               "retirement and bounds\n";
}
}  // namespace

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
    reb::ArtifactReceiver receiver(output / "in-process-artifacts",
                                   {.max_artifact_bytes = reb::kNativeArtifactMaxContentBytes,
                                    .max_store_bytes = 256U * 1024U * 1024U});
    Corpus(receiver, output);
    Lifecycle(receiver);
    Admission(output);
    NativeWasmDispatch(receiver);
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
