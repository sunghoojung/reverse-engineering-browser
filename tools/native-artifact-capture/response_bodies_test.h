// Response bodies (protocol/native-network-v3.md) through the real network
// sink, artifact sink, response-body capture and production receiver.

constexpr std::uint64_t kResponseExpiry = 1'000'000'000'000;
constexpr std::int64_t kSecond = 1'000'000'000;

void ConfigureResponses(const reb::NativeResponseBodyPolicy& policy = {.enabled = true}) {
  base::test_now_ns = 100;
  NativeArtifactSocketClient::Get().connected = true;
  NativeArtifactCaptureSink::Get().SetEmitter(Emit, kSession, kMask, kResponseExpiry,
                                              reb::kNativeRequestContentDefaultBudgetBytes, policy);
  reb::NativeNetworkCaptureSink::Get().SetEmitter(Emit, kSession, kMask, kResponseExpiry,
                                                  policy.enabled);
}

struct Response {
  std::uint64_t id = 0;
  std::uint64_t creator = 0;
  int pipe = 0;
  bool teed = false;
};

struct ResponseHead {
  std::string mime = "application/json";
  int resource_type = 13;
  int status = 200;
  std::optional<std::string> encoding;
  std::int64_t declared = 0;
  bool service_worker = false;
  bool still_encoded = false;
};

Response Respond(const std::uint64_t id, const ResponseHead& spec = {}) {
  auto& network = reb::NativeNetworkCaptureSink::Get();
  network::ResourceRequest request;
  request.resource_type = spec.resource_type;
  request.url = GURL("https://api.fixture.test/r/" + std::to_string(id) + "?q=1");
  network.RecordRequestStarted(id, 0, 0, 1, kFrame, 11, 12, request);
  network::mojom::URLResponseHead head;
  head.mime_type = spec.mime;
  head.headers->code = spec.status;
  head.headers->content_encoding = spec.encoding;
  head.content_length = spec.declared;
  head.was_fetched_via_service_worker = spec.service_worker;
  if (spec.still_encoded) {
    head.client_side_content_decoding_types.push_back(1);
  }
  const auto creator = network.RecordResponseStarted(id, 0, 0, 1, kFrame, 11, 12, head);
  const int pipe = next_pipe++;
  const auto tees = NativeArtifactBodyTee::pending.size();
  const auto returned = NativeArtifactCaptureSink::Get().MaybeCaptureResponse(
      id, kFrame, creator, request, head, {pipe});
  Check(returned.id == pipe, "The response body handle is forwarded unchanged");
  return {id, creator, pipe, NativeArtifactBodyTee::pending.size() == tees + 1};
}

void Completed(const Response& response, const int error = 0) {
  network::URLLoaderCompletionStatus status;
  status.error_code = error;
  reb::NativeNetworkCaptureSink::Get().RecordRequestCompleted(response.id, 0, 0, 1, kFrame, 11, 12,
                                                              status);
}

reb::ResponseBodyPayload ResponseRecord(const NativeProbeEvent& event) {
  reb::ResponseBodyPayload value;
  Check(event.header.type == NativeProbeType::kResponseBody &&
            reb::DecodeResponseBodyPayload(event.inline_payload, value) &&
            reb::IsValidEvent(std::bit_cast<reb::EventRecord>(event)),
        "Produced response_body record passes the core validator");
  return value;
}

NativeProbeEvent Ended(
    const Response& response,
    const std::span<const std::uint8_t> bytes,
    const int error = 0,
    const reb::NativeArtifactBodyEnd end = reb::NativeArtifactBodyEnd::kSourceClosed) {
  NativeArtifactBodyTee::Deliver(response.pipe, bytes);
  NativeArtifactBodyTee::End(response.pipe, end);
  Completed(response, error);
  base::ThreadPool::RunPending();
  return LastOf(NativeProbeType::kResponseBody);
}

reb::ResponseBodyState StateOf(const reb::ResponseBodyPayload& payload) {
  return static_cast<reb::ResponseBodyState>(payload.state);
}

// The record names an artifact holding exactly `bytes`, created by the
// response_started record it is a child of.
void CheckRetained(const NativeProbeEvent& record,
                   const Response& response,
                   const std::span<const std::uint8_t> bytes,
                   const std::string& label) {
  const auto payload = ResponseRecord(record);
  const auto& transfer = *NativeArtifactSocketClient::Get().transfers.at(record.header.artifact_id);
  const auto digest = crypto::hash::Sha256(bytes);
  Check(record.header.parent_event_id == response.creator &&
            record.header.request_id == response.id && record.header.frame_id == kFrame &&
            transfer.header.kind == reb::NativeArtifactKind::kResponseBody &&
            transfer.header.capture_origin == reb::NativeArtifactCaptureOrigin::kNetworkResponse &&
            (transfer.header.flags & reb::kNativeArtifactFlagSensitive) != 0 &&
            transfer.header.creator_event_id == response.creator &&
            transfer.header.expected_sha256 == digest && payload.sha256 == digest &&
            payload.captured_length == bytes.size() &&
            std::equal(transfer.content.begin(), transfer.content.end(), bytes.begin(),
                       bytes.end()) &&
            reb::IsValidArtifactHeader(std::bit_cast<reb::ArtifactHeader>(transfer.header)),
        label + ": exact bytes and digest, joined to its response_started creator");
}

// A body opened after the pre-expiry flush can no longer be recorded, so
// neither its bytes nor a checkpoint reach the receiver.
void StreamPastExpiry() {
  ConfigureResponses();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  transfers.clear();
  const auto response = Respond(8100);
  std::vector<std::uint8_t> chunk(64 * 1024, 'c');
  NativeArtifactBodyTee::Deliver(response.pipe, chunk);
  const auto streaming = transfers.size();
  Check(streaming == 1, "The streaming body is open at the receiver");
  base::test_now_ns = static_cast<std::int64_t>(kResponseExpiry) + 1;
  const auto records_before = events.size();
  NativeArtifactBodyTee::Deliver(response.pipe, chunk);
  Check(transfers.empty() && events.size() == records_before,
        "Bytes past expiry abort the stream and nothing more is sent");
  NativeArtifactBodyTee::Deliver(response.pipe, chunk);
  NativeArtifactBodyTee::End(response.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  Completed(response);
  Check(transfers.empty() && events.size() == records_before,
        "Later bytes and the end of the aborted body change nothing");
  ConfigureResponses();
  transfers.clear();
  std::cout << "PASS response body stream past expiry is aborted\n";
}

void ResponseBodies(reb::ArtifactReceiver& receiver, const std::filesystem::path& output) {
  ConfigureResponses();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  transfers.clear();
  std::ofstream expected(output / "response-bodies.json");
  bool first = true;
  const auto expect = [&](const Response& response, const NativeProbeEvent& record,
                          const std::string& url, const std::string& mime) {
    const auto payload = ResponseRecord(record);
    expected << (first ? "\n" : ",\n") << "{\"request_id\":\"" << response.id
             << "\",\"response_sequence\":\"" << response.creator << "\",\"record_sequence\":\""
             << record.header.sequence_number << "\",\"artifact_id\":\""
             << record.header.artifact_id << "\",\"state\":" << unsigned{payload.state}
             << ",\"body_length\":" << payload.body_length
             << ",\"captured_length\":" << payload.captured_length << ",\"sha256\":\""
             << Hex(payload.sha256) << "\",\"url\":\"" << url << "\",\"mime_type\":\"" << mime
             << "\"}";
    first = false;
  };
  const auto url = [](std::uint64_t id) {
    return "https://api.fixture.test/r/" + std::to_string(id) + "?q=1";
  };
  const auto receive = [&](const Response& response, const NativeProbeEvent& record) {
    Receive(receiver, record.header.artifact_id);
    CheckCapture(record.header.artifact_id, response.creator, response.id);
  };
  expected << "[";

  const auto json = Bytes("{\"challenge\":\"c1\",\"answers\":[1,2,3],\"html\":\"<b>x</b>\"}");
  const auto json_response = Respond(701);
  const auto json_record = Ended(json_response, json);
  CheckRetained(json_record, json_response, json, "JSON fetch");
  Check(StateOf(ResponseRecord(json_record)) == reb::ResponseBodyState::kCaptured,
        "A finished JSON body is captured");
  expect(json_response, json_record, url(701), "application/json");
  receive(json_response, json_record);

  // The tee sees decoded bytes; the record keeps the codings the server sent.
  const auto html = Bytes("<!doctype html><title>t</title><script>alert(1)</script><p>body");
  const auto html_response =
      Respond(702, {.mime = "text/html", .resource_type = 0, .encoding = "gzip", .declared = 41});
  const auto html_record = Ended(html_response, html);
  CheckRetained(html_record, html_response, html, "gzip HTML document");
  const auto html_payload = ResponseRecord(html_record);
  Check(
      html_payload.coding_count == 1 &&
          html_payload.codings[0] == static_cast<std::uint8_t>(reb::NativeResponseCoding::kGzip) &&
          std::string_view(html_payload.content_type.data(), html_payload.content_type_length) ==
              "text/html" &&
          html_payload.body_length == html.size(),
      "gzip is recorded and the decoded length is the body length");
  expect(html_response, html_record, url(702), "text/html");
  receive(html_response, html_record);

  const auto brotli = Bytes("{\"compressed\":\"brotli\"}");
  const auto brotli_response =
      Respond(703, {.encoding = "br", .declared = 19, .service_worker = true});
  const auto brotli_record = Ended(brotli_response, brotli);
  CheckRetained(brotli_record, brotli_response, brotli, "brotli JSON");
  const auto brotli_payload = ResponseRecord(brotli_record);
  Check(brotli_payload.coding_count == 1 &&
            brotli_payload.codings[0] ==
                static_cast<std::uint8_t>(reb::NativeResponseCoding::kBrotli) &&
            (brotli_payload.flags & reb::kResponseBodyServiceWorker) != 0,
        "br and a service-worker response are recorded");
  expect(brotli_response, brotli_record, url(703), "application/json");
  receive(brotli_response, brotli_record);

  // A fetched image is kept by default and retained byte for byte.
  std::vector<std::uint8_t> png{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
  for (std::uint8_t index = 0; index < 120; ++index) {
    png.push_back(static_cast<std::uint8_t>(index * 7U));
  }
  const auto image_response = Respond(704, {.mime = "image/png"});
  const auto image_record = Ended(image_response, png);
  CheckRetained(image_record, image_response, png, "fetched PNG");
  expect(image_response, image_record, url(704), "image/png");
  receive(image_response, image_record);

  // A chunked event stream is retained as it arrives, marked partial until it ends.
  const auto first_events = Bytes("data: one\n\n");
  const auto stream = Respond(705, {.mime = "text/event-stream"});
  const auto records = [] {
    return std::ranges::count_if(events, [](const auto& event) {
      return event.header.type == NativeProbeType::kResponseBody;
    });
  };
  NativeArtifactBodyTee::Deliver(stream.pipe, first_events);
  const auto before_snapshot = records();
  base::test_now_ns += 2 * kSecond;
  const auto more_events = Bytes("data: two\n\ndata: three\n\n");
  NativeArtifactBodyTee::Deliver(stream.pipe, more_events);
  Check(records() == before_snapshot + 1 && base::ThreadPool::pending.empty(),
        "An open stream is published by a receiver checkpoint; nothing is copied or hashed later");
  std::vector<std::uint8_t> so_far = first_events;
  so_far.insert(so_far.end(), more_events.begin(), more_events.end());
  const auto partial = LastOf(NativeProbeType::kResponseBody);
  const auto partial_payload = ResponseRecord(partial);
  Check(StateOf(partial_payload) == reb::ResponseBodyState::kPartial &&
            partial_payload.partial_index == 1 && partial_payload.body_length == so_far.size(),
        "The snapshot is partial 1 and counts every byte so far");
  CheckRetained(partial, stream, so_far, "partial event stream");
  expect(stream, partial, url(705), "text/event-stream");
  receive(stream, partial);
  base::test_now_ns += 2 * kSecond;
  NativeArtifactBodyTee::Deliver(stream.pipe, Bytes("x"));
  Check(records() == before_snapshot + 1, "A snapshot waits until the body grew by half");
  const auto last_events = Bytes("data: four\n\n");
  so_far.push_back('x');
  so_far.insert(so_far.end(), last_events.begin(), last_events.end());
  const auto stream_record = Ended(stream, last_events);
  Check(StateOf(ResponseRecord(stream_record)) == reb::ResponseBodyState::kCaptured &&
            stream_record.header.sequence_number > partial.header.sequence_number,
        "The ended stream is captured after its partial record");
  CheckRetained(stream_record, stream, so_far, "ended event stream");
  expect(stream, stream_record, url(705), "text/event-stream");
  receive(stream, stream_record);

  // The network failed mid-body: the bytes that arrived are kept and say so.
  std::vector<std::uint8_t> download(200 * 1024, 'd');
  const auto aborted = Respond(706, {.mime = "application/octet-stream", .declared = 1 << 20});
  // net::ERR_CONTENT_LENGTH_MISMATCH.
  const auto aborted_record = Ended(aborted, download, -354);
  Check(StateOf(ResponseRecord(aborted_record)) == reb::ResponseBodyState::kAborted,
        "An aborted download is not a captured body");
  CheckRetained(aborted_record, aborted, download, "aborted download prefix");
  expect(aborted, aborted_record, url(706), "application/octet-stream");
  receive(aborted, aborted_record);

  // Bodies the tee could not observe state why instead of looking empty.
  const auto not_modified = Respond(707, {.status = 304});
  const auto not_modified_payload = ResponseRecord(LastOf(NativeProbeType::kResponseBody));
  Check(!not_modified.teed &&
            StateOf(not_modified_payload) == reb::ResponseBodyState::kNotModified &&
            LastOf(NativeProbeType::kResponseBody).header.parent_event_id == not_modified.creator,
        "A 304 has no body to tee and says so");
  expect(not_modified, LastOf(NativeProbeType::kResponseBody), url(707), "application/json");
  network::ResourceRequest redirected_request;
  redirected_request.url = GURL(url(708));
  auto& network = reb::NativeNetworkCaptureSink::Get();
  network.RecordRequestStarted(708, 0, 0, 1, kFrame, 11, 12, redirected_request);
  net::RedirectInfo redirect;
  redirect.new_url = GURL("https://api.fixture.test/after");
  network::mojom::URLResponseHead redirect_head;
  redirect_head.headers->code = 302;
  network.RecordRequestRedirected(708, 0, 0, 1, kFrame, 11, 12, redirect, redirect_head);
  const auto hop = LastOf(NativeProbeType::kRequestRedirected);
  const auto hop_body = LastOf(NativeProbeType::kResponseBody);
  Check(StateOf(ResponseRecord(hop_body)) == reb::ResponseBodyState::kRedirected &&
            hop_body.header.parent_event_id == hop.header.sequence_number,
        "A redirect hop says Chromium discarded its body");
  expect({708, hop.header.sequence_number, 0, false}, hop_body, url(708), "text/javascript");
  const auto cancelled = Respond(709);
  const auto cancelled_record = Ended(cancelled, {}, 0, reb::NativeArtifactBodyEnd::kTargetClosed);
  Check(StateOf(ResponseRecord(cancelled_record)) == reb::ResponseBodyState::kCancelled &&
            cancelled_record.header.artifact_id == 0,
        "A body the page stopped reading before any byte is cancelled, not empty");
  expect(cancelled, cancelled_record, url(709), "application/json");
  const auto font = Respond(710, {.mime = "font/woff2", .resource_type = 5});
  Check(!font.teed && StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
                          reb::ResponseBodyState::kNotCapturedType,
        "Fonts are skipped unless asked for, visibly");
  expect(font, LastOf(NativeProbeType::kResponseBody), url(710), "font/woff2");
  expected << "\n]\n";
  Check(transfers.empty(), "Every corpus body was received");
  std::cout << "PASS response bodies: JSON, gzip HTML, brotli and service-worker JSON, fetched "
               "PNG, a chunked stream partial then captured, an aborted prefix, 304, redirect, "
               "cancelled and font records joined to their response_started creators\n";
}

void ResponseBodyLimits(reb::ArtifactReceiver& receiver, const std::filesystem::path& output) {
  record_corpus = false;
  constexpr std::size_t kKiB = 1024U, kMiB = 1024U * 1024U;
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  std::uint64_t next = 800;
  const auto body = Bytes("{\"ok\":true}");
  const auto drain = [&] {
    while (!transfers.empty()) {
      Receive(receiver, transfers.begin()->first);
    }
  };

  // Identical bytes are stored once; the repeat names the first artifact.
  ConfigureResponses({.enabled = true, .budget = 64 * kKiB});
  transfers.clear();
  const std::vector<std::uint8_t> forty(40 * kKiB, 'f');
  const auto original = Ended(Respond(next++), forty);
  const auto repeat = Ended(Respond(next++), forty);
  const auto repeat_payload = ResponseRecord(repeat);
  Check(repeat.header.artifact_id == original.header.artifact_id && transfers.size() == 1 &&
            (repeat_payload.flags & reb::kResponseBodyShared) != 0 &&
            StateOf(repeat_payload) == reb::ResponseBodyState::kCaptured,
        "A repeated body names the first artifact and is not sent again");
  // The budget counts unique bytes, and running out is a named state.
  std::vector<std::uint8_t> other(40 * kKiB, 'o');
  const auto over = ResponseRecord(Ended(Respond(next++), other));
  Check(StateOf(over) == reb::ResponseBodyState::kNotCapturedSessionBudget &&
            over.body_length == other.size() && transfers.size() == 1,
        "A body past the byte budget is refused visibly with its length");
  drain();
  const std::vector<std::uint8_t> small(30 * kKiB, 's');
  Check(ResponseRecord(Ended(Respond(next++), small)).state ==
            static_cast<std::uint8_t>(reb::ResponseBodyState::kNotCapturedSessionBudget),
        "Accepted bytes stay charged");
  // A receiver refusal refunds the bytes and forgets the digest.
  ConfigureResponses({.enabled = true, .budget = 64 * kKiB});
  transfers.clear();
  reb::ArtifactReceiver refusing(output / "refusing-response-receiver",
                                 {.max_artifact_bytes = kMiB, .max_store_bytes = kMiB});
  const auto refused = Ended(Respond(next++), forty);
  Receive(refusing, refused.header.artifact_id, true,
          reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled);
  Check(events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            Payload(events.back()) == "sensitive_capture_disabled" &&
            events.back().header.parent_event_id == refused.header.parent_event_id,
        "The receiver's refusal joins the body's creator");
  const auto resent = Ended(Respond(next++), forty);
  Check(resent.header.artifact_id != refused.header.artifact_id && transfers.size() == 1 &&
            ResponseRecord(resent).flags == ResponseRecord(refused).flags,
        "A refused digest is sent again within the refunded budget");
  drain();
  Ended(Respond(next++), std::vector<std::uint8_t>(24 * kKiB, 'e'));
  const auto exhausted = Respond(next++);
  Check(!exhausted.teed && StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
                               reb::ResponseBodyState::kNotCapturedSessionBudget,
        "With the budget used up nothing is teed and each response says so");
  transfers.clear();

  // 50 parallel responses all fit: each holds its bytes, not a 16 MiB share.
  ConfigureResponses();
  transfers.clear();
  std::vector<Response> parallel;
  for (int index = 0; index < 50; ++index) {
    parallel.push_back(Respond(next++));
  }
  Check(sink.in_flight_bytes() == 0 &&
            std::ranges::all_of(parallel, [](const Response& item) { return item.teed; }),
        "50 parallel bodies are teed and hold nothing before their bytes arrive");
  std::vector<std::vector<std::uint8_t>> parallel_bytes;
  for (std::size_t index = 0; index < parallel.size(); ++index) {
    parallel_bytes.push_back(Bytes("{\"index\":" + std::to_string(index) + ",\"pad\":\"" +
                                   std::string(20 * kKiB, 'p') + "\"}"));
    NativeArtifactBodyTee::Deliver(parallel[index].pipe, parallel_bytes.back());
  }
  for (const auto& item : parallel) {
    NativeArtifactBodyTee::End(item.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
    Completed(item);
  }
  base::ThreadPool::RunPending();
  Check(transfers.size() == 50 && sink.in_flight_bytes() <= reb::kNativeArtifactInFlightBytes,
        "All 50 are streamed within the in-flight pool");
  for (std::size_t index = 0; index < parallel.size(); ++index) {
    const auto record = std::find_if(events.rbegin(), events.rend(), [&](const auto& event) {
      return event.header.type == NativeProbeType::kResponseBody &&
             event.header.parent_event_id == parallel[index].creator;
    });
    Check(record != events.rend(), "Every parallel response has its record");
    CheckRetained(*record, parallel[index], parallel_bytes[index], "parallel body");
  }
  drain();
  Check(sink.in_flight_bytes() == 0, "Written transfers return their share");

  // Browser memory is bounded by the pool; a full pool is a named refusal.
  {
    auto held = reb::NativeArtifactReservation::Acquire(
        sink.memory_pool(), reb::kNativeArtifactInFlightBytes - 32 * kKiB);
    const auto starved = Respond(next++);
    const auto starved_record = Ended(starved, std::vector<std::uint8_t>(64 * kKiB, 'z'));
    Check(starved.teed &&
              StateOf(ResponseRecord(starved_record)) ==
                  reb::ResponseBodyState::kNotCapturedTransferRefused &&
              starved_record.header.artifact_id == 0 &&
              sink.in_flight_bytes() == reb::kNativeArtifactInFlightBytes - 32 * kKiB,
          "A full pool refuses the body visibly and keeps nothing of it");
  }
  const auto big_a = Respond(next++, {.declared = static_cast<std::int64_t>(16 * kMiB)});
  const auto big_b = Respond(next++, {.declared = static_cast<std::int64_t>(16 * kMiB)});
  Check(big_a.teed && big_b.teed && sink.in_flight_bytes() == 0,
        "A declared length reserves nothing");
  // A body past 16 MiB keeps its first 16 MiB and counts every byte.
  std::vector<std::uint8_t> huge(16 * kMiB + 4321);
  for (std::size_t index = 0; index < huge.size(); ++index) {
    huge[index] = static_cast<std::uint8_t>(index * 13U);
  }
  const auto truncated = Ended(big_a, huge);
  const auto truncated_payload = ResponseRecord(truncated);
  Check(StateOf(truncated_payload) == reb::ResponseBodyState::kCapturedTruncated &&
            truncated_payload.body_length == huge.size(),
        "A body past the artifact cap is truncated visibly");
  CheckRetained(truncated, big_a, std::span(huge).first(16 * kMiB), "16 MiB prefix");
  NativeArtifactBodyTee::End(big_b.pipe, reb::NativeArtifactBodyEnd::kTargetClosed);
  Check(StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
                reb::ResponseBodyState::kCancelled &&
            sink.in_flight_bytes() == 16 * kMiB,
        "A cancelled empty body returns its share");
  drain();
  Check(sink.in_flight_bytes() == 0, "The truncated body's share returns once written");

  // Without a completion the body is kept after a bounded wait, flagged.
  auto& runner = *base::SequencedTaskRunner::GetCurrentDefault();
  runner.tasks.clear();
  const auto silent = Respond(next++);
  NativeArtifactBodyTee::Deliver(silent.pipe, body);
  NativeArtifactBodyTee::End(silent.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  Check(runner.tasks.size() == 1 && runner.tasks[0].first == 10 * kSecond,
        "A finished body waits for its loader completion");
  const auto waiting = events.size();
  runner.tasks[0].second();
  runner.tasks.clear();
  base::ThreadPool::RunPending();
  const auto unobserved = ResponseRecord(LastOf(NativeProbeType::kResponseBody));
  Check(events.size() > waiting && StateOf(unobserved) == reb::ResponseBodyState::kCaptured &&
            (unobserved.flags & reb::kResponseBodyCompletionUnobserved) != 0,
        "A body whose completion never came is kept and flagged");
  // A completion that reports a failure after the source closed is aborted.
  const auto failed = Respond(next++);
  NativeArtifactBodyTee::Deliver(failed.pipe, body);
  NativeArtifactBodyTee::End(failed.pipe, reb::NativeArtifactBodyEnd::kSourceFailed);
  Completed(failed, -2);
  base::ThreadPool::RunPending();
  Check(StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
            reb::ResponseBodyState::kAborted,
        "A failed source is aborted");
  // net::ERR_ABORTED is the page or browser stopping the request.
  const auto stopped = Respond(next++);
  Completed(stopped, -3);
  NativeArtifactBodyTee::Deliver(stopped.pipe, body);
  NativeArtifactBodyTee::End(stopped.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  base::ThreadPool::RunPending();
  Check(StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
            reb::ResponseBodyState::kCancelled,
        "A completion before the body ends still decides the state");
  // A still-encoded body and several codings are recorded as sent.
  const auto encoded = ResponseRecord(
      Ended(Respond(next++, {.encoding = "gzip, br, x-custom", .still_encoded = true}),
            Bytes("\x1f\x8b raw")));
  Check(encoded.coding_count == 3 && encoded.codings[0] == 1 && encoded.codings[1] == 3 &&
            encoded.codings[2] == 15 && (encoded.flags & reb::kResponseBodyStillEncoded) != 0,
        "Codings keep their order and client-side decoding is flagged");
  drain();

  // An open stream at capture end becomes a partial record, not a silent loss.
  const auto open = Respond(next++, {.mime = "text/event-stream"});
  NativeArtifactBodyTee::Deliver(open.pipe, Bytes("data: open\n\n"));
  ConfigureResponses();
  const auto flushed = ResponseRecord(LastOf(NativeProbeType::kResponseBody));
  Check(StateOf(flushed) == reb::ResponseBodyState::kPartial && flushed.partial_index == 1 &&
            transfers.size() == 1,
        "Capture end retains an open stream as partial");
  NativeArtifactBodyTee::End(open.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  Check(base::ThreadPool::RunPending() == 0, "The stale tee ends without a record");
  transfers.clear();
  // One with no byte yet still gets a named state.
  const auto nothing_yet = Respond(next++, {.mime = "text/event-stream"});
  ConfigureResponses();
  const auto unsent = LastOf(NativeProbeType::kResponseBody);
  Check(unsent.header.parent_event_id == nothing_yet.creator &&
            StateOf(ResponseRecord(unsent)) ==
                reb::ResponseBodyState::kNotCapturedArtifactUnavailable &&
            transfers.empty(),
        "Capture end names an open body that received nothing");
  NativeArtifactBodyTee::End(nothing_yet.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  base::ThreadPool::RunPending();

  // Images that page elements load are media; asking for media keeps them.
  const std::vector<std::uint8_t> gif{'G', 'I', 'F', '8', '9', 'a', 1, 0, 1, 0};
  Check(!Respond(next++, {.mime = "image/gif", .resource_type = 4}).teed,
        "An element-loaded image is skipped by default");
  ConfigureResponses({.enabled = true, .media = true});
  const auto media = Respond(next++, {.mime = "image/gif", .resource_type = 4});
  CheckRetained(Ended(media, gif), media, gif, "element image with media");
  transfers.clear();

  // A response the loader gave no body pipe is empty, not missing.
  {
    auto& network = reb::NativeNetworkCaptureSink::Get();
    network::ResourceRequest request;
    request.resource_type = 13;
    request.url = GURL("https://api.fixture.test/none");
    network.RecordRequestStarted(next, 0, 0, 1, kFrame, 11, 12, request);
    network::mojom::URLResponseHead head;
    head.mime_type = "application/json";
    const auto creator = network.RecordResponseStarted(next, 0, 0, 1, kFrame, 11, 12, head);
    Check(!sink.MaybeCaptureResponse(next++, kFrame, creator, request, head, {}).is_valid() &&
              StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
                  reb::ResponseBodyState::kEmpty &&
              LastOf(NativeProbeType::kResponseBody).header.parent_event_id == creator,
          "A missing body pipe is an empty body record");
  }
  transfers.clear();

  // Metadata-only sessions tee nothing and record nothing.
  ConfigureResponses({});
  const auto before = events.size();
  const auto metadata = Respond(next++);
  Check(!metadata.teed &&
            std::none_of(events.begin() + static_cast<std::ptrdiff_t>(before), events.end(),
                         [](const auto& event) {
                           return event.header.type == NativeProbeType::kResponseBody;
                         }),
        "A metadata-only session keeps no response body");
  // A tee that cannot start is a named refusal.
  ConfigureResponses();
  NativeArtifactBodyTee::unavailable = true;
  const auto no_tee = Respond(next++);
  NativeArtifactBodyTee::unavailable = false;
  Check(!no_tee.teed &&
            StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
                reb::ResponseBodyState::kNotCapturedTransferRefused &&
            sink.in_flight_bytes() == 0,
        "An unavailable tee is refused visibly and returns its share");
  Configure();
  transfers.clear();
  std::cout << "PASS response body limits: digest dedupe, unique-byte budget and exhaustion, "
               "receiver refusal refund, 50 parallel bodies, full pool, 16 MiB truncation, "
               "missing completion, failed and stopped bodies, coding order, capture-end "
               "partial, media opt-in, metadata-only and tee refusal\n";
}
