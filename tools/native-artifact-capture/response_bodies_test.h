// Response bodies (protocol/native-network-v3.md) through the real network
// sink, artifact sink, response-body capture and production receiver.

constexpr std::uint64_t kResponseExpiry = 1'000'000'000'000;
constexpr std::int64_t kSecond = 1'000'000'000;

void ConfigureResponses(const reb::NativeResponseBodyPolicy& policy = {.enabled = true},
                        const std::uint64_t expiry = kResponseExpiry) {
  base::test_now_ns = 100;
  NativeArtifactSocketClient::Get().connected = true;
  NativeArtifactCaptureSink::Get().SetEmitter(Emit, kSession, kMask, expiry, policy);
  reb::NativeNetworkCaptureSink::Get().SetEmitter(Emit, kSession, kMask, expiry, policy.enabled);
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
  std::optional<std::string> encoding{};
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
  base::test_now_ns += kSecond / 2;
  NativeArtifactBodyTee::Deliver(stream.pipe, Bytes("x"));
  Check(records() == before_snapshot + 1, "A snapshot waits a second after the one before");
  base::test_now_ns += kSecond / 2;
  NativeArtifactBodyTee::Deliver(stream.pipe, Bytes("y"));
  so_far.insert(so_far.end(), {'x', 'y'});
  const auto second = ResponseRecord(LastOf(NativeProbeType::kResponseBody));
  Check(records() == before_snapshot + 2 && StateOf(second) == reb::ResponseBodyState::kPartial &&
            second.partial_index == 2 && second.body_length == so_far.size(),
        "A second later the grown stream is snapshotted again, however little it grew");
  receive(stream, LastOf(NativeProbeType::kResponseBody));
  const auto last_events = Bytes("data: four\n\n");
  so_far.insert(so_far.end(), last_events.begin(), last_events.end());
  const auto stream_record = Ended(stream, last_events);
  Check(StateOf(ResponseRecord(stream_record)) == reb::ResponseBodyState::kCaptured &&
            stream_record.header.sequence_number > partial.header.sequence_number,
        "The ended stream is captured after its partial record");
  CheckRetained(stream_record, stream, so_far, "ended event stream");
  expect(stream, stream_record, url(705), "text/event-stream");
  receive(stream, stream_record);

  // A body that declares its length is retained as it arrives too.
  const auto declared = Respond(712, {.mime = "application/octet-stream", .declared = 4096});
  const std::vector<std::uint8_t> first_half(2048, 'h');
  NativeArtifactBodyTee::Deliver(declared.pipe, first_half);
  base::test_now_ns += 2 * kSecond;
  NativeArtifactBodyTee::Deliver(declared.pipe, first_half);
  const auto declared_partial = LastOf(NativeProbeType::kResponseBody);
  Check(declared_partial.header.parent_event_id == declared.creator &&
            StateOf(ResponseRecord(declared_partial)) == reb::ResponseBodyState::kPartial &&
            ResponseRecord(declared_partial).body_length == 4096,
        "A declared length is retained as partial while it arrives");
  receive(declared, declared_partial);
  const auto declared_record = Ended(declared, {});
  Check(StateOf(ResponseRecord(declared_record)) == reb::ResponseBodyState::kCaptured,
        "The declared body ends captured");
  receive(declared, declared_record);

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
  // Fonts are kept like any other body.
  const std::vector<std::uint8_t> woff2{'w', 'O', 'F', '2', 0, 1, 0, 0, 0, 0, 0, 42};
  const auto font = Respond(710, {.mime = "font/woff2", .resource_type = 5});
  const auto font_record = Ended(font, woff2);
  Check(font.teed && StateOf(ResponseRecord(font_record)) == reb::ResponseBodyState::kCaptured,
        "A font is captured by default");
  CheckRetained(font_record, font, woff2, "font");
  expect(font, font_record, url(710), "font/woff2");
  receive(font, font_record);
  expected << "\n]\n";
  Check(transfers.empty(), "Every corpus body was received");
  std::cout << "PASS response bodies: JSON, gzip HTML, brotli and service-worker JSON, fetched "
               "PNG, a chunked stream partial then captured, an aborted prefix, 304, redirect, "
               "cancelled and a captured font joined to their response_started creators\n";
}

// Runs every posted task whose delay has passed on the test clock.
void RunDueTasks() {
  auto& runner = *base::SequencedTaskRunner::GetCurrentDefault();
  for (bool ran = true; ran;) {
    ran = false;
    for (auto task = runner.tasks.begin(); task != runner.tasks.end(); ++task) {
      if (task->posted + task->first <= base::test_now_ns) {
        auto run = std::move(task->second);
        runner.tasks.erase(task);
        run();
        ran = true;
        break;
      }
    }
  }
}

// The contract's sizing table, replayed through the capture itself: one
// stream per profile opened at the start of a one-hour session, its chunks at
// a fixed rate, each posted timer run at its due time.
// tools/check-native-artifact-capture.py holds the table to it.
void ResponseBodyScheduleReplay(const std::filesystem::path& output) {
  struct Profile {
    const char* name;
    std::size_t bytes;
    std::int64_t tick;
    std::int64_t duration;
  };
  constexpr std::int64_t kHour = 3600 * kSecond;
  const Profile profiles[] = {{"60 KB/s", 15'000, kSecond / 4, kHour},
                              {"3.6 KB/s", 1'800, kSecond / 2, kHour},
                              {"10 KB/s for 60 s", 2'500, kSecond / 4, 60 * kSecond},
                              {"a heartbeat every 15 s", 2, 15 * kSecond, kHour}};
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  auto& runner = *base::SequencedTaskRunner::GetCurrentDefault();
  std::ofstream json(output / "schedule-replay.json");
  json << "[";
  std::uint64_t id = 9100;
  for (const auto& profile : profiles) {
    ConfigureResponses({.enabled = true}, static_cast<std::uint64_t>(100 + kHour + kSecond));
    transfers.clear();
    runner.tasks.clear();
    const auto start = static_cast<std::uint64_t>(base::test_now_ns);
    const auto response = Respond(id++, {.mime = "text/event-stream"});
    const std::vector<std::uint8_t> chunk(profile.bytes, 'r');
    std::uint64_t kept = 0, snapshots = 0, copied = 0, last_time = start, last_size = 0, stale = 0;
    std::size_t seen = events.size();
    const auto count = [&] {
      // The writer keeps up, so the stream never waits for the pool.
      DrainQueued();
      for (; seen < events.size(); ++seen) {
        const auto& event = events[seen];
        if (event.header.type != NativeProbeType::kResponseBody ||
            event.header.parent_event_id != response.creator) {
          continue;
        }
        const auto record = ResponseRecord(event);
        if (StateOf(record) != reb::ResponseBodyState::kPartial) {
          continue;
        }
        ++snapshots;
        last_time = event.header.monotonic_time_ns;
        last_size = record.captured_length;
        copied += record.captured_length;
      }
      // Snapshot copies are counted, then dropped, so the replay holds one stream.
      std::erase_if(transfers, [](const auto& entry) { return entry.second->stream_id != 0; });
    };
    // Staleness peaks just before a snapshot: at a chunk, or at a timer's due
    // time between chunks, so it is sampled at both.
    const auto sample = [&] {
      if (kept > last_size) {
        stale = std::max(stale, static_cast<std::uint64_t>(base::test_now_ns) - last_time);
      }
    };
    for (std::int64_t at = profile.tick; at <= profile.duration; at += profile.tick) {
      const std::int64_t next_chunk = static_cast<std::int64_t>(start) + at;
      for (;;) {
        std::optional<std::int64_t> due;
        for (const auto& task : runner.tasks) {
          const std::int64_t when = task.posted + task.first;
          if (when <= next_chunk && (!due || when < *due)) {
            due = when;
          }
        }
        if (!due) {
          break;
        }
        base::test_now_ns = std::max(base::test_now_ns, *due);
        sample();
        RunDueTasks();
        count();
      }
      base::test_now_ns = next_chunk;
      sample();
      NativeArtifactBodyTee::Deliver(response.pipe, chunk);
      kept += chunk.size();
      count();
    }
    NativeArtifactBodyTee::End(response.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
    Completed(response);
    base::ThreadPool::RunPending();
    const auto end = ResponseRecord(LastOf(NativeProbeType::kResponseBody));
    Check(StateOf(end) == reb::ResponseBodyState::kCaptured && end.captured_length == kept,
          "The replayed stream ends captured whole");
    const bool withheld = (end.flags & reb::kResponseBodySnapshotsWithheld) != 0;
    json << (id == 9101 ? "\n" : ",\n") << "{\"name\":\"" << profile.name
         << "\",\"snapshots\":" << snapshots << ",\"copied_bytes\":" << copied
         << ",\"kept_bytes\":" << kept << ",\"stale_ns\":" << stale
         << ",\"withheld\":" << (withheld ? "true" : "false") << "}";
    std::cout << "REPLAY " << profile.name << ": " << snapshots << " snapshots, "
              << copied / (1024 * 1024) << " MiB copied of " << kept / (1024 * 1024)
              << " MiB kept, newest snapshot at most " << stale / kSecond << " s old"
              << (withheld ? ", snapshots withheld" : "") << "\n";
    transfers.clear();
    runner.tasks.clear();
  }
  json << "\n]\n";
  ConfigureResponses();
  transfers.clear();
}

// Partial snapshots follow a schedule bounded by bytes and time, not a count
// ("Partial bodies" in protocol/native-network-v3.md).
void ResponseBodySchedule(reb::ArtifactReceiver& receiver, const std::filesystem::path& output) {
  record_corpus = false;
  constexpr std::size_t kKiB = 1024U, kMiB = 1024U * 1024U;
  constexpr std::int64_t kHour = 3600 * kSecond;
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const auto partials = [](const Response& response) {
    std::vector<NativeProbeEvent> found;
    for (const auto& event : events) {
      if (event.header.type == NativeProbeType::kResponseBody &&
          event.header.parent_event_id == response.creator &&
          StateOf(ResponseRecord(event)) == reb::ResponseBodyState::kPartial) {
        found.push_back(event);
      }
    }
    return found;
  };
  const auto checkpoints = [&transfers] {
    return std::ranges::count_if(transfers,
                                 [](const auto& entry) { return entry.second->stream_id != 0; });
  };
  const auto receive_snapshots = [&] {
    for (auto entry = transfers.begin(); entry != transfers.end();) {
      const auto id = entry->first;
      const bool snapshot = entry->second->stream_id != 0;
      ++entry;
      if (snapshot) {
        Receive(receiver, id);
      }
    }
  };
  const auto spacing = [](const std::uint64_t age) {
    return std::max<std::uint64_t>(reb::kNativeResponseBodySnapshotFirstNs,
                                   age / reb::kNativeResponseBodySnapshotAgeDivisor);
  };

  // A stream that trickles one 1 KiB event every 10 s for two hours keeps
  // being retained as it arrives, with no count to run out.
  ConfigureResponses({.enabled = true}, static_cast<std::uint64_t>(3 * kHour));
  transfers.clear();
  const auto started = static_cast<std::uint64_t>(base::test_now_ns);
  const auto trickle = Respond(9001, {.mime = "text/event-stream"});
  const std::vector<std::uint8_t> event(1024, 'e');
  std::uint64_t sent = 0;
  for (int tick = 0; tick < 720; ++tick) {
    base::test_now_ns += 10 * kSecond;
    NativeArtifactBodyTee::Deliver(trickle.pipe, event);
    sent += event.size();
  }
  const auto now = static_cast<std::uint64_t>(base::test_now_ns);
  const auto trickled = partials(trickle);
  Check(trickled.size() > 16, "A two-hour stream is snapshotted far past the old limit of 15");
  std::uint64_t previous = started, copied = 0, index = 0;
  for (const auto& snapshot : trickled) {
    const auto at = snapshot.header.monotonic_time_ns;
    const auto payload = ResponseRecord(snapshot);
    Check(at - previous >= spacing(at - started) && payload.partial_index == ++index,
          "Each snapshot waits a second and a 32nd of the body's age after the one before");
    copied += payload.captured_length;
    previous = at;
  }
  Check(copied <= reb::kNativeResponseBodySnapshotCopyFactor * sent +
                       reb::kNativeResponseBodySnapshotSlackBytes,
        "One body's snapshots copy at most four times its bytes plus 64 MiB");
  Check(now - trickled.back().header.monotonic_time_ns <=
                spacing(now - started) + static_cast<std::uint64_t>(10 * kSecond) &&
            ResponseRecord(trickled.back()).body_length + 32 * kKiB >= sent,
        "The newest snapshot is at most a 32nd of the stream's age old, plus one event");
  receive_snapshots();
  const auto trickle_end = Ended(trickle, {});
  Check(StateOf(ResponseRecord(trickle_end)) == reb::ResponseBodyState::kCaptured &&
            ResponseRecord(trickle_end).body_length == sent,
        "The ended stream supersedes its snapshots");
  Receive(receiver, trickle_end.header.artifact_id);
  std::cout << "PASS response body snapshots: " << trickled.size()
            << " snapshots of a two-hour stream, spaced by age, " << copied / kKiB
            << " KiB copied\n";

  // A body's snapshots together copy at most four times what it kept, plus
  // 64 MiB. A 10 MiB body that barely grows takes ten snapshots, then the
  // bound withholds the eleventh. No timer waits for it, since only more kept
  // bytes raise the bound, and every later record says one was withheld.
  auto& runner = *base::SequencedTaskRunner::GetCurrentDefault();
  const auto drop_copies = [&transfers] {
    std::erase_if(transfers, [](const auto& entry) { return entry.second->stream_id != 0; });
  };
  const auto copied_by = [&](const Response& response) {
    std::uint64_t total = 0;
    for (const auto& snapshot : partials(response)) {
      total += ResponseRecord(snapshot).captured_length;
    }
    return total;
  };
  const auto bound = [](const std::uint64_t kept) {
    return reb::kNativeResponseBodySnapshotCopyFactor * kept +
           reb::kNativeResponseBodySnapshotSlackBytes;
  };
  ConfigureResponses();
  transfers.clear();
  runner.tasks.clear();
  const auto paced = Respond(9002, {.mime = "text/event-stream"});
  NativeArtifactBodyTee::Deliver(paced.pipe, std::vector<std::uint8_t>(10 * kMiB, 'p'));
  for (int tick = 0; tick < 12; ++tick) {
    base::test_now_ns += 2 * kSecond;
    RunDueTasks();
    NativeArtifactBodyTee::Deliver(paced.pipe, Bytes("x"));
    drop_copies();
  }
  Check(partials(paced).size() == 10 && runner.tasks.empty() &&
            copied_by(paced) <= bound(10 * kMiB + 12),
        "Ten 10 MiB copies fit the bound; the eleventh is withheld and no timer waits for it");
  // 100 MiB copied fits 4 * kept + 64 MiB once 12 MiB + 15 bytes are kept,
  // which the 33rd 64 KiB chunk of the next burst reaches.
  base::test_now_ns += 2 * kSecond;
  NativeArtifactBodyTee::Deliver(paced.pipe, std::vector<std::uint8_t>(12 * kMiB, 'q'));
  drop_copies();
  const auto grown = partials(paced);
  Check(grown.size() == 11 && ResponseRecord(grown.back()).body_length == 12 * kMiB + 64 * kKiB + 12 &&
            (ResponseRecord(grown.back()).flags & reb::kResponseBodySnapshotsWithheld) != 0 &&
            copied_by(paced) <= bound(ResponseRecord(grown.back()).body_length),
        "More kept bytes raise the bound; the next snapshot says one was withheld");
  const auto paced_end = ResponseRecord(Ended(paced, {}));
  Check(StateOf(paced_end) == reb::ResponseBodyState::kCaptured &&
            paced_end.protocol_version == 3 && paced_end.captured_length == 22 * kMiB + 12 &&
            (paced_end.flags & reb::kResponseBodySnapshotsWithheld) != 0,
        "The ended body is whole and says a snapshot was withheld");
  const auto quick = ResponseRecord(Ended(Respond(9003), Bytes("{}")));
  Check((quick.flags & reb::kResponseBodySnapshotsWithheld) == 0,
        "A body whose snapshots were never withheld carries no flag");
  transfers.clear();
  runner.tasks.clear();

  // The disk reserve refusing a snapshot's copy is a disk_reserve failure
  // joined to the body's creator, and the stream stays open for later
  // snapshots. Refusing the stream itself ends the body as
  // not_captured_disk_reserve, with its length and no artifact.
  ConfigureResponses();
  transfers.clear();
  const auto reserved = Respond(9010, {.mime = "text/event-stream"});
  NativeArtifactBodyTee::Deliver(reserved.pipe, std::vector<std::uint8_t>(100 * kKiB, 'a'));
  base::test_now_ns += 2 * kSecond;
  NativeArtifactBodyTee::Deliver(reserved.pipe, Bytes("!"));
  Check(partials(reserved).size() == 1, "The first snapshot is taken");
  const auto refused_copy = partials(reserved).back().header.artifact_id;
  const auto reserved_stream = transfers.at(refused_copy)->stream_id;
  NativeArtifactCaptureSink::TransferCompleted(refused_copy,
                                               reb::NativeArtifactReceiveStatus::kDiskReserve);
  Check(events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            Payload(events.back()) == "disk_reserve" &&
            events.back().header.artifact_id == refused_copy &&
            events.back().header.parent_event_id == reserved.creator,
        "A snapshot the disk reserve refused is a disk_reserve failure joined to the creator");
  base::test_now_ns += 2 * kSecond;
  NativeArtifactBodyTee::Deliver(reserved.pipe, Bytes("!"));
  Check(partials(reserved).size() == 2, "The stream stays open and the next snapshot is taken");
  const auto records_before_refusal = events.size();
  NativeArtifactCaptureSink::TransferCompleted(reserved_stream,
                                               reb::NativeArtifactReceiveStatus::kDiskReserve);
  Check(events.size() == records_before_refusal, "A refused open body waits for its end");
  const auto refused_body = Ended(reserved, Bytes("more"));
  const auto refused_payload = ResponseRecord(refused_body);
  Check(StateOf(refused_payload) == reb::ResponseBodyState::kNotCapturedDiskReserve &&
            refused_body.header.artifact_id == 0 && refused_payload.captured_length == 0 &&
            refused_payload.body_length == 100 * kKiB + 6,
        "A body whose stream the disk reserve refused ends as not_captured_disk_reserve");
  ConfigureResponses();
  transfers.clear();
  runner.tasks.clear();

  // A body past 16 MiB and past the whole in-flight pool streams whole while
  // the writer drains it. Its snapshots are receiver checkpoints like any
  // other, and its end names every byte.
  std::vector<std::uint8_t> large(40 * kMiB + 9);
  for (std::size_t offset = 0; offset < large.size(); ++offset) {
    large[offset] = static_cast<std::uint8_t>(offset * 31U + 7U);
  }
  const auto big = Respond(9020, {.mime = "application/x-ndjson"});
  for (std::size_t offset = 0; offset < large.size();) {
    const std::size_t piece = std::min<std::size_t>(16 * kMiB, large.size() - offset);
    NativeArtifactBodyTee::Deliver(big.pipe, std::span(large).subspan(offset, piece));
    offset += piece;
    Check(NativeArtifactBodyTee::Waiting(big.pipe) == 0, "The writer keeps up with the body");
    DrainQueued();
    base::test_now_ns += 2 * kSecond;
    RunDueTasks();
    receive_snapshots();
  }
  const auto big_partials = partials(big);
  Check(big_partials.size() == 3 &&
            ResponseRecord(big_partials[0]).captured_length == 16 * kMiB &&
            ResponseRecord(big_partials[1]).captured_length == 32 * kMiB &&
            checkpoints() == 0,
        "A large open body is snapshotted by checkpoints of every byte so far");
  const auto big_end = Ended(big, {});
  const auto big_payload = ResponseRecord(big_end);
  Check(StateOf(big_payload) == reb::ResponseBodyState::kCaptured &&
            big_payload.body_length == large.size() && big_payload.captured_length == large.size(),
        "A 40 MiB body ends captured whole");
  CheckRetained(big_end, big, large, "40 MiB body");
  Receive(receiver, big_end.header.artifact_id);
  // A large body still open at capture end is one last partial naming all of it.
  const auto open = Respond(9023, {.mime = "application/x-ndjson"});
  NativeArtifactBodyTee::Deliver(open.pipe, std::span(large).subspan(3, 20 * kMiB));
  ConfigureResponses();
  runner.tasks.clear();
  const auto flushed = partials(open);
  Check(flushed.size() == 1 && ResponseRecord(flushed.back()).captured_length == 20 * kMiB,
        "Capture end keeps an open 20 MiB body as one last partial");
  CheckRetained(flushed.back(), open, std::span(large).subspan(3, 20 * kMiB), "flushed body");
  Receive(receiver, flushed.back().header.artifact_id);
  NativeArtifactBodyTee::End(open.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  base::ThreadPool::RunPending();
  Check(transfers.empty() && NativeArtifactBodyTee::pending.empty(),
        "Every scheduled stream was received and every tee ended");

  // A burst followed by silence is published once the spacing allows, by one
  // timer per body; an ended body's timer does nothing.
  ConfigureResponses();
  transfers.clear();
  runner.tasks.clear();
  const auto burst = Respond(9030, {.mime = "text/event-stream"});
  NativeArtifactBodyTee::Deliver(burst.pipe, Bytes("data: a\n\n"));
  base::test_now_ns += kSecond / 2;
  NativeArtifactBodyTee::Deliver(burst.pipe, Bytes("data: b\n\n"));
  Check(runner.tasks.size() == 1 && runner.tasks[0].first == kSecond && partials(burst).empty(),
        "One timer waits for the spacing; nothing is published early");
  base::test_now_ns += kSecond / 2;
  RunDueTasks();
  const auto timed = partials(burst);
  Check(timed.size() == 1 && ResponseRecord(timed[0]).body_length == 18 && runner.tasks.empty(),
        "With no new chunk the timer publishes what arrived");
  NativeArtifactBodyTee::Deliver(burst.pipe, Bytes("data: c\n\n"));
  NativeArtifactBodyTee::End(burst.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  Completed(burst);
  base::ThreadPool::RunPending();
  base::test_now_ns += 10 * kSecond;
  const auto ended = events.size();
  RunDueTasks();
  Check(events.size() == ended, "A timer of an ended body publishes nothing");
  transfers.clear();
  runner.tasks.clear();

  Configure();
  std::cout << "PASS response body schedule: the copy bound of four times the kept bytes plus "
               "64 MiB and its withheld flag, the disk reserve on a snapshot and on its stream, a "
               "40 MiB body snapshotted and kept whole, a timer that publishes a burst\n";
  ResponseBodyScheduleReplay(output);
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
  ConfigureResponses();
  transfers.clear();
  const std::vector<std::uint8_t> forty(40 * kKiB, 'f');
  const auto original = Ended(Respond(next++), forty);
  const auto repeat = Ended(Respond(next++), forty);
  const auto repeat_payload = ResponseRecord(repeat);
  Check(repeat.header.artifact_id == original.header.artifact_id && transfers.size() == 1 &&
            (repeat_payload.flags & reb::kResponseBodyShared) != 0 &&
            StateOf(repeat_payload) == reb::ResponseBodyState::kCaptured,
        "A repeated body names the first artifact and is not sent again");
  drain();

  // Distinct bodies past what an older session's 512 MiB budget allowed are
  // still retained: nothing counts what a session already kept.
  std::vector<std::uint8_t> sixteen(16 * kMiB);
  for (std::uint8_t fill = 0; fill < 33; ++fill) {
    std::ranges::fill(sixteen, fill);
    const auto retained = Ended(Respond(next++), sixteen);
    Check(StateOf(ResponseRecord(retained)) == reb::ResponseBodyState::kCaptured &&
              transfers.size() == 1 && retained.header.artifact_id != 0,
          "A 16 MiB body past 512 MiB of earlier bodies is retained");
    transfers.clear();
  }

  // A receiver refusal forgets the digest, so a repeat is sent again.
  ConfigureResponses();
  transfers.clear();
  reb::ArtifactReceiver refusing(output / "refusing-response-receiver", {});
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
        "A refused digest is sent again");
  transfers.clear();

  // A body that ended before the disk reserve refused it already has a
  // record naming its artifact, so the refusal follows as a disk_reserve
  // failure joined to its creator.
  reb::ArtifactReceiver full(output / "disk-reserve-response-receiver",
                             {.disk_reserve_bytes = std::numeric_limits<std::uint64_t>::max(),
                              .allow_sensitive = true});
  const auto reserved = Ended(Respond(next++), std::vector<std::uint8_t>(40 * kKiB, 'd'));
  Receive(full, reserved.header.artifact_id, true, reb::ArtifactReceiveStatus::kDiskReserve);
  Check(events.back().header.type == NativeProbeType::kArtifactCaptureFailed &&
            Payload(events.back()) == "disk_reserve" &&
            events.back().header.artifact_id == reserved.header.artifact_id &&
            events.back().header.parent_event_id == reserved.header.parent_event_id,
        "A body the disk reserve refused after its record is a disk_reserve failure");
  transfers.clear();

  // 50 parallel responses all fit: each holds its bytes, not a 16 MiB share.
  ConfigureResponses();
  transfers.clear();
  std::vector<Response> parallel;
  for (int index = 0; index < 50; ++index) {
    parallel.push_back(Respond(next++));
  }
  Check(sink.in_flight_bytes() <= 50 * 256 &&
            std::ranges::all_of(parallel, [](const Response& item) { return item.teed; }),
        "50 parallel bodies are teed and hold only their metadata before their bytes arrive");
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

  // Browser memory is bounded by the pool. A full pool makes the tee wait,
  // holding the source pipe, and the body is kept whole once there is room.
  const std::vector<std::uint8_t> starved_bytes(64 * kKiB, 'z');
  const auto starved = Respond(next++);
  {
    auto held = reb::NativeArtifactReservation::Acquire(
        sink.memory_pool(), sink.memory_pool().stream_mark() - 32 * kKiB,
        reb::NativeArtifactPoolUse::kStream);
    NativeArtifactBodyTee::Deliver(starved.pipe, starved_bytes);
    Check(starved.teed && NativeArtifactBodyTee::Waiting(starved.pipe) == starved_bytes.size(),
          "A body the full pool cannot take waits in its source pipe");
  }
  base::SequencedTaskRunner::RunPosted();
  const auto starved_record = Ended(starved, {});
  Check(StateOf(ResponseRecord(starved_record)) == reb::ResponseBodyState::kCaptured,
        "The waiting body is captured once the pool has room");
  CheckRetained(starved_record, starved, starved_bytes, "body that waited for the pool");
  drain();
  const auto big_a = Respond(next++, {.declared = static_cast<std::int64_t>(16 * kMiB)});
  const auto big_b = Respond(next++, {.declared = static_cast<std::int64_t>(16 * kMiB)});
  Check(big_a.teed && big_b.teed && sink.in_flight_bytes() <= 2 * 256,
        "A declared length reserves nothing beyond the stream's metadata");
  // A body past 16 MiB is kept whole, like any other.
  std::vector<std::uint8_t> huge(16 * kMiB + 4321);
  for (std::size_t index = 0; index < huge.size(); ++index) {
    huge[index] = static_cast<std::uint8_t>(index * 13U);
  }
  const auto whole = Ended(big_a, huge);
  const auto whole_payload = ResponseRecord(whole);
  Check(StateOf(whole_payload) == reb::ResponseBodyState::kCaptured &&
            whole_payload.body_length == huge.size() &&
            whole_payload.captured_length == huge.size(),
        "A body past 16 MiB is captured whole");
  CheckRetained(whole, big_a, huge, "16 MiB + 4321 body");
  const auto before_cancel = sink.in_flight_bytes();
  NativeArtifactBodyTee::End(big_b.pipe, reb::NativeArtifactBodyEnd::kTargetClosed);
  Check(StateOf(ResponseRecord(LastOf(NativeProbeType::kResponseBody))) ==
                reb::ResponseBodyState::kCancelled &&
            sink.in_flight_bytes() < before_cancel && sink.in_flight_bytes() >= huge.size(),
        "A cancelled empty body returns its share");
  drain();
  Check(sink.in_flight_bytes() == 0, "The whole body's share returns once written");

  // Without a completion the body is kept after a bounded wait, flagged.
  auto& runner = *base::SequencedTaskRunner::GetCurrentDefault();
  runner.tasks.clear();
  const auto silent = Respond(next++);
  NativeArtifactBodyTee::Deliver(silent.pipe, body);
  NativeArtifactBodyTee::End(silent.pipe, reb::NativeArtifactBodyEnd::kSourceClosed);
  // The snapshot timer the first chunk posted waits too; the completion wait is the 10 s task.
  const auto wait = std::ranges::find_if(
      runner.tasks, [](const auto& task) { return task.first == 10 * kSecond; });
  Check(wait != runner.tasks.end() && runner.tasks.size() == 2,
        "A finished body waits for its loader completion");
  const auto waiting = events.size();
  const auto timeout = wait->second;
  for (const auto& task : runner.tasks) {
    if (task.first != 10 * kSecond) {
      task.second();
    }
  }
  Check(events.size() == waiting, "A snapshot timer finds an ended body and does nothing");
  timeout();
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

  // Images that page elements load are media, kept like any other body.
  const std::vector<std::uint8_t> gif{'G', 'I', 'F', '8', '9', 'a', 1, 0, 1, 0};
  const auto media = Respond(next++, {.mime = "image/gif", .resource_type = 4});
  CheckRetained(Ended(media, gif), media, gif, "element image");
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
  std::cout << "PASS response body limits: digest dedupe, 528 MiB with no session budget, "
               "receiver and disk reserve refusals, 50 parallel bodies, a wait for the full pool, "
               "a body past 16 MiB kept whole, missing completion, failed and stopped bodies, "
               "coding order, capture-end partial, media by default, metadata-only and tee "
               "refusal\n";
}
