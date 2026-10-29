// Production NativeProbeHost guest boundary against the production sink.
// Content, Mojo and shared memory are narrow adapters, not a Brave runtime.
struct RecordingProbeClient final : reb::mojom::NativeProbeClient {
  void Configure(std::uint64_t,
                 std::uint64_t,
                 std::uint64_t,
                 bool,
                 base::UnsafeSharedMemoryRegion,
                 std::uint64_t epoch,
                 const std::string&) override {
    configured_epoch = epoch;
  }
  void Disable() override {}
  void NativeGuestModuleStatus(std::uint64_t epoch, std::uint64_t token, bool accepted) override {
    verdicts.push_back({epoch, token, accepted});
  }
  struct Verdict {
    std::uint64_t epoch, token;
    bool accepted;
  };
  std::uint64_t configured_epoch = 0;
  std::vector<Verdict> verdicts;
};

void NativeProbeHostGuestBoundary(reb::ArtifactReceiver& receiver) {
  record_corpus = false;
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  transfers.clear();
  const std::vector<std::uint8_t> module{0, 97, 115, 109, 1, 0, 0, 0, 14, 1, 0, 0}, code{7, 8, 9};
  const std::string recipe = "{\"host\":1}";
  auto adapter = std::make_shared<reb::NativeWasmGuestAdapter>();
  adapter->json = recipe;
  adapter->module_sha256 = reb::NativeGuestDigest(module);
  adapter->recipe_sha256 = reb::NativeGuestDigest(
      std::span(reinterpret_cast<const std::uint8_t*>(recipe.data()), recipe.size()));
  adapter->sites[0].function_index = 1;
  adapter->sites[0].dispatch_module_offset = 8;
  adapter->sites[1].function_index = 2;  // A second dispatcher of the same module.
  adapter->sites[1].dispatch_module_offset = 9;
  adapter->site_count = 2;
  adapter->sample_limit = 16;
  reb::test_guest_adapter = adapter;

  const auto mask = kMask | reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas);
  auto& session = reb::NativeProbeSession::Get();
  session.active = true;
  session.id = kSession;
  session.mask = mask;
  session.expires = 200;
  session.adapter_json = recipe;
  session.emitted = [](const NativeProbeEvent& event) { Emit(event); };
  Configure(kSession, mask);
  events.clear();

  auto& process = content::RenderProcessHost::Instance();
  content::RenderFrameHost frame;
  frame.frame = {3, 5};
  frame.document = {11, 12};
  process.frames = {&frame};
  const std::uint64_t frame_id = std::rotl(std::uint64_t{3}, 17) ^ std::uint64_t{5};

  RecordingProbeClient client;
  reb::NativeProbeHost host(session, 1);
  host.BindClient({&client});
  Check(client.configured_epoch != 0, "Binding an active session configures the renderer");
  const auto epoch = client.configured_epoch;

  NativeProbeEvent invocation, dispatch;
  auto& d = dispatch.header;
  d.category = reb::NativeProbeCategory::kVm;
  d.type = NativeProbeType::kWasmGuestDispatch;
  d.session_id = kSession;
  d.process_id = 123;
  d.thread_id = 7;
  d.frame_id = frame_id;
  d.sequence_number = 501;
  d.parent_event_id = 500;
  d.monotonic_time_ns = 100;
  d.payload_size = 128;
  invocation.header = d;
  invocation.header.type = NativeProbeType::kWasmGuestInvocation;
  invocation.header.sequence_number = 500;
  invocation.header.parent_event_id = 0;
  reb::NativeGuestPut(dispatch.inline_payload, 0, 1, 2);
  reb::NativeGuestPut(dispatch.inline_payload, 2, 128, 2);
  reb::NativeGuestPut(dispatch.inline_payload, 4, 1, 4);
  reb::NativeGuestPut(dispatch.inline_payload, 8, 8, 4);
  reb::NativeGuestPut(dispatch.inline_payload, 24, 20, 8);
  reb::NativeGuestPut(dispatch.inline_payload, 32, 30, 8);
  reb::NativeGuestPut(dispatch.inline_payload, 72, code.size(), 4);
  reb::NativeGuestPut(dispatch.inline_payload, 92, 7, 4);
  reb::NativeGuestPut(invocation.inline_payload, 0, 3, 2);
  reb::NativeGuestPut(invocation.inline_payload, 2, 128, 2);
  reb::NativeGuestPut(invocation.inline_payload, 4, 1, 4);
  reb::NativeGuestPut(invocation.inline_payload, 8, 20, 8);
  reb::NativeGuestPut(invocation.inline_payload, 16, 30, 8);
  for (std::size_t n = 0; n < 32; ++n) {
    dispatch.inline_payload[96 + n] = static_cast<std::byte>(adapter->recipe_sha256[n]);
    invocation.inline_payload[32 + n] = static_cast<std::byte>(adapter->recipe_sha256[n]);
  }
  const auto record = [](const NativeProbeEvent& event) {
    std::vector<std::uint8_t> bytes(sizeof(event));
    std::memcpy(bytes.data(), &event, sizeof(event));
    return bytes;
  };
  const auto send = [&](std::span<const std::uint8_t> module_bytes, const std::string& json) {
    host.CaptureNativeGuest(epoch, record(invocation), record(dispatch), 10, 11, 12,
                            "fixture://host-guest", json, mojo_base::BigBuffer(module_bytes),
                            mojo_base::BigBuffer(code));
  };
  const auto gap_for = [&](std::uint64_t sequence, std::string_view reason) {
    return std::any_of(events.begin(), events.end(), [&](const auto& e) {
      return e.header.type == NativeProbeType::kGap && e.header.process_id == 123 &&
             e.header.sequence_number == sequence && Payload(e) == reason;
    });
  };

  send(module, "{\"other\":1}");
  Check(transfers.empty() && gap_for(501, "native_guest_adapter_mismatch") &&
            client.verdicts.size() == 1 && !client.verdicts.back().accepted &&
            client.verdicts.back().token == 501,
        "Adapter mismatch is an explicit gap and a module rejection");
  frame.document = {11, 99};
  d.sequence_number = 502;
  send(module, recipe);
  Check(transfers.empty() && gap_for(502, "native_guest_document_unavailable") &&
            client.verdicts.size() == 2 && client.verdicts.back().token == 502,
        "Missing owning document is an explicit gap and a module rejection");
  frame.document = {11, 12};
  d.sequence_number = 503;
  auto corrupt = module;
  corrupt[11] = 9;
  send(corrupt, recipe);
  Check(transfers.empty() && gap_for(503, "native_guest_module_mismatch"),
        "Module digest mismatch is explicit");
  d.sequence_number = 504;
  send({}, recipe);
  Check(transfers.empty() && gap_for(504, "native_guest_module_unbound") &&
            client.verdicts.size() == 3,
        "An empty module never produces a verdict");
  d.sequence_number = 505;
  send(module, recipe);
  Check(transfers.size() == 3, "A valid capture reaches the production sink");
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  Check(client.verdicts.size() == 4 && client.verdicts.back().accepted &&
            client.verdicts.back().token == 505 && client.verdicts.back().epoch == epoch,
        "Accepted module binding is reported back to the renderer");

  auto api = dispatch;
  api.header.category = reb::NativeProbeCategory::kCanvas;
  api.header.type = NativeProbeType::kApiCall;
  api.header.sequence_number = 506;
  api.header.parent_event_id = 505;
  api.header.payload_size = 0;
  api.inline_payload = {};
  host.CaptureNativeGuestHost(epoch, record(api));
  Check(events.back().header.sequence_number == 506 &&
            events.back().header.parent_event_id == 505 && events.back().header.tab_id == 1,
        "Host keeps its exact parent and tab");
  const auto before_malformed = events.size();
  api.header.process_id = 999;
  api.header.sequence_number = 507;
  host.CaptureNativeGuestHost(epoch, record(api));
  api.header.sequence_number = 508;
  host.CaptureNativeGuestHost(epoch, record(api));
  Check(events.size() == before_malformed + 1 &&
            Payload(events.back()) == "native_guest_host_malformed",
        "Foreign host identity has one bounded marker");

  // A dispatch at site 1 is admitted only from an activation whose marker
  // names site 1; both sites count against the one browser sample budget.
  invocation.header.sequence_number = 510;
  d.sequence_number = 511;
  d.parent_event_id = 510;
  reb::NativeGuestPut(invocation.inline_payload, 4, 2, 4);
  reb::NativeGuestPut(invocation.inline_payload, 16, 31, 8);
  reb::NativeGuestPut(dispatch.inline_payload, 4, 2, 4);
  reb::NativeGuestPut(dispatch.inline_payload, 8, 9, 4);
  reb::NativeGuestPut(dispatch.inline_payload, 32, 31, 8);
  send({}, recipe);
  Check(transfers.empty() && gap_for(511, "native_guest_capture_invalid"),
        "A site 1 dispatch under a site 0 marker is an explicit gap");
  reb::NativeGuestPut(invocation.inline_payload, 80, 1, 4);
  d.sequence_number = 512;
  send({}, recipe);
  Check(transfers.size() == 1 && !gap_for(512, "native_guest_capture_invalid"),
        "A site 1 dispatch under its own marker reaches the production sink");
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  Check(std::any_of(events.begin(), events.end(),
                    [](const auto& e) {
                      return e.header.sequence_number == 510 &&
                             e.inline_payload[80] == std::byte{1};
                    }),
        "The published marker keeps its site");
  const auto stale = events.size();
  d.sequence_number = 509;
  host.CaptureNativeGuest(epoch + 1, record(invocation), record(dispatch), 10, 11, 12,
                          "fixture://host-guest", recipe, mojo_base::BigBuffer(module),
                          mojo_base::BigBuffer(code));
  Check(events.size() == stale && transfers.empty(),
        "A retired configuration's capture is discarded like its queue records");

  // Physical call_indirect through the production host: stale epochs and
  // invalid resolutions are discarded, a missing document is one bounded gap.
  const std::vector<std::uint8_t> indirect_module{0, 97, 115, 109, 1, 0, 0, 0, 0x11, 0, 0};
  const auto indirect = [&](std::uint64_t capture_epoch, std::uint64_t sequence,
                            std::uint32_t resolution, std::uint32_t callee) {
    host.CaptureWasmIndirect(capture_epoch, kSession, sequence, 100, 123, 7, frame_id, 10, 11, 12,
                             1, 8, 0, 4, callee, resolution, 0, "fixture://host-indirect",
                             mojo_base::BigBuffer(indirect_module));
  };
  const auto before_indirect = events.size();
  indirect(epoch + 1, 600, 0, 2);
  indirect(epoch, 601, 5, 0);
  Check(events.size() == before_indirect && transfers.empty(),
        "Retired epochs and unknown resolutions are discarded");
  frame.document = {11, 99};
  indirect(epoch, 602, 0, 2);
  indirect(epoch, 603, 0, 2);
  Check(gap_for(602, "native_wasm_indirect_document_unavailable") &&
            events.size() == before_indirect + 1 && transfers.empty(),
        "A missing owning document is one bounded gap");
  frame.document = {11, 12};
  indirect(epoch, 604, 0, 2);
  Check(transfers.size() == 1, "A valid call_indirect observation reaches the production sink");
  Receive(receiver, transfers.begin()->first);
  Check(std::any_of(events.begin(), events.end(),
                    [](const auto& e) {
                      return e.header.type == NativeProbeType::kWasmIndirectObservation &&
                             e.header.sequence_number == 604 && e.header.tab_id == 1;
                    }),
        "The host keeps the observation's own sequence and tab");
  host.Disable();
  session.active = false;
  session.emitted = {};
  reb::test_guest_adapter = nullptr;
  process.frames.clear();
  std::cout << "PASS production NativeProbeHost guest refusals as explicit gaps, module verdicts "
               "to the renderer, exact host parents and bounded malformed markers\n";
}
