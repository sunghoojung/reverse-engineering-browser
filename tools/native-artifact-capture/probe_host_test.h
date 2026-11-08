// Production NativeProbeHost guest boundary against the production sink.
// Content, Mojo and shared memory are narrow adapters, not a Brave runtime.
struct RecordingProbeClient final : reb::mojom::NativeProbeClient {
  void Configure(std::uint64_t,
                 std::uint64_t,
                 std::uint64_t,
                 bool,
                 base::UnsafeSharedMemoryRegion queue_region,
                 std::uint64_t epoch,
                 const std::string&,
                 const std::vector<std::uint8_t>& js_dispatch_sites,
                 const std::vector<std::uint8_t>& js_invocation_sites,
                 bool js_invocation_digests,
                 bool capture_request_content,
                 bool capture_browser_internal) override {
    ++configured;
    request_content = capture_request_content;
    browser_internal = capture_browser_internal;
    configured_epoch = epoch;
    region = std::move(queue_region);
    js_sites = js_dispatch_sites;
    invocation_sites = js_invocation_sites;
    invocation_digests = js_invocation_digests;
  }
  void SetWasmSampleBudget(const std::vector<std::uint8_t>&) override {}
  void ResetWasmSampleBudgets() override {}
  void Disable() override { ++disabled; }
  void NativeGuestModuleStatus(std::uint64_t epoch, std::uint64_t token, bool accepted) override {
    verdicts.push_back({epoch, token, accepted});
  }
  struct Verdict {
    std::uint64_t epoch, token;
    bool accepted;
  };
  std::uint64_t configured_epoch = 0;
  unsigned configured = 0, disabled = 0;
  bool request_content = false, browser_internal = false;
  std::vector<Verdict> verdicts;
  base::UnsafeSharedMemoryRegion region;
  std::vector<std::uint8_t> js_sites;
  std::vector<std::uint8_t> invocation_sites;
  bool invocation_digests = false;
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
                             1, 8, 0, 4, callee, resolution, 0, 0, 0, "fixture://host-indirect",
                             mojo_base::BigBuffer(indirect_module));
  };
  const auto before_indirect = events.size();
  indirect(epoch + 1, 600, 0, 2);
  indirect(epoch, 601, 5, 0);
  Check(events.size() == before_indirect + 1 &&
            gap_for(601, "native_wasm_indirect_limit_or_invalid") && transfers.empty(),
        "A retired epoch is discarded; an unknown resolution fills its own slot");
  frame.document = {11, 99};
  indirect(epoch, 602, 0, 2);
  indirect(epoch, 603, 0, 2);
  Check(gap_for(602, "native_wasm_indirect_document_unavailable") &&
            gap_for(603, "native_wasm_indirect_document_unavailable") &&
            events.size() == before_indirect + 3 && transfers.empty(),
        "Each observation without its owning document fills its own slot");
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
  // Function 9 has not been claimed. A missing document and a module that is
  // not a call_indirect must not take its one sample.
  session.wasm_budget = {};
  session.wasm_budget.samples_per_function = 1;
  const auto capture_indirect = [&](std::uint64_t sequence,
                                    const std::vector<std::uint8_t>& bytes) {
    host.CaptureWasmIndirect(epoch, kSession, sequence, 100, 123, 7, frame_id, 10, 11, 12, 9, 8, 0,
                             4, 2, 0, 0, 0, 0, "fixture://host-indirect",
                             mojo_base::BigBuffer(bytes));
  };
  frame.document = {11, 99};
  capture_indirect(605, indirect_module);
  Check(gap_for(605, "native_wasm_indirect_document_unavailable") && transfers.empty(),
        "A missing document is refused before the per-function budget");
  frame.document = {11, 12};
  capture_indirect(606, std::vector<std::uint8_t>{1, 2, 3, 4});
  Check(gap_for(606, "native_wasm_indirect_module_invalid") && transfers.empty(),
        "An invalid module is refused before the per-function budget");
  capture_indirect(607, indirect_module);
  Check(std::any_of(events.begin(), events.end(),
                    [](const auto& e) {
                      return e.header.type == NativeProbeType::kWasmIndirectObservation &&
                             e.header.sequence_number == 607;
                    }) &&
            !gap_for(607, "native_wasm_indirect_browser_function_budget_incomplete"),
        "Refusals did not consume function 9's host sample");
  session.wasm_budget = {};
  host.CaptureWasmExecution(epoch, kSession, 610, 100, 123, 7, frame_id, 10, 11, 12, 4, 9, 8, 0, 0,
                            1, 0, 3, 2, 0, 0, "fixture://host-indirect",
                            mojo_base::BigBuffer(indirect_module));
  const auto trap = std::find_if(events.begin(), events.end(), [](const auto& event) {
    return event.header.type == reb::NativeProbeType::kWasmExecutionOutcome &&
           event.header.sequence_number == 610;
  });
  reb::WasmExecutionOutcomePayload trap_payload;
  Check(trap != events.end() &&
            reb::DecodeWasmExecutionOutcomePayload(trap->inline_payload, trap_payload) &&
            trap_payload.reason ==
                static_cast<std::uint8_t>(reb::WasmExecutionReason::kSignatureMismatch) &&
            trap_payload.function_index == 9,
        "The host publishes a signature-mismatch trap for a resolved entry");
  host.CaptureWasmExecution(epoch, kSession, 611, 100, 123, 7, frame_id, 10, 11, 12, 5, 1, 8, 0, 1,
                            0, 0, 3, 2, 0, 0, "fixture://host-indirect",
                            mojo_base::BigBuffer(std::span<const std::uint8_t>{}));
  const auto still = std::find_if(events.begin(), events.end(), [](const auto& event) {
    return event.header.sequence_number == 611;
  });
  reb::WasmExecutionOutcomePayload still_payload;
  Check(still != events.end() && still->header.artifact_id == trap->header.artifact_id &&
            reb::DecodeWasmExecutionOutcomePayload(still->inline_payload, still_payload) &&
            still_payload.kind ==
                static_cast<std::uint8_t>(reb::WasmExecutionKind::kStillExecuting) &&
            still_payload.reason == 0,
        "An empty still-executing record binds the document's one module");

  // caller_observed crosses the host. An unwalked record stays version 2.
  // Zero caller bytes are not an observed host, and a named index on an
  // unwalked record is refused instead of being dropped or published.
  const std::vector<std::uint8_t> dispatch_module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 1, 0, 0};
  const auto wasm_dispatch = [&](std::uint64_t sequence, bool observed, std::uint8_t kind,
                                 std::uint32_t caller_index) {
    host.CaptureWasmDispatch(epoch, kSession, sequence, 100, 123, 7, frame_id, 10, 11, 12, 1, 8, 0,
                             1, observed, kind, caller_index, 0, 0, 0, "fixture://host-dispatch",
                             mojo_base::BigBuffer(dispatch_module));
  };
  const auto published = [&](std::uint64_t sequence) {
    return std::find_if(events.begin(), events.end(), [&](const auto& event) {
      return event.header.type == NativeProbeType::kWasmDispatchObservation &&
             event.header.sequence_number == sequence;
    });
  };
  wasm_dispatch(700, false, reb::kWasmDirectCallerUnknown, 0);
  Check(transfers.size() == 1, "An unwalked dispatch still transfers its module");
  Receive(receiver, transfers.begin()->first);
  reb::WasmDispatchObservationPayload host_payload;
  const auto unwalked = published(700);
  Check(unwalked != events.end() &&
            reb::DecodeWasmDispatchObservationPayload(unwalked->inline_payload, host_payload) &&
            host_payload.protocol_version == 2 && host_payload.caller_kind == 0 &&
            host_payload.caller_function_index == 0,
        "The host keeps an unwalked record at version 2");
  wasm_dispatch(701, true, reb::kWasmDirectCallerUnknown, 0);
  // The module artifact is already bound, so this observation is published
  // without a second transfer.
  if (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  const auto host_unknown = published(701);
  Check(host_unknown != events.end() &&
            reb::DecodeWasmDispatchObservationPayload(host_unknown->inline_payload, host_payload) &&
            host_payload.protocol_version == 3 &&
            host_payload.caller_kind == reb::kWasmDirectCallerUnknown &&
            host_payload.caller_function_index == 0,
        "An observed host caller is version 3 unknown, not function 0");
  const auto before_unwalked_index = events.size();
  wasm_dispatch(702, false, reb::kWasmDirectCallerSameInstance, 4);
  Check(transfers.empty() && gap_for(702, "native_wasm_dispatch_limit_or_invalid") &&
            events.size() == before_unwalked_index + 1,
        "A function index on an unwalked record is a gap, not a dropped caller");
  host.Disable();
  session.active = false;
  session.emitted = {};
  reb::test_guest_adapter = nullptr;
  process.frames.clear();
  std::cout << "PASS production NativeProbeHost guest refusals as explicit gaps, module verdicts "
               "to the renderer, exact host parents and bounded malformed markers\n";
}

// Native JavaScript dispatch records use the ordinary renderer ring: the host
// forwards the session's site records and drains type 21 with tab attribution.
void NativeProbeHostJsDispatchForwarding() {
  record_corpus = false;
  auto& session = reb::NativeProbeSession::Get();
  session.active = true;
  session.id = kSession;
  session.mask = kMask;
  session.expires = 200;
  session.adapter_json.clear();
  reb::NativeJsDispatchSite site;
  site.source_sha256.fill(7);
  site.source_length = 300;
  site.anchor_offset = 41;
  site.shape = reb::NativeJsDispatchShape::kIndexedCall;
  const auto site_record = reb::EncodeNativeJsDispatchSite(site);
  session.js_sites.assign(site_record.begin(), site_record.end());
  reb::NativeJsInvocationSite invocation_site;
  invocation_site.source_sha256.fill(8);
  invocation_site.source_length = 900;
  invocation_site.anchor_offset = 41;
  const auto invocation_record = reb::EncodeNativeJsInvocationSite(invocation_site);
  session.invocation_sites.assign(invocation_record.begin(), invocation_record.end());
  session.invocation_digests = true;
  session.emitted = [](const NativeProbeEvent& event) { Emit(event); };
  Configure(kSession, kMask);
  events.clear();

  auto& process = content::RenderProcessHost::Instance();
  content::RenderFrameHost frame;
  frame.frame = {3, 5};
  frame.document = {11, 12};
  process.frames = {&frame};
  RecordingProbeClient client;
  reb::NativeProbeHost host(session, 1);
  host.BindClient({&client});
  Check(client.js_sites == session.js_sites && client.region.IsValid(),
        "Renderer configuration carries the session's JS dispatch site records");
  Check(client.invocation_sites == session.invocation_sites && client.invocation_digests,
        "Renderer configuration carries the invocation sites and the digest opt-in");

  reb::NativeJsDispatchObservationPayload payload;
  payload.shape = 2;
  payload.selector_kind = 1;
  payload.script_id = 9;
  payload.anchor_offset = 41;
  payload.source_length = 300;
  payload.selector_low32 = 3;
  payload.activation_id = 1;
  payload.source_sha256 = site.source_sha256;
  NativeProbeEvent record;
  record.header.category = reb::NativeProbeCategory::kVm;
  record.header.type = NativeProbeType::kJsDispatchObservation;
  record.header.payload_size = 128;
  record.header.session_id = kSession;
  record.header.process_id = 123;
  record.header.thread_id = 7;
  record.header.frame_id = std::rotl(std::uint64_t{3}, 17) ^ std::uint64_t{5};
  record.header.sequence_number = 601;
  record.header.monotonic_time_ns = 100;
  const auto bytes = reb::EncodeNativeJsDispatchObservationPayload(payload);
  std::copy(bytes.begin(), bytes.end(), record.inline_payload.begin());
  auto mapping = client.region.Map();
  auto* queue = static_cast<reb::NativeProbeQueue*>(mapping.memory());
  Check(queue->TryPush(record), "Renderer ring admits the JS dispatch record");
  host.EventsAvailable();
  Check(events.size() == 1 && events[0].header.type == NativeProbeType::kJsDispatchObservation &&
            events[0].header.tab_id == 1 && events[0].header.sequence_number == 601 &&
            reb::IsValidNativeJsDispatchHeader(events[0].header) &&
            std::equal(bytes.begin(), bytes.end(), events[0].inline_payload.begin()),
        "Host forwards the JS dispatch record unchanged with its tab");
  // An invocation start rides the same ring and is forwarded unchanged.
  reb::NativeJsInvocationStartPayload start;
  start.argument_count = 1;
  start.argument_kinds[0] = 3;
  start.script_id = 9;
  start.anchor_offset = 41;
  start.source_length = 900;
  start.invocation_id = 4;
  start.source_sha256 = invocation_site.source_sha256;
  start.document_id = 77;
  NativeProbeEvent start_record = record;
  start_record.header.type = NativeProbeType::kJsInvocationStart;
  start_record.header.sequence_number = 602;
  start_record.inline_payload = reb::EncodeNativeJsInvocationStartPayload(start);
  Check(queue->TryPush(start_record), "Renderer ring admits the invocation start");
  host.EventsAvailable();
  Check(events.size() == 2 && events[1].header.type == NativeProbeType::kJsInvocationStart &&
            events[1].header.tab_id == 1 &&
            reb::IsValidNativeJsInvocationStartHeader(events[1].header) &&
            events[1].inline_payload == start_record.inline_payload,
        "Host forwards the invocation start unchanged with its tab");
  start_record.header.sequence_number = 603;
  Check(queue->TryPush(start_record), "Renderer ring admits a record before disable");
  host.Disable();
  Check(events.size() == 3 && events[2].header.sequence_number == 603,
        "Disable publishes what the renderer already queued");
  session.active = false;
  session.js_sites.clear();
  session.invocation_sites.clear();
  session.invocation_digests = false;
  session.emitted = {};
  process.frames.clear();
  std::cout << "PASS production NativeProbeHost forwards JS dispatch site records and type 21 "
               "ring records with tab attribution\n";
}

// protocol/native-network-v3.md: queue exclusion counters become cumulative
// reports, and a renderer granted WebUI bindings leaves with what it queued.
void NativeProbeHostBrowserInternalScope() {
  auto& session = reb::NativeProbeSession::Get();
  session.active = true;
  session.id = kSession;
  session.mask = kMask;
  session.expires = 200;
  session.request_content = true;
  session.exclusions.clear();
  session.webui_excluded = 0;
  session.emitted = [](const NativeProbeEvent& event) { Emit(event); };
  Configure(kSession, kMask);
  events.clear();
  auto& security = *content::ChildProcessSecurityPolicy::GetInstance();
  RecordingProbeClient client;
  reb::NativeProbeHost host(session, 1);
  host.BindClient({&client});
  Check(client.configured == 1 && client.request_content && !client.browser_internal,
        "Renderer configuration carries the request content and browser-internal gates");
  auto mapping = client.region.Map();
  auto* queue = static_cast<reb::NativeProbeQueue*>(mapping.memory());
  queue->CountExclusion(reb::NativeSchemeClass::kChrome);
  queue->CountExclusion(reb::NativeSchemeClass::kChrome);
  queue->CountExclusion(reb::NativeSchemeClass::kDevTools);
  queue->CountExclusion(reb::NativeSchemeClass::kHttps);
  host.EventsAvailable();
  host.EventsAvailable();
  Check(session.exclusions.size() == 2 && session.exclusions[0].process == 123 &&
            session.exclusions[0].exclusion_class == 16 && session.exclusions[0].count == 2 &&
            session.exclusions[1].exclusion_class == 19 && session.exclusions[1].count == 1 &&
            events.empty(),
        "Each changed class is reported once with its cumulative count, without records");
  queue->CountExclusion(reb::NativeSchemeClass::kChrome);
  host.EventsAvailable();
  Check(session.exclusions.size() == 3 && session.exclusions[2].count == 3,
        "A later count supersedes the earlier report");

  NativeProbeEvent record;
  record.header.category = reb::NativeProbeCategory::kNetwork;
  record.header.type = NativeProbeType::kRequestInitiated;
  record.header.session_id = kSession;
  record.header.process_id = 123;
  record.header.sequence_number = 700;
  record.header.monotonic_time_ns = 100;
  Check(queue->TryPush(record), "Renderer ring admits a record before the WebUI grant");
  security.webui.insert(1);
  host.EventsAvailable();
  Check(events.empty() && session.webui_excluded == 1 && client.disabled != 0,
        "A renderer granted WebUI bindings is detached and its queued records are discarded");
  host.BindClient({&client});
  Check(client.configured == 1 && session.webui_excluded == 1,
        "A detached WebUI renderer is never configured again and counts once");
  security.webui.clear();

  session.browser_internal = true;
  security.webui.insert(1);
  RecordingProbeClient opted;
  reb::NativeProbeHost admitted(session, 1);
  admitted.BindClient({&opted});
  Check(opted.configured == 1 && opted.browser_internal && session.webui_excluded == 1,
        "--reb-capture-browser-internal keeps WebUI renderers");
  security.webui.clear();
  session.browser_internal = false;
  session.request_content = false;
  session.active = false;
  session.emitted = {};
  std::cout << "PASS production NativeProbeHost reports cumulative exclusions and detaches "
               "renderers granted WebUI bindings\n";
}
