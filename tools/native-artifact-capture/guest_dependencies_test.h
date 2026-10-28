
// Production sink + real artifact receiver: no independent fake dependency model.
void NativeGuestDependencies(reb::ArtifactReceiver& receiver) {
  record_corpus = false;
  auto& sink = NativeArtifactCaptureSink::Get();
  auto& transfers = NativeArtifactSocketClient::Get().transfers;
  const auto configure = [&] {
    Configure(kSession, kMask | reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas));
  };
  transfers.clear();
  configure();
  events.clear();
  const std::vector<std::uint8_t> module{0, 97, 115, 109, 1, 0, 0, 0, 14, 1, 0, 0}, code{7, 8, 9};
  const std::string recipe = "{}";
  reb::NativeGuestCapture capture;
  capture.execution_context_id = 10;
  capture.document_token_high = 11;
  capture.document_token_low = 12;
  capture.source_url = "fixture://guest-dependencies";
  capture.adapter_json = recipe;
  capture.module_bytes = module;
  capture.bytecode_bytes = code;
  auto& d = capture.dispatch;
  d.header.category = reb::NativeProbeCategory::kVm;
  d.header.type = NativeProbeType::kWasmGuestDispatch;
  d.header.session_id = kSession;
  d.header.process_id = 123;
  d.header.thread_id = 7;
  d.header.frame_id = kFrame;
  d.header.sequence_number = 101;
  d.header.parent_event_id = 100;
  d.header.monotonic_time_ns = 100;
  d.header.payload_size = 128;
  auto& i = capture.invocation;
  i.header = d.header;
  i.header.type = NativeProbeType::kWasmGuestInvocation;
  i.header.sequence_number = 100;
  i.header.parent_event_id = 0;
  reb::NativeGuestPut(d.inline_payload, 0, 1, 2);
  reb::NativeGuestPut(d.inline_payload, 2, 128, 2);
  reb::NativeGuestPut(d.inline_payload, 8, 8, 4);
  reb::NativeGuestPut(d.inline_payload, 16, 1, 4);
  reb::NativeGuestPut(d.inline_payload, 24, 20, 8);
  reb::NativeGuestPut(d.inline_payload, 32, 30, 8);
  reb::NativeGuestPut(d.inline_payload, 72, code.size(), 4);
  reb::NativeGuestPut(d.inline_payload, 92, 7, 4);
  reb::NativeGuestPut(i.inline_payload, 0, 1, 2);
  reb::NativeGuestPut(i.inline_payload, 2, 128, 2);
  reb::NativeGuestPut(i.inline_payload, 8, 20, 8);
  reb::NativeGuestPut(i.inline_payload, 16, 30, 8);
  const auto digest = reb::NativeGuestDigest(
      std::span(reinterpret_cast<const std::uint8_t*>(recipe.data()), recipe.size()));
  for (std::size_t n = 0; n < digest.size(); ++n) {
    d.inline_payload[96 + n] = static_cast<std::byte>(digest[n]);
    i.inline_payload[32 + n] = static_cast<std::byte>(digest[n]);
  }
  const auto typed = [&] {
    std::vector<NativeProbeEvent> result;
    for (const auto& e : events)
      if (e.header.process_id == 123 && (e.header.type == NativeProbeType::kWasmGuestInvocation ||
                                         e.header.type == NativeProbeType::kWasmGuestDispatch ||
                                         e.header.type == NativeProbeType::kApiCall))
        result.push_back(e);
    return result;
  };
  bool current = true;
  std::vector<bool> verdicts;
  const auto status = [&](bool accepted) { verdicts.push_back(accepted); };
  const auto gap_for = [&](std::uint64_t sequence, std::string_view reason) {
    return std::any_of(events.begin(), events.end(), [&](const auto& e) {
      return e.header.type == NativeProbeType::kGap && e.header.process_id == 123 &&
             e.header.sequence_number == sequence && Payload(e) == reason;
    });
  };
  const auto browser_gap = [&](std::string_view reason) {
    return std::count_if(events.begin(), events.end(), [&](const auto& e) {
      return e.header.type == NativeProbeType::kGap && Payload(e) == reason;
    });
  };
  const auto artifact_of = [&](reb::NativeArtifactKind kind) {
    for (const auto& [id, t] : transfers)
      if (t->header.kind == kind)
        return id;
    return std::uint64_t{0};
  };
  const auto receive_all = [&] {
    while (!transfers.empty())
      Receive(receiver, transfers.begin()->first);
  };
  sink.CaptureNativeGuest(capture, 1, [&] { return current; }, status);
  Check(transfers.size() == 3 && typed().empty(), "Guest capture waits for artifact receipts");
  const auto module_id = artifact_of(reb::NativeArtifactKind::kWasm);
  const auto adapter_id = artifact_of(reb::NativeArtifactKind::kWasmGuestAdapter);
  const auto snapshot_id = artifact_of(reb::NativeArtifactKind::kBytecodeBuffer);
  Check(transfers.at(adapter_id)->header.creator_event_id == 100 &&
            transfers.at(snapshot_id)->header.creator_event_id == 101 &&
            transfers.at(adapter_id)->header.parent_artifact_id == module_id,
        "Artifact creator references preserve real renderer sequences");
  auto host = d;
  host.header.type = NativeProbeType::kApiCall;
  host.header.category = reb::NativeProbeCategory::kCanvas;
  host.header.sequence_number = 102;
  host.header.parent_event_id = 101;
  host.header.payload_size = 0;
  host.inline_payload = {};
  sink.CaptureNativeGuestHost(host, 1);
  Receive(receiver, snapshot_id);
  Check(typed().empty() && verdicts.empty(), "Snapshot alone cannot publish ancestry");
  Receive(receiver, adapter_id);
  Check(typed().empty() && verdicts.empty(), "Adapter alone cannot release missing module");
  Receive(receiver, module_id);
  const auto emitted = typed();
  Check(emitted.size() == 3 && emitted[0].header.sequence_number == 100 &&
            emitted[1].header.sequence_number == 101 && emitted[2].header.sequence_number == 102,
        "Out-of-order ACK releases invocation then dispatch then host");
  Check(verdicts == std::vector<bool>{true}, "Accepted module binding is reported to the renderer");
  Check(reb::IsValidWasmGuestInvocation(std::bit_cast<reb::EventRecord>(emitted[0])) &&
            reb::IsValidWasmGuestDispatch(std::bit_cast<reb::EventRecord>(emitted[1])),
        "Produced guest records pass the actual core validators");
  Check(emitted[2].header.artifact_id == module_id && emitted[2].header.parent_event_id == 101,
        "Host retains module and genuine dispatch parent");
  NativeArtifactCaptureSink::TransferCompleted(module_id,
                                               reb::NativeArtifactReceiveStatus::kAccepted);
  sink.CaptureNativeGuestHost(host, 1);
  Check(typed().size() == 3, "Repeated ACK and host cannot duplicate evidence");
  host.header.sequence_number = 103;
  sink.CaptureNativeGuestHost(host, 1);
  Check(typed().size() == 4 && typed().back().header.parent_event_id == 101,
        "A host after publication keeps its parent without waiting");

  capture.module_bytes = {};
  d.header.sequence_number = 104;
  sink.CaptureNativeGuest(capture, 1, [&] { return current; });
  Check(transfers.size() == 1 &&
            transfers.begin()->second->header.kind == reb::NativeArtifactKind::kBytecodeBuffer,
        "Later dispatch reuses exact module and adapter");
  Receive(receiver, transfers.begin()->first);
  Check(typed().size() == 5 && typed().back().header.sequence_number == 104,
        "Invocation emitted only once");
  d.header.sequence_number = 105;
  sink.CaptureNativeGuest(capture, 1, [&] { return current; });
  host.header.sequence_number = 106;
  host.header.parent_event_id = 105;
  sink.CaptureNativeGuestHost(host, 1);
  current = false;
  Receive(receiver, transfers.begin()->first);
  Check(typed().size() == 6 && typed().back().header.sequence_number == 106 &&
            typed().back().header.parent_event_id == 0,
        "Navigation loses the dispatch but keeps its held host, unparented");
  Check(gap_for(105, "native_guest_dependency_lost"),
        "Lost dispatch fills its own sequence slot with a gap");
  current = true;

  d.header.sequence_number = 107;
  sink.CaptureNativeGuest(capture, 1, [&] { return current; });
  const auto retired = transfers.begin()->first;
  configure();
  Receive(receiver, retired);
  Check(typed().size() == 6, "Same-session reconfiguration rejects old dependencies");
  d.header.sequence_number = 108;
  sink.CaptureNativeGuest(capture, 1, [] { return true; });
  Check(transfers.empty() && gap_for(108, "native_guest_module_unbound"),
        "Unknown empty module is refused explicitly");

  // A rejected module artifact is reported and can be resent, within bounds.
  verdicts.clear();
  capture.module_bytes = module;
  d.header.sequence_number = 109;
  sink.CaptureNativeGuest(capture, 1, [] { return true; }, status);
  Check(transfers.size() == 3, "Fresh configuration needs fresh module and recipe");
  d.header.sequence_number = 110;
  capture.module_bytes = {};
  sink.CaptureNativeGuest(capture, 1, [] { return true; });
  const auto first_module = artifact_of(reb::NativeArtifactKind::kWasm);
  NativeArtifactCaptureSink::TransferCompleted(first_module,
                                               reb::NativeArtifactReceiveStatus::kIoError);
  transfers.erase(first_module);
  receive_all();
  Check(verdicts == std::vector<bool>{false}, "Rejected module is reported to the renderer");
  Check(
      gap_for(109, "native_guest_dependency_lost") && gap_for(110, "native_guest_dependency_lost"),
      "Dispatches bound to the rejected module become explicit gaps");
  d.header.sequence_number = 111;
  sink.CaptureNativeGuest(capture, 1, [] { return true; });
  Check(transfers.empty() && gap_for(111, "native_guest_module_lost"),
        "Failed binding refuses empty-module samples explicitly");
  capture.module_bytes = module;
  d.header.sequence_number = 112;
  sink.CaptureNativeGuest(capture, 1, [] { return true; }, status);
  Check(transfers.size() == 3, "Resent module retries the binding");
  const auto before_retry = typed().size();
  receive_all();
  Check(verdicts == std::vector<bool>{false, true} && typed().size() == before_retry + 2,
        "Retried binding publishes the invocation and dispatch");
  configure();
  verdicts.clear();
  for (std::uint8_t attempt = 0; attempt < reb::kNativeGuestModuleAttemptLimit; ++attempt) {
    d.header.sequence_number = 120 + attempt;
    NativeArtifactSocketClient::Get().reject_next = true;
    sink.CaptureNativeGuest(capture, 1, [] { return true; }, status);
  }
  Check(transfers.empty() && verdicts.size() == reb::kNativeGuestModuleAttemptLimit,
        "Each failed module transfer is refused and reported");
  d.header.sequence_number = 130;
  sink.CaptureNativeGuest(capture, 1, [] { return true; }, status);
  Check(transfers.empty() && gap_for(130, "native_guest_module_unavailable") &&
            verdicts.size() == reb::kNativeGuestModuleAttemptLimit + 1u,
        "Module attempts are bounded");

  // Hosts whose parent never existed are kept, unparented, with one marker.
  configure();
  host.header.sequence_number = 131;
  host.header.parent_event_id = 99;
  const auto before_lost = typed().size();
  sink.CaptureNativeGuestHost(host, 1);
  host.header.sequence_number = 132;
  sink.CaptureNativeGuestHost(host, 1);
  Check(typed().size() == before_lost + 2 && typed().back().header.parent_event_id == 0 &&
            browser_gap("native_guest_host_parent_lost") >= 1,
        "Lost-parent hosts are published unparented");
  const auto malformed_before = events.size();
  auto malformed = host;
  malformed.header.sequence_number = 133;
  malformed.header.category = reb::NativeProbeCategory::kVm;
  sink.CaptureNativeGuestHost(malformed, 1);
  malformed.header.sequence_number = 134;
  sink.CaptureNativeGuestHost(malformed, 1);
  Check(events.size() == malformed_before + 1, "Malformed hosts have one bounded marker");

  // Held hosts are bounded; overflow is published at once without parent.
  configure();
  d.header.sequence_number = 140;
  sink.CaptureNativeGuest(capture, 2, [] { return true; });
  for (std::size_t n = 0; n <= reb::kNativeGuestHeldHostLimit; ++n) {
    host.header.sequence_number = 200 + n;
    host.header.parent_event_id = 140;
    sink.CaptureNativeGuestHost(host, 2);
  }
  Check(typed().back().header.sequence_number == 200 + reb::kNativeGuestHeldHostLimit &&
            typed().back().header.parent_event_id == 0 &&
            browser_gap("native_guest_host_parent_omitted") >= 1,
        "Held-host overflow is published without its parent");
  const auto before_release = typed().size();
  receive_all();
  Check(typed().size() == before_release + 2 + reb::kNativeGuestHeldHostLimit,
        "Held hosts are released after their parent");

  // Shortly before expiry, unresolved work becomes explicit gaps.
  auto& runner = *base::SequencedTaskRunner::GetCurrentDefault();
  runner.tasks.clear();
  configure();
  Check(runner.tasks.size() == 1 && runner.tasks.back().first == 0,
        "Configuration schedules a pre-expiry flush");
  d.header.sequence_number = 300;
  sink.CaptureNativeGuest(capture, 3, [] { return true; });
  host.header.sequence_number = 301;
  host.header.parent_event_id = 300;
  sink.CaptureNativeGuestHost(host, 3);
  const auto before_flush = typed().size();
  runner.tasks.back().second();
  Check(gap_for(300, "native_guest_pending_at_expiry") && typed().size() == before_flush + 1 &&
            typed().back().header.sequence_number == 301,
        "Pre-expiry flush reports pending dispatches and keeps held hosts");
  receive_all();
  const auto published_300 = [&] {
    const auto all = typed();
    return std::any_of(all.begin(), all.end(), [](const auto& e) {
      return e.header.type == NativeProbeType::kWasmGuestDispatch &&
             e.header.sequence_number == 300;
    });
  };
  Check(!published_300(), "Flushed work is never published afterward");
  base::test_now_ns = 201;
  d.header.sequence_number = 302;
  sink.CaptureNativeGuest(capture, 3, [] { return true; });
  Check(transfers.empty(), "Expired captures admit nothing");
  base::test_now_ns = 100;
  configure();
  d.header.sequence_number = 303;
  sink.CaptureNativeGuest(capture, 3, [] { return true; });
  runner.tasks.front().second();
  Check(!gap_for(303, "native_guest_pending_at_expiry"),
        "A replaced configuration's flush is a no-op");
  receive_all();
  runner.tasks.clear();

  configure();
  d.header.sequence_number = 400;
  sink.CaptureNativeGuest(capture, 4, [] { return true; });
  capture.module_bytes = {};
  for (std::size_t n = 1; n < reb::kNativeGuestSampleLimit; ++n) {
    d.header.sequence_number = 400 + n;
    sink.CaptureNativeGuest(capture, 4, [] { return true; });
  }
  Check(transfers.size() == reb::kNativeGuestSampleLimit + 2,
        "Entire sample budget shares one module and adapter");
  d.header.sequence_number = 1000;
  sink.CaptureNativeGuest(capture, 4, [] { return true; });
  Check(transfers.size() == reb::kNativeGuestSampleLimit + 2 &&
            gap_for(1000, "native_guest_browser_sample_budget"),
        "Dependency count budget enforced explicitly");
  const auto capped = events.size();
  d.header.sequence_number = 1001;
  sink.CaptureNativeGuest(capture, 4, [] { return true; });
  Check(events.size() == capped, "Budget omission bounded");
  configure();
  transfers.clear();
  capture.module_bytes = module;
  capture.dispatch.header.category = reb::NativeProbeCategory::kCanvas;
  capture.dispatch.header.sequence_number = 1002;
  sink.CaptureNativeGuest(capture, 1, [] { return true; });
  Check(transfers.empty() && gap_for(1002, "native_guest_dependency_rejected"),
        "Wrong invocation or dispatch category rejected");
  std::cout << "PASS production guest ACK ordering, module verdicts and bounded retry, exact host "
               "parents without host loss, pre-expiry flush and explicit gaps\n";
}
