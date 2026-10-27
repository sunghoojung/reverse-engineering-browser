
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
  sink.CaptureNativeGuest(capture, 1, [&] { return current; });
  Check(transfers.size() == 3 && typed().empty(), "Guest capture waits for artifact receipts");
  std::uint64_t module_id = 0, adapter_id = 0, snapshot_id = 0;
  for (const auto& [id, t] : transfers) {
    if (t->header.kind == reb::NativeArtifactKind::kWasm)
      module_id = id;
    if (t->header.kind == reb::NativeArtifactKind::kWasmGuestAdapter)
      adapter_id = id;
    if (t->header.kind == reb::NativeArtifactKind::kBytecodeBuffer)
      snapshot_id = id;
  }
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
  Check(typed().empty(), "Snapshot alone cannot publish ancestry");
  Receive(receiver, adapter_id);
  Check(typed().empty(), "Adapter alone cannot release missing module");
  Receive(receiver, module_id);
  const auto emitted = typed();
  Check(emitted.size() == 3 && emitted[0].header.sequence_number == 100 &&
            emitted[1].header.sequence_number == 101 && emitted[2].header.sequence_number == 102,
        "Out-of-order ACK releases invocation then dispatch then host");
  Check(reb::IsValidWasmGuestInvocation(std::bit_cast<reb::EventRecord>(emitted[0])) &&
            reb::IsValidWasmGuestDispatch(std::bit_cast<reb::EventRecord>(emitted[1])),
        "Produced guest records pass the actual core validators");
  Check(emitted[2].header.artifact_id == module_id && emitted[2].header.parent_event_id == 101,
        "Host retains module and genuine dispatch parent");
  NativeArtifactCaptureSink::TransferCompleted(module_id,
                                               reb::NativeArtifactReceiveStatus::kAccepted);
  sink.CaptureNativeGuestHost(host, 1);
  Check(typed().size() == 3, "Repeated ACK and host cannot duplicate evidence");
  capture.module_bytes = {};
  d.header.sequence_number = 103;
  sink.CaptureNativeGuest(capture, 1, [&] { return current; });
  Check(transfers.size() == 1 &&
            transfers.begin()->second->header.kind == reb::NativeArtifactKind::kBytecodeBuffer,
        "Later dispatch reuses exact module and adapter");
  Receive(receiver, transfers.begin()->first);
  Check(typed().size() == 4 && typed().back().header.sequence_number == 103,
        "Invocation emitted only once");
  d.header.sequence_number = 104;
  sink.CaptureNativeGuest(capture, 1, [&] { return current; });
  current = false;
  Receive(receiver, transfers.begin()->first);
  Check(typed().size() == 4, "Navigation invalidates pending dispatch and children");
  current = true;
  d.header.sequence_number = 105;
  sink.CaptureNativeGuest(capture, 1, [&] { return current; });
  const auto retired = transfers.begin()->first;
  configure();
  Receive(receiver, retired);
  Check(typed().size() == 4, "Same-session reconfiguration rejects old dependencies");
  capture.module_bytes = {};
  d.header.sequence_number = 106;
  sink.CaptureNativeGuest(capture, 1, [] { return true; });
  Check(transfers.empty(), "Unknown empty module fails closed");
  capture.module_bytes = module;
  sink.CaptureNativeGuest(capture, 1, [] { return true; });
  Check(transfers.size() == 3, "Fresh configuration needs fresh module and recipe");
  std::uint64_t failed_snapshot = 0;
  for (const auto& [id, t] : transfers)
    if (t->header.kind == reb::NativeArtifactKind::kBytecodeBuffer)
      failed_snapshot = id;
  NativeArtifactCaptureSink::TransferCompleted(failed_snapshot,
                                               reb::NativeArtifactReceiveStatus::kIoError);
  transfers.erase(failed_snapshot);
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  Check(typed().size() == 5 && typed().back().header.type == NativeProbeType::kWasmGuestInvocation,
        "Snapshot failure preserves invocation but never failed dispatch");
  configure();
  transfers.clear();
  capture.module_bytes = module;
  const auto before_expiry = typed().size();
  d.header.sequence_number = 107;
  sink.CaptureNativeGuest(capture, 2, [] { return true; });
  base::test_now_ns = 201;
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  Check(typed().size() == before_expiry, "Expired captures cannot publish pending guests");
  configure();
  d.header.sequence_number = 108;
  sink.CaptureNativeGuest(capture, 2, [] { return true; });
  const auto before_world = transfers.size();
  capture.module_bytes = {};
  capture.execution_context_id = 99;
  d.header.sequence_number = 109;
  sink.CaptureNativeGuest(capture, 2, [] { return true; });
  Check(transfers.size() == before_world, "Another execution world cannot reuse module binding");
  capture.execution_context_id = 10;
  while (!transfers.empty())
    Receive(receiver, transfers.begin()->first);
  host.header.sequence_number = 110;
  host.header.parent_event_id = 108;
  const auto before_epoch = typed().size();
  sink.CaptureNativeGuestHost(host, 3);
  Check(typed().size() == before_epoch, "Wrong host epoch cannot inherit ancestry");
  const auto gaps = events.size();
  sink.CaptureNativeGuestHost(host, 3);
  Check(events.size() == gaps, "Rejected hosts have bounded omission marker");
  configure();
  capture.module_bytes = module;
  for (std::size_t n = 0; n < reb::kNativeGuestSampleLimit; ++n) {
    d.header.sequence_number = 200 + n;
    sink.CaptureNativeGuest(capture, 4, [] { return true; });
    capture.module_bytes = {};
  }
  Check(transfers.size() == reb::kNativeGuestSampleLimit + 2,
        "Entire sample budget shares one module and adapter");
  d.header.sequence_number = 1000;
  sink.CaptureNativeGuest(capture, 4, [] { return true; });
  Check(transfers.size() == reb::kNativeGuestSampleLimit + 2, "Dependency count budget enforced");
  const auto capped = events.size();
  sink.CaptureNativeGuest(capture, 4, [] { return true; });
  Check(events.size() == capped, "Budget omission bounded");
  configure();
  transfers.clear();
  capture.module_bytes = module;
  NativeArtifactSocketClient::Get().reject_next = true;
  sink.CaptureNativeGuest(capture, 5, [] { return true; });
  Check(transfers.empty(), "Failed first module leaves no admitted artifact");
  const auto failure = events.size();
  capture.module_bytes = {};
  d.header.sequence_number = 1001;
  sink.CaptureNativeGuest(capture, 5, [] { return true; });
  Check(transfers.empty() && events.size() == failure,
        "Failed binding tombstone does not retry empty module");
  capture.module_bytes = module;
  d.header.sequence_number = 1002;
  sink.CaptureNativeGuest(capture, 5, [] { return true; });
  Check(transfers.empty() && events.size() == failure,
        "Resent module cannot silently revive failed epoch");
  configure();
  sink.CaptureNativeGuest(capture, 6, [] { return true; });
  Check(transfers.size() == 3, "Explicit reconfiguration permits new binding");
  configure();
  transfers.clear();
  capture.dispatch.header.category = reb::NativeProbeCategory::kCanvas;
  sink.CaptureNativeGuest(capture, 1, [] { return true; });
  Check(transfers.empty(), "Wrong invocation or dispatch category rejected");
  std::cout << "PASS production guest ACK ordering, stable module binding, exact host parents, "
               "lifecycle, tombstones and bounded loss\n";
}
