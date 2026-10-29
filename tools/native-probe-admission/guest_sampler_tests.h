// Production sink state machine; borrowed native callbacks, not V8 acceptance.
#include <functional>
std::array<std::uint8_t, 16> guest_memory{};
std::uint64_t guest_pc = 0;
reb::NativeWasmGuestContext guest_context{};
bool guest_context_valid = true, guest_capture_accept = true;
std::function<void()> guest_reenter;
std::vector<NativeProbeEvent> guest_dispatches, guest_hosts, guest_invocations;
std::vector<std::size_t> guest_module_sizes;
std::uint64_t GuestFrame() noexcept {
  return 8;
}
bool GuestRead(void*, std::uint32_t index, std::uint64_t* value, std::uint8_t* type) {
  if (index != 320)
    return false;
  *value = guest_pc;
  *type = 32;
  return true;
}
bool GuestCopy(void*,
               std::uint32_t index,
               std::uint64_t offset,
               std::uint32_t length,
               std::uint8_t* out) {
  if (index || offset > guest_memory.size() || length > guest_memory.size() - offset)
    return false;
  if (guest_reenter) {
    auto callback = std::move(guest_reenter);
    guest_reenter = {};
    callback();
  }
  std::copy_n(guest_memory.data() + offset, length, out);
  return true;
}
bool GuestContext(std::uint32_t function, reb::NativeWasmGuestContext* out) noexcept {
  if (!guest_context_valid || function != guest_context.function_index)
    return false;
  *out = guest_context;
  return true;
}
bool GuestCapture(const reb::NativeGuestCapture& capture, std::uint64_t) noexcept {
  if (!guest_capture_accept)
    return false;
  guest_dispatches.push_back(capture.dispatch);
  guest_invocations.push_back(capture.invocation);
  guest_module_sizes.push_back(capture.module_bytes.size());
  return true;
}
bool GuestHost(const NativeProbeEvent& event, std::uint64_t) noexcept {
  guest_hosts.push_back(event);
  return true;
}
void NativeGuestAdmission() {
  const std::array<std::uint8_t, 11> module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 0, 0};
  auto adapter = std::make_shared<reb::NativeWasmGuestAdapter>();
  adapter->module_sha256 = reb::NativeGuestDigest(module);
  adapter->function_index = 414;
  adapter->dispatch_module_offset = 8;
  adapter->pc_local_index = 320;
  adapter->memory_length.constant = 16;
  adapter->import_call_offsets[0] = 9;
  adapter->import_call_count = 1;
  adapter->sample_limit = 3;
  adapter->json = "owned boundary recipe";
  adapter->recipe_sha256 = reb::NativeGuestDigest(
      std::span(reinterpret_cast<const std::uint8_t*>(adapter->json.data()), adapter->json.size()));
  const auto configure = [&] {
    sink.SetEmitters(&AcceptRuntimeEvent, &CaptureRuntimeMetadata, 42,
                     reb::kAllNativeProbeCategoryMask, kForever, false, &GuestFrame);
    sink.ConfigureNativeWasmGuest(adapter, &GuestCapture, &GuestHost);
    sink.SetNativeWasmGuestRuntime(&GuestContext, nullptr);
  };
  configure();
  assert(sink.IsNativeWasmGuestDispatchSite(414, 8));
  assert(!sink.IsNativeWasmGuestDispatchSite(413, 8));
  assert(!sink.IsNativeWasmGuestDispatchSite(414, 9));
  using Decision = reb::NativeWasmGuestModuleDecision;
  assert(sink.AdmitNativeWasmGuestModule(module, 414) == Decision::kAdmit);
  // Another function of an unknown module defers; it must not be remembered
  // as a module rejection before the dispatcher itself is entered.
  assert(sink.AdmitNativeWasmGuestModule(module, 413) == Decision::kNotDispatcher);
  auto changed = module;
  changed[10] = 1;
  assert(sink.AdmitNativeWasmGuestModule(changed, 414) == Decision::kRejectModule);
  assert(sink.AdmitNativeWasmGuestModule({}, 414) == Decision::kRejectModule);
  reb::NativeWasmGuestStateView view{7, 11, 414, 8, 0, 0, nullptr, &GuestRead, &GuestCopy};
  guest_context = {7, 11, 414, 8, 9, 9};
  const auto record = [&] {
    sink.RecordNativeWasmGuest(1, 8, "https://owned.test/module.wasm", module, view, 5, 6);
  };
  guest_memory[0] = 0x41;
  record();
  assert(guest_dispatches.size() == 1 && guest_module_sizes.back() == module.size());
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == 1);
  assert(guest_hosts.back().header.parent_event_id ==
         guest_dispatches.back().header.sequence_number);
  const auto outer_parent = guest_hosts.back().header.parent_event_id;
  view.module_byte_offset = 9;
  record();
  view.module_byte_offset = 8;
  assert(guest_dispatches.size() == 1);
  view.invocation_id = 12;
  guest_context.invocation_id = 12;
  guest_pc = 1;
  record();
  assert(guest_dispatches.size() == 2 && guest_module_sizes.back() == 0);
  assert(guest_invocations[0].header.sequence_number !=
         guest_invocations[1].header.sequence_number);
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == 2);
  guest_context.invocation_id = 11;
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.back().header.parent_event_id == outer_parent);
  view.invocation_id = 11;
  guest_pc = 2;
  record();
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_dispatches.size() == 3);
  const auto before = guest_hosts.size();
  record();
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before);
  assert(sink.IsNativeWasmGuestDispatchSite(414, 8));  // Cap is not site identity.
  configure();
  record();
  assert(guest_dispatches.size() == 4 && guest_module_sizes.back() == module.size());
  guest_pc = 99;
  record();
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before);
  guest_pc = 0;
  guest_capture_accept = false;
  record();
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before);
  assert(sink.IsNativeWasmGuestDispatchSite(414, 8));  // Failed transport is not a new site.
  guest_capture_accept = true;
  configure();
  record();
  guest_context_valid = false;
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before);
  guest_context_valid = true;
  guest_context.import_module_byte_offset = 99;
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before);
  guest_context.import_module_byte_offset = 9;
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before + 1);
  sink.InvalidateNativeWasmGuest(view);  // Blink metadata refusal must not retain predecessor.
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before + 1);
  view.invocation_id = 0;
  record();
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before + 1);
  view.invocation_id = 11;
  configure();
  const auto before_reentry_dispatch = guest_dispatches.size();
  const auto before_reentry_host = guest_hosts.size();
  guest_reenter = record;
  record();
  assert(guest_dispatches.size() == before_reentry_dispatch);
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before_reentry_host);
  record();  // The bounded scratch guard must recover after cancellation.
  assert(guest_dispatches.size() == before_reentry_dispatch + 1);
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before_reentry_host + 1);
  const auto direct_parent = guest_hosts.back().header.parent_event_id;
  view.module_byte_offset = 9;  // Unrelated br_table within the same activation.
  sink.InvalidateNativeWasmGuest(view);
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before_reentry_host + 2);
  assert(guest_hosts.back().header.parent_event_id == direct_parent);
  view.module_byte_offset = 8;
  sink.InvalidateNativeWasmGuest(view);
  // Model Blink's selected dispatch followed by a metadata admission refusal.
  sink.RecordNativeWasmGuest(1, 8, "", module, view, 5, 6);
  assert(guest_dispatches.size() == before_reentry_dispatch + 1);
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before_reentry_host + 2);
  sink.SetEmitters(nullptr, nullptr, 0, 0, 0);
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == before_reentry_host + 2);
  assert(!sink.IsNativeWasmGuestDispatchSite(414, 8));  // Configuration reset clears recipe.
  sink.ConfigureNativeWasmGuest(adapter, nullptr, nullptr);
  assert(!sink.IsNativeWasmGuestEnabled());
  assert(sink.IsNativeWasmGuestDispatchSite(414, 8));  // Recipe identity is not admission.
  sink.ConfigureNativeWasmGuest(nullptr, nullptr, nullptr);
  assert(!sink.IsNativeWasmGuestDispatchSite(414, 8));
  configure();
  assert(sink.IsNativeWasmGuestDispatchSite(414, 8));
  sink.SetEmitters(nullptr, nullptr, 0, 0, 0);
  sink.SetNativeWasmGuestRuntime(nullptr, nullptr);
  std::cout
      << "PASS guest sink exact invocation/import parents, reentry, cap/read/transport/identity "
         "failure invalidation, no async fallback and module-once binding\n";
}

std::vector<NativeProbeEvent> guest_queue_events;
reb::NativeProbeEmitStatus RecordGuestQueue(const NativeProbeEvent& event, std::uint64_t) noexcept {
  guest_queue_events.push_back(event);
  return reb::NativeProbeEmitStatus::kAdmitted;
}
bool GuestQueueHasGap(std::string_view reason) {
  return std::any_of(guest_queue_events.begin(), guest_queue_events.end(), [&](const auto& event) {
    return event.header.type == reb::NativeProbeType::kGap &&
           std::string_view(reinterpret_cast<const char*>(event.inline_payload.data()),
                            event.header.payload_size) == reason;
  });
}

// Module bytes are resent until the browser accepts them, within a bounded
// number of attempts; host parent routing is bounded without losing hosts.
void NativeGuestModuleVerdictsAndHostBudget() {
  const std::array<std::uint8_t, 11> module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 0, 0};
  auto adapter = std::make_shared<reb::NativeWasmGuestAdapter>();
  adapter->module_sha256 = reb::NativeGuestDigest(module);
  adapter->function_index = 414;
  adapter->dispatch_module_offset = 8;
  adapter->pc_local_index = 320;
  adapter->memory_length.constant = 16;
  adapter->import_call_offsets[0] = 9;
  adapter->import_call_count = 1;
  // The adapter is immutable for the process: reuse the earlier recipe.
  adapter->sample_limit = 3;
  adapter->json = "owned boundary recipe";
  adapter->recipe_sha256 = reb::NativeGuestDigest(
      std::span(reinterpret_cast<const std::uint8_t*>(adapter->json.data()), adapter->json.size()));
  const auto configure = [&] {
    sink.SetEmitters(&RecordGuestQueue, &CaptureRuntimeMetadata, 43,
                     reb::kAllNativeProbeCategoryMask, kForever, false, &GuestFrame);
    sink.ConfigureNativeWasmGuest(adapter, &GuestCapture, &GuestHost);
    sink.SetNativeWasmGuestRuntime(&GuestContext, nullptr);
  };
  guest_dispatches.clear();
  guest_module_sizes.clear();
  guest_hosts.clear();
  guest_queue_events.clear();
  guest_capture_accept = true;
  guest_context_valid = true;
  guest_pc = 0;
  guest_memory[0] = 0x41;
  configure();
  reb::NativeWasmGuestStateView view{7, 21, 414, 8, 0, 0, nullptr, &GuestRead, &GuestCopy};
  const auto record = [&] {
    sink.RecordNativeWasmGuest(1, 8, "https://owned.test/module.wasm", module, view, 5, 6);
  };
  record();
  assert(guest_dispatches.size() == 1 && guest_module_sizes.back() == module.size());
  const auto first_token = guest_dispatches.back().header.sequence_number;
  sink.NoteNativeGuestModuleStatus(first_token, false);
  record();
  assert(guest_module_sizes.back() == module.size());  // Rejected: resend.
  sink.NoteNativeGuestModuleStatus(guest_dispatches.back().header.sequence_number, false);
  record();
  assert(guest_module_sizes.back() == module.size());
  sink.NoteNativeGuestModuleStatus(guest_dispatches.back().header.sequence_number, false);
  const auto attempts = guest_dispatches.size();
  record();
  assert(guest_dispatches.size() == attempts);  // Attempt limit stops this binding.
  assert(GuestQueueHasGap("native_guest_module_unavailable"));

  configure();
  guest_queue_events.clear();
  record();
  assert(guest_module_sizes.back() == module.size());
  const auto accepted_token = guest_dispatches.back().header.sequence_number;
  sink.NoteNativeGuestModuleStatus(first_token, true);  // Stale token: no effect.
  record();
  assert(guest_module_sizes.back() == 0);  // Pending: bind to the in-flight module.
  sink.NoteNativeGuestModuleStatus(accepted_token, true);
  record();
  assert(guest_dispatches.size() == attempts + 3 && guest_module_sizes.back() == 0);

  guest_context = {7, 21, 414, 8, 9, 9};
  const auto routed_before = guest_hosts.size();
  for (std::size_t n = 0; n < reb::kNativeGuestHostParentLimit; ++n)
    sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == routed_before + reb::kNativeGuestHostParentLimit);
  const auto queued_before = guest_queue_events.size();
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == routed_before + reb::kNativeGuestHostParentLimit);
  bool unparented_host = false;
  for (std::size_t n = queued_before; n < guest_queue_events.size(); ++n)
    unparented_host |= guest_queue_events[n].header.type == reb::NativeProbeType::kApiCall &&
                       guest_queue_events[n].header.parent_event_id == 0;
  assert(unparented_host);  // Over budget: kept on the ordinary queue, not lost.
  assert(GuestQueueHasGap("native_guest_host_parent_budget"));
  configure();
  sink.RecordApiCall(kRuntime, "Math.acos");
  assert(guest_hosts.size() == routed_before + reb::kNativeGuestHostParentLimit);
  sink.SetEmitters(nullptr, nullptr, 0, 0, 0);
  sink.SetNativeWasmGuestRuntime(nullptr, nullptr);
  std::cout << "PASS guest module verdict resend, bounded attempts, stale verdicts and bounded "
               "host parent routing without host loss\n";
}

// An inner activation names its parent's retained current dispatch exactly.
// Otherwise it names at most the parent activation and the renderer emits one
// explicit gap per configuration; it never substitutes an older dispatch.
void NativeGuestParentDispatch() {
  const std::array<std::uint8_t, 11> module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 0, 0};
  auto adapter = std::make_shared<reb::NativeWasmGuestAdapter>();
  adapter->module_sha256 = reb::NativeGuestDigest(module);
  adapter->function_index = 414;
  adapter->dispatch_module_offset = 8;
  adapter->pc_local_index = 320;
  adapter->memory_length.constant = 16;
  adapter->sample_limit = 3;
  adapter->json = "owned boundary recipe";
  adapter->recipe_sha256 = reb::NativeGuestDigest(
      std::span(reinterpret_cast<const std::uint8_t*>(adapter->json.data()), adapter->json.size()));
  std::uint64_t expires = kForever;
  const auto configure = [&] {
    sink.SetEmitters(&RecordGuestQueue, &CaptureRuntimeMetadata, 44,
                     reb::kAllNativeProbeCategoryMask, expires, false, &GuestFrame);
    sink.ConfigureNativeWasmGuest(adapter, &GuestCapture, &GuestHost);
    sink.SetNativeWasmGuestRuntime(&GuestContext, nullptr);
    guest_queue_events.clear();
  };
  guest_dispatches.clear();
  guest_invocations.clear();
  guest_module_sizes.clear();
  guest_capture_accept = true;
  guest_pc = 0;
  guest_memory[0] = 0x41;
  reb::NativeWasmGuestStateView outer{7, 41, 414, 8, 0, 0, nullptr, &GuestRead, &GuestCopy};
  auto inner = outer;
  inner.parent_invocation_id = 41;
  inner.parent = reb::NativeWasmGuestParent::kResolved;
  // Blink revokes the activation's previous dispatch before recording.
  const auto record = [&](const reb::NativeWasmGuestStateView& view, std::uint64_t document = 5) {
    sink.InvalidateNativeWasmGuest(view);
    sink.RecordNativeWasmGuest(1, 8, "https://owned.test/module.wasm", module, view, document, 6);
  };
  const auto names = [&](std::uint64_t parent, std::uint64_t dispatch) {
    reb::NativeWasmGuestInvocationPayload payload;
    return reb::DecodeNativeWasmGuestInvocationPayload(guest_invocations.back().inline_payload,
                                                       payload) &&
           payload.protocol_version == 2 && payload.parent_invocation_id == parent &&
           payload.parent_dispatch_sequence_number == dispatch;
  };
  const auto unresolved = [] { return GuestQueueHasGap("native_guest_parent_unresolved"); };

  configure();
  record(outer);
  assert(guest_dispatches.size() == 1 && names(0, 0));
  const auto outer_dispatch = guest_dispatches.back().header.sequence_number;
  inner.invocation_id = 42;
  record(inner);
  assert(guest_dispatches.size() == 2 && names(41, outer_dispatch) && !unresolved());
  assert(guest_invocations.back().header.sequence_number > outer_dispatch);
  const auto inner_marker = guest_invocations.back();
  record(inner);  // Later dispatches reuse the marker resolved at the first.
  assert(guest_dispatches.size() == 3 &&
         guest_invocations.back().inline_payload == inner_marker.inline_payload &&
         guest_invocations.back().header.sequence_number == inner_marker.header.sequence_number);

  // Queue loss of the parent's current dispatch: the earlier retained one is
  // not current, so the inner marker names the activation only.
  configure();
  record(outer);
  guest_capture_accept = false;
  record(outer);
  guest_capture_accept = true;
  inner.invocation_id = 43;
  record(inner);
  assert(names(41, 0) && unresolved());

  // The engine could not resolve the parent: no parent at all, and a gap.
  configure();
  auto lost = inner;
  lost.invocation_id = 44;
  lost.parent_invocation_id = 0;
  lost.parent = reb::NativeWasmGuestParent::kUnresolved;
  record(lost);
  assert(names(0, 0) && unresolved());

  // A selected dispatch without identity revokes every current dispatch, and
  // a parent in another document is not joined.
  for (const bool other_document : {false, true}) {
    configure();
    record(outer);
    if (!other_document) {
      auto anonymous = outer;
      anonymous.instance_id = anonymous.invocation_id = 0;
      sink.InvalidateNativeWasmGuest(anonymous);
    }
    inner.invocation_id = other_document ? 46 : 45;
    record(inner, other_document ? 9 : 5);
    assert(names(41, 0) && unresolved());
  }

  // Expired or disabled capture records nothing, so it names no parent.
  expires = 500;
  configure();
  record(outer);
  base::test_now_ns = 1000;
  const auto before = guest_invocations.size();
  inner.invocation_id = 47;
  record(inner);
  base::test_now_ns = 100;
  sink.SetEmitters(nullptr, nullptr, 0, 0, 0);
  inner.invocation_id = 48;
  record(inner);
  assert(guest_invocations.size() == before && !unresolved());
  sink.SetNativeWasmGuestRuntime(nullptr, nullptr);
  std::cout << "PASS guest invocations name the exact current parent dispatch; lost, revoked, "
               "unresolved or cross-document parents are explicit gaps, and disabled or "
               "expired capture names none\n";
}
