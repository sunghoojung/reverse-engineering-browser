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
  assert(sink.AdmitNativeWasmGuestModule(module, 414));
  assert(!sink.AdmitNativeWasmGuestModule(module, 413));
  auto changed = module;
  changed[10] = 1;
  assert(!sink.AdmitNativeWasmGuestModule(changed, 414));
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
