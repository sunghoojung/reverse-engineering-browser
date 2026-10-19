#include <cassert>
#include <iostream>
#include <string>
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/common/native_network_lifecycle.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "chromium_stubs.h"
namespace {
reb::NativeProbeEvent last;
unsigned emitted = 0;
reb::NativeProbeQueue queue;
void Emit(const reb::NativeProbeEvent& event) noexcept {
  last = event;
  ++emitted;
}
void Queue(const reb::NativeProbeEvent& event) noexcept {
  static_cast<void>(queue.TryPush(event));
}
std::string Payload() {
  return {reinterpret_cast<const char*>(last.inline_payload.data()), last.header.payload_size};
}
}  // namespace
int main() {
  auto& sink = reb::NativeNetworkCaptureSink::Get();
  network::ResourceRequest request;
  auto start = [&] { sink.RecordRequestStarted(17, 9, 42, 3, 5, 11, 12, request); };
  start();
  assert(emitted == 0 && base::test_clock_reads == 0);
  assert(!sink.IsEnabled() && base::test_clock_reads == 0);
  content::BrowserContext owned(base::FilePath("/owned/Default"), false);
  content::BrowserContext other(base::FilePath("/other/Default"), false);
  content::BrowserContext system(base::FilePath("/owned/System Profile"), false);
  content::BrowserContext otr(base::FilePath("/owned/Default"), true);
  assert(!sink.IsOwnedContext(&owned));
  sink.SetOwnedProfilePath(base::FilePath("/owned/Default"));
  assert(sink.IsOwnedContext(&owned) && !sink.IsOwnedContext(&other));
  assert(!sink.IsOwnedContext(&system) && !sink.IsOwnedContext(&otr));
  assert(!sink.IsOwnedContext(nullptr));
  const auto mask = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork);
  sink.SetEmitter(Emit, 22, mask, 200);
  reb::NativeNetworkLifecycle active(sink.generation());
  reb::NativeNetworkLifecycle disabled;
  assert(!disabled.IsCurrent(sink.generation()));
  start();
  assert(last.header.session_id == 22 && last.header.request_id == 17);
  assert(last.header.browser_context_id_high == 11 && last.header.browser_context_id_low == 12);
  assert(last.header.tab_id == 3 && last.header.frame_id == 5);
  assert(Payload() == "GET fixture.test");
  request.originated_from_service_worker = true;
  request.resource_type = -1;
  start();
  assert(last.header.resource_type == 0 && (last.header.flags & 4) != 0);
  request.method.assign(200, 'A');
  start();
  assert(last.header.payload_size == 128 && (last.header.flags & 1) != 0);
  net::RedirectInfo redirect;
  network::mojom::URLResponseHead head;
  head.headers = std::make_shared<net::HttpResponseHeaders>();
  head.headers->code = 302;
  sink.RecordRequestRedirected(17, 9, 42, 3, 5, 11, 12, redirect, head);
  assert(last.header.status_code == 302 && Payload() == "GET fixture.test");
  head.headers->code = 200;
  head.was_fetched_via_cache = true;
  head.was_fetched_via_service_worker = true;
  assert(sink.RecordResponseStarted(17, 9, 42, 3, 5, 11, 12, head) != 0);
  assert(last.header.status_code == 200 && (last.header.flags & 6) == 6);
  assert(sink.RecordResponseStarted(17, 9, 42, 3, 5, 11, 12, head, true) != 0);
  assert(Payload() == "synthetic_shields; text/plain");
  network::URLLoaderCompletionStatus status;
  status.error_code = -3;
  if (active.Finish(sink.generation()))
    sink.RecordRequestCompleted(17, 9, 42, 3, 5, 11, 12, status, "proxy_destroyed");
  assert(Payload() == "proxy_destroyed" && last.header.error_code == -3);
  assert(last.header.type == reb::NativeProbeType::kRequestFailed);
  assert(!active.Finish(sink.generation()) && !active.IsCurrent(sink.generation()));
  reb::NativeNetworkLifecycle old(sink.generation());
  sink.SetEmitter(Emit, 22, mask, 200);
  assert(!old.IsCurrent(sink.generation()) && !old.Finish(sink.generation()));
  const unsigned before_expiry = emitted;
  base::test_now_ns = 200;
  start();
  assert(!sink.IsEnabled() && emitted == before_expiry);
  base::test_now_ns = 100;
  sink.SetEmitter(Emit, 22, 1, 200);
  start();
  assert(!sink.IsEnabled() && emitted == before_expiry);
  sink.SetEmitter(Queue, 22, mask, 200);
  for (std::size_t i = 0; i < reb::kNativeProbeQueueCapacity + 7; ++i)
    start();
  assert(queue.DroppedCount() == 7);
  reb::NativeProbeEvent event;
  assert(queue.TryPop(event));
  const auto gap = reb::MakeNativeProbeGapEvent(event, queue.DroppedCount());
  assert(gap.header.type == reb::NativeProbeType::kGap);
  assert(reb::NativeProbeDropWeight(gap) == 7);
  assert(gap.header.tab_id == 0 && gap.header.request_id == 0);
  sink.SetEmitter(nullptr, 0, 0, 0);
  const auto reads = base::test_clock_reads;
  start();
  assert(base::test_clock_reads == reads);
  std::cout
      << "PASS native network sink: disabled/expiry/category, owned profile, stable identity, "
         "synthetic/abort provenance, terminal-once/session rollover, truncation/queue loss\n";
}
