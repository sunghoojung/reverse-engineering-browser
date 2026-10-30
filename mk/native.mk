# Explicit link dependencies keep each application independent.
# Header dependencies are emitted by the compiler for every translation unit.

DEMO_BINARY := $(BUILD_DIR)/reb-event-demo
PRODUCER_BINARY := $(BUILD_DIR)/reb-event-producer
BROKER_BINARY := $(BUILD_DIR)/reb-event-broker
ARTIFACT_PRODUCER_BINARY := $(BUILD_DIR)/reb-artifact-producer
ARTIFACT_RECEIVER_BINARY := $(BUILD_DIR)/reb-artifact-receiver
HEAP_SNAPSHOT_BINARY := $(BUILD_DIR)/reb-heap-snapshot
DECODER_BINARY := $(BUILD_DIR)/reb-decoder
NATIVE_VM_FIXTURE_BINARY := $(BUILD_DIR)/reb-native-vm-fixture
OWNED_VM_FIXTURE_TEST := $(BUILD_DIR)/check-owned-vm-fixture
NATIVE_CONSOLE_BINARY := $(BUILD_DIR)/reb-console
NATIVE_CONSOLE_MESSAGES_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_console_messages.o
NATIVE_CONSOLE_IO_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_console_io.o
NATIVE_PROBE_QUEUE_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_queue.o
NATIVE_WORKER_SOURCE_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_worker_source.o
NATIVE_WORKER_OBSERVATION_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_worker_observation.o
NATIVE_WORKER_TRANSFER_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_worker_transfer.o
NATIVE_WORKER_AUTHORITY_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_worker_authority.o
NATIVE_WORKER_TRANSFER_GATE_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_worker_transfer_gate.o
NATIVE_PROXY_POLICY_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_proxy_policy.o
NATIVE_PROXY_POLICY_TEST := $(BUILD_DIR)/check-native-proxy-policy
EVENT_TEST_BINARY := $(BUILD_DIR)/tests/event-test
EVENT_BROKER_TEST_BINARY := $(BUILD_DIR)/tests/event-broker-test
VM_DISPATCH_TEST_BINARY := $(BUILD_DIR)/tests/vm-dispatch-test
OWNED_REGISTER_SAMPLER_TEST := $(BUILD_DIR)/tests/owned-register-sampler-test
PAGE_GUEST_SAMPLER_TEST := $(BUILD_DIR)/tests/page-guest-sampler-test
NATIVE_GUEST_TEST := $(BUILD_DIR)/tests/native-wasm-guest-test
JS_DISPATCH_TEST := $(BUILD_DIR)/tests/js-dispatch-test
ARTIFACT_TEST_BINARY := $(BUILD_DIR)/tests/artifact-test
NATIVE_TEST_BINARIES := $(ARTIFACT_TEST_BINARY) $(EVENT_TEST_BINARY) $(EVENT_BROKER_TEST_BINARY) $(VM_DISPATCH_TEST_BINARY) $(OWNED_REGISTER_SAMPLER_TEST) $(PAGE_GUEST_SAMPLER_TEST) $(NATIVE_GUEST_TEST) $(JS_DISPATCH_TEST)
ORIGIN_TRACE_BACKEND := apps/origin-trace-backend/target/debug/origin-trace-backend
VM_ANALYZER := apps/origin-trace-backend/target/debug/origin-trace-vm

APP_BINARIES := \
	$(NATIVE_VM_FIXTURE_BINARY) \
	$(DEMO_BINARY) \
	$(PRODUCER_BINARY) \
	$(BROKER_BINARY) \
	$(ARTIFACT_PRODUCER_BINARY) \
	$(ARTIFACT_RECEIVER_BINARY) \
	$(HEAP_SNAPSHOT_BINARY) \
	$(DECODER_BINARY) \
	$(NATIVE_CONSOLE_BINARY)
$(NATIVE_VM_FIXTURE_BINARY): $(BUILD_DIR)/apps/reb-native-vm-fixture/main.o $(BUILD_DIR)/apps/reb-native-vm-fixture/dispatch_events.o \
	$(BUILD_DIR)/src/analysis/native_vm_recorder.o $(BUILD_DIR)/src/analysis/owned_vm_fixture.o \
	$(BUILD_DIR)/src/capture/event.o $(BUILD_DIR)/src/capture/vm_dispatch.o $(BUILD_DIR)/src/capture/vm_finding.o

$(DEMO_BINARY): $(BUILD_DIR)/apps/reb-event-demo/main.o \
	$(BUILD_DIR)/src/capture/event.o $(NATIVE_CONSOLE_MESSAGES_OBJECT) $(NATIVE_PROBE_QUEUE_OBJECT) $(NATIVE_WORKER_SOURCE_OBJECT) $(NATIVE_WORKER_OBSERVATION_OBJECT) $(NATIVE_WORKER_TRANSFER_OBJECT) $(NATIVE_WORKER_AUTHORITY_OBJECT) $(NATIVE_WORKER_TRANSFER_GATE_OBJECT)
$(BUILD_DIR)/apps/reb-event-demo/main.o: CPPFLAGS += -Ibrowser/integration/brave/overlay
$(PRODUCER_BINARY): $(BUILD_DIR)/apps/reb-event-producer/main.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/transport/local_ipc.o \
	$(BUILD_DIR)/src/capture/vm_finding.o
$(EVENT_TEST_BINARY): $(BUILD_DIR)/tests/event_test.o \
	$(BUILD_DIR)/src/capture/event.o
$(EVENT_BROKER_TEST_BINARY): $(BUILD_DIR)/tests/event_broker_test.o \
	$(BUILD_DIR)/src/evidence/event_broker.o \
	$(BUILD_DIR)/src/capture/event.o
$(ARTIFACT_TEST_BINARY): $(BUILD_DIR)/tests/artifact_test.o \
	$(BUILD_DIR)/src/evidence/artifact.o
$(VM_DISPATCH_TEST_BINARY): $(BUILD_DIR)/tests/vm_dispatch_test.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/capture/vm_dispatch.o
$(OWNED_REGISTER_SAMPLER_TEST): $(BUILD_DIR)/tests/owned_vm_guest_sampler_test.o \
	$(BUILD_DIR)/src/analysis/owned_vm_guest_sampler.o \
	$(BUILD_DIR)/src/analysis/owned_vm_fixture.o \
	$(BUILD_DIR)/src/analysis/native_vm_recorder.o
$(BUILD_DIR)/tests/page_guest_sampler_test.o: CPPFLAGS += -Ibrowser/integration/brave/overlay
$(PAGE_GUEST_SAMPLER_TEST): $(BUILD_DIR)/tests/page_guest_sampler_test.o
$(BROKER_BINARY): $(BUILD_DIR)/services/event-broker/main.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/evidence/event_broker.o \
	$(BUILD_DIR)/src/transport/local_ipc.o \
	$(BUILD_DIR)/src/evidence/origin_trace.o \
	$(BUILD_DIR)/src/evidence/request_signal_profile.o
$(ARTIFACT_PRODUCER_BINARY): $(BUILD_DIR)/apps/reb-artifact-producer/main.o \
	$(BUILD_DIR)/src/evidence/artifact.o \
	$(BUILD_DIR)/src/transport/local_ipc.o
$(ARTIFACT_RECEIVER_BINARY): $(BUILD_DIR)/services/artifact-receiver/main.o \
	$(BUILD_DIR)/src/evidence/artifact.o \
	$(BUILD_DIR)/src/transport/local_ipc.o
$(HEAP_SNAPSHOT_BINARY): $(BUILD_DIR)/apps/reb-heap-snapshot/main.o \
	$(BUILD_DIR)/src/analysis/heap_snapshot.o
$(DECODER_BINARY): $(BUILD_DIR)/apps/reb-decoder/main.o \
	$(BUILD_DIR)/src/analysis/decoder.o
$(NATIVE_CONSOLE_BINARY): $(BUILD_DIR)/apps/native-console/main.o $(NATIVE_CONSOLE_IO_OBJECT)
$(BUILD_DIR)/apps/native-console/main.o: CPPFLAGS += -Ibrowser/integration/brave/overlay
$(DECODER_BINARY): LDLIBS += $(ZLIB_LIBS)

# Authored sanitizer fixtures call the same parser through a test-only process.
# Never package this driver or relax the production decoder's process limits.
$(BUILD_DIR)/reb-decoder-test: $(BUILD_DIR)/tools/decoder-test-driver.o $(BUILD_DIR)/src/analysis/decoder.o mk/native.mk
	@mkdir -p $(@D)
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) $(ZLIB_LIBS) -o $@

$(OWNED_VM_FIXTURE_TEST): $(BUILD_DIR)/tools/check-owned-vm-fixture.o $(BUILD_DIR)/src/analysis/native_vm_recorder.o $(BUILD_DIR)/src/analysis/owned_vm_fixture.o

$(NATIVE_PROXY_POLICY_TEST): $(BUILD_DIR)/tools/check-native-proxy-policy.o $(NATIVE_PROXY_POLICY_OBJECT)

$(BUILD_DIR)/tools/check-native-proxy-policy.o: CPPFLAGS += -Ibrowser/integration/brave/overlay

$(APP_BINARIES) $(NATIVE_PROXY_POLICY_TEST) $(OWNED_VM_FIXTURE_TEST) $(NATIVE_TEST_BINARIES):
	@mkdir -p $(@D)
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -c $< -o $@
	SCCACHE_DISABLE=1 $(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -MM -MP -MT $@ -MF $(@:.o=.d) $<

$(BUILD_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -c $< -o $@
	SCCACHE_DISABLE=1 $(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -MM -MP -MT $@ -MF $(@:.o=.d) $<

# sccache replays cached dependency files with the original output path. Generate
# these separately, without cache, so each build directory has correct targets.
# Discover dependency files without adding sources to any link target implicitly.
NATIVE_CPP_SOURCES := $(wildcard src/*/*.cpp apps/*/main.cpp services/*/main.cpp tests/*.cpp)
NATIVE_OBJECTS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(NATIVE_CPP_SOURCES)) \
	$(NATIVE_CONSOLE_MESSAGES_OBJECT) $(NATIVE_PROBE_QUEUE_OBJECT) $(NATIVE_CONSOLE_IO_OBJECT) $(NATIVE_WORKER_SOURCE_OBJECT) $(NATIVE_WORKER_OBSERVATION_OBJECT) $(NATIVE_WORKER_TRANSFER_OBJECT) $(NATIVE_WORKER_AUTHORITY_OBJECT) $(NATIVE_WORKER_TRANSFER_GATE_OBJECT) \
	$(NATIVE_PROXY_POLICY_OBJECT) $(BUILD_DIR)/tools/check-native-proxy-policy.o $(BUILD_DIR)/tools/decoder-test-driver.o $(BUILD_DIR)/tools/check-owned-vm-fixture.o

$(NATIVE_OBJECTS) $(BUILD_DIR)/tools/check-magic-decoder-limits.o: mk/config.mk mk/native.mk
$(APP_BINARIES) $(NATIVE_PROXY_POLICY_TEST) $(OWNED_VM_FIXTURE_TEST) $(NATIVE_TEST_BINARIES): mk/native.mk

-include $(NATIVE_OBJECTS:.o=.d)

$(BUILD_DIR)/check-magic-decoder-limits: $(BUILD_DIR)/tools/check-magic-decoder-limits.o $(BUILD_DIR)/src/analysis/decoder.o
	@mkdir -p $(@D)
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) $(ZLIB_LIBS) -o $@
-include $(BUILD_DIR)/tools/check-magic-decoder-limits.d

# Test-only ABI producer. No authored JSON substitute for cross-language checks.
NATIVE_WASM_DISPATCH_GOLDEN := $(BUILD_DIR)/reb-native-wasm-dispatch-golden
.PHONY: native-wasm-dispatch-golden
native-wasm-dispatch-golden: $(NATIVE_WASM_DISPATCH_GOLDEN)
$(BUILD_DIR)/tools/native-wasm-dispatch-golden.o: mk/config.mk mk/native.mk
$(NATIVE_WASM_DISPATCH_GOLDEN): $(BUILD_DIR)/tools/native-wasm-dispatch-golden.o $(BUILD_DIR)/src/capture/event.o mk/native.mk
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) -o $@
-include $(BUILD_DIR)/tools/native-wasm-dispatch-golden.d

# Native guest ABI producer; shares the actual renderer encoder.
NATIVE_WASM_GUEST_GOLDEN := $(BUILD_DIR)/reb-native-wasm-guest-golden
.PHONY: native-wasm-guest-golden
native-wasm-guest-golden: $(NATIVE_WASM_GUEST_GOLDEN)
$(BUILD_DIR)/tools/native-wasm-guest-golden.o: mk/config.mk mk/native.mk
$(NATIVE_WASM_GUEST_GOLDEN): $(BUILD_DIR)/tools/native-wasm-guest-golden.o $(BUILD_DIR)/src/capture/event.o mk/native.mk
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) -o $@
-include $(BUILD_DIR)/tools/native-wasm-guest-golden.d

$(BUILD_DIR)/tests/native_wasm_guest_test.o: CPPFLAGS += -Ibrowser/integration/brave/overlay -Itools/native-test-support
$(NATIVE_GUEST_TEST): $(BUILD_DIR)/tests/native_wasm_guest_test.o

# Overlay renderer encoder and core decoder must agree on every JavaScript
# dispatch field; the same producer emits the cross-language golden cases.
$(BUILD_DIR)/tests/js_dispatch_test.o: CPPFLAGS += -Ibrowser/integration/brave/overlay
$(JS_DISPATCH_TEST): $(BUILD_DIR)/tests/js_dispatch_test.o $(BUILD_DIR)/src/capture/event.o
NATIVE_JS_DISPATCH_GOLDEN := $(BUILD_DIR)/reb-native-js-dispatch-golden
.PHONY: native-js-dispatch-golden
native-js-dispatch-golden: $(NATIVE_JS_DISPATCH_GOLDEN)
$(BUILD_DIR)/tools/native-js-dispatch-golden.o: mk/config.mk mk/native.mk
$(NATIVE_JS_DISPATCH_GOLDEN): $(BUILD_DIR)/tools/native-js-dispatch-golden.o $(BUILD_DIR)/src/capture/event.o mk/native.mk
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) -o $@
-include $(BUILD_DIR)/tools/native-js-dispatch-golden.d
