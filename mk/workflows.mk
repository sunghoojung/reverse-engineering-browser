bootstrap-brave:
	./scripts/bootstrap-brave.sh

bootstrap-dev-tools:
	./scripts/bootstrap-dev-tools.sh

brave-doctor:
	./scripts/brave-toolchain.sh doctor

brave-probe-check:
	./scripts/brave-toolchain.sh probe-check

brave-foundation-check:
	./scripts/brave-toolchain.sh foundation-check

browser-sync:
	./scripts/sync-browser-integration.sh

workspace-check:
	./scripts/check-workspace.sh

demo: $(DEMO_BINARY)

producer: $(PRODUCER_BINARY)

broker: $(BROKER_BINARY)

artifact-producer: $(ARTIFACT_PRODUCER_BINARY)

artifact-receiver: $(ARTIFACT_RECEIVER_BINARY)

heap-snapshot: $(HEAP_SNAPSHOT_BINARY)

decoder: $(DECODER_BINARY)

native-console-build: $(NATIVE_CONSOLE_BINARY)

native-console: native-console-build
	./scripts/run-native-console.sh

native-console-check: native-console-build origin-trace-backend
	python3 tools/check-native-console.py --binary $(NATIVE_CONSOLE_BINARY) --backend $(ORIGIN_TRACE_BACKEND)

e2e: native-request-identity-check origin-trace-backend native-vm-fixture producer broker artifact-producer artifact-receiver heap-snapshot decoder native-console-check
	@mkdir -p $(BUILD_DIR)/sessions
	python3 tools/check-native-request-identity.py --broker $(BROKER_BINARY) --backend $(ORIGIN_TRACE_BACKEND)
	$(PRODUCER_BINARY) | $(BROKER_BINARY) \
		--store $(BUILD_DIR)/sessions/demo.jsonl \
		--trace-store $(BUILD_DIR)/sessions/origin-trace.jsonl \
		--signal-store $(BUILD_DIR)/sessions/request-signals.jsonl
	$(RM) -r "$(BUILD_DIR)/sessions/artifacts"
	$(ARTIFACT_PRODUCER_BINARY) | $(ARTIFACT_RECEIVER_BINARY) --store $(BUILD_DIR)/sessions/artifacts
	$(VM_ANALYZER) --artifacts $(BUILD_DIR)/sessions/artifacts --events $(BUILD_DIR)/sessions/demo.jsonl
	python3 tools/check-runtime-snapshot-producer.py --producer $(ARTIFACT_PRODUCER_BINARY) --receiver $(ARTIFACT_RECEIVER_BINARY) --analyzer $(VM_ANALYZER)
	CXX="$(CXX)" python3 tools/check-runtime-snapshot-pipeline.py --receiver $(ARTIFACT_RECEIVER_BINARY) --broker $(BROKER_BINARY) --analyzer $(VM_ANALYZER) --backend $(ORIGIN_TRACE_BACKEND)
	test "$$(wc -l < $(BUILD_DIR)/sessions/demo.jsonl | tr -d ' ')" = "14"
	test "$$(wc -l < $(BUILD_DIR)/sessions/origin-trace.jsonl | tr -d ' ')" = "12"
	test "$$(wc -l < $(BUILD_DIR)/sessions/request-signals.jsonl | tr -d ' ')" = "2"
	test "$$(grep -c '\"relation\":\"parent_event\"' $(BUILD_DIR)/sessions/origin-trace.jsonl)" = "12"
	test "$$(grep -c '\"document_kind\":\"request-signal-profile\"' $(BUILD_DIR)/sessions/request-signals.jsonl)" = "2"
	test "$$(grep -c '\"category\":\"web_audio\",\"relation\":\"parent_chain\",\"confidence\":\"observed\",\"event_count\":\"1\",\"first_event\":{\"process_id\":10,\"sequence_number\":\"3\"},\"last_event\":{\"process_id\":10,\"sequence_number\":\"3\"}' $(BUILD_DIR)/sessions/request-signals.jsonl)" = "2"
	! $(BROKER_BINARY) --store $(BUILD_DIR)/sessions/demo.jsonl \
		--trace-store $(BUILD_DIR)/sessions/../sessions/demo.jsonl </dev/null
	test "$$(grep -c '\"payload\":\"$(DEMO_NETWORK_PAYLOAD_HEX)\"' $(BUILD_DIR)/sessions/demo.jsonl)" = "2"
	test "$$(grep -c '\"category\":\"web_audio\",\"type\":\"api_call\".*\"payload\":\"$(DEMO_WEB_AUDIO_PAYLOAD_HEX)\"' $(BUILD_DIR)/sessions/demo.jsonl)" = "1"
	test "$$(grep -c '\"category\":\"vm\"' $(BUILD_DIR)/sessions/demo.jsonl)" = "6"
	test "$$(wc -l < $(BUILD_DIR)/sessions/artifacts/manifest.jsonl | tr -d ' ')" = "3"
	test "$$(grep -c 'vm-sample.js' $(BUILD_DIR)/sessions/artifacts/manifest.jsonl)" = "1"
	test "$$(grep -c '\"execution_context_id\":\"2200\",\"capture_origin\":\"dynamic_javascript\".*vm-sample.js' $(BUILD_DIR)/sessions/artifacts/manifest.jsonl)" = "1"
	test "$$(python3 -c 'import json; print(json.load(open("$(BUILD_DIR)/sessions/artifacts/analysis/vm-analysis-v1.json"))["summary"]["likely_vm_count"])')" = "1"
	python3 tools/validate-evidence-store.py $(BUILD_DIR)/sessions/demo.jsonl \
		--broker $(BROKER_BINARY) --receiver $(ARTIFACT_RECEIVER_BINARY) --producer $(PRODUCER_BINARY)
	python3 tools/check-owned-vm-dispatch.py --binary $(NATIVE_VM_FIXTURE_BINARY) --broker $(BROKER_BINARY) --analyzer $(VM_ANALYZER)

ui: e2e heap-snapshot decoder deob-worker-build
	$(ORIGIN_TRACE_BACKEND) \
		--demo-evidence \
		--store $(BUILD_DIR)/sessions/demo.jsonl \
		--trace-store $(BUILD_DIR)/sessions/origin-trace.jsonl \
		--signal-store $(BUILD_DIR)/sessions/request-signals.jsonl

origin-trace-backend:
	cargo build --locked --manifest-path apps/origin-trace-backend/Cargo.toml

# CDP-backed live-browser operations were removed, not silently emulated.
traffic-capture-check backend-e2e element-screenshot-ui-check:
	@echo "Removed CDP workflow: use native capture checks and backend tests." >&2
	@exit 2

app-build: heap-snapshot decoder broker artifact-receiver native-console-build $(NATIVE_VM_FIXTURE_BINARY)
	./scripts/build-research-app.sh

app: app-build
	open "$(CURDIR)/$(BUILD_DIR)/Origin Trace.app"

app-demo: app-build e2e
	open "$(CURDIR)/$(BUILD_DIR)/Origin Trace.app" --args \
		--demo-evidence \
		--store "$(CURDIR)/$(BUILD_DIR)/sessions/demo.jsonl" \
		--trace-store "$(CURDIR)/$(BUILD_DIR)/sessions/origin-trace.jsonl" \
		--signal-store "$(CURDIR)/$(BUILD_DIR)/sessions/request-signals.jsonl" \
		--artifacts "$(CURDIR)/$(BUILD_DIR)/sessions/artifacts"

live: app-build broker artifact-receiver
	./scripts/run-live-session.sh

deob-benchmark: deob-worker-build
	@command -v node >/dev/null 2>&1 || { echo "Node.js is not installed" >&2; exit 1; }
	python3 tools/run-deobfuscation-benchmark.py

.PHONY: native-request-identity-check
native-request-identity-check: broker
	python3 tools/check-native-request-identity.py --broker $(BROKER_BINARY)
