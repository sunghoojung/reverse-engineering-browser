bootstrap-brave:
	./scripts/bootstrap-brave.sh

bootstrap-dev-tools:
	./scripts/bootstrap-dev-tools.sh

brave-doctor:
	./scripts/brave-toolchain.sh doctor

brave-probe-check:
	./scripts/brave-toolchain.sh probe-check

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

debugger-transport: $(DEBUGGER_TRANSPORT_BINARY)

native-console-build: $(NATIVE_CONSOLE_BINARY)

native-console: native-console-build
	./scripts/run-native-console.sh

native-console-check: native-console-build origin-trace-backend
	python3 tools/check-native-console.py --binary $(NATIVE_CONSOLE_BINARY) --backend $(ORIGIN_TRACE_BACKEND)

e2e: origin-trace-backend producer broker artifact-producer artifact-receiver debugger-transport heap-snapshot decoder native-console-check
	@mkdir -p $(BUILD_DIR)/sessions
	$(PRODUCER_BINARY) | $(BROKER_BINARY) \
		--store $(BUILD_DIR)/sessions/demo.jsonl \
		--trace-store $(BUILD_DIR)/sessions/origin-trace.jsonl \
		--signal-store $(BUILD_DIR)/sessions/request-signals.jsonl
	$(RM) -r "$(BUILD_DIR)/sessions/artifacts"
	$(ARTIFACT_PRODUCER_BINARY) | $(ARTIFACT_RECEIVER_BINARY) --store $(BUILD_DIR)/sessions/artifacts
	$(VM_ANALYZER) --artifacts $(BUILD_DIR)/sessions/artifacts --events $(BUILD_DIR)/sessions/demo.jsonl
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
	python3 tools/validate-evidence-store.py $(BUILD_DIR)/sessions/demo.jsonl

ui: e2e heap-snapshot decoder deob-worker-build
	$(ORIGIN_TRACE_BACKEND) \
		--demo-evidence \
		--store $(BUILD_DIR)/sessions/demo.jsonl \
		--trace-store $(BUILD_DIR)/sessions/origin-trace.jsonl \
		--signal-store $(BUILD_DIR)/sessions/request-signals.jsonl

origin-trace-backend:
	cargo build --locked --manifest-path apps/origin-trace-backend/Cargo.toml

backend-e2e: origin-trace-backend debugger-transport heap-snapshot decoder deob-worker-build
	node tools/check-origin-trace-debugger.mjs

app-build: heap-snapshot decoder broker artifact-receiver debugger-transport native-console-build
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

live: app-build broker artifact-receiver debugger-transport
	./scripts/run-live-session.sh

deob-benchmark: deob-worker-build
	@command -v node >/dev/null 2>&1 || { echo "Node.js is not installed" >&2; exit 1; }
	python3 tools/run-deobfuscation-benchmark.py
