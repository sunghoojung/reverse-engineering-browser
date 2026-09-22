bootstrap-brave:
	./scripts/bootstrap-brave.sh

bootstrap-dev-tools:
	./scripts/bootstrap-dev-tools.sh

bootstrap-test:
	./tests/bootstrap_brave_test.sh

brave-doctor:
	./scripts/brave-toolchain.sh doctor

brave-probe-check:
	./scripts/brave-toolchain.sh probe-check

browser-sync:
	./scripts/sync-browser-integration.sh

browser-sync-test:
	./tests/sync_browser_integration_test.sh

brave-distribution-test:
	./tests/brave_distribution_test.sh

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

e2e: producer broker artifact-producer artifact-receiver debugger-transport heap-snapshot decoder
	@mkdir -p $(BUILD_DIR)/sessions
	$(PRODUCER_BINARY) | $(BROKER_BINARY) \
		--store $(BUILD_DIR)/sessions/demo.jsonl \
		--trace-store $(BUILD_DIR)/sessions/origin-trace.jsonl \
		--signal-store $(BUILD_DIR)/sessions/request-signals.jsonl
	$(RM) -r "$(BUILD_DIR)/sessions/artifacts"
	$(ARTIFACT_PRODUCER_BINARY) | $(ARTIFACT_RECEIVER_BINARY) --store $(BUILD_DIR)/sessions/artifacts
	python3 $(VM_ANALYZER) --artifacts $(BUILD_DIR)/sessions/artifacts --events $(BUILD_DIR)/sessions/demo.jsonl
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
	./tests/event_broker_socket_test.sh $(BROKER_BINARY) $(PRODUCER_BINARY) $(DEMO_NETWORK_PAYLOAD_HEX)
	./tests/artifact_receiver_socket_test.sh $(ARTIFACT_RECEIVER_BINARY) $(ARTIFACT_PRODUCER_BINARY)
	./tests/live_session_test.sh ./scripts/run-live-session.sh $(PRODUCER_BINARY) $(ARTIFACT_PRODUCER_BINARY)

socket-e2e: producer broker
	./tests/event_broker_socket_test.sh $(BROKER_BINARY) $(PRODUCER_BINARY) $(DEMO_NETWORK_PAYLOAD_HEX)

artifact-socket-e2e: artifact-producer artifact-receiver
	./tests/artifact_receiver_socket_test.sh $(ARTIFACT_RECEIVER_BINARY) $(ARTIFACT_PRODUCER_BINARY)

ui: e2e heap-snapshot decoder
	python3 apps/research-ui/server.py \
		--demo-evidence \
		--store $(BUILD_DIR)/sessions/demo.jsonl \
		--trace-store $(BUILD_DIR)/sessions/origin-trace.jsonl \
		--signal-store $(BUILD_DIR)/sessions/request-signals.jsonl

app-build: heap-snapshot decoder broker artifact-receiver debugger-transport
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

deob-benchmark:
	@command -v cargo >/dev/null 2>&1 || { echo "Cargo is not installed" >&2; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "Node.js is not installed" >&2; exit 1; }
	cargo build --locked --manifest-path apps/deobfuscator-worker/Cargo.toml
	python3 tools/run-deobfuscation-benchmark.py
