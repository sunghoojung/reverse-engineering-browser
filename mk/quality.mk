native-build-test:
	./scripts/check-native-build.sh

WIRE_DECODER_EXECUTABLE ?= $(DECODER_BINARY)
wire-decoder-check: $(WIRE_DECODER_EXECUTABLE)
	node tools/check-wire-decoder.mjs $(WIRE_DECODER_EXECUTABLE) $(WIRE_DECODER_CHECK_FLAGS)

MAGIC_DECODER_EXECUTABLE ?= $(DECODER_BINARY)
magic-decoder-check: $(MAGIC_DECODER_EXECUTABLE) $(BUILD_DIR)/check-magic-decoder-limits
	node tools/check-magic-decoder.mjs $(MAGIC_DECODER_EXECUTABLE) $(MAGIC_DECODER_CHECK_FLAGS) --limits=$(BUILD_DIR)/check-magic-decoder-limits

native-tests: $(NATIVE_TEST_BINARIES)
	@set -e; for test_binary in $(NATIVE_TEST_BINARIES); do "$$test_binary"; done

# Run exactly one named ignored Rust test. --exact and the executed-count check
# make a renamed or filtered-out test fail instead of passing with 0 tests.
# $(1): cargo target selector, $(2): exact test path, $(3): environment.
define ignored-rust-test
	output=$$(env $(3) cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml $(1) -- --ignored --exact $(2) 2>&1); \
		status=$$?; printf '%s\n' "$$output"; test $$status -eq 0 && \
		printf '%s\n' "$$output" | grep -q '^test result: ok\. 1 passed; 0 failed;' || \
		{ echo "Expected exactly one passing ignored test: $(2)" >&2; exit 1; }
endef

check: native-wasm-golden-check all heap-snapshot-check native-artifact-capture-check native-request-identity-check wire-decoder-check magic-decoder-check native-vm-recorder-check owned-vm-helper-check native-probe-compile native-probe-admission-check native-network-capture-check native-proxy-policy-check native-build-test native-tests workspace-check deob-benchmark vm-lab-check native-only-check
	cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml
	cargo test --locked --manifest-path apps/deobfuscator-worker/Cargo.toml
	$(call ignored-rust-test,--lib,owned_vm_debugger::tests::owned_vm_real_helper_control_and_independent_goldens,\
		REB_OWNED_VM_TEST_HELPER="$(abspath $(NATIVE_VM_FIXTURE_BINARY))")
	$(call ignored-rust-test,--test owned_vm_http,owned_vm_real_helper_http_cli_lifecycle,\
		REB_OWNED_VM_TEST_HELPER="$(abspath $(NATIVE_VM_FIXTURE_BINARY))")
	$(call ignored-rust-test,--test http,source_facts_real_worker_http_and_cli,\
		REB_SOURCE_FACTS_TEST_WORKER="$(abspath $(or $(CARGO_TARGET_DIR),apps/deobfuscator-worker/target))/debug/reb-deobfuscator-worker")

# The actual C++ native Wasm encoders feed the Rust workspace builder, the
# shipped viewer and the Python validator. The Rust tests also export the exact
# evidence stores they built; make rendered-ui-check renders those stores
# instead of a hand-mirrored copy.
NATIVE_GOLDEN_DIR := $(abspath $(BUILD_DIR)/native-golden)
.PHONY: native-wasm-golden-check
native-wasm-golden-check: $(NATIVE_WASM_GUEST_GOLDEN) $(NATIVE_WASM_DISPATCH_GOLDEN)
	rm -rf "$(NATIVE_GOLDEN_DIR)"
	mkdir -p "$(NATIVE_GOLDEN_DIR)"
	$(call ignored-rust-test,--lib,vm_opcode::native_wasm::tests::native_wasm_cpp_golden,\
		REB_NATIVE_WASM_GOLDEN="$(abspath $(NATIVE_WASM_DISPATCH_GOLDEN))" \
		REB_NATIVE_WASM_WORKSPACE_OUTPUT="$(NATIVE_GOLDEN_DIR)/native-wasm-workspace.json" \
		REB_NATIVE_WASM_EVIDENCE_OUTPUT="$(NATIVE_GOLDEN_DIR)/wasm-evidence")
	REB_NATIVE_WASM_WORKSPACE_INPUT="$(NATIVE_GOLDEN_DIR)/native-wasm-workspace.json" \
		REB_NATIVE_WASM_GOLDEN="$(abspath $(NATIVE_WASM_DISPATCH_GOLDEN))" \
		node tools/check-vm-opcode-workspace-ui.mjs
	$(call ignored-rust-test,--lib,vm_opcode::native_guest::tests::native_guest_cpp_golden,\
		REB_NATIVE_GUEST_GOLDEN="$(abspath $(NATIVE_WASM_GUEST_GOLDEN))" \
		REB_NATIVE_GUEST_WORKSPACE_OUTPUT="$(NATIVE_GOLDEN_DIR)/native-guest-workspace.json" \
		REB_NATIVE_GUEST_EVIDENCE_OUTPUT="$(NATIVE_GOLDEN_DIR)/guest-evidence")
	REB_NATIVE_GUEST_GOLDEN="$(abspath $(NATIVE_WASM_GUEST_GOLDEN))" \
		REB_NATIVE_GUEST_WORKSPACE_INPUT="$(NATIVE_GOLDEN_DIR)/native-guest-workspace.json" \
		node tools/check-native-guest-wire.mjs

# The public QuickJS module is a pinned development dependency installed with
# npm ci --prefix tools/quickjs-native-fixture; it is not native capture.
QUICKJS_WASM := $(abspath tools/quickjs-native-fixture/node_modules/@jitl/quickjs-wasmfile-debug-sync/dist/emscripten-module.wasm)
.PHONY: quickjs-binding-check
quickjs-binding-check: $(NATIVE_WASM_GUEST_GOLDEN)
	@test -f "$(QUICKJS_WASM)" || { echo "Missing $(QUICKJS_WASM); run npm ci --prefix tools/quickjs-native-fixture --ignore-scripts" >&2; exit 1; }
	node tools/quickjs-native-fixture/verify.mjs
	node tools/quickjs-native-fixture/exercise-quickjs.mjs
	$(call ignored-rust-test,--lib,native_guest_binding::tests::pinned_public_module_and_corruption,\
		REB_QUICKJS_WASM="$(QUICKJS_WASM)")
	rm -f "$(abspath $(BUILD_DIR)/native-quickjs-workspace.json)"
	$(call ignored-rust-test,--lib,vm_opcode::native_guest::tests::native_guest_quickjs_cpp_golden,\
		REB_QUICKJS_WASM="$(QUICKJS_WASM)" \
		REB_NATIVE_GUEST_GOLDEN="$(abspath $(NATIVE_WASM_GUEST_GOLDEN))" \
		REB_NATIVE_GUEST_WORKSPACE_OUTPUT="$(abspath $(BUILD_DIR)/native-quickjs-workspace.json)")
	REB_NATIVE_GUEST_WORKSPACE_INPUT="$(abspath $(BUILD_DIR)/native-quickjs-workspace.json)" \
		REB_NATIVE_GUEST_GOLDEN="$(abspath $(NATIVE_WASM_GUEST_GOLDEN))" \
		node tools/check-native-guest-wire.mjs

# CDP removal contract: shipped UI startup in a DOM model, no removed controls,
# and launch scripts that reject retired CDP options. The DOM model uses the
# pinned development-only LinkeDOM lockfile.
UI_STARTUP_DEPS := tools/ui-startup-deps/node_modules/linkedom/package.json
$(UI_STARTUP_DEPS): tools/ui-startup-deps/package-lock.json
	npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
	touch $@

native-only-check: $(UI_STARTUP_DEPS)
	node tools/check-native-only-ui.mjs
	node tools/check-native-only-startup.cjs
	node tools/check-native-only-launch.mjs

owned-vm-helper-check: $(NATIVE_VM_FIXTURE_BINARY) $(OWNED_VM_FIXTURE_TEST)
	$(OWNED_VM_FIXTURE_TEST)
	python3 tools/check-owned-vm-helper.py --binary $(NATIVE_VM_FIXTURE_BINARY)

native-vm-recorder-check: $(NATIVE_VM_FIXTURE_BINARY) $(BROKER_BINARY)
	python3 tools/check-native-vm-recorder.py --binary $(NATIVE_VM_FIXTURE_BINARY)
	python3 tools/check-owned-vm-dispatch.py --binary $(NATIVE_VM_FIXTURE_BINARY) --broker $(BROKER_BINARY)

native-probe-compile: $(NATIVE_PROBE_QUEUE_OBJECT)

native-probe-admission-check:
	CXX="$(CXX)" ./tools/check-native-probe-admission.sh

native-artifact-capture-check: $(ARTIFACT_RECEIVER_BINARY) $(BROKER_BINARY) origin-trace-backend
	CXX="$(CXX)" python3 tools/check-native-artifact-capture.py --receiver $(ARTIFACT_RECEIVER_BINARY) --broker $(BROKER_BINARY) --analyzer $(abspath $(or $(CARGO_TARGET_DIR),apps/origin-trace-backend/target))/debug/origin-trace-vm --backend $(abspath $(or $(CARGO_TARGET_DIR),apps/origin-trace-backend/target))/debug/origin-trace-backend

native-network-capture-check:
	CXX="$(CXX)" ./tools/check-native-network-capture.sh

native-proxy-policy-check: $(NATIVE_PROXY_POLICY_TEST)
	$(NATIVE_PROXY_POLICY_TEST)

lint: format-check shellcheck python-check javascript-check repository-check workflow-check
	cargo fmt --check --manifest-path apps/origin-trace-backend/Cargo.toml
	cargo clippy --locked --manifest-path apps/origin-trace-backend/Cargo.toml -- -D warnings
	cargo fmt --check --manifest-path apps/deobfuscator-worker/Cargo.toml
	cargo clippy --locked --all-targets --manifest-path apps/deobfuscator-worker/Cargo.toml -- -D warnings

deob-worker-build:
	@command -v cargo >/dev/null 2>&1 || { echo "Cargo is not installed" >&2; exit 1; }
	cargo build --locked --manifest-path apps/deobfuscator-worker/Cargo.toml

sanitize:
	$(MAKE) BUILD_DIR=$(SANITIZE_BUILD_DIR) clean
	$(MAKE) \
		BUILD_DIR=$(SANITIZE_BUILD_DIR) \
		WIRE_DECODER_EXECUTABLE=$(SANITIZE_BUILD_DIR)/reb-decoder-test \
		WIRE_DECODER_CHECK_FLAGS=--strict-stderr \
		MAGIC_DECODER_EXECUTABLE=$(SANITIZE_BUILD_DIR)/reb-decoder-test \
		MAGIC_DECODER_CHECK_FLAGS=--strict-stderr \
		OPT_CXXFLAGS="-O1 -g" \
		EXTRA_CXXFLAGS="-fsanitize=$(SANITIZERS) -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=$(SANITIZERS)" \
		all native-request-identity-check wire-decoder-check magic-decoder-check native-probe-compile native-proxy-policy-check native-vm-recorder-check owned-vm-helper-check native-tests
	REB_PROBE_TEST_SANITIZERS="$(SANITIZERS)" CXX="$(CXX)" ./tools/check-native-network-capture.sh
	REB_PROBE_TEST_SANITIZERS="$(SANITIZERS)" CXX="$(CXX)" python3 tools/check-native-artifact-capture.py --receiver $(SANITIZE_BUILD_DIR)/reb-artifact-receiver --broker $(SANITIZE_BUILD_DIR)/reb-event-broker

format:
	@if command -v $(CLANG_FORMAT) >/dev/null 2>&1; then \
		$(CLANG_FORMAT) -i $(FORMATTED_SOURCES); \
	else \
		echo "$(CLANG_FORMAT) is not installed"; \
		exit 1; \
	fi

format-check:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || { \
		echo "$(CLANG_FORMAT) is not installed" >&2; exit 1; \
	}
	$(CLANG_FORMAT) --dry-run --Werror $(FORMATTED_SOURCES)

shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { \
		echo "shellcheck is not installed" >&2; exit 1; \
	}
	shellcheck $(SHELL_SOURCES)

python-check: vm-lab-check
	python3 tools/check-brave-services.py
	python3 tools/release-companion-test.py
	python3 tools/write-release-pair-test.py
	python3 tools/publish-release-pair-test.py
	python3 tools/check-integrated-brave-state-test.py
	python3 tools/check-cookie-import-terminal.py
	python3 -m compileall -q tools
	$(RUFF) check tools

vm-lab-check:
	python3 tests/research_ui/test_vm_lab.py

repository-check:
	./scripts/check-repository-hygiene.sh

workflow-check:
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "actionlint is not installed" >&2; exit 1; \
	}
	actionlint

clean:
	rm -rf $(BUILD_DIR)

javascript-check: capture-completeness-check
	@command -v node >/dev/null 2>&1 || { echo "Node.js is not installed" >&2; exit 1; }
	@set -e; for source in apps/research-ui/*.js apps/runtime-hook-demo/*.mjs tools/*.mjs tools/*.cjs; do node --check "$$source"; done
	node tools/check-vm-request-linkage-ui.mjs
	node tools/check-traffic-capture.mjs
	node tools/check-traffic-selection-work.mjs
	node tools/check-event-window.mjs
	node tools/check-traffic-capture-qa.mjs
	node tools/check-captured-client-project.mjs
	node tools/check-captured-client-export.mjs
	node tools/check-captured-har.mjs
	node tools/check-captured-export-ui.mjs
	node tools/check-local-overrides.mjs
	node tools/check-graphql-sdl.mjs
	node tools/check-passive-security.mjs
	node tools/check-marker-fuzz.mjs
	node tools/check-cookie-import.mjs
	node tools/check-owned-vm-integration.mjs
	node tools/check-owned-vm-debugger-ui.mjs
	node tools/check-vm-semantics.mjs
	node tools/check-vm-analysis-packs.mjs
	node tools/check-vm-agent.mjs
	node tools/check-vm-opcode-ledger.mjs
	node tools/check-vm-opcode-ledger-ui.mjs
	node tools/check-vm-workspace-contract.mjs
	node tools/check-vm-opcode-workspace-ui.mjs
	node tools/check-vm-full-shell-ui.mjs
	node tools/check-owned-opcode-experiments.mjs
	node tools/owned-opcode-experiment-ui-cases.mjs --validate-fixtures
	node tools/check-vm-static.mjs
	node tools/check-vm-static-ui.mjs
	node tools/check-vm-contextual.mjs
	node tools/check-vm-contextual-evidence.mjs
	node tools/check-vm-contextual-ui.mjs
	node tools/check-vm-compatibility-demo.mjs
	node tools/check-vm-linked-model.mjs
	node tools/check-vm-observed-path.mjs
	node tools/check-vm-compare-cli.mjs
	node tools/check-python-client-project.mjs
	node tools/check-origin-trace-debugger.mjs --field-provenance-only
	node tools/check-origin-trace-launcher.mjs --cleanup-only
	node tools/check-origin-trace-package.mjs --contract-only
	node tools/check-origin-trace-native-close.mjs --contract-only

.PHONY: capture-completeness-check native-only-check
capture-completeness-check:
	node tools/check-capture-completeness-response-evidence.mjs
	node tools/check-capture-completeness-startup.mjs
	node tools/check-capture-completeness-reference.mjs
	node tools/check-capture-completeness-lifecycle.mjs
	node tools/check-capture-completeness-fixture.mjs
	node tools/check-capture-completeness-netlog.mjs
	node tools/check-capture-completeness-integration.mjs
	node tools/check-capture-completeness-report.mjs

.PHONY: native-artifact-capture-check

heap-snapshot-check: $(HEAP_SNAPSHOT_BINARY)
	node tools/check-heap-snapshot-ingest.mjs $(HEAP_SNAPSHOT_BINARY)
