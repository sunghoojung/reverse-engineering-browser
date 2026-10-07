native-build-test:
	./scripts/check-native-build.sh

check: all native-probe-compile native-build-test workspace-check deob-benchmark
	cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml
	cargo test --locked --manifest-path apps/deobfuscator-worker/Cargo.toml
	REB_SOURCE_FACTS_TEST_WORKER="$(abspath $(or $(CARGO_TARGET_DIR),apps/deobfuscator-worker/target))/debug/reb-deobfuscator-worker" \
		cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml source_facts_real_worker_http_and_cli -- --ignored

native-probe-compile: $(NATIVE_PROBE_QUEUE_OBJECT)

lint: format-check shellcheck python-check javascript-check repository-check workflow-check
	cargo fmt --check --manifest-path apps/origin-trace-backend/Cargo.toml
	cargo clippy --locked --manifest-path apps/origin-trace-backend/Cargo.toml -- -D warnings

deob-worker-build:
	@command -v cargo >/dev/null 2>&1 || { echo "Cargo is not installed" >&2; exit 1; }
	cargo build --locked --manifest-path apps/deobfuscator-worker/Cargo.toml

sanitize:
	$(MAKE) BUILD_DIR=$(SANITIZE_BUILD_DIR) clean
	$(MAKE) \
		BUILD_DIR=$(SANITIZE_BUILD_DIR) \
		OPT_CXXFLAGS="-O1 -g" \
		EXTRA_CXXFLAGS="-fsanitize=$(SANITIZERS) -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=$(SANITIZERS)" \
		all native-probe-compile

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

python-check:
	python3 -m compileall -q tools
	$(RUFF) check tools

repository-check:
	./scripts/check-repository-hygiene.sh

workflow-check:
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "actionlint is not installed" >&2; exit 1; \
	}
	actionlint

clean:
	rm -rf $(BUILD_DIR)

javascript-check:
	@command -v node >/dev/null 2>&1 || { echo "Node.js is not installed" >&2; exit 1; }
	@set -e; for source in apps/research-ui/*.js apps/runtime-hook-demo/*.mjs tools/*.mjs; do node --check "$$source"; done
	node tools/check-origin-trace-debugger.mjs --field-provenance-only
