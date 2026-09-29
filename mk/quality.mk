native-build-test:
	./scripts/check-native-build.sh

check: all native-probe-compile native-build-test workspace-check deob-benchmark

native-probe-compile: $(NATIVE_PROBE_QUEUE_OBJECT)

lint: format-check shellcheck python-check javascript-check repository-check workflow-check

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
	python3 -m compileall -q apps/research-ui tools
	$(RUFF) check apps/research-ui tools

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
	@set -e; for source in apps/research-ui/*.js; do node --check "$$source"; done
