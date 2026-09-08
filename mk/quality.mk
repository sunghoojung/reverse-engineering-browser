native-build-test:
	./tests/native_build_test.sh

check: native-build-test workspace-check bootstrap-test browser-sync-test test ui-test

lint: format-check shellcheck python-check javascript-check repository-check workflow-check

test: $(TEST_BINARIES)
	@set -e; for test_binary in $(TEST_BINARIES); do \
		echo "Running $$test_binary"; \
		$$test_binary; \
	done

ui-test: heap-snapshot decoder debugger-transport
	PYTHONPATH=apps/research-ui python3 -m unittest discover -s tests/research_ui -p 'test_*.py'

sanitize:
	$(MAKE) BUILD_DIR=$(SANITIZE_BUILD_DIR) clean
	$(MAKE) \
		BUILD_DIR=$(SANITIZE_BUILD_DIR) \
		OPT_CXXFLAGS="-O1 -g" \
		EXTRA_CXXFLAGS="-fsanitize=$(SANITIZERS) -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=$(SANITIZERS)" \
		test

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
	python3 -m compileall -q apps/research-ui tests/research_ui tools
	python3 -m ruff check apps/research-ui tests/research_ui tools

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
