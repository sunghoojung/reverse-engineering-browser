# Public commands stay here; implementation lives in mk/.
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

include mk/config.mk
include mk/native.mk
include mk/workflows.mk
include mk/quality.mk

.PHONY: backend-e2e all app app-build app-demo artifact-producer artifact-receiver bootstrap-brave bootstrap-dev-tools brave-doctor brave-probe-check browser-sync broker check clean deob-benchmark deob-worker-build debugger-transport decoder demo e2e format format-check heap-snapshot javascript-check lint live native-build-test native-probe-compile origin-trace-backend producer python-check repository-check sanitize shellcheck ui workflow-check workspace-check
.PHONY: native-console native-console-build native-console-check

all: demo producer broker artifact-producer artifact-receiver heap-snapshot decoder debugger-transport native-console-build
