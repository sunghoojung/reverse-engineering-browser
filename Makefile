# Public commands stay here; implementation lives in mk/.
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

include mk/config.mk
include mk/native.mk
include mk/workflows.mk
include mk/quality.mk

.PHONY: all app app-build artifact-producer artifact-receiver artifact-socket-e2e bootstrap-brave bootstrap-test brave-doctor brave-probe-check browser-sync browser-sync-test broker check clean debugger-transport decoder demo e2e format format-check heap-snapshot javascript-check lint live native-build-test producer python-check repository-check sanitize shellcheck socket-e2e test ui ui-test workflow-check workspace-check

all: demo producer broker artifact-producer artifact-receiver heap-snapshot decoder debugger-transport
