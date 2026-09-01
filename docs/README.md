# Documentation

This index separates the implemented architecture and operating guides from the
broader product direction. Source, tests, and versioned protocol files are the
final authority for current behavior.

## Start here

- [Project overview and quick start](../README.md)
- [Technical architecture](./architecture/technical-architecture.md)
- [System architecture](./architecture/system-architecture.md)
- [Feature roadmap](./product/feature-list.md)
- [Feature catalog](./product/feature-catalog.md)
- [Contributor guide](../CONTRIBUTING.md)

Coding agents should also read the repository contract in
[AGENTS.md](../AGENTS.md). It routes UI, Brave, and handoff work to the focused
skills under `.agents/skills/`.

## Architecture and contracts

- [Technical architecture](./architecture/technical-architecture.md)
- [System architecture](./architecture/system-architecture.md)
- [System architecture diagram](./architecture/system-architecture.svg)
- [Artifact transfer channel](./architecture/artifact-transfer-channel.md)
- [Shared protocol](../protocol/README.md)

## Product direction

- [Feature roadmap](./product/feature-list.md)
- [Feature catalog](./product/feature-catalog.md)
- [WireBrowser parity inventory](./product/wirebrowser-parity.md)

The roadmap describes the intended product surface. Versioned feature documents
below capture bounded designs and implementation contracts. A design document
can include follow-up work, so confirm present behavior in source and tests.

## Versioned feature designs

- [Action Scope Policy v1](./product/action-scope-policy-v1.md)
- [Anti-bot VM detection v1](./product/anti-bot-vm-detection-v1.md)
- [API Collection v1](./product/api-collection-v1.md)
- [Automation Recipes v1](./product/automation-recipes-v1.md)
- [Decoder Tools v1](./product/decoder-tools-v1.md)
- [Heap Reference Inspection v2](./product/heap-reference-inspection-v2.md)
- [Live Object Experiment v1](./product/live-object-experiment-v1.md)
- [Local Analyst Workspace v1](./product/local-analyst-workspace-v1.md)
- [Memory Origin Trace v1](./product/memory-origin-trace-v1.md)
- [Repeater v1](./product/repeater-v1.md)
- [Request Interception v1](./product/request-interception-v1.md)
- [Request Origin Trace v1](./product/request-origin-trace-v1.md)
- [Request Signal Profile v1](./product/request-signal-profile-v1.md)
- [Runtime Hooks v1](./product/runtime-hooks-v1.md)
- [Web Audio function-call capture v1](./product/web-audio-call-capture-v1.md)

## Subsystem guides

- [Origin Trace UI and macOS application](../apps/research-ui/README.md)
- [Event broker](../services/event-broker/README.md)
- [Artifact receiver](../services/artifact-receiver/README.md)
- [Brave workspace](../browser/README.md)
- [Brave integration overlay](../browser/integration/brave/README.md)
- [Development tools](../tools/README.md)

Keep product planning and architecture here. Keep setup, operation, and
troubleshooting beside the subsystem they describe so implementation and usage
stay synchronized.
