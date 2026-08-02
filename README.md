# Reverse Engineering Browser

Brave-based browser harness for authorized website security research.

The project goal is to observe browser behavior through native browser instrumentation, not page JavaScript hooks. Native C++ probe surfaces emit bounded telemetry to a browser-process broker, which streams normalized events to a local harness for human researchers and AI agents.

## Docs

- [Technical architecture](./reverse-engineering-browser.md)
- [System architecture diagram](./system-architecture.md)

