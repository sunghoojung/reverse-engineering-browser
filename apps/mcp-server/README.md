# MCP Server

The MCP server is the agent-facing adapter for the reverse engineering browser.

## Responsibilities

- Expose bounded searches over sessions, requests, scripts, probe events, and artifacts.
- Expose explicit browser actions with authorization scope and audit records.
- Return stable identifiers so an agent can work backward from a request field.
- Report missing evidence, redaction, truncation, and dropped events honestly.

## Boundary

The MCP server communicates with the event broker. It does not attach to Chrome DevTools Protocol or instrument page JavaScript independently. Browser-specific implementation details stay behind the broker API.
