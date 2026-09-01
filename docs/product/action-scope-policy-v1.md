# Action Scope Policy v1

Action Scope gives mutable browser tools one shared policy for either every
disposable page or one exact disposable page. It completes the page-selector
workflow pinned from WireBrowser commit
`77e1e48ceb4acaef0356877ee2d09391763613cc` without allowing rules to reach
the baseline browsing context.

## Scope boundary

The policy applies to Request Interception and Automation Recipes. Repeater,
Object Lab, and Runtime Hooks remain attached to the primary disposable page
because their state contains page-specific requests, object references, or
debugger locations that cannot safely move between targets.

`global` means all page and webview targets inside the current disposable
Experiment BrowserContext. It never means every open Brave tab. `target`
means one exact target ID in that same context. Removing a targeted page leaves
the policy in an error state and never widens it to global.

## Contract

The debugger snapshot exposes `action_scope` with protocol version 1:

- state: `idle`, `discovering`, `ready`, `partial`, `disposed`, or `error`;
- mode: `global` or `target`;
- exact target ID for targeted mode;
- monotonically increasing policy revision;
- bounded target records with ID, type, redacted URL, connection, and match
  state;
- matched, connected, and overflow counts;
- the shared and target-only rule-family lists;
- fixed limits for targets and queued automation triggers.

The control plane rejects policy changes while interception requests or
automation work are active. Arming a mutable rule requires every matched page
to be connected and refuses overflow, so a global rule cannot silently cover
only part of the context.

## Target sessions

Each retained disposable page owns one DevTools WebSocket session. A session
has an independent command sequence and pending-command table. Request IDs are
keyed by page and request ID, and automation runs are serialized across pages.
The browser bridge retains at most eight page sessions and sixteen queued
automation triggers.

Request Interception installs Fetch rules only on matched sessions. Automation
installs before-load bindings and scripts on every matched session atomically,
then runs created, before-load, after-load, and manual recipes with the exact
page ID recorded in each result. A matched-page disconnect disarms automatic
recipes to prevent partial coverage.

## Privacy and lifecycle

New pages accept only credential-free HTTP or HTTPS URLs without fragments, or
`about:blank`. Public state strips query text. Interception audit records add
the target ID but still omit query strings, headers, and bodies. Disposing the
BrowserContext closes every target session and erases rule, variable, result,
and queue state according to the owning tool's existing lifecycle.

The inactive path does not change native probes, renderer transports, event
records, or C++ hot paths. Target discovery and policy work run only while a
disposable Experiment context exists.
