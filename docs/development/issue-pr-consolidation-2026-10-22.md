# Open-issue PR consolidation, 2026-10-22

This is an issue map, not a claim that all acceptance criteria are complete.
Repository visibility stays unchanged. No merge is requested by this report.
The inventory baseline is main `abc519bbe5f3f62a9020d11c1489553fc66c0264`.
Use each PR's final head, checks and manual checklist for acceptance.

| Issue | Canonical PR / disposition | Remaining acceptance |
| --- | --- | --- |
| [#233](https://github.com/sunghoojung/reverse-engineering-browser/issues/233) new-tab Traffic | [#301](https://github.com/sunghoojung/reverse-engineering-browser/pull/301): bounded, generation-checked recovery of stay-open HTTP(S) pages from the debugger list. Unrelated native Backtraces changes were removed from this PR. | This is partial: requests before attachment and `Network.enable`, including short-lived tabs, are not recovered. Confirm live new-tab behavior manually. |
| [#234](https://github.com/sunghoojung/reverse-engineering-browser/issues/234) bundled Brave services | [#293](https://github.com/sunghoojung/reverse-engineering-browser/pull/293): seven research-build defaults. | Full matching Brave build and runtime acceptance, including an explicit opt-in override. |
| [#266](https://github.com/sunghoojung/reverse-engineering-browser/issues/266) native canvas queue loss | Existing queue-capacity work was merged in [#281](https://github.com/sunghoojung/reverse-engineering-browser/pull/281); do not duplicate that implementation. | Reproduce with the matching rebuilt browser rather than an older queue. Queue losses remain distinct from sequence gaps, failed HTTP requests and capture-transport drops. |
| [#267](https://github.com/sunghoojung/reverse-engineering-browser/issues/267) Traffic/native evidence joins | [#297](https://github.com/sunghoojung/reverse-engineering-browser/pull/297) preserves independent native Traffic rows; [#294](https://github.com/sunghoojung/reverse-engineering-browser/pull/294) owns exact identity/order groundwork. | A heuristic match is not exact provenance. Confirm Backtraces choices on a matching capture; cross-process identity limitations remain. |
| [#278](https://github.com/sunghoojung/reverse-engineering-browser/issues/278) live Console documents | [#303](https://github.com/sunghoojung/reverse-engineering-browser/pull/303) (reviewed candidate; branch update pending): direct native document-generation selection, explicit live mutation consent and binding pinning. | Matching native browser build; duplicate-URL tabs, reload/navigation, frame replacement, disconnect/reconnect and no-fallback manual checks. Disposable mode remains the default. |
| [#287](https://github.com/sunghoojung/reverse-engineering-browser/issues/287) Traffic window eviction | [#300](https://github.com/sunghoojung/reverse-engineering-browser/pull/300) (reviewed candidate; branch update pending): independent newest network/general windows, bounded tail scanning and byte-verified parse cache. | Counts have explicit whole-store versus bounded-tail scope. Live browser performance/interaction checks remain; the separate Swift stored-evidence reader is not claimed to have equivalent retention/cache behavior. |
| [#288](https://github.com/sunghoojung/reverse-engineering-browser/issues/288) capture owner loss | [#296](https://github.com/sunghoojung/reverse-engineering-browser/pull/296): ancestor-cleanup ownership correction. | Matching-browser multi-tab/worker/frame stress. This fixes a specific contributor, not every possible hang. |
| [#289](https://github.com/sunghoojung/reverse-engineering-browser/issues/289) captured Runtime Hooks | [#302](https://github.com/sunghoojung/reverse-engineering-browser/pull/302) (reviewed candidate; branch update pending): exact document/source/action guards, explicit mutation confirmation and cleanup independent of target liveness. | Native Add/Arm/Disarm/Erase flow, competing breakpoint pauses, navigation, target closure and reuse. An isolated world is not a sandbox for paused-frame hook logic. |
| [#290](https://github.com/sunghoojung/reverse-engineering-browser/issues/290) failed-request notice | [#298](https://github.com/sunghoojung/reverse-engineering-browser/pull/298) is merged and the issue is closed. Preserve its failed-request counter when integrating #300. | The counter describes retained failed rows, not an asserted deduplicated session total. |
| [#291](https://github.com/sunghoojung/reverse-engineering-browser/issues/291) missing guest execution evidence | [#295](https://github.com/sunghoojung/reverse-engineering-browser/pull/295) owns truthful diagnostics; [#299](https://github.com/sunghoojung/reverse-engineering-browser/pull/299) adds caller-fed bounded writer groundwork and generation-scoped quota claims. | No automatic guest interpreter sampler or actual guest program counter is established by these PRs. Zero samples alone does not prove a build lacks the writer. Reconcile diagnostic wording when integrating #299. |
| [#292](https://github.com/sunghoojung/reverse-engineering-browser/issues/292) initiation/completion identity | [#294](https://github.com/sunghoojung/reverse-engineering-browser/pull/294): exact joins and delivery ordering. | Cross-process namespace propagation still requires matching producer evidence and native validation; do not infer a full fix from exact IDs alone. |

## Integration rules

- Keep each corrective change on its existing canonical PR; preserve source
  commits and review history instead of opening duplicate implementations.
- [#243](https://github.com/sunghoojung/reverse-engineering-browser/pull/243) is a
  separate experimental capture-first approach, not a replacement for the
  narrowly scoped #233 recovery or an accepted first-navigation solution.
- Run the exact final branch checks and resolve overlapping UI/API contracts
  before considering a PR ready. Passing synthetic fixtures does not establish
  native Chromium, macOS compilation or browser runtime acceptance.
- Cloud AF_UNIX restrictions and LeakSanitizer/ptrace incompatibility are
  unavailable local gates, not passing tests. Hosted CI and the documented
  native checklist remain necessary where those restrictions apply.
