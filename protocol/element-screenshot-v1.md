# Element screenshot markup v1

> **Retired.** Element screenshots used the backend CDP transport through `POST /api/debugger/actions`. CDP and the `/api/debugger` routes were removed; every `/api/debugger` route now returns 410 `debugger_unavailable`, and no operation or schema in [openapi.json](openapi.json) implements this contract. This page is kept as a historical record for reading earlier captures and notes.

This is explicit, local-only capture of the selected **primary disposable
Experiment page**. The researcher opens an authorized HTTP(S) page in Objects,
opens Experiments → Element screenshot, clicks **Inspect selected document**,
reviews the limits and confirms raw local capture, then clicks **Grab local
screenshot**. Numbered local overlays and a keyboard-selectable list identify
layout bounds. Selecting a number never interacts with the target page.

This workflow used the backend's CDP transport. It does not use
page JavaScript, DOM injection, the native Console, Canvas artifact capture, an
AI/vision provider, or test-harness screenshots. It does not establish ownership
or permission to capture a target. [SAFETY.md](../SAFETY.md) still applies.

## Exact scope and lifecycle

Two actions share `POST /api/debugger/actions` and the `reb-api` CLI:

- `inspect_element_document`: requires an explicit `target_id` equal to the
  currently selected, running primary owned disposable page. Returns `document`.
- `capture_element_screenshot`: requires the complete original `selection` and
  `confirm_sensitive: true`. Returns `capture` with format
  `reb-element-screenshot-v1`, the same document descriptor and a PNG.

The [OpenAPI schema](openapi.json) defines closed request and response objects.
The selection contains `instance_id`, `connection_epoch`, `session_id`, `target_id`,
`document_epoch`, `frame_id`, `loader_id`, `document_node_id` and `revision`.
Instance/session/connection checks prevent cross-session and reconnect reuse.
Frame and loader IDs and the root backend node bind the document. Navigation,
same-document navigation, document-open and resize observations advance a
public epoch. `connection_epoch` is the existing `network.capture_epoch`, which
changes even on a same-page reconnect with unchanged frame/loader/DOM IDs. Capture
owner fields must match before any CDP read; a stale request cannot inspect the
new lifetime's raw DOM before refusal. A SHA-256 fingerprint covers the bounded DOM snapshot, viewport,
frame identity and owner. It is a selection revision, not a universal DOM
mutation counter or an authenticity signature.

Capture rereads the selection immediately before requesting pixels, then reads
it again afterward. Any observed change refuses the result. The original live
connection and disposable ownership must still match. No missing, stale or
unsupported input substitutes another target or retries automatically. The
normal debugger action lock excludes competing explicit actions; existing
Memory, Object, Hooks, Automation and Repeater ownership guards also apply.

The UI binds each pending request to its local context generation. New document,
backend, target or experiment state, disconnection, Cancel / clear, leaving the
panel or page hide retires late replies. Requests have a 15-second client deadline.
A backend request can continue briefly after HTTP cancellation, but expires at
12 seconds and retains no image in debugger state. A returned image is a
historical local snapshot, never a promise that the live page still matches.

## Privacy and limits

Inspection uses `DOMSnapshot.captureSnapshot`, not runtime evaluation. Its raw
text and attributes are read transiently in the local backend to check privacy
markers and fingerprint the selection. They are never returned in the document
metadata, written to evidence, or logged by this feature. Only opaque IDs,
finite geometry, fixed limitations, and counts are returned.

The entire capture is refused if either observed snapshot contains an input,
textarea, select, option, form, editable attribute, `data-reb-private`,
`data-private`, or `data-sensitive`. This intentionally includes hidden fields
and `contenteditable="false"`. Frames, shadow trees, object/embed documents,
multiple documents and malformed/incomplete snapshot structure are also refused.
The privacy gate runs before the screenshot and again afterward. It cannot
identify arbitrary custom-editor or document-designMode editing state,
sensitive text/images, or detect a field that appears and
disappears entirely between observations. **This is not a redaction or secrecy
guarantee.** Use only authorized non-sensitive fixtures for development.

| Resource | Bound / behavior |
| --- | --- |
| DOM snapshot | 4096 nodes; 2 MiB serialized snapshot; 256 attribute entries per node |
| Geometry | 128 viewport-intersecting element layout boxes; overflow refuses the whole operation |
| Viewport / PNG | Each edge ≤4096; area ≤8,000,000 pixels; PNG ≤4 MiB |
| Encoded PNG | ≤5,592,408 base64 characters, PNG signature/IHDR dimensions checked |
| Timing | Shared writer admission/write ≤5 seconds, command reply wait ≤3 seconds; entire inspect/capture ≤12 seconds |
| Zoom | Unit page and pinch zoom only; unsupported zoom refuses capture |
| Device scale | Derived from actual PNG dimensions versus CSS viewport, each axis 0.5–4; discrepancy >0.01 refuses |
| Retention | One ephemeral local UI document/image; no backend screenshot history or disk write |

The debugger transport's existing 64 MiB frame ingress bound applies before
feature-specific 2 MiB snapshot validation. Limits fail closed; there is no
silent node truncation or partial PNG success. Hidden/no-layout nodes are not
numbered; `outside_viewport` counts only element layout boxes excluded because
they do not intersect the viewport. No claim of complete DOM coverage is made.

## Geometry and image interpretation

`viewport` is the CSS visual viewport's document-space x/y/width/height. Bounds
come from the same top-level DOMSnapshot layout tree and are clipped against
that viewport, then expressed relative to its top-left. `viewport_clipped`
records that clipping. Scroll offsets therefore do not masquerade as image
coordinates. The screenshot explicitly clips the current viewport and does not
scroll, resize, change device emulation, or capture beyond it.

The PNG carries its actual pixel width/height and SHA-256 digest. The UI validates
the digest, PNG header and decoded dimensions, then scales geometry as a fraction
of the displayed image. Number buttons and a separate list support pointer,
Tab/Enter/Space and arrow/Home/End selection with visible focus. Overlapping
labels remain possible; the list makes every retained number reachable.

`consistency` is `before-after-observed-stable`, **not atomic**. Paint-only
animations, image/canvas/video changes and a state that changes and reverts
between reads can escape fingerprint comparison. `occlusion` is always
`unknown`: layout bounds do not establish visibility, hit testing, overlap,
ancestor clipping, transforms, pseudo-element coverage or exact painted shapes.
The overlay is not a segmentation mask or visual verification result.

## Verification

The checks that covered this workflow (`tools/check-element-screenshot.mjs`,
the Rust `debugger::element_screenshot` tests and the `make backend-e2e`
capture run) were removed with the implementation.
