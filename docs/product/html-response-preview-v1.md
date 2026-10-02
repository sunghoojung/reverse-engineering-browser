# HTML Response Preview v1

Traffic provides an explicit **Preview** tab for response records whose MIME
type is `text/html`, ignoring case and Content-Type parameters. Request bodies
and other MIME types keep their existing text, JSON, and hex views. Preview
uses only the retained body and does not start sensitive capture or retrieve
missing resources. [SAFETY.md](../../SAFETY.md) governs capture authorization.

## Researcher workflow

1. Enable bounded response content for the authorized session and reproduce
   the request in the attached browser.
2. Select the request in Traffic. In a narrow window, select **Response**.
3. Select **Preview** to inspect the static content, or **Raw body** to inspect
   the original retained markup. Arrow keys, Home, and End navigate the tabs.

The preview labels its isolation and styling limits. Missing, loading,
redacted, failed, empty, or unsupported content displays a reason instead of
fabricated output. Truncated capture is explicitly incomplete. Search, wrapping,
copying, and decoding continue to operate on the source views, not the derived
frame. Preview selection survives unchanged live refreshes.
Supported elements remain previewable even without text, including blocks drawn
with inline backgrounds or borders. Capture and rendering-limit warnings also
remain visible when no supported content survives the inspected prefix.

## Rendering boundary

`apps/research-ui/traffic_view.js` parses at most the existing 128 KiB retained
body in an inert template. It constructs fresh HTML nodes from an explicit
presentation allowlist. No captured node is attached to the application DOM.
Rendering visits at most 1,000 nodes and 24 nested levels; omissions are
visible and Raw body retains the full captured prefix.

Scripts, metadata, base URLs, stylesheets, embedded frames, objects, SVG, MathML,
custom elements, event attributes, resource URLs, and link destinations are
discarded. Images become escaped text placeholders with their alternative text.
Forms become static containers, and form controls are disabled. Only bounded
title, language, direction, and value attributes survive; table spans are
limited to 64. Inline
styles use a fixed presentation-property allowlist and bounded simple values,
including numeric RGB/HSL colors; URLs, escapes, arbitrary functions, custom
properties, positioning, and animation are excluded. Each style value is capped
at 256 characters, with numeric components capped at 4,096 to reject pathological
layout sizes.

The serialized result loads through `iframe.srcdoc` with an empty `sandbox`
attribute and `no-referrer` policy. The frame has an opaque origin and cannot
execute scripts, submit forms, navigate the parent, open windows, or access the
application's data. A trusted Content Security Policy appears before derived
content: `default-src 'none'`, explicit script/resource restrictions,
`base-uri 'none'`, and `form-action 'none'`. Only inline styles are allowed.
The preview is a static approximation, not a replay of the original page.

## Evidence and compatibility

No broker, HTTP, storage, or capture contract changes are required. Source
records remain immutable, and production bundles include no preview fixtures.
The native macOS WebKit shell and browser development UI share the same renderer
and limits. Validate with a synthetic local capture containing executable
markup and resource attempts, check zero resource deliveries and unchanged raw
bytes, and exercise keyboard navigation and narrow layouts in both product paths.
