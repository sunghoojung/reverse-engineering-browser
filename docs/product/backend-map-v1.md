# Backend map v1

A researcher who has captured an authorized site wants to know what is behind
its front end: who hosts it, which CDN and proxies sit in front, which server
framework answers, which backend services and third-party products the page
talks to, and what the API surface looks like. **Backend** in Origin Trace
answers that from the traffic already captured, and agents get the same answer
from `get_backend_map` (contract: [Backend map](../../protocol/http-api.md#backend-map)).

It is an offline reading. It never sends a request, probes a host, resolves a
name or calls an online service, and it never runs captured code. Every finding
is a guess that names the evidence it rests on, so the researcher can open the
Traffic row behind it and judge it.

## What it reads

One walk of every Traffic row, through the HAR export's exact joins, so each
hop's URL, status, HTTP version, remote address, header blocks and retained
bodies come from the same records Traffic and the HAR show. Scripts are kept
as source artifacts rather than response bodies, so each distinct script on a
mapped host is then read once, and its citations open it in Sources. Browser
pages such as the new tab page are skipped and counted.

| Technique | What it reveals | Needs |
| --- | --- | --- |
| Vendor headers (`x-vercel-id`, `cf-ray`, `x-amz-cf-pop`, `fly-request-id`, `x-railway-edge`, `x-nf-request-id`, `x-render-origin-server`, `server`, `via`, `x-powered-by`, ...) | Hosting platform, CDN, proxy, server, framework; edge region or POP as a short token | Header capture |
| Server-Timing, Cache-Status, Via and X-Cache names | Stacked layers (Cloudflare in front of Vercel), Workers that ran, Rails instrumentation | Header capture |
| ETag formats (nginx `"mtime-length"`, Apache, Express `W/"len-sha1"`, Rack, Spring `"0…"`, IIS `":0"`, Netlify `-ssl`) | The origin or storage layer, even when `Server` is stripped | Header capture |
| Cookie names, never values (`JSESSIONID`, `PHPSESSID`, `laravel_session` and Laravel 11's `laravel-session`, `connect.sid`, `__cf_bm`, `AWSALB`, `__client_uat`, `sb-<ref>-auth-token`, bot-vendor names) | Language, framework, load balancer, auth provider, bot protection | Header capture |
| Hosts and paths (`*.supabase.co`, `firestore.googleapis.com`, `*.ingest.sentry.io`, `/_next/`, `/__data.json`, `/rest/v1/`, `/wp-json/`, `/cdn-cgi/`) | Backend services, third-party products, framework transports | Metadata |
| Request headers the page sends (`rsc`, `next-action`, `x-inertia`, `hx-request`, `x-client-info: supabase-js/2.x`, `apollographql-client-name`, `sentry-trace`, `traceparent`) | Client SDKs and their versions, and which backends are traced | Header capture |
| Error bodies and default pages (Spring, DRF, FastAPI, Laravel, NestJS, Fastify, ASP.NET ProblemDetails, PostgREST `PGRST` codes, Prisma, Apollo, nginx, Werkzeug, Go, S3, CloudFront) | Framework and storage behind an API | Content capture |
| Bundle configuration (Supabase project URLs, Firebase `authDomain`, Sentry DSNs, Cognito pool regions, Stripe live or test mode) | Services the bundle is built against | Content capture |
| Declared hosts: CSP (header and `<meta>`), Report-To, Reporting-Endpoints, NEL and Link headers, and URLs in bodies | Services the site may use but this capture did not exercise | Header or content capture |
| CORS header names (`Access-Control-Expose-Headers`, `-Allow-Headers`, the page's `-Request-Headers`) | Custom backend headers and the client SDKs that send them | Header capture |
| Remote addresses against bundled published ranges (Cloudflare, Fastly, CloudFront, AWS, Google Cloud, Google) | The outermost network layer | Header capture |
| Route templating (`/api/users/{int}`, `{uuid}`, `{objectid}`, `{ulid}`, `{cus_id}`, ...) seeded by templates the server names (`x-matched-path`, `x-sveltekit-routeid`) | The API surface per host, with its style: JSON, GraphQL, tRPC, RSC, gRPC-Web, Connect, SSE, WebSocket | Metadata for hosts, content capture for paths |

A Metadata-only session keeps hosts and remote addresses but no paths,
headers or bodies, so most signals cannot match; the screen and `coverage`
say so instead of implying the site has no stack.

## How a guess is scored and shown

- **Signals** are reviewed rules in
  `apps/origin-trace-backend/assets/backend-signatures.json`. Each has a weight
  from 1 to 100 and a tier: `vendor` for a marker one product emits by design,
  `convention` for a name or shape that products share or anyone can set.
- **Confidence** adds the weights of a technology's distinct signals, capped at
  100. It is a ranking aid, not a probability. A technology another implies
  (Next.js implies React, Supabase implies PostgREST and PostgreSQL) takes the
  confidence of what implies it and is marked `implied`.
- **Declared** evidence alone supports at most 40: a policy or a URL in a bundle
  says what a site may use, not what it used.
- **Scope** separates the answer a researcher wants from noise. `site` is the
  site's own stack (evidence on a first-party host). `service` is a backend or
  third-party service seen on its vendor's hosts. `vendor` is how a third party
  serves its own hosts: Stripe's nginx describes Stripe, not the site.
- **Layers are not contradictions.** Cloudflare and Vercel on one host means
  Cloudflare in front of Vercel; both are listed with their evidence.

## Privacy

Credential header values and cookie values never reach a rule: the analyzer
drops every value of a credential-named header (the rule `get_request_headers`
uses) and keeps only cookie names. A rule may return only a short plain token
it captured, such as `iad1`, `SJC`, `2.45.4`, a 20-character Supabase project
reference or `live`; a longer capture is counted and dropped. Whole header
values are never returned, since several carry request identifiers. The
analyzer needs no change to [SAFETY.md](../../SAFETY.md): it reads only what
the session already retained and adds nothing to capture.

## Using it

Open **Backend** in the sidebar (⌘6). **Stack** lists technologies by scope and
category, each with its confidence, basis, party and captured tokens; selecting
one shows every signal, the hosts it matched, and first and last citations that
open their Traffic row. **Hosts & routes** lists contacted hosts with their role,
addresses and ranges, CORS names and route table, then hosts that were only
named. **Refresh** reads the session again; a failed refresh keeps the last map.

Agents call `get_backend_map` with the Traffic filters, or `rows`, to map one
part of a session.

## Rule maintenance

- Every rule cites a primary source where one exists (vendor docs or framework
  source) in its technology's `references`. Fingerprint databases under the GPL
  (the maintained Wappalyzer forks, WhatWeb) were consulted as reference only;
  none of their data is copied.
- The backend's tests refuse a rule file with a repeated ID, an unknown
  category, implication or range provider, an implication cycle, a pattern that
  does not compile, a capture group that does not exist, or a cookie capture.
- `tools/update-backend-ip-ranges.py` regenerates
  `assets/backend-ip-ranges.json` from the providers' published lists. It is the
  only part that touches the network, and only when a maintainer runs it.

## Not included in v1

TLS certificate issuer and names (not captured), header order (not yet
verified to be wire order for HTTP/2 and HTTP/3), JWT claim reading (tokens are
credentials), source map `sources[]` paths, JSON key-casing and pagination
heuristics, ID format attribution beyond route templating, and a log-odds
confidence model with independence groups. Each is a candidate for v2.
