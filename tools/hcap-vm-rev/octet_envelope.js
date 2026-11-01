/**
 * Reconstructive model of click-session POST api.hcaptcha.com request 13
 * (Origin Trace session 9623810216396876129).
 *
 * SAFETY: reconstructive analysis only. No solver, no captured payload
 * bytes, no tokens/sitekeys/bodies, no api.hcaptcha.com I/O.
 *
 * Proven from reb-api on stored session http://127.0.0.1:56738
 * (get_health, get_session_context, get_artifacts, get_events,
 *  inspect_wasm, get_vm_analysis, get_vm_opcode_workspace,
 *  get_vm_host_links). Native network payloads are METHOD+host only
 *  (request_started) and MIME+protocol (response_started).
 *  payload_truncated=false on every req 11–17 row.
 *
 *  decoded_body_length on request_completed is the decoded RESPONSE
 *  body: req 12 decoded 1543169 == artifact 4 byte_size; req 14
 *  decoded 33480 == artifact 6 byte_size; req 5 decoded 415879 ==
 *  artifact 2 byte_size. Therefore req 13's 2613 is the response
 *  length, paired with response MIME application/octet-stream.
 *
 * Field layout of those 2613 bytes: UNKNOWN (no body capture).
 */
"use strict";

/** Reconstructive schema version. Not a recovered HSW protocol version. */
const ENVELOPE_VERSION = 1;

const SESSION_ID = "9623810216396876129";

const RESOURCE_TYPE = Object.freeze({
  main_frame: 0,
  sub_frame: 1,
  stylesheet: 2,
  script: 3,
  image: 4,
  favicon: 12,
  xhr: 13,
});

/**
 * Named stages in recorded order. Sizes/MIME/order are proven.
 * URL paths are proven only when an artifact URL exists; XHR paths
 * are inferred from timing+MIME, never from a captured path.
 */
const STAGES = Object.freeze([
  Object.freeze({
    name: "demo_document",
    requestId: 4,
    method: "GET",
    host: "accounts.hcaptcha.com",
    resourceType: RESOURCE_TYPE.main_frame,
    status: 200,
    contentType: "text/html",
    protocol: "h2",
    decodedBodyLength: 4359,
    encodedDataLength: 2801,
    path: "UNKNOWN",
    role: "demo document",
  }),
  Object.freeze({
    name: "api_js",
    requestId: 5,
    method: "GET",
    host: "js.hcaptcha.com",
    resourceType: RESOURCE_TYPE.script,
    status: 200,
    contentType: "application/javascript",
    protocol: "h2",
    decodedBodyLength: 415879,
    encodedDataLength: 118030,
    artifactId: 2,
    pathHint: "/1/api.js",
    role: "widget loader",
  }),
  Object.freeze({
    name: "telemetry_png_parent",
    requestId: 6,
    method: "GET",
    host: "*.w.hcaptcha.com",
    resourceType: RESOURCE_TYPE.xhr,
    status: 200,
    contentType: "image/png",
    protocol: "http/1.1",
    decodedBodyLength: 2593,
    encodedDataLength: 3313,
    path: "UNKNOWN",
    role: "telemetry/logo candidate",
  }),
  Object.freeze({
    name: "hcaptcha_html_challenge_frame",
    requestId: 7,
    method: "GET",
    host: "newassets.hcaptcha.com",
    resourceType: RESOURCE_TYPE.sub_frame,
    status: 200,
    contentType: "text/html",
    protocol: "h2",
    decodedBodyLength: 694539,
    encodedDataLength: 209862,
    pathHint: "/captcha/v1/[build]/static/hcaptcha.html",
    role: "challenge iframe",
  }),
  Object.freeze({
    name: "hcaptcha_html_checkbox_frame",
    requestId: 8,
    method: "GET",
    host: "newassets.hcaptcha.com",
    resourceType: RESOURCE_TYPE.sub_frame,
    status: 200,
    contentType: "text/html",
    protocol: "h2",
    decodedBodyLength: 694539,
    encodedDataLength: 0,
    flags: ["from_cache"],
    path: "UNKNOWN",
    role: "checkbox iframe (same decoded size, cache hit)",
  }),
  Object.freeze({
    name: "favicon_404",
    requestId: 9,
    method: "GET",
    host: "accounts.hcaptcha.com",
    resourceType: RESOURCE_TYPE.favicon,
    status: 404,
    contentType: "text/plain",
    protocol: "h2",
    decodedBodyLength: 0,
    encodedDataLength: 46,
    path: "UNKNOWN",
  }),
  Object.freeze({
    name: "telemetry_png_challenge_frame",
    requestId: 10,
    method: "GET",
    host: "*.w.hcaptcha.com",
    resourceType: RESOURCE_TYPE.xhr,
    status: 200,
    contentType: "image/png",
    protocol: "http/1.1",
    decodedBodyLength: 2593,
    encodedDataLength: 3313,
    path: "UNKNOWN",
    role: "telemetry/logo candidate",
  }),
  Object.freeze({
    name: "getcaptcha_json",
    requestId: 11,
    method: "POST",
    host: "api.hcaptcha.com",
    resourceType: RESOURCE_TYPE.xhr,
    status: 200,
    contentType: "application/json",
    protocol: "h2",
    decodedBodyLength: 822,
    encodedDataLength: 867,
    path: "UNKNOWN",
    pathInferredAs: "getcaptcha",
    role: "first api.hcaptcha.com POST; JSON 822 B; before hsw.js",
    tRelMsFromDemo: 325.23,
  }),
  Object.freeze({
    name: "hsw_js",
    requestId: 12,
    method: "GET",
    host: "newassets.hcaptcha.com",
    resourceType: RESOURCE_TYPE.script,
    status: 200,
    contentType: "application/javascript",
    protocol: "h3",
    decodedBodyLength: 1543169,
    encodedDataLength: 671603,
    artifactId: 4,
    pathHint: "/c/[content-hash]/hsw.js",
    role: "HSW glue",
    tRelMsFromDemo: 370.297,
  }),
  Object.freeze({
    name: "wasm_stub",
    requestId: null,
    origin: "webassembly_module",
    artifactId: 3,
    byteLength: 8,
    contentType: "application/wasm",
    role: "empty \\0asm stub",
  }),
  Object.freeze({
    name: "wasm_instantiate",
    requestId: null,
    origin: "webassembly_instantiate",
    artifactId: 5,
    byteLength: 1020263,
    contentType: "application/wasm",
    sha256Prefix: "49086a4a",
    vmScore: 75,
    tier: "likely-vm",
    importedFunctions: 190,
    brTableCount: 742,
    callIndirectCount: 144,
    dispatchSiteCount: 886,
    nativeDispatchSamples: 0,
    role: "HSW wasm (CFF). Host-links stop at req 12 (seq 39); req 13 is 67.8s later.",
  }),
  Object.freeze({
    name: "octet_stream",
    requestId: 13,
    method: "POST",
    host: "api.hcaptcha.com",
    resourceType: RESOURCE_TYPE.xhr,
    status: 200,
    contentType: "application/octet-stream",
    protocol: "h3",
    decodedBodyLength: 2613,
    encodedDataLength: 3112,
    responseStartedEncoded: 471,
    path: "UNKNOWN",
    requestContentType: "UNKNOWN",
    requestBodyLength: "UNKNOWN",
    fieldLayout: "UNKNOWN",
    role: "post-click binary exchange; response MIME+length proven",
    tRelMsFromDemo: 68135.037,
    tRelMsFromGetcaptcha: 67809.807,
    rttMs: 190.122,
    rendererInitiated: true,
  }),
  Object.freeze({
    name: "challenge_js_image_drag_drop",
    requestId: 14,
    method: "GET",
    host: "newassets.hcaptcha.com",
    resourceType: RESOURCE_TYPE.script,
    status: 200,
    contentType: "text/javascript",
    protocol: "h3",
    decodedBodyLength: 33480,
    encodedDataLength: 9444,
    artifactId: 6,
    pathHint: "/captcha/v1/[build]/challenge/image_drag_drop/challenge.js",
    challengeKind: "image_drag_drop",
    role: "visual challenge UI; starts 7.7ms after octet-stream completes",
    tRelMsFromDemo: 68332.953,
  }),
  Object.freeze({
    name: "challenge_image_jpeg",
    requestId: 15,
    method: "GET",
    host: "imgs3.hcaptcha.com",
    resourceType: RESOURCE_TYPE.image,
    status: 200,
    contentType: "image/jpeg",
    protocol: "h2",
    decodedBodyLength: 40878,
    encodedDataLength: 41228,
    path: "UNKNOWN",
  }),
  Object.freeze({
    name: "challenge_image_png_a",
    requestId: 16,
    method: "GET",
    host: "imgs3.hcaptcha.com",
    resourceType: RESOURCE_TYPE.image,
    status: 200,
    contentType: "image/png",
    protocol: "h2",
    decodedBodyLength: 3729,
    encodedDataLength: 4034,
    path: "UNKNOWN",
  }),
  Object.freeze({
    name: "challenge_image_png_b",
    requestId: 17,
    method: "GET",
    host: "imgs3.hcaptcha.com",
    resourceType: RESOURCE_TYPE.image,
    status: 200,
    contentType: "image/png",
    protocol: "h2",
    decodedBodyLength: 5019,
    encodedDataLength: 5594,
    path: "UNKNOWN",
  }),
]);

const STAGE_BY_NAME = Object.freeze(
  Object.fromEntries(STAGES.map((s) => [s.name, s]))
);

/**
 * Proven vs UNKNOWN for the 2613-byte octet-stream message.
 * Offsets, version bytes, ciphertext structure: not in the capture.
 */
const FIELD_LAYOUT = Object.freeze({
  status: "UNKNOWN",
  proven: Object.freeze({
    sessionId: SESSION_ID,
    requestId: 13,
    method: "POST",
    host: "api.hcaptcha.com",
    resourceType: RESOURCE_TYPE.xhr,
    httpStatus: 200,
    responseContentType: "application/octet-stream",
    protocol: "h3",
    decodedBodyLength: 2613,
    encodedDataLengthCompleted: 3112,
    encodedDataLengthResponseStarted: 471,
    nativePayload: "METHOD+host only",
    nativePayloadText: "POST api.hcaptcha.com",
    nativePayloadSize: 21,
    payloadTruncated: false,
    order: Object.freeze({
      after: "getcaptcha_json",
      afterContentType: "application/json",
      afterDecodedBodyLength: 822,
      before: "challenge_js_image_drag_drop",
      beforeContentType: "text/javascript",
      beforeDecodedBodyLength: 33480,
    }),
    dwellMsAfterGetcaptchaStart: 67809.807,
    responseRttMs: 190.122,
    challengeJsDelayMsAfterComplete: 7.709,
  }),
  unknown: Object.freeze([
    "url_path",
    "query_string",
    "request_content_type",
    "request_body_length",
    "request_body_bytes",
    "response_body_bytes",
    "protocol_version_byte",
    "header_length_encoding",
    "field_order",
    "field_widths",
    "ciphertext_vs_plaintext_split",
    "pow_nonce_presence",
    "session_binding_fields",
    "whether_path_is_getcaptcha_or_checkcaptcha",
  ]),
});

const UNKNOWN = FIELD_LAYOUT.unknown;

/**
 * Encode the observed envelope metadata. Never includes captured
 * payload bytes. `version` is this module's schema, not a wire tag.
 *
 * Shape: { version, contentType, byteLength, after, before }
 */
function encodeEnvelope() {
  const after = STAGE_BY_NAME.getcaptcha_json;
  const before = STAGE_BY_NAME.challenge_js_image_drag_drop;
  const envelope = Object.freeze({
    version: ENVELOPE_VERSION,
    contentType: "application/octet-stream",
    byteLength: 2613,
    after: Object.freeze({
      stage: after.name,
      contentType: after.contentType,
      byteLength: after.decodedBodyLength,
      requestId: after.requestId,
      method: after.method,
      host: after.host,
    }),
    before: Object.freeze({
      stage: before.name,
      contentType: before.contentType,
      byteLength: before.decodedBodyLength,
      requestId: before.requestId,
      method: before.method,
      host: before.host,
      pathHint: before.pathHint,
      challengeKind: before.challengeKind,
    }),
  });
  assertNoPayloadBytes(envelope);
  return envelope;
}

function assertNoPayloadBytes(value, path) {
  const here = path || "$";
  if (value == null) return;
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(value)) {
    throw new Error("captured payload bytes forbidden at " + here);
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    throw new Error("captured payload bytes forbidden at " + here);
  }
  if (typeof value === "string") {
    if (/^[A-Za-z0-9+/=_-]{40,}$/.test(value) && here.indexOf("sha") === -1) {
      throw new Error("token-like string forbidden at " + here);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoPayloadBytes(v, here + "[" + i + "]"));
    return;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (/body|token|sitekey|cookie|payloadBytes/i.test(k) && k !== "decodedBodyLength") {
        const v = value[k];
        if (v && typeof v === "object") {
          throw new Error("payload field forbidden at " + here + "." + k);
        }
      }
      assertNoPayloadBytes(value[k], here + "." + k);
    }
  }
}

function stage(name) {
  return STAGE_BY_NAME[name] || null;
}

function sequenceNames() {
  return STAGES.map((s) => s.name);
}

const api = {
  ENVELOPE_VERSION,
  SESSION_ID,
  RESOURCE_TYPE,
  STAGES,
  STAGE_BY_NAME,
  FIELD_LAYOUT,
  UNKNOWN,
  encodeEnvelope,
  stage,
  sequenceNames,
  assertNoPayloadBytes,
};

module.exports = api;
