#!/usr/bin/env python3

import json
import shutil
import subprocess
import unittest
from pathlib import Path


class DecoderUiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

    def test_tools_ui_exposes_bounded_explicit_decoder_and_jwt_flows(self) -> None:
        for marker in (
            'data-screen="tools"',
            'id="request-decoder-pivot"',
            'id="decoder-pipeline"',
            'id="decoder-output"',
            'id="jwt-inspect-form"',
            'id="jwt-create-form"',
            "function appendDecoderTransform()",
            "function runJwtAction(action)",
            "function createJwtToken()",
            "At most 16 explicit steps",
            "Decompression stops at the output cap",
            "Decoding is not verification",
            "I understand this creates an unsigned token with no authenticity",
            "Native C++ decoder ready",
        ):
            self.assertIn(marker, self.html)

        for operation in (
            "base64-encode",
            "base64-decode",
            "base64url-encode",
            "base64url-decode",
            "hex-encode",
            "hex-decode",
            "url-encode",
            "url-decode",
            "html-encode",
            "html-decode",
            "base36-encode",
            "base36-decode",
            "gzip-compress",
            "gzip-decompress",
            "zlib-compress",
            "zlib-decompress",
            "deflate-compress",
            "deflate-decompress",
            "json-pretty",
            "json-minify",
        ):
            self.assertIn(f'value="{operation}"', self.html)

        state_model = self.html[
            self.html.index("      const state = {") : self.html.index("      const elements = {")
        ]
        self.assertNotIn("jwtSecret", state_model)
        self.assertNotIn("jwtCreateSecret", state_model)
        self.assertIn("toolsElements.jwtSecret.value = '';", self.html)
        self.assertIn("toolsElements.jwtCreateSecret.value = '';", self.html)

    def test_browser_contract_accepts_native_null_errors_and_rejects_mismatches(
        self,
    ) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")
        start = self.html.index("      const decoderNativeOperations")
        end = self.html.index("      async function createAnalystFolder")
        model = self.html[start:end]
        exercise = r"""
const isPlainObject = value => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const isSafeIntegerInRange = (value, minimum, maximum) => Number.isSafeInteger(value) && value >= minimum && value <= maximum;
const utf8ByteLength = value => new TextEncoder().encode(value).byteLength;
const engine = {protocol_version: 1, available: true, busy: false, limits: {
  input_bytes: 1048576, output_bytes: 1048576, pipeline_steps: 16,
  retained_bytes: 4194304, jwt_bytes: 65536, secret_bytes: 4096,
  json_depth: 64, json_tokens: 100000, timeout_ms: 2000,
  operations: [...decoderNativeOperations], jwt_algorithms: [...decoderAlgorithms]
}};
const request = {operation_id: 7, operation: 'base64-decode'};
const transform = {protocol_version: 1, ok: true, operation_id: 7,
  operation: 'base64-decode', input_bytes: 8, output_bytes: 5,
  output_base64: 'SGVsbG8=', utf8_text: 'Hello', hex_preview: '48656c6c6f',
  preview_truncated: false, duration_us: 3};
const inspection = {protocol_version: 1, ok: true, algorithm: 'HS256',
  signature_status: 'verified', header_json: '{"alg":"HS256"}',
  payload_json: '{"sub":"123"}', token_bytes: 100, signature_bytes: 32,
  error: null, duration_us: 4};
const creation = {protocol_version: 1, ok: true, token: 'a.b.c', error: null,
  duration_us: 5};
process.stdout.write(JSON.stringify({
  engineAccepted: isDecoderEngine(engine),
  missingOperationRejected: !isDecoderEngine({...engine, limits: {...engine.limits,
    operations: engine.limits.operations.slice(1)}}),
  transformAccepted: isDecoderTransform(transform, request),
  mismatchedOperationRejected: !isDecoderTransform({...transform, operation_id: 8}, request),
  malformedBase64Rejected: !isDecoderTransform({...transform, output_base64: 'SGVsbG8'}, request),
  inspectionNullErrorAccepted: isJwtInspection(inspection),
  unsupportedStatusRejected: !isJwtInspection({...inspection, signature_status: 'trusted'}),
  creationNullErrorAccepted: isJwtCreation(creation),
  unexpectedCreationFieldRejected: !isJwtCreation({...creation, secret: 'leak'})
}));
"""
        result = subprocess.run(
            [node, "-e", f"{model}\n{exercise}"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertTrue(all(json.loads(result.stdout).values()))


if __name__ == "__main__":
    unittest.main()
