import base64
import gzip
import json
import os
import tempfile
import unittest
import zlib
from pathlib import Path

from decoder_service import (
    DECODER_PROTOCOL_VERSION,
    DecoderError,
    DecoderProtocolError,
    DecoderService,
    DecoderTimeout,
    DecoderUnavailable,
)


class DecoderServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = (
            Path(__file__).resolve().parents[2] / "build" / "reb-decoder"
        ).resolve()
        if not cls.binary.is_file():
            raise RuntimeError("build/reb-decoder is required for decoder service tests")

    def setUp(self) -> None:
        self.service = DecoderService(self.binary)

    def action(self, action: str, **values):
        return self.service.action(
            {
                "protocol_version": DECODER_PROTOCOL_VERSION,
                "action": action,
                **values,
            }
        )

    def transform(self, operation: str, value: bytes, operation_id: int = 1):
        return self.action(
            "transform",
            operation_id=operation_id,
            operation=operation,
            input_base64=base64.b64encode(value).decode("ascii"),
        )

    def test_state_and_binary_safe_transform_contract(self) -> None:
        state = self.service.state()
        self.assertTrue(state["available"])
        self.assertFalse(state["busy"])
        self.assertEqual(state["limits"]["input_bytes"], 1 << 20)
        self.assertEqual(state["limits"]["pipeline_steps"], 16)

        encoded = self.transform("hex-encode", b"A\x00Z", operation_id=7)
        self.assertEqual(encoded["operation_id"], 7)
        self.assertEqual(encoded["utf8_text"], "41005a")
        self.assertEqual(encoded["input_bytes"], 3)
        self.assertGreater(encoded["duration_us"], 0)
        decoded = self.transform("hex-decode", b"41005a", operation_id=8)
        self.assertEqual(base64.b64decode(decoded["output_base64"]), b"A\x00Z")
        self.assertEqual(decoded["utf8_text"], "A\x00Z")

    def test_compression_round_trip_and_output_limit(self) -> None:
        source = b"bounded evidence " * 4_096
        compressed = self.transform("gzip-compress", source)
        compressed_bytes = base64.b64decode(compressed["output_base64"])
        self.assertLess(len(compressed_bytes), len(source))
        decompressed = self.transform("gzip-decompress", compressed_bytes)
        self.assertEqual(base64.b64decode(decompressed["output_base64"]), source)

        with self.assertRaisesRegex(DecoderProtocolError, "byte limit"):
            self.transform("gzip-decompress", gzip.compress(b"A" * ((1 << 20) + 1)))

    def test_gzip_decodes_all_members_with_one_output_limit(self) -> None:
        empty = gzip.compress(b"")
        first = b"first\x00" * 100
        second = b"second" * 100
        encoded = empty + gzip.compress(first) + empty + gzip.compress(second) + empty
        decoded = self.transform("gzip-decompress", encoded)
        self.assertEqual(base64.b64decode(decoded["output_base64"]), first + second)

        half = gzip.compress(b"A" * (1 << 19))
        at_limit = self.transform("gzip-decompress", half + half + empty)
        self.assertEqual(base64.b64decode(at_limit["output_base64"]), b"A" * (1 << 20))
        with self.assertRaisesRegex(DecoderProtocolError, "byte limit"):
            self.transform("gzip-decompress", half + half + gzip.compress(b"B"))

    def test_compressed_trailing_data_is_rejected(self) -> None:
        raw = zlib.compressobj(wbits=-15)
        streams = {
            "gzip-decompress": gzip.compress(b"first"),
            "zlib-decompress": zlib.compress(b"first"),
            "deflate-decompress": raw.compress(b"first") + raw.flush(),
        }
        for operation, encoded in streams.items():
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(DecoderError, "malformed|trailing"):
                    self.transform(operation, encoded + b"garbage")
                if operation != "gzip-decompress":
                    with self.assertRaisesRegex(DecoderError, "trailing"):
                        self.transform(operation, encoded + encoded)

    def test_gzip_rejects_malformed_later_members(self) -> None:
        first = gzip.compress(b"first")
        second = gzip.compress(b"second")
        corrupt = second[:-1] + bytes([second[-1] ^ 1])
        for suffix in (second[:1], second[:-3], corrupt, zlib.compress(b"second")):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(DecoderError, "malformed"):
                    self.transform("gzip-decompress", first + suffix)

    def test_transform_rejects_malformed_and_non_allowlisted_actions(self) -> None:
        with self.assertRaisesRegex(DecoderError, "shape"):
            self.service.action(
                {
                    "protocol_version": 1,
                    "action": "transform",
                    "operation_id": 1,
                    "operation": "hex-decode",
                    "input_base64": "00",
                    "extra": True,
                }
            )
        with self.assertRaisesRegex(DecoderError, "allowlisted"):
            self.transform("execute-javascript", b"alert(1)")
        with self.assertRaisesRegex(DecoderError, "canonical Base64"):
            self.action(
                "transform",
                operation_id=1,
                operation="hex-decode",
                input_base64="not base64",
            )
        with self.assertRaisesRegex(DecoderError, "protocol"):
            self.service.action({"protocol_version": 2, "action": "jwt_inspect"})

    def test_jwt_inspect_verify_create_and_unsigned_confirmation(self) -> None:
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjMiLCJhZG1pbiI6dHJ1ZX0."
            "4EgcHtcYc2TlAm54RQRAMM4--ALPIGwXRwjRBu6AMoQ"
        )
        inspection = self.action("jwt_inspect", token=token)
        self.assertTrue(inspection["ok"])
        self.assertEqual(inspection["signature_status"], "not_checked")
        self.assertEqual(inspection["algorithm"], "HS256")
        self.assertTrue(json.loads(inspection["payload_json"])["admin"])

        verified = self.action("jwt_verify", token=token, secret="secret")
        self.assertEqual(verified["signature_status"], "verified")
        invalid = self.action("jwt_verify", token=token, secret="wrong")
        self.assertEqual(invalid["signature_status"], "invalid")

        created = self.action(
            "jwt_create",
            payload_json='{"sub":"native"}',
            algorithm="HS512",
            secret="private-value",
            expires_in_seconds=3_600,
            allow_unsigned_confirmed=False,
        )
        self.assertTrue(created["ok"])
        created_inspection = self.action("jwt_inspect", token=created["token"])
        self.assertEqual(created_inspection["algorithm"], "HS512")
        self.assertIn("exp", json.loads(created_inspection["payload_json"]))

        with self.assertRaisesRegex(DecoderError, "explicit confirmation"):
            self.action(
                "jwt_create",
                payload_json="{}",
                algorithm="none",
                secret="",
                expires_in_seconds=None,
                allow_unsigned_confirmed=False,
            )
        unsigned = self.action(
            "jwt_create",
            payload_json="{}",
            algorithm="none",
            secret="",
            expires_in_seconds=None,
            allow_unsigned_confirmed=True,
        )
        self.assertTrue(unsigned["token"].endswith("."))
        self.assertEqual(
            self.action("jwt_inspect", token=unsigned["token"])["signature_status"],
            "unsigned",
        )

    def test_unavailable_timeout_and_malformed_helper_are_visible(self) -> None:
        unavailable = DecoderService(Path("/not/a/decoder"))
        with self.assertRaises(DecoderUnavailable):
            unavailable.action(
                {
                    "protocol_version": 1,
                    "action": "jwt_inspect",
                    "token": "a.b.c",
                }
            )

        with tempfile.TemporaryDirectory() as temporary:
            helper = Path(temporary) / "helper"
            helper.write_text("#!/bin/sh\nexec sleep 3\n", encoding="utf-8")
            os.chmod(helper, 0o700)
            with self.assertRaises(DecoderTimeout):
                DecoderService(helper).action(
                    {
                        "protocol_version": 1,
                        "action": "jwt_inspect",
                        "token": "a.b.c",
                    }
                )

            helper.write_text("#!/bin/sh\nprintf malformed\n", encoding="utf-8")
            os.chmod(helper, 0o700)
            with self.assertRaises(DecoderProtocolError):
                DecoderService(helper).action(
                    {
                        "protocol_version": 1,
                        "action": "jwt_inspect",
                        "token": "a.b.c",
                    }
                )


if __name__ == "__main__":
    unittest.main()
