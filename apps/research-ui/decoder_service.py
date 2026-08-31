import base64
import binascii
import json
import os
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional

DECODER_PROTOCOL_VERSION = 1
MAX_DECODER_INPUT_BYTES = 1 << 20
MAX_DECODER_OUTPUT_BYTES = 1 << 20
MAX_DECODER_ACTION_BYTES = 1536 << 10
MAX_DECODER_PIPELINE_STEPS = 16
MAX_DECODER_RETAINED_BYTES = 4 << 20
MAX_DECODER_JWT_BYTES = 64 << 10
MAX_DECODER_SECRET_BYTES = 4 << 10
MAX_DECODER_JSON_DEPTH = 64
MAX_DECODER_JSON_TOKENS = 100_000
DECODER_TIMEOUT_SECONDS = 2.0
MAX_JWT_EXPIRY_SECONDS = 7 * 24 * 60 * 60

DECODER_OPERATIONS = (
    "base64-encode",
    "base64-decode",
    "base64url-encode",
    "base64url-decode",
    "hex-encode",
    "hex-decode",
    "url-encode",
    "url-decode",
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
)
JWT_ALGORITHMS = ("HS256", "HS384", "HS512", "none")


class DecoderError(ValueError):
    pass


class DecoderProtocolError(DecoderError):
    pass


class DecoderUnavailable(DecoderError):
    pass


class DecoderTimeout(DecoderError):
    pass


def decoder_limits() -> dict[str, Any]:
    return {
        "input_bytes": MAX_DECODER_INPUT_BYTES,
        "output_bytes": MAX_DECODER_OUTPUT_BYTES,
        "pipeline_steps": MAX_DECODER_PIPELINE_STEPS,
        "retained_bytes": MAX_DECODER_RETAINED_BYTES,
        "jwt_bytes": MAX_DECODER_JWT_BYTES,
        "secret_bytes": MAX_DECODER_SECRET_BYTES,
        "json_depth": MAX_DECODER_JSON_DEPTH,
        "json_tokens": MAX_DECODER_JSON_TOKENS,
        "timeout_ms": int(DECODER_TIMEOUT_SECONDS * 1_000),
        "operations": list(DECODER_OPERATIONS),
        "jwt_algorithms": list(JWT_ALGORITHMS),
    }


def _bounded_text(value: Any, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str):
        raise DecoderError(f"{label} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise DecoderError(f"{label} must be valid UTF-8") from exception
    if len(encoded) > maximum_bytes:
        raise DecoderError(f"{label} exceeds {maximum_bytes} bytes")
    return value


def _decode_base64(value: Any, label: str, maximum_bytes: int) -> bytes:
    text = _bounded_text(value, label, ((maximum_bytes + 2) // 3) * 4 + 4)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exception:
        raise DecoderError(f"{label} must be canonical Base64") from exception
    if len(decoded) > maximum_bytes:
        raise DecoderError(f"{label} exceeds {maximum_bytes} decoded bytes")
    return decoded


def _frame(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(part)) + part for part in parts)


def _utf8_or_none(value: bytes) -> Optional[str]:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return None


class DecoderService:
    def __init__(self, executable: Path):
        self.executable = executable.resolve()
        self._lock = threading.Lock()

    def available(self) -> bool:
        return self.executable.is_file() and os.access(self.executable, os.X_OK)

    def state(self) -> dict[str, Any]:
        return {
            "protocol_version": DECODER_PROTOCOL_VERSION,
            "available": self.available(),
            "busy": self._lock.locked(),
            "limits": decoder_limits(),
        }

    def action(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise DecoderError("Decoder action must be an object")
        if request.get("protocol_version") != DECODER_PROTOCOL_VERSION:
            raise DecoderError("Decoder protocol version is unsupported")
        action = request.get("action")
        if action == "transform":
            return self._transform(request)
        if action == "jwt_inspect":
            return self._jwt_inspect(request)
        if action == "jwt_verify":
            return self._jwt_verify(request)
        if action == "jwt_create":
            return self._jwt_create(request)
        raise DecoderError("Decoder action is unsupported")

    def _run(self, arguments: list[str], input_bytes: bytes) -> subprocess.CompletedProcess:
        if not self.available():
            raise DecoderUnavailable("The native decoder executable is unavailable")
        started = time.monotonic_ns()
        acquired = self._lock.acquire(timeout=DECODER_TIMEOUT_SECONDS)
        if not acquired:
            raise DecoderTimeout("The native decoder is busy")
        try:
            try:
                process = subprocess.run(
                    [str(self.executable), *arguments],
                    input=input_bytes,
                    capture_output=True,
                    check=False,
                    timeout=DECODER_TIMEOUT_SECONDS,
                    env={"LC_ALL": "C", "PATH": os.defpath},
                )
            except subprocess.TimeoutExpired as exception:
                raise DecoderTimeout("Decoder operation exceeded two seconds") from exception
        finally:
            self._lock.release()
        process.duration_us = max(1, (time.monotonic_ns() - started) // 1_000)
        return process

    def _transform(self, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {
            "protocol_version",
            "action",
            "operation_id",
            "operation",
            "input_base64",
        }:
            raise DecoderError("Decoder transform shape is invalid")
        operation_id = request.get("operation_id")
        if not isinstance(operation_id, int) or isinstance(operation_id, bool) or operation_id < 1:
            raise DecoderError("Decoder operation ID must be a positive integer")
        operation = request.get("operation")
        if operation not in DECODER_OPERATIONS:
            raise DecoderError("Decoder transform is not allowlisted")
        input_bytes = _decode_base64(
            request.get("input_base64"), "Decoder input", MAX_DECODER_INPUT_BYTES
        )
        process = self._run(["transform", operation], input_bytes)
        if process.returncode != 0:
            error = process.stderr[:4_096].decode("utf-8", errors="replace").strip()
            if process.returncode == 3:
                raise DecoderProtocolError(error or "Decoder output limit was reached")
            raise DecoderError(error or "Native decoder rejected the transform")
        if len(process.stdout) > MAX_DECODER_OUTPUT_BYTES:
            raise DecoderProtocolError("Native decoder returned oversized output")
        text = _utf8_or_none(process.stdout)
        return {
            "protocol_version": DECODER_PROTOCOL_VERSION,
            "ok": True,
            "operation_id": operation_id,
            "operation": operation,
            "input_bytes": len(input_bytes),
            "output_bytes": len(process.stdout),
            "output_base64": base64.b64encode(process.stdout).decode("ascii"),
            "utf8_text": text,
            "hex_preview": process.stdout[:256].hex(),
            "preview_truncated": len(process.stdout) > 256,
            "duration_us": process.duration_us,
        }

    def _jwt_inspect(self, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"protocol_version", "action", "token"}:
            raise DecoderError("JWT inspection shape is invalid")
        token = _bounded_text(request.get("token"), "JWT", MAX_DECODER_JWT_BYTES)
        return self._jwt_response(self._run(["jwt-inspect"], token.encode("utf-8")))

    def _jwt_verify(self, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"protocol_version", "action", "token", "secret"}:
            raise DecoderError("JWT verification shape is invalid")
        token = _bounded_text(request.get("token"), "JWT", MAX_DECODER_JWT_BYTES)
        secret = _bounded_text(
            request.get("secret"), "JWT HMAC secret", MAX_DECODER_SECRET_BYTES
        ).encode("utf-8")
        if not secret:
            raise DecoderError("JWT HMAC secret cannot be empty")
        return self._jwt_response(
            self._run(["jwt-verify"], _frame(token.encode("utf-8"), secret))
        )

    def _jwt_create(self, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {
            "protocol_version",
            "action",
            "payload_json",
            "algorithm",
            "secret",
            "expires_in_seconds",
            "allow_unsigned_confirmed",
        }:
            raise DecoderError("JWT creation shape is invalid")
        payload = _bounded_text(
            request.get("payload_json"), "JWT payload", 56 << 10
        ).encode("utf-8")
        algorithm = request.get("algorithm")
        if algorithm not in JWT_ALGORITHMS:
            raise DecoderError("JWT creation algorithm is unsupported")
        secret = _bounded_text(
            request.get("secret"), "JWT HMAC secret", MAX_DECODER_SECRET_BYTES
        ).encode("utf-8")
        unsigned_confirmed = request.get("allow_unsigned_confirmed")
        if not isinstance(unsigned_confirmed, bool):
            raise DecoderError("Unsigned JWT confirmation must be boolean")
        if algorithm == "none":
            if not unsigned_confirmed:
                raise DecoderError("Creating an unsigned JWT requires explicit confirmation")
            if secret:
                raise DecoderError("Unsigned JWT creation does not accept a secret")
        elif not secret:
            raise DecoderError("Signed JWT creation requires an HMAC secret")
        expires_in = request.get("expires_in_seconds")
        expiration = "none"
        if expires_in is not None:
            if (
                not isinstance(expires_in, int)
                or isinstance(expires_in, bool)
                or not 1 <= expires_in <= MAX_JWT_EXPIRY_SECONDS
            ):
                raise DecoderError("JWT expiry must be between one second and seven days")
            expiration = str(int(time.time()) + expires_in)
        return self._jwt_response(
            self._run(
                ["jwt-create", algorithm, expiration],
                _frame(payload, secret),
            ),
            creation=True,
        )

    def _jwt_response(
        self, process: subprocess.CompletedProcess, creation: bool = False
    ) -> dict[str, Any]:
        if process.returncode != 0 or len(process.stdout) > 256 << 10:
            raise DecoderProtocolError("Native JWT decoder returned an invalid response")
        try:
            response = json.loads(process.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise DecoderProtocolError("Native JWT decoder returned malformed JSON") from exception
        expected = (
            {"protocol_version", "ok", "token", "error"}
            if creation
            else {
                "protocol_version",
                "ok",
                "algorithm",
                "signature_status",
                "header_json",
                "payload_json",
                "token_bytes",
                "signature_bytes",
                "error",
            }
        )
        if not isinstance(response, dict) or set(response) != expected:
            raise DecoderProtocolError("Native JWT decoder response contract is invalid")
        response["duration_us"] = process.duration_us
        return response
