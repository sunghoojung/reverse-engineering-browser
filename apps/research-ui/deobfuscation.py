"""Bounded deobfuscation analysis for captured source text.

The workspace offers three evidence-only products:

1. a classification (readable, minified, packed, obfuscated) with the measured
   evidence behind the label,
2. a derived representation plus an exact derived-range to original-byte map,
3. recovered string tables and a replayable transformation log.

Nothing here executes analyzed code, resolves identifiers, or claims semantics
the evidence does not support. Every derived byte maps back to a source range,
so a consumer can always return to the original evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any, Optional

MAX_DEOBFUSCATION_SOURCE_BYTES = 4 * 1024 * 1024
MAX_DERIVED_BYTES = 2 * 1024 * 1024
MAX_SEGMENTS = 250000
MAX_STRING_TABLES = 64
MAX_STRING_ENTRIES = 2048
MAX_TRANSFORMATIONS = 64
MAX_EVIDENCE = 32
MAX_DECODED_CHARS = 4096

SCHEMA = "deobfuscation-analysis-v1"
CLASSIFICATION_LABELS = ("readable", "minified", "packed", "obfuscated")
MIN_STRING_ARRAY_ENTRIES = 8
MIN_CHAR_CODE_ARRAY_ENTRIES = 8
MIN_MINIFIED_MEAN_LINE = 120
MIN_OBFUSCATED_IDENTIFIERS = 10

RAW_STRING_LITERAL = r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'"
STRING_LITERAL_PATTERN = re.compile(RAW_STRING_LITERAL)
STRING_ALTERNATION = "(?:" + RAW_STRING_LITERAL + ")"
STRING_ARRAY_PATTERN = re.compile(
    r"\[\s*(?:"
    + STRING_ALTERNATION
    + r"\s*,\s*){"
    + str(MIN_STRING_ARRAY_ENTRIES - 1)
    + r",}"
    + STRING_ALTERNATION
    + r"\s*\]"
)
CHAR_CODE_ARRAY_PATTERN = re.compile(
    r"\[\s*(?:\d{1,7}\s*,\s*){"
    + str(MIN_CHAR_CODE_ARRAY_ENTRIES - 1)
    + r",}\d{1,7}\s*\]"
)
NUMBER_PATTERN = re.compile(
    r"(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+"
    r"|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?n?)"
)
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_$][\w$]*")
HEX_ESCAPE_PATTERN = re.compile(r"\\x[0-9a-fA-F]{2}")
UNICODE_ESCAPE_PATTERN = re.compile(r"\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]{1,6}\})")
BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
PERCENT_BLOB_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2}){64,}")
OBFUSCATED_IDENTIFIER_PATTERN = re.compile(r"\b_0x[0-9a-fA-F]{2,}\b")
DYNAMIC_CODE_PATTERN = re.compile(
    r"\beval\s*\(|\bnew\s+Function\b|\bFunction\s*\(|document\.write\s*\("
)
PACKER_SIGNATURE_PATTERN = re.compile(
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,"
)
BLOB_DECODER_PATTERN = re.compile(
    r"(?:atob|fromCharCode|decodeURIComponent|unescape)\s*\("
)
FUNCTION_DEFINITION_PATTERN = re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(")
REGEXP_PREFIX_CHARS = frozenset("([{,;=:!&|?+-*%^~<>")
REGEXP_PREFIX_WORDS = frozenset(
    (
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "typeof",
        "void",
        "yield",
    )
)
VERBATIM_KINDS = ("comment", "identifier", "number", "regexp", "string", "template")
INDENT_UNIT = "  "
TRAILING_PUNCTUATION = frozenset((";", ",", ")", "]", "}"))


class DeobfuscationError(ValueError):
    """Raised when a source cannot be analyzed as requested."""


def ensure_source(source: Any) -> str:
    """Validate a caller-supplied source body and return it unchanged."""

    if not isinstance(source, str):
        raise DeobfuscationError("Source must be a string")
    if not source:
        raise DeobfuscationError("Source is empty")
    if len(source.encode("utf-8", "surrogatepass")) > MAX_DEOBFUSCATION_SOURCE_BYTES:
        raise DeobfuscationError("Source exceeds the deobfuscation byte limit")
    return source


def _quoted_end(source: str, start: int, quote: str) -> int:
    escaped = False
    index = start + 1
    length = len(source)
    while index < length:
        character = source[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == quote:
            return index + 1
        elif character == "\n":
            return index
        index += 1
    return length


def _template_end(source: str, start: int) -> int:
    escaped = False
    index = start + 1
    length = len(source)
    while index < length:
        character = source[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "`":
            return index + 1
        index += 1
    return length


def _regexp_end(source: str, start: int) -> int:
    escaped = False
    character_class = False
    index = start + 1
    length = len(source)
    while index < length:
        character = source[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "\n":
            return start + 1
        elif character == "[":
            character_class = True
        elif character == "]":
            character_class = False
        elif character == "/" and not character_class:
            end = index + 1
            while end < length and source[end].isalpha():
                end += 1
            return end
        index += 1
    return start + 1


def _regexp_allowed(previous: str) -> bool:
    if not previous:
        return True
    if previous in REGEXP_PREFIX_CHARS:
        return True
    return previous in REGEXP_PREFIX_WORDS


def _scan_tokens(source: str) -> list[tuple[str, int, int]]:
    """Split source into verbatim tokens; every offset indexes the source."""

    tokens: list[tuple[str, int, int]] = []
    length = len(source)
    index = 0
    previous = ""
    while index < length:
        character = source[index]
        if character.isspace():
            start = index
            while index < length and source[index].isspace():
                index += 1
            tokens.append(("whitespace", start, index))
            continue
        if character == "/" and source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end == -1 else end
            tokens.append(("comment", index, end))
            index = end
            continue
        if character == "/" and source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            tokens.append(("comment", index, end))
            index = end
            continue
        if character in "\"'":
            end = _quoted_end(source, index, character)
            tokens.append(("string", index, end))
            previous = "string"
            index = end
            continue
        if character == "`":
            end = _template_end(source, index)
            tokens.append(("template", index, end))
            previous = "template"
            index = end
            continue
        if character.isdigit() or (
            character == "." and index + 1 < length and source[index + 1].isdigit()
        ):
            match = NUMBER_PATTERN.match(source, index)
            if match is not None:
                tokens.append(("number", index, match.end()))
                previous = "number"
                index = match.end()
                continue
        if character.isalpha() or character in "_$" or ord(character) > 127:
            match = IDENTIFIER_PATTERN.match(source, index)
            if match is not None:
                tokens.append(("identifier", index, match.end()))
                previous = source[index : match.end()]
                index = match.end()
                continue
        if character == "/" and _regexp_allowed(previous):
            end = _regexp_end(source, index)
            if end > index + 1:
                tokens.append(("regexp", index, end))
                previous = "regexp"
                index = end
                continue
        tokens.append(("punct", index, index + 1))
        previous = character
        index += 1
    return tokens


def _next_significant(
    significant: list[tuple[str, int, int]], position: int
) -> Optional[tuple[str, int, int]]:
    if position + 1 >= len(significant):
        return None
    return significant[position + 1]


def derive_representation(
    source: str, *, max_bytes: int = MAX_DERIVED_BYTES
) -> dict[str, Any]:
    """Produce a readable derived view plus an exact derived-to-original map.

    The derived text is a re-indentation of the original tokens, never a
    rewrite: every verbatim segment satisfies
    ``source[start:end] == derived[derived_start:derived_end]``. Inserted
    whitespace is recorded as a zero-width synthetic segment at the original
    offset where it was inserted, so the map covers the derived text exactly.
    """

    if max_bytes < 1024:
        raise DeobfuscationError("Derived byte budget is too small")
    tokens = _scan_tokens(source)
    significant = [token for token in tokens if token[0] != "whitespace"]
    parts: list[str] = []
    segments: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    first_offset: dict[str, int] = {}
    derived_length = 0
    derived_bytes = 0
    truncated = False

    def emit(
        text: str,
        kind: str,
        original_start: Optional[int] = None,
        original_end: Optional[int] = None,
        transformation: Optional[str] = None,
    ) -> bool:
        nonlocal derived_length, derived_bytes, truncated
        if not text:
            return True
        text_bytes = len(text.encode("utf-8", "surrogatepass"))
        if derived_bytes + text_bytes > max_bytes:
            truncated = True
            return False
        start = derived_length
        parts.append(text)
        derived_length += len(text)
        derived_bytes += text_bytes
        segments.append(
            {
                "kind": kind,
                "derived_start": start,
                "derived_end": derived_length,
                "original_start": original_start,
                "original_end": original_end,
            }
        )
        if transformation:
            counts[transformation] = counts.get(transformation, 0) + 1
            first_offset.setdefault(
                transformation,
                original_start if original_start is not None else len(source),
            )
        if len(segments) >= MAX_SEGMENTS:
            truncated = True
            return False
        return True

    indent = 0
    paren_depth = 0
    verbatim_tokens = 0
    collapsed_whitespace = 0
    live = True
    for position, (kind, start, end) in enumerate(significant):
        if not live:
            break
        if kind == "whitespace":
            continue
        text = source[start:end]
        if kind == "punct" and text == "{":
            live = emit(" {", "synthetic", start, start, "space-before-brace")
            indent += 1
            live = live and emit(
                "\n" + INDENT_UNIT * indent, "synthetic", end, end, "line-splitting"
            )
            continue
        if kind == "punct" and text == "}":
            indent = max(0, indent - 1)
            live = emit("\n" + INDENT_UNIT * indent, "synthetic", start, start, "indentation")
            live = live and emit("}", "verbatim", start, end)
            following = _next_significant(significant, position)
            if following is None:
                continue
            following_text = source[following[1] : following[2]]
            if following[0] != "punct" or following_text not in TRAILING_PUNCTUATION:
                live = live and emit(
                    "\n" + INDENT_UNIT * indent, "synthetic", end, end, "line-splitting"
                )
            continue
        if kind == "punct" and text == ";":
            live = emit(";", "verbatim", start, end)
            if paren_depth == 0:
                live = live and emit(
                    "\n" + INDENT_UNIT * indent, "synthetic", end, end, "line-splitting"
                )
            continue
        if kind == "punct" and text == ",":
            live = emit(",", "verbatim", start, end)
            live = live and emit(" ", "synthetic", end, end, "space-after-comma")
            continue
        if kind == "punct" and text == "(":
            paren_depth += 1
            live = emit("(", "verbatim", start, end)
            continue
        if kind == "punct" and text == ")":
            paren_depth = max(0, paren_depth - 1)
            live = emit(")", "verbatim", start, end)
            continue
        if kind == "punct":
            live = emit(text, "verbatim", start, end)
            continue
        previous_character = parts[-1][-1] if parts and parts[-1] else ""
        if previous_character and _needs_separation(previous_character, text[0]):
            live = emit(" ", "synthetic", start, start, "token-separation")
        live = live and emit(text, "verbatim", start, end)
        verbatim_tokens += 1

    while segments and parts and not parts[-1].strip():
        segments.pop()
        parts.pop()
    collapsed_whitespace = sum(
        1
        for kind, start, end in tokens
        if kind == "whitespace" and (end - start > 1 or "\n" in source[start:end])
    )
    derived_text = "".join(parts)
    transformations = _transformation_log(
        counts, first_offset, collapsed_whitespace, len(tokens), verbatim_tokens
    )
    document: dict[str, Any] = {
        "text": derived_text,
        "segments": segments,
        "transformations": transformations,
        "segment_count": len(segments),
        "derived_bytes": len(derived_text.encode("utf-8", "surrogatepass")),
        "unchanged": derived_text == source,
        "truncated": truncated,
        "limits": {
            "max_derived_bytes": max_bytes,
            "max_segments": MAX_SEGMENTS,
        },
    }
    return document


def _needs_separation(previous_character: str, next_character: str) -> bool:
    if not previous_character or not next_character:
        return False
    if previous_character.isspace() or next_character.isspace():
        return False
    return _identifier_character(previous_character) and _identifier_character(
        next_character
    )


def _identifier_character(character: str) -> bool:
    return character.isalnum() or character in "_$"


def _transformation_log(
    counts: dict[str, int],
    first_offset: dict[str, int],
    collapsed_whitespace: int,
    token_count: int,
    verbatim_tokens: int,
) -> list[dict[str, Any]]:
    details = {
        "line-splitting": "Inserted line breaks between statements and blocks.",
        "indentation": "Re-indented block bodies by brace depth.",
        "space-before-brace": "Inserted a space before an opening brace.",
        "space-after-comma": "Inserted a space after a comma.",
        "token-separation": "Inserted a space to keep adjacent tokens distinct.",
    }
    transformations: list[dict[str, Any]] = []
    for identifier, count in counts.items():
        transformations.append(
            {
                "id": identifier,
                "kind": "format",
                "detail": details.get(identifier, "Inserted whitespace."),
                "count": count,
                "original_start": first_offset.get(identifier),
                "reversible": True,
            }
        )
    if collapsed_whitespace:
        transformations.append(
            {
                "id": "whitespace-collapse",
                "kind": "format",
                "detail": "Collapsed runs of whitespace to a single separator.",
                "count": collapsed_whitespace,
                "original_start": 0,
                "reversible": True,
            }
        )
    transformations.append(
        {
            "id": "verbatim-tokens",
            "kind": "identity",
            "detail": (
                "Copied every token byte-for-byte; only whitespace was added. "
                "No identifier, literal, or operator was rewritten."
            ),
            "count": verbatim_tokens,
            "original_start": 0,
            "reversible": True,
        }
    )
    if not any(entry["kind"] == "format" for entry in transformations):
        transformations.insert(
            0,
            {
                "id": "none",
                "kind": "no-op",
                "detail": "The source is already readable; no formatting was applied.",
                "count": 0,
                "original_start": 0,
                "reversible": True,
            },
        )
    return transformations[:MAX_TRANSFORMATIONS]


def original_offset_for_derived(
    segments: list[dict[str, Any]], derived_offset: int
) -> Optional[int]:
    """Map a derived text offset to an original source offset."""

    if not segments:
        return None
    low = 0
    high = len(segments) - 1
    while low <= high:
        middle = (low + high) // 2
        segment = segments[middle]
        if derived_offset < segment["derived_start"]:
            high = middle - 1
        elif derived_offset >= segment["derived_end"]:
            low = middle + 1
        else:
            if segment["original_start"] is None:
                return None
            if segment["kind"] == "synthetic":
                return segment["original_start"]
            return segment["original_start"] + (derived_offset - segment["derived_start"])
    return None


def _metrics(source: str, tokens: list[tuple[str, int, int]]) -> dict[str, Any]:
    length = len(source)
    lines = source.split("\n")
    non_empty_lines = [line for line in lines if line.strip()]
    mean_line = sum(len(line) for line in non_empty_lines) / max(1, len(non_empty_lines))
    whitespace = sum(end - start for kind, start, end in tokens if kind == "whitespace")
    identifiers = [source[start:end] for kind, start, end in tokens if kind == "identifier"]
    short_identifiers = sum(1 for name in identifiers if len(name) <= 2)
    return {
        "bytes": len(source.encode("utf-8", "surrogatepass")),
        "characters": length,
        "lines": len(lines),
        "non_empty_lines": len(non_empty_lines),
        "max_line_length": max((len(line) for line in lines), default=0),
        "mean_line_length": round(mean_line, 2),
        "whitespace_ratio": round(whitespace / max(1, length), 4),
        "hex_escapes": len(HEX_ESCAPE_PATTERN.findall(source)),
        "unicode_escapes": len(UNICODE_ESCAPE_PATTERN.findall(source)),
        "obfuscated_identifiers": len(OBFUSCATED_IDENTIFIER_PATTERN.findall(source)),
        "identifiers": len(identifiers),
        "short_identifier_ratio": round(short_identifiers / max(1, len(identifiers)), 4),
        "base64_blobs": len(BASE64_BLOB_PATTERN.findall(source)),
        "percent_blobs": len(PERCENT_BLOB_PATTERN.findall(source)),
        "dynamic_code_calls": len(DYNAMIC_CODE_PATTERN.findall(source)),
        "packer_signature": bool(PACKER_SIGNATURE_PATTERN.search(source)),
        "blob_decoders": len(BLOB_DECODER_PATTERN.findall(source)),
    }


def classify_source(source: str) -> dict[str, Any]:
    """Classify a source as readable, minified, packed, or obfuscated."""

    tokens = _scan_tokens(source)
    metrics = _metrics(source, tokens)
    evidence: list[dict[str, Any]] = []

    def record(identifier: str, weight: int, detail: str, value: Any) -> int:
        evidence.append(
            {"id": identifier, "weight": weight, "detail": detail, "value": value}
        )
        return weight

    packed_score = 0
    if metrics["packer_signature"]:
        packed_score += record(
            "packer-signature",
            60,
            "Matches the classic evaluate-a-decoder-function packer shape.",
            True,
        )
    if metrics["dynamic_code_calls"] and (
        metrics["base64_blobs"] or metrics["percent_blobs"]
    ):
        packed_score += record(
            "packed-blob",
            45,
            "Dynamic code construction next to a large encoded blob.",
            {
                "dynamic_code_calls": metrics["dynamic_code_calls"],
                "blobs": metrics["base64_blobs"] + metrics["percent_blobs"],
            },
        )

    obfuscated_score = 0
    if metrics["obfuscated_identifiers"] >= MIN_OBFUSCATED_IDENTIFIERS:
        obfuscated_score += record(
            "hex-identifiers",
            40,
            "Hexadecimal _0x-prefixed identifiers dominate the script.",
            metrics["obfuscated_identifiers"],
        )
    if metrics["hex_escapes"] >= 20:
        obfuscated_score += record(
            "hex-escapes",
            35,
            "String literals are written as hexadecimal escape runs.",
            metrics["hex_escapes"],
        )
    if metrics["unicode_escapes"] >= 20:
        obfuscated_score += record(
            "unicode-escapes",
            35,
            "String literals are written as unicode escape runs.",
            metrics["unicode_escapes"],
        )
    if metrics["blob_decoders"] and (
        metrics["hex_escapes"] or metrics["obfuscated_identifiers"]
    ):
        obfuscated_score += record(
            "encoded-string-table",
            20,
            "Blob decoders run over escape-encoded strings or hex identifiers.",
            metrics["blob_decoders"],
        )

    minified_score = 0
    if metrics["non_empty_lines"] and metrics["mean_line_length"] >= MIN_MINIFIED_MEAN_LINE:
        minified_score += record(
            "long-lines",
            35,
            "Non-empty lines are far longer than hand-written source.",
            metrics["mean_line_length"],
        )
    if metrics["whitespace_ratio"] <= 0.12:
        minified_score += record(
            "low-whitespace",
            25,
            "Whitespace is too sparse for hand-written source.",
            metrics["whitespace_ratio"],
        )
    if metrics["short_identifier_ratio"] >= 0.5 and metrics["identifiers"] >= 50:
        minified_score += record(
            "short-identifiers-widespread",
            15,
            "Identifier minification is widespread, not local to one scope.",
            metrics["short_identifier_ratio"],
        )

    label = "readable"
    if packed_score >= 45 and packed_score >= obfuscated_score:
        label = "packed"
    elif obfuscated_score >= 35:
        label = "obfuscated"
    elif minified_score >= 35:
        label = "minified"
    score = {"packed": packed_score, "obfuscated": obfuscated_score, "minified": minified_score}
    if label == "readable":
        evidence.append(
            {
                "id": "readable-baseline",
                "weight": 0,
                "detail": "No packing, obfuscation, or minification evidence passed threshold.",
                "value": {
                    "mean_line_length": metrics["mean_line_length"],
                    "whitespace_ratio": metrics["whitespace_ratio"],
                },
            }
        )
    competing = max(
        (value for key, value in score.items() if key != label and value > 0), default=0
    )
    confidence = 50 if label == "readable" else min(95, 40 + score[label] - competing // 2)
    return {
        "label": label,
        "confidence": max(0, min(100, confidence)),
        "scores": score,
        "evidence": evidence[:MAX_EVIDENCE],
        "alternatives": [
            {"label": key, "score": value}
            for key, value in sorted(score.items(), key=lambda item: -item[1])
            if value > 0 and key != label
        ],
    }


def _decode_string_literal(raw: str) -> tuple[str, str]:
    """Decode one string literal's escapes without evaluating it."""

    body = raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'" else raw
    encoding = "literal"
    if "\\x" in body or "\\u" in body:
        encoding = "escape-sequence"
    decoded = _unescape_string(body)
    if encoding == "literal" and len(decoded) >= 8:
        candidate = decoded.strip()
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate or " ") and len(candidate) % 4 == 0:
            try:
                raw_bytes = base64.b64decode(candidate, validate=True)
            except (binascii.Error, ValueError):
                raw_bytes = b""
            if raw_bytes:
                text = raw_bytes.decode("utf-8", "replace")
                printable = sum(
                    1 for character in text if character.isprintable() or character in "\n\t"
                )
                if text and printable / len(text) >= 0.85:
                    return text[:MAX_DECODED_CHARS], "base64"
        if re.fullmatch(r"[0-9a-fA-F]+", candidate) and len(candidate) % 2 == 0:
            try:
                raw_bytes = binascii.unhexlify(candidate)
            except (binascii.Error, ValueError):
                raw_bytes = b""
            if raw_bytes:
                text = raw_bytes.decode("utf-8", "replace")
                printable = sum(1 for character in text if character.isprintable())
                if text and printable / len(text) >= 0.85:
                    return text[:MAX_DECODED_CHARS], "hex"
    return decoded[:MAX_DECODED_CHARS], encoding


def _unescape_string(body: str) -> str:
    output: list[str] = []
    index = 0
    length = len(body)
    while index < length:
        character = body[index]
        if character != "\\" or index + 1 >= length:
            output.append(character)
            index += 1
            continue
        marker = body[index + 1]
        if marker == "x" and index + 3 < length + 1:
            digits = body[index + 2 : index + 4]
            if re.fullmatch(r"[0-9a-fA-F]{2}", digits or " "):
                output.append(chr(int(digits, 16)))
                index += 4
                continue
        if marker == "u" and body.startswith("u{", index + 1):
            end = body.find("}", index + 3)
            if end != -1:
                digits = body[index + 3 : end]
                if re.fullmatch(r"[0-9a-fA-F]{1,6}", digits or " "):
                    output.append(chr(int(digits, 16)))
                    index = end + 1
                    continue
        if marker == "u" and index + 5 < length + 1:
            digits = body[index + 2 : index + 6]
            if re.fullmatch(r"[0-9a-fA-F]{4}", digits or " "):
                output.append(chr(int(digits, 16)))
                index += 6
                continue
        simple = {
            "n": "\n",
            "t": "\t",
            "r": "\r",
            "b": "\b",
            "f": "\f",
            "v": "\v",
            "0": "\0",
            "\\": "\\",
            "'": "'",
            '"': '"',
            "`": "`",
            "/": "/",
        }
        if marker in simple:
            output.append(simple[marker])
            index += 2
            continue
        output.append(marker)
        index += 2
    return "".join(output)


def recover_string_tables(source: str) -> list[dict[str, Any]]:
    """Recover literal string tables and code-point arrays without running them."""

    tables: list[dict[str, Any]] = []
    entries_used = 0
    for match in CHAR_CODE_ARRAY_PATTERN.finditer(source):
        if len(tables) >= MAX_STRING_TABLES or entries_used >= MAX_STRING_ENTRIES:
            break
        body = match.group(0)
        code_points = [
            (int(number.group(0)), match.start() + number.start())
            for number in re.finditer(r"\d{1,7}", body)
        ]
        values = [value for value, _ in code_points]
        decoded = _decode_code_points(values)
        if decoded is None:
            continue
        entries_used += len(values)
        tables.append(
            _table_document(
                source,
                match.start(),
                len(body),
                "code-point-array",
                code_points,
                decoded,
            )
        )
    for match in STRING_ARRAY_PATTERN.finditer(source):
        if len(tables) >= MAX_STRING_TABLES or entries_used >= MAX_STRING_ENTRIES:
            break
        body = match.group(0)
        base = match.start()
        entries: list[dict[str, Any]] = []
        encodings: set[str] = set()
        for index, literal in enumerate(STRING_LITERAL_PATTERN.finditer(body)):
            if entries_used >= MAX_STRING_ENTRIES:
                break
            raw = literal.group(0)
            value, encoding = _decode_string_literal(raw)
            encodings.add(encoding)
            entries_used += 1
            entries.append(
                {
                    "index": index,
                    "offset": base + literal.start(),
                    "raw": raw[:MAX_DECODED_CHARS],
                    "encoding": encoding,
                    "value": value,
                }
            )
        if len(entries) < MIN_STRING_ARRAY_ENTRIES:
            continue
        tables.append(
            {
                "kind": "string-array",
                "offset": base,
                "length": len(body),
                "entry_count": len(entries),
                "encodings": sorted(encodings),
                "entries": entries,
                "decoder_hint": _decoder_hint(source, base + len(body)),
            }
        )
    tables.sort(key=lambda table: table["offset"])
    return tables


def _decode_code_points(values: list[int]) -> Optional[str]:
    if not values or any(value > 0x10FFFF or value < 0 for value in values):
        return None
    text = "".join(chr(value) for value in values)
    printable = sum(1 for character in text if character.isprintable() or character == "\n")
    if not text or printable / len(text) < 0.85:
        return None
    return text[:MAX_DECODED_CHARS]


def _table_document(
    source: str,
    offset: int,
    length: int,
    kind: str,
    code_points: list[tuple[int, int]],
    decoded: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "offset": offset,
        "length": length,
        "entry_count": len(code_points),
        "encodings": ["code-point"],
        "entries": [
            {
                "index": index,
                "offset": entry_offset,
                "raw": str(value),
                "encoding": "code-point",
                "value": chr(value),
            }
            for index, (value, entry_offset) in enumerate(code_points)
        ],
        "decoded_preview": decoded[:512],
        "decoder_hint": _decoder_hint(source, offset + length),
    }


def _decoder_hint(source: str, boundary: int) -> dict[str, Any]:
    window = source[boundary : boundary + 2000]
    definition = FUNCTION_DEFINITION_PATTERN.search(window)
    return {
        "kind": "function-definition-near-table" if definition else "none",
        "name": definition.group(1) if definition else None,
        "offset": boundary + definition.start() if definition else None,
        "dynamic_code_nearby": bool(DYNAMIC_CODE_PATTERN.search(window)),
        "confidence": "low" if definition else "none",
        "note": "A nearby definition is a hint, not proof, that it decodes this table.",
    }


def analyze_source(
    source: Any, *, url: Optional[str] = None, sha256: Optional[str] = None
) -> dict[str, Any]:
    """Build the deobfuscation analysis document for one source body."""

    text = ensure_source(source)
    representation = derive_representation(text)
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "source": {
            "url": url,
            "sha256": sha256 or hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
            "byte_size": len(text.encode("utf-8", "surrogatepass")),
            "lines": text.count("\n") + 1,
        },
        "classification": classify_source(text),
        "stats": _metrics(text, _scan_tokens(text)),
        "representation": {
            "status": "unchanged" if representation["unchanged"] else "derived",
            "derived_bytes": representation["derived_bytes"],
            "segment_count": representation["segment_count"],
            "truncated": representation["truncated"],
            "transformations": representation["transformations"],
        },
        "string_tables": recover_string_tables(text),
        "limits": {
            "max_source_bytes": MAX_DEOBFUSCATION_SOURCE_BYTES,
            "max_derived_bytes": MAX_DERIVED_BYTES,
            "max_segments": MAX_SEGMENTS,
            "max_string_tables": MAX_STRING_TABLES,
            "max_string_entries": MAX_STRING_ENTRIES,
        },
    }
    return document


def verify_deobfuscation_document(document: Any) -> dict[str, Any]:
    """Validate an analysis document; raise DeobfuscationError when malformed."""

    if not isinstance(document, dict):
        raise DeobfuscationError("Analysis document must be an object")
    if document.get("schema") != SCHEMA:
        raise DeobfuscationError("Analysis document schema is not supported")
    source = document.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("sha256"), str):
        raise DeobfuscationError("Analysis document is missing source identity")
    if not isinstance(source.get("byte_size"), int):
        raise DeobfuscationError("Analysis document is missing source size")
    classification = document.get("classification")
    if not isinstance(classification, dict):
        raise DeobfuscationError("Analysis document is missing a classification")
    if classification.get("label") not in CLASSIFICATION_LABELS:
        raise DeobfuscationError("Analysis classification label is invalid")
    if not isinstance(classification.get("evidence"), list):
        raise DeobfuscationError("Analysis classification is missing evidence")
    representation = document.get("representation")
    if not isinstance(representation, dict):
        raise DeobfuscationError("Analysis document is missing its representation")
    if representation.get("status") not in ("derived", "unchanged"):
        raise DeobfuscationError("Analysis representation status is invalid")
    if not isinstance(representation.get("transformations"), list):
        raise DeobfuscationError("Analysis representation is missing its log")
    if not isinstance(document.get("string_tables"), list):
        raise DeobfuscationError("Analysis document is missing string tables")
    limits = document.get("limits")
    if not isinstance(limits, dict):
        raise DeobfuscationError("Analysis document is missing its limits")
    return document
