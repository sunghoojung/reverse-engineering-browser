"""Unit tests for the bounded deobfuscation analysis module."""

import base64
import copy
import unittest

from deobfuscation import (
    CLASSIFICATION_LABELS,
    SCHEMA,
    DeobfuscationError,
    analyze_source,
    classify_source,
    derive_representation,
    ensure_source,
    original_offset_for_derived,
    recover_string_tables,
    verify_deobfuscation_document,
)

READABLE_SOURCE = """\
function greet(name) {
  const message = "Hello, " + name + "!";
  return message;
}

// A small readable module.
module.exports = { greet: greet };
"""

MINIFIED_SOURCE = (
    "function a(b,c){return b+c}function d(e,f){return e*f}var g=a(1,2),h=d(3,4);"
    "var i=g+h,j=i*2,k=j-1,l=k+g,m=l+h,n=m*i,o=n+j,p=o-k,q=p+g,r=q+h;"
    "var s=a(r,m),t=d(s,o);"
)

PACKED_SOURCE = (
    "eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};"
    "if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]"
    "||c.toString(a)}}return p}('0.1(\"2 3\")',4,4,"
    "'console|log|hello|world'.split('|'),0,{}))"
)

HEX_WORDS = ("hello", "world", "abcd", "efgh", "ijkl", "mnop", "qrst", "uvwx")


def hex_escape_literal(word):
    body = "".join("\\x%02x" % ord(character) for character in word)
    return "'" + body + "'"


OBFUSCATED_SOURCE = (
    "var _0x4a2b=["
    + ",".join(hex_escape_literal(word) for word in HEX_WORDS)
    + "];var _0x9f1c=_0x4a2b[0];var _0x11aa=_0x4a2b[1];"
    "var _0x22bb=_0x4a2b[2];var _0x33cc=_0x4a2b[3];"
    "var _0x44dd=_0x4a2b[4];var _0x55ee=_0x4a2b[5];"
    "function _0x88bb(_0x99cc){return _0x4a2b[_0x99cc];}"
)

LARGE_SOURCE = "".join(
    "function handler%d(value) { return value + %d; }\n" % (index, index)
    for index in range(200)
)

SAMPLES = (
    ("readable", READABLE_SOURCE),
    ("minified", MINIFIED_SOURCE),
    ("packed", PACKED_SOURCE),
    ("obfuscated", OBFUSCATED_SOURCE),
)


def evidence_ids(classification):
    return [entry["id"] for entry in classification["evidence"]]


def evidence_entry(classification, identifier):
    return next(
        entry
        for entry in classification["evidence"]
        if entry["id"] == identifier
    )


class ClassificationTests(unittest.TestCase):
    def test_readable_snippet_is_classified_readable(self):
        result = classify_source(READABLE_SOURCE)

        self.assertEqual(result["label"], "readable")
        self.assertEqual(
            set(result["scores"]), set(CLASSIFICATION_LABELS) - {"readable"}
        )
        self.assertTrue(all(score == 0 for score in result["scores"].values()))
        self.assertEqual(evidence_ids(result), ["readable-baseline"])
        self.assertEqual(result["alternatives"], [])

    def test_single_line_bundle_is_classified_minified(self):
        self.assertNotIn("\n", MINIFIED_SOURCE)

        result = classify_source(MINIFIED_SOURCE)

        self.assertEqual(result["label"], "minified")
        self.assertGreaterEqual(result["scores"]["minified"], 35)
        self.assertLess(result["scores"]["obfuscated"], 35)
        self.assertLess(result["scores"]["packed"], 45)
        self.assertIn("long-lines", evidence_ids(result))
        self.assertIn("low-whitespace", evidence_ids(result))

    def test_classic_packer_shape_is_classified_packed(self):
        result = classify_source(PACKED_SOURCE)

        self.assertEqual(result["label"], "packed")
        self.assertGreaterEqual(result["scores"]["packed"], 45)
        self.assertGreaterEqual(
            result["scores"]["packed"], result["scores"]["obfuscated"]
        )
        self.assertIn("packer-signature", evidence_ids(result))
        self.assertIs(evidence_entry(result, "packer-signature")["value"], True)

    def test_escape_dominated_script_is_classified_obfuscated(self):
        result = classify_source(OBFUSCATED_SOURCE)

        self.assertEqual(result["label"], "obfuscated")
        self.assertGreaterEqual(result["scores"]["obfuscated"], 35)
        self.assertLess(result["scores"]["packed"], 45)
        self.assertIn("hex-escapes", evidence_ids(result))
        self.assertIn("hex-identifiers", evidence_ids(result))
        self.assertGreaterEqual(evidence_entry(result, "hex-escapes")["value"], 20)

    def test_every_classification_carries_structured_evidence(self):
        for expected, source in SAMPLES:
            with self.subTest(label=expected):
                result = classify_source(source)

                self.assertEqual(result["label"], expected)
                self.assertIn(result["label"], CLASSIFICATION_LABELS)
                self.assertTrue(result["evidence"])
                for entry in result["evidence"]:
                    self.assertTrue({"id", "detail", "value"} <= set(entry))
                    self.assertIsInstance(entry["id"], str)
                    self.assertIsInstance(entry["detail"], str)
                    self.assertNotEqual(entry["detail"], "")
                    self.assertIsNotNone(entry["value"])
                self.assertGreaterEqual(result["confidence"], 0)
                self.assertLessEqual(result["confidence"], 100)


class DerivationInvariantTests(unittest.TestCase):
    def test_segments_cover_the_derived_text_exactly(self):
        for _, source in SAMPLES:
            with self.subTest(source=source[:24]):
                document = derive_representation(source)
                derived = document["text"]
                segments = document["segments"]

                self.assertTrue(segments)
                self.assertEqual(segments[0]["derived_start"], 0)
                self.assertEqual(segments[-1]["derived_end"], len(derived))
                for index in range(len(segments) - 1):
                    self.assertEqual(
                        segments[index]["derived_end"],
                        segments[index + 1]["derived_start"],
                    )

    def test_verbatim_segments_are_identity_slices(self):
        for _, source in SAMPLES:
            with self.subTest(source=source[:24]):
                document = derive_representation(source)
                derived = document["text"]
                for segment in document["segments"]:
                    if segment["kind"] != "verbatim":
                        continue
                    original = source[
                        segment["original_start"]:segment["original_end"]
                    ]
                    copied = derived[
                        segment["derived_start"]:segment["derived_end"]
                    ]
                    self.assertEqual(original, copied)

    def test_synthetic_segments_are_zero_width_insertions(self):
        document = derive_representation(MINIFIED_SOURCE)
        synthetic = [
            segment
            for segment in document["segments"]
            if segment["kind"] == "synthetic"
        ]

        self.assertTrue(synthetic)
        for segment in synthetic:
            self.assertEqual(segment["original_start"], segment["original_end"])
            self.assertLessEqual(segment["original_start"], len(MINIFIED_SOURCE))
            self.assertGreater(segment["derived_end"], segment["derived_start"])

    def test_original_offset_for_derived_maps_tokens_back(self):
        document = derive_representation(READABLE_SOURCE)
        derived = document["text"]
        segments = document["segments"]
        marker = "greet"

        derived_offset = derived.index(marker)
        original_offset = original_offset_for_derived(segments, derived_offset)

        self.assertIsNotNone(original_offset)
        self.assertEqual(
            READABLE_SOURCE[original_offset:original_offset + len(marker)], marker
        )
        for segment in segments:
            if segment["kind"] != "verbatim":
                continue
            self.assertEqual(
                original_offset_for_derived(segments, segment["derived_start"]),
                segment["original_start"],
            )

    def test_synthetic_offsets_resolve_to_their_insertion_point(self):
        document = derive_representation(MINIFIED_SOURCE)
        segments = document["segments"]

        for segment in segments:
            if segment["kind"] != "synthetic":
                continue
            self.assertEqual(
                original_offset_for_derived(segments, segment["derived_start"]),
                segment["original_start"],
            )

    def test_offsets_outside_the_map_return_none(self):
        document = derive_representation(READABLE_SOURCE)

        self.assertIsNone(original_offset_for_derived([], 0))
        self.assertIsNone(
            original_offset_for_derived(
                document["segments"], len(document["text"])
            )
        )

    def test_derived_budget_truncates_and_stops(self):
        self.assertGreater(len(LARGE_SOURCE), 4096)

        document = derive_representation(LARGE_SOURCE, max_bytes=1024)

        self.assertTrue(document["truncated"])
        self.assertEqual(document["limits"]["max_derived_bytes"], 1024)
        self.assertLessEqual(document["derived_bytes"], 1024)
        self.assertLess(len(document["text"]), len(LARGE_SOURCE))
        for segment in document["segments"]:
            self.assertLessEqual(segment["derived_end"], 1024)

    def test_derived_budget_counts_utf8_bytes(self):
        source = "+".join('"漢"' for _ in range(200))
        self.assertLess(len(source), 1024)
        self.assertGreater(len(source.encode("utf-8")), 1024)

        document = derive_representation(source, max_bytes=1024)

        self.assertTrue(document["truncated"])
        self.assertLessEqual(document["derived_bytes"], 1024)
        self.assertEqual(
            document["derived_bytes"],
            len(document["text"].encode("utf-8", "surrogatepass")),
        )

    def test_derived_budget_below_the_floor_is_rejected(self):
        with self.assertRaisesRegex(DeobfuscationError, "budget is too small"):
            derive_representation(READABLE_SOURCE, max_bytes=64)


class SourceBoundsTests(unittest.TestCase):
    def test_ensure_source_returns_strings_unchanged(self):
        self.assertEqual(ensure_source("const value = 1;"), "const value = 1;")

    def test_ensure_source_rejects_non_strings(self):
        for value in (b"const value = 1;", None, 17, ["const"]):
            with self.subTest(value=value):
                with self.assertRaises(DeobfuscationError):
                    ensure_source(value)

    def test_ensure_source_rejects_empty_text(self):
        with self.assertRaisesRegex(DeobfuscationError, "Source is empty"):
            ensure_source("")

    def test_analyze_source_reaches_the_same_bounds(self):
        for value in (b"const value = 1;", "", None):
            with self.subTest(value=value):
                with self.assertRaises(DeobfuscationError):
                    analyze_source(value)


class StringTableTests(unittest.TestCase):
    def test_escaped_string_array_is_recovered_with_decoded_values(self):
        tables = recover_string_tables(OBFUSCATED_SOURCE)
        arrays = [table for table in tables if table["kind"] == "string-array"]

        self.assertEqual(len(arrays), 1)
        table = arrays[0]
        self.assertEqual(table["entry_count"], len(HEX_WORDS))
        self.assertEqual(table["encodings"], ["escape-sequence"])
        self.assertEqual(
            [entry["value"] for entry in table["entries"]], list(HEX_WORDS)
        )
        for entry in table["entries"]:
            raw = entry["raw"]
            offset = entry["offset"]
            self.assertEqual(
                OBFUSCATED_SOURCE[offset:offset + len(raw)], raw
            )

    def test_recovered_table_hint_is_not_a_claim(self):
        table = next(
            table
            for table in recover_string_tables(OBFUSCATED_SOURCE)
            if table["kind"] == "string-array"
        )
        hint = table["decoder_hint"]

        self.assertEqual(hint["kind"], "function-definition-near-table")
        self.assertEqual(hint["name"], "_0x88bb")
        self.assertIn(hint["confidence"], ("low", "none"))
        self.assertIn("hint, not proof", hint["note"])

    def test_base64_array_entry_is_decoded(self):
        payload = base64.b64encode(b"the quick brown fox jumps").decode("ascii")
        words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf"]
        source = (
            "var values=["
            + ",".join('"%s"' % word for word in words + [payload])
            + "];"
        )

        table = next(
            table
            for table in recover_string_tables(source)
            if table["kind"] == "string-array"
        )
        entries = {entry["index"]: entry for entry in table["entries"]}

        self.assertEqual(entries[0]["encoding"], "literal")
        self.assertEqual(entries[0]["value"], "alpha")
        self.assertEqual(entries[len(words)]["encoding"], "base64")
        self.assertEqual(entries[len(words)]["value"], "the quick brown fox jumps")
        self.assertEqual(table["encodings"], ["base64", "literal"])

    def test_code_point_array_decodes_to_readable_text(self):
        source = "var text=[104,101,108,108,111,32,119,111,114,108,100];"

        tables = recover_string_tables(source)

        self.assertEqual(len(tables), 1)
        table = tables[0]
        self.assertEqual(table["kind"], "code-point-array")
        self.assertEqual(table["encodings"], ["code-point"])
        self.assertEqual(table["entry_count"], 11)
        self.assertEqual(table["decoded_preview"], "hello world")
        self.assertEqual(
            "".join(entry["value"] for entry in table["entries"]), "hello world"
        )

    def test_code_point_entries_index_their_own_numbers(self):
        source = "var text=[104,101,108,108,111,32,119,111,114,108,100];"

        table = recover_string_tables(source)[0]

        self.assertEqual(table["kind"], "code-point-array")
        for entry in table["entries"]:
            raw = entry["raw"]
            offset = entry["offset"]
            self.assertEqual(source[offset:offset + len(raw)], raw)
            self.assertEqual(int(raw), ord(entry["value"]))


class AnalysisDocumentTests(unittest.TestCase):
    def test_analyzed_document_verifies(self):
        document = analyze_source(
            READABLE_SOURCE, url="https://authorized.test/readable.js"
        )

        self.assertEqual(verify_deobfuscation_document(document), document)
        self.assertEqual(document["schema"], SCHEMA)
        self.assertEqual(
            document["source"]["url"], "https://authorized.test/readable.js"
        )
        self.assertEqual(len(document["source"]["sha256"]), 64)
        self.assertEqual(document["source"]["byte_size"], len(READABLE_SOURCE))
        self.assertEqual(document["classification"]["label"], "readable")
        self.assertTrue(document["classification"]["evidence"])
        self.assertIn(document["classification"]["label"], CLASSIFICATION_LABELS)
        self.assertIn(document["representation"]["status"], ("derived", "unchanged"))
        self.assertTrue(document["representation"]["transformations"])
        self.assertIsInstance(document["string_tables"], list)
        self.assertGreater(document["limits"]["max_source_bytes"], 0)
        self.assertGreater(document["limits"]["max_derived_bytes"], 0)

    def test_explicit_source_identity_is_kept(self):
        document = analyze_source(READABLE_SOURCE, sha256="a" * 64)

        self.assertEqual(document["source"]["sha256"], "a" * 64)
        self.assertEqual(verify_deobfuscation_document(document), document)

    def test_malformed_documents_are_rejected(self):
        document = analyze_source(READABLE_SOURCE)
        cases = {}

        cases["not-an-object"] = SCHEMA
        cases["list-document"] = []
        wrong_schema = copy.deepcopy(document)
        wrong_schema["schema"] = "deobfuscation-analysis-v0"
        cases["wrong-schema"] = wrong_schema
        bad_label = copy.deepcopy(document)
        bad_label["classification"]["label"] = "encrypted"
        cases["bad-label"] = bad_label
        missing_log = copy.deepcopy(document)
        del missing_log["representation"]["transformations"]
        cases["missing-representation-log"] = missing_log
        missing_representation = copy.deepcopy(document)
        del missing_representation["representation"]
        cases["missing-representation"] = missing_representation
        missing_identity = copy.deepcopy(document)
        missing_identity["source"]["sha256"] = None
        cases["missing-source-identity"] = missing_identity
        missing_evidence = copy.deepcopy(document)
        missing_evidence["classification"]["evidence"] = "none"
        cases["missing-evidence"] = missing_evidence
        missing_tables = copy.deepcopy(document)
        del missing_tables["string_tables"]
        cases["missing-string-tables"] = missing_tables
        missing_limits = copy.deepcopy(document)
        del missing_limits["limits"]
        cases["missing-limits"] = missing_limits

        for name, candidate in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(DeobfuscationError):
                    verify_deobfuscation_document(candidate)


if __name__ == "__main__":
    unittest.main()
