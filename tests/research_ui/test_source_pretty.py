import json
import shutil
import subprocess
import unittest

from ui_test_support import UI_DIRECTORY


class SourcePrettyPrintTest(unittest.TestCase):
    def run_node(self, exercise: str):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")
        model = (UI_DIRECTORY / "source_syntax.js").read_text(encoding="utf-8")
        completed = subprocess.run(
            [node, "-e", model + "\n" + exercise],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    def test_javascript_pretty_print_preserves_tokens_and_maps_lines(self):
        result = self.run_node(
            r"""
const source = {kind:'javascript',mime_type:'application/javascript',url:'strings.js'};
const original = 'loadTimeData.data={"label":"a;{b}","items":[true,false]};const n=1e+3;function check(x){if(x){return /a+/.test(`v${x}`);}else{return 0;}}';
const formatted = prettyPrintSource(source, original);
const tokens = value => sourcePrettyTokens(value, 'javascript')
  .filter(token => token.kind !== 'whitespace')
  .map(token => token.text);
const lines = sourceRepresentationLineMap(original, original, null, formatted);
process.stdout.write(JSON.stringify({
  text: formatted.text,
  tokensPreserved: JSON.stringify(tokens(original)) === JSON.stringify(tokens(formatted.text)),
  mappedLines: lines.filter(line => line.originalLine !== null).map(line => line.originalLine),
  offsetUnit: formatted.offset_unit,
  changed: formatted.changed
}));
"""
        )
        self.assertTrue(result["changed"])
        self.assertTrue(result["tokensPreserved"])
        self.assertEqual(result["offsetUnit"], "utf-16-code-unit")
        self.assertIn("\n  \"label\": \"a;{b}\",", result["text"])
        self.assertIn("\n    return /a+/.test(`v${x}`);", result["text"])
        self.assertTrue(result["mappedLines"])
        self.assertEqual(set(result["mappedLines"]), {0})

    def test_pretty_print_uses_detected_json_css_and_markup_grammars(self):
        result = self.run_node(
            r"""
const cases = [
  [{kind:'source_map',mime_type:'application/json',url:'app.js.map'}, '{"a":1,"b":[true,false]}'],
  [{kind:'response_body',mime_type:'text/css',url:'app.css'}, 'body{color:red;margin:0 1px}@media(x){a{display:block;}}'],
  [{kind:'response_body',mime_type:'text/html',url:'index.html'}, '<main><script>if(a<b){console.log("<x>")}</script><button data-x="1">Run</button><br></main>']
];
process.stdout.write(JSON.stringify(cases.map(([source, value]) => {
  const formatted = prettyPrintSource(source, value);
  return {language: formatted.language, text: formatted.text, error: formatted.error ?? null};
})));
"""
        )
        self.assertEqual([entry["language"] for entry in result], ["json", "css", "markup"])
        self.assertTrue(all(entry["error"] is None for entry in result))
        self.assertIn('\n  "b": [\n', result[0]["text"])
        self.assertIn("body {\n  color: red;", result[1]["text"])
        self.assertIn('if(a<b){console.log("<x>")}', result[2]["text"])
        self.assertIn('<button data-x="1">\n    Run\n  </button>', result[2]["text"])

    def test_pretty_print_composes_with_deobfuscation_mapping(self):
        result = self.run_node(
            r"""
const source = {kind:'javascript',mime_type:'text/javascript',url:'app.js'};
const original = 'const value=1+2;\nfunction read(){return value;}';
const derivedText = 'const value=3;\nfunction read(){return value;}';
const originalExpression = original.indexOf('1+2');
const derivedExpression = derivedText.indexOf('3');
const derived = {
  text: derivedText,
  offset_unit: 'utf-16-code-unit',
  segments: [
    {kind:'verbatim',original_start:0,original_end:originalExpression,derived_start:0,derived_end:derivedExpression},
    {kind:'replacement',original_start:originalExpression,original_end:originalExpression+3,derived_start:derivedExpression,derived_end:derivedExpression+1},
    {kind:'verbatim',original_start:originalExpression+3,original_end:original.length,derived_start:derivedExpression+1,derived_end:derivedText.length}
  ]
};
const formatted = prettyPrintSource(source, derivedText);
const map = sourceRepresentationLineMap(original, derivedText, derived, formatted);
const lines = formatted.text.split('\n');
process.stdout.write(JSON.stringify({
  returnLine: map[lines.findIndex(line => line.includes('return value'))].originalLine,
  replacementLine: map[lines.findIndex(line => line.includes('const value'))].originalLine
}));
"""
        )
        self.assertEqual(result, {"returnLine": 1, "replacementLine": 0})

    def test_pretty_print_rejects_unsupported_and_oversized_sources(self):
        result = self.run_node(
            r"""
process.stdout.write(JSON.stringify({
  text: prettyPrintSource({kind:'response_body',mime_type:'text/plain',url:'readme.txt'}, 'plain').error,
  oversized: prettyPrintSource(
    {kind:'javascript',mime_type:'text/javascript',url:'large.js'},
    'x'.repeat(SOURCE_PRETTY_INPUT_LIMIT + 1)
  ).error,
  tokenLimit: prettyPrintSource(
    {kind:'javascript',mime_type:'text/javascript',url:'pathological.js'},
    'a+'.repeat(SOURCE_PRETTY_TOKEN_LIMIT)
  ).error
}));
"""
        )
        self.assertIn("does not support Plain text", result["text"])
        self.assertIn("limited to the first 2 MB", result["oversized"])
        self.assertIn("token limit reached", result["tokenLimit"])


if __name__ == "__main__":
    unittest.main()
