"""End-to-end worker regressions for the ReverseJS technique comparison.

Only these repository-owned fixtures run in Node for differential validation.
The worker itself never invokes a JavaScript runtime.
"""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from deobfuscation_worker import WorkerError, derive_with_worker

from ui_test_support import UI_DIRECTORY


class DeobfuscationMethodsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('cargo'):
            raise unittest.SkipTest('Cargo is not installed')
        worker = UI_DIRECTORY.parent / 'deobfuscator-worker'
        subprocess.run(['cargo', 'build', '--locked', '--manifest-path', str(worker / 'Cargo.toml')], check=True, capture_output=True)
        cls.worker = worker / 'target/debug/reb-deobfuscator-worker'

    def analyze(self, source):
        result = subprocess.run([str(self.worker)], input=json.dumps({'source': source}), capture_output=True, text=True, check=True, timeout=5)
        response = json.loads(result.stdout)
        self.assertTrue(response['ok'], response['syntax_errors'])
        original = source.encode()
        offset = 0
        rebuilt = bytearray()
        for rewrite in response['transformations']:
            start, end = rewrite['original_start'], rewrite['original_end']
            self.assertGreaterEqual(start, offset)
            self.assertGreater(end, start)
            rebuilt.extend(original[offset:start])
            rebuilt.extend(rewrite['replacement'].encode())
            offset = end
        rebuilt.extend(original[offset:])
        self.assertEqual(rebuilt.decode(), response['derived_source'])
        return response

    def test_supported_techniques_through_worker_protocol(self):
        cases = [
            ('const result = 1 + 2 * 3;', '(7)', 'constant-fold'),
            ('const result = "\\x68" + "\\u0069";', '("hi")', 'constant-fold'),
            ('const result = "\\x68i";', '("hi")', 'literal-normalization'),
            ('const result = +~!+!+!~+!!0;', '(-1)', 'constant-fold'),
            ('const key = 7; const result = key ^ 3;', '(4)', 'constant-fold'),
            ('const key = 7; console.log(key);', 'console.log((7))', 'constant-propagation'),
            ('console["log"]("x");', 'console.log', 'member-normalization'),
            ('const result = ["first", "second"][1];', '("second")', 'literal-index'),
            ('function f(){ const t = ["first", "second"]; return t[1]; }', '("second")', 'literal-index'),
            ('const result = true ? "yes" : effect();', '("yes")', 'dead-expression'),
            ('const result = false && effect();', '(false)', 'dead-expression'),
            ('if (2 > 1) yes(); else no();', '{void 0; yes();}', 'dead-branch'),
        ]
        for source, expected, kind in cases:
            with self.subTest(source=source):
                response = self.analyze(source)
                self.assertIn(expected, response['derived_source'])
                self.assertIn(kind, [r['kind'] for r in response['transformations']])

    def test_observable_semantics_on_trusted_fixtures(self):
        if not shutil.which('node'):
            self.skipTest('Node.js is not installed')
        cases = [
            'const result = [1+2*3, -0, ~4294967296, 4294967295>>>0, 2**8];',
            'const result = [1/0, 0/0, 1/(-0), (-0)*1, "😀" < "\\ue000"];',
            'let count=0; function effect(){count++;return 2;} const result=[void effect(),count];',
            'let count=0; const result=[true ? 4 : ++count, false && ++count, count];',
            'const x=7; function f(x){return x+1;} const result=[f(2),x];',
            'const x=7; const f=(x=3)=>x+1; const result=[f(),x];',
            'const x=7; const f=(x)=>x+1; const result=[f(2),x];',
            'let result; try { f(); const x=7; function f(){result=x;} } catch(e){ result=e.name; }',
            'const x=7; const result=delete x;',
            'const a=["before"]; a[0]="after"; const result=a[0];',
            'function f(){const a=["before"]; a[0]="after";return a[0];} const result=f();',
            'function f(){const a=["before"]; const alias=a;alias[0]="after";return a[0];} const result=f();',
            'function f(){const a=["before"]; eval("a[0]=\\\"after\\\"");return a[0];} const result=f();',
            'function f(){const a=["a"];delete a[0];return a[0];} const result=f();',
            'function f(){const a=[1];a[0]++;return a[0];} const result=f();',
            'function f(){const a=[1];delete (a[0]);return a[0];} const result=f();',
            'function f(){const a=["a"]; {const a=["b"];return a[0];}} const result=f();',
            'Array.prototype[0]="inherited";const result=[,][0];delete Array.prototype[0];',
            'Array.prototype.toString=function(){return "changed"}; const result=+[];',
            'let n=0;const result=[1,++n][0]+n;',
            'const result="😀"[0].charCodeAt(0);',
            'if(false){var x=1;}const result=typeof x;',
            'let result=0;if(true)result=1;else result=2;',
            'let result=0;if(false)result=1;',
            'const result=1["toString"]();',
            'const n=1; const result=n["toString"]();',
            'const result = "\\ud800";',
            'function f(){"use " + "strict"; return this === undefined;} const result=f();',
            'let result; try{const x=1; for(let x of [3]) result=x+1;}catch(e){result=e.name;}',
        ]
        for source in cases:
            with self.subTest(source=source):
                derived = self.analyze(source)['derived_source']
                tail = '\nconsole.log(JSON.stringify(result, (_, v) => typeof v === "number" && !Number.isFinite(v) ? String(v) : Object.is(v, -0) ? "negative zero" : v));'
                outputs = [subprocess.run(['node', '-e', code + tail], capture_output=True, text=True, timeout=3) for code in (source, derived)]
                self.assertEqual(outputs[0].returncode, 0, outputs[0].stderr)
                self.assertEqual(outputs[1].returncode, 0, outputs[1].stderr)
                self.assertEqual(outputs[0].stdout, outputs[1].stdout, derived)

    def test_unknown_execution_remains_inert_and_visible(self):
        for source in [
            'Number.constructor("throw 1")();',
            '+({valueOf(){throw new Error("executed")}});',
            'const result=void unknown();',
            'const result=+[[[],,,]];',
            'const result=decrypt("ciphertext");',
        ]:
            self.assertEqual(self.analyze(source)['derived_source'], source)

    def test_browser_adapter_matches_worker_and_survives_parser_failure(self):
        with patch('deobfuscation_worker.worker_path', return_value=self.worker):
            source = 'const key=7; const result=key^3;'
            self.assertEqual(derive_with_worker(source)['text'], self.analyze(source)['derived_source'])
            with self.assertRaises(WorkerError) as caught:
                derive_with_worker('const broken=;')
            self.assertEqual(caught.exception.status, 422)
        # A crashing parser is isolated in a disposable request process. Use a
        # deterministic failing executable rather than relying on OS stack size.
        with tempfile.TemporaryDirectory() as directory:
            crashed = Path(directory) / 'failed-worker'
            crashed.write_text('#!/bin/sh\nexit 17\n')
            crashed.chmod(0o700)
            with patch('deobfuscation_worker.worker_path', return_value=crashed):
                with self.assertRaises(WorkerError) as caught:
                    derive_with_worker('1+2')
                self.assertEqual(caught.exception.status, 502)
        with patch('deobfuscation_worker.worker_path', return_value=self.worker):
            self.assertEqual(derive_with_worker('1+2')['text'], '(3)')
        with patch('deobfuscation_worker.worker_path', return_value=None):
            self.assertIsNone(derive_with_worker('1+2'))

    def test_rewrite_and_depth_budgets_preserve_parseable_remainder(self):
        source = 'const result=[' + ','.join('1+2' for _ in range(4200)) + '];'
        response = self.analyze(source)
        self.assertTrue(response['transformations_truncated'])
        self.assertEqual(len(response['transformations']), 4096)
        self.analyze(response['derived_source'])
        source = 'const result=' + '!' * 100 + '0;'
        self.assertTrue(self.analyze(source)['transformations_truncated'])

    def test_string_growth_and_replacement_byte_limits(self):
        source = 'const result="' + 'a' * 12000 + '"+"' + 'b' * 12000 + '";'
        response = self.analyze(source)
        self.assertTrue(response['transformations_truncated'])
        self.assertEqual(response['derived_source'], source)
        source = 'const text="' + 'a' * 16000 + '";' + 'console.log(text);' * 100
        response = self.analyze(source)
        self.assertTrue(response['transformations_truncated'])
        self.assertLessEqual(sum(len(r['replacement'].encode()) for r in response['transformations']), 512 * 1024)
        self.assertIn('console.log(text)', response['derived_source'])
