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

    def analyze(self, source, assume_intrinsics=False):
        result = subprocess.run([str(self.worker)], input=json.dumps({'source': source, 'assume_intrinsics': assume_intrinsics}), capture_output=True, text=True, check=True, timeout=5)
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

    def test_pathological_nesting_is_rejected_without_losing_framing(self):
        source = '!' * 10000 + '0;'
        request = json.dumps({'source': source}) + '\n' + json.dumps({'source': '1+2'}) + '\n'
        result = subprocess.run([str(self.worker)], input=request, text=True, capture_output=True, timeout=5, check=True)
        rejected, recovered = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertFalse(rejected['ok'])
        self.assertEqual(rejected['derived_source'], source)
        self.assertIn('depth', rejected['syntax_errors'][0]['message'])
        self.assertEqual(recovered['derived_source'], '(3)')

    def test_pure_proxy_calls_and_unsafe_call_boundaries(self):
        positive = [
            ('const p=(a,b)=>a^b; const result=p(7,3);', '(4)'),
            ('const result=((a,b)=>a+b)("ab","cd");', '("abcd")'),
            ('function f(){function p(a){return a*2;} return p(4);}', '(8)'),
            ('const p=function(a){return a+1;}; const result=p(4);', '(5)'),
        ]
        for source, value in positive:
            response = self.analyze(source)
            self.assertIn(value, response['derived_source'])
            self.assertIn('proxy-call', [r['kind'] for r in response['transformations']])
        negative = [
            'const p=(x)=>1; p(effect());',
            'const p=(x)=>1; p(1,effect());',
            'const p=(x=effect())=>1; p();',
            'const p=async(x)=>x+1; p(2);',
            'const p=(x)=>this.value+x; p(2);',
            'const y=4; const p=(x)=>x+y; p(2);',
            'function f(){function p(x){return x+1;} p=other;return p(2);}',
            'function f(){function p(x){return x+1;} eval("p=other");return p(2);}',
            'const p=(x)=>((y)=>y+1)(x); p(2);',
        ]
        for source in negative:
            self.assertNotIn('proxy-call', [r['kind'] for r in self.analyze(source)['transformations']], source)

    def test_custom_xor_decoder_requires_explicit_intrinsic_assumption(self):
        source = 'const decode=function(s,k){var out="";for(var i=0;i<s.length;i++){out+=String.fromCharCode(s.charCodeAt(i)^k);}return out;};const result=decode("idmmn",1);'
        self.assertEqual(self.analyze(source)['derived_source'], source)
        response = self.analyze(source, True)
        self.assertIn('const result=("hello")', response['derived_source'])
        self.assertEqual(response['assumptions'], ['standard-intrinsics'])
        self.assertIn('custom-decoder', [r['kind'] for r in response['transformations']])
        with patch('deobfuscation_worker.worker_path', return_value=self.worker):
            self.assertEqual(derive_with_worker(source, True)['text'], response['derived_source'])
        if shutil.which('node'):
            outputs = [subprocess.run(['node', '-e', code+';console.log(result)'], check=True, text=True, capture_output=True).stdout for code in (source, response['derived_source'])]
            self.assertEqual(outputs, ['hello\n', 'hello\n'])

    def test_custom_decoder_effects_shadowing_and_loop_budget(self):
        for body in [
            'var out=String.fromCharCode(65);var String;return out;',
            'external=1;return "bad";',
            'var out="";network();return out;',
            'var out={};out.value=1;return out.value;',
            'let x=1;return x;',
        ]:
            source = 'const d=function(){'+body+'};d();'
            self.assertNotIn('custom-decoder', [r['kind'] for r in self.analyze(source, True)['transformations']])
        response = self.analyze('const d=function(){var i=0;for(;;){i++;}return i;};d();', True)
        self.assertTrue(response['transformations_truncated'])
        self.assertNotIn('custom-decoder', [r['kind'] for r in response['transformations']])
        response = self.analyze('const d=function(n){var x=0;for(var i=0;i<n;i++){x+=i;}return x;};d(5);')
        self.assertIn('(10)', response['derived_source'])

    def test_intrinsic_model_rejects_lexical_shadowing_and_visible_mutation(self):
        for source in [
            'const String={fromCharCode(){return "changed";}};const d=()=>String.fromCharCode(65);d();',
            'String.fromCharCode=()=>"changed";const d=()=>String.fromCharCode(65);d();',
            'Object.defineProperty(String,"fromCharCode",{});const d=()=>String.fromCharCode(65);d();',
        ]:
            self.assertFalse(any(r['kind'] in ('proxy-call','custom-decoder') for r in self.analyze(source, True)['transformations']))
