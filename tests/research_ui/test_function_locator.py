import json
import unittest
from pathlib import Path
from unittest import mock

from debugger.errors import DebuggerBridgeError
from debugger.function_locator import locate_function


class FunctionLocatorTest(unittest.TestCase):
    def test_nested_anonymous_arrow_from_mid_body_with_utf16_and_inline_offset(self):
        source = '"😀"; const outer = () => { const inner = x => x + 1; };'
        script = {'start_line': 4, 'start_column': 10}
        cursor = source.index('x + 1')
        column = 10 + len(source[:cursor].encode('utf-16-le')) // 2
        start = source.index('x => x + 1')
        end = start + len('x => x + 1')
        body = source.index('x + 1')
        response = {
            'schema': 'reb-deobfuscator-worker-v1', 'ok': True,
            'function_location': {
                'kind': 'arrow_function', 'start': len(source[:start].encode()),
                'end': len(source[:end].encode()), 'body_start': len(source[:body].encode()),
            },
        }
        with mock.patch('debugger.function_locator.worker_path', return_value='/worker'), \
             mock.patch('debugger.function_locator.subprocess.run', return_value=mock.Mock(
                 returncode=0, stdout=json.dumps(response).encode())) as run:
            location = locate_function(source, script, 4, column)
        request = json.loads(run.call_args.kwargs['input'])
        self.assertEqual(request['function_at_byte'], len(source[:cursor].encode()))
        self.assertEqual(location['kind'], 'arrow_function')
        self.assertEqual(location['start']['column'], 10 + len(source[:start].encode('utf-16-le')) // 2)
        self.assertEqual(location['body_start']['column'], 10 + len(source[:body].encode('utf-16-le')) // 2)

    def test_rejects_missing_function_and_split_surrogate(self):
        source = '"😀"; const value = 1;'
        script = {'start_line': 0, 'start_column': 0}
        with self.assertRaisesRegex(DebuggerBridgeError, 'UTF-16'):
            locate_function(source, script, 0, 2)
        response = {'schema': 'reb-deobfuscator-worker-v1', 'ok': True,
                    'function_location': None}
        with mock.patch('debugger.function_locator.worker_path', return_value='/worker'), \
             mock.patch('debugger.function_locator.subprocess.run', return_value=mock.Mock(
                 returncode=0, stdout=json.dumps(response).encode())):
            with self.assertRaisesRegex(DebuggerBridgeError, 'No enclosing'):
                locate_function(source, script, 0, 0)

    def test_real_worker_finds_nested_anonymous_function_when_available(self):
        from deobfuscation_worker import worker_path
        if worker_path() is None:
            self.skipTest('Rust worker has not been built')
        source = 'const outer = () => { const inner = x => x + 1; return inner(2); };'
        cursor = source.index('x + 1')
        location = locate_function(source, {'start_line': 0, 'start_column': 0}, 0, cursor)
        self.assertEqual(location['kind'], 'arrow_function')
        self.assertEqual(location['body_start'], {'line': 0, 'column': cursor})
        self.assertEqual(location['start'], {'line': 0, 'column': source.index('x => x + 1')})

    def test_real_worker_locates_ghostwire_signer_when_available(self):
        from deobfuscation_worker import worker_path
        if worker_path() is None:
            self.skipTest('Rust worker has not been built')
        source = (
            Path(__file__).resolve().parents[2]
            / 'apps/runtime-hook-demo/ghostwire-worker/signer-worker.js'
        ).read_text()
        start = source.index('function _0x2a814c')
        cursor = source.index('const _0x379be2', start)
        location = locate_function(source, {'start_line': 0, 'start_column': 0}, 0, cursor)
        self.assertEqual(location['kind'], 'function_declaration')
        self.assertEqual(location['start'], {'line': 0, 'column': start})
        self.assertLess(location['body_start']['column'], cursor)
