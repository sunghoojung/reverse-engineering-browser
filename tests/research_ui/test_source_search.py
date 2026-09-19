import json
import shutil
import subprocess
import unittest

from ui_test_support import UI_DIRECTORY


class SourceSearchTest(unittest.TestCase):
    def test_occurrences_preserve_offsets_and_bound_results(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js is not installed')
        model = (UI_DIRECTORY / 'source_syntax.js').read_text()
        exercise = r'''
const result = {
  repeated: findSourceOccurrences(['function a(){}; function b(){}', 'FUNCTION c(){}'], 'function'),
  literal: findSourceOccurrences(['a.b aXb [x]'], 'a.b'),
  brackets: findSourceOccurrences(['a.b aXb [x]'], '[x]'),
  unicode: findSourceOccurrences(['İ😀function'], 'function'),
  astral: findSourceOccurrences(['😀😀'], '😀'),
  empty: findSourceOccurrences(['anything'], ''),
  missing: findSourceOccurrences(['anything'], 'absent'),
  capped: findSourceOccurrences(['aaaa', 'aaaa'], 'a', 3),
  exact: findSourceOccurrences(['aaa'], 'a', 3),
};
process.stdout.write(JSON.stringify(result));
'''
        result = subprocess.run([node, '-e', model + exercise],
                                check=True, capture_output=True, text=True)
        actual = json.loads(result.stdout)
        self.assertEqual(actual['repeated']['matches'], [
            {'line': 0, 'column': 0, 'length': 8},
            {'line': 0, 'column': 16, 'length': 8},
            {'line': 1, 'column': 0, 'length': 8},
        ])
        self.assertEqual(actual['literal']['matches'], [{'line': 0, 'column': 0, 'length': 3}])
        self.assertEqual(actual['brackets']['matches'], [{'line': 0, 'column': 8, 'length': 3}])
        self.assertEqual(actual['unicode']['matches'], [{'line': 0, 'column': 3, 'length': 8}])
        self.assertEqual([m['column'] for m in actual['astral']['matches']], [0, 2])
        self.assertEqual([m['length'] for m in actual['astral']['matches']], [2, 2])
        self.assertEqual(actual['empty'], {'matches': [], 'truncated': False})
        self.assertEqual(actual['missing'], {'matches': [], 'truncated': False})
        self.assertEqual(len(actual['capped']['matches']), 3)
        self.assertTrue(actual['capped']['truncated'])
        self.assertFalse(actual['exact']['truncated'])
