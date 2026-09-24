import json
import shutil
import subprocess
import unittest

from ui_test_support import read_ui_sources


class SourceCursorTest(unittest.TestCase):
    def test_hook_pivot_uses_only_original_selected_script_coordinates(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js is not installed')
        source = read_ui_sources()
        functions = []
        for name in ('sourceRuntimeColumn', 'pivotSourceToRuntimeHooks'):
            start = source.index(f'      function {name}(')
            end = source.index('\n      }', start) + len('\n      }')
            functions.append(source[start:end])
        exercise = r'''
const source = {source_type: 'script', script_id: 'second', start_line: 7, start_column: 31};
const state = {sourceDeobfuscated: false, sourceCursor: {scriptId: 'first', line: 90, column: 800}, debuggerSession: {target: {id: 'page'}}};
const elements = Object.fromEntries(['hooksScript', 'hooksEntryMode', 'hooksLine', 'hooksColumn', 'hooksLabel'].map(k => [k, {value: '', focus(){}}]));
const selectedSource = () => source;
const runtimeHooksState = () => ({isolated: true, target_id: 'page'});
const showScreen = () => {};
const renderRuntimeHooks = () => {};
const sourceName = () => 'inline';
const requestAnimationFrame = callback => callback();
pivotSourceToRuntimeHooks();
const switched = [elements.hooksEntryMode.value, elements.hooksLine.value, elements.hooksColumn.value];
state.sourceCursor = {scriptId: 'second', line: 8, column: 62};
pivotSourceToRuntimeHooks();
const selected = [elements.hooksLine.value, elements.hooksColumn.value];
state.sourceDeobfuscated = true;
state.sourceCursor.column = 999;
pivotSourceToRuntimeHooks();
const pretty = elements.hooksColumn.value;
process.stdout.write(JSON.stringify({switched, selected, pretty, nextLine: sourceRuntimeColumn(source, 1)}));
'''
        result = subprocess.run([node, '-e', '\n'.join(functions) + exercise],
                                check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout), {
            'switched': ['source', '8', '32'], 'selected': ['9', '63'],
            'pretty': '63', 'nextLine': 0,
        })
