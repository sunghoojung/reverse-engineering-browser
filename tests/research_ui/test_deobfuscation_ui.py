import json
import shutil
import subprocess
import unittest

from deobfuscation import derive_representation
from ui_test_support import UI_DIRECTORY


class DeobfuscationUiTest(unittest.TestCase):
    def node(self, program):
        if not shutil.which('node'):
            self.skipTest('Node.js is not installed')
        result = subprocess.run(['node', '-e', program], check=True, text=True, capture_output=True)
        return json.loads(result.stdout)

    def test_unicode_mapping_crosses_python_and_javascript_boundary(self):
        original = '"😀😀😀😀😀";\nconst a = 1;\nconst b = 2;'
        representation = derive_representation(original)
        program = (UI_DIRECTORY / 'source_syntax.js').read_text()
        program += '\nconst original = ' + json.dumps(original) + ';'
        program += '\nconst representation = ' + json.dumps(representation) + ';'
        program += '''
const segments = sourceSegmentsUTF16(original, representation.text, representation.segments, representation.offset_unit);
const offset = representation.text.indexOf('const b');
console.log(JSON.stringify({mapped: derivedOriginalOffset(segments, offset), expected: original.indexOf('const b')}));
'''
        result = self.node(program)
        self.assertEqual(result['mapped'], result['expected'])

    def test_utf8_replacements_map_to_original_expression(self):
        program = (UI_DIRECTORY / 'source_syntax.js').read_text() + '''
const source = '"😀";1+2';
const derived = '"😀";3';
const segments = sourceSegmentsUTF16(source, derived, [
{kind:'verbatim', original_start:0,original_end:7,derived_start:0,derived_end:7},
{kind:'replacement',original_start:7,original_end:10,derived_start:7,derived_end:8}
], 'utf-8-byte');
console.log(JSON.stringify({offset:derivedOriginalOffset(segments, derived.indexOf('3')), expected:source.indexOf('1')}));
'''
        result = self.node(program)
        self.assertEqual(result['offset'], result['expected'])

    def test_failure_rerender_does_not_retry_and_explicit_retry_preserves_result(self):
        app = (UI_DIRECTORY / 'app.js').read_text()
        start = app.index('      function deobfuscationKey(')
        end = app.index('      function deobfuscationRow(', start)
        program = app[start:end] + '''
const state = {deobfuscationCache:new Map(),deobfuscationRequests:new Map()};
const source = {key:'artifact:9', source_type:'artifact', artifact_id:'9',sha256:'first'};
const selectedSource = () => ({...source});
let calls = 0;
let fail = true;
const fetch = async () => { calls++; return {ok:!fail,status:404,json:async()=>fail ? {error:'missing'} : {schema:'deobfuscation-analysis-v1',analysis:{},representation:{text:'3'},original_source:'1+2'}}; };
const renderSources = () => { if(calls > 8) throw new Error('retry loop'); loadDeobfuscation({...source}); };
(async()=>{
 await loadDeobfuscation({...source});
 await loadDeobfuscation({...source});
 const failedCalls = calls;
 fail = false;
 await loadDeobfuscation({...source},{retry:true});
 const old = state.deobfuscationCache.get(deobfuscationKey(source));
 fail = true;
 await loadDeobfuscation({...source},{retry:true});
 const retained = state.deobfuscationCache.get(deobfuscationKey(source)) === old;
 source.sha256 = 'second';
 await loadDeobfuscation({...source});
 console.log(JSON.stringify({failedCalls,calls,retained}));
})();
'''
        self.assertEqual(self.node(program), {'failedCalls': 1, 'calls': 4, 'retained': True})

    def test_failed_or_pending_analysis_is_labelled_as_original(self):
        app = (UI_DIRECTORY / 'app.js').read_text()
        start = app.index('      function sourceViewLabel(')
        end = app.index('      function revealOriginalLine(', start)
        program = app[start:end] + """
const state = {sourcePretty:true,deobfuscationRequests:new Map()};
const source = {key:'artifact:9',source_type:'artifact'};
const deobfuscationKey = source => source.key;
const pending = sourceViewLabel(source);
state.deobfuscationRequests.set(source.key,{status:'error'});
const failed = sourceViewLabel(source);
source.deobfuscation = {representation:{text:'3'}};
const retained = sourceViewLabel(source);
console.log(JSON.stringify({pending,failed,retained}));
"""
        self.assertEqual(self.node(program), {
            'pending': 'Original evidence · analysis pending',
            'failed': 'Original evidence · analysis failed',
            'retained': 'Derived · mapped to original source',
        })

    def test_intrinsic_assumption_changes_cache_identity(self):
        app = (UI_DIRECTORY / 'app.js').read_text()
        start = app.index('      function deobfuscationKey(')
        end = app.index('      async function loadDeobfuscation(', start)
        result = self.node(app[start:end] + """
const state={deobfuscationAssumeIntrinsics:false};
const source={key:'artifact:9',sha256:'abc'};
const original=deobfuscationKey(source);
state.deobfuscationAssumeIntrinsics=true;
console.log(JSON.stringify({different:original!==deobfuscationKey(source)}));
""")
        self.assertTrue(result['different'])

    def test_deobfuscation_remains_in_sources(self):
        from html.parser import HTMLParser

        class Controls(HTMLParser):
            def __init__(self):
                super().__init__()
                self.elements = []

            def handle_starttag(self, tag, attrs):
                self.elements.append(dict(attrs))

        controls = Controls()
        controls.feed((UI_DIRECTORY / 'index.html').read_text())
        self.assertFalse(any(element.get('data-screen') == 'deobfuscation' for element in controls.elements))
        self.assertFalse(any(element.get('id') == 'screen-deobfuscation' for element in controls.elements))
        self.assertTrue(any(element.get('id') == 'source-pretty' for element in controls.elements))
        self.assertTrue(any(element.get('id') == 'deobfuscation-report' for element in controls.elements))

    def test_unchanged_artifact_poll_preserves_source_controls(self):
        app = (UI_DIRECTORY / 'app.js').read_text()
        start = app.index('      async function refreshArtifacts(')
        end = app.index('      function showScreen(', start)
        program = app[start:end] + """
const metadata = [{artifact_id:'9',sha256:'abc'}];
const state = {artifactRefreshing:false,artifactEtag:null,artifactCatalogSignature:JSON.stringify(metadata),artifacts:[{...metadata[0],content:'retained'}]};
const location = {protocol:'reb:'};
const fetch = async()=>({ok:true,status:200,headers:{get:()=>null},json:async()=>({artifacts:metadata})});
const isArtifactResponse = ()=>true;
const renderShellStatus = ()=>{};
let health = 0;
const renderSourceHealth = ()=>{health++;};
const renderSources = ()=>{throw new Error('Unexpected replacement of focused source controls');};
(async()=>{await refreshArtifacts(); console.log(JSON.stringify({health,content:state.artifacts[0].content,error:state.artifactReceiverError}));})();
"""
        self.assertEqual(self.node(program), {'health': 1, 'content': 'retained', 'error': None})
