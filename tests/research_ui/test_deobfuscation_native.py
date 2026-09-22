import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from deobfuscation import verify_deobfuscation_document
from ui_test_support import UI_DIRECTORY


class DeobfuscationNativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != 'Darwin':
            raise unittest.SkipTest('Native deobfuscation requires macOS')
        if not shutil.which('cargo'):
            raise unittest.SkipTest('Cargo is not installed')
        worker = UI_DIRECTORY.parent / 'deobfuscator-worker'
        subprocess.run(['cargo', 'build', '--locked', '--manifest-path', str(worker / 'Cargo.toml')], check=True, capture_output=True)
        cls.worker = worker / 'target/debug/reb-deobfuscator-worker'
        cls.temporary = tempfile.TemporaryDirectory()
        cls.runner = Path(cls.temporary.name) / 'native-test'
        harness = Path(cls.temporary.name) / 'main.swift'
        application = (UI_DIRECTORY / 'macos/OriginTraceApp.swift').read_text()
        start = application.index('  private func debuggerUnavailableResponse(')
        end = application.index('\n  private func ', start + 1)
        offline_function = application[start:end].replace('private func', 'func', 1)
        harness.write_text('''
import Foundation
''' + offline_function + '''
if CommandLine.arguments[1] == "--offline" {
  FileHandle.standardOutput.write(try debuggerUnavailableResponse(ifNoneMatch: nil).0)
  exit(0)
}
let service = NativeDeobfuscationService(executableURL: URL(fileURLWithPath: CommandLine.arguments[1]))
do {
  let result = try service.analyze(source: FileHandle.standardInput.readDataToEndOfFile(), artifactID: "9", mode: "derived", assumeIntrinsics: CommandLine.arguments.contains("--assume-intrinsics"))
  FileHandle.standardOutput.write(result)
} catch let error as NativeDecoderError {
  FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: ["status":error.status,"error":error.message]))
}
''')
        subprocess.run(['xcrun', 'swiftc', str(harness), str(UI_DIRECTORY / 'macos/DecoderService.swift'), str(UI_DIRECTORY / 'macos/DeobfuscationService.swift'), '-o', str(cls.runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def analyze(self, source, assume_intrinsics=False):
        args = [str(self.runner), str(self.worker)] + (["--assume-intrinsics"] if assume_intrinsics else [])
        result = subprocess.run(args, input=source, capture_output=True, check=True, timeout=10)
        return json.loads(result.stdout)

    def test_native_worker_returns_unicode_source_and_mapped_fold(self):
        source = 'const emoji = "😀"; const value = 1 + 2;'
        response = self.analyze(source.encode())
        self.assertEqual(response['original_source'], source)
        self.assertEqual(response['engine'], 'rust-oxc')
        verify_deobfuscation_document(response['analysis'])
        representation = response['representation']
        self.assertEqual(representation['offset_unit'], 'utf-8-byte')
        self.assertEqual(representation['text'], 'const emoji = "😀"; const value = (3);')
        for segment in representation['segments']:
            if segment['kind'] == 'verbatim':
                self.assertEqual(source.encode()[segment['original_start']:segment['original_end']], representation['text'].encode()[segment['derived_start']:segment['derived_end']])
        self.assertEqual(response['analysis']['classification']['label'], 'unclassified')

    def test_native_dispatcher_result_keeps_source_mapping(self):
        source = b'const decode=function(){var n=0;while(true){switch(n++){case 0:continue;case 1:return "hi";}}};const result=decode();'
        response = self.analyze(source)
        self.assertIn('const result=("hi");', response['representation']['text'])
        self.assertEqual(response['original_source'], source.decode())
        verify_deobfuscation_document(response['analysis'])

    def test_invalid_and_oversized_sources_have_explicit_errors(self):
        for source, status in [(b'const broken = ;', 422), (b'\xff', 400), (b'x' * (4 * 1024 * 1024 + 1), 400)]:
            with self.subTest(status=status):
                self.assertEqual(self.analyze(source)['status'], status)

    def test_worker_deadline_terminates_a_hung_process(self):
        worker = Path(self.temporary.name) / 'hung-worker'
        worker.write_text('#!/bin/sh\nexec /bin/sleep 20\n')
        worker.chmod(0o700)
        result = subprocess.run([str(self.runner), str(worker)], input=b'1+2', capture_output=True, check=True, timeout=8)
        self.assertEqual(json.loads(result.stdout)['status'], 408)

    def test_offline_native_snapshot_matches_ui_contract(self):
        if not shutil.which('node'):
            self.skipTest('Node.js is not installed')
        response = subprocess.run([str(self.runner), '--offline'], capture_output=True, text=True, check=True)
        program = (UI_DIRECTORY / 'evidence_models.js').read_text()
        program += '\nconsole.log(isDebuggerResponse(' + response.stdout + '));'
        result = subprocess.run(['node', '-e', program], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), 'true')

    def test_native_custom_decoder_assumptions_are_explicit(self):
        source = b'const d=function(s){var out="";for(var i=0;i<s.length;i++){out+=String.fromCharCode(s.charCodeAt(i)^1);}return out;};d("idmmn");'
        original = self.analyze(source)
        self.assertEqual(original['analysis']['assumptions'], [])
        self.assertEqual(original['representation']['text'], source.decode())
        derived = self.analyze(source, True)
        self.assertEqual(derived['analysis']['assumptions'], ['standard-intrinsics'])
        self.assertIn('("hello")', derived['representation']['text'])

    def test_native_jsfuck_model_is_opt_in(self):
        source = b'const result=+([[[[[[]],,,]]]] != 0);'
        self.assertEqual(self.analyze(source)['representation']['text'], source.decode())
        response = self.analyze(source, True)
        self.assertEqual(response['representation']['text'], 'const result=(1);')
        self.assertEqual(response['analysis']['assumptions'], ['standard-intrinsics'])
