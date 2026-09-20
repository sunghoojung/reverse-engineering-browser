import json
import unittest
from pathlib import Path

from vm_deob import UnsupportedVM, analyze


FIXTURE = Path(__file__).parent / "fixtures" / "xor-stack-vm.js"


class VMDeobTests(unittest.TestCase):
    def test_recovers_xor_stack_vm_without_execution(self):
        result = analyze(FIXTURE.read_text())
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["bytecode"]["xor_key"], 0x8A)
        self.assertEqual(result["result"], 12)
        self.assertEqual(len(result["instructions"]), 4)
        json.dumps(result)

    def test_rejects_unknown_handler(self):
        source = FIXTURE.read_text().replace("case 0x60: return", "case 0x61: return")
        with self.assertRaises(UnsupportedVM):
            analyze(source)


if __name__ == "__main__":
    unittest.main()
