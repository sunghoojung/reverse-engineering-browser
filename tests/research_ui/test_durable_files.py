import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from durable_files import atomic_write_private


class DurableFilesTest(unittest.TestCase):
    def test_replacement_is_private_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workspace" / "document.json"
            atomic_write_private(path, b'{"generation":1}\n')
            atomic_write_private(path, b'{"generation":2}\n')
            self.assertEqual(path.read_bytes(), b'{"generation":2}\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_failed_replace_preserves_previous_document_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document.json"
            atomic_write_private(path, b"original")
            with mock.patch("durable_files.os.replace", side_effect=OSError("disk error")):
                with self.assertRaisesRegex(OSError, "disk error"):
                    atomic_write_private(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_failed_permissions_close_the_temporary_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document.json"
            with mock.patch("durable_files.os.fchmod", side_effect=OSError("permissions")) as chmod:
                with self.assertRaisesRegex(OSError, "permissions"):
                    atomic_write_private(path, b"replacement")
            descriptor = chmod.call_args.args[0]
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertEqual(list(path.parent.iterdir()), [])
