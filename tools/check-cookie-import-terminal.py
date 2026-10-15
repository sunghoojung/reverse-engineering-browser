#!/usr/bin/env python3
"""Exercise the real hidden-input terminal flow with synthetic data only."""

import json
import os
import pty
import select
import subprocess
import tempfile
import time
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="reb-cookie-terminal-check-") as directory:
        path = Path(directory).resolve() / "selected-synthetic.json"
        source = json.dumps([{
            "domain": "account.example.test", "hostOnly": True,
            "httpOnly": True, "name": "SYNTHETIC_TERMINAL_NAME", "path": "/",
            "sameSite": "strict", "secure": True, "session": True,
            "storeId": "0", "value": "SYNTHETIC_TERMINAL_VALUE",
        }]).encode()
        path.write_bytes(source)
        for final_answer in (b"CANCEL\r", b"\x03", b"\x04"):
            master, slave = pty.openpty()
            child = subprocess.Popen(
                ["node", str(root / "tools/import-browser-cookies.mjs"),
                 "--browser", "/synthetic/unused/browser"],
                stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
            )
            os.close(slave)
            output = bytearray()

            def wait_for(marker):
                deadline = time.monotonic() + 5
                while marker.encode() not in output:
                    assert time.monotonic() < deadline, "Terminal prompt deadline"
                    ready, _, _ = select.select([master], [], [], 0.1)
                    if ready:
                        output.extend(os.read(master, 65536))

            try:
                for prompt, reply in [
                    ("Selected export file", str(path)),
                    ("Export format", "chrome"),
                    ("Exact destination", "https://account.example.test"),
                    ("Disposable lifetime", "30"),
                ]:
                    wait_for(prompt)
                    # Send immediately when the prompt becomes visible. This
                    # catches a terminal-echo race before setRawMode(true).
                    os.write(master, reply.encode() + b"\r")
                wait_for("Type IMPORT")
                os.write(master, final_answer)
                if final_answer == b"CANCEL\r":
                    wait_for("Cancelled before browser launch.")
                    assert child.wait(timeout=5) == 0
                else:
                    wait_for("Cookie import refused (cancelled)")
                    assert child.wait(timeout=5) == 1
                for private in [str(path), "SYNTHETIC_TERMINAL_NAME",
                                "SYNTHETIC_TERMINAL_VALUE"]:
                    assert private.encode() not in output, "Private terminal echo"
                assert path.read_bytes() == source
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                os.close(master)
    print("PASS real terminal: hidden input/review, keyboard cancel/Ctrl-C/Ctrl-D, "
          "unchanged synthetic source, no browser launch")


if __name__ == "__main__":
    main()
