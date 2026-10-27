#!/usr/bin/env python3
"""Verify the retired CLI refuses before consuming input or launching a browser."""

import subprocess
import tempfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    cli = root / "tools/import-browser-cookies.mjs"
    with tempfile.TemporaryDirectory(prefix="reb-cookie-refusal-check-") as directory:
        directory = Path(directory)
        source = directory / "PRIVATE_SYNTHETIC_SOURCE.json"
        private = b"SYNTHETIC_PRIVATE_COOKIE_NAME_AND_VALUE"
        source.write_bytes(private)
        marker = directory / "browser-started"
        browser = directory / "browser"
        browser.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        browser.chmod(0o700)
        for args in ([], ["--browser", str(browser)], [str(source)]):
            result = subprocess.run(
                ["node", str(cli), *args], input=private + b"\n",
                capture_output=True, timeout=5, check=False,
            )
            assert result.returncode == 2, "Retired import must fail explicitly"
            output = result.stdout + result.stderr
            assert b"removed" in output
            assert b"No input was read" in output
            assert b"Selected export" not in output
            assert private not in output and str(source).encode() not in output
            assert not marker.exists(), "Retired import launched a browser"
            assert source.read_bytes() == private
        # An open pipe with no data must not block waiting for private input.
        child = subprocess.Popen(
            ["node", str(cli), "--browser", str(browser)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            assert child.wait(timeout=5) == 2
            assert not marker.exists()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()
        help_result = subprocess.run(
            ["node", str(cli), "--help"], capture_output=True, timeout=5, check=False,
        )
        assert help_result.returncode == 0
        assert b"removed" in help_result.stdout
    print("PASS removed cookie CLI: refusal without stdin, no browser spawn, "
          "unchanged synthetic source, no private output")


if __name__ == "__main__":
    main()
