#!/usr/bin/env python3
"""Drive reb-api-mcp.sh --choose through a pseudo-terminal."""

import os
import pty
import select
import subprocess
import sys
import time


def main() -> int:
    script, root, log, fake, choice = sys.argv[1:6]
    extra = sys.argv[6:]
    if os.path.exists(log):
        os.remove(log)
    master, slave = pty.openpty()
    env = os.environ.copy()
    env["REB_API"] = fake
    env["REB_API_LOG"] = log
    env["HOME"] = os.environ.get("REB_MCP_TEST_HOME", "/nonexistent-reb-home")
    env.pop("REB_LIVE_SESSION_ROOT", None)
    args = [script, "--choose", "--sessions-root", root, *extra]
    process = subprocess.Popen(
        args,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
    )
    os.close(slave)
    data = b""
    deadline = time.monotonic() + 5
    while b"End of session list." not in data:
        if time.monotonic() > deadline:
            process.kill()
            sys.stderr.buffer.write(data)
            print("prompt missing", file=sys.stderr)
            return 1
        ready, _, _ = select.select([master], [], [], 0.2)
        if not ready:
            if process.poll() is not None:
                sys.stderr.buffer.write(data)
                print("chooser exited before the list", file=sys.stderr)
                return process.returncode or 1
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    os.write(master, choice.encode() + b"\n")
    code = process.wait(timeout=5)
    sys.stdout.buffer.write(data)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
