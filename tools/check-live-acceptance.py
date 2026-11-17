#!/usr/bin/env python3
"""Run the v0.6.0 live acceptance through a capture browser built from this tree.

Serves owned loopback fixtures (tools/live_acceptance/), starts one visibly
labeled session per kind (content, budget, metadata, no-stacks) for those
fixtures only, drives the pages with session actions and compares the stored
evidence with what the fixture server saw and sent. Prints PASS, FAIL,
MANUAL and SKIP lines; MANUAL names the steps a person still has to take. Exits
1 on any FAIL and 2 when no browser is given. See docs/development/paired-release.md.
"""

from __future__ import annotations

from live_acceptance.driver import main

if __name__ == "__main__":
    raise SystemExit(main())
