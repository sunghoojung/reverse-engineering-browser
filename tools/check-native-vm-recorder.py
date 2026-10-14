#!/usr/bin/env python3
"""Check the owned fixture's CLI contract without browser dependencies."""

import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()

    def successful(*flags):
        result = subprocess.run(
            [args.binary, *flags],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        assert not result.stderr, result.stderr
        return result.stdout

    assert successful("--self-test") == "Native VM recorder fixture checks passed\n"

    def run(*flags):
        return json.loads(successful(*flags))

    for flags, name in [((), "register"), (("--stack",), "stack")]:
        disabled = run(*flags)
        assert disabled["records"] == []
        assert disabled["recorded"] == disabled["attempted"] == 0
        assert disabled["session_id"] == "0"
        trace = run("--enable-owned-fixture", *flags)
        assert trace == run("--enable-owned-fixture", *flags)
        assert trace["schema"] == "reb-owned-vm-fixture-v1"
        assert trace["fixture"] == name
        assert trace["backend"] == "cooperative-native-fixture"
        assert trace["program_id"] == f"owned-{name}-v1"
        assert trace["fixture_revision"] == 1
        assert trace["pc_units"] == "instruction-index"
        assert trace["value_semantics"] == "unsigned-64-bit-bits"
        assert trace["termination_reason"] == "halt"
        assert trace["generation"] == "1"
        assert trace["session_id"] == "1"
        assert trace["document_id"] == "2"
        assert trace["invocation_id"] == "3"
        assert trace["expires_at"] == "100"
        assert trace["recorded"] == trace["attempted"] == 9
        assert not any(trace["loss"].values())
        for index, record in enumerate(trace["records"]):
            assert record["sequence"] == record["tick"] == str(index + 1)
            assert record["before"]["pc"] == str([0, 1, 2, 3, 4, 5, 6, 8, 10][index])
            assert record["after"]["pc"] == str([1, 2, 3, 4, 5, 6, 8, 10, 10][index])
            assert record["opcode_evidence"] == "observed"
            assert not record["partial"]
            if index < 5:
                assert record["operands"] and record["effects"]
            if index:
                assert record["before"] == trace["records"][index - 1]["after"]
        final = trace["records"][-1]["after"]
        assert final["halted"]
        assert [r["opcode"] for r in trace["records"]][-4:] == [5, 6, 7, 8]
        assert final["memory"] == [
            {"guest_address": "16", "value": {"bits": "12", "evidence": "observed"}}
        ]
        slots = final["stack"] if name == "stack" else final["registers"]
        assert slots[-1] == {"bits": "12", "evidence": "observed"}
    invalid = subprocess.run(
        [args.binary, "--unknown"], capture_output=True, text=True, check=False, timeout=10
    )
    assert invalid.returncode == 2 and not invalid.stdout
    assert invalid.stderr == (
        "Usage: reb-native-vm-fixture [--enable-owned-fixture] [--stack]\n"
        "       reb-native-vm-fixture --self-test\n"
    )
    print("Native VM fixture CLI contract passed")


if __name__ == "__main__":
    main()
