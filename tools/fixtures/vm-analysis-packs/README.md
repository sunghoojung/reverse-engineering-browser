# Owned pack/comparison fixture

The two JavaScript files are repository-authored, inert test inputs. They are
never executed by the pack command or its tests. The workspace documents carry
explicit test effect declarations, not results claimed from static recovery.
Their source hashes bind the exact adjacent source bytes; document hashes use
the canonical ASCII-escaped JSON convention.

Expected comparison: one moved constant (1 → 9), unchanged halt (2), changed
effect (4), and two unknown/contradicted rows from each build (7, 8). The
contradicted row intentionally disagrees with source. All uncertainty must
survive the comparison. See the [contract and command](../../../protocol/vm-analysis-pack-v1.md).
