//! Bounded static site ranking, not an interpreter or guest-ISA classifier.
use super::Instruction;
use serde_json::{Value, json};
use std::{cmp::Reverse, collections::BTreeMap, ops::Range};

pub(super) const MAX_SITES: usize = 256;
// Loops first, then interpreter-scale sites. Scale is the explicit br_table arm
// count, or the static active-element funcref count for call_indirect. Unknown
// indirect fanout ranks as zero and never fills arm_count. Small br_table sites
// keep the detector's structural preference below that scale threshold. Size
// never raises the VM confidence score or supplies an observed guest opcode.
pub(super) type Rank = (
    bool,
    bool,
    u32,
    u64,
    bool,
    usize,
    usize,
    u32,
    Reverse<usize>,
);

#[derive(Default)]
pub(super) struct Inventory {
    ranked: BTreeMap<Rank, Value>,
    sites: usize,
    br_tables: usize,
    indirect_calls: usize,
}

impl Inventory {
    pub fn function(
        &mut self,
        index: u32,
        body: &Range<usize>,
        decoded: &[Instruction],
        score: u64,
        ip_like: bool,
        element_fanout: &BTreeMap<u32, u32>,
    ) -> Option<(Rank, usize, usize)> {
        let mut best = None;
        for instruction in decoded.iter().filter(|i| [0x0e, 0x11].contains(&i.opcode)) {
            let fanout = instruction
                .table_index
                .and_then(|table| element_fanout.get(&table).copied());
            // br_table scale is the explicit arm count. call_indirect scale is the
            // static funcref count when an active element segment names that table.
            let scale = if instruction.opcode == 0x0e {
                instruction.arm_count.unwrap_or(0)
            } else {
                fanout.unwrap_or(0)
            };
            let major = scale >= 32;
            let rank = (
                instruction.loop_depth > 0,
                major,
                if major { scale } else { 0 },
                score,
                ip_like,
                instruction.loop_depth,
                body.len(),
                scale,
                Reverse(instruction.start),
            );
            let kind = if instruction.opcode == 0x0e {
                self.br_tables += 1;
                "br_table"
            } else {
                self.indirect_calls += 1;
                "call_indirect"
            };
            self.sites += 1;
            // Three static labels. None of them is a proven guest opcode ISA:
            // that would require a guest PC and a bytecode stream, which this
            // inventory does not have.
            let classification = if kind == "call_indirect" {
                "indirect-handler-candidate"
            } else if !major {
                "cff-helper-candidate"
            } else {
                "dispatch-candidate"
            };
            self.ranked.insert(rank, json!({
                "kind": kind, "function_index": index,
                "byte_offset": instruction.start, "byte_size": instruction.end - instruction.start,
                "function_body_offset": body.start, "function_body_size": body.len(),
                "arm_count": instruction.arm_count, "unique_target_count": instruction.unique_targets,
                "element_fanout": fanout, "loop_depth": instruction.loop_depth,
                "ip_like": ip_like, "structural_score": score, "classification": classification,
            }));
            if self.ranked.len() > MAX_SITES {
                self.ranked.pop_first();
            }
            if instruction.loop_depth > 0
                && best
                    .as_ref()
                    .is_none_or(|(previous, _, _)| rank > *previous)
            {
                best = Some((rank, instruction.start, instruction.end));
            }
        }
        best
    }

    pub fn value(self, selected: Option<usize>) -> Value {
        let candidates = self
            .ranked
            .into_iter()
            .rev()
            .map(|(_, site)| site)
            .collect::<Vec<_>>();
        json!({
            "ranking_version": 1, "site_count": self.sites,
            "br_table_count": self.br_tables, "call_indirect_count": self.indirect_calls,
            "omitted_site_count": self.sites.saturating_sub(candidates.len()),
            "selected_byte_offset": selected, "candidates": candidates,
        })
    }
}
