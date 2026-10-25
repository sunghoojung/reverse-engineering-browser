//! Bounded static site ranking, not an interpreter or guest-ISA classifier.
use super::Instruction;
use serde_json::{Value, json};
use std::{cmp::Reverse, collections::BTreeMap, ops::Range};

pub(super) const MAX_SITES: usize = 256;
// Loops first, then interpreter-scale tables. Small sites retain the detector's
// structural evidence preference, so a bare tiny jump table cannot displace an
// indirect dispatch with local/global and memory signals. Size never raises the
// VM confidence score or supplies an observed guest opcode.
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
    ) -> Option<(Rank, usize, usize)> {
        let mut best = None;
        for instruction in decoded.iter().filter(|i| [0x0e, 0x11].contains(&i.opcode)) {
            let arms = instruction.arm_count.unwrap_or(0);
            let major = arms >= 32;
            let rank = (
                instruction.loop_depth > 0,
                major,
                if major { arms } else { 0 },
                score,
                ip_like,
                instruction.loop_depth,
                body.len(),
                arms,
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
            let classification = if kind == "br_table" && !major {
                "cff-helper-candidate"
            } else {
                "dispatch-candidate"
            };
            self.ranked.insert(rank, json!({
                "kind": kind, "function_index": index,
                "byte_offset": instruction.start, "byte_size": instruction.end - instruction.start,
                "function_body_offset": body.start, "function_body_size": body.len(),
                "arm_count": instruction.arm_count, "loop_depth": instruction.loop_depth,
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
