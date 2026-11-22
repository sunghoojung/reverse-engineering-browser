//! Control dependence of one function's basic blocks (Ferrante, Ottenstein
//! and Warren): block `b` depends on decision `a` when one of `a`'s successors
//! always leads to `b` and another may not. Post-dominators come from the
//! iterative algorithm of Cooper, Harvey and Kennedy run on the reversed
//! graph from a virtual exit, and dependences from walking the post-dominator
//! tree up from each successor of a decision. Both are linear in the blocks,
//! edges and dependences for the structured graphs Wasm produces.
//!
//! A block from which no exit is reachable (an endless loop) is joined to the
//! virtual exit, as the usual construction does, so every block has a
//! post-dominator.
use crate::error::{Result, check_cancelled};
use crate::wasm_graph::ControlFlow;
use std::sync::atomic::AtomicBool;

const UNSET: u32 = u32::MAX;

/// For each block, the decision blocks it is directly control dependent on.
pub(crate) struct Dependences {
    start: Vec<u32>,
    decisions: Vec<u32>,
}

impl Dependences {
    pub(crate) fn of(&self, block: u32) -> &[u32] {
        let start = self.start[block as usize] as usize;
        let end = self.start[block as usize + 1] as usize;
        &self.decisions[start..end]
    }
}

pub(crate) fn dependences(flow: &ControlFlow, cancelled: &AtomicBool) -> Result<Dependences> {
    const WHAT: &str = "Control dependence";
    let blocks = flow.leaders.len();
    let exit = blocks as u32;
    let nodes = blocks + 1;
    // The reversed graph: an edge a -> b of the body is b -> a here, and the
    // virtual exit leads to every exit block.
    let mut reverse_count = vec![0u32; nodes + 1];
    let mut exits: Vec<u32> = (0..blocks as u32)
        .filter(|block| flow.exits[*block as usize])
        .collect();
    for block in 0..blocks as u32 {
        for successor in flow.successors(block) {
            reverse_count[*successor as usize + 1] += 1;
        }
    }
    for index in 0..nodes {
        reverse_count[index + 1] += reverse_count[index];
    }
    let mut reverse = vec![0u32; reverse_count[nodes] as usize];
    let mut fill = reverse_count.clone();
    for block in 0..blocks as u32 {
        for successor in flow.successors(block) {
            reverse[fill[*successor as usize] as usize] = block;
            fill[*successor as usize] += 1;
        }
    }
    let reverse_successors = |node: u32| -> &[u32] {
        &reverse[reverse_count[node as usize] as usize..reverse_count[node as usize + 1] as usize]
    };
    // Postorder of the reversed graph from the exit. Nothing leads back to
    // the exit there, so each of its children is walked on its own and the
    // exit is numbered last. Blocks no walk reaches cannot reach an exit;
    // each such region is joined to the exit at its highest block, usually
    // its back-edge source, and walked in turn.
    let mut order: Vec<u32> = Vec::with_capacity(nodes);
    let mut number = vec![UNSET; nodes];
    let mut seen = vec![false; nodes];
    let mut stack: Vec<(u32, usize)> = Vec::new();
    let mut walk = |root: u32, seen: &mut Vec<bool>, order: &mut Vec<u32>| {
        if seen[root as usize] {
            return;
        }
        seen[root as usize] = true;
        stack.push((root, 0));
        while let Some((node, position)) = stack.last_mut() {
            let children = reverse_successors(*node);
            if *position < children.len() {
                let child = children[*position];
                *position += 1;
                if !seen[child as usize] {
                    seen[child as usize] = true;
                    stack.push((child, 0));
                }
            } else {
                order.push(*node);
                stack.pop();
            }
        }
    };
    seen[exit as usize] = true;
    for block in exits.clone() {
        walk(block, &mut seen, &mut order);
    }
    for block in (0..blocks as u32).rev() {
        if !seen[block as usize] {
            if block & 4095 == 0 {
                check_cancelled(cancelled, WHAT)?;
            }
            exits.push(block);
            walk(block, &mut seen, &mut order);
        }
    }
    order.push(exit);
    for (position, node) in order.iter().enumerate() {
        number[*node as usize] = position as u32;
    }
    // Cooper, Harvey and Kennedy over the reversed graph: a node's
    // predecessors there are its successors in the body, and the exit for an
    // exit block.
    let is_exit = {
        let mut flags = vec![false; blocks];
        for block in &exits {
            flags[*block as usize] = true;
        }
        flags
    };
    let mut ipdom = vec![UNSET; nodes];
    ipdom[exit as usize] = exit;
    let intersect = |ipdom: &[u32], mut a: u32, mut b: u32| -> u32 {
        while a != b {
            while number[a as usize] < number[b as usize] {
                a = ipdom[a as usize];
            }
            while number[b as usize] < number[a as usize] {
                b = ipdom[b as usize];
            }
        }
        a
    };
    let mut changed = true;
    let mut rounds = 0u32;
    while changed {
        changed = false;
        rounds += 1;
        if rounds & 7 == 0 {
            check_cancelled(cancelled, WHAT)?;
        }
        // Reverse postorder, the exit first.
        for node in order.iter().rev().copied() {
            if node == exit {
                continue;
            }
            let mut chosen = UNSET;
            let consider = |predecessor: u32, chosen: &mut u32| {
                if ipdom[predecessor as usize] == UNSET {
                    return;
                }
                *chosen = if *chosen == UNSET {
                    predecessor
                } else {
                    intersect(&ipdom, predecessor, *chosen)
                };
            };
            if is_exit[node as usize] {
                consider(exit, &mut chosen);
            }
            for successor in flow.successors(node) {
                consider(*successor, &mut chosen);
            }
            if chosen != UNSET && ipdom[node as usize] != chosen {
                ipdom[node as usize] = chosen;
                changed = true;
            }
        }
    }
    // Each edge a -> b of a decision a: every block from b up the
    // post-dominator tree to a's own post-dominator depends on a.
    let mut pairs: Vec<(u32, u32)> = Vec::new();
    for block in 0..blocks as u32 {
        let successors = flow.successors(block);
        let outs = successors.len() + usize::from(is_exit[block as usize]);
        if outs < 2 {
            continue;
        }
        if block & 4095 == 0 {
            check_cancelled(cancelled, WHAT)?;
        }
        let stop = ipdom[block as usize];
        for successor in successors {
            let mut runner = *successor;
            while runner != stop && runner != exit && runner != UNSET {
                pairs.push((runner, block));
                runner = ipdom[runner as usize];
            }
        }
    }
    pairs.sort_unstable();
    pairs.dedup();
    let mut start = vec![0u32; blocks + 1];
    for (block, _) in &pairs {
        start[*block as usize + 1] += 1;
    }
    for block in 0..blocks {
        start[block + 1] += start[block];
    }
    let decisions = pairs.into_iter().map(|(_, decision)| decision).collect();
    Ok(Dependences { start, decisions })
}
