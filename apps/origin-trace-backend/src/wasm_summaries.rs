//! Which parameters of a function reach which of its results: the function
//! summary a value-flow slice uses to continue through a call without losing
//! the call site. Backward at a call's result `r`, the arguments `k` whose
//! parameter reaches `r` feed the result; forward at an argument `k`, the
//! results its parameter reaches carry the value on. The flow inside the
//! callee is still walked and listed by the slice; the summary only says which
//! result returns to which call, which a context-insensitive walk cannot.
//!
//! A summary is exact over the same edges the slice follows as values
//! (operands, locals, joins, forwarded stores and globals, `select` operands)
//! and through the summaries of the functions the callee calls, so it is as
//! deep as the call graph. Summaries are computed on demand for the entries a
//! slice asks about, each once per module hash: a depth-first walk over the
//! entries with an explicit stack, and a fixpoint over the entries of each
//! recursive cycle (strongly connected component of the entries met), since
//! the result slots a parameter reaches only grow. Nothing is bounded but
//! the module itself; a request that goes away stops the walk.
use crate::error::{Result, check_cancelled};
use crate::wasm_def_use::{EdgeKind, NodeKind, Simulation};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

const WHAT: &str = "WASM function summaries";

/// Result slots a value reaches, one bit each; a type declares at most 1,000.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Mask {
    words: Vec<u64>,
}

impl Mask {
    pub fn empty(results: u32) -> Self {
        Self {
            words: vec![0; (results as usize).div_ceil(64)],
        }
    }
    pub fn set(&mut self, bit: u32) {
        let word = bit as usize / 64;
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= 1 << (bit % 64);
    }
    pub fn get(&self, bit: u32) -> bool {
        self.words
            .get(bit as usize / 64)
            .is_some_and(|word| word & (1 << (bit % 64)) != 0)
    }
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }
    pub fn bits(&self) -> impl Iterator<Item = u32> + '_ {
        self.words.iter().enumerate().flat_map(|(index, word)| {
            (0..64)
                .filter(move |bit| word & (1 << bit) != 0)
                .map(move |bit| index as u32 * 64 + bit)
        })
    }
    pub fn bytes(&self) -> u64 {
        (self.words.len() * 8) as u64
    }
}

/// The simulations a summary walks: one per function, built on demand and
/// shared with the slice that asked.
pub trait Bodies {
    /// `None` for a function that has no body this walk can read (imported,
    /// undefined, or its simulation was refused and the refusal noted); its
    /// calls are opaque and its parameters reach nothing.
    fn simulation(&self, function: u32) -> Result<Option<Arc<Simulation>>>;
    fn imported_functions(&self) -> u32;
}

/// Summaries of one module, keyed by (function, parameter).
#[derive(Default)]
pub struct Reach {
    done: Mutex<HashMap<(u32, u32), Arc<Mask>>>,
}

/// An entry's state during one walk. `Open` is an entry whose frame is on
/// the stack or whose cycle is still being iterated: `depth` is the stack
/// position of the frame or fixpoint that owns it, and `mask` the slots
/// known so far.
enum State {
    Open { depth: usize, mask: Mask },
    Done(Arc<Mask>),
}

/// One entry's walk: a forward BFS from its parameter through the callee's
/// values, paused at each call whose summary is not known yet.
struct Explore {
    function: u32,
    param: u32,
    depth: usize,
    /// `None` when the function has no body to walk.
    sim: Option<Arc<Simulation>>,
    queue: VecDeque<(u32, u16)>,
    seen: HashSet<(u32, u16)>,
    results: Mask,
    /// Calls met: the call node, its callee and the argument slot the walked
    /// value reaches; resolved in order once each callee's summary is known.
    pending: VecDeque<(u32, u32, u16)>,
    asked: HashSet<(u32, u16)>,
    /// The lowest stack depth of an open entry this walk consumed: below its
    /// own depth, the entry is part of a cycle headed there.
    lowest: usize,
    /// Tentative entries recorded before this frame started.
    mark: usize,
}

/// The entries of one recursive cycle, iterated until no mask grows.
struct Fixpoint {
    depth: usize,
    members: Vec<(u32, u32)>,
    before: Vec<Mask>,
    mark: usize,
    running: bool,
}

enum Frame {
    Explore(Explore),
    Fixpoint(Fixpoint),
}

impl Reach {
    /// What the summaries hold, for a cache bounded by bytes.
    pub fn bytes(&self) -> u64 {
        self.done
            .lock()
            .map(|done| done.values().map(|mask| mask.bytes() + 32).sum::<u64>())
            .unwrap_or(0)
    }

    /// The result slots `function`'s parameter `param` reaches.
    pub fn of(
        &self,
        bodies: &dyn Bodies,
        function: u32,
        param: u32,
        cancelled: &AtomicBool,
    ) -> Result<Arc<Mask>> {
        if let Some(mask) = self.known((function, param)) {
            return Ok(mask);
        }
        let mut walk = Walk {
            reach: self,
            bodies,
            cancelled,
            state: HashMap::new(),
            tentatives: Vec::new(),
            stack: Vec::new(),
            polled: 0,
        };
        walk.open(function, param, None)?;
        walk.run()?;
        Ok(self
            .known((function, param))
            .expect("a finished walk leaves its root summary done"))
    }

    fn known(&self, key: (u32, u32)) -> Option<Arc<Mask>> {
        self.done.lock().ok()?.get(&key).cloned()
    }

    fn finish(&self, key: (u32, u32), mask: Mask) -> Arc<Mask> {
        let mask = Arc::new(mask);
        if let Ok(mut done) = self.done.lock() {
            done.insert(key, mask.clone());
        }
        mask
    }
}

struct Walk<'w> {
    reach: &'w Reach,
    bodies: &'w dyn Bodies,
    cancelled: &'w AtomicBool,
    state: HashMap<(u32, u32), State>,
    /// Entries finished inside a cycle whose head is still open, in order.
    tentatives: Vec<(u32, u32)>,
    stack: Vec<Frame>,
    polled: u64,
}

/// Whether a value reaching `kind` over `edge` keeps flowing on as that value.
fn carries(kind: NodeKind, edge: EdgeKind) -> bool {
    match kind {
        NodeKind::Operation
        | NodeKind::LocalSet
        | NodeKind::LocalTee
        | NodeKind::LocalGet
        | NodeKind::Phi => true,
        NodeKind::Select => edge == EdgeKind::Operand,
        NodeKind::Load => edge == EdgeKind::ForwardedStore,
        NodeKind::GlobalGet => edge == EdgeKind::ForwardedGlobal,
        _ => false,
    }
}

impl Walk<'_> {
    /// Pushes a frame for `(function, param)`. The entry stays owned by
    /// `owner` (a fixpoint iterating its cycle) or becomes owned by the new
    /// frame, so a walk that consumes it knows which cycle it joins.
    fn open(&mut self, function: u32, param: u32, owner: Option<usize>) -> Result<()> {
        let depth = self.stack.len();
        let mask = match self.state.get(&(function, param)) {
            Some(State::Open { mask, .. }) => mask.clone(),
            _ => Mask::default(),
        };
        self.state.insert(
            (function, param),
            State::Open {
                depth: owner.unwrap_or(depth),
                mask,
            },
        );
        let sim = self.bodies.simulation(function)?;
        let mut explore = Explore {
            function,
            param,
            depth,
            sim,
            queue: VecDeque::new(),
            seen: HashSet::new(),
            results: Mask::default(),
            pending: VecDeque::new(),
            asked: HashSet::new(),
            lowest: depth,
            mark: self.tentatives.len(),
        };
        if let Some(sim) = &explore.sim {
            explore.results = Mask::empty(sim.results);
            if let Some(node) = sim
                .nodes
                .iter()
                .position(|node| node.kind == NodeKind::Param && node.index == param)
            {
                explore.seen.insert((node as u32, 0));
                explore.queue.push_back((node as u32, 0));
            }
        }
        self.stack.push(Frame::Explore(explore));
        Ok(())
    }

    /// A known entry: the depth of the open frame or cycle that owns it, and
    /// the slots known so far.
    fn lookup(&self, key: (u32, u32)) -> Option<(Option<usize>, Mask)> {
        match self.state.get(&key) {
            Some(State::Done(mask)) => Some((None, (**mask).clone())),
            Some(State::Open { depth, mask }) => Some((Some(*depth), mask.clone())),
            None => self.reach.known(key).map(|mask| (None, (*mask).clone())),
        }
    }

    fn run(&mut self) -> Result<()> {
        let imported = self.bodies.imported_functions();
        while let Some(frame) = self.stack.pop() {
            match frame {
                Frame::Explore(mut explore) => {
                    self.polled += explore.walk(imported);
                    if self.polled > 4096 {
                        self.polled = 0;
                        check_cancelled(self.cancelled, WHAT)?;
                    }
                    if let Some(&(node, callee, arg)) = explore.pending.front() {
                        match self.lookup((callee, u32::from(arg))) {
                            Some((owner, mask)) => {
                                explore.pending.pop_front();
                                if let Some(depth) = owner {
                                    explore.lowest = explore.lowest.min(depth);
                                }
                                explore.feed(node, &mask);
                                self.stack.push(Frame::Explore(explore));
                            }
                            None => {
                                self.stack.push(Frame::Explore(explore));
                                self.open(callee, u32::from(arg), None)?;
                            }
                        }
                        continue;
                    }
                    self.complete(explore);
                }
                Frame::Fixpoint(mut fixpoint) => {
                    if !fixpoint.running {
                        fixpoint.running = true;
                        fixpoint.before = fixpoint
                            .members
                            .iter()
                            .map(|member| match self.state.get(member) {
                                Some(State::Open { mask, .. }) => mask.clone(),
                                _ => Mask::default(),
                            })
                            .collect();
                        let depth = fixpoint.depth;
                        let members = fixpoint.members.clone();
                        self.stack.push(Frame::Fixpoint(fixpoint));
                        for (function, param) in members {
                            self.open(function, param, Some(depth))?;
                        }
                        continue;
                    }
                    // Every member ran once more; entries that finished
                    // tentatively meanwhile joined the cycle.
                    for joined in self.tentatives.split_off(fixpoint.mark) {
                        if !fixpoint.members.contains(&joined) {
                            fixpoint.members.push(joined);
                            fixpoint.before.push(Mask::default());
                        }
                    }
                    let changed =
                        fixpoint
                            .members
                            .iter()
                            .zip(&fixpoint.before)
                            .any(|(member, before)| match self.state.get(member) {
                                Some(State::Open { mask, .. }) => mask != before,
                                _ => false,
                            });
                    if changed {
                        fixpoint.running = false;
                        self.stack.push(Frame::Fixpoint(fixpoint));
                        continue;
                    }
                    for member in fixpoint.members {
                        if let Some(State::Open { mask, .. }) = self.state.remove(&member) {
                            let done = self.reach.finish(member, mask);
                            self.state.insert(member, State::Done(done));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// A finished walk: done, tentative inside a cycle, or the head of one.
    fn complete(&mut self, explore: Explore) {
        let key = (explore.function, explore.param);
        if explore.lowest < explore.depth {
            self.state.insert(
                key,
                State::Open {
                    depth: explore.lowest,
                    mask: explore.results,
                },
            );
            self.tentatives.push(key);
            if let Some(Frame::Explore(parent)) = self.stack.last_mut() {
                parent.lowest = parent.lowest.min(explore.lowest);
            }
            return;
        }
        if self.tentatives.len() > explore.mark {
            let mut members = self.tentatives.split_off(explore.mark);
            members.push(key);
            self.state.insert(
                key,
                State::Open {
                    depth: explore.depth,
                    mask: explore.results,
                },
            );
            self.stack.push(Frame::Fixpoint(Fixpoint {
                depth: explore.depth,
                members,
                before: Vec::new(),
                mark: self.tentatives.len(),
                running: false,
            }));
            return;
        }
        let done = self.reach.finish(key, explore.results);
        self.state.insert(key, State::Done(done));
    }
}

impl Explore {
    /// Runs the BFS until the queue is empty or a call needs a summary.
    /// Returns the values walked, for cancellation polling.
    fn walk(&mut self, imported: u32) -> u64 {
        let Some(sim) = &self.sim else {
            return 0;
        };
        let mut walked = 0u64;
        while let Some((node, result)) = self.queue.pop_front() {
            walked += 1;
            for edge in sim.adjacency.uses(node) {
                let edge = sim.edges[*edge as usize];
                if edge.result != result {
                    continue;
                }
                let target = sim.nodes[edge.to as usize];
                if carries(target.kind, edge.kind) {
                    for slot in 0..target.results.max(1) {
                        if self.seen.insert((edge.to, slot)) {
                            self.queue.push_back((edge.to, slot));
                        }
                    }
                } else if target.kind == NodeKind::Return && edge.kind == EdgeKind::Return {
                    self.results.set(u32::from(edge.operand));
                } else if target.kind == NodeKind::Call
                    && edge.kind == EdgeKind::Argument
                    && target.index >= imported
                    && self.asked.insert((edge.to, edge.operand))
                {
                    self.pending
                        .push_back((edge.to, target.index, edge.operand));
                }
            }
        }
        walked
    }

    /// The call at `node` returns `mask`'s slots for the argument walked.
    fn feed(&mut self, node: u32, mask: &Mask) {
        for slot in mask.bits() {
            let slot = slot as u16;
            if self.seen.insert((node, slot)) {
                self.queue.push_back((node, slot));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_def_use::{self, Module};

    struct Fixture {
        bytes: Vec<u8>,
        cancelled: AtomicBool,
    }

    impl Fixture {
        fn new(wat: &str) -> Self {
            Self {
                bytes: wat::parse_str(wat).unwrap(),
                cancelled: AtomicBool::new(false),
            }
        }
    }

    impl Bodies for Fixture {
        fn simulation(&self, function: u32) -> Result<Option<Arc<Simulation>>> {
            let module = Module::read(&self.bytes).unwrap();
            let Some(body) = module
                .bodies
                .get((function.wrapping_sub(module.imported_functions)) as usize)
            else {
                return Ok(None);
            };
            if function < module.imported_functions {
                return Ok(None);
            }
            Ok(Some(Arc::new(wasm_def_use::simulate(
                &module,
                function,
                body,
                &self.cancelled,
            )?)))
        }
        fn imported_functions(&self) -> u32 {
            Module::read(&self.bytes).unwrap().imported_functions
        }
    }

    fn bits(mask: &Mask) -> Vec<u32> {
        mask.bits().collect()
    }

    #[test]
    fn parameters_reach_results_through_locals_joins_and_calls() {
        let fixture = Fixture::new(
            r#"(module
                  (import "env" "now" (func $now (result i32)))
                  (func $id (param i32) (result i32) (local.get 0))
                  (func $pair (param i32 i32) (result i32 i32)
                    (local.get 1) (call $id (local.get 0)))
                  (func $pick (param i32 i32) (result i32)
                    (if (result i32) (local.get 0) (then (local.get 1)) (else (call $now))))
                  (func $tail (param i32) (result i32) (return_call $id (local.get 0)))
                  (func $dead (param i32) (result i32) (call $now)))"#,
        );
        let reach = Reach::default();
        let never = AtomicBool::new(false);
        let of = |f: u32, p: u32| bits(&reach.of(&fixture, f, p, &never).unwrap());
        assert_eq!(of(1, 0), vec![0]);
        assert_eq!(of(2, 0), vec![1], "through the callee's summary");
        assert_eq!(of(2, 1), vec![0]);
        assert_eq!(of(3, 0), Vec::<u32>::new(), "a selector is not the value");
        assert_eq!(of(3, 1), vec![0], "through the if join");
        assert_eq!(
            of(4, 0),
            vec![0],
            "a tail call returns the callee's results"
        );
        assert_eq!(of(5, 0), Vec::<u32>::new());
        assert_eq!(of(0, 0), Vec::<u32>::new(), "an import has no body");
        assert!(reach.bytes() > 0);
    }

    #[test]
    fn recursive_cycles_reach_a_fixpoint() {
        // even(n, acc) returns acc when n is 0 and odd(n - 1, acc) otherwise;
        // odd returns its own n at 0 and even(n - 1, acc) otherwise: acc reaches
        // both results only around the cycle, and n reaches odd's result.
        // self(n) returns self(n) or 0: its parameter reaches its result only
        // through itself, so the least fixpoint says it never does.
        let fixture = Fixture::new(
            r#"(module
                  (func $even (param i32 i32) (result i32)
                    (if (result i32) (local.get 0)
                      (then (call $odd (i32.sub (local.get 0) (i32.const 1)) (local.get 1)))
                      (else (local.get 1))))
                  (func $odd (param i32 i32) (result i32)
                    (if (result i32) (local.get 0)
                      (then (call $even (i32.sub (local.get 0) (i32.const 1)) (local.get 1)))
                      (else (local.get 0))))
                  (func $self (param i32) (result i32)
                    (if (result i32) (local.get 0)
                      (then (call $self (local.get 0)))
                      (else (i32.const 0)))))"#,
        );
        let reach = Reach::default();
        let never = AtomicBool::new(false);
        let of = |f: u32, p: u32| bits(&reach.of(&fixture, f, p, &never).unwrap());
        assert_eq!(of(0, 1), vec![0], "acc returns through odd then even");
        assert_eq!(of(1, 1), vec![0]);
        assert_eq!(
            of(0, 0),
            vec![0],
            "n reaches odd's result, which even returns"
        );
        assert_eq!(of(1, 0), vec![0]);
        assert_eq!(
            of(2, 0),
            Vec::<u32>::new(),
            "self recursion alone returns nothing of the argument"
        );
    }

    #[test]
    fn a_cancelled_request_stops_the_walk() {
        let fixture = Fixture::new("(module (func (param i32) (result i32) (local.get 0)))");
        fixture
            .cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let reach = Reach::default();
        let error = reach.of(&fixture, 0, 0, &fixture.cancelled).unwrap_err();
        assert_eq!(error.status, 499);
    }
}
