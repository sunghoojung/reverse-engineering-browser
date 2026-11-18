//! Every direct call site of every function in one module, built once per
//! module hash. A value-flow slice asks it who calls the seed's function (and
//! whether anything else can reach that function: an export, the start
//! function, an element segment or a `ref.func`), and the callers route lists
//! the sites a page at a time. The scan decodes every body once, in parallel,
//! and keeps only the calls, so the index is proportional to the module's
//! call sites and not to its bytes.
use crate::error::{Result, check_cancelled};
use crate::wasm_def_use::Module;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use wasmparser::Operator;

const WHAT: &str = "WASM call index";
/// Bodies one worker claims at a time: bodies vary from a few bytes to
/// megabytes, so claims are small and work stays balanced.
const CLAIM: usize = 64;

/// One direct call: the function it is in, the call instruction's original
/// byte offset, and whether it is a tail call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Site {
    pub caller: u32,
    pub offset: u32,
    pub tail: bool,
}

#[derive(Debug)]
pub struct CallIndex {
    /// Sites sorted by callee, then caller, then offset.
    sites: Vec<(u32, Site)>,
    /// Start of each callee's sites in `sites`, over the function index space.
    start: Vec<u32>,
    /// Functions a `ref.func` in a body names, sorted.
    referenced: Vec<u32>,
    /// Bodies that do not decode; their calls are not indexed.
    pub undecoded: Vec<u32>,
    /// Call instructions found, direct or not, for the index's own accounting.
    pub calls: u64,
}

impl CallIndex {
    /// Scans every body of `module`. The scan stops with 499 once `cancelled`
    /// is set.
    pub fn build(module: &Module<'_>, cancelled: &AtomicBool) -> Result<Self> {
        let bodies = &module.bodies;
        let imported = module.imported_functions;
        let claims = bodies.len().div_ceil(CLAIM);
        let workers = thread::available_parallelism()
            .map_or(1, usize::from)
            .clamp(1, claims.max(1));
        let next = AtomicUsize::new(0);
        struct Found {
            sites: Vec<(u32, Site)>,
            referenced: Vec<u32>,
            undecoded: Vec<u32>,
            calls: u64,
        }
        let scan = || -> Result<Found> {
            let mut found = Found {
                sites: Vec::new(),
                referenced: Vec::new(),
                undecoded: Vec::new(),
                calls: 0,
            };
            let mut polled = 0u64;
            loop {
                let claim = next.fetch_add(1, Ordering::Relaxed);
                if claim >= claims {
                    return Ok(found);
                }
                for (position, body) in bodies.iter().enumerate().skip(claim * CLAIM).take(CLAIM) {
                    let caller = imported + position as u32;
                    let Ok(mut reader) = body.get_operators_reader() else {
                        found.undecoded.push(caller);
                        continue;
                    };
                    while !reader.eof() {
                        polled += 1;
                        if polled & 4095 == 0 {
                            check_cancelled(cancelled, WHAT)?;
                        }
                        let Ok((op, offset)) = reader.read_with_offset() else {
                            found.undecoded.push(caller);
                            break;
                        };
                        let site = |tail| Site {
                            caller,
                            offset: offset as u32,
                            tail,
                        };
                        match op {
                            Operator::Call { function_index } => {
                                found.calls += 1;
                                found.sites.push((function_index, site(false)));
                            }
                            Operator::ReturnCall { function_index } => {
                                found.calls += 1;
                                found.sites.push((function_index, site(true)));
                            }
                            Operator::CallIndirect { .. }
                            | Operator::ReturnCallIndirect { .. }
                            | Operator::CallRef { .. }
                            | Operator::ReturnCallRef { .. } => found.calls += 1,
                            Operator::RefFunc { function_index } => {
                                found.referenced.push(function_index);
                            }
                            _ => {}
                        }
                    }
                }
            }
        };
        let parts = thread::scope(|scope| {
            let others: Vec<_> = (1..workers).map(|_| scope.spawn(scan)).collect();
            let mut parts = vec![scan()];
            parts.extend(others.into_iter().map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            }));
            parts
        })
        .into_iter()
        .collect::<Result<Vec<Found>>>()?;
        let mut sites = Vec::with_capacity(parts.iter().map(|part| part.sites.len()).sum());
        let mut referenced = Vec::new();
        let mut undecoded = Vec::new();
        let mut calls = 0u64;
        for part in parts {
            sites.extend(part.sites);
            referenced.extend(part.referenced);
            undecoded.extend(part.undecoded);
            calls += part.calls;
        }
        check_cancelled(cancelled, WHAT)?;
        sites.sort_unstable_by_key(|(callee, site)| (*callee, site.caller, site.offset));
        referenced.sort_unstable();
        referenced.dedup();
        undecoded.sort_unstable();
        undecoded.dedup();
        let functions = module.types.function_count() as usize;
        let mut start = vec![0u32; functions + 1];
        for (callee, _) in &sites {
            if let Some(slot) = start.get_mut(*callee as usize + 1) {
                *slot += 1;
            }
        }
        for function in 0..functions {
            start[function + 1] += start[function];
        }
        Ok(Self {
            sites,
            start,
            referenced,
            undecoded,
            calls,
        })
    }

    /// Direct call sites of `callee`, by caller then offset.
    pub fn callers(&self, callee: u32) -> &[(u32, Site)] {
        let Some(&from) = self.start.get(callee as usize) else {
            return &[];
        };
        let to = self.start[callee as usize + 1];
        &self.sites[from as usize..to as usize]
    }

    /// Whether a `ref.func` in some body names `function`.
    pub fn referenced(&self, function: u32) -> bool {
        self.referenced.binary_search(&function).is_ok()
    }

    /// Whether anything besides a direct call can reach `function`: an
    /// export, the start function, an element segment or a `ref.func`.
    pub fn reachable_indirectly(&self, module: &Module<'_>, function: u32) -> bool {
        self.referenced(function)
            || module.exported.contains(&function)
            || module.element_functions.contains(&function)
            || module.start == Some(function)
    }

    /// What the index holds, for a cache bounded by bytes.
    pub fn bytes(&self) -> u64 {
        (self.sites.len() * std::mem::size_of::<(u32, Site)>()
            + (self.start.len() + self.referenced.len() + self.undecoded.len()) * 4) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_direct_and_tail_calls_by_callee_and_names_references() {
        let bytes = wat::parse_str(
            r#"(module
              (import "env" "now" (func $now (result i32)))
              (table 1 funcref)
              (func $a (result i32) (call $now))
              (func $b (result i32) (return_call $a))
              (func $c (result i32) (drop (call $a)) (drop (ref.func $b)) (call $b))
              (elem declare func $b))"#,
        )
        .unwrap();
        let module = Module::read(&bytes).unwrap();
        let index = CallIndex::build(&module, &AtomicBool::new(false)).unwrap();
        let callers = |function: u32| -> Vec<(u32, bool)> {
            index
                .callers(function)
                .iter()
                .map(|(_, site)| (site.caller, site.tail))
                .collect()
        };
        assert_eq!(callers(0), vec![(1, false)]);
        assert_eq!(callers(1), vec![(2, true), (3, false)]);
        assert_eq!(callers(2), vec![(3, false)]);
        assert_eq!(callers(3), Vec::<(u32, bool)>::new());
        assert_eq!(callers(99), Vec::<(u32, bool)>::new());
        assert!(index.referenced(2));
        assert!(!index.referenced(1));
        assert!(index.reachable_indirectly(&module, 2));
        assert!(!index.reachable_indirectly(&module, 1));
        assert_eq!(index.calls, 4);
        assert!(index.undecoded.is_empty());
        assert!(index.bytes() > 0);
    }

    #[test]
    fn a_cancelled_scan_stops_with_499() {
        let bytes = wat::parse_str("(module (func (nop)))").unwrap();
        let module = Module::read(&bytes).unwrap();
        let error = CallIndex::build(&module, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(error.status, 499);
    }
}
