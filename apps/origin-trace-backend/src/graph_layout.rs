//! `POST /api/graph-layout`: node sizes and edges in, top-left node corners
//! and edge waypoints out, computed by the vendored Triskel engine (SESE
//! regions and Sugiyama layering; see `vendor/README.md`).
//!
//! Triskel is third-party C++ fed graphs shaped by captured pages, and this
//! revision can loop forever, crash or overlap nodes on some of them, so it
//! never runs in the server. A request's graphs go to a contained
//! `--graph-layout-worker` process, at most two run at once, and a graph that
//! hangs, crashes or exhausts memory costs only itself: a new worker
//! continues with the graphs after it until the request deadline.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdout},
    sync::Semaphore,
};

pub(crate) const WORKER_FLAG: &str = "--graph-layout-worker";
pub(crate) const WORKER_TEST_VALUE: &str = "graph-layout";
const ENGINE_REVISION: &str = "196ba112eba992c1460af3097c038defcf7a7e45";
const SCHEMA: &str = "graph-layout-v1";
const MAX_GRAPHS: usize = 64;
const MAX_TOTAL_NODES: usize = 8_000;
// Measured Triskel cost on tree-like graphs with some back edges: 1,000 nodes
// 0.6 s, 3,000 nodes 6.6 s, 8,000 nodes 85 s. The per-graph limits keep one
// graph well inside the request deadline.
const MAX_GRAPH_NODES: usize = 2_000;
const MAX_GRAPH_EDGES: usize = 8_000;
const MAX_NODE_SIZE: f64 = 100_000.0;
const DEADLINE: Duration = Duration::from_secs(10);
/// The admitted body is at most 8 MiB; its re-encoding for the worker is
/// bounded by the same counts.
const MAX_WORKER_INPUT: u64 = 64 << 20;
const MAX_REPLY_LINE: u64 = 64 << 20;
/// Resident memory at which the worker exits. Triskel allocates with C++
/// `new`, which the Rust allocator ceiling of the JavaScript workers does not
/// see, so a watchdog thread samples the process peak instead.
const MEMORY_LIMIT: u64 = 2 << 30;
const MEMORY_EXIT: i32 = 75;
const REPLY: &[u8] = b"REBGL1 ";
const INVALID: &str = "The layout worker returned an invalid result";
const SHAPE: &str = "The graph layout body must be {\"graphs\": [{\"nodes\": [[width, height], ...], \"edges\": [[from, to], ...]}]} with integer node indexes";
/// Two layouts at once keep a burst of graph views from taking every core; a
/// third request waits for a slot instead of failing.
static WORKERS: Semaphore = Semaphore::const_new(2);
static MEMORY: AtomicU64 = AtomicU64::new(MEMORY_LIMIT);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    graphs: Vec<Graph>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Graph {
    nodes: Vec<[f64; 2]>,
    edges: Vec<[u64; 2]>,
}

/// A coordinate rounded to 2 decimals; whole values are written as integers
/// to keep the payload small.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
#[serde(transparent)]
struct Coord(f64);

impl Coord {
    fn rounded(value: f64) -> Self {
        let rounded = (value * 100.0).round() / 100.0;
        // Never write -0.
        Self(if rounded == 0.0 { 0.0 } else { rounded })
    }
}

impl Serialize for Coord {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if self.0.fract() == 0.0 && self.0.abs() < 1e15 {
            serializer.serialize_i64(self.0 as i64)
        } else {
            serializer.serialize_f64(self.0)
        }
    }
}

/// One graph's result, in request order. The worker writes `LaidOut` or
/// `Failed`; the server assigns the others.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    LaidOut {
        nodes: Vec<[Coord; 2]>,
        edges: Vec<Vec<Coord>>,
        width: Coord,
        height: Coord,
        elapsed_ms: u64,
    },
    TooLarge {
        reason: String,
    },
    Failed {
        reason: String,
    },
    Timeout {
        reason: String,
    },
}

#[derive(Serialize)]
struct Response<'a> {
    schema: &'static str,
    engine: Engine,
    graphs: &'a [Outcome],
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct Engine {
    name: &'static str,
    revision: &'static str,
}

/// `POST /api/graph-layout`. `bytes` has already passed the shared body
/// admission (one Content-Length within `x-max-body-bytes`, body deadline).
pub(crate) async fn route(bytes: Vec<u8>) -> Result<Vec<u8>> {
    let started = Instant::now();
    let graphs = tokio::task::spawn_blocking(move || parse(&bytes))
        .await
        .map_err(|_| Error::new(500, "Graph layout validation failed"))??;
    let graphs = lay_out_all(graphs, DEADLINE).await;
    let elapsed_ms = millis(started.elapsed());
    tokio::task::spawn_blocking(move || {
        serde_json::to_vec(&Response {
            schema: SCHEMA,
            engine: Engine {
                name: "triskel",
                revision: ENGINE_REVISION,
            },
            graphs: &graphs,
            elapsed_ms,
        })
    })
    .await
    .map_err(|_| Error::new(500, "Graph layout serialization failed"))?
    .map_err(|_| Error::new(500, "Graph layout serialization failed"))
}

fn parse(bytes: &[u8]) -> Result<Vec<Graph>> {
    let request: Request = serde_json::from_slice(bytes).map_err(|error| {
        Error::bad(if error.is_data() {
            SHAPE
        } else {
            "The graph layout body is malformed JSON"
        })
    })?;
    if request.graphs.len() > MAX_GRAPHS {
        return Err(Error::bad(format!(
            "A graph layout request holds at most {MAX_GRAPHS} graphs"
        )));
    }
    let total = request
        .graphs
        .iter()
        .map(|graph| graph.nodes.len())
        .sum::<usize>();
    if total > MAX_TOTAL_NODES {
        return Err(Error::bad(format!(
            "A graph layout request holds at most {MAX_TOTAL_NODES} nodes in all"
        )));
    }
    let size = |value: f64| value.is_finite() && value > 0.0 && value <= MAX_NODE_SIZE;
    for (index, graph) in request.graphs.iter().enumerate() {
        if let Some(node) = graph.nodes.iter().position(|&[w, h]| !size(w) || !size(h)) {
            return Err(Error::bad(format!(
                "Graph {index} node {node} needs a width and height above 0 and at most {MAX_NODE_SIZE}"
            )));
        }
        let count = graph.nodes.len() as u64;
        if let Some(edge) = graph
            .edges
            .iter()
            .position(|&[from, to]| from >= count || to >= count)
        {
            return Err(Error::bad(format!(
                "Graph {index} edge {edge} names a node outside the graph"
            )));
        }
    }
    Ok(request.graphs)
}

async fn lay_out_all(graphs: Vec<Graph>, deadline: Duration) -> Vec<Outcome> {
    let mut outcomes = graphs.iter().map(admit).collect::<Vec<_>>();
    let pending = (0..graphs.len())
        .filter(|&index| outcomes[index].is_none())
        .collect::<Vec<_>>();
    if !pending.is_empty() {
        let replies = match encode(graphs, pending.clone()).await {
            Some(jobs) => in_worker(&jobs, deadline).await,
            None => vec![
                Outcome::Failed {
                    reason: "The layout request could not be encoded".to_owned(),
                };
                pending.len()
            ],
        };
        for (index, reply) in pending.into_iter().zip(replies) {
            outcomes[index] = Some(reply);
        }
    }
    outcomes
        .into_iter()
        .map(|outcome| outcome.expect("every graph has an outcome"))
        .collect()
}

/// The result decided without Triskel, if any.
fn admit(graph: &Graph) -> Option<Outcome> {
    if graph.nodes.len() > MAX_GRAPH_NODES || graph.edges.len() > MAX_GRAPH_EDGES {
        return Some(Outcome::TooLarge {
            reason: format!(
                "This graph has {} nodes and {} edges; one graph is laid out with at most {MAX_GRAPH_NODES} nodes and {MAX_GRAPH_EDGES} edges",
                graph.nodes.len(),
                graph.edges.len()
            ),
        });
    }
    graph.nodes.is_empty().then(empty)
}

fn empty() -> Outcome {
    Outcome::LaidOut {
        nodes: Vec::new(),
        edges: Vec::new(),
        width: Coord(0.0),
        height: Coord(0.0),
        elapsed_ms: 0,
    }
}

/// One graph as the worker reads it, with the counts its result must match.
struct Job {
    nodes: usize,
    edges: usize,
    json: Vec<u8>,
}

impl Job {
    /// Measured Triskel time grows with the square of the node count (about 2
    /// µs times n squared on a loaded machine); four times that, and at least
    /// 1 s, separates a slow layout from one that will never finish.
    fn budget(&self) -> Duration {
        let nodes = self.nodes as u64;
        Duration::from_secs(1) + Duration::from_nanos(8_000 * nodes * nodes)
    }
}

/// The pending graphs encoded for the worker, off the async runtime: a request
/// holds up to 8 MiB of numbers.
async fn encode(graphs: Vec<Graph>, pending: Vec<usize>) -> Option<Vec<Job>> {
    tokio::task::spawn_blocking(move || {
        pending
            .iter()
            .map(|&index| {
                let graph = &graphs[index];
                Some(Job {
                    nodes: graph.nodes.len(),
                    edges: graph.edges.len(),
                    json: serde_json::to_vec(graph).ok()?,
                })
            })
            .collect()
    })
    .await
    .ok()
    .flatten()
}

/// Why one worker stopped before every graph it was given had a result.
enum Stop {
    Complete,
    /// The request deadline passed: no graph left gets a layout.
    RequestDeadline,
    /// The graph in progress overran its own budget.
    Budget(Duration),
    /// The graph in progress crashed the worker or produced an invalid result.
    Graph(String),
    /// The worker failed before or apart from any one graph.
    Abandon(String),
}

/// Lays out `jobs` in order, one worker at a time. Triskel can loop forever
/// or crash on some graphs (see `vendor/README.md`), so each graph has its own
/// budget inside the request deadline: a graph that overruns it, crashes the
/// worker or exhausts its memory gets `timeout` or `failed`, and a new worker
/// continues with the graphs after it.
async fn in_worker(jobs: &[Job], deadline: Duration) -> Vec<Outcome> {
    let mut outcomes = Vec::with_capacity(jobs.len());
    let _slot = WORKERS.acquire().await;
    let end = tokio::time::Instant::now() + deadline;
    while outcomes.len() < jobs.len() {
        let rest = &jobs[outcomes.len()..];
        let missing = match exchange(rest, end, &mut outcomes).await {
            Stop::Complete => continue,
            Stop::Budget(budget) => {
                outcomes.push(Outcome::Timeout {
                    reason: format!(
                        "The layout did not finish within this graph's {:.1} s budget",
                        budget.as_secs_f64()
                    ),
                });
                continue;
            }
            Stop::Graph(reason) => {
                outcomes.push(Outcome::Failed { reason });
                continue;
            }
            Stop::RequestDeadline => Outcome::Timeout {
                reason: format!(
                    "The layout did not finish within the {} s request deadline",
                    deadline.as_secs_f64()
                ),
            },
            Stop::Abandon(reason) => Outcome::Failed { reason },
        };
        outcomes.resize(jobs.len(), missing);
    }
    outcomes
}

/// A contained worker in its own process group, which is killed with it.
fn start_worker() -> Option<(Child, Option<crate::worker::ProcessGroup>)> {
    let mut command =
        crate::vm::dispatch_shape::javascript::worker_command_for(WORKER_FLAG, WORKER_TEST_VALUE)
            .ok()?;
    #[cfg(test)]
    if let Some(fault) = tests::FAULT.get() {
        command.env(tests::FAULT_VARIABLE, fault);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let child = command.spawn().ok()?;
    let group = child.id().map(crate::worker::ProcessGroup);
    Some((child, group))
}

/// One worker for `jobs`; each result that arrives is pushed to `outcomes`.
async fn exchange(jobs: &[Job], end: tokio::time::Instant, outcomes: &mut Vec<Outcome>) -> Stop {
    let not_started = || Stop::Abandon("The layout worker could not start".to_owned());
    // The group guard kills the worker's whole process group on every return path.
    let Some((mut child, _group)) = start_worker() else {
        return not_started();
    };
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return not_started();
    };
    let mut started = tokio::time::Instant::now();
    // The worker reads its whole request, one JSON array of the graphs,
    // before it replies. One that exits early breaks the pipe, and its exit
    // status says why.
    let written = tokio::time::timeout_at(end, async move {
        for (index, job) in jobs.iter().enumerate() {
            stdin
                .write_all(if index == 0 { b"[" } else { b"," })
                .await?;
            stdin.write_all(&job.json).await?;
        }
        stdin.write_all(b"]").await
    });
    if written.await.is_err() {
        return Stop::RequestDeadline;
    }
    let mut reader = BufReader::new(stdout);
    for job in jobs {
        let budget = job.budget();
        let until = end.min(started + budget);
        let reply = async {
            match next_reply(&mut reader).await? {
                Some(line) => parse_reply(line, job).await.map(Some),
                None => Ok(None),
            }
        };
        let reply = match tokio::time::timeout_at(until, reply).await {
            Err(_) if until < end => return Stop::Budget(budget),
            Err(_) => return Stop::RequestDeadline,
            Ok(reply) => reply,
        };
        match reply {
            Ok(Some(outcome)) => outcomes.push(outcome),
            Ok(None) => {
                return match tokio::time::timeout_at(end, child.wait()).await {
                    Err(_) => Stop::RequestDeadline,
                    Ok(status) => stopped(status),
                };
            }
            Err(reason) => return Stop::Graph(reason.to_owned()),
        }
        started = tokio::time::Instant::now();
    }
    Stop::Complete
}

/// The next reply line, prefix and newline included, or `None` at the end of
/// the worker's output.
async fn next_reply(
    reader: &mut BufReader<ChildStdout>,
) -> std::result::Result<Option<Vec<u8>>, &'static str> {
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut *reader)
            .take(MAX_REPLY_LINE + 1)
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| INVALID)?;
        if line.last() != Some(&b'\n') {
            // End of output, possibly mid-line: the exit status says why.
            return if read as u64 > MAX_REPLY_LINE {
                Err(INVALID)
            } else {
                Ok(None)
            };
        }
        if line.starts_with(REPLY) {
            return Ok(Some(line));
        }
        // libtest prints this banner before a re-executed test worker runs.
        let text = &line[..line.len() - 1];
        if !(cfg!(test) && (text.is_empty() || text == b"running 1 test")) {
            return Err(INVALID);
        }
    }
}

/// Parses and checks one reply line off the async runtime: a reply runs to
/// tens of MiB of coordinates.
async fn parse_reply(line: Vec<u8>, job: &Job) -> std::result::Result<Outcome, &'static str> {
    let (nodes, edges) = (job.nodes, job.edges);
    tokio::task::spawn_blocking(move || {
        let json = &line[REPLY.len()..line.len() - 1];
        let outcome = serde_json::from_slice(json).map_err(|_| INVALID)?;
        checked(outcome, nodes, edges)
    })
    .await
    .map_err(|_| INVALID)?
}

/// The server trusts the worker's code but not what Triskel computed.
fn checked(
    outcome: Outcome,
    node_count: usize,
    edge_count: usize,
) -> std::result::Result<Outcome, &'static str> {
    match &outcome {
        Outcome::LaidOut {
            nodes,
            edges,
            width,
            height,
            ..
        } => {
            let valid = nodes.len() == node_count
                && edges.len() == edge_count
                && edges.iter().all(|edge| edge.len() % 2 == 0)
                && nodes
                    .iter()
                    .flatten()
                    .chain(edges.iter().flatten())
                    .chain([width, height])
                    .all(|value| value.0.is_finite() && value.0 >= 0.0);
            if valid { Ok(outcome) } else { Err(INVALID) }
        }
        Outcome::Failed { .. } => Ok(outcome),
        Outcome::TooLarge { .. } | Outcome::Timeout { .. } => Err(INVALID),
    }
}

/// A signal or the memory limit belongs to the graph in progress; any other
/// exit is the worker's own failure.
fn stopped(status: std::io::Result<std::process::ExitStatus>) -> Stop {
    let Ok(status) = status else {
        return Stop::Abandon("The layout worker could not be observed".to_owned());
    };
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return Stop::Graph(format!(
            "The layout worker stopped on signal {signal} while laying out this graph"
        ));
    }
    match status.code() {
        Some(MEMORY_EXIT) => Stop::Graph(format!(
            "The layout worker exceeded its {} GiB memory limit on this graph",
            MEMORY_LIMIT >> 30
        )),
        Some(0) => Stop::Abandon("The layout worker ended without a result".to_owned()),
        Some(code) => Stop::Abandon(format!("The layout worker exited with status {code}")),
        None => Stop::Abandon("The layout worker stopped".to_owned()),
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

/// Entry for the contained worker process: one request on stdin, then one
/// reply line per graph, flushed as each layout finishes.
pub(crate) fn worker_main() -> i32 {
    use std::os::fd::FromRawFd;
    if crate::js_worker_alloc::contain().is_err() {
        return 70;
    }
    // Triskel's debug paths print to stdout. Keep the reply on a private
    // descriptor and send stray output to stderr, which the server discards.
    // SAFETY: dup and dup2 only duplicate descriptors this process owns.
    let reply = unsafe { libc::dup(libc::STDOUT_FILENO) };
    if reply < 0 || unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } < 0 {
        return 71;
    }
    // SAFETY: reply is a fresh descriptor that nothing else owns.
    let mut reply = std::io::BufWriter::new(unsafe { std::fs::File::from_raw_fd(reply) });
    if watch_memory().is_err() {
        return 71;
    }
    let mut input = Vec::new();
    if std::io::stdin()
        .lock()
        .take(MAX_WORKER_INPUT)
        .read_to_end(&mut input)
        .is_err()
    {
        return 72;
    }
    let Ok(graphs) = serde_json::from_slice::<Vec<Graph>>(&input) else {
        return 72;
    };
    drop(input);
    for graph in &graphs {
        #[cfg(test)]
        tests::fault();
        let Ok(json) = serde_json::to_vec(&lay_out(graph)) else {
            return 73;
        };
        let written = reply
            .write_all(REPLY)
            .and_then(|()| reply.write_all(&json))
            .and_then(|()| reply.write_all(b"\n"))
            .and_then(|()| reply.flush());
        if written.is_err() {
            return 74;
        }
    }
    0
}

fn watch_memory() -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("memory watchdog".to_owned())
        .spawn(|| {
            loop {
                std::thread::sleep(Duration::from_millis(20));
                if resident_peak() > MEMORY.load(Relaxed) {
                    // SAFETY: _exit ends the process without unwinding or locks.
                    unsafe { libc::_exit(MEMORY_EXIT) };
                }
            }
        })
        .map(drop)
}

fn resident_peak() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the zeroed struct it is given.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return 0;
    }
    // SAFETY: zeroed and then filled by the kernel.
    let peak = unsafe { usage.assume_init() }.ru_maxrss.max(0) as u64;
    // macOS reports bytes, Linux kibibytes.
    if cfg!(target_os = "macos") {
        peak
    } else {
        peak.saturating_mul(1024)
    }
}

/// Lays out each weakly connected part on its own and packs the parts in
/// rows, largest first. Under one virtual root Triskel lays many separate
/// parts out side by side and in sparse graphs places some of their nodes on
/// top of each other; one part at a time it does so far less often, and it is
/// faster, since its cost grows faster than the node count.
fn lay_out(graph: &Graph) -> Outcome {
    let started = Instant::now();
    if graph.nodes.is_empty() {
        return empty();
    }
    if graph.nodes.len() > MAX_GRAPH_NODES || graph.edges.len() > MAX_GRAPH_EDGES {
        return Outcome::Failed {
            reason: "The graph exceeds the layout limits".to_owned(),
        };
    }
    let parts = parts(graph);
    let mut local = vec![0usize; graph.nodes.len()];
    let mut drawings = Vec::with_capacity(parts.len());
    for (nodes, edges) in &parts {
        for (index, &node) in nodes.iter().enumerate() {
            local[node] = index;
        }
        let part = Graph {
            nodes: nodes.iter().map(|&node| graph.nodes[node]).collect(),
            edges: edges
                .iter()
                .map(|&edge| {
                    let [from, to] = graph.edges[edge];
                    [local[from as usize] as u64, local[to as usize] as u64]
                })
                .collect(),
        };
        match draw(&part) {
            Ok(drawing) => drawings.push(drawing),
            Err(reason) => return Outcome::Failed { reason },
        }
    }
    let offsets = pack(&drawings);
    let mut corners = vec![[Coord(0.0); 2]; graph.nodes.len()];
    let mut routes = vec![Vec::new(); graph.edges.len()];
    let (mut width, mut height) = (0.0f64, 0.0f64);
    for (((nodes, edges), drawing), &(dx, dy)) in parts.iter().zip(&drawings).zip(&offsets) {
        for (&node, &(x, y)) in nodes.iter().zip(&drawing.nodes) {
            corners[node] = [Coord::rounded(x + dx), Coord::rounded(y + dy)];
        }
        for (&edge, points) in edges.iter().zip(&drawing.edges) {
            routes[edge] = points
                .iter()
                .flat_map(|&(x, y)| [Coord::rounded(x + dx), Coord::rounded(y + dy)])
                .collect();
        }
        (width, height) = (
            width.max(dx + drawing.width),
            height.max(dy + drawing.height),
        );
    }
    let outcome = Outcome::LaidOut {
        nodes: corners,
        edges: routes,
        width: Coord::rounded(width),
        height: Coord::rounded(height),
        elapsed_ms: millis(started.elapsed()),
    };
    match defect(graph, &outcome) {
        Some(reason) => Outcome::Failed { reason },
        None => outcome,
    }
}

/// The weakly connected parts of a graph: their nodes in index order and the
/// edges between them in input order, largest part first, then by first node.
fn parts(graph: &Graph) -> Vec<(Vec<usize>, Vec<usize>)> {
    fn find(parent: &mut [usize], mut node: usize) -> usize {
        while parent[node] != node {
            parent[node] = parent[parent[node]];
            node = parent[node];
        }
        node
    }
    let mut parent = (0..graph.nodes.len()).collect::<Vec<_>>();
    for &[from, to] in &graph.edges {
        let (a, b) = (
            find(&mut parent, from as usize),
            find(&mut parent, to as usize),
        );
        parent[a.max(b)] = a.min(b);
    }
    let mut part_of = vec![usize::MAX; graph.nodes.len()];
    let mut parts = Vec::<(Vec<usize>, Vec<usize>)>::new();
    for node in 0..graph.nodes.len() {
        let root = find(&mut parent, node);
        if part_of[root] == usize::MAX {
            part_of[root] = parts.len();
            parts.push((Vec::new(), Vec::new()));
        }
        parts[part_of[root]].0.push(node);
    }
    for (edge, &[from, _]) in graph.edges.iter().enumerate() {
        let root = find(&mut parent, from as usize);
        parts[part_of[root]].1.push(edge);
    }
    // Stable, so equal sizes keep the order of their first nodes.
    parts.sort_by_key(|(nodes, _)| std::cmp::Reverse(nodes.len()));
    parts
}

/// Space between packed parts: Triskel's own gutter between nodes.
const PART_GAP: f64 = 50.0;

/// Top-left offsets that put the parts in rows about 1.6 times as wide as
/// they are tall, never narrower than the widest part.
fn pack(drawings: &[Drawing]) -> Vec<(f64, f64)> {
    let widest = drawings
        .iter()
        .map(|drawing| drawing.width)
        .fold(0.0, f64::max);
    let area = drawings
        .iter()
        .map(|drawing| (drawing.width + PART_GAP) * (drawing.height + PART_GAP))
        .sum::<f64>();
    let limit = widest.max((area * 1.6).sqrt());
    let (mut x, mut y, mut row) = (0.0f64, 0.0f64, 0.0f64);
    drawings
        .iter()
        .map(|drawing| {
            if x > 0.0 && x + drawing.width > limit {
                (x, y, row) = (0.0, y + row + PART_GAP, 0.0);
            }
            let at = (x, y);
            x += drawing.width + PART_GAP;
            row = row.max(drawing.height);
            at
        })
        .collect()
}

/// One connected part laid out, before rounding, with its smallest x and y
/// at 0.
struct Drawing {
    nodes: Vec<(f64, f64)>,
    edges: Vec<Vec<(f64, f64)>>,
    width: f64,
    height: f64,
}

fn draw(part: &Graph) -> std::result::Result<Drawing, String> {
    if part.edges.is_empty() {
        // A part without edges is one node; Triskel adds nothing to it.
        let [width, height] = part.nodes[0];
        return Ok(Drawing {
            nodes: vec![(0.0, 0.0)],
            edges: Vec::new(),
            width,
            height,
        });
    }
    let (sizes, endpoints) = rooted(part);
    let raw = triskel(&sizes, &endpoints)?;
    place(part, &raw).ok_or_else(|| "Triskel returned a non-finite or incomplete layout".to_owned())
}

/// How far a rounded coordinate may sit past a box it should touch.
const SLACK: f64 = 1.0;

/// Triskel can place nodes on top of each other, mostly in graphs without
/// branch and loop structure. A drawing the UI cannot read is reported as
/// failed, so the caller can lay that graph out another way.
fn defect(graph: &Graph, outcome: &Outcome) -> Option<String> {
    let Outcome::LaidOut { nodes, edges, .. } = outcome else {
        return None;
    };
    let span = |node: usize| {
        let ([x, y], [width, height]) = (nodes[node], graph.nodes[node]);
        (x.0, y.0, x.0 + width, y.0 + height)
    };
    // Sorted by left edge, each node is compared only with the nodes that
    // start before it ends.
    let mut order = (0..nodes.len()).collect::<Vec<_>>();
    order.sort_by(|&a, &b| span(a).0.total_cmp(&span(b).0));
    for (index, &a) in order.iter().enumerate() {
        let (_, top, right, bottom) = span(a);
        for &b in &order[index + 1..] {
            let (left, top_b, _, bottom_b) = span(b);
            if left >= right - 0.02 {
                break;
            }
            if top < bottom_b - 0.02 && top_b < bottom - 0.02 {
                return Some(format!(
                    "Triskel placed nodes {} and {} on top of each other",
                    a.min(b),
                    a.max(b)
                ));
            }
        }
    }
    let touches = |x: f64, y: f64, node: usize| {
        let (left, top, right, bottom) = span(node);
        x >= left - SLACK && x <= right + SLACK && y >= top - SLACK && y <= bottom + SLACK
    };
    for (index, (points, &[from, to])) in edges.iter().zip(&graph.edges).enumerate() {
        let ends = points.len() >= 4
            && touches(points[0].0, points[1].0, from as usize)
            && touches(
                points[points.len() - 2].0,
                points[points.len() - 1].0,
                to as usize,
            );
        if !ends {
            return Some(format!("Triskel routed edge {index} away from its nodes"));
        }
    }
    None
}

/// Triskel's SESE analysis needs a graph it can close into one cycle: a
/// root, node 0, that reaches every node, and a path from every node to a
/// node with no out-edge, which it links back to the root. Without either it
/// throws "EMPTY BL". So node 0 is a virtual root of size 0 with an edge to
/// every node no other node enters, then to one node of each part still
/// unreached (a cycle with no entry). When some part reaches no node without
/// out-edges (a cycle with no exit, a lone self loop), one more virtual node
/// of size 0 after the real ones takes an edge from the deepest node of each
/// such part. Input node `i` is Triskel node `i + 1`; input edge `j` keeps
/// index `j`, and the virtual edges follow.
fn rooted(graph: &Graph) -> (Vec<f32>, Vec<u32>) {
    let count = graph.nodes.len();
    let mut sizes = Vec::with_capacity(2 * (count + 2));
    sizes.extend([0.0, 0.0]);
    for &[width, height] in &graph.nodes {
        sizes.extend([width as f32, height as f32]);
    }
    let mut endpoints = Vec::with_capacity(2 * (graph.edges.len() + 2 * count));
    let mut successors = vec![Vec::new(); count];
    let mut predecessors = vec![Vec::new(); count];
    let mut entered = vec![false; count];
    for &[from, to] in &graph.edges {
        let (from, to) = (from as usize, to as usize);
        endpoints.extend([from as u32 + 1, to as u32 + 1]);
        successors[from].push(to);
        predecessors[to].push(from);
        entered[to] |= from != to;
    }
    // Marks every node `links` leads to from `start`, in discovery order.
    let walk = |links: &[Vec<usize>], start: usize, seen: &mut [bool], order: &mut Vec<usize>| {
        seen[start] = true;
        order.push(start);
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            for &next in &links[node] {
                if !seen[next] {
                    seen[next] = true;
                    order.push(next);
                    stack.push(next);
                }
            }
        }
    };
    let mut reached = vec![false; count];
    let mut order = Vec::with_capacity(count);
    let starts = (0..count).filter(|&node| !entered[node]).chain(0..count);
    for start in starts {
        if !reached[start] {
            endpoints.extend([0, start as u32 + 1]);
            walk(&successors, start, &mut reached, &mut order);
        }
    }
    // Triskel links only nodes without any out-edge, self loops included, to
    // its own exit.
    let mut exits = vec![false; count];
    let mut ignored = Vec::new();
    for node in 0..count {
        if successors[node].is_empty() && !exits[node] {
            walk(&predecessors, node, &mut exits, &mut ignored);
        }
    }
    let sink = count as u32 + 1;
    for &node in order.iter().rev() {
        if !exits[node] {
            endpoints.extend([node as u32 + 1, sink]);
            walk(&predecessors, node, &mut exits, &mut ignored);
        }
    }
    if endpoints
        .as_chunks::<2>()
        .0
        .iter()
        .any(|pair| pair[1] == sink)
    {
        sizes.extend([0.0, 0.0]);
    }
    (sizes, endpoints)
}

#[repr(C)]
struct View {
    nodes: *const f32,
    node_count: usize,
    edge_offsets: *const usize,
    edge_count: usize,
    points: *const f32,
    point_count: usize,
    error: *const std::ffi::c_char,
}

// cpp/triskel_bridge.cpp, compiled by build.rs.
unsafe extern "C" {
    fn reb_graph_layout(
        node_count: usize,
        sizes: *const f32,
        edge_count: usize,
        endpoints: *const u32,
        view: *mut View,
    ) -> *mut std::ffi::c_void;
    fn reb_graph_layout_free(layout: *mut std::ffi::c_void);
}

/// Triskel's raw result for the rooted graph: x, y per node; edge `i` is
/// `points[2 * offsets[i]..2 * offsets[i + 1]]`.
struct Raw {
    nodes: Vec<f32>,
    offsets: Vec<usize>,
    points: Vec<f32>,
}

fn triskel(sizes: &[f32], endpoints: &[u32]) -> std::result::Result<Raw, String> {
    // SAFETY: an empty vector's pointer may be null; a zero-length slice
    // needs a non-null pointer, so only nonempty views are dereferenced.
    unsafe fn slice<'a, T>(pointer: *const T, length: usize) -> &'a [T] {
        if length == 0 || pointer.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(pointer, length) }
        }
    }
    let (node_count, edge_count) = (sizes.len() / 2, endpoints.len() / 2);
    let mut view = View {
        nodes: std::ptr::null(),
        node_count: 0,
        edge_offsets: std::ptr::null(),
        edge_count: 0,
        points: std::ptr::null(),
        point_count: 0,
        error: std::ptr::null(),
    };
    // SAFETY: sizes holds node_count pairs and endpoints edge_count pairs of
    // indexes below node_count; the bridge catches every C++ exception.
    let handle = unsafe {
        reb_graph_layout(
            node_count,
            sizes.as_ptr(),
            edge_count,
            endpoints.as_ptr(),
            &mut view,
        )
    };
    if handle.is_null() {
        return Err("Triskel could not allocate its result".to_owned());
    }
    // SAFETY: the view points into the live handle until it is freed below.
    let result = unsafe {
        if !view.error.is_null() {
            let reason = std::ffi::CStr::from_ptr(view.error).to_string_lossy();
            let reason = reason
                .chars()
                .filter(|character| character.is_ascii_graphic() || *character == ' ')
                .take(200)
                .collect::<String>();
            Err(format!("Triskel could not lay out this graph: {reason}"))
        } else if view.node_count != node_count || view.edge_count != edge_count {
            Err("Triskel returned an incomplete layout".to_owned())
        } else {
            let offsets = slice(view.edge_offsets, edge_count + 1).to_vec();
            let monotonic = offsets.first() == Some(&0)
                && offsets.windows(2).all(|pair| pair[0] <= pair[1])
                && offsets.last() == Some(&view.point_count);
            if monotonic {
                Ok(Raw {
                    nodes: slice(view.nodes, 2 * node_count).to_vec(),
                    offsets,
                    points: slice(view.points, 2 * view.point_count).to_vec(),
                })
            } else {
                Err("Triskel returned an inconsistent layout".to_owned())
            }
        }
    };
    // SAFETY: handle came from reb_graph_layout and is freed once.
    unsafe { reb_graph_layout_free(handle) };
    result
}

/// Drops the virtual nodes and their edges, then moves the drawing so its
/// smallest x and y are 0 (Triskel puts the first node at a negative y).
/// The extent covers the real nodes and the waypoints of the input edges.
/// Triskel returns some edges it reversed to break a cycle target first, so
/// a list whose ends sit on the wrong nodes is turned around: every edge runs
/// from its source to its target.
fn place(graph: &Graph, raw: &Raw) -> Option<Drawing> {
    let corner = |node: usize| {
        (
            f64::from(raw.nodes[2 * (node + 1)]),
            f64::from(raw.nodes[2 * (node + 1) + 1]),
        )
    };
    let points = |edge: usize| &raw.points[2 * raw.offsets[edge]..2 * raw.offsets[edge + 1]];
    let (mut low_x, mut low_y) = (f64::INFINITY, f64::INFINITY);
    let (mut high_x, mut high_y) = (f64::NEG_INFINITY, f64::NEG_INFINITY);
    for (node, &[width, height]) in graph.nodes.iter().enumerate() {
        let (x, y) = corner(node);
        if !x.is_finite() || !y.is_finite() {
            return None;
        }
        (low_x, low_y) = (low_x.min(x), low_y.min(y));
        (high_x, high_y) = (high_x.max(x + width), high_y.max(y + height));
    }
    for edge in 0..graph.edges.len() {
        for &[x, y] in points(edge).as_chunks::<2>().0 {
            let (x, y) = (f64::from(x), f64::from(y));
            if !x.is_finite() || !y.is_finite() {
                return None;
            }
            (low_x, low_y) = (low_x.min(x), low_y.min(y));
            (high_x, high_y) = (high_x.max(x), high_y.max(y));
        }
    }
    // Manhattan distance from a point to a node's box, 0 on or inside it.
    let away = |point: &[f32; 2], node: usize| {
        let ((x, y), [width, height]) = (corner(node), graph.nodes[node]);
        let (px, py) = (f64::from(point[0]), f64::from(point[1]));
        (x - px).max(px - x - width).max(0.0) + (y - py).max(py - y - height).max(0.0)
    };
    let edges = graph
        .edges
        .iter()
        .enumerate()
        .map(|(edge, &[from, to])| {
            let (from, to) = (from as usize, to as usize);
            let mut pairs = points(edge).as_chunks::<2>().0.to_vec();
            if let (Some(first), Some(last)) = (pairs.first(), pairs.last())
                && away(first, to) + away(last, from) < away(first, from) + away(last, to)
            {
                pairs.reverse();
            }
            pairs
                .into_iter()
                .map(|point| (f64::from(point[0]) - low_x, f64::from(point[1]) - low_y))
                .collect()
        })
        .collect();
    Some(Drawing {
        nodes: (0..graph.nodes.len())
            .map(|node| {
                let (x, y) = corner(node);
                (x - low_x, y - low_y)
            })
            .collect(),
        edges,
        width: high_x - low_x,
        height: high_y - low_y,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) const FAULT_VARIABLE: &str = "REB_GRAPH_LAYOUT_TEST_FAULT";

    thread_local! {
        /// The fault the workers a test starts on this thread inject.
        pub(super) static FAULT: std::cell::Cell<Option<&'static str>> =
            const { std::cell::Cell::new(None) };
    }

    /// Test-only faults in the re-executed worker, after the first graph's
    /// reply so a test sees both a kept result and the missing ones.
    pub(super) fn fault() {
        static GRAPHS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        if GRAPHS.fetch_add(1, Relaxed) == 0 {
            return;
        }
        match std::env::var(FAULT_VARIABLE).as_deref() {
            Ok("hang") => std::thread::sleep(Duration::from_secs(600)),
            // SAFETY: abort ends the worker with SIGABRT, as a C++ crash would.
            Ok("crash") => unsafe { libc::abort() },
            Ok("memory") => {
                MEMORY.store(0, Relaxed);
                std::thread::sleep(Duration::from_secs(600));
            }
            _ => (),
        }
    }

    fn graph(nodes: &[[f64; 2]], edges: &[[u64; 2]]) -> Graph {
        Graph {
            nodes: nodes.to_vec(),
            edges: edges.to_vec(),
        }
    }

    fn sized(count: usize) -> Vec<[f64; 2]> {
        (0..count)
            .map(|node| {
                [
                    80.0 + (node % 5) as f64 * 30.0,
                    24.0 + (node % 3) as f64 * 16.0,
                ]
            })
            .collect()
    }

    /// A tree with some back and cross edges, the shape of the measured graphs.
    fn tree(count: usize) -> Graph {
        let mut edges = (1..count as u64)
            .map(|node| [(node - 1) / 2, node])
            .collect::<Vec<_>>();
        edges.extend((7..count as u64).step_by(7).map(|node| [node, node / 3]));
        Graph {
            nodes: sized(count),
            edges,
        }
    }

    fn touches(point: (f64, f64), corner: [Coord; 2], size: [f64; 2]) -> bool {
        point.0 >= corner[0].0 - SLACK
            && point.0 <= corner[0].0 + size[0] + SLACK
            && point.1 >= corner[1].0 - SLACK
            && point.1 <= corner[1].0 + size[1] + SLACK
    }

    /// Every invariant the UI relies on.
    fn assert_sound(graph: &Graph, outcome: &Outcome, label: &str) {
        let Outcome::LaidOut {
            nodes,
            edges,
            width,
            height,
            ..
        } = outcome
        else {
            panic!("{label}: {outcome:?}");
        };
        assert_eq!(
            nodes.len(),
            graph.nodes.len(),
            "{label}: the root never shows"
        );
        assert_eq!(edges.len(), graph.edges.len(), "{label}: nor do its edges");
        for value in nodes.iter().flatten().chain(edges.iter().flatten()) {
            assert!(value.0.is_finite() && value.0 >= 0.0, "{label}: {value:?}");
            assert_eq!(value.0, Coord::rounded(value.0).0, "{label}: 2 decimals");
        }
        for (node, (corner, size)) in nodes.iter().zip(&graph.nodes).enumerate() {
            assert!(
                corner[0].0 + size[0] <= width.0 + 0.02 && corner[1].0 + size[1] <= height.0 + 0.02,
                "{label}: node {node} lies outside {width:?} x {height:?}"
            );
            for (other, (corner2, size2)) in
                nodes.iter().zip(&graph.nodes).enumerate().skip(node + 1)
            {
                let apart = corner[0].0 + size[0] <= corner2[0].0 + 0.02
                    || corner2[0].0 + size2[0] <= corner[0].0 + 0.02
                    || corner[1].0 + size[1] <= corner2[1].0 + 0.02
                    || corner2[1].0 + size2[1] <= corner[1].0 + 0.02;
                assert!(apart, "{label}: nodes {node} and {other} overlap");
            }
        }
        let min_x = nodes
            .iter()
            .map(|corner| corner[0].0)
            .fold(f64::INFINITY, f64::min);
        let min_y = nodes
            .iter()
            .map(|corner| corner[1].0)
            .fold(f64::INFINITY, f64::min);
        assert!(min_x >= 0.0 && min_y >= 0.0, "{label}");
        for (edge, (points, &[from, to])) in edges.iter().zip(&graph.edges).enumerate() {
            assert!(
                points.len() >= 4 && points.len() % 2 == 0,
                "{label}: edge {edge} {points:?}"
            );
            let first = (points[0].0, points[1].0);
            let last = (points[points.len() - 2].0, points[points.len() - 1].0);
            let (from, to) = (from as usize, to as usize);
            assert!(
                touches(first, nodes[from], graph.nodes[from]),
                "{label}: edge {edge} starts at {first:?}, away from node {from} at {:?}",
                nodes[from]
            );
            assert!(
                touches(last, nodes[to], graph.nodes[to]),
                "{label}: edge {edge} ends at {last:?}, away from node {to} at {:?}",
                nodes[to]
            );
        }
    }

    #[tokio::test]
    async fn shapes_lay_out_without_overlap_or_the_virtual_root() {
        let shapes = [
            (
                "diamond",
                graph(&sized(4), &[[0, 1], [0, 2], [1, 3], [2, 3]]),
            ),
            ("two roots", graph(&sized(3), &[[0, 2], [1, 2]])),
            (
                "cycle with no entry",
                graph(&sized(3), &[[0, 1], [1, 2], [2, 0]]),
            ),
            ("self loop", graph(&sized(2), &[[0, 1], [1, 1]])),
            ("lone self loop", graph(&sized(1), &[[0, 0]])),
            (
                "duplicate edges",
                graph(&sized(3), &[[0, 1], [0, 1], [1, 2], [1, 2]]),
            ),
            (
                "two components",
                graph(&sized(5), &[[0, 1], [2, 3], [3, 4], [4, 2]]),
            ),
            ("tree with back edges", tree(60)),
            ("empty", graph(&[], &[])),
            ("single node", graph(&[[120.0, 40.0]], &[])),
        ];
        let graphs = shapes.iter().map(|(_, shape)| shape.clone()).collect();
        let outcomes = lay_out_all(graphs, DEADLINE).await;
        for ((label, shape), outcome) in shapes.iter().zip(&outcomes) {
            assert_sound(shape, outcome, label);
        }
        let Outcome::LaidOut {
            nodes,
            width,
            height,
            ..
        } = &outcomes[9]
        else {
            unreachable!()
        };
        // Only the real node sets the origin and the extent.
        assert_eq!(nodes, &vec![[Coord(0.0), Coord(0.0)]]);
        assert_eq!((width.0, height.0), (120.0, 40.0));
        let Outcome::LaidOut { width, height, .. } = &outcomes[8] else {
            unreachable!()
        };
        assert_eq!((width.0, height.0), (0.0, 0.0));
    }

    #[tokio::test]
    async fn separate_parts_are_packed_in_rows_without_overlap() {
        // 90 small trees and isolated nodes, the shape of a sparse flow
        // graph; one virtual root over all of them made Triskel overlap nodes.
        let mut edges = Vec::new();
        let mut start = 0u64;
        for part in 0..90u64 {
            let size = 1 + part % 5;
            edges.extend(
                (start + 1..start + size).map(|node| [start + (node - start - 1) / 2, node]),
            );
            start += size;
        }
        let forest = graph(&sized(start as usize), &edges);
        let parts = parts(&forest);
        assert_eq!(parts.len(), 90);
        assert_eq!(parts[0].0.len(), 5, "largest part first");
        let outcomes = lay_out_all(vec![forest.clone()], DEADLINE).await;
        assert_sound(&forest, &outcomes[0], "forest");
        let Outcome::LaidOut { width, height, .. } = &outcomes[0] else {
            unreachable!()
        };
        assert!(
            width.0 < 4.0 * height.0 && height.0 < 4.0 * width.0,
            "{width:?} x {height:?}"
        );
    }

    #[tokio::test]
    async fn oversized_graphs_are_refused_alone() {
        let graphs = vec![
            graph(&sized(MAX_GRAPH_NODES + 1), &[]),
            graph(&sized(2), &[[0, 1]]),
            graph(&sized(2), &vec![[0, 1]; MAX_GRAPH_EDGES + 1]),
        ];
        let outcomes = lay_out_all(graphs, DEADLINE).await;
        for index in [0, 2] {
            let Outcome::TooLarge { reason } = &outcomes[index] else {
                panic!("{:?}", outcomes[index]);
            };
            assert!(
                reason.contains("at most 2000 nodes and 8000 edges"),
                "{reason}"
            );
        }
        assert_sound(
            &graph(&sized(2), &[[0, 1]]),
            &outcomes[1],
            "beside oversized graphs",
        );
    }

    #[tokio::test]
    async fn a_stopped_graph_costs_only_itself() {
        let small = || graph(&sized(3), &[[0, 1], [1, 2]]);
        for (fault, deadline, kept, words) in [
            ("hang", 5_000, true, "this graph's 1.0 s budget"),
            ("hang", 600, false, "0.6 s request deadline"),
            ("crash", 5_000, true, "signal 6 while laying out this graph"),
            ("memory", 5_000, true, "2 GiB memory limit on this graph"),
        ] {
            FAULT.set(Some(fault));
            let outcomes = lay_out_all(
                vec![small(), small(), small()],
                Duration::from_millis(deadline),
            )
            .await;
            let label = format!("{fault} in {deadline} ms");
            assert_sound(&small(), &outcomes[0], &label);
            let reason = match (&outcomes[1], fault) {
                (Outcome::Timeout { reason }, "hang") | (Outcome::Failed { reason }, _) => reason,
                (outcome, _) => panic!("{label}: {outcome:?}"),
            };
            assert!(reason.contains(words), "{label}: {reason}");
            if kept {
                // A new worker lays out the graphs after the stopped one.
                assert_sound(&small(), &outcomes[2], &label);
            } else {
                assert!(
                    matches!(&outcomes[2], Outcome::Timeout { reason: rest } if rest == reason),
                    "{label}: {:?}",
                    outcomes[2]
                );
            }
        }
    }

    /// A small connected graph on which this Triskel revision never returns:
    /// two entries meet at 3, and the SESE pass roots the region {0, 4, 5, 6}
    /// at its exit node 0, so cycle removal misses the loop 6 -> 4 -> 5 -> 6
    /// and layer assignment spins (see vendor/README.md).
    #[tokio::test]
    async fn a_graph_triskel_never_finishes_times_out_alone() {
        let looping = graph(
            &sized(7),
            &[[0, 3], [6, 0], [4, 5], [2, 6], [6, 4], [5, 6], [1, 3]],
        );
        let diamond = graph(&sized(4), &[[0, 1], [0, 2], [1, 3], [2, 3]]);
        let started = Instant::now();
        let outcomes = lay_out_all(vec![looping, diamond.clone()], DEADLINE).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        let Outcome::Timeout { reason } = &outcomes[0] else {
            panic!("{:?}", outcomes[0]);
        };
        assert!(reason.contains("budget"), "{reason}");
        assert_sound(&diamond, &outcomes[1], "after a looping graph");
    }

    #[tokio::test]
    async fn the_request_deadline_stops_a_real_layout() {
        let outcomes = lay_out_all(vec![tree(1_500)], Duration::from_millis(20)).await;
        let Outcome::Timeout { reason } = &outcomes[0] else {
            panic!("{:?}", outcomes[0]);
        };
        assert!(reason.contains("0.02 s"), "{reason}");
    }

    #[tokio::test]
    async fn a_third_request_waits_for_a_worker_slot() {
        let small = || vec![graph(&sized(3), &[[0, 1], [1, 2]])];
        let (first, second, third) = tokio::join!(
            lay_out_all(small(), DEADLINE),
            lay_out_all(small(), DEADLINE),
            lay_out_all(small(), DEADLINE)
        );
        for outcomes in [first, second, third] {
            assert_sound(&graph(&sized(3), &[[0, 1], [1, 2]]), &outcomes[0], "queued");
        }
    }

    /// Seeded random graphs, most without CFG structure: every layout that
    /// comes back keeps every invariant, and the rest say why they did not.
    #[tokio::test]
    async fn random_graphs_never_return_an_unsound_layout() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let graphs = (0..64)
            .map(|_| {
                let count = 1 + next(60);
                let edges = (0..count * (1 + next(3)) / 2)
                    .map(|_| [next(count), next(count)])
                    .collect::<Vec<_>>();
                graph(&sized(count as usize), &edges)
            })
            .collect::<Vec<_>>();
        let outcomes = lay_out_all(graphs.clone(), DEADLINE).await;
        let mut laid_out = 0;
        for (index, (graph, outcome)) in graphs.iter().zip(&outcomes).enumerate() {
            match outcome {
                Outcome::LaidOut { .. } => {
                    assert_sound(graph, outcome, &format!("random graph {index}"));
                    laid_out += 1;
                }
                Outcome::Failed { reason } | Outcome::Timeout { reason } => {
                    assert!(
                        reason.contains("Triskel") || reason.contains("budget"),
                        "{reason}"
                    );
                }
                Outcome::TooLarge { .. } => panic!("{outcome:?}"),
            }
        }
        assert!(laid_out >= 60, "{laid_out} of 64 laid out");
    }

    #[test]
    fn requests_are_validated_before_any_layout() {
        let bad = |body: &str| parse(body.as_bytes()).err().map(|error| error.message);
        assert!(bad(r#"{"graphs":[{"nodes":[[1,2]],"edges":[]}]}"#).is_none());
        for (body, words) in [
            ("{", "malformed JSON"),
            ("[]", "must be"),
            (r#"{"graphs":[],"extra":1}"#, "must be"),
            (r#"{"graphs":[{"nodes":[[1]],"edges":[]}]}"#, "must be"),
            (
                r#"{"graphs":[{"nodes":[[1,2]],"edges":[[0,0.5]]}]}"#,
                "must be",
            ),
            (
                r#"{"graphs":[{"nodes":[[1,2]],"edges":[[0,-1]]}]}"#,
                "must be",
            ),
            (
                r#"{"graphs":[{"nodes":[[1,2]],"edges":[[0,1]]}]}"#,
                "edge 0 names a node outside",
            ),
            (
                r#"{"graphs":[{"nodes":[[0,2]],"edges":[]}]}"#,
                "node 0 needs",
            ),
            (
                r#"{"graphs":[{"nodes":[[-3,2]],"edges":[]}]}"#,
                "node 0 needs",
            ),
            (
                r#"{"graphs":[{"nodes":[[1,100001]],"edges":[]}]}"#,
                "node 0 needs",
            ),
            (
                r#"{"graphs":[{"nodes":[[1,NaN]],"edges":[]}]}"#,
                "malformed JSON",
            ),
            (
                r#"{"graphs":[{"nodes":[[1,1e999]],"edges":[]}]}"#,
                "malformed JSON",
            ),
        ] {
            let message = bad(body).unwrap_or_else(|| panic!("{body} was accepted"));
            assert!(message.contains(words), "{body}: {message}");
        }
        let graphs = |count: usize, nodes: usize| {
            let one = json(nodes);
            format!("{{\"graphs\":[{}]}}", vec![one; count].join(","))
        };
        fn json(nodes: usize) -> String {
            format!(
                "{{\"nodes\":[{}],\"edges\":[]}}",
                vec!["[1,1]"; nodes].join(",")
            )
        }
        assert!(bad(&graphs(MAX_GRAPHS, 1)).is_none());
        assert!(
            bad(&graphs(MAX_GRAPHS + 1, 1))
                .unwrap()
                .contains("at most 64 graphs")
        );
        assert!(bad(&graphs(4, 2_000)).is_none());
        assert!(
            bad(&graphs(5, 1_601))
                .unwrap()
                .contains("8000 nodes in all")
        );
    }

    #[test]
    fn the_virtual_root_and_exit_close_every_part_once() {
        // 0 -> 1, a cycle 2 -> 3 -> 2 with no entry or exit, 4 entered and
        // left only by itself.
        let (sizes, endpoints) = rooted(&graph(&sized(5), &[[0, 1], [2, 3], [3, 2], [4, 4]]));
        assert_eq!(&sizes[..2], &[0.0, 0.0]);
        assert_eq!(sizes.len(), 14);
        assert_eq!(&sizes[12..], &[0.0, 0.0]);
        let virtual_edges = endpoints[8..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[from, to]| (from, to))
            .collect::<Vec<_>>();
        // The root enters 0, 4 and the cycle; the cycle's deepest node and 4
        // leave to the exit, node 6. 0 -> 1 already ends at a node with no
        // out-edge.
        assert_eq!(virtual_edges, vec![(0, 1), (0, 5), (0, 3), (4, 6), (5, 6)]);
        let (sizes, endpoints) = rooted(&graph(&sized(3), &[[0, 1], [1, 2]]));
        assert_eq!(sizes.len(), 8, "no exit node when every part has one");
        assert_eq!(&endpoints[4..], &[0, 1]);
    }

    #[test]
    fn coordinates_round_to_two_decimals_without_negative_zero() {
        assert_eq!(
            serde_json::to_string(&Coord::rounded(12.345_6)).unwrap(),
            "12.35"
        );
        assert_eq!(serde_json::to_string(&Coord::rounded(40.0)).unwrap(), "40");
        assert_eq!(serde_json::to_string(&Coord::rounded(-0.001)).unwrap(), "0");
        assert_eq!(
            serde_json::to_string(&Coord::rounded(0.1 + 0.2)).unwrap(),
            "0.3"
        );
    }
}
