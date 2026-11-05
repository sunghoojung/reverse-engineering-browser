//! Confirmed commands against the Wasm instance dispatch capture attached to.
//!
//! The HTTP API speaks a bounded local socket. This module's peer is the
//! contract implementation tests drive. A rebuilt Brave does not speak the
//! socket yet: without a peer the API reports the command unavailable and does
//! not invent memory bytes, return values, or dispatch samples. See
//! protocol/live-wasm-instance-v1.md.

use crate::{
    error::{Cause, Code, Error, Reason, Result},
    validation,
};
use serde_json::{Value, json};
use std::{
    io::Read,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use wasmparser::{
    BlockType, CompositeInnerType, Encoding, ExternalKind, Operator, Parser, Payload, TypeRef,
    ValType,
};

/// Same cap as `kNativeWasmDispatchSampleBudget`. Page script and a live call
/// share one counter so neither stream grows a private budget.
pub const DISPATCH_BUDGET: u32 = 16;
/// A call that is still running after this many instructions did not return.
/// The bound is what makes a non-terminating body observable in this peer.
const STEP_LIMIT: u32 = 64;
const MAX_MODULE_BYTES: usize = 65_536;
const MAX_FUNCTIONS: usize = 64;
const MAX_OPERATORS: usize = 256;
const MAX_MEMORY_PAGES: u64 = 16;
const MAX_NAME_BYTES: usize = 64;
const MAX_ARGS: usize = 16;
const MAX_PAYLOAD: usize = 8_192;
const MEMORY_SLICE: u32 = 4_096;
const REQUEST_HEADER: usize = 56;
const RESPONSE_HEADER: usize = 32;
const MAGIC: u32 = 0x3157_4C52;
const VERSION: u16 = 1;
const OP_LIST: u16 = 1;
const OP_READ: u16 = 2;
const OP_WRITE: u16 = 3;
const OP_CALL_EXPORT: u16 = 4;
const OP_CALL_FUNCTION: u16 = 5;

pub const FIXTURE_INSTANCE: u64 = 7;
pub const FIXTURE_DOCUMENT_HIGH: u64 = 11;
pub const FIXTURE_DOCUMENT_LOW: u64 = 13;
pub const FIXTURE_DOCUMENT_EPOCH: u64 = 1;

/// Small module the contract tests attach. Function 3 is the unexported
/// `br_table`. The byte at that instruction is checked, not assumed.
pub const FIXTURE_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)
  (func (export "trap") (result i32)
    unreachable)
  (func (export "hang") (param i32) (result i32)
    (loop
      br 0)
    local.get 0)
  (func (param i32) (result i32)
    (block
      (block
        local.get 0
        br_table 0 1))
    local.get 0)
  (func (param i64) (result i64)
    local.get 0))
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NumType {
    I32,
    I64,
    F32,
    F64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Val {
    I32(u32),
    I64(u64),
    F32(u32),
    F64(u64),
}

impl Val {
    fn ty(self) -> NumType {
        match self {
            Self::I32(_) => NumType::I32,
            Self::I64(_) => NumType::I64,
            Self::F32(_) => NumType::F32,
            Self::F64(_) => NumType::F64,
        }
    }
    fn bits(self) -> u64 {
        match self {
            Self::I32(v) | Self::F32(v) => u64::from(v),
            Self::I64(v) | Self::F64(v) => v,
        }
    }
    fn zero(ty: NumType) -> Self {
        match ty {
            NumType::I32 => Self::I32(0),
            NumType::I64 => Self::I64(0),
            NumType::F32 => Self::F32(0),
            NumType::F64 => Self::F64(0),
        }
    }
}

fn num_name(ty: NumType) -> &'static str {
    match ty {
        NumType::I32 => "i32",
        NumType::I64 => "i64",
        NumType::F32 => "f32",
        NumType::F64 => "f64",
    }
}

fn numeric(ty: ValType) -> Option<NumType> {
    match ty {
        ValType::I32 => Some(NumType::I32),
        ValType::I64 => Some(NumType::I64),
        ValType::F32 => Some(NumType::F32),
        ValType::F64 => Some(NumType::F64),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Malformed,
    StaleDocument,
    InstanceMismatch,
    UnknownExport,
    UnknownMemory,
    UnknownFunction,
    SignatureMismatch,
    Trap,
    DidNotReturn,
    OutOfBounds,
    Unavailable,
    Unsupported,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Malformed => "malformed",
            Self::StaleDocument => "stale_document",
            Self::InstanceMismatch => "instance_mismatch",
            Self::UnknownExport => "unknown_export",
            Self::UnknownMemory => "unknown_memory",
            Self::UnknownFunction => "unknown_function",
            Self::SignatureMismatch => "signature_mismatch",
            Self::Trap => "trap",
            Self::DidNotReturn => "did_not_return",
            Self::OutOfBounds => "out_of_bounds",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
        }
    }
    fn code(self) -> u16 {
        match self {
            Self::Ok => 0,
            Self::Malformed => 1,
            Self::StaleDocument => 2,
            Self::InstanceMismatch => 3,
            Self::UnknownExport => 4,
            Self::UnknownMemory => 5,
            Self::UnknownFunction => 6,
            Self::SignatureMismatch => 7,
            Self::Trap => 8,
            Self::DidNotReturn => 9,
            Self::OutOfBounds => 10,
            Self::Unavailable => 11,
            Self::Unsupported => 12,
        }
    }
    fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::Malformed,
            2 => Self::StaleDocument,
            3 => Self::InstanceMismatch,
            4 => Self::UnknownExport,
            5 => Self::UnknownMemory,
            6 => Self::UnknownFunction,
            7 => Self::SignatureMismatch,
            8 => Self::Trap,
            9 => Self::DidNotReturn,
            10 => Self::OutOfBounds,
            11 => Self::Unavailable,
            12 => Self::Unsupported,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    PageScript,
    LiveCall,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::PageScript => "page_script",
            Self::LiveCall => "live_call",
        }
    }
}

#[derive(Clone, Debug)]
enum Inst {
    LocalGet(u32),
    I32Const(u32),
    I64Const(u64),
    I32Add,
    I64Add,
    Unreachable,
    Block(Option<NumType>),
    Loop(Option<NumType>),
    End,
    Br(u32),
    BrTable {
        labels: Vec<u32>,
        default: u32,
        offset: u32,
    },
}

struct Func {
    params: Vec<NumType>,
    results: Vec<NumType>,
    locals: Vec<NumType>,
    export_name: Option<String>,
    ops: Vec<Inst>,
    block_end: Vec<Option<usize>>,
    /// False when the body is not in the closed operator set. A call is refused
    /// before entry rather than half-executed.
    executable: bool,
    imported: bool,
}

struct Memory {
    name: Option<String>,
    bytes: Vec<u8>,
    shared: bool,
}

#[derive(Clone, Debug)]
pub struct Attachment {
    pub instance_id: u64,
    pub document_token_high: u64,
    pub document_token_low: u64,
    pub document_epoch: u64,
}

struct Outcome<'a> {
    action: &'a str,
    identity: (u64, u64, u64, u64),
    status: Status,
    entered: bool,
    recorded: &'a Recorded,
    memory: Value,
    results: Value,
    export: Value,
    function_index: Value,
}

struct Recorded {
    samples: Vec<u32>,
    gap: bool,
}

pub struct Engine {
    module: Vec<u8>,
    functions: Vec<Func>,
    memories: Vec<Memory>,
    attachment: Attachment,
    detached: bool,
    samples_used: u32,
    gaps: u32,
    observations: Vec<Value>,
    commands: u64,
    entries: u64,
    writes: u64,
    br_table_function: Option<u32>,
}

impl Engine {
    pub fn load(bytes: &[u8], attachment: Attachment) -> std::result::Result<Self, String> {
        if bytes.len() > MAX_MODULE_BYTES {
            return Err("module exceeds this peer's 64 KiB bound".into());
        }
        if attachment.instance_id == 0 || attachment.document_epoch == 0 {
            return Err("attachment identity must be nonzero".into());
        }
        let mut signatures = Vec::new();
        let mut functions = Vec::new();
        let mut memories = Vec::new();
        let mut imported_functions = 0usize;
        let mut defined = 0usize;
        let mut saw_code = 0usize;
        for payload in Parser::new(0).parse_all(bytes) {
            let payload = payload.map_err(|error| error.to_string())?;
            match payload {
                Payload::Version {
                    num: 1,
                    encoding: Encoding::Module,
                    ..
                } => {}
                Payload::Version { .. } => {
                    return Err("only a core wasm v1 module can be attached".into());
                }
                Payload::TypeSection(reader) => {
                    for group in reader {
                        let group = group.map_err(|error| error.to_string())?;
                        for ty in group.types() {
                            let CompositeInnerType::Func(function) = &ty.composite_type.inner
                            else {
                                return Err("non-function types are not executed".into());
                            };
                            let mut params = Vec::new();
                            let mut numeric_only = true;
                            for ty in function.params() {
                                match numeric(*ty) {
                                    Some(ty) => params.push(ty),
                                    None => numeric_only = false,
                                }
                            }
                            let mut results = Vec::new();
                            for ty in function.results() {
                                match numeric(*ty) {
                                    Some(ty) => results.push(ty),
                                    None => numeric_only = false,
                                }
                            }
                            if !numeric_only || params.len() > MAX_ARGS || results.len() > MAX_ARGS
                            {
                                params.clear();
                                results.clear();
                            }
                            signatures.push((params, results, numeric_only));
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        let import = import.map_err(|error| error.to_string())?;
                        match import.ty {
                            TypeRef::Func(index) => {
                                let (params, results, numeric) = signature(&signatures, index)?;
                                functions.push(Func {
                                    params,
                                    results,
                                    locals: Vec::new(),
                                    export_name: None,
                                    ops: Vec::new(),
                                    block_end: Vec::new(),
                                    executable: false,
                                    imported: true,
                                });
                                imported_functions += 1;
                                let _ = numeric;
                            }
                            TypeRef::Memory(_) => {
                                return Err(
                                    "imported memory is not this peer's linear memory".into()
                                );
                            }
                            _ => {}
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for index in reader {
                        let index = index.map_err(|error| error.to_string())?;
                        let (params, results, numeric) = signature(&signatures, index)?;
                        functions.push(Func {
                            params: params.clone(),
                            results: results.clone(),
                            locals: params.clone(),
                            export_name: None,
                            ops: Vec::new(),
                            block_end: Vec::new(),
                            executable: numeric
                                && params.len() <= MAX_ARGS
                                && results.len() <= MAX_ARGS,
                            imported: false,
                        });
                        defined += 1;
                    }
                }
                Payload::MemorySection(reader) => {
                    for memory in reader {
                        let memory = memory.map_err(|error| error.to_string())?;
                        if memory.shared || memory.memory64 {
                            return Err(
                                "shared and memory64 memories are refused, not sliced".into()
                            );
                        }
                        if memory.page_size_log2.is_some_and(|log| log != 16) {
                            return Err("custom memory page sizes are not sliced".into());
                        }
                        if memory.initial > MAX_MEMORY_PAGES {
                            return Err("memory exceeds this peer's 1 MiB bound".into());
                        }
                        let len = usize::try_from(memory.initial * 65_536)
                            .map_err(|_| "memory length overflow".to_owned())?;
                        memories.push(Memory {
                            name: None,
                            bytes: vec![0; len],
                            shared: false,
                        });
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(|error| error.to_string())?;
                        if export.name.len() > MAX_NAME_BYTES || export.name.is_empty() {
                            return Err("export name is empty or longer than 64 bytes".into());
                        }
                        match export.kind {
                            ExternalKind::Func => {
                                let func =
                                    functions.get_mut(export.index as usize).ok_or_else(|| {
                                        "export function index is out of range".to_owned()
                                    })?;
                                if func.export_name.is_some() {
                                    return Err("duplicate function export".into());
                                }
                                func.export_name = Some(export.name.to_owned());
                            }
                            ExternalKind::Memory => {
                                let memory =
                                    memories.get_mut(export.index as usize).ok_or_else(|| {
                                        "export memory index is out of range".to_owned()
                                    })?;
                                if memory.name.is_some() {
                                    return Err("duplicate memory export".into());
                                }
                                memory.name = Some(export.name.to_owned());
                            }
                            _ => {}
                        }
                    }
                }
                Payload::CodeSectionEntry(body) => {
                    let index = imported_functions + saw_code;
                    saw_code += 1;
                    let func = functions
                        .get_mut(index)
                        .ok_or_else(|| "code entry has no function".to_owned())?;
                    parse_body(func, &body).map_err(|error| error.to_string())?;
                }
                Payload::StartSection { .. } => {
                    return Err("this peer does not run a start function".into());
                }
                Payload::DataSection(reader) => {
                    if reader.count() > 0 {
                        return Err("this peer does not apply data segments".into());
                    }
                }
                Payload::End(_) => {}
                _ => {}
            }
        }
        if functions.len() > MAX_FUNCTIONS {
            return Err("too many functions for this peer".into());
        }
        if memories.len() > 16 {
            return Err("too many memories for this peer".into());
        }
        if saw_code != defined {
            return Err("function and code counts disagree".into());
        }
        let br_table_function = functions.iter().enumerate().find_map(|(index, func)| {
            func.ops
                .iter()
                .any(|op| matches!(op, Inst::BrTable { .. }))
                .then_some(u32::try_from(index).ok())
                .flatten()
        });
        Ok(Self {
            module: bytes.to_vec(),
            functions,
            memories,
            attachment,
            detached: false,
            samples_used: 0,
            gaps: 0,
            observations: Vec::new(),
            commands: 0,
            entries: 0,
            writes: 0,
            br_table_function,
        })
    }

    pub fn br_table_function(&self) -> Option<u32> {
        self.br_table_function
    }
    pub fn byte_at(&self, offset: u32) -> Option<u8> {
        self.module.get(offset as usize).copied()
    }
    pub fn commands(&self) -> u64 {
        self.commands
    }
    pub fn entries(&self) -> u64 {
        self.entries
    }
    pub fn writes(&self) -> u64 {
        self.writes
    }
    pub fn samples_used(&self) -> u32 {
        self.samples_used
    }
    pub fn memory(&self, name: &str) -> Option<Vec<u8>> {
        self.memories
            .iter()
            .find(|memory| memory.name.as_deref() == Some(name))
            .map(|memory| memory.bytes.clone())
    }
    pub fn navigate(&mut self) {
        match self.attachment.document_epoch.checked_add(1) {
            Some(epoch) => self.attachment.document_epoch = epoch,
            None => self.detached = true,
        }
    }
    /// Runs the function the way page script would: same body, same budget,
    /// observations tagged `page_script`. Not an HTTP operation.
    pub fn run_page_script(&mut self, function_index: u32, args: &[Val]) {
        let _ = self.call(function_index, args, Source::PageScript);
    }

    fn note_command(&mut self) {
        self.commands = self.commands.saturating_add(1);
    }

    fn admit(&self, instance: u64, high: u64, low: u64, epoch: u64) -> Option<Status> {
        if self.detached {
            return Some(Status::Unavailable);
        }
        if high != self.attachment.document_token_high
            || low != self.attachment.document_token_low
            || epoch != self.attachment.document_epoch
        {
            return Some(Status::StaleDocument);
        }
        if instance != self.attachment.instance_id {
            return Some(Status::InstanceMismatch);
        }
        None
    }

    fn record(
        &mut self,
        source: Source,
        function_index: u32,
        offset: u32,
        selector: u32,
        table_count: u32,
    ) -> Recorded {
        let identity = self.attachment.clone();
        if self.samples_used >= DISPATCH_BUDGET {
            self.gaps = self.gaps.saturating_add(1);
            self.push_observation(json!({
                "source": source.as_str(),
                "kind": "gap",
                "reason": "native_wasm_dispatch_budget_incomplete",
                "instance_id": dec(identity.instance_id),
                "document_token_high": dec(identity.document_token_high),
                "document_token_low": dec(identity.document_token_low),
                "document_epoch": dec(identity.document_epoch),
                "function_index": function_index,
                "module_byte_offset": offset,
                "selector": selector,
                "table_count": table_count,
                "sample_index": Value::Null,
            }));
            return Recorded {
                samples: Vec::new(),
                gap: true,
            };
        }
        let sample = self.samples_used;
        self.samples_used += 1;
        self.push_observation(json!({
            "source": source.as_str(),
            "kind": "sample",
            "reason": Value::Null,
            "instance_id": dec(identity.instance_id),
            "document_token_high": dec(identity.document_token_high),
            "document_token_low": dec(identity.document_token_low),
            "document_epoch": dec(identity.document_epoch),
            "function_index": function_index,
            "module_byte_offset": offset,
            "selector": selector,
            "table_count": table_count,
            "sample_index": sample,
        }));
        Recorded {
            samples: vec![sample],
            gap: false,
        }
    }

    fn push_observation(&mut self, value: Value) {
        // The counters above stay exact. The retained log is only a window.
        if self.observations.len() < 32 {
            self.observations.push(value);
        }
    }

    fn state_json(&self) -> Value {
        let mut exports = Vec::new();
        let mut functions = Vec::new();
        for (index, func) in self.functions.iter().enumerate() {
            let params = func
                .params
                .iter()
                .copied()
                .map(num_name)
                .collect::<Vec<_>>();
            let results = func
                .results
                .iter()
                .copied()
                .map(num_name)
                .collect::<Vec<_>>();
            if let Some(name) = &func.export_name {
                exports.push(json!({
                    "name": name,
                    "kind": "function",
                    "params": params,
                    "results": results,
                }));
            }
            functions.push(json!({
                "index": index,
                "params": func.params.iter().copied().map(num_name).collect::<Vec<_>>(),
                "results": func.results.iter().copied().map(num_name).collect::<Vec<_>>(),
                "export": func.export_name,
            }));
        }
        let mut memories = Vec::new();
        for memory in &self.memories {
            let Some(name) = &memory.name else {
                continue;
            };
            exports.push(json!({
                "name": name,
                "kind": "memory",
                "params": [],
                "results": [],
            }));
            memories.push(json!({
                "name": name,
                "byte_length": memory.bytes.len(),
                "shared": memory.shared,
            }));
        }
        json!({
            "protocol_version": 1,
            "availability": "ready",
            "reason": Value::Null,
            "budget": DISPATCH_BUDGET,
            "dispatch_samples_used": self.samples_used,
            "dispatch_gaps": self.gaps,
            "observations_truncated": self.observations.len() == 32
                && (self.samples_used as usize + self.gaps as usize) > self.observations.len(),
            "observations": self.observations,
            "attachments": [{
                "instance_id": dec(self.attachment.instance_id),
                "document_token_high": dec(self.attachment.document_token_high),
                "document_token_low": dec(self.attachment.document_token_low),
                "document_epoch": dec(self.attachment.document_epoch),
                "memories": memories,
                "exports": exports,
                "functions": functions,
            }],
        })
    }

    fn outcome(&self, fields: Outcome<'_>) -> Value {
        json!({
            "protocol_version": 1,
            "action": fields.action,
            "status": fields.status.as_str(),
            "entered": fields.entered,
            "instance_id": dec(fields.identity.0),
            "document_token_high": dec(fields.identity.1),
            "document_token_low": dec(fields.identity.2),
            "document_epoch": dec(fields.identity.3),
            "samples_consumed": fields.recorded.samples.len(),
            "sample_indexes": fields.recorded.samples,
            "budget_gap": fields.recorded.gap,
            "memory": fields.memory,
            "results": fields.results,
            "export": fields.export,
            "function_index": fields.function_index,
        })
    }

    fn refusal(&self, action: &str, identity: (u64, u64, u64, u64), status: Status) -> Value {
        let recorded = empty_record();
        self.outcome(Outcome {
            action,
            identity,
            status,
            entered: false,
            recorded: &recorded,
            memory: Value::Null,
            results: Value::Null,
            export: Value::Null,
            function_index: Value::Null,
        })
    }

    fn call(
        &mut self,
        function_index: u32,
        args: &[Val],
        source: Source,
    ) -> (Status, bool, Option<Vec<Val>>, Recorded) {
        let Some(func) = self.functions.get(function_index as usize) else {
            return (Status::UnknownFunction, false, None, empty_record());
        };
        if func.imported || !func.executable {
            return (Status::Unsupported, false, None, empty_record());
        }
        // The type is the function's declared signature. A mismatch returns
        // before the body, so a br_table in that body cannot spend a sample.
        let mismatch = func.params.len() != args.len()
            || func
                .params
                .iter()
                .zip(args.iter())
                .any(|(expected, value)| *expected != value.ty());
        if mismatch {
            return (Status::SignatureMismatch, false, None, empty_record());
        }
        let mut locals = func
            .locals
            .iter()
            .copied()
            .map(Val::zero)
            .collect::<Vec<_>>();
        let ops = func.ops.clone();
        let ends = func.block_end.clone();
        let results = func.results.clone();
        self.entries = self.entries.saturating_add(1);
        for (slot, value) in locals.iter_mut().zip(args.iter()) {
            *slot = *value;
        }
        match self.run(function_index, source, &ops, &ends, &results, &mut locals) {
            Run::Values(values, recorded) => (Status::Ok, true, Some(values), recorded),
            Run::Status(status, recorded) => (status, true, None, recorded),
        }
    }

    fn run(
        &mut self,
        function_index: u32,
        source: Source,
        ops: &[Inst],
        ends: &[Option<usize>],
        results: &[NumType],
        locals: &mut [Val],
    ) -> Run {
        let mut stack = Vec::new();
        let mut ctrl = vec![Ctrl {
            kind: CtrlKind::Func,
            start: 0,
            end: ops.len().saturating_sub(1),
            height: 0,
            result: (results.len() == 1).then_some(results[0]),
        }];
        let mut recorded = empty_record();
        let mut ip = 0;
        let mut steps = 0u32;
        while ip < ops.len() {
            steps += 1;
            if steps > STEP_LIMIT {
                return Run::Status(Status::DidNotReturn, recorded);
            }
            match &ops[ip] {
                Inst::LocalGet(index) => {
                    let Some(value) = locals.get(*index as usize).copied() else {
                        return Run::Status(Status::Unsupported, recorded);
                    };
                    stack.push(value);
                    ip += 1;
                }
                Inst::I32Const(value) => {
                    stack.push(Val::I32(*value));
                    ip += 1;
                }
                Inst::I64Const(value) => {
                    stack.push(Val::I64(*value));
                    ip += 1;
                }
                Inst::I32Add => {
                    let Some(right) = pop(&mut stack, NumType::I32) else {
                        return Run::Status(Status::Unsupported, recorded);
                    };
                    let Some(left) = pop(&mut stack, NumType::I32) else {
                        return Run::Status(Status::Unsupported, recorded);
                    };
                    stack.push(Val::I32(
                        (left.bits() as u32).wrapping_add(right.bits() as u32),
                    ));
                    ip += 1;
                }
                Inst::I64Add => {
                    let Some(right) = pop(&mut stack, NumType::I64) else {
                        return Run::Status(Status::Unsupported, recorded);
                    };
                    let Some(left) = pop(&mut stack, NumType::I64) else {
                        return Run::Status(Status::Unsupported, recorded);
                    };
                    stack.push(Val::I64(left.bits().wrapping_add(right.bits())));
                    ip += 1;
                }
                Inst::Unreachable => return Run::Status(Status::Trap, recorded),
                Inst::Block(result) | Inst::Loop(result) => {
                    let kind = if matches!(ops[ip], Inst::Loop(_)) {
                        CtrlKind::Loop
                    } else {
                        CtrlKind::Block
                    };
                    let Some(end) = ends.get(ip).copied().flatten() else {
                        return Run::Status(Status::Unsupported, recorded);
                    };
                    ctrl.push(Ctrl {
                        kind,
                        start: ip,
                        end,
                        height: stack.len(),
                        result: *result,
                    });
                    ip += 1;
                }
                Inst::End => {
                    ctrl.pop();
                    if ctrl.is_empty() {
                        if stack.len() != results.len()
                            || stack
                                .iter()
                                .zip(results)
                                .any(|(value, ty)| value.ty() != *ty)
                        {
                            return Run::Status(Status::Unsupported, recorded);
                        }
                        return Run::Values(stack, recorded);
                    }
                    ip += 1;
                }
                Inst::Br(depth) => {
                    if !branch(*depth, &mut ctrl, &mut stack, &mut ip) {
                        return Run::Status(Status::Unsupported, recorded);
                    }
                }
                Inst::BrTable {
                    labels,
                    default,
                    offset,
                } => {
                    let Some(selector) = pop(&mut stack, NumType::I32) else {
                        return Run::Status(Status::Unsupported, recorded);
                    };
                    let selector = selector.bits() as u32;
                    let effect = self.record(
                        source,
                        function_index,
                        *offset,
                        selector,
                        u32::try_from(labels.len()).unwrap_or(u32::MAX),
                    );
                    recorded.samples.extend(effect.samples);
                    recorded.gap |= effect.gap;
                    let depth = labels.get(selector as usize).copied().unwrap_or(*default);
                    if !branch(depth, &mut ctrl, &mut stack, &mut ip) {
                        return Run::Status(Status::Unsupported, recorded);
                    }
                }
            }
        }
        Run::Status(Status::Unsupported, recorded)
    }
}

fn empty_record() -> Recorded {
    Recorded {
        samples: Vec::new(),
        gap: false,
    }
}

fn pop(stack: &mut Vec<Val>, ty: NumType) -> Option<Val> {
    let value = stack.pop()?;
    (value.ty() == ty).then_some(value)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CtrlKind {
    Func,
    Block,
    Loop,
}

struct Ctrl {
    kind: CtrlKind,
    start: usize,
    end: usize,
    height: usize,
    result: Option<NumType>,
}

fn branch(depth: u32, ctrl: &mut Vec<Ctrl>, stack: &mut Vec<Val>, ip: &mut usize) -> bool {
    let depth = depth as usize;
    if depth >= ctrl.len() {
        return false;
    }
    let index = ctrl.len() - 1 - depth;
    let target_kind = ctrl[index].kind;
    let target_end = ctrl[index].end;
    let target_start = ctrl[index].start;
    let height = ctrl[index].height;
    let result = ctrl[index].result;
    let produced = if let Some(ty) = result {
        let Some(value) = pop(stack, ty) else {
            return false;
        };
        Some(value)
    } else {
        None
    };
    if stack.len() < height {
        return false;
    }
    stack.truncate(height);
    if let Some(value) = produced {
        stack.push(value);
    }
    if target_kind == CtrlKind::Loop {
        ctrl.truncate(index + 1);
        *ip = target_start + 1;
    } else {
        ctrl.truncate(index + 1);
        *ip = target_end;
    }
    true
}

enum Run {
    Values(Vec<Val>, Recorded),
    Status(Status, Recorded),
}

fn signature(
    signatures: &[(Vec<NumType>, Vec<NumType>, bool)],
    index: u32,
) -> std::result::Result<(Vec<NumType>, Vec<NumType>, bool), String> {
    signatures
        .get(index as usize)
        .cloned()
        .ok_or_else(|| "function type index is out of range".into())
}

fn parse_body(
    func: &mut Func,
    body: &wasmparser::FunctionBody<'_>,
) -> std::result::Result<(), String> {
    let mut reader = body
        .get_locals_reader()
        .map_err(|error| error.to_string())?;
    for _ in 0..reader.get_count() {
        let (count, ty) = reader.read().map_err(|error| error.to_string())?;
        let Some(ty) = numeric(ty) else {
            func.executable = false;
            return Ok(());
        };
        if func.locals.len() + count as usize > 256 {
            func.executable = false;
            return Ok(());
        }
        func.locals.extend(std::iter::repeat_n(ty, count as usize));
    }
    let operators = body
        .get_operators_reader()
        .map_err(|error| error.to_string())?;
    for op in operators.into_iter_with_offsets() {
        let (op, offset) = op.map_err(|error| error.to_string())?;
        if func.ops.len() >= MAX_OPERATORS {
            func.executable = false;
            func.ops.clear();
            return Ok(());
        }
        let Some(inst) = decode_operator(op, offset) else {
            func.executable = false;
            func.ops.clear();
            return Ok(());
        };
        func.ops.push(inst);
    }
    let mut stack = Vec::new();
    func.block_end = vec![None; func.ops.len()];
    for (ip, inst) in func.ops.iter().enumerate() {
        match inst {
            Inst::Block(_) | Inst::Loop(_) => stack.push(ip),
            Inst::End => {
                if let Some(start) = stack.pop() {
                    func.block_end[start] = Some(ip);
                } else if ip + 1 != func.ops.len() {
                    func.executable = false;
                    return Ok(());
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        func.executable = false;
    }
    Ok(())
}

fn decode_operator(op: Operator<'_>, offset: usize) -> Option<Inst> {
    let offset = u32::try_from(offset).ok()?;
    Some(match op {
        Operator::LocalGet { local_index } => Inst::LocalGet(local_index),
        Operator::I32Const { value } => Inst::I32Const(value as u32),
        Operator::I64Const { value } => Inst::I64Const(value as u64),
        Operator::I32Add => Inst::I32Add,
        Operator::I64Add => Inst::I64Add,
        Operator::Unreachable => Inst::Unreachable,
        Operator::Block { blockty } => Inst::Block(block_result(blockty)?),
        Operator::Loop { blockty } => Inst::Loop(block_result(blockty)?),
        Operator::End => Inst::End,
        Operator::Br { relative_depth } => Inst::Br(relative_depth),
        Operator::BrTable { targets } => {
            let labels = targets
                .targets()
                .collect::<std::result::Result<Vec<_>, _>>()
                .ok()?;
            if labels.len() > 256 {
                return None;
            }
            Inst::BrTable {
                labels,
                default: targets.default(),
                offset,
            }
        }
        _ => return None,
    })
}

fn block_result(ty: BlockType) -> Option<Option<NumType>> {
    match ty {
        BlockType::Empty => Some(None),
        BlockType::Type(ty) => Some(Some(numeric(ty)?)),
        // A function-typed block can carry parameters. This peer does not.
        BlockType::FuncType(_) => None,
    }
}

fn dec(value: u64) -> String {
    value.to_string()
}

pub struct Peer {
    socket: PathBuf,
    engine: Arc<Mutex<Engine>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Peer {
    pub fn spawn(engine: Engine) -> std::io::Result<Self> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket = dir.path().join("live-wasm.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let engine = Arc::new(Mutex::new(engine));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_engine = Arc::clone(&engine);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = std::thread::Builder::new()
            .name("live-wasm-peer".into())
            .spawn(move || serve(listener, thread_shutdown, thread_engine))?;
        Ok(Self {
            socket,
            engine,
            shutdown,
            thread: Some(thread),
            _dir: dir,
        })
    }
    pub fn socket(&self) -> &Path {
        &self.socket
    }
    pub fn with_engine<T>(&self, body: impl FnOnce(&mut Engine) -> T) -> T {
        let mut engine = self
            .engine
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        body(&mut engine)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(listener: UnixListener, shutdown: Arc<AtomicBool>, engine: Arc<Mutex<Engine>>) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok((stream, _)) = listener.accept() else {
            break;
        };
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let _ = handle_connection(stream, &engine);
    }
}

fn handle_connection(mut stream: UnixStream, engine: &Mutex<Engine>) -> std::io::Result<()> {
    silence_sigpipe(&stream);
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    if !same_user(&stream) {
        return Ok(());
    }
    let mut header = [0u8; REQUEST_HEADER];
    stream.read_exact(&mut header)?;
    let request = match decode_request(&header) {
        Some(request) => request,
        None => {
            let _ = write_reply(
                &mut stream,
                &reply(0, Status::Malformed, false, &empty_record(), b""),
            );
            return Ok(());
        }
    };
    if request.payload_len > MAX_PAYLOAD {
        let _ = write_reply(
            &mut stream,
            &reply(request.id, Status::Malformed, false, &empty_record(), b""),
        );
        return Ok(());
    }
    let mut payload = vec![0u8; request.payload_len];
    if request.payload_len > 0 {
        stream.read_exact(&mut payload)?;
    }
    let mut engine = engine.lock().unwrap_or_else(|error| error.into_inner());
    let (status, entered, recorded, body) = dispatch(&mut engine, &request, &payload);
    write_reply(
        &mut stream,
        &reply(request.id, status, entered, &recorded, body.as_bytes()),
    )
}

struct Request {
    id: u64,
    op: u16,
    instance: u64,
    high: u64,
    low: u64,
    epoch: u64,
    payload_len: usize,
}

fn decode_request(bytes: &[u8]) -> Option<Request> {
    if bytes.len() != REQUEST_HEADER {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
    let op = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
    let id = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let instance = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
    let high = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
    let low = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
    let epoch = u64::from_le_bytes(bytes[40..48].try_into().ok()?);
    let payload_len = u32::from_le_bytes(bytes[48..52].try_into().ok()?) as usize;
    let reserved = u32::from_le_bytes(bytes[52..56].try_into().ok()?);
    if magic != MAGIC || version != VERSION || id == 0 || reserved != 0 {
        return None;
    }
    if !matches!(
        op,
        OP_LIST | OP_READ | OP_WRITE | OP_CALL_EXPORT | OP_CALL_FUNCTION
    ) {
        return None;
    }
    Some(Request {
        id,
        op,
        instance,
        high,
        low,
        epoch,
        payload_len,
    })
}

fn dispatch(
    engine: &mut Engine,
    request: &Request,
    payload: &[u8],
) -> (Status, bool, Recorded, String) {
    if request.op == OP_LIST {
        if request.instance != 0
            || request.high != 0
            || request.low != 0
            || request.epoch != 0
            || !payload.is_empty()
        {
            return (Status::Malformed, false, empty_record(), String::new());
        }
        engine.note_command();
        let body = engine.state_json().to_string();
        return (Status::Ok, false, empty_record(), body);
    }
    let action = match request.op {
        OP_READ => "read_memory",
        OP_WRITE => "write_memory",
        OP_CALL_EXPORT => "call_export",
        OP_CALL_FUNCTION => "call_function",
        _ => return (Status::Malformed, false, empty_record(), String::new()),
    };
    let identity = (request.instance, request.high, request.low, request.epoch);
    let parsed = parse_payload(request.op, payload);
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(()) => return (Status::Malformed, false, empty_record(), String::new()),
    };
    engine.note_command();
    if let Some(status) = engine.admit(request.instance, request.high, request.low, request.epoch) {
        let body = engine.refusal(action, identity, status).to_string();
        return (status, false, empty_record(), body);
    }
    let (status, entered, recorded, memory, results, export, function_index) =
        perform(engine, parsed);
    let body = engine
        .outcome(Outcome {
            action,
            identity,
            status,
            entered,
            recorded: &recorded,
            memory,
            results,
            export,
            function_index,
        })
        .to_string();
    (status, entered, recorded, body)
}

enum Parsed {
    Read {
        name: String,
        offset: u32,
        length: u32,
    },
    Write {
        name: String,
        offset: u32,
        bytes: Vec<u8>,
    },
    Export {
        name: String,
        args: Vec<Val>,
    },
    Function {
        index: u32,
        args: Vec<Val>,
    },
}

fn parse_payload(op: u16, mut payload: &[u8]) -> std::result::Result<Parsed, ()> {
    match op {
        OP_READ => {
            let name = take_name(&mut payload)?;
            let offset = take_u32(&mut payload)?;
            let length = take_u32(&mut payload)?;
            if length == 0 || length > MEMORY_SLICE || !payload.is_empty() {
                return Err(());
            }
            Ok(Parsed::Read {
                name,
                offset,
                length,
            })
        }
        OP_WRITE => {
            let name = take_name(&mut payload)?;
            let offset = take_u32(&mut payload)?;
            let length = take_u32(&mut payload)?;
            if length == 0 || length > MEMORY_SLICE || payload.len() != length as usize {
                return Err(());
            }
            Ok(Parsed::Write {
                name,
                offset,
                bytes: payload.to_vec(),
            })
        }
        OP_CALL_EXPORT => {
            let name = take_name(&mut payload)?;
            let args = take_args(&mut payload)?;
            if !payload.is_empty() {
                return Err(());
            }
            Ok(Parsed::Export { name, args })
        }
        OP_CALL_FUNCTION => {
            let index = take_u32(&mut payload)?;
            let args = take_args(&mut payload)?;
            if !payload.is_empty() {
                return Err(());
            }
            Ok(Parsed::Function { index, args })
        }
        _ => Err(()),
    }
}

fn take_name(payload: &mut &[u8]) -> std::result::Result<String, ()> {
    if payload.len() < 2 {
        return Err(());
    }
    let len = u16::from_le_bytes(payload[..2].try_into().unwrap()) as usize;
    *payload = &payload[2..];
    if len == 0 || len > MAX_NAME_BYTES || payload.len() < len {
        return Err(());
    }
    let name = std::str::from_utf8(&payload[..len])
        .map_err(|_| ())?
        .to_owned();
    *payload = &payload[len..];
    if name.len() != len {
        return Err(());
    }
    Ok(name)
}

fn take_u32(payload: &mut &[u8]) -> std::result::Result<u32, ()> {
    if payload.len() < 4 {
        return Err(());
    }
    let value = u32::from_le_bytes(payload[..4].try_into().unwrap());
    *payload = &payload[4..];
    Ok(value)
}

fn take_args(payload: &mut &[u8]) -> std::result::Result<Vec<Val>, ()> {
    if payload.len() < 4 {
        return Err(());
    }
    let count = u16::from_le_bytes(payload[..2].try_into().unwrap()) as usize;
    let reserved = u16::from_le_bytes(payload[2..4].try_into().unwrap());
    *payload = &payload[4..];
    if reserved != 0 || count > MAX_ARGS {
        return Err(());
    }
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        if payload.len() < 9 {
            return Err(());
        }
        let tag = payload[0];
        let bits = u64::from_le_bytes(payload[1..9].try_into().unwrap());
        *payload = &payload[9..];
        let value = match tag {
            1 if bits <= u64::from(u32::MAX) => Val::I32(bits as u32),
            2 => Val::I64(bits),
            3 if bits <= u64::from(u32::MAX) => Val::F32(bits as u32),
            4 => Val::F64(bits),
            _ => return Err(()),
        };
        args.push(value);
    }
    Ok(args)
}

fn perform(
    engine: &mut Engine,
    parsed: Parsed,
) -> (Status, bool, Recorded, Value, Value, Value, Value) {
    match parsed {
        Parsed::Read {
            name,
            offset,
            length,
        } => {
            let Some(memory) = engine
                .memories
                .iter()
                .find(|memory| memory.name.as_deref() == Some(name.as_str()))
            else {
                return refuse_fields(Status::UnknownMemory);
            };
            if memory.shared {
                return refuse_fields(Status::Unsupported);
            }
            let end = offset as u64 + length as u64;
            if end > memory.bytes.len() as u64 {
                return refuse_fields(Status::OutOfBounds);
            }
            let start = offset as usize;
            let bytes = memory.bytes[start..start + length as usize].to_vec();
            let body = memory_json(&name, offset, &bytes, memory.bytes.len());
            (
                Status::Ok,
                false,
                empty_record(),
                body,
                Value::Null,
                Value::Null,
                Value::Null,
            )
        }
        Parsed::Write {
            name,
            offset,
            bytes,
        } => {
            let Some(memory) = engine
                .memories
                .iter_mut()
                .find(|memory| memory.name.as_deref() == Some(name.as_str()))
            else {
                return refuse_fields(Status::UnknownMemory);
            };
            if memory.shared {
                return refuse_fields(Status::Unsupported);
            }
            let end = offset as u64 + bytes.len() as u64;
            if end > memory.bytes.len() as u64 {
                return refuse_fields(Status::OutOfBounds);
            }
            let start = offset as usize;
            memory.bytes[start..start + bytes.len()].copy_from_slice(&bytes);
            let len = memory.bytes.len();
            let stored = memory.bytes[start..start + bytes.len()].to_vec();
            engine.writes = engine.writes.saturating_add(1);
            (
                Status::Ok,
                false,
                empty_record(),
                memory_json(&name, offset, &stored, len),
                Value::Null,
                Value::Null,
                Value::Null,
            )
        }
        Parsed::Export { name, args } => {
            let Some(index) = engine
                .functions
                .iter()
                .position(|func| func.export_name.as_deref() == Some(name.as_str()))
            else {
                return (
                    Status::UnknownExport,
                    false,
                    empty_record(),
                    Value::Null,
                    Value::Null,
                    json!(name),
                    Value::Null,
                );
            };
            let (status, entered, results, recorded) =
                engine.call(index as u32, &args, Source::LiveCall);
            (
                status,
                entered,
                recorded,
                Value::Null,
                results_json(results),
                json!(name),
                json!(index),
            )
        }
        Parsed::Function { index, args } => {
            let (status, entered, results, recorded) = engine.call(index, &args, Source::LiveCall);
            (
                status,
                entered,
                recorded,
                Value::Null,
                results_json(results),
                Value::Null,
                json!(index),
            )
        }
    }
}

fn refuse_fields(status: Status) -> (Status, bool, Recorded, Value, Value, Value, Value) {
    (
        status,
        false,
        empty_record(),
        Value::Null,
        Value::Null,
        Value::Null,
        Value::Null,
    )
}

fn memory_json(name: &str, offset: u32, bytes: &[u8], byte_length: usize) -> Value {
    json!({
        "name": name,
        "offset": offset,
        "length": bytes.len(),
        "byte_length": byte_length,
        "shared": false,
        "bytes": bytes,
    })
}

fn results_json(results: Option<Vec<Val>>) -> Value {
    let Some(results) = results else {
        return Value::Null;
    };
    Value::Array(
        results
            .into_iter()
            .map(|value| json!({"type": num_name(value.ty()), "bits": dec(value.bits())}))
            .collect(),
    )
}

fn reply(id: u64, status: Status, entered: bool, recorded: &Recorded, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESPONSE_HEADER + body.len());
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&status.code().to_le_bytes());
    out.extend_from_slice(&id.to_le_bytes());
    out.push(u8::from(entered));
    out.push(u8::try_from(recorded.samples.len()).unwrap_or(255));
    let flags: u16 = u16::from(recorded.gap);
    out.extend_from_slice(&flags.to_le_bytes());
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(out.len(), RESPONSE_HEADER);
    out.extend_from_slice(body);
    out
}

fn write_reply(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    write_msg(stream, bytes)
}

fn write_msg(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fd = stream.as_raw_fd();
        let mut rest = bytes;
        while !rest.is_empty() {
            let count =
                unsafe { libc::send(fd, rest.as_ptr().cast(), rest.len(), libc::MSG_NOSIGNAL) };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "live wasm socket closed",
                ));
            }
            rest = &rest[count as usize..];
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SO_NOSIGPIPE is set on the socket before any write.
        std::io::Write::write_all(stream, bytes)
    }
}

fn silence_sigpipe(stream: &UnixStream) {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let enabled: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                std::ptr::from_ref(&enabled).cast(),
                libc::socklen_t::try_from(std::mem::size_of_val(&enabled)).unwrap_or(0),
            );
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    {
        let _ = stream;
    }
}

fn same_user(stream: &UnixStream) -> bool {
    peer_uid(stream).is_some_and(|uid| uid == unsafe { libc::geteuid() })
}

fn peer_uid(stream: &UnixStream) -> Option<libc::uid_t> {
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::from_mut(&mut cred).cast(),
                &mut len,
            )
        };
        (ok == 0).then_some(cred.uid)
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ok = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        let _ = gid;
        (ok == 0).then_some(uid)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    )))]
    {
        let _ = fd;
        None
    }
}

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct LiveWasm {
    socket: Option<PathBuf>,
}

impl LiveWasm {
    pub fn new(socket: Option<PathBuf>) -> Self {
        Self { socket }
    }

    pub fn state(&self) -> Result<Value> {
        let Some(socket) = &self.socket else {
            return checked(
                "LiveWasmState",
                json!({
                    "protocol_version": 1,
                    "availability": "unsupported",
                    "reason": "browser_command_unsupported",
                    "budget": Value::Null,
                    "dispatch_samples_used": Value::Null,
                    "dispatch_gaps": Value::Null,
                    "observations_truncated": false,
                    "observations": [],
                    "attachments": [],
                }),
            );
        };
        match exchange(socket, OP_LIST, 0, 0, 0, 0, &[]) {
            Ok(value) => checked("LiveWasmState", value),
            Err(error) if error.status == 503 => checked(
                "LiveWasmState",
                json!({
                    "protocol_version": 1,
                    "availability": "unsupported",
                    "reason": "peer_unavailable",
                    "budget": Value::Null,
                    "dispatch_samples_used": Value::Null,
                    "dispatch_gaps": Value::Null,
                    "observations_truncated": false,
                    "observations": [],
                    "attachments": [],
                }),
            ),
            Err(error) => Err(error),
        }
    }

    pub fn action(&self, value: &Value) -> Result<Value> {
        validation::schema("LiveWasmAction", value, 400)?;
        let Some(socket) = &self.socket else {
            return Err(Error::new(
                503,
                "No live Wasm command peer is configured. No memory was read or written and no function was entered.",
            )
            .with_code(Code::DependencyUnavailable));
        };
        let action = value["action"].as_str().unwrap_or("");
        let instance = validation::canonical(&value["instance_id"], 64, true, "Instance ID")?;
        let high =
            validation::canonical(&value["document_token_high"], 64, false, "Document token")?;
        let low = validation::canonical(&value["document_token_low"], 64, false, "Document token")?;
        let epoch = validation::canonical(&value["document_epoch"], 64, true, "Document epoch")?;
        let (op, payload) = encode_action(action, value)?;
        let result = exchange(socket, op, instance, high, low, epoch, &payload)?;
        if result["action"] != action {
            return Err(uncertain(
                Cause::InvalidReply,
                "The live Wasm command peer reply did not match the action. Whether the command ran is unknown.",
            ));
        }
        checked("LiveWasmResult", result)
    }
}

fn checked(name: &str, value: Value) -> Result<Value> {
    validation::schema(name, &value, 500)?;
    Ok(value)
}

fn unavailable(message: &str) -> Error {
    Error::new(503, message).with_code(Code::DependencyUnavailable)
}

fn uncertain(cause: Cause, message: &str) -> Error {
    let status = if matches!(cause, Cause::Timeout) {
        408
    } else {
        422
    };
    Error::new(status, message).with_reason(Reason::uncertain(cause))
}

fn encode_action(action: &str, value: &Value) -> Result<(u16, Vec<u8>)> {
    match action {
        "read_memory" => {
            let mut payload = Vec::new();
            push_name(&mut payload, value["memory"].as_str().unwrap_or(""))?;
            push_u32(&mut payload, field_u32(value, "offset")?);
            let length = field_u32(value, "length")?;
            if length == 0 || length > MEMORY_SLICE {
                return Err(Error::bad("Memory length must be 1 to 4096"));
            }
            push_u32(&mut payload, length);
            Ok((OP_READ, payload))
        }
        "write_memory" => {
            let bytes = value["bytes"]
                .as_array()
                .ok_or_else(|| Error::bad("Memory bytes must be an array"))?;
            if bytes.is_empty() || bytes.len() > MEMORY_SLICE as usize {
                return Err(Error::bad("Memory length must be 1 to 4096"));
            }
            let mut raw = Vec::with_capacity(bytes.len());
            for byte in bytes {
                let byte = byte
                    .as_u64()
                    .filter(|byte| *byte <= 255)
                    .ok_or_else(|| Error::bad("Memory bytes must be integers from 0 to 255"))?;
                raw.push(byte as u8);
            }
            let mut payload = Vec::new();
            push_name(&mut payload, value["memory"].as_str().unwrap_or(""))?;
            push_u32(&mut payload, field_u32(value, "offset")?);
            push_u32(&mut payload, u32::try_from(raw.len()).unwrap_or(0));
            payload.extend_from_slice(&raw);
            Ok((OP_WRITE, payload))
        }
        "call_export" => {
            let mut payload = Vec::new();
            push_name(&mut payload, value["export"].as_str().unwrap_or(""))?;
            push_args(&mut payload, &value["arguments"])?;
            Ok((OP_CALL_EXPORT, payload))
        }
        "call_function" => {
            let mut payload = Vec::new();
            push_u32(&mut payload, field_u32(value, "function_index")?);
            push_args(&mut payload, &value["arguments"])?;
            Ok((OP_CALL_FUNCTION, payload))
        }
        _ => Err(Error::bad("Live Wasm action is invalid")),
    }
}

fn field_u32(value: &Value, name: &str) -> Result<u32> {
    value[name]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| Error::bad(format!("{name} is outside its range")))
}

fn push_name(payload: &mut Vec<u8>, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(Error::bad("Wasm name is empty or longer than 64 bytes"));
    }
    let len = u16::try_from(name.len()).map_err(|_| Error::bad("Wasm name is too long"))?;
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    Ok(())
}

fn push_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

fn push_args(payload: &mut Vec<u8>, value: &Value) -> Result<()> {
    let args = value
        .as_array()
        .ok_or_else(|| Error::bad("Wasm arguments must be an array"))?;
    if args.len() > MAX_ARGS {
        return Err(Error::bad("Wasm calls accept at most 16 arguments"));
    }
    let count = u16::try_from(args.len()).unwrap_or(0);
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    for arg in args {
        let tag = match arg["type"].as_str() {
            Some("i32") => 1u8,
            Some("i64") => 2,
            Some("f32") => 3,
            Some("f64") => 4,
            _ => return Err(Error::bad("Wasm argument type is invalid")),
        };
        let bits = validation::canonical(&arg["bits"], 64, false, "Argument bits")?;
        if matches!(tag, 1 | 3) && bits > u64::from(u32::MAX) {
            return Err(Error::bad("Argument bits do not fit the argument type"));
        }
        payload.push(tag);
        payload.extend_from_slice(&bits.to_le_bytes());
    }
    Ok(())
}

fn exchange(
    socket: &Path,
    op: u16,
    instance: u64,
    high: u64,
    low: u64,
    epoch: u64,
    payload: &[u8],
) -> Result<Value> {
    trusted_socket(socket)?;
    let mut stream = UnixStream::connect(socket).map_err(|_| {
        unavailable(
            "The live Wasm command peer is not available. No memory was read or written and no function was entered.",
        )
    })?;
    silence_sigpipe(&stream);
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| unavailable("The live Wasm command peer could not be timed."))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| unavailable("The live Wasm command peer could not be timed."))?;
    let id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let mut request = Vec::with_capacity(REQUEST_HEADER + payload.len());
    request.extend_from_slice(&MAGIC.to_le_bytes());
    request.extend_from_slice(&VERSION.to_le_bytes());
    request.extend_from_slice(&op.to_le_bytes());
    request.extend_from_slice(&id.to_le_bytes());
    request.extend_from_slice(&instance.to_le_bytes());
    request.extend_from_slice(&high.to_le_bytes());
    request.extend_from_slice(&low.to_le_bytes());
    request.extend_from_slice(&epoch.to_le_bytes());
    let len = u32::try_from(payload.len()).map_err(|_| Error::bad("Wasm command is too large"))?;
    request.extend_from_slice(&len.to_le_bytes());
    request.extend_from_slice(&0u32.to_le_bytes());
    request.extend_from_slice(payload);
    write_msg(&mut stream, &request).map_err(|_| {
        uncertain(
            Cause::Disconnected,
            "The live Wasm command peer disconnected after the command was sent. Whether it ran is unknown.",
        )
    })?;
    let mut header = [0u8; RESPONSE_HEADER];
    stream.read_exact(&mut header).map_err(|error| {
        let cause = if error.kind() == std::io::ErrorKind::TimedOut || error.kind() == std::io::ErrorKind::WouldBlock
        {
            Cause::Timeout
        } else {
            Cause::Disconnected
        };
        uncertain(
            cause,
            "The live Wasm command peer did not finish its reply. Whether the command ran is unknown.",
        )
    })?;
    let response = decode_response(&header).ok_or_else(|| {
        uncertain(
            Cause::InvalidReply,
            "The live Wasm command peer reply was malformed. Whether the command ran is unknown.",
        )
    })?;
    if response.id != id || response.payload_len > MAX_PAYLOAD {
        return Err(uncertain(
            Cause::InvalidReply,
            "The live Wasm command peer reply was malformed. Whether the command ran is unknown.",
        ));
    }
    let mut body = vec![0u8; response.payload_len];
    if response.payload_len > 0 {
        stream.read_exact(&mut body).map_err(|_| {
            uncertain(
                Cause::Disconnected,
                "The live Wasm command peer reply was truncated. Whether the command ran is unknown.",
            )
        })?;
    }
    if response.status == Status::Malformed {
        return Err(uncertain(
            Cause::InvalidReply,
            "The live Wasm command peer rejected the command framing. Whether a previous command ran is unchanged.",
        ));
    }
    let value: Value = serde_json::from_slice(&body).map_err(|_| {
        uncertain(
            Cause::InvalidReply,
            "The live Wasm command peer reply was not JSON. Whether the command ran is unknown.",
        )
    })?;
    if op == OP_LIST {
        return Ok(value);
    }
    if value["status"] != response.status.as_str()
        || value["entered"] != json!(response.entered)
        || value["budget_gap"] != json!(response.gap)
        || value["samples_consumed"] != json!(response.samples)
    {
        return Err(uncertain(
            Cause::InvalidReply,
            "The live Wasm command peer reply disagreed with its header. Whether the command ran is unknown.",
        ));
    }
    Ok(value)
}

struct ResponseHeader {
    id: u64,
    status: Status,
    entered: bool,
    samples: u64,
    gap: bool,
    payload_len: usize,
}

fn decode_response(bytes: &[u8]) -> Option<ResponseHeader> {
    if bytes.len() != RESPONSE_HEADER {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
    let status = Status::from_code(u16::from_le_bytes(bytes[6..8].try_into().ok()?))?;
    let id = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let entered = match bytes[16] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let samples = u64::from(bytes[17]);
    let flags = u16::from_le_bytes(bytes[18..20].try_into().ok()?);
    let payload_len = u32::from_le_bytes(bytes[20..24].try_into().ok()?) as usize;
    let reserved = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
    let pad = u32::from_le_bytes(bytes[28..32].try_into().ok()?);
    if magic != MAGIC || version != VERSION || id == 0 || reserved != 0 || pad != 0 || flags > 1 {
        return None;
    }
    Some(ResponseHeader {
        id,
        status,
        entered,
        samples,
        gap: flags == 1,
        payload_len,
    })
}

fn trusted_socket(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            unavailable("The live Wasm command socket is not in a private directory.")
        })?;
    let directory = std::fs::symlink_metadata(parent)
        .map_err(|_| unavailable("The live Wasm command socket is not available."))?;
    let socket = std::fs::symlink_metadata(path)
        .map_err(|_| unavailable("The live Wasm command socket is not available."))?;
    let uid = unsafe { libc::geteuid() };
    if directory.file_type().is_symlink()
        || !directory.is_dir()
        || directory.uid() != uid
        || directory.permissions().mode() & 0o777 != 0o700
        || socket.file_type().is_symlink()
        || !socket.file_type().is_socket()
        || socket.uid() != uid
        || socket.permissions().mode() & 0o777 != 0o600
    {
        return Err(unavailable(
            "The live Wasm command socket is not a private user socket. No command was sent.",
        ));
    }
    Ok(())
}

pub fn unsupported_state() -> Value {
    json!({
        "protocol_version": 1,
        "availability": "unsupported",
        "reason": "browser_command_unsupported",
        "budget": Value::Null,
        "dispatch_samples_used": Value::Null,
        "dispatch_gaps": Value::Null,
        "observations_truncated": false,
        "observations": [],
        "attachments": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        let bytes = wat::parse_str(FIXTURE_WAT).unwrap();
        Engine::load(
            &bytes,
            Attachment {
                instance_id: FIXTURE_INSTANCE,
                document_token_high: FIXTURE_DOCUMENT_HIGH,
                document_token_low: FIXTURE_DOCUMENT_LOW,
                document_epoch: FIXTURE_DOCUMENT_EPOCH,
            },
        )
        .unwrap()
    }

    #[test]
    fn br_table_offset_is_the_real_opcode_byte() {
        let engine = engine();
        let index = engine.br_table_function().unwrap();
        let offset = engine.functions[index as usize]
            .ops
            .iter()
            .find_map(|op| match op {
                Inst::BrTable { offset, .. } => Some(*offset),
                _ => None,
            })
            .unwrap();
        assert_eq!(engine.byte_at(offset), Some(0x0e));
    }

    #[test]
    fn page_script_and_live_call_share_budget_and_identity() {
        let mut engine = engine();
        let index = engine.br_table_function().unwrap();
        engine.run_page_script(index, &[Val::I32(1)]);
        let (status, entered, results, recorded) =
            engine.call(index, &[Val::I32(0)], Source::LiveCall);
        assert_eq!(status, Status::Ok);
        assert!(entered);
        assert_eq!(results.unwrap()[0], Val::I32(0));
        assert_eq!(recorded.samples, vec![1]);
        assert!(!recorded.gap);
        assert_eq!(engine.samples_used(), 2);
        let page = &engine.observations[0];
        let live = &engine.observations[1];
        assert_eq!(page["source"], "page_script");
        assert_eq!(live["source"], "live_call");
        assert_eq!(page["sample_index"], 0);
        assert_eq!(live["sample_index"], 1);
        for field in [
            "instance_id",
            "document_token_high",
            "document_token_low",
            "document_epoch",
            "function_index",
            "module_byte_offset",
        ] {
            assert_eq!(page[field], live[field], "{field}");
        }
        assert_eq!(page["module_byte_offset"], live["module_byte_offset"]);
        assert_eq!(
            engine.byte_at(page["module_byte_offset"].as_u64().unwrap() as u32),
            Some(0x0e)
        );
    }

    #[test]
    fn signature_mismatch_does_not_enter_or_spend_a_sample() {
        let mut engine = engine();
        let index = engine.br_table_function().unwrap();
        engine.run_page_script(index, &[Val::I32(1)]);
        let before = engine.entries();
        let (status, entered, results, recorded) =
            engine.call(index, &[Val::I64(1)], Source::LiveCall);
        assert_eq!(status, Status::SignatureMismatch);
        assert!(!entered);
        assert!(results.is_none());
        assert!(recorded.samples.is_empty());
        assert_eq!(engine.entries(), before);
        assert_eq!(engine.samples_used(), 1);
        assert_eq!(engine.observations.len(), 1);
    }

    #[test]
    fn export_call_returns_a_result_or_a_trap_or_did_not_return() {
        let mut engine = engine();
        let add = engine
            .functions
            .iter()
            .position(|func| func.export_name.as_deref() == Some("add"))
            .unwrap() as u32;
        let (status, entered, results, _) =
            engine.call(add, &[Val::I32(20), Val::I32(22)], Source::LiveCall);
        assert_eq!(
            (status, entered, results.unwrap()[0]),
            (Status::Ok, true, Val::I32(42))
        );
        let trap = engine
            .functions
            .iter()
            .position(|func| func.export_name.as_deref() == Some("trap"))
            .unwrap() as u32;
        let (status, entered, results, _) = engine.call(trap, &[], Source::LiveCall);
        assert_eq!(status, Status::Trap);
        assert!(entered && results.is_none());
        let hang = engine
            .functions
            .iter()
            .position(|func| func.export_name.as_deref() == Some("hang"))
            .unwrap() as u32;
        let (status, entered, results, _) = engine.call(hang, &[Val::I32(1)], Source::LiveCall);
        assert_eq!(status, Status::DidNotReturn);
        assert!(entered && results.is_none());
        let (status, entered, _, _) = engine.call(hang, &[], Source::LiveCall);
        assert_eq!(status, Status::SignatureMismatch);
        assert!(!entered);
    }

    #[test]
    fn write_is_visible_to_a_later_read_and_a_stale_document_is_not() {
        let mut engine = engine();
        let parsed = Parsed::Write {
            name: "memory".into(),
            offset: 8,
            bytes: vec![1, 2, 255],
        };
        let (status, _, _, memory, _, _, _) = perform(&mut engine, parsed);
        assert_eq!(status, Status::Ok);
        assert_eq!(memory["bytes"], json!([1, 2, 255]));
        let (status, _, _, memory, _, _, _) = perform(
            &mut engine,
            Parsed::Read {
                name: "memory".into(),
                offset: 8,
                length: 3,
            },
        );
        assert_eq!(status, Status::Ok);
        assert_eq!(memory["bytes"], json!([1, 2, 255]));
        let before = engine.memory("memory").unwrap();
        engine.navigate();
        let request = Request {
            id: 1,
            op: OP_WRITE,
            instance: FIXTURE_INSTANCE,
            high: FIXTURE_DOCUMENT_HIGH,
            low: FIXTURE_DOCUMENT_LOW,
            epoch: FIXTURE_DOCUMENT_EPOCH,
            payload_len: 0,
        };
        let mut payload = Vec::new();
        push_name(&mut payload, "memory").unwrap();
        push_u32(&mut payload, 8);
        push_u32(&mut payload, 1);
        payload.push(9);
        let (status, entered, _, _) = dispatch(&mut engine, &request, &payload);
        assert_eq!(status, Status::StaleDocument);
        assert!(!entered);
        assert_eq!(engine.memory("memory").unwrap(), before);
        let mut wrong = request;
        wrong.epoch = engine.attachment.document_epoch;
        wrong.instance = FIXTURE_INSTANCE + 1;
        let (status, _, _, _) = dispatch(&mut engine, &wrong, &payload);
        assert_eq!(status, Status::InstanceMismatch);
        assert_eq!(engine.memory("memory").unwrap(), before);
    }

    #[test]
    fn the_seventeenth_sample_is_a_gap_for_either_source() {
        let mut engine = engine();
        let index = engine.br_table_function().unwrap();
        for _ in 0..DISPATCH_BUDGET {
            engine.run_page_script(index, &[Val::I32(0)]);
        }
        assert_eq!(engine.samples_used(), DISPATCH_BUDGET);
        let (status, entered, _, recorded) = engine.call(index, &[Val::I32(0)], Source::LiveCall);
        assert_eq!(status, Status::Ok);
        assert!(entered);
        assert!(recorded.samples.is_empty() && recorded.gap);
        assert_eq!(engine.samples_used(), DISPATCH_BUDGET);
        assert!(engine.observations.iter().any(|row| {
            row["kind"] == "gap" && row["source"] == "live_call" && row["sample_index"].is_null()
        }));
    }
}
