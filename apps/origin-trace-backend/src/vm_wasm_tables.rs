//! Static funcref table layout of a captured module.
//!
//! Active element segments are placed at their evaluated offset, in segment
//! order, so a later segment overwrites an earlier one exactly as
//! instantiation would. An offset that reads an imported global, directly or
//! through a defined global, is only known at instantiation; those segments
//! stay relative and never receive a slot. A segment that ends past the
//! table's declared minimum is out of range and is not placed, because
//! instantiation is only guaranteed to have that many slots. Instantiation
//! applies active segments in order and traps at the first one that does not
//! fit, so every later active segment is unreached: it never writes a slot.
//! Passive and declared segments initialize no table and are kept apart.
//! Nothing here instantiates the module.
use crate::vm::dispatch_shape::{Memory, Meter};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};
use wasmparser::{
    CompositeInnerType, ConstExpr, ElementItems, ElementKind, Operator, Parser, Payload, TypeRef,
    ValType,
};

/// Tables beyond this many placed slots are not expanded into slot maps.
pub(crate) const MAX_TABLE_SLOTS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Placement {
    /// A constant offset, including through defined immutable globals.
    Placed(u32),
    /// The offset reads this imported global, so the slot base is unknown.
    Relative(u32),
    /// The segment at this offset ends past the table's declared minimum.
    OutOfRange(u32),
    /// An earlier active segment is out of range, so instantiation traps
    /// before this segment at this offset is applied.
    Unreached(u32),
    /// The offset expression is outside the evaluated constant subset.
    Unresolved,
    Passive,
    Declared,
}

impl Placement {
    pub fn label(self) -> &'static str {
        match self {
            Self::Placed(_) => "placed",
            Self::Relative(_) => "relative",
            Self::OutOfRange(_) => "out-of-range",
            Self::Unreached(_) => "unreached",
            Self::Unresolved => "unresolved",
            Self::Passive => "passive",
            Self::Declared => "declared",
        }
    }
}

/// One element item. A `ref.null` empties its slot; any other non-`ref.func`
/// expression stores a reference whose function is not statically known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Function(u32),
    Null,
    Unknown,
}

impl Entry {
    pub fn function(self) -> Option<u32> {
        match self {
            Self::Function(function) => Some(function),
            _ => None,
        }
    }
}

pub(crate) struct Segment {
    pub index: u32,
    pub placement: Placement,
    pub entry_count: usize,
}

type Signature = (Vec<ValType>, Vec<ValType>);
/// Matching slots and the count of non-null placed slots, shared by every
/// call site of one (table, type) so no site copies the slot list.
pub(crate) struct MatchingSlots(pub Vec<u32>, pub usize, Memory);
pub(crate) type Matching = Option<Rc<MatchingSlots>>;
type SlotGroups = HashMap<(u32, u32), Rc<MatchingSlots>>;

pub(crate) struct Tables {
    pub segments: Vec<Segment>,
    /// Real table slot to its entry after placed segments are applied in order.
    pub slots: BTreeMap<u32, Vec<(u32, Entry)>>,
    /// Tables whose placed slots exceeded the bound and were not expanded.
    pub oversized: Vec<u32>,
    /// Function index (imports first) to type index.
    pub function_types: Vec<u32>,
    /// Type index to function signature; None for non-function types.
    pub signatures: Vec<Option<Signature>>,
    /// Declared minimum size per table index, imports first.
    pub minimums: Vec<u64>,
    active: BTreeMap<u32, Vec<u32>>,
    by_table: BTreeMap<u32, Vec<usize>>,
    memory: Memory,
    signature_ids: Vec<Option<u32>>,
    groups: OnceCell<SlotGroups>,
    populated: HashMap<u32, usize>,
    /// One slot scan per (table, type); a module reuses few call types.
    matching: RefCell<BTreeMap<(u32, u32), Matching>>,
    matching_scans: Cell<usize>,
}

#[derive(Clone, Copy)]
enum Evaluated {
    Value(i64),
    Imported(u32),
}

impl Tables {
    #[cfg(test)]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        Self::parse_under(bytes, &Meter::new())
    }

    pub fn parse_under(bytes: &[u8], meter: &Meter) -> Option<Self> {
        let mut tables = Self {
            segments: Vec::new(),
            slots: BTreeMap::new(),
            oversized: Vec::new(),
            function_types: Vec::new(),
            signatures: Vec::new(),
            minimums: Vec::new(),
            matching: RefCell::new(BTreeMap::new()),
            matching_scans: Cell::new(0),
            active: BTreeMap::new(),
            by_table: BTreeMap::new(),
            memory: Memory::new(meter),
            signature_ids: Vec::new(),
            groups: OnceCell::new(),
            populated: HashMap::new(),
        };
        if !meter.charge(bytes.len() as u64) {
            return None;
        }
        let temporary = Memory::new(meter);
        let mut seen = HashSet::new();
        let mut imported_globals = 0u32;
        let mut constant_globals: Vec<Option<Evaluated>> = Vec::new();
        let mut trapped = false;
        for payload in Parser::new(0).parse_all(bytes) {
            if !meter.charge(1) {
                return None;
            }
            match payload.ok()? {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        for ty in group.ok()?.into_types() {
                            let signature = match ty.composite_type.inner {
                                CompositeInnerType::Func(f) => {
                                    let count = f.params().len() + f.results().len();
                                    if !meter.charge(count as u64 + 1)
                                        || !tables
                                            .memory
                                            .keep((count * std::mem::size_of::<ValType>()) as u64)
                                    {
                                        return None;
                                    }
                                    Some((f.params().to_vec(), f.results().to_vec()))
                                }
                                _ => None,
                            };
                            if !tables.memory.push(&mut tables.signatures, signature) {
                                return None;
                            }
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        if !meter.charge(1) {
                            return None;
                        }
                        let kept = match import.ok()?.ty {
                            TypeRef::Func(ty) => tables.memory.push(&mut tables.function_types, ty),
                            TypeRef::Global(_) => {
                                imported_globals += 1;
                                true
                            }
                            TypeRef::Table(table) => {
                                tables.memory.push(&mut tables.minimums, table.initial)
                            }
                            _ => true,
                        };
                        if !kept {
                            return None;
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        if !meter.charge(1)
                            || !tables.memory.push(&mut tables.function_types, ty.ok()?)
                        {
                            return None;
                        }
                    }
                }
                Payload::TableSection(reader) => {
                    for table in reader {
                        if !meter.charge(1)
                            || !tables
                                .memory
                                .push(&mut tables.minimums, table.ok()?.ty.initial)
                        {
                            return None;
                        }
                    }
                }
                Payload::GlobalSection(reader) => {
                    for global in reader {
                        let global = global.ok()?;
                        let value = (!global.ty.mutable)
                            .then(|| {
                                evaluate(&global.init_expr, imported_globals, &constant_globals)
                            })
                            .flatten();
                        if !meter.charge(1) || !temporary.push(&mut constant_globals, value) {
                            return None;
                        }
                    }
                }
                Payload::ElementSection(reader) => {
                    for element in reader {
                        if !meter.charge(1) {
                            return None;
                        }
                        let element = element.ok()?;
                        let entry_count = match &element.items {
                            ElementItems::Functions(r) => r.count(),
                            ElementItems::Expressions(_, r) => r.count(),
                        } as usize;
                        let (table, placement) = match element.kind {
                            ElementKind::Active {
                                table_index,
                                offset_expr,
                            } => {
                                let table = table_index.unwrap_or(0);
                                let placement = match evaluate(
                                    &offset_expr,
                                    imported_globals,
                                    &constant_globals,
                                ) {
                                    Some(Evaluated::Value(value)) => match u32::try_from(value) {
                                        Ok(offset) => match tables.minimums.get(table as usize) {
                                            Some(minimum)
                                                if u64::from(offset) + entry_count as u64
                                                    <= *minimum =>
                                            {
                                                Placement::Placed(offset)
                                            }
                                            Some(_) => Placement::OutOfRange(offset),
                                            None => Placement::Unresolved,
                                        },
                                        Err(_) => Placement::Unresolved,
                                    },
                                    Some(Evaluated::Imported(global)) => {
                                        Placement::Relative(global)
                                    }
                                    None => Placement::Unresolved,
                                };
                                let placement = match placement {
                                    Placement::Placed(offset) | Placement::OutOfRange(offset)
                                        if trapped =>
                                    {
                                        Placement::Unreached(offset)
                                    }
                                    other => other,
                                };
                                trapped |= matches!(placement, Placement::OutOfRange(_));
                                (Some(table), placement)
                            }
                            ElementKind::Passive => (None, Placement::Passive),
                            ElementKind::Declared => (None, Placement::Declared),
                        };
                        let segment_index = tables.segments.len();
                        if let Some(table) = table {
                            if !tables.by_table.contains_key(&table) && !tables.memory.keep(256) {
                                return None;
                            }
                            if !tables
                                .memory
                                .push(tables.by_table.entry(table).or_default(), segment_index)
                            {
                                return None;
                            }
                        }
                        if !tables.memory.push(
                            &mut tables.segments,
                            Segment {
                                index: segment_index as u32,
                                placement,
                                entry_count,
                            },
                        ) {
                            return None;
                        }
                        let mut add = |position: usize, entry: Entry| -> Option<()> {
                            if !meter.charge(1) {
                                return None;
                            }
                            if let Some(table) = table {
                                if let Some(function) = entry.function()
                                    && !seen.contains(&(table, function))
                                {
                                    if !temporary.keep(48)
                                        || !tables.memory.keep(64)
                                        || !tables
                                            .memory
                                            .push(tables.active.entry(table).or_default(), function)
                                    {
                                        return None;
                                    }
                                    seen.insert((table, function));
                                }
                                if let Placement::Placed(offset) = placement {
                                    if !tables.slots.contains_key(&table)
                                        && !tables.memory.keep(128)
                                    {
                                        return None;
                                    }
                                    if !tables.memory.push(
                                        tables.slots.entry(table).or_default(),
                                        (offset + position as u32, entry),
                                    ) {
                                        return None;
                                    }
                                }
                            }
                            Some(())
                        };
                        match element.items {
                            ElementItems::Functions(functions) => {
                                for (position, function) in functions.into_iter().enumerate() {
                                    add(position, Entry::Function(function.ok()?))?;
                                }
                            }
                            ElementItems::Expressions(_, expressions) => {
                                for (position, expression) in expressions.into_iter().enumerate() {
                                    let mut reader = expression.ok()?.get_operators_reader();
                                    let mut entry = Entry::Unknown;
                                    let mut operators = 0;
                                    while !reader.eof() {
                                        if !meter.charge(1) {
                                            return None;
                                        }
                                        match reader.read().ok()? {
                                            Operator::End => (),
                                            Operator::RefFunc { function_index } => {
                                                entry = Entry::Function(function_index);
                                                operators += 1;
                                            }
                                            Operator::RefNull { .. } => {
                                                entry = Entry::Null;
                                                operators += 1;
                                            }
                                            _ => operators += 2,
                                        }
                                    }
                                    add(
                                        position,
                                        if operators == 1 {
                                            entry
                                        } else {
                                            Entry::Unknown
                                        },
                                    )?;
                                }
                            }
                        }
                    }
                }
                _ => (),
            }
        }
        for (table, slots) in &mut tables.slots {
            sort_slots(slots, meter)?;
            if slots.len() > MAX_TABLE_SLOTS {
                slots.clear();
                if !tables.memory.push(&mut tables.oversized, *table) {
                    return None;
                }
            }
        }
        let mut signatures = HashMap::new();
        for signature in &tables.signatures {
            let id = if let Some(signature) = signature {
                if !meter.charge((signature.0.len() + signature.1.len()) as u64 + 1)
                    || !temporary.keep(96)
                {
                    return None;
                }
                let next = signatures.len() as u32;
                Some(*signatures.entry(signature).or_insert(next))
            } else {
                None
            };
            if !tables.memory.push(&mut tables.signature_ids, id) {
                return None;
            }
        }
        for (table, slots) in &tables.slots {
            if !meter.charge(slots.len() as u64) || !tables.memory.keep(96) {
                return None;
            }
            tables.populated.insert(
                *table,
                slots.iter().filter(|(_, e)| *e != Entry::Null).count(),
            );
        }
        Some(tables)
    }

    /// All table targets are indexed in the element stream's single pass.
    pub fn active_functions(&self) -> &BTreeMap<u32, Vec<u32>> {
        &self.active
    }

    pub fn segments_for(&self, table: u32) -> &[usize] {
        self.by_table.get(&table).map_or(&[], Vec::as_slice)
    }

    pub fn active_tables(&self) -> impl Iterator<Item = u32> + '_ {
        self.by_table.keys().copied()
    }

    /// Placed slots whose function has exactly the signature of `type_index`,
    /// and the count of non-null placed slots. Memoized per (table, type):
    /// the scan is charged to the meter once, and every site shares it.
    pub fn matching_slots(
        &self,
        table: u32,
        type_index: u32,
        meter: &crate::vm::dispatch_shape::Meter,
    ) -> Matching {
        if let Some(matching) = self.matching.borrow().get(&(table, type_index)) {
            meter.charge(1);
            return matching.clone();
        }
        let wanted = *self.signature_ids.get(type_index as usize)?.as_ref()?;
        let populated = *self.populated.get(&table)?;
        let groups = self.groups.get_or_init(|| {
            self.matching_scans.set(self.matching_scans.get() + 1);
            let mut groups = HashMap::<(u32, u32), MatchingSlots>::new();
            for (table, slots) in &self.slots {
                for (slot, entry) in slots {
                    if !meter.charge(1) {
                        break;
                    }
                    let signature = entry
                        .function()
                        .and_then(|f| self.function_types.get(f as usize))
                        .and_then(|ty| self.signature_ids.get(*ty as usize))
                        .and_then(|id| *id);
                    let Some(signature) = signature else {
                        continue;
                    };
                    if !groups.contains_key(&(*table, signature)) && !self.memory.keep(192) {
                        break;
                    }
                    let group = groups.entry((*table, signature)).or_insert_with(|| {
                        MatchingSlots(Vec::new(), self.populated[table], Memory::new(meter))
                    });
                    if !group.2.push(&mut group.0, *slot) {
                        break;
                    }
                }
            }
            groups
                .into_iter()
                .map(|(key, slots)| (key, Rc::new(slots)))
                .collect()
        });
        if meter.exhausted() {
            return None;
        }
        let matching =
            Some(groups.get(&(table, wanted)).cloned().unwrap_or_else(|| {
                Rc::new(MatchingSlots(Vec::new(), populated, Memory::new(meter)))
            }));
        if !self.memory.keep(128) {
            return None;
        }
        self.matching
            .borrow_mut()
            .insert((table, type_index), matching.clone());
        matching
    }

    #[cfg(test)]
    pub fn matching_scans(&self) -> usize {
        self.matching_scans.get()
    }
}

/// Stable four-pass radix ordering preserves segment application order at
/// equal slots. Compact in place, retaining the last assignment at each slot.
fn sort_slots(slots: &mut Vec<(u32, Entry)>, meter: &Meter) -> Option<()> {
    if slots.len() < 2 {
        return Some(());
    }
    if !meter.charge(slots.len() as u64 * 2) {
        return None;
    }
    if !slots.windows(2).all(|pair| pair[0].0 <= pair[1].0) {
        let temporary = Memory::new(meter);
        if !meter.charge(slots.len() as u64 * 12)
            || !temporary.keep((slots.len() * std::mem::size_of::<(u32, Entry)>()) as u64)
        {
            return None;
        }
        let mut scratch = vec![(0, Entry::Unknown); slots.len()];
        for shift in [0, 8, 16, 24] {
            let mut counts = [0usize; 256];
            for (slot, _) in slots.iter() {
                counts[((slot >> shift) & 255) as usize] += 1;
            }
            let mut prefix = 0;
            for count in &mut counts {
                let length = *count;
                *count = prefix;
                prefix += length;
            }
            for &entry in slots.iter() {
                let bucket = ((entry.0 >> shift) & 255) as usize;
                scratch[counts[bucket]] = entry;
                counts[bucket] += 1;
            }
            slots.copy_from_slice(&scratch);
        }
    }
    let mut length = 0;
    for read in 0..slots.len() {
        if length > 0 && slots[length - 1].0 == slots[read].0 {
            slots[length - 1] = slots[read];
        } else {
            slots[length] = slots[read];
            length += 1;
        }
    }
    slots.truncate(length);
    Some(())
}

/// Evaluate the constant-expression subset used for offsets: integer
/// constants, global.get, and extended-const add, sub and mul.
fn evaluate(
    expr: &ConstExpr<'_>,
    imported_globals: u32,
    constants: &[Option<Evaluated>],
) -> Option<Evaluated> {
    let mut reader = expr.get_operators_reader();
    let mut stack: Vec<Evaluated> = Vec::new();
    while !reader.eof() {
        match reader.read().ok()? {
            Operator::I32Const { value } => stack.push(Evaluated::Value(i64::from(value as u32))),
            Operator::I64Const { value } => stack.push(Evaluated::Value(value)),
            Operator::GlobalGet { global_index } => {
                if global_index < imported_globals {
                    stack.push(Evaluated::Imported(global_index));
                } else {
                    let defined = (global_index - imported_globals) as usize;
                    stack.push((*constants.get(defined)?)?);
                }
            }
            op @ (Operator::I32Add
            | Operator::I32Sub
            | Operator::I32Mul
            | Operator::I64Add
            | Operator::I64Sub
            | Operator::I64Mul) => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                stack.push(match (left, right) {
                    (Evaluated::Value(left), Evaluated::Value(right)) => {
                        let value = match op {
                            Operator::I32Add | Operator::I64Add => left.wrapping_add(right),
                            Operator::I32Sub | Operator::I64Sub => left.wrapping_sub(right),
                            _ => left.wrapping_mul(right),
                        };
                        Evaluated::Value(
                            if matches!(op, Operator::I32Add | Operator::I32Sub | Operator::I32Mul)
                            {
                                i64::from(value as u32)
                            } else {
                                value
                            },
                        )
                    }
                    (Evaluated::Imported(global), _) | (_, Evaluated::Imported(global)) => {
                        Evaluated::Imported(global)
                    }
                });
            }
            Operator::End => break,
            _ => return None,
        }
    }
    let value = stack.pop()?;
    stack.is_empty().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review regression: a defined global's initializer is evaluated with
    /// the globals before it, so an offset through it is placed or relative.
    #[test]
    fn defined_global_offsets_follow_their_initializers() {
        let bytes = wat::parse_str(
            r#"(module
              (import "env" "base" (global $base i32))
              (table 16 funcref)
              (global $k0 i32 (i32.const 3))
              (global $k1 i32 (global.get $k0))
              (global $moved i32 (global.get $base))
              (func $a)
              (elem (global.get $k1) func $a)
              (elem (global.get $moved) func $a))"#,
        )
        .unwrap();
        let tables = Tables::parse(&bytes).unwrap();
        assert_eq!(tables.segments[0].placement, Placement::Placed(3));
        assert_eq!(tables.segments[1].placement, Placement::Relative(0));
    }

    /// Review regression: a non-`ref.func` item does not erase a placed
    /// function slot, and only `ref.null` makes a slot empty.
    #[test]
    fn non_function_items_do_not_erase_placed_slots() {
        let bytes = wat::parse_str(
            r#"(module
              (import "env" "f" (global $f funcref))
              (table 8 funcref)
              (func $a) (func $b)
              (elem (i32.const 0) func $a $b)
              (elem (i32.const 1) funcref (global.get $f))
              (elem (i32.const 0) funcref (ref.null func)))"#,
        )
        .unwrap();
        let tables = Tables::parse(&bytes).unwrap();
        // Slot 0 is null, slot 1 holds an unknown funcref.
        assert_eq!(
            tables.slots[&0]
                .iter()
                .map(|(s, e)| (*s, *e))
                .collect::<Vec<_>>(),
            [(0, Entry::Null), (1, Entry::Unknown)]
        );
    }

    /// Review regression: a segment past the table's declared minimum is not
    /// placed.
    #[test]
    fn offsets_beyond_the_table_minimum_are_not_placed() {
        let bytes = wat::parse_str(
            r#"(module
              (table 4 funcref)
              (func $a) (func $b)
              (elem (i32.const 3) func $a $b))"#,
        )
        .unwrap();
        let tables = Tables::parse(&bytes).unwrap();
        assert_eq!(tables.segments[0].placement, Placement::OutOfRange(3));
        assert!(tables.slots.get(&0).is_none_or(|slots| slots.is_empty()));
    }

    /// Review regression: matching slots are scanned once per (table, type),
    /// not once per call site.
    #[test]
    fn matching_slots_scan_once_per_table_and_type() {
        let bytes = wat::parse_str(
            r#"(module
              (type $t (func (param i32) (result i32)))
              (table 4 funcref)
              (func $a (type $t) (local.get 0))
              (elem (i32.const 0) func $a $a))"#,
        )
        .unwrap();
        let tables = Tables::parse(&bytes).unwrap();
        let meter = crate::vm::dispatch_shape::Meter::new();
        for _ in 0..100 {
            assert_eq!(
                tables
                    .matching_slots(0, 0, &meter)
                    .map(|m| (m.0.clone(), m.1)),
                Some((vec![0, 1], 2))
            );
        }
        assert_eq!(tables.matching_scans(), 1);
    }

    /// Review regression: instantiation stops at the first segment that does
    /// not fit, so later segments never place a slot.
    #[test]
    fn segments_after_an_out_of_range_segment_are_not_placed() {
        let bytes = wat::parse_str(
            r#"(module
              (table 4 funcref)
              (func $a) (func $b)
              (elem (i32.const 0) func $a)
              (elem (i32.const 3) func $a $b)
              (elem (i32.const 1) func $b))"#,
        )
        .unwrap();
        let tables = Tables::parse(&bytes).unwrap();
        assert_eq!(tables.segments[0].placement, Placement::Placed(0));
        assert_eq!(tables.segments[1].placement, Placement::OutOfRange(3));
        assert_eq!(tables.segments[2].placement, Placement::Unreached(1));
        assert!(
            tables.slots[&0]
                .binary_search_by_key(&1, |(slot, _)| *slot)
                .is_err()
        );
    }

    #[test]
    fn segments_place_at_offsets_overwrite_in_order_and_keep_relative_apart() {
        let bytes = wat::parse_str(
            r#"(module
              (import "env" "base" (global $base i32))
              (type $t (func (param i32) (result i32)))
              (type $u (func))
              (table 16 funcref)
              (global $k i32 (i32.const 9))
              (func $a (type $t) local.get 0)
              (func $b (type $t) local.get 0)
              (func $c (type $u))
              (elem (i32.const 1) func $a $b $c)
              (elem (i32.const 2) func $a)
              (elem (global.get $k) func $b)
              (elem (global.get $base) func $c)
              (elem func $a)
              (elem declare func $b))"#,
        )
        .unwrap();
        let tables = Tables::parse(&bytes).unwrap();
        let placements = tables
            .segments
            .iter()
            .map(|segment| segment.placement)
            .collect::<Vec<_>>();
        assert_eq!(
            placements,
            [
                Placement::Placed(1),
                Placement::Placed(2),
                Placement::Placed(9),
                Placement::Relative(0),
                Placement::Passive,
                Placement::Declared,
            ]
        );
        let slots = &tables.slots[&0];
        assert_eq!(
            slots.iter().map(|(s, f)| (*s, *f)).collect::<Vec<_>>(),
            [
                (1, Entry::Function(0)),
                (2, Entry::Function(0)),
                (3, Entry::Function(2)),
                (9, Entry::Function(1))
            ]
        );
        // Four populated placed slots plus one relative entry.
        let meter = crate::vm::dispatch_shape::Meter::new();
        let matching = tables.matching_slots(0, 0, &meter).unwrap();
        assert_eq!((&matching.0, matching.1), (&vec![1, 2, 9], 4));
    }
}
