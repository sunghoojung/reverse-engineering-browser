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
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
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
    /// Only active segments name a table. MVP segments omit it and mean 0.
    pub table: Option<u32>,
    pub placement: Placement,
    pub entries: Vec<Entry>,
}

type Signature = (Vec<ValType>, Vec<ValType>);
/// Matching slots and the count of non-null placed slots, shared by every
/// call site of one (table, type) so no site copies the slot list.
pub(crate) type Matching = Option<Rc<(Vec<u32>, usize)>>;

#[derive(Default)]
pub(crate) struct Tables {
    pub segments: Vec<Segment>,
    /// Real table slot to its entry after placed segments are applied in order.
    pub slots: BTreeMap<u32, BTreeMap<u32, Entry>>,
    /// Tables whose placed slots exceeded the bound and were not expanded.
    pub oversized: Vec<u32>,
    /// Function index (imports first) to type index.
    pub function_types: Vec<u32>,
    /// Type index to function signature; None for non-function types.
    pub signatures: Vec<Option<Signature>>,
    /// Declared minimum size per table index, imports first.
    pub minimums: Vec<u64>,
    /// Work parsing did: element entries read plus slots placed. The
    /// classifier charges it to the artifact meter.
    pub work: u64,
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
    /// None when the module's non-code sections do not decode.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let mut tables = Self::default();
        let mut imported_globals = 0u32;
        // Defined global index to its evaluated initializer when immutable.
        let mut constant_globals: Vec<Option<Evaluated>> = Vec::new();
        let mut segment_index = 0u32;
        let mut trapped = false;
        for payload in Parser::new(0).parse_all(bytes) {
            match payload.ok()? {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        for ty in group.ok()?.into_types() {
                            tables.signatures.push(match ty.composite_type.inner {
                                CompositeInnerType::Func(f) => {
                                    Some((f.params().to_vec(), f.results().to_vec()))
                                }
                                _ => None,
                            });
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        match import.ok()?.ty {
                            TypeRef::Func(ty) => tables.function_types.push(ty),
                            TypeRef::Global(_) => imported_globals += 1,
                            TypeRef::Table(table) => tables.minimums.push(table.initial),
                            _ => (),
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        tables.function_types.push(ty.ok()?);
                    }
                }
                Payload::TableSection(reader) => {
                    for table in reader {
                        tables.minimums.push(table.ok()?.ty.initial);
                    }
                }
                Payload::GlobalSection(reader) => {
                    for global in reader {
                        let global = global.ok()?;
                        // Earlier globals are visible to later initializers.
                        let value = (!global.ty.mutable)
                            .then(|| {
                                evaluate(&global.init_expr, imported_globals, &constant_globals)
                            })
                            .flatten();
                        constant_globals.push(value);
                    }
                }
                Payload::ElementSection(reader) => {
                    for element in reader {
                        let element = element.ok()?;
                        let mut entries = Vec::new();
                        tables.work += 1;
                        match element.items {
                            ElementItems::Functions(functions) => {
                                for function in functions {
                                    entries.push(Entry::Function(function.ok()?));
                                }
                            }
                            ElementItems::Expressions(_, expressions) => {
                                for expression in expressions {
                                    let mut reader = expression.ok()?.get_operators_reader();
                                    let mut entry = Entry::Unknown;
                                    let mut operators = 0;
                                    while !reader.eof() {
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
                                    entries.push(if operators == 1 {
                                        entry
                                    } else {
                                        Entry::Unknown
                                    });
                                }
                            }
                        }
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
                                        Ok(offset) => {
                                            let end = u64::from(offset) + entries.len() as u64;
                                            match tables.minimums.get(table as usize) {
                                                Some(minimum) if end <= *minimum => {
                                                    Placement::Placed(offset)
                                                }
                                                Some(_) => Placement::OutOfRange(offset),
                                                None => Placement::Unresolved,
                                            }
                                        }
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
                        tables.segments.push(Segment {
                            index: segment_index,
                            table,
                            placement,
                            entries,
                        });
                        segment_index += 1;
                    }
                }
                _ => (),
            }
        }
        for segment in &tables.segments {
            let (Some(table), Placement::Placed(offset)) = (segment.table, segment.placement)
            else {
                continue;
            };
            if tables.oversized.contains(&table) {
                continue;
            }
            let slots = tables.slots.entry(table).or_default();
            tables.work += segment.entries.len() as u64;
            for (position, entry) in segment.entries.iter().enumerate() {
                // Placement already checked offset + length against the minimum.
                slots.insert(offset + position as u32, *entry);
            }
            if slots.len() > MAX_TABLE_SLOTS {
                tables.slots.remove(&table);
                tables.oversized.push(table);
            }
        }
        Some(tables)
    }

    /// Distinct functions that active segments can place into `table`, placed
    /// or relative. Used for call-graph neighborhoods, never as slot numbers.
    pub fn active_functions(&self, table: u32) -> Vec<u32> {
        let mut functions = Vec::new();
        for segment in &self.segments {
            if segment.table != Some(table) {
                continue;
            }
            for function in segment.entries.iter().filter_map(|entry| entry.function()) {
                if !functions.contains(&function) {
                    functions.push(function);
                }
            }
        }
        functions
    }

    /// Bytes the slot maps, segment entries and cached matching lists keep.
    pub fn retained_bytes(&self) -> u64 {
        let slots = self.slots.values().map(BTreeMap::len).sum::<usize>();
        let entries = self
            .segments
            .iter()
            .map(|segment| segment.entries.len())
            .sum::<usize>();
        let matching = self
            .matching
            .borrow()
            .values()
            .flatten()
            .map(|matching| matching.0.len())
            .sum::<usize>();
        (slots * 24 + entries * 8 + matching * 4) as u64
    }

    /// Tables named by any active segment, in index order.
    pub fn active_tables(&self) -> Vec<u32> {
        let mut tables = self
            .segments
            .iter()
            .filter_map(|segment| segment.table)
            .collect::<Vec<_>>();
        tables.sort_unstable();
        tables.dedup();
        tables
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
        meter.charge(self.slots.get(&table).map_or(1, BTreeMap::len) as u64);
        let matching = self.scan_matching(table, type_index);
        // Released with the tables: `retained_bytes` counts every cached list.
        meter.retain(matching.as_ref().map_or(0, |matching| matching.0.len() * 4) as u64);
        self.matching
            .borrow_mut()
            .insert((table, type_index), matching.clone());
        matching
    }

    fn scan_matching(&self, table: u32, type_index: u32) -> Matching {
        self.matching_scans.set(self.matching_scans.get() + 1);
        let wanted = self.signatures.get(type_index as usize)?.as_ref()?;
        let slots = self.slots.get(&table)?;
        let mut matching = Vec::new();
        let mut populated = 0usize;
        for (slot, entry) in slots {
            if *entry == Entry::Null {
                continue;
            }
            populated += 1;
            let signature = entry
                .function()
                .and_then(|function| self.function_types.get(function as usize))
                .and_then(|ty| self.signatures.get(*ty as usize))
                .and_then(Option::as_ref);
            if signature == Some(wanted) {
                matching.push(*slot);
            }
        }
        Some(Rc::new((matching, populated)))
    }

    #[cfg(test)]
    pub fn matching_scans(&self) -> usize {
        self.matching_scans.get()
    }
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
                tables.matching_slots(0, 0, &meter).as_deref(),
                Some(&(vec![0, 1], 2))
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
        assert!(!tables.slots[&0].contains_key(&1));
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
        assert_eq!(*matching, (vec![1, 2, 9], 4));
    }
}
