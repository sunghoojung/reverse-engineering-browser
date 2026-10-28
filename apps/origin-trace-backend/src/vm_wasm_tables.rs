//! Static funcref table layout of a captured module.
//!
//! Active element segments are placed at their evaluated offset, in segment
//! order, so a later segment overwrites an earlier one exactly as
//! instantiation would. An offset that reads an imported global is only known
//! at instantiation; those segments stay relative and never receive a slot.
//! Passive and declared segments initialize no table and are kept apart.
//! Nothing here instantiates the module.
use std::collections::BTreeMap;
use wasmparser::{
    CompositeInnerType, ConstExpr, ElementItems, ElementKind, Operator, Parser, Payload, TypeRef,
    ValType,
};

/// Tables beyond this many populated slots are not expanded into slot maps.
pub(crate) const MAX_TABLE_SLOTS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Placement {
    /// A constant offset, including a defined immutable constant global.
    Placed(u32),
    /// The offset reads this imported global, so the slot base is unknown.
    Relative(u32),
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
            Self::Unresolved => "unresolved",
            Self::Passive => "passive",
            Self::Declared => "declared",
        }
    }
}

pub(crate) struct Segment {
    pub index: u32,
    /// Only active segments name a table. MVP segments omit it and mean 0.
    pub table: Option<u32>,
    pub placement: Placement,
    /// Each entry's function, or None for a null reference or other expression.
    pub entries: Vec<Option<u32>>,
}

#[derive(Default)]
pub(crate) struct Tables {
    pub segments: Vec<Segment>,
    /// Real table slot to function after placed segments are applied in order.
    pub slots: BTreeMap<u32, BTreeMap<u32, Option<u32>>>,
    /// Tables whose placed slots exceeded the bound and were not expanded.
    pub oversized: Vec<u32>,
    /// Function index (imports first) to type index.
    pub function_types: Vec<u32>,
    /// Type index to function signature; None for non-function types.
    pub signatures: Vec<Option<(Vec<ValType>, Vec<ValType>)>>,
}

impl Tables {
    /// None when the module's non-code sections do not decode.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let mut tables = Self::default();
        let mut imported_globals = 0u32;
        // Defined global index to its constant i32 initializer when immutable.
        let mut constant_globals: Vec<Option<i64>> = Vec::new();
        let mut segment_index = 0u32;
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
                            _ => (),
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        tables.function_types.push(ty.ok()?);
                    }
                }
                Payload::GlobalSection(reader) => {
                    for global in reader {
                        let global = global.ok()?;
                        constant_globals.push(if global.ty.mutable {
                            None
                        } else {
                            match evaluate(&global.init_expr, imported_globals, &[]) {
                                Some(Evaluated::Value(value)) => Some(value),
                                _ => None,
                            }
                        });
                    }
                }
                Payload::ElementSection(reader) => {
                    for element in reader {
                        let element = element.ok()?;
                        let (table, placement) = match element.kind {
                            ElementKind::Active {
                                table_index,
                                offset_expr,
                            } => (
                                Some(table_index.unwrap_or(0)),
                                match evaluate(&offset_expr, imported_globals, &constant_globals) {
                                    Some(Evaluated::Value(value)) => u32::try_from(value)
                                        .map_or(Placement::Unresolved, Placement::Placed),
                                    Some(Evaluated::Imported(global)) => {
                                        Placement::Relative(global)
                                    }
                                    None => Placement::Unresolved,
                                },
                            ),
                            ElementKind::Passive => (None, Placement::Passive),
                            ElementKind::Declared => (None, Placement::Declared),
                        };
                        let mut entries = Vec::new();
                        match element.items {
                            ElementItems::Functions(functions) => {
                                for function in functions {
                                    entries.push(Some(function.ok()?));
                                }
                            }
                            ElementItems::Expressions(_, expressions) => {
                                for expression in expressions {
                                    let mut reader = expression.ok()?.get_operators_reader();
                                    let mut function = None;
                                    while !reader.eof() {
                                        if let Operator::RefFunc { function_index } =
                                            reader.read().ok()?
                                        {
                                            function = Some(function_index);
                                        }
                                    }
                                    entries.push(function);
                                }
                            }
                        }
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
            for (position, function) in segment.entries.iter().enumerate() {
                let Some(slot) = u32::try_from(position)
                    .ok()
                    .and_then(|position| offset.checked_add(position))
                else {
                    break;
                };
                slots.insert(slot, *function);
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
            for function in segment.entries.iter().flatten() {
                if !functions.contains(function) {
                    functions.push(*function);
                }
            }
        }
        functions
    }

    /// Static funcref fanout: populated placed slots plus funcref entries of
    /// relative or unresolved active segments, which cannot overlap-check.
    pub fn fanout(&self) -> BTreeMap<u32, u32> {
        let mut fanout = BTreeMap::<u32, u32>::new();
        for (table, slots) in &self.slots {
            let populated = slots.values().filter(|function| function.is_some()).count();
            fanout.insert(*table, u32::try_from(populated).unwrap_or(u32::MAX));
        }
        for segment in &self.segments {
            let Some(table) = segment.table else {
                continue;
            };
            let unplaced = matches!(
                segment.placement,
                Placement::Relative(_) | Placement::Unresolved
            ) || self.oversized.contains(&table);
            let entry = fanout.entry(table).or_insert(0);
            if unplaced {
                let count = segment.entries.iter().flatten().count();
                *entry = entry.saturating_add(u32::try_from(count).unwrap_or(u32::MAX));
            }
        }
        fanout
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

    /// Placed slots whose function has exactly the signature of `type_index`.
    /// Returns (matching slots, populated placed slot count).
    pub fn matching_slots(&self, table: u32, type_index: u32) -> Option<(Vec<u32>, usize)> {
        let wanted = self.signatures.get(type_index as usize)?.as_ref()?;
        let slots = self.slots.get(&table)?;
        let mut matching = Vec::new();
        let mut populated = 0usize;
        for (slot, function) in slots {
            let Some(function) = function else {
                continue;
            };
            populated += 1;
            let signature = self
                .function_types
                .get(*function as usize)
                .and_then(|ty| self.signatures.get(*ty as usize))
                .and_then(Option::as_ref);
            if signature == Some(wanted) {
                matching.push(*slot);
            }
        }
        Some((matching, populated))
    }
}

enum Evaluated {
    Value(i64),
    Imported(u32),
}

/// Evaluate the constant-expression subset used for offsets: integer
/// constants, global.get, and extended-const add, sub and mul.
fn evaluate(
    expr: &ConstExpr<'_>,
    imported_globals: u32,
    constants: &[Option<i64>],
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
                    stack.push(Evaluated::Value((*constants.get(defined)?)?));
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
            [(1, Some(0)), (2, Some(0)), (3, Some(2)), (9, Some(1))]
        );
        // Four populated placed slots plus one relative entry.
        assert_eq!(tables.fanout()[&0], 5);
        let (matching, populated) = tables.matching_slots(0, 0).unwrap();
        assert_eq!((matching, populated), (vec![1, 2, 9], 4));
    }
}
