//! Primitive coercion rules and an explicitly assumed standard object model.
//! https://tc39.es/ecma262/2024/multipage/abstract-operations.html
use super::MAX_VALUE_BYTES;
use std::mem::size_of;

const MAX_ALLOCATED_BYTES: usize = 8 * 1024 * 1024;
const MAX_ALLOCATED_NODES: usize = 250_000;
const MAX_VALUE_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq)]
struct Cost {
    bytes: usize,
    nodes: usize,
    depth: usize,
}

// Monotonic allocation/work allowance shared by the complete Folder. Dropping
// a value does not refund it. Reservations happen before owned copies or growth.
pub(super) struct ValueBudget {
    bytes: usize,
    nodes: usize,
    depth: usize,
    pub(super) exhausted: bool,
}
impl Default for ValueBudget {
    fn default() -> Self {
        Self {
            bytes: MAX_ALLOCATED_BYTES,
            nodes: MAX_ALLOCATED_NODES,
            depth: MAX_VALUE_DEPTH,
            exhausted: false,
        }
    }
}
impl ValueBudget {
    #[cfg(test)]
    pub(super) fn limited(bytes: usize, nodes: usize, depth: usize) -> Self {
        Self {
            bytes,
            nodes,
            depth,
            exhausted: false,
        }
    }
    pub(super) fn reserve(&mut self, nodes: usize, bytes: usize) -> Option<()> {
        if self.exhausted || nodes > self.nodes || bytes > self.bytes {
            self.exhausted = true;
            return None;
        }
        self.nodes -= nodes;
        self.bytes -= bytes;
        Some(())
    }
    pub(super) fn array(&mut self, length: usize) -> Option<Vec<Option<Value>>> {
        let bytes = length
            .checked_mul(size_of::<Option<Value>>())?
            .checked_add(size_of::<Value>())?;
        self.reserve(1 + length, bytes)?;
        Some(Vec::with_capacity(length))
    }
}

// No Clone implementation: every deep copy must name the shared allowance.
#[derive(Debug, PartialEq)]
pub(super) enum Value {
    Number(f64),
    String(String),
    Bool(bool),
    Null,
    Undefined,
    Array(ArrayValue),
    EmptyObject,
}
#[derive(Debug, PartialEq)]
pub(super) struct ArrayValue {
    values: Vec<Option<Value>>,
    cost: Cost,
}
impl std::ops::Deref for ArrayValue {
    type Target = [Option<Value>];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl ArrayValue {
    pub(super) fn into_values(self) -> Vec<Option<Value>> {
        self.values
    }
}

impl Value {
    fn cost(&self) -> Cost {
        match self {
            Self::Array(array) => array.cost,
            _ => Cost {
                bytes: size_of::<Self>()
                    + match self {
                        Self::String(s) => s.len(),
                        _ => 0,
                    },
                nodes: 1,
                depth: 1,
            },
        }
    }
    pub(super) fn try_clone(&self, budget: &mut ValueBudget) -> Option<Self> {
        let cost = self.cost();
        if cost.depth > budget.depth {
            budget.exhausted = true;
            return None;
        }
        budget.reserve(cost.nodes, cost.bytes)?;
        Some(self.clone_reserved())
    }
    // Only called after a reservation for the complete tree. Cached costs make
    // the check O(1); the subsequent recursive copy has bounded nodes and depth.
    fn clone_reserved(&self) -> Self {
        match self {
            Self::Number(n) => Self::Number(*n),
            Self::String(s) => Self::String(s.clone()),
            Self::Bool(b) => Self::Bool(*b),
            Self::Null => Self::Null,
            Self::Undefined => Self::Undefined,
            Self::EmptyObject => Self::EmptyObject,
            Self::Array(a) => Self::Array(ArrayValue {
                cost: a.cost,
                values: a
                    .values
                    .iter()
                    .map(|value| value.as_ref().map(Self::clone_reserved))
                    .collect(),
            }),
        }
    }
    pub(super) fn string(text: &str, budget: &mut ValueBudget) -> Option<Self> {
        if text.len() > MAX_VALUE_BYTES {
            return None;
        }
        budget.reserve(1, size_of::<Self>() + text.len())?;
        Some(Self::String(text.to_string()))
    }
    pub(super) fn character(character: char, budget: &mut ValueBudget) -> Option<Self> {
        budget.reserve(1, size_of::<Self>() + 8)?;
        Some(Self::String(character.to_string()))
    }
    // `values` must have been created with ValueBudget::array before filling.
    pub(super) fn array(values: Vec<Option<Self>>, budget: &mut ValueBudget) -> Option<Self> {
        let mut cost = Cost {
            bytes: size_of::<Self>() + values.len() * size_of::<Option<Self>>(),
            nodes: 1 + values.len(),
            depth: 1,
        };
        for value in values.iter().flatten() {
            let child = value.cost();
            cost.bytes = cost.bytes.checked_add(child.bytes)?;
            cost.nodes = cost.nodes.checked_add(child.nodes)?;
            cost.depth = cost.depth.max(child.depth + 1);
        }
        if cost.depth > budget.depth {
            budget.exhausted = true;
            return None;
        }
        Some(Self::Array(ArrayValue { values, cost }))
    }
    pub(super) fn is_primitive(&self) -> bool {
        !matches!(self, Self::Array(_) | Self::EmptyObject)
    }
    pub(super) fn truthy(&self) -> bool {
        match self {
            Self::Number(n) => *n != 0.0 && !n.is_nan(),
            Self::String(s) => !s.is_empty(),
            Self::Bool(b) => *b,
            Self::Null | Self::Undefined => false,
            Self::Array(_) | Self::EmptyObject => true,
        }
    }
    pub(super) fn number(&self, budget: &mut ValueBudget) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Bool(b) => Some(f64::from(u8::from(*b))),
            Self::Null => Some(0.0),
            Self::Undefined => Some(f64::NAN),
            Self::String(s) => string_number(s),
            Self::Array(_) | Self::EmptyObject => string_number(&self.js_string(budget)?),
        }
    }
    pub(super) fn primitive(&self, budget: &mut ValueBudget) -> Option<Self> {
        if self.is_primitive() {
            self.try_clone(budget)
        } else {
            Some(Self::String(self.js_string(budget)?))
        }
    }
    pub(super) fn js_string(&self, budget: &mut ValueBudget) -> Option<String> {
        match self {
            Self::String(s) => {
                budget.reserve(1, size_of::<Self>() + s.len())?;
                Some(s.clone())
            }
            Self::Array(values) => {
                budget.reserve(1, size_of::<Self>() + MAX_VALUE_BYTES)?;
                let mut result = String::with_capacity(MAX_VALUE_BYTES);
                for (index, value) in values.iter().enumerate() {
                    let separator = usize::from(index > 0);
                    let piece = match value {
                        None | Some(Self::Null | Self::Undefined) => None,
                        Some(value) => Some(value.js_string(budget)?),
                    };
                    if result.len() + separator + piece.as_ref().map_or(0, String::len)
                        > MAX_VALUE_BYTES
                    {
                        return None;
                    }
                    if separator > 0 {
                        result.push(',');
                    }
                    if let Some(piece) = piece {
                        result.push_str(&piece);
                    }
                }
                Some(result)
            }
            _ => {
                // Every modeled primitive spelling here is shorter than 64 bytes.
                budget.reserve(1, size_of::<Self>() + 64)?;
                match self {
                    Self::Number(n) if *n == 0.0 => Some("0".into()),
                    Self::Number(n) if n.is_finite() && (1e-6..1e21).contains(&n.abs()) => {
                        Some(n.to_string())
                    }
                    Self::Number(_) => None,
                    Self::Bool(b) => Some(b.to_string()),
                    Self::Null => Some("null".into()),
                    Self::Undefined => Some("undefined".into()),
                    Self::EmptyObject => Some("[object Object]".into()),
                    _ => unreachable!(),
                }
            }
        }
    }
    pub(super) fn add(&self, other: &Self, budget: &mut ValueBudget) -> Option<Self> {
        let (a, b) = (self.primitive(budget)?, other.primitive(budget)?);
        if matches!(a, Self::String(_)) || matches!(b, Self::String(_)) {
            let left = a.js_string(budget)?;
            let right = b.js_string(budget)?;
            let length = left.len() + right.len();
            if length > MAX_VALUE_BYTES {
                return None;
            }
            budget.reserve(1, size_of::<Self>() + length)?;
            let mut result = String::with_capacity(length);
            result.push_str(&left);
            result.push_str(&right);
            Some(Self::String(result))
        } else {
            Some(Self::Number(a.number(budget)? + b.number(budget)?))
        }
    }
    pub(super) fn loose_equal(&self, other: &Self, budget: &mut ValueBudget) -> Option<bool> {
        if !self.is_primitive() && !other.is_primitive() {
            return None;
        }
        let (a, b) = (self.primitive(budget)?, other.primitive(budget)?);
        if matches!(a, Self::Null | Self::Undefined) || matches!(b, Self::Null | Self::Undefined) {
            Some(
                matches!(a, Self::Null | Self::Undefined)
                    && matches!(b, Self::Null | Self::Undefined),
            )
        } else if std::mem::discriminant(&a) == std::mem::discriminant(&b) {
            Some(a == b)
        } else {
            Some(a.number(budget)? == b.number(budget)?)
        }
    }
    pub(super) fn code(&self, budget: &mut ValueBudget) -> Option<String> {
        // JSON may escape each byte with six characters. Finite f64 Display
        // uses fewer than 512 bytes, including subnormal decimal spellings.
        let maximum = match self {
            Self::String(s) => {
                2 + s
                    .bytes()
                    .map(|byte| match byte {
                        b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
                        0..=31 => 6,
                        _ => 1,
                    })
                    .sum::<usize>()
            }
            _ => 512,
        };
        budget.reserve(1, maximum * 2)?;
        Some(match self {
            Self::Number(n) if *n == 0.0 && n.is_sign_negative() => "-0".into(),
            Self::Number(n) => n.to_string(),
            Self::String(s) => serde_json::to_string(s).unwrap(),
            Self::Bool(b) => b.to_string(),
            Self::Null => "null".into(),
            Self::Undefined => "void 0".into(),
            Self::Array(_) | Self::EmptyObject => {
                unreachable!("only primitives may become replacement text")
            }
        })
    }
}

fn string_number(text: &str) -> Option<f64> {
    let text = text.trim_matches(|c| matches!(c, '\u{0009}'..='\u{000d}' | ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'));
    if text.is_empty() {
        return Some(0.0);
    }
    match text {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => (),
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            // Keep radix conversions exact; large integers remain unresolved.
            let n = u64::from_str_radix(digits, radix).ok();
            return match n {
                Some(n) if n <= 9007199254740991 => Some(n as f64),
                Some(_) => None,
                None if digits.len() > 16 => None,
                None => Some(f64::NAN),
            };
        }
    }
    if !text
        .bytes()
        .all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'+' | b'-' | b'e' | b'E'))
    {
        return Some(f64::NAN);
    }
    Some(text.parse::<f64>().unwrap_or(f64::NAN))
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    fn small_tree() -> Value {
        let mut budget = ValueBudget::default();
        let mut values = budget.array(1).unwrap();
        values.push(Some(Value::string("owned", &mut budget).unwrap()));
        let mut tree = Value::array(values, &mut budget).unwrap();
        // Only three small levels are materialized. Never build an OOM probe.
        for _ in 0..3 {
            let mut values = budget.array(2).unwrap();
            values.push(Some(tree.try_clone(&mut budget).unwrap()));
            values.push(Some(tree.try_clone(&mut budget).unwrap()));
            tree = Value::array(values, &mut budget).unwrap();
        }
        tree
    }

    #[test]
    fn deep_clone_reserves_the_entire_cached_cost_before_copying() {
        let tree = small_tree();
        let cost = tree.cost();
        let mut denied = ValueBudget::limited(cost.bytes - 1, cost.nodes, MAX_VALUE_DEPTH);
        assert!(tree.try_clone(&mut denied).is_none());
        assert!(denied.exhausted);
        assert_eq!(denied.bytes, cost.bytes - 1);
        assert_eq!(denied.nodes, cost.nodes);
        let mut exact = ValueBudget::limited(cost.bytes, cost.nodes, MAX_VALUE_DEPTH);
        let copy = tree.try_clone(&mut exact).unwrap();
        assert_eq!(copy, tree);
        assert_eq!(exact.bytes, 0);
        assert_eq!(exact.nodes, 0);
    }

    #[test]
    fn alias_string_copies_share_a_monotonic_budget() {
        let value = Value::String("small fixture string".to_string());
        let cost = value.cost();
        let mut budget = ValueBudget::limited(cost.bytes * 2, cost.nodes * 2, MAX_VALUE_DEPTH);
        let first = value.try_clone(&mut budget).unwrap();
        drop(first); // Dropping a temporary must not refund allocation work.
        let _retained = value.try_clone(&mut budget).unwrap();
        assert!(value.try_clone(&mut budget).is_none());
        assert!(budget.exhausted);
    }

    #[test]
    fn node_depth_and_symbolic_growth_limits_refuse_without_large_allocations() {
        let tree = small_tree();
        let cost = tree.cost();
        let mut nodes = ValueBudget::limited(cost.bytes, cost.nodes - 1, MAX_VALUE_DEPTH);
        assert!(tree.try_clone(&mut nodes).is_none());
        let mut depth = ValueBudget::limited(cost.bytes, cost.nodes, cost.depth - 1);
        assert!(tree.try_clone(&mut depth).is_none());
        assert!(depth.exhausted);
        // Account for a hypothetical doubling tree without constructing it.
        let mut hypothetical = Value::Number(0.0).cost();
        for _ in 0..30 {
            hypothetical = Cost {
                bytes: size_of::<Value>() + 2 * size_of::<Option<Value>>() + 2 * hypothetical.bytes,
                nodes: 3 + 2 * hypothetical.nodes,
                depth: hypothetical.depth + 1,
            };
        }
        let mut budget = ValueBudget::default();
        assert!(hypothetical.bytes > MAX_ALLOCATED_BYTES);
        assert!(
            budget
                .reserve(hypothetical.nodes, hypothetical.bytes)
                .is_none()
        );
        assert!(budget.exhausted);
    }
}
