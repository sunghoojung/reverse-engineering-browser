//! Primitive coercion rules and an explicitly assumed standard object model.
//! https://tc39.es/ecma262/2024/multipage/abstract-operations.html
use super::MAX_VALUE_BYTES;

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Value {
    Number(f64),
    String(String),
    Bool(bool),
    Null,
    Undefined,
    Array(Vec<Option<Value>>),
    EmptyObject,
}

impl Value {
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
    pub(super) fn number(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Bool(b) => Some(f64::from(u8::from(*b))),
            Self::Null => Some(0.0),
            Self::Undefined => Some(f64::NAN),
            Self::String(s) => string_number(s),
            Self::Array(_) | Self::EmptyObject => string_number(&self.js_string()?),
        }
    }
    pub(super) fn primitive(&self) -> Option<Self> {
        if self.is_primitive() {
            Some(self.clone())
        } else {
            Some(Self::String(self.js_string()?))
        }
    }
    pub(super) fn js_string(&self) -> Option<String> {
        match self {
            Self::String(s) => Some(s.clone()),
            Self::Number(n) if *n == 0.0 => Some("0".into()),
            Self::Number(n) if n.is_finite() && (1e-6..1e21).contains(&n.abs()) => {
                Some(n.to_string())
            }
            Self::Number(_) => None, // Avoid engine-dependent/spelling mismatches.
            Self::Bool(b) => Some(b.to_string()),
            Self::Null => Some("null".into()),
            Self::Undefined => Some("undefined".into()),
            Self::EmptyObject => Some("[object Object]".into()),
            Self::Array(values) => {
                let mut result = String::new();
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        result.push(',');
                    }
                    match value {
                        None | Some(Self::Null | Self::Undefined) => (),
                        Some(value) => result.push_str(&value.js_string()?),
                    }
                    if result.len() > MAX_VALUE_BYTES {
                        return None;
                    }
                }
                Some(result)
            }
        }
    }
    pub(super) fn add(&self, other: &Self) -> Option<Self> {
        let (a, b) = (self.primitive()?, other.primitive()?);
        if matches!(a, Self::String(_)) || matches!(b, Self::String(_)) {
            let mut left = a.js_string()?;
            let right = b.js_string()?;
            if left.len() + right.len() > MAX_VALUE_BYTES {
                return None;
            }
            left.push_str(&right);
            Some(Self::String(left))
        } else {
            Some(Self::Number(a.number()? + b.number()?))
        }
    }
    pub(super) fn loose_equal(&self, other: &Self) -> Option<bool> {
        if !self.is_primitive() && !other.is_primitive() {
            return None;
        }
        let (a, b) = (self.primitive()?, other.primitive()?);
        if matches!(a, Self::Null | Self::Undefined) || matches!(b, Self::Null | Self::Undefined) {
            return Some(
                matches!(a, Self::Null | Self::Undefined)
                    && matches!(b, Self::Null | Self::Undefined),
            );
        }
        if std::mem::discriminant(&a) == std::mem::discriminant(&b) {
            Some(a == b)
        } else {
            Some(a.number()? == b.number()?)
        }
    }
    pub(super) fn code(&self) -> String {
        match self {
            Self::Number(n) if *n == 0.0 && n.is_sign_negative() => "-0".into(),
            Self::Number(n) => n.to_string(),
            Self::String(s) => serde_json::to_string(s).unwrap(),
            Self::Bool(b) => b.to_string(),
            Self::Null => "null".into(),
            Self::Undefined => "void 0".into(),
            Self::Array(_) | Self::EmptyObject => {
                unreachable!("only primitives may become replacement text")
            }
        }
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
