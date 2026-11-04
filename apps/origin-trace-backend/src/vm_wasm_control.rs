//! Structured control of a Wasm function body, shared by every analyzer that
//! tracks block nesting or loop depth. Each block-like operator opens a frame
//! that one `end` closes, so an operator missing here makes its `end` close the
//! enclosing frame instead. wasmparser decodes `try_table` by default; legacy
//! `try`, `catch`, `catch_all` and `delegate` only with that feature enabled.
use wasmparser::Operator;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockKind {
    Block,
    Loop,
    If,
    TryTable,
    /// Legacy exception handling.
    Try,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Control {
    /// Opens a frame of this kind.
    Open(BlockKind),
    /// `else`, `catch` or `catch_all`: a new arm of the innermost frame, which
    /// must be of this kind.
    Arm(BlockKind),
    /// `end` closes the innermost frame, or the function body when none is
    /// open. A legacy `delegate` closes a `try` frame, never the body.
    Close { delegate: bool },
    /// No structured control effect.
    Other,
}

pub(crate) fn control(op: &Operator<'_>) -> Control {
    match op {
        Operator::Block { .. } => Control::Open(BlockKind::Block),
        Operator::Loop { .. } => Control::Open(BlockKind::Loop),
        Operator::If { .. } => Control::Open(BlockKind::If),
        Operator::TryTable { .. } => Control::Open(BlockKind::TryTable),
        Operator::Try { .. } => Control::Open(BlockKind::Try),
        Operator::Else => Control::Arm(BlockKind::If),
        Operator::Catch { .. } | Operator::CatchAll => Control::Arm(BlockKind::Try),
        Operator::End => Control::Close { delegate: false },
        Operator::Delegate { .. } => Control::Close { delegate: true },
        _ => Control::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmparser::{BlockType, TryTable};

    #[test]
    fn every_block_like_operator_opens_a_frame() {
        let block = BlockType::Empty;
        let table = TryTable {
            ty: block,
            catches: Vec::new(),
        };
        for (op, expected) in [
            (
                Operator::Block { blockty: block },
                Control::Open(BlockKind::Block),
            ),
            (
                Operator::Loop { blockty: block },
                Control::Open(BlockKind::Loop),
            ),
            (
                Operator::If { blockty: block },
                Control::Open(BlockKind::If),
            ),
            (
                Operator::TryTable { try_table: table },
                Control::Open(BlockKind::TryTable),
            ),
            (
                Operator::Try { blockty: block },
                Control::Open(BlockKind::Try),
            ),
            (Operator::Else, Control::Arm(BlockKind::If)),
            (
                Operator::Catch { tag_index: 0 },
                Control::Arm(BlockKind::Try),
            ),
            (Operator::CatchAll, Control::Arm(BlockKind::Try)),
            (Operator::End, Control::Close { delegate: false }),
            (
                Operator::Delegate { relative_depth: 0 },
                Control::Close { delegate: true },
            ),
            (Operator::Nop, Control::Other),
        ] {
            assert_eq!(control(&op), expected, "{op:?}");
        }
    }
}
