//! Prettier-style document over original source slices. The printer chooses
//! only whitespace: every `Text` command is a byte range of the input.

pub(crate) const PRINT_WIDTH: usize = 80;
const INDENT: usize = 2;
// Deep nesting keeps its structure without letting indentation dominate output.
const MAX_INDENT: usize = 160;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Line {
    /// Nothing when flat.
    Soft,
    /// One space when flat.
    Normal,
    Hard,
    /// A hard line that keeps one empty line.
    Blank,
}

#[derive(Clone, Copy)]
enum Cmd {
    Text(u32, u32),
    Space,
    Line(Line),
    Open(u32),
    Close,
    Indent,
    Dedent,
    /// Indents only when the named group printed broken.
    IndentIf(u32),
}

struct Group {
    /// Contains a hard line outside its hug target.
    hard: bool,
    /// An argument group that may expand alone while its siblings stay flat.
    hug: Option<u32>,
    close: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Flat,
    Break,
    Hug(u32),
}

pub(crate) struct Doc {
    cmds: Vec<Cmd>,
    groups: Vec<Group>,
    open: Vec<u32>,
    /// The innermost open group may expand this child alone.
    hugs: Vec<Option<u32>>,
}

pub(crate) struct OutputLimit;

impl Doc {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            cmds: Vec::with_capacity(capacity),
            groups: Vec::new(),
            open: Vec::new(),
            hugs: Vec::new(),
        }
    }
    pub(crate) fn text(&mut self, start: u32, end: u32) {
        self.cmds.push(Cmd::Text(start, end));
    }
    pub(crate) fn space(&mut self) {
        self.cmds.push(Cmd::Space);
    }
    /// Returns the command index so a soft line can later become a space.
    pub(crate) fn line(&mut self, line: Line) -> usize {
        self.cmds.push(Cmd::Line(line));
        if matches!(line, Line::Hard | Line::Blank) {
            self.propagate_hard();
        }
        self.cmds.len() - 1
    }
    pub(crate) fn harden_soft(&mut self, at: usize) {
        if let Cmd::Line(Line::Soft) = self.cmds[at] {
            self.cmds[at] = Cmd::Line(Line::Normal);
        }
    }
    pub(crate) fn open(&mut self) -> u32 {
        let id = self.groups.len() as u32;
        if let Some(Some(target)) = self.hugs.last()
            && *target == u32::MAX
        {
            let parent = *self.open.last().unwrap();
            self.groups[parent as usize].hug = Some(id);
            *self.hugs.last_mut().unwrap() = Some(id);
        }
        self.groups.push(Group {
            hard: false,
            hug: None,
            close: 0,
        });
        self.cmds.push(Cmd::Open(id));
        self.open.push(id);
        self.hugs.push(None);
        id
    }
    /// The next group opened directly inside the current group is its hug target.
    pub(crate) fn hug_next(&mut self) {
        *self.hugs.last_mut().unwrap() = Some(u32::MAX);
    }
    pub(crate) fn close(&mut self) {
        let id = self.open.pop().unwrap();
        self.hugs.pop();
        self.groups[id as usize].close = self.cmds.len() as u32;
        self.cmds.push(Cmd::Close);
    }
    /// Breaks the innermost open group and its ancestors.
    pub(crate) fn force_break(&mut self) {
        self.propagate_hard();
    }
    pub(crate) fn indent(&mut self) {
        self.cmds.push(Cmd::Indent);
    }
    pub(crate) fn dedent(&mut self) {
        self.cmds.push(Cmd::Dedent);
    }
    pub(crate) fn indent_if(&mut self, group: u32) {
        self.cmds.push(Cmd::IndentIf(group));
    }
    fn propagate_hard(&mut self) {
        for depth in (0..self.open.len()).rev() {
            let id = self.open[depth] as usize;
            let in_target = self.groups[id]
                .hug
                .is_some_and(|target| self.open.get(depth + 1) == Some(&target));
            if in_target {
                continue;
            }
            if self.groups[id].hard {
                break;
            }
            self.groups[id].hard = true;
        }
    }

    pub(crate) fn print(&self, source: &str, limit: usize) -> Result<String, OutputLimit> {
        Printer {
            doc: self,
            source,
            out: String::with_capacity(source.len() + source.len() / 2),
            text_end: 0,
            modes: vec![Mode::Break],
            indents: vec![0],
            chosen: vec![Mode::Flat; self.groups.len()],
            column: 0,
            line_start: true,
            limit,
        }
        .run()
    }
}

struct Printer<'d> {
    doc: &'d Doc,
    source: &'d str,
    out: String,
    /// End of the last source slice in `out`. Spaces before it are source
    /// text, such as a line comment's trailing spaces, and are never trimmed.
    text_end: usize,
    modes: Vec<Mode>,
    indents: Vec<usize>,
    chosen: Vec<Mode>,
    column: usize,
    line_start: bool,
    limit: usize,
}

impl Printer<'_> {
    fn run(mut self) -> Result<String, OutputLimit> {
        let mut at = 0;
        while at < self.doc.cmds.len() {
            match self.doc.cmds[at] {
                Cmd::Text(start, end) => self.write(start as usize, end as usize)?,
                Cmd::Space => {
                    if !self.line_start {
                        self.out.push(' ');
                        self.column += 1;
                    }
                }
                Cmd::Line(line) => match (line, *self.modes.last().unwrap()) {
                    (Line::Hard, _) => self.newline(false),
                    (Line::Blank, _) => self.newline(true),
                    (_, Mode::Break) => self.newline(false),
                    (Line::Normal, _) => {
                        if !self.line_start {
                            self.out.push(' ');
                            self.column += 1;
                        }
                    }
                    (Line::Soft, _) => (),
                },
                Cmd::Open(id) => {
                    let mode = self.choose(at, id);
                    self.chosen[id as usize] = mode;
                    self.modes.push(mode);
                }
                Cmd::Close => {
                    self.modes.pop();
                }
                Cmd::Indent => {
                    let top = *self.indents.last().unwrap();
                    let next = if *self.modes.last().unwrap() == Mode::Break {
                        (top + INDENT).min(MAX_INDENT)
                    } else {
                        top
                    };
                    self.indents.push(next);
                }
                Cmd::IndentIf(group) => {
                    let top = *self.indents.last().unwrap();
                    let next = if self.chosen[group as usize] == Mode::Break {
                        (top + INDENT).min(MAX_INDENT)
                    } else {
                        top
                    };
                    self.indents.push(next);
                }
                Cmd::Dedent => {
                    self.indents.pop();
                }
            }
            at += 1;
        }
        let trimmed = self.out.trim_end_matches([' ', '\n']).len();
        self.out.truncate(trimmed.max(self.text_end));
        self.out.push('\n');
        Ok(self.out)
    }

    fn choose(&self, at: usize, id: u32) -> Mode {
        let group = &self.doc.groups[id as usize];
        if group.hard {
            return Mode::Break;
        }
        match *self.modes.last().unwrap() {
            Mode::Flat => Mode::Flat,
            Mode::Hug(target) if target == id => Mode::Break,
            Mode::Hug(_) => Mode::Flat,
            Mode::Break => {
                if self.fits(at, Mode::Flat) {
                    Mode::Flat
                } else if let Some(target) = group.hug
                    && self.fits(at, Mode::Hug(target))
                {
                    Mode::Hug(target)
                } else {
                    Mode::Break
                }
            }
        }
    }

    /// Prettier's `fits`: the group in `mode`, then what follows up to any line.
    fn fits(&self, at: usize, mode: Mode) -> bool {
        let Cmd::Open(id) = self.doc.cmds[at] else {
            return true;
        };
        let close = self.doc.groups[id as usize].close as usize;
        let mut remaining = PRINT_WIDTH as isize
            - if self.line_start {
                *self.indents.last().unwrap()
            } else {
                self.column
            } as isize;
        let mut modes = vec![mode];
        let mut index = at + 1;
        while index < self.doc.cmds.len() {
            let rest = index > close;
            match self.doc.cmds[index] {
                Cmd::Text(start, end) => {
                    let (width, newline) =
                        width(&self.source[start as usize..end as usize], remaining);
                    remaining -= width as isize;
                    if remaining < 0 {
                        return false;
                    }
                    if newline {
                        return true;
                    }
                }
                Cmd::Space => remaining -= 1,
                Cmd::Line(line) => {
                    if rest
                        || matches!(line, Line::Hard | Line::Blank)
                        || *modes.last().unwrap() == Mode::Break
                    {
                        return true;
                    }
                    if line == Line::Normal {
                        remaining -= 1;
                    }
                }
                Cmd::Open(nested) if !rest => {
                    let parent = *modes.last().unwrap();
                    let group = &self.doc.groups[nested as usize];
                    modes.push(if group.hard || parent == Mode::Hug(nested) {
                        Mode::Break
                    } else if let Mode::Hug(_) = parent {
                        Mode::Flat
                    } else {
                        parent
                    });
                }
                Cmd::Close if !rest => {
                    modes.pop();
                }
                _ => (),
            }
            if remaining < 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    fn write(&mut self, start: usize, end: usize) -> Result<(), OutputLimit> {
        let text = &self.source[start..end];
        if self.line_start {
            let indent = *self.indents.last().unwrap();
            self.out.extend(std::iter::repeat_n(' ', indent));
            self.column = indent;
            self.line_start = false;
        }
        self.out.push_str(text);
        self.text_end = self.out.len();
        match text.rfind('\n') {
            Some(at) => self.column = text[at + 1..].chars().count(),
            None => self.column += width(text, isize::MAX).0,
        }
        if self.out.len() > self.limit {
            return Err(OutputLimit);
        }
        Ok(())
    }

    fn newline(&mut self, blank: bool) {
        let trimmed = self.out.trim_end_matches(' ').len();
        self.out.truncate(trimmed.max(self.text_end));
        if self.out.is_empty() {
            return;
        }
        if !self.out.ends_with('\n') {
            self.out.push('\n');
        }
        if blank && !self.out.ends_with("\n\n") {
            self.out.push('\n');
        }
        self.line_start = true;
        self.column = 0;
    }
}

/// Columns before the first line break, counting at most `limit + 1`.
fn width(text: &str, limit: isize) -> (usize, bool) {
    let cap = usize::try_from(limit).unwrap_or(0).saturating_add(1);
    if text.is_ascii() {
        return match text.find('\n') {
            Some(at) => (at, true),
            None => (text.len(), false),
        };
    }
    let mut columns = 0;
    for character in text.chars() {
        if character == '\n' {
            return (columns, true);
        }
        columns += 1;
        if columns > cap {
            break;
        }
    }
    (columns, false)
}
