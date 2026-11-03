//! Trusted mouse and keyboard input for an agent's own capture browser.
//!
//! Pages tell script events (`isTrusted` false) from user input, so input is
//! sent the way a person sends it: macOS Quartz events, after the capture
//! browser is brought to the front. The browser's accessibility tree locates
//! the page and its controls, including inside cross-origin frames. There is
//! no Chrome DevTools Protocol and no page JavaScript.
//!
//! Input must never reach browser controls, browser dialogs or another
//! application. So a click is sent only after a hit test shows the element
//! under the point belongs to the page (and to the named control), and a key
//! only while the keyboard focus is inside the page. Only left clicks exist,
//! since a context menu would reach browser features. macOS must grant
//! Accessibility to the app that started the session; without it nothing is
//! sent. Input moves the real pointer, so one lock serializes it across every
//! session on the machine.
//!
//! The macOS frameworks are loaded at run time, only when input is used. The
//! backend binary also runs as the sandboxed JavaScript analysis worker, and
//! that process must not load window-server frameworks.
use crate::error::{Code, Error, Result};
use serde_json::{Value, json};

pub const MAX_ELEMENTS: usize = 200;
const MAX_NODES: usize = 6000;
const MAX_DEPTH: usize = 64;
const NAME_CHARS: usize = 120;
/// Keeps one typing action well inside a client's 30-second call timeout.
pub const MAX_TEXT: usize = 200;
const MAX_COORDINATE: f64 = 100_000.0;
const MAX_SCROLL: i64 = 10_000;

/// Apple accessibility roles of controls an agent can act on, with the short
/// names agents use. A subrole can refine a role.
const ROLES: [(&str, Option<&str>, &str); 16] = [
    ("AXCheckBox", Some("AXSwitch"), "switch"),
    ("AXCheckBox", None, "checkbox"),
    ("AXRadioButton", Some("AXTabButton"), "tab"),
    ("AXRadioButton", None, "radio"),
    ("AXTextField", Some("AXSecureTextField"), "password"),
    ("AXTextField", Some("AXSearchField"), "searchfield"),
    ("AXTextField", None, "textfield"),
    ("AXButton", None, "button"),
    ("AXLink", None, "link"),
    ("AXTextArea", None, "textarea"),
    ("AXPopUpButton", None, "popup"),
    ("AXComboBox", None, "combobox"),
    ("AXMenuItem", None, "menuitem"),
    ("AXMenuButton", None, "menubutton"),
    ("AXSlider", None, "slider"),
    ("AXDisclosureTriangle", None, "disclosure"),
];

/// Named keys for `press`, with their macOS virtual key codes.
pub const KEYS: [(&str, u16); 13] = [
    ("Enter", 36),
    ("Tab", 48),
    ("Escape", 53),
    ("Backspace", 51),
    ("Space", 49),
    ("ArrowLeft", 123),
    ("ArrowRight", 124),
    ("ArrowDown", 125),
    ("ArrowUp", 126),
    ("PageDown", 121),
    ("PageUp", 116),
    ("Home", 115),
    ("End", 119),
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
impl Rect {
    fn contains(&self, x: f64, y: f64) -> bool {
        x >= self.x && y >= self.y && x < self.x + self.width && y < self.y + self.height
    }
    fn intersect(&self, other: &Rect) -> Rect {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        Rect {
            x,
            y,
            width: ((self.x + self.width).min(other.x + other.width) - x).max(0.0),
            height: ((self.y + self.height).min(other.y + other.height) - y).max(0.0),
        }
    }
}

/// One control of the page. Frames are in screen points; `clip` is the part
/// of the screen its enclosing frames leave visible.
#[derive(Clone, Debug, PartialEq)]
pub struct Element {
    pub role: &'static str,
    pub name: String,
    pub frame: Rect,
    pub clip: Rect,
    pub frame_depth: u32,
    pub checked: Option<bool>,
}

/// The controls of the page, and the page viewport in screen points.
#[derive(Debug, PartialEq)]
pub struct Listing {
    pub viewport: Rect,
    pub elements: Vec<Element>,
    pub truncated: bool,
}

/// What the accessibility tree must answer for one node.
pub trait Node: Sized {
    fn role(&self) -> Option<String>;
    fn subrole(&self) -> Option<String>;
    fn name(&self) -> String;
    fn frame(&self) -> Option<Rect>;
    fn checked(&self) -> Option<bool>;
    /// The document address of a web area.
    fn url(&self) -> Option<String>;
    fn children(&self) -> Vec<Self>;
}

fn short_role(role: &str, subrole: Option<&str>) -> Option<&'static str> {
    ROLES
        .iter()
        .find(|(apple, refined, _)| {
            *apple == role && refined.is_none_or(|refined| subrole == Some(refined))
        })
        .map(|(_, _, short)| *short)
}

/// Page text is untrusted data: keep it short, single-line and printable.
fn clean_name(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(NAME_CHARS)
        .collect()
}

fn expired(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| std::time::Instant::now() > deadline)
}

/// The tab's web page: the largest HTTP(S) web area in the window. DevTools,
/// side panels and browser pages (`chrome://`, `brave://`) are never chosen,
/// and the search does not enter a page's own frames.
pub fn find_page<N: Node>(window: N, deadline: Option<std::time::Instant>) -> Option<N> {
    let mut queue = std::collections::VecDeque::from([(window, 0usize)]);
    let mut visited = 0;
    let mut best: Option<(f64, N)> = None;
    while let Some((node, depth)) = queue.pop_front() {
        visited += 1;
        if visited > 2000 || expired(deadline) {
            break;
        }
        if node.role().as_deref() == Some("AXWebArea") {
            let web = node
                .url()
                .is_some_and(|url| url.starts_with("http://") || url.starts_with("https://"));
            if web
                && let Some(frame) = node.frame()
                && best
                    .as_ref()
                    .is_none_or(|(area, _)| frame.width * frame.height > *area)
            {
                best = Some((frame.width * frame.height, node));
            }
            continue;
        }
        if depth < 30 {
            for child in node.children() {
                queue.push_back((child, depth + 1));
            }
        }
    }
    best.map(|(_, node)| node)
}

/// The page's controls in document order, nested frames included, within
/// fixed node, depth, element and time budgets. The second vector holds the
/// node of each listed control, for hit tests.
pub fn collect<N: Node>(
    page: N,
    deadline: Option<std::time::Instant>,
) -> Option<(Listing, Vec<N>)> {
    let viewport = page.frame()?;
    let mut listing = Listing {
        viewport,
        elements: Vec::new(),
        truncated: false,
    };
    let mut nodes = Vec::new();
    let mut stack = vec![(page, 0usize, 0u32, viewport, true)];
    let mut visited = 0;
    while let Some((node, depth, frame_depth, clip, root)) = stack.pop() {
        visited += 1;
        if visited > MAX_NODES || expired(deadline) {
            listing.truncated = true;
            break;
        }
        let role = node.role().unwrap_or_default();
        let (frame_depth, clip) = if role == "AXWebArea" && !root {
            // A frame shows only the part of itself that its parent shows.
            let clip = node.frame().map_or(clip, |frame| clip.intersect(&frame));
            (frame_depth + 1, clip)
        } else {
            (frame_depth, clip)
        };
        let children = if depth < MAX_DEPTH {
            node.children()
        } else {
            Vec::new()
        };
        if let Some(short) = short_role(&role, node.subrole().as_deref())
            && let Some(frame) = node.frame()
        {
            if listing.elements.len() == MAX_ELEMENTS {
                listing.truncated = true;
                break;
            }
            listing.elements.push(Element {
                role: short,
                name: clean_name(&node.name()),
                frame,
                clip,
                frame_depth,
                checked: matches!(short, "checkbox" | "switch" | "radio")
                    .then(|| node.checked())
                    .flatten(),
            });
            nodes.push(node);
        }
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|child| (child, depth + 1, frame_depth, clip, false)),
        );
    }
    Some((listing, nodes))
}

impl Listing {
    fn visible(&self, element: &Element) -> bool {
        let frame = element.frame;
        frame.width > 0.0
            && frame.height > 0.0
            && element
                .clip
                .contains(frame.x + frame.width / 2.0, frame.y + frame.height / 2.0)
    }
    pub fn document(&self) -> Value {
        let round = |value: f64| (value * 10.0).round() / 10.0;
        json!({
            "viewport": {"width": round(self.viewport.width), "height": round(self.viewport.height)},
            "elements": self.elements.iter().enumerate().map(|(index, element)| {
                let mut item = json!({
                    "index": index,
                    "role": element.role,
                    "name": element.name,
                    "x": round(element.frame.x - self.viewport.x),
                    "y": round(element.frame.y - self.viewport.y),
                    "width": round(element.frame.width),
                    "height": round(element.frame.height),
                    "visible": self.visible(element),
                    "frame_depth": element.frame_depth,
                });
                if let Some(checked) = element.checked {
                    item["checked"] = json!(checked);
                }
                item
            }).collect::<Vec<_>>(),
            "truncated": self.truncated,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    /// Viewport points from the page's top-left corner.
    Point(f64, f64),
    Element {
        role: Option<String>,
        name: Option<String>,
        nth: Option<usize>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    List,
    Click { target: Target, count: u8 },
    Type(String),
    Press(&'static str, u16),
    Scroll { dx: i32, dy: i32 },
}

fn keys(request: &Value, allowed: &[&str]) -> Result<()> {
    let object = request
        .as_object()
        .ok_or_else(|| Error::bad("Session action must be an object"))?;
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(Error::bad(format!(
            "{key} is not a field of this input action"
        )));
    }
    Ok(())
}

fn coordinate(value: &Value, label: &str) -> Result<f64> {
    value
        .as_f64()
        .filter(|n| n.is_finite() && (0.0..=MAX_COORDINATE).contains(n))
        .ok_or_else(|| Error::bad(format!("{label} must be a viewport coordinate")))
}

/// Validates an input action before anything platform specific runs.
pub fn parse(request: &Value) -> Result<Input> {
    match request["action"].as_str() {
        Some("list_inputs") => {
            keys(request, &["action"])?;
            Ok(Input::List)
        }
        Some("click") => {
            keys(
                request,
                &["action", "x", "y", "role", "name", "nth", "count"],
            )?;
            let point = request.get("x").is_some() || request.get("y").is_some();
            let element = ["role", "name", "nth"]
                .iter()
                .any(|key| request.get(*key).is_some());
            let target = match (point, element) {
                (true, false) => Target::Point(
                    coordinate(&request["x"], "x")?,
                    coordinate(&request["y"], "y")?,
                ),
                (false, true) => {
                    let role = request["role"].as_str().map(str::to_owned);
                    if request.get("role").is_some()
                        && !role
                            .as_deref()
                            .is_some_and(|role| ROLES.iter().any(|(_, _, short)| *short == role))
                    {
                        return Err(Error::bad("role must be a control role from list_inputs"));
                    }
                    let name = request["name"].as_str().map(str::to_owned);
                    if request.get("name").is_some()
                        && !name
                            .as_deref()
                            .is_some_and(|name| (1..=200).contains(&name.chars().count()))
                    {
                        return Err(Error::bad("name must be 1 to 200 characters"));
                    }
                    if role.is_none() && name.is_none() {
                        return Err(Error::bad("nth needs a role or name"));
                    }
                    let nth = match request.get("nth") {
                        None => None,
                        Some(value) => Some(
                            value
                                .as_u64()
                                .filter(|n| *n < MAX_ELEMENTS as u64)
                                .ok_or_else(|| Error::bad("nth must be below 200"))?
                                as usize,
                        ),
                    };
                    Target::Element { role, name, nth }
                }
                _ => {
                    return Err(Error::bad(
                        "Click needs either x and y, or a role or name from list_inputs",
                    ));
                }
            };
            let count = match request.get("count") {
                None => 1,
                Some(value) => match value.as_u64() {
                    Some(1) => 1,
                    Some(2) => 2,
                    _ => return Err(Error::bad("count must be 1 or 2")),
                },
            };
            Ok(Input::Click { target, count })
        }
        Some("type") => {
            keys(request, &["action", "text"])?;
            // Line breaks and other controls are keys with meaning; use press.
            let text = request["text"]
                .as_str()
                .filter(|text| {
                    (1..=MAX_TEXT).contains(&text.chars().count())
                        && !text.chars().any(char::is_control)
                })
                .ok_or_else(|| {
                    Error::bad(format!(
                        "text must be 1 to {MAX_TEXT} characters without line breaks or control characters"
                    ))
                })?;
            Ok(Input::Type(text.to_owned()))
        }
        Some("press") => {
            keys(request, &["action", "key"])?;
            let name = request["key"].as_str().unwrap_or("");
            KEYS.iter()
                .find(|(key, _)| *key == name)
                .map(|(key, code)| Input::Press(key, *code))
                .ok_or_else(|| {
                    Error::bad(format!(
                        "key must be one of {}",
                        KEYS.iter()
                            .map(|(key, _)| *key)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })
        }
        Some("scroll") => {
            keys(request, &["action", "dx", "dy"])?;
            let amount = |key: &str| match request.get(key) {
                None => Ok(0),
                Some(value) => value
                    .as_i64()
                    .filter(|n| n.abs() <= MAX_SCROLL)
                    .map(|n| n as i32)
                    .ok_or_else(|| Error::bad(format!("{key} must be within 10000 points"))),
            };
            let (dx, dy) = (amount("dx")?, amount("dy")?);
            if dx == 0 && dy == 0 {
                return Err(Error::bad("Scroll needs a nonzero dx or dy"));
            }
            Ok(Input::Scroll { dx, dy })
        }
        _ => Err(Error::bad("Input action is invalid")),
    }
}

/// The screen point to click and, for a named control, its index. A point
/// outside the page viewport is refused.
pub fn resolve(listing: &Listing, target: &Target) -> Result<((f64, f64), Option<usize>)> {
    match target {
        Target::Point(x, y) => {
            let point = (listing.viewport.x + x, listing.viewport.y + y);
            if !listing.viewport.contains(point.0, point.1) {
                return Err(Error::bad(format!(
                    "({x}, {y}) is outside the {}x{} page viewport. No input was sent.",
                    listing.viewport.width, listing.viewport.height
                )));
            }
            Ok((point, None))
        }
        Target::Element { role, name, nth } => {
            let wanted = name.as_ref().map(|name| name.to_lowercase());
            let matches = listing
                .elements
                .iter()
                .enumerate()
                .filter(|(_, element)| listing.visible(element))
                .filter(|(_, element)| role.as_deref().is_none_or(|role| element.role == role))
                .filter(|(_, element)| {
                    wanted
                        .as_ref()
                        .is_none_or(|wanted| element.name.to_lowercase().contains(wanted))
                })
                .collect::<Vec<_>>();
            let (index, element) = match (nth, matches.len()) {
                (_, 0) => {
                    return Err(Error::conflict(
                        "No visible control matches. Call list_inputs to see the page's controls. No input was sent.",
                    )
                    .with_code(Code::TargetUnavailable));
                }
                (Some(nth), count) if *nth >= count => {
                    return Err(Error::bad(format!(
                        "nth {nth} is past the {count} matching controls. No input was sent."
                    )));
                }
                (Some(nth), _) => matches[*nth],
                (None, 1) => matches[0],
                (None, count) => {
                    return Err(Error::bad(format!(
                        "{count} visible controls match; pass nth or a longer name. No input was sent."
                    )));
                }
            };
            let frame = element.frame;
            Ok((
                (frame.x + frame.width / 2.0, frame.y + frame.height / 2.0),
                Some(index),
            ))
        }
    }
}

/// Pointer positions from `from` to `to`, eased like a hand movement.
pub fn path(from: (f64, f64), to: (f64, f64), steps: usize) -> Vec<(f64, f64)> {
    (1..=steps)
        .map(|step| {
            let t = step as f64 / steps as f64;
            let eased = t * t * (3.0 - 2.0 * t);
            (
                from.0 + (to.0 - from.0) * eased,
                from.1 + (to.1 - from.1) * eased,
            )
        })
        .collect()
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn untrusted() -> Error {
    Error::conflict(
        "macOS has not granted Accessibility to the app that started this session, so no input was sent. Grant it in System Settings > Privacy & Security > Accessibility: Origin Trace for app sessions, or the terminal or T3 Code app for sessions started from reb-api. Then retry.",
    )
    .with_code(Code::DependencyUnavailable)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn lost(message: impl Into<String>) -> Error {
    Error::conflict(message).with_code(Code::TargetUnavailable)
}

/// Runs one validated input action against the capture browser `pid`.
pub fn act(pid: i32, request: &Value) -> Result<Value> {
    let input = parse(request)?;
    #[cfg(target_os = "macos")]
    {
        mac::act(pid, input)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (pid, input);
        Err(
            Error::conflict("Native input is available only on macOS. No input was sent.")
                .with_code(Code::DependencyUnavailable),
        )
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::{
        ffi::{c_ulong, c_void},
        ptr::null,
        sync::OnceLock,
        thread::sleep,
        time::{Duration, Instant},
    };

    type CFTypeRef = *const c_void;
    type CFIndex = isize;
    const UTF8: u32 = 0x0800_0100;
    const AX_POINT: u32 = 1;
    const AX_SIZE: u32 = 2;
    const NUMBER_SINT64: CFIndex = 4;
    const HID_TAP: u32 = 0;
    const MOUSE_MOVED: u32 = 5;
    const LEFT_DOWN: u32 = 1;
    const LEFT_UP: u32 = 2;
    const CLICK_STATE: u32 = 1;
    const SCROLL_PIXELS: u32 = 0;
    const ESCAPE: u16 = 53;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CGPoint {
        x: f64,
        y: f64,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CGSize {
        width: f64,
        height: f64,
    }
    #[repr(C)]
    struct CFRange {
        location: CFIndex,
        length: CFIndex,
    }

    /// The framework entry points this module uses, resolved with `dlsym`.
    struct Api {
        boolean_true: CFTypeRef,
        ax_trusted: unsafe extern "C" fn() -> u8,
        ax_application: unsafe extern "C" fn(i32) -> CFTypeRef,
        ax_system: unsafe extern "C" fn() -> CFTypeRef,
        ax_copy: unsafe extern "C" fn(CFTypeRef, CFTypeRef, *mut CFTypeRef) -> i32,
        ax_set: unsafe extern "C" fn(CFTypeRef, CFTypeRef, CFTypeRef) -> i32,
        ax_perform: unsafe extern "C" fn(CFTypeRef, CFTypeRef) -> i32,
        ax_pid: unsafe extern "C" fn(CFTypeRef, *mut i32) -> i32,
        ax_timeout: unsafe extern "C" fn(CFTypeRef, f32) -> i32,
        ax_at: unsafe extern "C" fn(CFTypeRef, f32, f32, *mut CFTypeRef) -> i32,
        ax_value: unsafe extern "C" fn(CFTypeRef, u32, *mut c_void) -> u8,
        cg_event: unsafe extern "C" fn(CFTypeRef) -> CFTypeRef,
        cg_location: unsafe extern "C" fn(CFTypeRef) -> CGPoint,
        cg_mouse: unsafe extern "C" fn(CFTypeRef, u32, CGPoint, u32) -> CFTypeRef,
        cg_key: unsafe extern "C" fn(CFTypeRef, u16, u8) -> CFTypeRef,
        cg_unicode: unsafe extern "C" fn(CFTypeRef, c_ulong, *const u16),
        cg_scroll: unsafe extern "C" fn(CFTypeRef, u32, u32, i32, ...) -> CFTypeRef,
        cg_field: unsafe extern "C" fn(CFTypeRef, u32, i64),
        cg_post: unsafe extern "C" fn(u32, CFTypeRef),
        cf_release: unsafe extern "C" fn(CFTypeRef),
        cf_retain: unsafe extern "C" fn(CFTypeRef) -> CFTypeRef,
        cf_equal: unsafe extern "C" fn(CFTypeRef, CFTypeRef) -> u8,
        cf_type: unsafe extern "C" fn(CFTypeRef) -> usize,
        cf_string_type: unsafe extern "C" fn() -> usize,
        cf_array_type: unsafe extern "C" fn() -> usize,
        cf_number_type: unsafe extern "C" fn() -> usize,
        cf_boolean_type: unsafe extern "C" fn() -> usize,
        cf_url_type: unsafe extern "C" fn() -> usize,
        cf_boolean: unsafe extern "C" fn(CFTypeRef) -> u8,
        cf_number: unsafe extern "C" fn(CFTypeRef, CFIndex, *mut c_void) -> u8,
        cf_count: unsafe extern "C" fn(CFTypeRef) -> CFIndex,
        cf_at: unsafe extern "C" fn(CFTypeRef, CFIndex) -> CFTypeRef,
        cf_string: unsafe extern "C" fn(CFTypeRef, *const u8, CFIndex, u32, u8) -> CFTypeRef,
        cf_length: unsafe extern "C" fn(CFTypeRef) -> CFIndex,
        cf_bytes: unsafe extern "C" fn(
            CFTypeRef,
            CFRange,
            u32,
            u8,
            u8,
            *mut u8,
            CFIndex,
            *mut CFIndex,
        ) -> CFIndex,
        cf_url_string: unsafe extern "C" fn(CFTypeRef) -> CFTypeRef,
    }
    // Function pointers and the immortal kCFBooleanTrue constant.
    unsafe impl Send for Api {}
    unsafe impl Sync for Api {}

    static API: OnceLock<Option<Api>> = OnceLock::new();

    /// A `dlsym` address as the function pointer type `F` it names.
    ///
    /// # Safety
    ///
    /// `F` must be the C signature of the symbol at `pointer`.
    unsafe fn function<F: Copy>(pointer: *mut c_void) -> F {
        assert_eq!(size_of::<F>(), size_of::<*mut c_void>());
        unsafe { std::mem::transmute_copy::<*mut c_void, F>(&pointer) }
    }

    fn load() -> Option<Api> {
        unsafe {
            let open = |path: &str| {
                let path = std::ffi::CString::new(path).ok()?;
                let handle = libc::dlopen(path.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
                (!handle.is_null()).then_some(handle)
            };
            let services = open(
                "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices",
            )?;
            let foundation =
                open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")?;
            let symbol = |name: &str| -> Option<*mut c_void> {
                let name = std::ffi::CString::new(name).ok()?;
                [services, foundation].iter().find_map(|handle| {
                    let pointer = libc::dlsym(*handle, name.as_ptr());
                    (!pointer.is_null()).then_some(pointer)
                })
            };
            macro_rules! f {
                ($name:literal) => {
                    function(symbol($name)?)
                };
            }
            let boolean_true = *(symbol("kCFBooleanTrue")? as *const CFTypeRef);
            Some(Api {
                boolean_true,
                ax_trusted: f!("AXIsProcessTrusted"),
                ax_application: f!("AXUIElementCreateApplication"),
                ax_system: f!("AXUIElementCreateSystemWide"),
                ax_copy: f!("AXUIElementCopyAttributeValue"),
                ax_set: f!("AXUIElementSetAttributeValue"),
                ax_perform: f!("AXUIElementPerformAction"),
                ax_pid: f!("AXUIElementGetPid"),
                ax_timeout: f!("AXUIElementSetMessagingTimeout"),
                ax_at: f!("AXUIElementCopyElementAtPosition"),
                ax_value: f!("AXValueGetValue"),
                cg_event: f!("CGEventCreate"),
                cg_location: f!("CGEventGetLocation"),
                cg_mouse: f!("CGEventCreateMouseEvent"),
                cg_key: f!("CGEventCreateKeyboardEvent"),
                cg_unicode: f!("CGEventKeyboardSetUnicodeString"),
                cg_scroll: f!("CGEventCreateScrollWheelEvent"),
                cg_field: f!("CGEventSetIntegerValueField"),
                cg_post: f!("CGEventPost"),
                cf_release: f!("CFRelease"),
                cf_retain: f!("CFRetain"),
                cf_equal: f!("CFEqual"),
                cf_type: f!("CFGetTypeID"),
                cf_string_type: f!("CFStringGetTypeID"),
                cf_array_type: f!("CFArrayGetTypeID"),
                cf_number_type: f!("CFNumberGetTypeID"),
                cf_boolean_type: f!("CFBooleanGetTypeID"),
                cf_url_type: f!("CFURLGetTypeID"),
                cf_boolean: f!("CFBooleanGetValue"),
                cf_number: f!("CFNumberGetValue"),
                cf_count: f!("CFArrayGetCount"),
                cf_at: f!("CFArrayGetValueAtIndex"),
                cf_string: f!("CFStringCreateWithBytes"),
                cf_length: f!("CFStringGetLength"),
                cf_bytes: f!("CFStringGetBytes"),
                cf_url_string: f!("CFURLGetString"),
            })
        }
    }

    /// Only called after `act` has loaded the API.
    fn api() -> &'static Api {
        API.get()
            .and_then(Option::as_ref)
            .expect("macOS input API is loaded before use")
    }

    /// An owned Core Foundation reference.
    struct Cf(CFTypeRef);
    impl Drop for Cf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { (api().cf_release)(self.0) }
            }
        }
    }
    fn cfstr(text: &str) -> Cf {
        Cf(unsafe { (api().cf_string)(null(), text.as_ptr(), text.len() as CFIndex, UTF8, 0) })
    }
    /// A bounded prefix of a string; an unpaired surrogate becomes `?`.
    fn string(value: CFTypeRef) -> Option<String> {
        let a = api();
        unsafe {
            if value.is_null() || (a.cf_type)(value) != (a.cf_string_type)() {
                return None;
            }
            let length = (a.cf_length)(value).min(4096);
            let mut buffer = vec![0u8; length as usize * 4 + 4];
            let mut used: CFIndex = 0;
            (a.cf_bytes)(
                value,
                CFRange {
                    location: 0,
                    length,
                },
                UTF8,
                b'?',
                0,
                buffer.as_mut_ptr(),
                buffer.len() as CFIndex,
                &mut used,
            );
            buffer.truncate(used.max(0) as usize);
            Some(String::from_utf8_lossy(&buffer).into_owned())
        }
    }

    struct Ax(Cf);
    impl Ax {
        fn retain(&self) -> Ax {
            Ax(Cf(unsafe { (api().cf_retain)((self.0).0) }))
        }
        fn attribute(&self, name: &str) -> Option<Cf> {
            let key = cfstr(name);
            let mut value: CFTypeRef = null();
            let error = unsafe { (api().ax_copy)((self.0).0, key.0, &mut value) };
            (error == 0 && !value.is_null()).then(|| Cf(value))
        }
        fn text(&self, name: &str) -> Option<String> {
            self.attribute(name).and_then(|value| string(value.0))
        }
        fn element(&self, name: &str) -> Option<Ax> {
            self.attribute(name).map(Ax)
        }
        fn set_true(&self, name: &str) -> bool {
            let key = cfstr(name);
            unsafe { (api().ax_set)((self.0).0, key.0, api().boolean_true) == 0 }
        }
        fn perform(&self, action: &str) {
            let key = cfstr(action);
            unsafe {
                (api().ax_perform)((self.0).0, key.0);
            }
        }
        fn pid(&self) -> Option<i32> {
            let mut pid = 0;
            (unsafe { (api().ax_pid)((self.0).0, &mut pid) } == 0).then_some(pid)
        }
        fn same(&self, other: &Ax) -> bool {
            unsafe { (api().cf_equal)((self.0).0, (other.0).0) != 0 }
        }
        /// Whether `ancestor` is this element or encloses it.
        fn within(&self, ancestor: &Ax) -> bool {
            let mut current = self.retain();
            for _ in 0..96 {
                if current.same(ancestor) {
                    return true;
                }
                match current.element("AXParent") {
                    Some(parent) => current = parent,
                    None => return false,
                }
            }
            false
        }
    }
    impl Node for Ax {
        fn role(&self) -> Option<String> {
            self.text("AXRole")
        }
        fn subrole(&self) -> Option<String> {
            self.text("AXSubrole")
        }
        fn name(&self) -> String {
            ["AXTitle", "AXDescription", "AXPlaceholderValue"]
                .iter()
                .find_map(|key| self.text(key).filter(|text| !text.trim().is_empty()))
                .unwrap_or_default()
        }
        fn frame(&self) -> Option<Rect> {
            let position = self.attribute("AXPosition")?;
            let size = self.attribute("AXSize")?;
            let mut point = CGPoint::default();
            let mut extent = CGSize::default();
            unsafe {
                if (api().ax_value)(position.0, AX_POINT, (&mut point as *mut CGPoint).cast()) == 0
                    || (api().ax_value)(size.0, AX_SIZE, (&mut extent as *mut CGSize).cast()) == 0
                {
                    return None;
                }
            }
            Some(Rect {
                x: point.x,
                y: point.y,
                width: extent.width,
                height: extent.height,
            })
        }
        fn checked(&self) -> Option<bool> {
            let value = self.attribute("AXValue")?;
            let a = api();
            unsafe {
                if (a.cf_type)(value.0) == (a.cf_boolean_type)() {
                    return Some((a.cf_boolean)(value.0) != 0);
                }
                if (a.cf_type)(value.0) == (a.cf_number_type)() {
                    let mut number = 0i64;
                    if (a.cf_number)(value.0, NUMBER_SINT64, (&mut number as *mut i64).cast()) != 0
                    {
                        return Some(number == 1);
                    }
                }
            }
            None
        }
        fn url(&self) -> Option<String> {
            let value = self.attribute("AXURL")?;
            let a = api();
            unsafe {
                if (a.cf_type)(value.0) == (a.cf_url_type)() {
                    // Get rule: the string belongs to the URL.
                    return string((a.cf_url_string)(value.0));
                }
            }
            string(value.0)
        }
        fn children(&self) -> Vec<Self> {
            let Some(array) = self.attribute("AXChildren") else {
                return Vec::new();
            };
            let a = api();
            unsafe {
                if (a.cf_type)(array.0) != (a.cf_array_type)() {
                    return Vec::new();
                }
                (0..(a.cf_count)(array.0).min(4096))
                    .map(|index| (a.cf_at)(array.0, index))
                    .filter(|child| !child.is_null())
                    .map(|child| Ax(Cf((a.cf_retain)(child))))
                    .collect()
            }
        }
    }

    fn system() -> Ax {
        Ax(Cf(unsafe { (api().ax_system)() }))
    }

    /// One input at a time on this machine: it moves the shared pointer.
    struct InputLock(std::fs::File);
    impl InputLock {
        fn acquire() -> Result<Self> {
            use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
            let path = format!("/tmp/origin-trace-input-{}.lock", unsafe { libc::getuid() });
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    return Ok(Self(file));
                }
                if Instant::now() >= deadline {
                    return Err(Error::new(
                        503,
                        "Another session is sending input. Retry explicitly; no input was sent.",
                    )
                    .with_code(Code::ResourceLimit));
                }
                sleep(Duration::from_millis(100));
            }
        }
    }
    impl Drop for InputLock {
        fn drop(&mut self) {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }

    fn browser(pid: i32) -> Result<(Ax, Ax)> {
        let app = Ax(Cf(unsafe { (api().ax_application)(pid) }));
        // Chromium builds its web accessibility tree only for a client that
        // asks; this attribute is its documented request.
        app.set_true("AXManualAccessibility");
        let window = app
            .element("AXFocusedWindow")
            .or_else(|| app.element("AXMainWindow"))
            .ok_or_else(|| lost("The capture browser has no open window. No input was sent."))?;
        Ok((app, window))
    }

    /// The tab's web page. Its tree can take a moment to appear the first
    /// time it is requested.
    fn page(window: &Ax) -> Result<Ax> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(page) = find_page(window.retain(), Some(deadline)) {
                return Ok(page);
            }
            if Instant::now() >= deadline {
                return Err(lost(
                    "The capture browser's tab shows no HTTP(S) page. Open one with open_url. No input was sent.",
                ));
            }
            sleep(Duration::from_millis(200));
        }
    }

    fn controls(page: &Ax) -> Result<(Listing, Vec<Ax>)> {
        collect(page.retain(), Some(Instant::now() + Duration::from_secs(4)))
            .ok_or_else(|| lost("The page has no position on screen. No input was sent."))
    }

    fn focused_app(pid: i32) -> bool {
        system()
            .element("AXFocusedApplication")
            .and_then(|focused| focused.pid())
            == Some(pid)
    }

    /// The keyboard focus is in this browser and inside its page, not in the
    /// address bar, a browser dialog or a menu.
    fn focus_in_page(pid: i32, page: &Ax) -> bool {
        focused_app(pid)
            && system()
                .element("AXFocusedUIElement")
                .is_some_and(|focused| focused.pid() == Some(pid) && focused.within(page))
    }

    /// The topmost element at a screen point, across all applications.
    fn hit(point: (f64, f64)) -> Option<Ax> {
        let mut value: CFTypeRef = null();
        let error =
            unsafe { (api().ax_at)((system().0).0, point.0 as f32, point.1 as f32, &mut value) };
        (error == 0 && !value.is_null()).then(|| Ax(Cf(value)))
    }

    /// Brings the capture browser to the front and confirms it has the focus.
    fn activate(app: &Ax, window: &Ax, pid: i32) -> Result<()> {
        for _ in 0..3 {
            app.set_true("AXFrontmost");
            window.perform("AXRaise");
            sleep(Duration::from_millis(250));
            if focused_app(pid) {
                return Ok(());
            }
        }
        Err(lost(
            "The capture browser could not be brought to the front. No input was sent.",
        ))
    }

    fn post(event: CFTypeRef) {
        if !event.is_null() {
            unsafe {
                (api().cg_post)(HID_TAP, event);
                (api().cf_release)(event);
            }
        }
    }
    fn mouse(kind: u32, point: (f64, f64), clicks: i64) {
        unsafe {
            let event = (api().cg_mouse)(
                null(),
                kind,
                CGPoint {
                    x: point.0,
                    y: point.1,
                },
                0,
            );
            if clicks > 0 && !event.is_null() {
                (api().cg_field)(event, CLICK_STATE, clicks);
            }
            post(event);
        }
    }
    fn pointer() -> (f64, f64) {
        unsafe {
            let event = (api().cg_event)(null());
            if event.is_null() {
                return (0.0, 0.0);
            }
            let point = (api().cg_location)(event);
            (api().cf_release)(event);
            (point.x, point.y)
        }
    }
    fn move_to(point: (f64, f64)) {
        for step in path(pointer(), point, 14) {
            mouse(MOUSE_MOVED, step, 0);
            sleep(Duration::from_millis(12));
        }
    }
    fn key(code: u16, text: Option<&[u16]>) {
        for down in [1u8, 0] {
            unsafe {
                let event = (api().cg_key)(null(), code, down);
                if let Some(text) = text
                    && !event.is_null()
                {
                    (api().cg_unicode)(event, text.len() as c_ulong, text.as_ptr());
                }
                post(event);
            }
            sleep(Duration::from_millis(18));
        }
    }

    /// The element under `point` must be this browser's and inside `scope`:
    /// the named control, or the page for a point click.
    fn hits(point: (f64, f64), pid: i32, scope: &Ax) -> bool {
        hit(point).is_some_and(|element| element.pid() == Some(pid) && element.within(scope))
    }

    pub fn act(pid: i32, input: Input) -> Result<Value> {
        if API.get_or_init(load).is_none() {
            return Err(Error::conflict(
                "The macOS input frameworks could not be loaded. No input was sent.",
            )
            .with_code(Code::DependencyUnavailable));
        }
        if unsafe { (api().ax_trusted)() } == 0 {
            return Err(untrusted());
        }
        unsafe {
            (api().ax_timeout)((system().0).0, 1.0);
        }
        let (app, window) = browser(pid)?;
        if input == Input::List {
            let (listing, _) = controls(&page(&window)?)?;
            let mut document = listing.document();
            document["ok"] = json!(true);
            document["action"] = json!("list_inputs");
            return Ok(document);
        }
        let _lock = InputLock::acquire()?;
        activate(&app, &window, pid)?;
        let page = page(&window)?;
        match input {
            Input::List => unreachable!("handled above"),
            Input::Click { target, count } => {
                let (listing, nodes) = controls(&page)?;
                let (point, index) = resolve(&listing, &target)?;
                move_to(point);
                let scope = index.map_or(&page, |index| &nodes[index]);
                // Checked at the last moment: an overlay, a dialog, another
                // window or a moved page fails here instead of being clicked.
                if !focused_app(pid) || !hits(point, pid, scope) {
                    return Err(lost(
                        "Something else is under that point now, so no click was sent.",
                    ));
                }
                for click in 1..=i64::from(count) {
                    mouse(LEFT_DOWN, point, click);
                    sleep(Duration::from_millis(70));
                    mouse(LEFT_UP, point, click);
                    sleep(Duration::from_millis(90));
                }
                Ok(json!({
                    "ok": true,
                    "action": "click",
                    "x": point.0 - listing.viewport.x,
                    "y": point.1 - listing.viewport.y,
                    "target": index.map(|index| {
                        let element = &listing.elements[index];
                        json!({"role": element.role, "name": element.name})
                    }),
                }))
            }
            Input::Type(text) => {
                let total = text.chars().count();
                let mut units = [0u16; 2];
                for (sent, character) in text.chars().enumerate() {
                    if !focus_in_page(pid, &page) {
                        return Err(lost(format!(
                            "The keyboard focus left the page, so typing stopped after {sent} of {total} characters. Click a field in the page first."
                        )));
                    }
                    key(0, Some(character.encode_utf16(&mut units)));
                    sleep(Duration::from_millis(20));
                }
                Ok(json!({"ok": true, "action": "type", "characters": total}))
            }
            Input::Press(name, code) => {
                // Escape only closes things, so it is allowed anywhere in the
                // browser; every other key needs the focus in the page.
                let allowed = if code == ESCAPE {
                    focused_app(pid)
                } else {
                    focus_in_page(pid, &page)
                };
                if !allowed {
                    return Err(lost(
                        "The keyboard focus is not in the page, so no key was sent. Click a control in the page first.",
                    ));
                }
                key(code, None);
                Ok(json!({"ok": true, "action": "press", "key": name}))
            }
            Input::Scroll { dx, dy } => {
                let viewport = page.frame().ok_or_else(|| {
                    lost("The page has no position on screen. No input was sent.")
                })?;
                let center = (
                    viewport.x + viewport.width / 2.0,
                    viewport.y + viewport.height / 2.0,
                );
                // Wheel events go to the view under the pointer.
                move_to(center);
                if !focused_app(pid) || !hits(center, pid, &page) {
                    return Err(lost(
                        "Something else covers the page center, so no scroll was sent.",
                    ));
                }
                post(unsafe { (api().cg_scroll)(null(), SCROLL_PIXELS, 2, -dy, -dx) });
                Ok(json!({"ok": true, "action": "scroll", "dx": dx, "dy": dy}))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Fake {
        role: &'static str,
        subrole: Option<&'static str>,
        name: &'static str,
        url: Option<&'static str>,
        frame: Option<Rect>,
        checked: Option<bool>,
        children: Vec<Fake>,
    }
    impl Node for Fake {
        fn role(&self) -> Option<String> {
            Some(self.role.to_owned())
        }
        fn subrole(&self) -> Option<String> {
            self.subrole.map(str::to_owned)
        }
        fn name(&self) -> String {
            self.name.to_owned()
        }
        fn frame(&self) -> Option<Rect> {
            self.frame
        }
        fn checked(&self) -> Option<bool> {
            self.checked
        }
        fn url(&self) -> Option<String> {
            self.url.map(str::to_owned)
        }
        fn children(&self) -> Vec<Self> {
            self.children.clone()
        }
    }
    fn node(role: &'static str, name: &'static str, frame: (f64, f64, f64, f64)) -> Fake {
        Fake {
            role,
            subrole: None,
            name,
            url: None,
            frame: Some(Rect {
                x: frame.0,
                y: frame.1,
                width: frame.2,
                height: frame.3,
            }),
            checked: None,
            children: Vec::new(),
        }
    }
    fn window() -> Fake {
        let mut checkbox = node(
            "AXCheckBox",
            "hCaptcha checkbox.\nSelect in order to trigger the challenge",
            (130.0, 330.0, 28.0, 28.0),
        );
        checkbox.checked = Some(false);
        // Scrolled out of its frame: inside the page, outside the frame.
        let clipped = node("AXButton", "Hidden in frame", (130.0, 600.0, 40.0, 20.0));
        let mut frame = node("AXWebArea", "hCaptcha", (100.0, 300.0, 300.0, 80.0));
        frame.url = Some("https://newassets.example/checkbox");
        frame.children = vec![checkbox, clipped];
        let mut password = node("AXTextField", "Password", (110.0, 200.0, 200.0, 20.0));
        password.subrole = Some("AXSecureTextField");
        let mut page = node("AXWebArea", "Demo", (100.0, 100.0, 800.0, 600.0));
        page.url = Some("https://demo.example/");
        page.children = vec![
            node("AXGroup", "", (100.0, 100.0, 800.0, 50.0)),
            node("AXButton", "Submit", (120.0, 160.0, 80.0, 30.0)),
            password,
            frame,
            node("AXLink", "Far below", (100.0, 2000.0, 50.0, 20.0)),
        ];
        // DevTools comes first in the tree and is never the page.
        let mut devtools = node("AXWebArea", "DevTools", (100.0, 100.0, 900.0, 900.0));
        devtools.url = Some("devtools://devtools/bundled/inspector.html");
        devtools.children = vec![node("AXButton", "Console", (110.0, 110.0, 40.0, 20.0))];
        let mut toolbar = node("AXToolbar", "", (100.0, 50.0, 800.0, 50.0));
        toolbar.children = vec![node("AXButton", "Reload", (110.0, 60.0, 20.0, 20.0))];
        let mut root = node("AXWindow", "Brave", (100.0, 30.0, 800.0, 670.0));
        root.children = vec![toolbar, devtools, page];
        root
    }

    #[test]
    fn the_page_is_the_tabs_web_page_never_devtools_or_browser_pages() {
        let page = find_page(window(), None).unwrap();
        assert_eq!(page.name, "Demo");
        let mut internal = window();
        internal.children[2].url = Some("chrome://newtab/");
        internal.children[1].url = Some("brave://settings/");
        assert!(find_page(internal, None).is_none());
    }

    #[test]
    fn controls_include_cross_frame_ones_and_exclude_browser_chrome() {
        let (listing, nodes) = collect(find_page(window(), None).unwrap(), None).unwrap();
        assert_eq!(nodes.len(), listing.elements.len());
        let roles = listing
            .elements
            .iter()
            .map(|element| element.role)
            .collect::<Vec<_>>();
        assert_eq!(
            roles,
            vec!["button", "password", "checkbox", "button", "link"]
        );
        let checkbox = &listing.elements[2];
        assert_eq!(checkbox.frame_depth, 1);
        assert_eq!(checkbox.checked, Some(false));
        assert_eq!(
            checkbox.name,
            "hCaptcha checkbox. Select in order to trigger the challenge"
        );
        let document = listing.document();
        assert_eq!(document["elements"][0]["x"], 20.0);
        assert_eq!(document["elements"][0]["y"], 60.0);
        assert_eq!(document["elements"][2]["visible"], true);
        // Clipped by its frame, and below the page viewport.
        assert_eq!(document["elements"][3]["visible"], false);
        assert_eq!(document["elements"][4]["visible"], false);
        assert_eq!(document["viewport"]["width"], 800.0);
    }

    #[test]
    fn targets_resolve_to_points_inside_the_page_only() {
        let (listing, _) = collect(find_page(window(), None).unwrap(), None).unwrap();
        let named = Target::Element {
            role: Some("checkbox".into()),
            name: Some("HCAPTCHA".into()),
            nth: None,
        };
        assert_eq!(
            resolve(&listing, &named).unwrap(),
            ((144.0, 344.0), Some(2))
        );
        assert_eq!(
            resolve(&listing, &Target::Point(10.0, 20.0)).unwrap(),
            ((110.0, 120.0), None)
        );
        assert!(resolve(&listing, &Target::Point(800.0, 10.0)).is_err());
        let clipped = Target::Element {
            role: None,
            name: Some("hidden in frame".into()),
            nth: None,
        };
        assert_eq!(resolve(&listing, &clipped).unwrap_err().status, 409);
        let any = Target::Element {
            role: None,
            name: Some("s".into()),
            nth: None,
        };
        assert!(
            resolve(&listing, &any)
                .unwrap_err()
                .message
                .contains("pass nth")
        );
        let second = Target::Element {
            role: None,
            name: Some("s".into()),
            nth: Some(1),
        };
        assert_eq!(resolve(&listing, &second).unwrap().1, Some(1));
    }

    #[test]
    fn input_requests_are_validated_before_any_platform_call() {
        assert_eq!(
            parse(&json!({"action":"list_inputs"})).unwrap(),
            Input::List
        );
        assert_eq!(
            parse(&json!({"action":"click","x":10,"y":20})).unwrap(),
            Input::Click {
                target: Target::Point(10.0, 20.0),
                count: 1
            }
        );
        assert!(matches!(
            parse(&json!({"action":"click","role":"checkbox","nth":0,"count":2})).unwrap(),
            Input::Click { count: 2, .. }
        ));
        assert_eq!(
            parse(&json!({"action":"press","key":"Enter"})).unwrap(),
            Input::Press("Enter", 36)
        );
        let long = "a".repeat(MAX_TEXT + 1);
        for bad in [
            json!({"action":"click"}),
            json!({"action":"click","x":1}),
            json!({"action":"click","x":1,"y":2,"role":"button"}),
            json!({"action":"click","role":"AXButton"}),
            json!({"action":"click","nth":1}),
            json!({"action":"click","x":-1,"y":2}),
            json!({"action":"click","x":1,"y":2,"button":"right"}),
            json!({"action":"type","text":""}),
            json!({"action":"type","text":"a\nb"}),
            json!({"action":"type","text":long}),
            json!({"action":"press","key":"F13"}),
            json!({"action":"scroll","dy":0}),
            json!({"action":"scroll","dy":20000}),
            json!({"action":"list_inputs","extra":1}),
        ] {
            assert_eq!(parse(&bad).unwrap_err().status, 400, "{bad}");
        }
    }

    /// Every framework symbol resolves at run time. A test process is never
    /// granted Accessibility, so this ends at the trust check (or, in a
    /// trusted shell, at this windowless process) without sending input.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_frameworks_load_and_untrusted_callers_send_nothing() {
        let error = act(std::process::id() as i32, &json!({"action":"list_inputs"})).unwrap_err();
        assert!(
            !error.message.contains("could not be loaded"),
            "{}",
            error.message
        );
        assert_eq!(error.status, 409);
    }

    #[test]
    fn pointer_paths_end_on_the_target() {
        let steps = path((0.0, 0.0), (100.0, 50.0), 14);
        assert_eq!(steps.len(), 14);
        assert_eq!(*steps.last().unwrap(), (100.0, 50.0));
        assert!(steps.windows(2).all(|pair| pair[1].0 >= pair[0].0));
    }
}
