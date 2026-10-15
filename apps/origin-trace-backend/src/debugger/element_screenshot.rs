//! Explicit, ephemeral capture of the selected disposable top-level document.
//! CDP reads only: no page scripts, DOM mutation, automatic capture, or export.
use super::{Debugger, connection::Connection};
use crate::{error::{Error, Result}, validation};
use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::{Arc, atomic::Ordering}, time::Duration};

const MAX_NODES: usize = 4096;
const MAX_BOXES: usize = 128;
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_PNG_BYTES: usize = 4 * 1024 * 1024;
const MAX_EDGE: f64 = 4096.0;
const MAX_PIXELS: f64 = 8_000_000.0;
const DEADLINE: Duration = Duration::from_secs(12);

fn malformed() -> Error { Error::protocol("Element capture returned unsupported or malformed geometry") }
fn stale() -> Error { Error::conflict("The selected document or layout changed; inspect it again before capture") }
fn limited() -> Error { Error::conflict("Element capture exceeds its bounded document, geometry, or image limits") }
fn limitations() -> Value {
    json!([
        "Before/after document and geometry checks detect observed drift, not an atomic DOM/pixel snapshot. Animated pixels can change without DOM changes.",
        "Boxes are axis-aligned layout bounds, clipped to the viewport. Occlusion, ancestor clipping, transforms, pseudo-elements, and exact painted shapes are unknown.",
        "Only one top-level document at unit page/pinch zoom is supported. Frames, shadow trees, embedded documents and form/editable/private-marked content are refused.",
        "Arbitrary text and images may still contain sensitive data. The PNG is raw local capture, not redacted or safe to share. Nothing is automatically exported or sent to a provider."
    ])
}
fn number(value: &Value) -> Result<f64> { value.as_f64().filter(|v| v.is_finite()).ok_or_else(malformed) }
fn text(value: &Value) -> Result<String> {
    validation::text(value, "Document identifier", 4096, false, false)
        .map(str::to_owned).map_err(|_| malformed())
}
fn viewport(metrics: &Value) -> Result<Value> {
    let visual = &metrics["cssVisualViewport"];
    let x = number(&visual["pageX"])?;
    let y = number(&visual["pageY"])?;
    let width = number(&visual["clientWidth"])?;
    let height = number(&visual["clientHeight"])?;
    if number(&visual["scale"])? != 1.0 || visual.get("zoom").map(number).transpose()?.unwrap_or(1.0) != 1.0 {
        return Err(Error::conflict("Element capture supports unit page and pinch zoom only"));
    }
    if x < 0.0 || y < 0.0 || x > 10_000_000.0 || y > 10_000_000.0 || width <= 0.0 || height <= 0.0 || width > MAX_EDGE || height > MAX_EDGE || width * height > MAX_PIXELS {
        return Err(limited());
    }
    Ok(json!({"x":x,"y":y,"width":width,"height":height}))
}
fn frame(tree: &Value) -> Result<Value> {
    let tree = &tree["frameTree"];
    if !tree["frame"].is_object() || tree.get("childFrames").is_some_and(|v| !v.as_array().is_some_and(Vec::is_empty)) {
        return Err(Error::conflict("Element capture refuses child frames"));
    }
    let frame = &tree["frame"];
    if frame.get("parentId").is_some() { return Err(malformed()); }
    let url = frame["url"].as_str().ok_or_else(malformed)?;
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(Error::conflict("Open an authorized HTTP(S) disposable page before capture"));
    }
    Ok(json!({"frame_id":text(&frame["id"])?,"loader_id":text(&frame["loaderId"])?}))
}
fn array<'a>(value: &'a Value, key: &str, length: usize) -> Result<&'a Vec<Value>> {
    value[key].as_array().filter(|v| v.len() == length).ok_or_else(malformed)
}
fn snapshot_document(snapshot: &Value, view: &Value) -> Result<(u64, Vec<Value>, usize)> {
    if serde_json::to_vec(snapshot).map_err(|_| malformed())?.len() > MAX_SNAPSHOT_BYTES { return Err(limited()); }
    let strings = snapshot["strings"].as_array().ok_or_else(malformed)?;
    if strings.len() > MAX_NODES * 16 || strings.iter().any(|v| !v.is_string()) { return Err(limited()); }
    let string = |value: &Value| -> Result<&str> {
        value.as_u64().and_then(|i| strings.get(i as usize)).and_then(Value::as_str).ok_or_else(malformed)
    };
    let docs = snapshot["documents"].as_array().filter(|v| v.len() == 1).ok_or_else(|| Error::conflict("Element capture refuses multiple or missing documents"))?;
    let nodes = &docs[0]["nodes"];
    let types = nodes["nodeType"].as_array().filter(|v| !v.is_empty() && v.len() <= MAX_NODES).ok_or_else(limited)?;
    let count = types.len();
    let names = array(nodes, "nodeName", count)?;
    let ids = array(nodes, "backendNodeId", count)?;
    let parents = array(nodes, "parentIndex", count)?;
    let attrs = array(nodes, "attributes", count)?;
    for key in ["shadowRootType", "contentDocumentIndex"] {
        if nodes.get(key).is_some_and(|v| !v["index"].as_array().is_some_and(Vec::is_empty)) {
            return Err(Error::conflict("Element capture refuses shadow trees and embedded documents"));
        }
    }
    let mut seen = BTreeSet::new();
    for i in 0..count {
        let id = ids[i].as_u64().filter(|id| *id > 0).ok_or_else(malformed)?;
        if !seen.insert(id) || !types[i].as_u64().is_some_and(|t| (1..=12).contains(&t)) { return Err(malformed()); }
        let parent = parents[i].as_i64().ok_or_else(malformed)?;
        if (i == 0 && (parent != -1 || types[i] != 9)) || (i > 0 && (parent < 0 || parent as usize >= i)) { return Err(malformed()); }
        let name = string(&names[i])?.to_ascii_lowercase();
        if ["input", "textarea", "select", "option", "form", "iframe", "frame", "object", "embed"].contains(&name.rsplit(':').next().unwrap_or("")) {
            return Err(Error::conflict("Element capture refuses form controls and embedded/private content"));
        }
        let attrs = attrs[i].as_array().filter(|v| v.len() % 2 == 0 && v.len() <= 256).ok_or_else(malformed)?;
        for pair in attrs.chunks_exact(2) {
            let name = string(&pair[0])?.to_ascii_lowercase();
            // Validate every string index, but never return names, values or text.
            let _ = string(&pair[1])?;
            if ["contenteditable", "data-reb-private", "data-private", "data-sensitive"].contains(&name.as_str()) {
                return Err(Error::conflict("Element capture refuses editable or private-marked content"));
            }
        }
    }
    let layout = &docs[0]["layout"];
    let indices = layout["nodeIndex"].as_array().filter(|v| v.len() <= MAX_NODES).ok_or_else(limited)?;
    let bounds = array(layout, "bounds", indices.len())?;
    let (vx, vy, vw, vh) = (number(&view["x"])?, number(&view["y"])?, number(&view["width"])?, number(&view["height"])?);
    let mut elements = Vec::new();
    let mut seen_layout = BTreeSet::new();
    let mut outside = 0;
    for (index, bound) in indices.iter().zip(bounds) {
        let i = index.as_u64().filter(|i| *i < count as u64).ok_or_else(malformed)? as usize;
        if !seen_layout.insert(i) { return Err(malformed()); }
        let bound = bound.as_array().filter(|v| v.len() == 4).ok_or_else(malformed)?;
        let (x, y, width, height) = (number(&bound[0])?, number(&bound[1])?, number(&bound[2])?, number(&bound[3])?);
        if width < 0.0 || height < 0.0 || [x, y, width, height].iter().any(|n| n.abs() > 10_000_000.0) { return Err(malformed()); }
        if types[i] != 1 { continue; }
        let left = x.max(vx); let top = y.max(vy);
        let right = (x + width).min(vx + vw); let bottom = (y + height).min(vy + vh);
        if right <= left || bottom <= top { outside += 1; continue; }
        if elements.len() == MAX_BOXES { return Err(limited()); }
        elements.push(json!({"number":elements.len()+1,"node_id":ids[i].as_u64().unwrap().to_string(),
            "x":left-vx,"y":top-vy,"width":right-left,"height":bottom-top,
            "viewport_clipped":left!=x || top!=y || right!=x+width || bottom!=y+height}));
    }
    Ok((ids[0].as_u64().unwrap(), elements, outside))
}
fn png_dimensions(data: &str, view: &Value) -> Result<(u32, u32)> {
    if data.len() > MAX_PNG_BYTES.div_ceil(3) * 4 { return Err(limited()); }
    let bytes = base64::engine::general_purpose::STANDARD.decode(data).map_err(|_| malformed())?;
    if bytes.len() > MAX_PNG_BYTES || bytes.len() < 33 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" || bytes[8..12] != [0,0,0,13] || &bytes[12..16] != b"IHDR" { return Err(malformed()); }
    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    let sx = f64::from(width) / number(&view["width"])?;
    let sy = f64::from(height) / number(&view["height"])?;
    if width == 0 || height == 0 || f64::from(width) > MAX_EDGE || f64::from(height) > MAX_EDGE || f64::from(width) * f64::from(height) > MAX_PIXELS || !(0.5..=4.0).contains(&sx) || !(0.5..=4.0).contains(&sy) || (sx-sy).abs() > 0.01 {
        return Err(limited());
    }
    Ok((width, height))
}

fn element_owner_identity(s: &Value, target: &str) -> Result<Value> {
    validation::text(&s["network"]["instance_id"], "Element instance", 128, false, false)?;
    validation::integer(&s["network"]["capture_epoch"], "Element connection epoch", 1, validation::MAX_SAFE_INTEGER)?;
    validation::integer(&s["object_experiment"]["session_id"], "Element session", 1, validation::MAX_SAFE_INTEGER)?;
    validation::integer(&s["element_document_epoch"], "Element document epoch", 0, validation::MAX_SAFE_INTEGER)?;
    Ok(json!({"instance_id":s["network"]["instance_id"],"connection_epoch":s["network"]["capture_epoch"],"session_id":s["object_experiment"]["session_id"],"document_epoch":s["element_document_epoch"],"target_id":target}))
}
async fn admitted_element_work(request: &Value, owner: &Value, capture: bool, work: impl std::future::Future<Output = Result<Value>>) -> Result<Value> {
    // A stale capture must not inspect the replacement owner's raw DOM, even
    // before the later complete frame/loader/revision comparison rejects it.
    if capture && (request["confirm_sensitive"] != true || !owner.as_object().is_some_and(|fields| fields.iter().all(|(key, value)| request["selection"][key] == *value))) {
        return Err(stale());
    }
    work.await
}

impl Debugger {
    fn element_owner(&self, target: &str) -> Result<Value> {
        if self.isolated_target("request_interception", false)? != target { return Err(stale()); }
        let s = self.snapshot();
        if self.stopping.load(Ordering::Acquire)
            || self.experiment.context().is_none()
            || s["request_interception"]["isolated"] != true
            || s["object_experiment"]["isolated"] != true
            || s["request_interception"]["target_id"] != target
            || s["object_experiment"]["target_id"] != target
            || s["target"]["id"] != target
            || s["state"] != "running"
        {
            return Err(Error::conflict("The selected disposable page is no longer running or owned"));
        }
        element_owner_identity(&s, target)
    }
    async fn element_command(&self, connection: &Arc<Connection>, owner: &Value, method: &str, params: Value) -> Result<Value> {
        // Shared transport prerequisite: command_guarded checks authority after
        // taking its writer lock. A refused admission sends no command bytes.
        connection.command_guarded(method, params, Duration::from_secs(3), || {
            !connection.is_closed()
                && owner["target_id"].as_str().is_some_and(|target| self.element_owner(target).is_ok_and(|current| current == *owner))
                && self.connection.try_lock().is_ok_and(|current| current.as_ref().is_some_and(|current| Arc::ptr_eq(current, connection)))
        }).await?.ok_or_else(stale)
    }
    async fn element_document(&self, connection: &Arc<Connection>, owner: &Value) -> Result<Value> {
        let command = |method: &'static str, params: Value| self.element_command(connection, owner, method, params);
        let first = frame(&command("Page.getFrameTree", json!({})).await?)?;
        let metrics = command("Page.getLayoutMetrics", json!({})).await?;
        let view = viewport(&metrics)?;
        let snapshot = command("DOMSnapshot.captureSnapshot", json!({"computedStyles":[],"includePaintOrder":false,"includeDOMRects":false})).await?;
        let (root, elements, outside) = snapshot_document(&snapshot, &view)?;
        if first != frame(&command("Page.getFrameTree", json!({})).await?)? { return Err(stale()); }
        let frame_id = snapshot["documents"][0]["frameId"].as_u64()
            .and_then(|i| snapshot["strings"].get(i as usize)).and_then(Value::as_str).ok_or_else(malformed)?;
        if first["frame_id"] != frame_id { return Err(stale()); }
        let mut selection = owner.clone();
        selection["frame_id"] = first["frame_id"].clone();
        selection["loader_id"] = first["loader_id"].clone();
        selection["document_node_id"] = json!(root.to_string());
        // Full bounded snapshot hashing catches observed text/attribute/layout changes;
        // raw strings remain transient and are never returned or stored in state.
        selection["revision"] = json!(hex::encode(Sha256::digest(serde_json::to_vec(&json!([owner,first,view,snapshot])).map_err(|_| malformed())?)));
        self.element_current(connection, owner).await?;
        Ok(json!({"selection":selection,"viewport":view,"elements":elements,"outside_viewport":outside,"limitations":limitations()}))
    }
    async fn element_current(&self, connection: &Arc<Connection>, owner: &Value) -> Result<()> {
        connection.barrier().await?;
        if self.element_owner(owner["target_id"].as_str().ok_or_else(malformed)?)? != *owner || connection.is_closed() || !self.connection.lock().await.as_ref().is_some_and(|current| Arc::ptr_eq(current, connection)) { return Err(stale()); }
        Ok(())
    }
    pub(super) async fn element_screenshot(&self, request: &Value, capture: bool) -> Result<Value> {
        let target = if capture { text(&request["selection"]["target_id"])? } else { text(&request["target_id"])? };
        let owner = self.element_owner(&target)?;
        let work = async {
            let connection = self.connection.lock().await.clone().ok_or_else(stale)?;
            let before = self.element_document(&connection, &owner).await?;
            if !capture { return Ok(json!({"ok":true,"document":before})); }
            if request["confirm_sensitive"] != true || before["selection"] != request["selection"] { return Err(stale()); }
            let view = &before["viewport"];
            let image = self.element_command(&connection, &owner, "Page.captureScreenshot", json!({"format":"png","fromSurface":true,"captureBeyondViewport":false,
                "clip":{"x":view["x"],"y":view["y"],"width":view["width"],"height":view["height"],"scale":1}})).await?;
            let data = image["data"].as_str().ok_or_else(malformed)?;
            let (width, height) = png_dimensions(data, view)?;
            let after = self.element_document(&connection, &owner).await?;
            if before != after { return Err(stale()); }
            self.element_current(&connection, &owner).await?;
            let image_sha256 = hex::encode(Sha256::digest(base64::engine::general_purpose::STANDARD.decode(data).map_err(|_| malformed())?));
            Ok(json!({"ok":true,"capture":{"format":"reb-element-screenshot-v1","document":before,
                "image":{"mime":"image/png","base64":data,"width":width,"height":height,"sha256":image_sha256},
                "consistency":"before-after-observed-stable","occlusion":"unknown"}}))
        };
        tokio::time::timeout(DEADLINE, admitted_element_work(request, &owner, capture, work)).await.map_err(|_| Error::conflict("Element capture deadline expired; inspect again before retrying"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    fn view() -> Value { json!({"x":10,"y":20,"width":100,"height":80}) }
    fn fixture() -> Value {
        json!({"strings":["#document","DIV","frame","data-note","fixture"],"documents":[{"frameId":2,"nodes":{
            "nodeType":[9,1],"nodeName":[0,1],"backendNodeId":[1,2],"parentIndex":[-1,0],"attributes":[[],[3,4]],
            "shadowRootType":{"index":[],"value":[]},"contentDocumentIndex":{"index":[],"value":[]}},
            "layout":{"nodeIndex":[1],"bounds":[[5,10,40,40]]}}]})
    }
    #[test]
    fn clipping_and_opaque_identity() {
        let (root, elements, outside) = snapshot_document(&fixture(), &view()).unwrap();
        assert_eq!(root,1); assert_eq!(outside,0);
        assert_eq!(elements,json!([{"number":1,"node_id":"2","x":0.0,"y":0.0,"width":35.0,"height":30.0,"viewport_clipped":true}]));
        assert!(!serde_json::to_string(&elements).unwrap().contains("fixture"));
    }
    #[test]
    fn privacy_and_frame_rejection_is_fail_closed() {
        for tag in ["INPUT","TEXTAREA","SELECT","FORM","IFRAME","OBJECT","EMBED","html:input"] {
            let mut s=fixture(); s["strings"][1]=json!(tag); assert!(snapshot_document(&s,&view()).is_err());
        }
        for attr in ["contenteditable","data-reb-private","data-private","data-sensitive"] {
            let mut s=fixture(); s["strings"][3]=json!(attr); assert!(snapshot_document(&s,&view()).is_err());
        }
        for key in ["shadowRootType","contentDocumentIndex"] {
            let mut s=fixture(); s["documents"][0]["nodes"][key]["index"]=json!([1]); assert!(snapshot_document(&s,&view()).is_err());
        }
        let mut s=fixture(); let second=s["documents"][0].clone(); s["documents"].as_array_mut().unwrap().push(second);
        assert!(snapshot_document(&s,&view()).is_err());
    }
    #[test]
    fn malformed_or_oversized_geometry_never_becomes_partial_success() {
        for value in [json!(-1),json!(null),json!("100"),json!(20_000_000)] {
            let mut s=fixture(); s["documents"][0]["layout"]["bounds"][0][2]=value; assert!(snapshot_document(&s,&view()).is_err());
        }
        let mut s=fixture(); s["documents"][0]["nodes"]["attributes"][1]=json!([3]); assert!(snapshot_document(&s,&view()).is_err());
        let mut s=fixture(); s["documents"][0]["nodes"]["backendNodeId"][1]=json!(1); assert!(snapshot_document(&s,&view()).is_err());
        let mut s=fixture(); s["strings"][4]=json!("x".repeat(MAX_SNAPSHOT_BYTES)); assert!(snapshot_document(&s,&view()).is_err());
    }
    #[test]
    fn viewport_and_png_scale_bounds() {
        let mut metrics=json!({"cssVisualViewport":{"pageX":0,"pageY":0,"clientWidth":100,"clientHeight":80,"scale":1,"zoom":1}});
        assert!(viewport(&metrics).is_ok()); metrics["cssVisualViewport"]["zoom"]=json!(1.25); assert!(viewport(&metrics).is_err());
        let mut png=vec![0;33]; png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n"); png[8..12].copy_from_slice(&13u32.to_be_bytes()); png[12..16].copy_from_slice(b"IHDR");
        png[16..20].copy_from_slice(&200u32.to_be_bytes()); png[20..24].copy_from_slice(&160u32.to_be_bytes());
        assert_eq!(png_dimensions(&base64::engine::general_purpose::STANDARD.encode(&png),&view()).unwrap(),(200,160));
        png[20..24].copy_from_slice(&100u32.to_be_bytes()); assert!(png_dimensions(&base64::engine::general_purpose::STANDARD.encode(&png),&view()).is_err());
    }
    #[tokio::test]
    async fn navigation_and_resize_observations_retire_document_epoch() {
        let options = crate::config::Options::parse_from(["test"]);
        let debugger = Debugger::new(&options);
        for (index, method) in [
            "Page.navigatedWithinDocument",
            "Page.frameResized",
            "Page.documentOpened",
        ].iter().enumerate() {
            debugger.event(json!({"method":method,"params":{}})).await;
            assert_eq!(debugger.snapshot()["element_document_epoch"], index + 1);
        }
    }
    #[test]
    fn capture_schema_requires_exact_selection_and_confirmation() {
        let selection = json!({"instance_id":"synthetic", "connection_epoch":1, "session_id":1,
            "target_id":"owned", "document_epoch":1, "frame_id":"frame", "loader_id":"loader",
            "document_node_id":"1", "revision":"a".repeat(64)});
        let mut request = json!({"action":"capture_element_screenshot", "selection":selection, "confirm_sensitive":true});
        assert!(validation::schema("DebuggerAction", &request, 400).is_ok());
        request["confirm_sensitive"] = json!(false);
        assert!(validation::schema("DebuggerAction", &request, 400).is_err());
        request["confirm_sensitive"] = json!(true);
        request["selection"].as_object_mut().unwrap().remove("connection_epoch");
        assert!(validation::schema("DebuggerAction", &request, 400).is_err());
        request["selection"]["connection_epoch"] = json!(1);
        request["selection"].as_object_mut().unwrap().remove("loader_id");
        assert!(validation::schema("DebuggerAction", &request, 400).is_err());
    }
    #[tokio::test]
    async fn stale_owner_is_refused_before_polling_any_document_read() {
        use std::sync::atomic::AtomicUsize;
        let state = json!({"network":{"instance_id":"same-instance","capture_epoch":1},"object_experiment":{"session_id":7},"element_document_epoch":9});
        let owner = element_owner_identity(&state, "same-target").unwrap();
        for key in ["instance_id", "connection_epoch", "session_id", "document_epoch", "target_id"] {
            let mut selection = owner.clone(); selection[key] = if ["instance_id", "target_id"].contains(&key) { json!("stale") } else { json!(owner[key].as_u64().unwrap() + 1) };
            let request = json!({"selection":selection,"confirm_sensitive":true});
            let reads = AtomicUsize::new(0);
            let work = async { reads.fetch_add(1, Ordering::SeqCst); Ok(json!({"unexpected":"document read"})) };
            assert!(admitted_element_work(&request, &owner, true, work).await.is_err());
            assert_eq!(reads.load(Ordering::SeqCst), 0, "Stale {key} must dispatch zero CDP reads");
        }
        let mut reconnected = state.clone(); reconnected["network"]["capture_epoch"] = json!(2);
        let new_owner = element_owner_identity(&reconnected, "same-target").unwrap();
        assert_ne!(owner, new_owner, "Same-page reconnect changes identity without any navigation");
        let old_request = json!({"selection":owner,"confirm_sensitive":true});
        let reads = AtomicUsize::new(0);
        let result = admitted_element_work(&old_request, &new_owner, true, async { reads.fetch_add(1, Ordering::SeqCst); Ok(Value::Null) }).await;
        assert!(result.is_err()); assert_eq!(reads.load(Ordering::SeqCst), 0);
        let current_request = json!({"selection":new_owner,"confirm_sensitive":true});
        assert!(admitted_element_work(&current_request, &new_owner, true, async { reads.fetch_add(1, Ordering::SeqCst); Ok(Value::Null) }).await.is_ok());
        assert_eq!(reads.load(Ordering::SeqCst), 1, "Current admitted owner polls the document work exactly once");
        let unconfirmed = json!({"selection":new_owner,"confirm_sensitive":false});
        assert!(admitted_element_work(&unconfirmed, &new_owner, true, async { reads.fetch_add(1, Ordering::SeqCst); Ok(Value::Null) }).await.is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 1, "Missing consent must not poll document work");
    }
    #[test]
    fn baseline_and_stale_target_are_rejected_without_capture() {
        let options=crate::config::Options::parse_from(["test"]);
        let debugger=Debugger::new(&options);
        assert!(debugger.element_owner("baseline").is_err());
    }
}
