use crate::validation;
use serde_json::{Value, json};
fn text(value: &Value, max: usize) -> Value {
    value
        .as_str()
        .map(|s| json!(validation::truncate(s, max)))
        .unwrap_or(Value::Null)
}
fn array(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}
pub fn location(v: &Value) -> Option<Value> {
    let id = v["scriptId"].as_str().filter(|s| s.len() <= 4096)?;
    let line = v["lineNumber"].as_u64().filter(|n| *n < i32::MAX as u64)?;
    let column = v.get("columnNumber").and_then(Value::as_u64).unwrap_or(0);
    if column >= i32::MAX as u64 {
        return None;
    }
    Some(json!({"script_id":id,"line":line,"column":column}))
}
pub fn remote(v: &Value) -> Option<Value> {
    let kind = v["type"].as_str().filter(|s| s.len() <= 256)?;
    let mut result = json!({"type":kind,"subtype":text(&v["subtype"],256),"class_name":text(&v["className"],4096),"description":text(&v["description"],4096),"object_id":v["objectId"].as_str().filter(|s|s.len()<=4096),"unserializable_value":text(&v["unserializableValue"],4096),"value":null,"value_truncated":false});
    if let Some(s) = v["value"].as_str() {
        result["value"] = json!(validation::truncate(s, 4096));
        result["value_truncated"] = json!(s.len() > 4096);
    } else if !v["value"].is_array() && !v["value"].is_object() {
        result["value"] = v["value"].clone();
    }
    if v["preview"].is_object() {
        result["preview"] = json!({"description":text(&v["preview"]["description"],4096),"overflow":v["preview"]["overflow"]==true});
    }
    Some(result)
}
pub fn property(v: &Value) -> Option<Value> {
    Some(
        json!({"name":validation::truncate(v["name"].as_str()?,4096),"value":remote(&v["value"]),"get":remote(&v["get"]),"set":remote(&v["set"]),"enumerable":v["enumerable"]==true,"writable":v["writable"]==true,"configurable":v["configurable"]==true}),
    )
}
pub fn script(p: &Value) -> Option<Value> {
    let id = p["scriptId"].as_str().filter(|s| s.len() <= 4096)?;
    let url = p["url"].as_str().filter(|s| s.len() <= 65536)?;
    // Source-map display metadata is not a script identity. An oversized data
    // URL must not discard its script or falsely taint candidate completeness.
    let source_map = p["sourceMapURL"].as_str().unwrap_or("");
    let source_map_omitted = source_map.len() > 65536;
    let mut result = json!({"script_id":id,"url":url,"hash":p["hash"].as_str().unwrap_or(""),"source_map_url":if source_map_omitted {""} else {source_map},"has_source_url":p["hasSourceURL"]==true,"is_module":p["isModule"]==true,"language":if p["scriptLanguage"]=="WebAssembly" {"WebAssembly"} else {"JavaScript"}});
    if source_map_omitted {
        result["source_map_url_omitted"] = json!(true);
    }
    for (key, raw) in [
        ("start_line", "startLine"),
        ("start_column", "startColumn"),
        ("end_line", "endLine"),
        ("end_column", "endColumn"),
        ("execution_context_id", "executionContextId"),
        ("length", "length"),
    ] {
        result[key] = json!(p[raw].as_u64().unwrap_or(0).min(i32::MAX as u64));
    }
    if result["hash"].as_str().unwrap().len() > 65536 {
        return None;
    }
    Some(result)
}
fn frame(v: &Value) -> Option<Value> {
    let id = v["callFrameId"].as_str().filter(|s| s.len() <= 4096)?;
    let name = v["functionName"].as_str()?;
    let url = v["url"].as_str()?;
    let loc = location(&v["location"])?;
    let scopes=array(&v["scopeChain"]).take(12).filter_map(|s|Some(json!({"type":validation::truncate(s["type"].as_str()?,256),"name":validation::truncate(s["name"].as_str().unwrap_or(""),4096),"object":remote(&s["object"] )?,"location":location(&s["startLocation"]),"properties":[]}))).collect::<Vec<_>>();
    Some(
        json!({"id":id,"function_name":if name.is_empty() {"(anonymous)".into()} else {validation::truncate(name,4096)},"url":validation::truncate(url,65536),"location":loc,"function_location":location(&v["functionLocation"]),"this":remote(&v["this"]),"return_value":remote(&v["returnValue"]),"scopes":scopes}),
    )
}
pub fn pause(p: &Value) -> Value {
    let mut asynchronous = Vec::new();
    let mut stack = &p["asyncStackTrace"];
    while stack.is_object() && asynchronous.len() < 32 {
        let frames=array(&stack["callFrames"]).take(64).filter_map(|f|Some(json!({"function_name":validation::truncate(f["functionName"].as_str()?,4096),"url":validation::truncate(f["url"].as_str()?,65536),"location":location(f)?}))).collect::<Vec<_>>();
        asynchronous.push(json!({"description":validation::truncate(stack["description"].as_str().unwrap_or("Async"),4096),"call_frames":frames}));
        stack = &stack["parent"];
    }
    json!({"reason":validation::truncate(p["reason"].as_str().unwrap_or("other"),256),"description":text(p["data"].get("description").or_else(||p["data"].get("message")).unwrap_or(&Value::Null),4096),"call_frames":array(&p["callFrames"]).take(64).filter_map(frame).collect::<Vec<_>>(),"async_stack":asynchronous,"hit_breakpoints":array(&p["hitBreakpoints"]).filter(|v|v.as_str().is_some_and(|s|s.len()<=4096)).take(1000).collect::<Vec<_>>(),"scope_coverage":{"status":"loading","properties":0,"limit":2000}})
}
pub fn console(p: &Value, id: u64) -> Value {
    let stack=array(&p["stackTrace"]["callFrames"]).take(64).filter_map(|f|Some(json!({"function_name":validation::truncate(f["functionName"].as_str()?,4096),"url":validation::truncate(f["url"].as_str()?,65536),"line":f["lineNumber"].as_u64()? ,"column":f["columnNumber"].as_u64()?}))).collect::<Vec<_>>();
    json!({"id":id.to_string(),"type":validation::truncate(p["type"].as_str().unwrap_or("log"),64),"timestamp":p["timestamp"].as_f64(),"arguments":array(&p["args"]).take(32).filter_map(remote).collect::<Vec<_>>(),"stack":stack})
}
