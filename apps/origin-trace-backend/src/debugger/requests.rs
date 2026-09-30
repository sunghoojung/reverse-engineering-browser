use crate::{
    error::{Error, Result},
    validation, workspace,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn text(v: &Value, field: &str, max: usize, empty: bool) -> Result<String> {
    Ok(validation::text(v, field, max, empty, true)?.into())
}
pub fn url(v: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(v).map_err(|_| Error::bad("Experiment request URL is invalid"))?;
    if v.len() > 8192
        || v.chars().any(|c| c < ' ' || c == '\u{7f}')
        || !["http", "https"].contains(&parsed.scheme())
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(Error::bad(
            "Experiment request URL must be credential-free HTTP or HTTPS",
        ));
    }
    Ok(parsed)
}
pub fn redacted(v: &str) -> String {
    let Ok(mut u) = url::Url::parse(v) else {
        return String::new();
    };
    if !["http", "https"].contains(&u.scheme()) || u.host_str().is_none() {
        return String::new();
    }
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.set_fragment(None);
    validation::truncate(u.as_str(), 8192)
}
pub fn method(v: &str) -> Result<String> {
    let v = v.trim().to_ascii_uppercase();
    if v.is_empty()
        || v.len() > 32
        || !v.as_bytes()[0].is_ascii_uppercase()
        || !v.bytes().all(|b| {
            b.is_ascii_uppercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
    {
        return Err(Error::bad("Experiment request method is invalid"));
    }
    Ok(v)
}
pub fn headers(v: &Value) -> Result<Value> {
    let object = v
        .as_object()
        .ok_or_else(|| Error::bad("Request headers must be an object"))?;
    workspace::headers(&json!(
        object
            .iter()
            .map(|(name, value)| json!({"name":name,"value":value}))
            .collect::<Vec<_>>()
    ))
}
pub fn header_map(v: &Value) -> Value {
    json!(
        v.as_array()
            .unwrap()
            .iter()
            .map(|v| (v["name"].as_str().unwrap().to_owned(), v["value"].clone()))
            .collect::<BTreeMap<_, _>>()
    )
}
pub fn request(v: &Value) -> Result<Value> {
    let address = text(&v["url"], "Experiment request URL", 8192, false)?
        .trim()
        .to_owned();
    url(&address)?;
    let method = method(
        v.get("method")
            .unwrap_or(&json!("GET"))
            .as_str()
            .ok_or_else(|| Error::bad("Request method must be text"))?,
    )?;
    let body = text(
        v.get("body").unwrap_or(&json!("")),
        "Request body",
        65536,
        true,
    )?;
    if ["GET", "HEAD"].contains(&method.as_str()) && !body.is_empty() {
        return Err(Error::bad("GET and HEAD requests cannot include a body"));
    }
    Ok(
        json!({"url":address,"method":method,"headers":headers(v.get("headers").unwrap_or(&json!({})))?,"body":body}),
    )
}
pub fn default_rule() -> Value {
    json!({"mode":"continue","url_pattern":"*","method_filter":"","rewrite_url":"","rewrite_method":"","rewrite_headers":[],"rewrite_body":"","response_code":200,"response_headers":[],"response_body":""})
}
pub fn rule(v: &Value) -> Result<Value> {
    let mode = v["mode"]
        .as_str()
        .ok_or_else(|| Error::bad("Interception mode is required"))?;
    if !["continue", "block", "drop", "rewrite", "fulfill"].contains(&mode) {
        return Err(Error::bad("Interception mode is invalid"));
    }
    let pattern = text(&v["url_pattern"], "URL pattern", 2048, false)?;
    if !pattern.bytes().all(|b| (32..=126).contains(&b))
        || pattern != "*" && !pattern.starts_with("http://") && !pattern.starts_with("https://")
    {
        return Err(Error::bad("URL pattern must use HTTP, HTTPS, or *"));
    }
    let filter = text(
        v.get("method_filter").unwrap_or(&json!("")),
        "Method filter",
        32,
        true,
    )?
    .trim()
    .to_ascii_uppercase();
    if !filter.is_empty() {
        method(&filter)?;
    }
    let mut rule = default_rule();
    rule["mode"] = json!(mode);
    rule["url_pattern"] = json!(pattern);
    rule["method_filter"] = json!(filter);
    if mode == "rewrite" {
        let address = text(
            v.get("rewrite_url").unwrap_or(&json!("")),
            "Rewrite URL",
            8192,
            true,
        )?
        .trim()
        .to_owned();
        if !address.is_empty() {
            url(&address)?;
        }
        let m = text(
            v.get("rewrite_method").unwrap_or(&json!("")),
            "Rewrite method",
            32,
            true,
        )?
        .trim()
        .to_ascii_uppercase();
        if !m.is_empty() {
            method(&m)?;
        }
        let headers = headers(v.get("rewrite_headers").unwrap_or(&json!({})))?;
        let body = text(
            v.get("rewrite_body").unwrap_or(&json!("")),
            "Rewrite body",
            65536,
            true,
        )?;
        if address.is_empty()
            && m.is_empty()
            && headers.as_array().unwrap().is_empty()
            && body.is_empty()
        {
            return Err(Error::bad(
                "Request rewrite requires at least one bounded override",
            ));
        }
        rule["rewrite_url"] = json!(address);
        rule["rewrite_method"] = json!(m);
        rule["rewrite_headers"] = headers;
        rule["rewrite_body"] = json!(body);
    }
    if mode == "fulfill" {
        rule["response_code"] = json!(validation::integer(
            v.get("response_code").unwrap_or(&json!(200)),
            "Response status",
            100,
            599
        )?);
        let mut h = headers(v.get("response_headers").unwrap_or(&json!({})))?;
        let a = h.as_array_mut().unwrap();
        if a.is_empty() {
            a.push(json!({"name":"content-type","value":"text/plain; charset=utf-8"}));
        }
        if !a.iter().any(|h| {
            h["name"]
                .as_str()
                .unwrap()
                .eq_ignore_ascii_case("access-control-allow-origin")
        }) {
            if a.len() == 64 {
                return Err(Error::bad(
                    "Synthetic response must include access-control-allow-origin at the 64-header limit",
                ));
            }
            a.push(json!({"name":"access-control-allow-origin","value":"*"}));
        }
        rule["response_headers"] = h;
        rule["response_body"] = json!(text(
            v.get("response_body").unwrap_or(&json!("")),
            "Response body",
            65536,
            true
        )?);
    }
    Ok(rule)
}
pub fn public_rule(r: &Value) -> Value {
    json!({"mode":r["mode"],"url_pattern":r["url_pattern"],"method_filter":r["method_filter"],"rewrite_url":redacted(r["rewrite_url"].as_str().unwrap()),"rewrite_method":r["rewrite_method"],"rewrite_header_count":r["rewrite_headers"].as_array().unwrap().len(),"rewrite_body_bytes":r["rewrite_body"].as_str().unwrap().len(),"response_code":r["response_code"],"response_header_count":r["response_headers"].as_array().unwrap().len(),"response_body_bytes":r["response_body"].as_str().unwrap().len()})
}
pub fn result(v: &Value, repeater: bool) -> Result<Value> {
    if v["protocolVersion"] != 1 || !v["ok"].is_boolean() {
        return Err(Error::protocol("Malformed experiment result"));
    }
    let mut output = if v["ok"] == false {
        json!({"protocol_version":1,"ok":false,"status":0,"status_text":"","url":"","headers":[],"headers_truncated":false,"body":"","body_truncated":false,"error":validation::truncate(v["error"].as_str().ok_or_else(||Error::protocol("Malformed experiment error"))?,512)})
    } else {
        let status = validation::integer(&v["status"], "Response status", 0, 599)
            .map_err(|e| Error::protocol(e.message))?;
        let mut truncated = v["headersTruncated"]
            .as_bool()
            .ok_or_else(|| Error::protocol("Malformed header coverage"))?;
        let body_truncated = v["bodyTruncated"]
            .as_bool()
            .ok_or_else(|| Error::protocol("Malformed body coverage"))?;
        let a = v["headers"]
            .as_array()
            .filter(|a| a.len() <= 64)
            .ok_or_else(|| Error::protocol("Malformed response headers"))?;
        let mut h = Vec::new();
        let mut size = 0;
        for header in a {
            let name = header["name"]
                .as_str()
                .ok_or_else(|| Error::protocol("Malformed header name"))?;
            let value = header["value"]
                .as_str()
                .ok_or_else(|| Error::protocol("Malformed header value"))?;
            if [
                "authorization",
                "cookie",
                "proxy-authorization",
                "set-cookie",
            ]
            .contains(&name.to_ascii_lowercase().as_str())
            {
                return Err(Error::protocol(
                    "Sensitive response header was not redacted",
                ));
            }
            truncated |= name.len() > 128 || value.len() > 2048;
            let name = validation::truncate(name, 128);
            let value = validation::truncate(value, 2048);
            size += name.len() + value.len();
            if size > 16384 {
                return Err(Error::protocol("Response headers exceed 16 KiB"));
            }
            h.push(json!({"name":name,"value":value}));
        }
        let body = v["body"]
            .as_str()
            .ok_or_else(|| Error::protocol("Malformed response body"))?;
        let address = v["url"]
            .as_str()
            .ok_or_else(|| Error::protocol("Malformed response URL"))?;
        let status_text = v["statusText"]
            .as_str()
            .ok_or_else(|| Error::protocol("Malformed status text"))?;
        json!({"protocol_version":1,"ok":true,"status":status,"status_text":validation::truncate(status_text,256),"url":redacted(address),"headers":h,"headers_truncated":truncated,"body":validation::truncate(body,65536),"body_truncated":body_truncated||body.len()>65536,"error":null})
    };
    if repeater {
        let duration = validation::integer(&v["durationMs"], "Repeater duration", 0, 35000)
            .map_err(|e| Error::protocol(e.message))?;
        let cancelled = v["cancelled"]
            .as_bool()
            .ok_or_else(|| Error::protocol("Malformed cancellation result"))?;
        let timeout = v["timedOut"]
            .as_bool()
            .ok_or_else(|| Error::protocol("Malformed timeout result"))?;
        if cancelled && timeout || output["ok"] == true && (cancelled || timeout) {
            return Err(Error::protocol("Inconsistent cancellation result"));
        }
        output["duration_ms"] = json!(duration);
        output["cancelled"] = json!(cancelled);
        output["timed_out"] = json!(timeout);
        output["body_sha256"] = json!(hex::encode(Sha256::digest(
            output["body"].as_str().unwrap().as_bytes()
        )));
    }
    Ok(output)
}
pub fn template(v: &Value) -> Result<Value> {
    let address = text(&v["url"], "Repeater URL", 8192, false)?
        .trim()
        .to_owned();
    if address.chars().any(|c| c < ' ' || c == '\u{7f}') {
        return Err(Error::bad("Repeater URL is invalid"));
    }
    let method = text(
        v.get("method").unwrap_or(&json!("GET")),
        "Repeater method",
        256,
        false,
    )?
    .trim()
    .to_owned();
    if method.is_empty() || method.chars().any(|c| c < ' ' || c == '\u{7f}') {
        return Err(Error::bad("Repeater method is invalid"));
    }
    let collection = v.get("collection_request_id").unwrap_or(&Value::Null);
    if !collection.is_null() {
        validation::integer(
            collection,
            "Collection request ID",
            1,
            validation::MAX_SAFE_INTEGER,
        )?;
    }
    Ok(
        json!({"url":address,"method":method,"headers":headers(v.get("headers").unwrap_or(&json!({})))?,"body":text(v.get("body").unwrap_or(&json!("")),"Repeater body",65536,true)?,"timeout_ms":validation::integer(v.get("timeout_ms").unwrap_or(&json!(30000)),"Repeater timeout",100,30000)?,"collection_request_id":collection}),
    )
}
pub fn variables(v: &Value) -> Result<Value> {
    let map = workspace::variables(v, 64, 32768, true)?;
    Ok(json!(
        map.as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| json!({"name":name,"value":value}))
            .collect::<Vec<_>>()
    ))
}
pub fn resolve(t: &Value, variables: &Value) -> Result<(Value, Vec<String>)> {
    let map = variables
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["name"].as_str().unwrap(), v["value"].as_str().unwrap()))
        .collect::<BTreeMap<_, _>>();
    let pattern = regex::Regex::new(r"\{\{(=?)([^{}]+)\}\}").unwrap();
    let mut used = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut substitute = |s: &str| -> Result<String> {
        let mut invalid = false;
        let result = pattern.replace_all(s, |c: &regex::Captures| {
            let name = c[2].trim();
            if name.len() > 64 || !validation::variable_name(name) {
                invalid = true;
                return c[0].to_owned();
            }
            if &c[1] == "=" {
                return format!("{{{{{name}}}}}");
            }
            used.insert(name.to_owned());
            match map.get(name) {
                Some(v) => (*v).to_owned(),
                None => {
                    missing.insert(name.to_owned());
                    c[0].to_owned()
                }
            }
        });
        if invalid {
            return Err(Error::bad("Repeater contains an invalid variable"));
        }
        Ok(result.into_owned())
    };
    let address = substitute(t["url"].as_str().unwrap())?;
    let method = substitute(t["method"].as_str().unwrap())?;
    let body = substitute(t["body"].as_str().unwrap())?;
    let mut h = serde_json::Map::new();
    for header in t["headers"].as_array().unwrap() {
        h.insert(
            header["name"].as_str().unwrap().into(),
            json!(substitute(header["value"].as_str().unwrap())?),
        );
    }
    if !missing.is_empty() {
        return Err(Error::bad(format!(
            "Unresolved Repeater variables: {}",
            missing.into_iter().take(8).collect::<Vec<_>>().join(", ")
        )));
    }
    let mut resolved = request(&json!({"url":address,"method":method,"headers":h,"body":body}))?;
    resolved["timeout_ms"] = t["timeout_ms"].clone();
    Ok((resolved, used.into_iter().collect()))
}
pub fn compare(a: &Value, b: &Value) -> Value {
    let ar = &a["response"];
    let br = &b["response"];
    let map = |v: &Value| {
        v["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    h["name"].as_str().unwrap().to_ascii_lowercase(),
                    h["value"].clone(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let ah = map(ar);
    let bh = map(br);
    let ab = ar["body"].as_str().unwrap().len();
    let bb = br["body"].as_str().unwrap().len();
    json!({"protocol_version":1,"baseline_id":a["id"],"current_id":b["id"],"baseline_status":ar["status"],"current_status":br["status"],"status_changed":ar["status"]!=br["status"],"duration_delta_ms":br["duration_ms"].as_i64().unwrap()-ar["duration_ms"].as_i64().unwrap(),"baseline_body_bytes":ab,"current_body_bytes":bb,"body_bytes_delta":bb as i64-ab as i64,"baseline_body_sha256":ar["body_sha256"],"current_body_sha256":br["body_sha256"],"body_changed":ar["body_sha256"]!=br["body_sha256"],"headers_added":bh.keys().filter(|k|!ah.contains_key(*k)).collect::<Vec<_>>(),"headers_removed":ah.keys().filter(|k|!bh.contains_key(*k)).collect::<Vec<_>>(),"headers_changed":bh.iter().filter(|(k,v)|ah.get(*k).is_some_and(|old|old!=*v)).map(|(k,_)|k).collect::<Vec<_>>(),"partial":([&ar["headers_truncated"],&ar["body_truncated"],&br["headers_truncated"],&br["body_truncated"]].contains(&&json!(true)))})
}
