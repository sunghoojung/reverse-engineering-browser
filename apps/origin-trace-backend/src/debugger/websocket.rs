//! Observational bounded CDP WebSocket messages. No sends or message reassembly.
use crate::validation;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub(super) fn empty() -> Value {
    json!({"format":"reb-websocket-capture-v1","connections":[],"frames":[],
        "next_connection":0,"next_frame":0,"dropped_connections":0,"dropped_frames":0,
        "orphan_events":0,"malformed_events":0,
        "limits":{"connections":64,"frames":512,"payload_bytes":4096}})
}

fn increment(value: &mut Value, key: &str) {
    value[key] = json!(value[key].as_u64().unwrap_or(0).saturating_add(1));
}

pub(super) fn event(state: &mut Value, method: &str, p: &Value) {
    let target = state["target"]["id"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned();
    if state["network"]["websockets"].is_null() {
        state["network"]["websockets"] = empty();
    }
    let capture = &mut state["network"]["websockets"];
    let Some(id) = p["requestId"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 4096)
    else {
        increment(capture, "malformed_events");
        return;
    };
    if method == "Network.webSocketCreated" {
        let Some(url) = p["url"].as_str().filter(|url| !url.is_empty()) else {
            increment(capture, "malformed_events");
            return;
        };
        // Reused protocol IDs get separate generation identities; old frames stay old.
        if capture["connections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["protocol_request_id"] == id && item["state"] != "closed")
        {
            increment(capture, "malformed_events");
            return;
        }
        increment(capture, "next_connection");
        let serial = capture["next_connection"].clone();
        let connections = capture["connections"].as_array_mut().unwrap();
        if connections.len() >= 64 {
            connections.remove(0);
            increment(capture, "dropped_connections");
        }
        capture["connections"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":serial,
            "protocol_request_id":id,"target_id":target,"url":validation::truncate(url,8192),
            "url_truncated":url.len()>8192,"state":"created","handshake_status":null,
            "handshake_monotonic_seconds":null,"closed_monotonic_seconds":null,"error_count":0}));
        return;
    }
    let Some(index) = capture["connections"]
        .as_array()
        .unwrap()
        .iter()
        .rposition(|item| item["protocol_request_id"] == id && item["state"] != "closed")
    else {
        increment(capture, "orphan_events");
        return;
    };
    let Some(timestamp) = p["timestamp"]
        .as_f64()
        .filter(|time| time.is_finite() && *time >= 0.0)
    else {
        increment(capture, "malformed_events");
        return;
    };
    match method {
        "Network.webSocketHandshakeResponseReceived" => {
            let status = p["response"]["status"]
                .as_u64()
                .filter(|status| (100..=599).contains(status));
            let connection = &mut capture["connections"][index];
            connection["handshake_status"] = json!(status);
            connection["handshake_monotonic_seconds"] = json!(timestamp);
            connection["state"] = json!(if status == Some(101) {
                "open"
            } else {
                "handshake_observed"
            });
        }
        "Network.webSocketClosed" => {
            capture["connections"][index]["state"] = json!("closed");
            capture["connections"][index]["closed_monotonic_seconds"] = json!(timestamp);
        }
        "Network.webSocketFrameError" => {
            increment(&mut capture["connections"][index], "error_count");
        }
        "Network.webSocketFrameSent" | "Network.webSocketFrameReceived" => {
            let frame = &p["response"];
            let Some(opcode) = frame["opcode"].as_u64().filter(|opcode| *opcode <= 15) else {
                increment(capture, "malformed_events");
                return;
            };
            let Some(payload) = frame["payloadData"].as_str() else {
                increment(capture, "malformed_events");
                return;
            };
            let Some(masked) = frame["mask"].as_bool() else {
                increment(capture, "malformed_events");
                return;
            };
            let (data, size, truncated, payload_state) = if opcode == 1 {
                (
                    validation::truncate(payload, 4096),
                    Some(payload.len()),
                    payload.len() > 4096,
                    "available",
                )
            } else if payload.len() > 65536 {
                (String::new(), None, true, "oversized")
            } else {
                let Ok(bytes) = STANDARD.decode(payload) else {
                    increment(capture, "malformed_events");
                    return;
                };
                if STANDARD.encode(&bytes) != payload {
                    increment(capture, "malformed_events");
                    return;
                }
                (
                    STANDARD.encode(&bytes[..bytes.len().min(4096)]),
                    Some(bytes.len()),
                    bytes.len() > 4096,
                    "available",
                )
            };
            increment(capture, "next_frame");
            let sequence = capture["next_frame"].clone();
            let connection = capture["connections"][index]["id"].clone();
            if capture["frames"].as_array().unwrap().len() >= 512 {
                capture["frames"].as_array_mut().unwrap().remove(0);
                increment(capture, "dropped_frames");
            }
            capture["frames"].as_array_mut().unwrap().push(json!({"sequence":sequence,
                "connection_id":connection,"target_id":target,"monotonic_seconds":timestamp,
                "direction":if method.ends_with("Sent") {"sent"} else {"received"},"opcode":opcode,
                "masked":masked,"encoding":if opcode==1 {"utf8"} else {"base64"},
                "payload":data,"payload_bytes":size,"truncated":truncated,"payload_state":payload_state}));
        }
        // Handshake requests carry credentials; this projection intentionally records
        // message events and response status only, not handshake headers or cookies.
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Value {
        json!({"target":{"id":"owned"},"network":{"websockets":empty()}})
    }
    fn created(state: &mut Value, id: &str) {
        event(
            state,
            "Network.webSocketCreated",
            &json!({"requestId":id,"url":"ws://127.0.0.1/authored"}),
        );
    }
    fn frame(state: &mut Value, id: &str, opcode: u8, payload: &str) {
        event(
            state,
            "Network.webSocketFrameReceived",
            &json!({"requestId":id,"timestamp":1.25,
            "response":{"opcode":opcode,"mask":false,"payloadData":payload}}),
        );
    }
    #[test]
    fn text_binary_control_and_connection_lifecycle_keep_exact_ownership() {
        let mut value = state();
        created(&mut value, "a");
        frame(&mut value, "a", 1, "雪<script>inert</script>");
        frame(&mut value, "a", 2, "AP8=");
        frame(&mut value, "a", 9, "");
        event(
            &mut value,
            "Network.webSocketClosed",
            &json!({"requestId":"a","timestamp":2.0}),
        );
        frame(&mut value, "a", 1, "late");
        created(&mut value, "a");
        frame(&mut value, "a", 1, "new");
        let capture = &value["network"]["websockets"];
        assert_eq!(capture["frames"][0]["payload"], "雪<script>inert</script>");
        assert_eq!(capture["frames"][1]["encoding"], "base64");
        assert_eq!(capture["frames"][1]["payload_bytes"], 2);
        assert_eq!(capture["frames"][2]["opcode"], 9);
        assert_eq!(capture["orphan_events"], 1);
        assert_ne!(
            capture["frames"][0]["connection_id"],
            capture["frames"][3]["connection_id"]
        );
        assert_eq!(capture["connections"][0]["state"], "closed");
    }
    #[test]
    fn limits_malformed_events_and_oversized_payloads_are_visible() {
        let mut value = state();
        for id in 0..65 {
            created(&mut value, &id.to_string());
        }
        frame(&mut value, "0", 1, "evicted");
        for _ in 0..513 {
            frame(&mut value, "64", 1, &"雪".repeat(1500));
        }
        frame(&mut value, "64", 2, "bad");
        frame(&mut value, "64", 2, &"A".repeat(65540));
        let capture = &value["network"]["websockets"];
        assert_eq!(capture["connections"].as_array().unwrap().len(), 64);
        assert_eq!(capture["frames"].as_array().unwrap().len(), 512);
        assert_eq!(capture["dropped_connections"], 1);
        assert_eq!(capture["dropped_frames"], 2);
        assert_eq!(capture["orphan_events"], 1);
        assert_eq!(capture["malformed_events"], 1);
        assert_eq!(
            capture["frames"][0]["payload"].as_str().unwrap().len(),
            4095
        );
        assert_eq!(capture["frames"][511]["payload_state"], "oversized");
        assert_eq!(capture["frames"][511]["payload_bytes"], Value::Null);
    }
}
