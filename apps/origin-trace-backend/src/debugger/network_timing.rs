//! Bounded source clock evidence. Display durations are not timing evidence.
use serde_json::{Value, json};

const OFFSETS: [&str; 13] = [
    "proxyStart",
    "proxyEnd",
    "dnsStart",
    "dnsEnd",
    "connectStart",
    "connectEnd",
    "sslStart",
    "sslEnd",
    "sendStart",
    "sendEnd",
    "receiveHeadersStart",
    "receiveHeadersEnd",
    "workerStart",
];

fn number(parent: &Value, key: &str, offset: bool) -> Value {
    let Some(raw) = parent.get(key) else {
        return json!({"state":"missing"});
    };
    let Some(value) = raw.as_f64().filter(|v| v.is_finite()) else {
        return json!({"state":"invalid"});
    };
    if offset && value == -1.0 {
        return json!({"state":"unavailable"});
    }
    // Keep exact binary64 values; reject nonsensical magnitudes before conversion.
    if !(0.0..=8_640_000_000_000.0).contains(&value) {
        return json!({"state":"invalid"});
    }
    json!({"state":"available","value":value})
}

fn resource(response: &Value) -> Value {
    let Some(timing) = response.get("timing") else {
        return json!({"state":"missing"});
    };
    if !timing.is_object() {
        return json!({"state":"invalid"});
    }
    let mut fields = json!({"requestTime":number(timing,"requestTime",false)});
    for key in OFFSETS {
        fields[key] = number(timing, key, true);
    }
    json!({"state":"available","fields":fields})
}

pub(super) fn begin(p: &Value) -> Value {
    json!({"format":"reb-network-timing-v1",
        "request_monotonic_seconds":number(p,"timestamp",false),
        "request_wall_seconds":number(p,"wallTime",false),
        "response_monotonic_seconds":{"state":"missing"},
        "completion_monotonic_seconds":{"state":"missing"},
        "resource_timing":{"state":"missing"},
        "response_observed":false,"completion_observed":false,
        "response_source":"none","completion_source":"none",
        "duplicate_response":false,"duplicate_completion":false,"response_after_completion":false})
}

pub(super) fn response(record: &mut Value, p: &Value, redirected: bool) {
    let timing = &mut record["timing_evidence"];
    if !timing.is_object() {
        return;
    }
    if timing["response_observed"] == true {
        timing["duplicate_response"] = json!(true);
        return;
    }
    timing["response_after_completion"] = timing["completion_observed"].clone();
    timing["response_observed"] = json!(true);
    timing["response_source"] = json!(if redirected {
        "redirectResponse"
    } else {
        "responseReceived"
    });
    // A redirect's next-hop timestamp is not the prior hop's response timestamp.
    if !redirected {
        timing["response_monotonic_seconds"] = number(p, "timestamp", false);
    }
    timing["resource_timing"] = resource(&p["response"]);
}

pub(super) fn finish(record: &mut Value, p: &Value, failed: bool, redirected: bool) {
    let timing = &mut record["timing_evidence"];
    if !timing.is_object() {
        return;
    }
    if timing["completion_observed"] == true {
        timing["duplicate_completion"] = json!(true);
        return;
    }
    timing["completion_observed"] = json!(true);
    timing["completion_source"] = json!(if redirected {
        "redirectRequest"
    } else if failed {
        "loadingFailed"
    } else {
        "loadingFinished"
    });
    timing["completion_monotonic_seconds"] = number(p, "timestamp", false);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clocks_preserve_fractional_values_and_explicit_missing_invalid_states() {
        let timing = begin(&json!({"timestamp":1.23456789,"wallTime":1792000000.123456}));
        assert_eq!(timing["request_monotonic_seconds"]["value"], 1.23456789);
        assert_eq!(timing["request_wall_seconds"]["value"], 1792000000.123456);
        assert_eq!(
            begin(&json!({}))["request_wall_seconds"]["state"],
            "missing"
        );
        for value in [json!(null), json!(-1), json!("123"), json!(1e30)] {
            assert_eq!(
                begin(&json!({"wallTime":value}))["request_wall_seconds"]["state"],
                "invalid"
            );
        }
        assert_eq!(
            begin(&json!({"wallTime":0}))["request_wall_seconds"]["value"],
            0.0
        );
    }

    #[test]
    fn resource_projection_is_bounded_and_does_not_invent_unavailable_phases() {
        let value = resource(&json!({"timing":{"requestTime":1.1,"dnsStart":-1,
            "dnsEnd":null,"sendStart":0.125,"sendEnd":-2,"futureField":"unretained"}}));
        let fields = &value["fields"];
        assert_eq!(fields.as_object().unwrap().len(), 14);
        assert_eq!(fields["dnsStart"]["state"], "unavailable");
        assert_eq!(fields["dnsEnd"]["state"], "invalid");
        assert_eq!(fields["sendStart"]["value"], 0.125);
        assert_eq!(fields["sendEnd"]["state"], "invalid");
        assert_eq!(fields["sslStart"]["state"], "missing");
        assert!(fields.get("futureField").is_none());
        assert_eq!(resource(&json!({"timing":[]}))["state"], "invalid");
    }

    #[test]
    fn duplicate_and_reversed_events_keep_first_source_evidence() {
        let mut record = json!({"timing_evidence":begin(&json!({"timestamp":2}))});
        finish(&mut record, &json!({"timestamp":1}), false, false);
        finish(&mut record, &json!({"timestamp":3}), true, false);
        response(&mut record, &json!({"timestamp":0.5,"response":{}}), false);
        response(&mut record, &json!({"timestamp":5,"response":{}}), false);
        let timing = &record["timing_evidence"];
        assert_eq!(timing["completion_monotonic_seconds"]["value"], 1.0);
        assert_eq!(timing["completion_source"], "loadingFinished");
        assert_eq!(timing["response_monotonic_seconds"]["value"], 0.5);
        assert_eq!(timing["duplicate_completion"], true);
        assert_eq!(timing["duplicate_response"], true);
        assert_eq!(timing["response_after_completion"], true);
    }
}
