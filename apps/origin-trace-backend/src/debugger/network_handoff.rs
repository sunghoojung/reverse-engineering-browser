//! Narrow proof for a main resource whose completion moves to another target.
//!
//! Ordinary request identifiers remain session-scoped. The caller must first
//! establish: actual Network.loadingFinished, one unambiguous pending candidate
//! (including collisions with completed requests), distinct sessions on the same
//! live connection, and trustworthy target lineage. `relation` is Some(true) for
//! a proven ancestor, Some(false) for a conflicting or unresolved known parent,
//! and None only when no parent information exists. This helper does not infer
//! ownership from URL similarity or terminal request ID alone.

#[derive(Clone, Debug)]
pub(super) struct MainResource {
    pub request_id: String,
    pub loader_id: Option<String>,
    pub frame_id: Option<String>,
    pub resource_type: String,
    pub url: String,
    pub timestamp: f64,
}

impl MainResource {
    /// Retain exact protocol spelling. Oversized/malformed fields are rejected,
    /// never truncated into an identity that could match a different request.
    pub(super) fn from_event(params: &serde_json::Value) -> Option<Self> {
        let string = |value: &serde_json::Value, limit: usize, empty: bool| {
            value
                .as_str()
                .filter(|text| text.len() <= limit && (empty || !text.is_empty()))
                .map(str::to_owned)
        };
        let request_id = string(&params["requestId"], 4096, false)?;
        let loader_id = string(&params["loaderId"], 4096, true)?;
        let resource_type = string(&params["type"], 128, false)?;
        let url = string(&params["request"]["url"], 65536, false)?;
        let timestamp = params["timestamp"]
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0)?;
        let frame_id = match params.get("frameId") {
            Some(value) => Some(string(value, 4096, true)?),
            None => None,
        };
        match resource_type.as_str() {
            "Document"
                if loader_id == request_id
                    && frame_id.as_ref().is_some_and(|frame| !frame.is_empty()) => {}
            "Script" if loader_id.is_empty() => {}
            _ => return None,
        }
        Some(Self {
            request_id,
            loader_id: Some(loader_id),
            frame_id,
            resource_type,
            url,
            timestamp,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct OwnerInfo {
    pub target_id: String,
    pub target_type: String,
    pub url: String,
}

/// This proof authorizes only terminal adoption, never transfer of unrelated
/// events or subsequent requests. Request/body provenance remains explicit.
pub(super) fn proof(
    source: &OwnerInfo,
    destination: &OwnerInfo,
    relation: Option<bool>,
    resource: &MainResource,
    terminal_timestamp: f64,
) -> bool {
    if source.target_id.is_empty()
        || destination.target_id.is_empty()
        || source.target_id == destination.target_id
        || resource.request_id.is_empty()
        || resource.url.is_empty()
        || !resource.timestamp.is_finite()
        || resource.timestamp < 0.0
        || !terminal_timestamp.is_finite()
        || terminal_timestamp < resource.timestamp
    {
        return false;
    }
    match resource.resource_type.as_str() {
        "Document" => {
            matches!(source.target_type.as_str(), "page" | "iframe")
                && destination.target_type == "iframe"
                && relation == Some(true)
                && resource.loader_id.as_deref() == Some(resource.request_id.as_str())
                && resource.frame_id.as_deref() == Some(destination.target_id.as_str())
        }
        "Script" => {
            matches!(
                source.target_type.as_str(),
                "page" | "iframe" | "worker" | "shared_worker"
            ) && matches!(destination.target_type.as_str(), "worker" | "shared_worker")
                && relation != Some(false)
                && resource.loader_id.as_deref() == Some("")
                && resource.request_id == destination.target_id
                && resource.url == destination.url
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{MainResource, OwnerInfo, proof};

    fn source() -> OwnerInfo {
        OwnerInfo {
            target_id: "parent".into(),
            target_type: "page".into(),
            url: "http://localhost/page".into(),
        }
    }

    fn document() -> (OwnerInfo, MainResource) {
        (
            OwnerInfo {
                target_id: "child-frame".into(),
                target_type: "iframe".into(),
                url: "http://localhost/frame".into(),
            },
            MainResource {
                request_id: "navigation".into(),
                loader_id: Some("navigation".into()),
                frame_id: Some("child-frame".into()),
                resource_type: "Document".into(),
                url: "http://localhost/frame".into(),
                timestamp: 10.0,
            },
        )
    }

    fn worker() -> (OwnerInfo, MainResource) {
        (
            OwnerInfo {
                target_id: "worker-token".into(),
                target_type: "worker".into(),
                url: "http://localhost/worker.js".into(),
            },
            MainResource {
                request_id: "worker-token".into(),
                loader_id: Some(String::new()),
                frame_id: None,
                resource_type: "Script".into(),
                url: "http://localhost/worker.js".into(),
                timestamp: 10.0,
            },
        )
    }

    #[test]
    fn iframe_requires_exact_main_document_identity_and_ancestry() {
        let source = source();
        let (destination, resource) = document();
        assert!(proof(&source, &destination, Some(true), &resource, 11.0));
        for relation in [None, Some(false)] {
            assert!(!proof(&source, &destination, relation, &resource, 11.0));
        }
        for loader in [None, Some(String::new()), Some("other".into())] {
            let mut changed = resource.clone();
            changed.loader_id = loader;
            assert!(!proof(&source, &destination, Some(true), &changed, 11.0));
        }
        for frame in [None, Some(String::new()), Some("other".into())] {
            let mut changed = resource.clone();
            changed.frame_id = frame;
            assert!(!proof(&source, &destination, Some(true), &changed, 11.0));
        }
    }

    #[test]
    fn worker_requires_target_token_empty_loader_and_exact_url() {
        let source = source();
        let (destination, resource) = worker();
        for relation in [None, Some(true)] {
            assert!(proof(&source, &destination, relation, &resource, 11.0));
        }
        assert!(!proof(&source, &destination, Some(false), &resource, 11.0));
        for loader in [None, Some("worker-token".into()), Some("other".into())] {
            let mut changed = resource.clone();
            changed.loader_id = loader;
            assert!(!proof(&source, &destination, None, &changed, 11.0));
        }
        for request_id in ["", "colliding-ordinary-request"] {
            let mut changed = resource.clone();
            changed.request_id = request_id.into();
            assert!(!proof(&source, &destination, None, &changed, 11.0));
        }
        for url in [
            "",
            "http://localhost/other.js",
            "http://localhost/worker.js#different",
        ] {
            let mut changed = destination.clone();
            changed.url = url.into();
            assert!(!proof(&source, &changed, None, &resource, 11.0));
        }
    }

    #[test]
    fn worker_source_and_destination_types_are_explicitly_bounded() {
        let (destination, resource) = worker();
        for kind in ["page", "iframe", "worker", "shared_worker"] {
            let mut source = source();
            source.target_type = kind.into();
            for destination_kind in ["worker", "shared_worker"] {
                let mut destination = destination.clone();
                destination.target_type = destination_kind.into();
                assert!(proof(&source, &destination, None, &resource, 11.0));
            }
        }
        for kind in ["service_worker", "browser", "other", ""] {
            let mut owner = source();
            owner.target_type = kind.into();
            assert!(!proof(&owner, &destination, None, &resource, 11.0));
            let mut changed = destination.clone();
            changed.target_type = kind.into();
            assert!(!proof(&source(), &changed, None, &resource, 11.0));
        }
    }

    #[test]
    fn ordinary_resources_and_same_target_are_not_handoffs() {
        for (mut destination, resource) in [document(), worker()] {
            let source = source();
            for kind in ["Fetch", "XHR", "Image", "Stylesheet", "Other", ""] {
                let mut changed = resource.clone();
                changed.resource_type = kind.into();
                assert!(!proof(&source, &destination, Some(true), &changed, 11.0));
            }
            destination.target_id = source.target_id.clone();
            assert!(!proof(&source, &destination, Some(true), &resource, 11.0));
        }
    }

    #[test]
    fn invalid_or_reversed_timestamps_cannot_adopt() {
        let source = source();
        let (destination, resource) = document();
        assert!(proof(&source, &destination, Some(true), &resource, 10.0));
        for timestamp in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 9.0] {
            assert!(!proof(
                &source,
                &destination,
                Some(true),
                &resource,
                timestamp
            ));
        }
        for timestamp in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let mut changed = resource.clone();
            changed.timestamp = timestamp;
            assert!(!proof(&source, &destination, Some(true), &changed, 11.0));
        }
    }

    #[test]
    fn iframe_rejects_wrong_owner_types_and_missing_identity() {
        let (destination, resource) = document();
        for kind in ["worker", "shared_worker", "service_worker", "browser", ""] {
            let mut source = source();
            source.target_type = kind.into();
            assert!(!proof(&source, &destination, Some(true), &resource, 11.0));
        }
        for kind in ["page", "worker", "shared_worker", "service_worker", ""] {
            let mut changed = destination.clone();
            changed.target_type = kind.into();
            assert!(!proof(&source(), &changed, Some(true), &resource, 11.0));
        }
        let mut owner = source();
        owner.target_id.clear();
        assert!(!proof(&owner, &destination, Some(true), &resource, 11.0));
        let mut changed = resource;
        changed.url.clear();
        assert!(!proof(&source(), &destination, Some(true), &changed, 11.0));
    }

    fn event() -> serde_json::Value {
        serde_json::json!({
            "requestId": "navigation", "loaderId": "navigation", "frameId": "child-frame",
            "type": "Document", "timestamp": 10.0,
            "request": {"url": "http://localhost/frame"}
        })
    }

    #[test]
    fn event_parser_requires_exact_potential_main_resource_fields() {
        let parsed = MainResource::from_event(&event()).unwrap();
        assert_eq!(parsed.request_id, "navigation");
        for field in [
            "requestId",
            "loaderId",
            "frameId",
            "type",
            "timestamp",
            "request",
        ] {
            let mut changed = event();
            changed.as_object_mut().unwrap().remove(field);
            assert!(MainResource::from_event(&changed).is_none(), "{field}");
        }
        for kind in ["Fetch", "XHR", "Image", "Other", ""] {
            let mut changed = event();
            changed["type"] = serde_json::json!(kind);
            assert!(MainResource::from_event(&changed).is_none());
        }
        let mut script = event();
        script["type"] = serde_json::json!("Script");
        script["loaderId"] = serde_json::json!("");
        script.as_object_mut().unwrap().remove("frameId");
        assert!(MainResource::from_event(&script).is_some());
        script["frameId"] = serde_json::json!("");
        assert!(MainResource::from_event(&script).is_some());
        script["frameId"] = serde_json::Value::Null;
        assert!(MainResource::from_event(&script).is_none());
        script.as_object_mut().unwrap().remove("loaderId");
        assert!(MainResource::from_event(&script).is_none());
        let mut changed = event();
        changed["loaderId"] = serde_json::json!("different-loader");
        assert!(MainResource::from_event(&changed).is_none());
    }

    #[test]
    fn event_parser_rejects_overlong_identity_instead_of_truncating() {
        for field in ["requestId", "loaderId", "frameId"] {
            let mut changed = event();
            changed[field] = serde_json::json!("x".repeat(4097));
            assert!(MainResource::from_event(&changed).is_none(), "{field}");
        }
        let mut boundary = event();
        boundary["requestId"] = serde_json::json!("x".repeat(4096));
        boundary["loaderId"] = boundary["requestId"].clone();
        boundary["frameId"] = serde_json::json!("f".repeat(4096));
        boundary["request"]["url"] = serde_json::json!("u".repeat(65536));
        let parsed = MainResource::from_event(&boundary).unwrap();
        assert_eq!(parsed.request_id.len(), 4096);
        assert_eq!(parsed.url.len(), 65536);
        boundary["request"]["url"] = serde_json::json!("u".repeat(65537));
        assert!(MainResource::from_event(&boundary).is_none());
        let mut changed = event();
        changed["type"] = serde_json::json!("T".repeat(129));
        assert!(MainResource::from_event(&changed).is_none());
    }

    #[test]
    fn event_parser_rejects_malformed_values_and_timestamps() {
        for field in ["requestId", "loaderId", "frameId", "type"] {
            for value in [
                serde_json::Value::Null,
                serde_json::json!(7),
                serde_json::json!([]),
            ] {
                let mut changed = event();
                changed[field] = value;
                assert!(MainResource::from_event(&changed).is_none());
            }
        }
        for value in [
            serde_json::Value::Null,
            serde_json::json!("10"),
            serde_json::json!(-1),
        ] {
            let mut changed = event();
            changed["timestamp"] = value;
            assert!(MainResource::from_event(&changed).is_none());
        }
        let mut changed = event();
        changed["request"]["url"] = serde_json::json!("");
        assert!(MainResource::from_event(&changed).is_none());
    }
}
