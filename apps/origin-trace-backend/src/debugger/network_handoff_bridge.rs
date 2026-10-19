//! Connection-scoped proof for terminal main-resource events on a child owner.
use super::{
    Debugger,
    connection::Connection,
    network_capture::Owner,
    network_handoff::{OwnerInfo, proof},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, atomic::Ordering},
};

fn retain_lineage(
    lineage: &mut BTreeMap<(usize, String), Option<String>>,
    key: (usize, String),
    value: Option<String>,
) -> bool {
    if let Some(previous) = lineage.get_mut(&key) {
        if *previous != value {
            *previous = None;
        }
        true
    } else if lineage.len() < 512 {
        lineage.insert(key, value);
        true
    } else {
        false
    }
}

impl Debugger {
    pub(super) fn remember_handoff_lineage(
        &self,
        connection: &Arc<Connection>,
        target: &Value,
        parent_session: Option<&str>,
    ) {
        let Some(target_id) = target["targetId"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 4096)
        else {
            return;
        };
        if connection.is_closed() || !self.capture.browser.current(connection) {
            return;
        }
        let explicit = target.get("parentId").and_then(Value::as_str);
        let malformed = target.get("parentId").is_some()
            && explicit.is_none_or(|id| id.is_empty() || id.len() > 4096);
        let owners = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let parent = parent_session
            .and_then(|session| {
                owners.values().find(|owner| {
                    owner.session.as_deref() == Some(session)
                        && !owner.retired.load(Ordering::Acquire)
                        && owner
                            .connection
                            .as_ref()
                            .is_some_and(|c| Arc::ptr_eq(c, connection))
                })
            })
            .and_then(|owner| owner.target["id"].as_str());
        if parent_session.is_none() && target.get("parentId").is_none() {
            return;
        }
        let value = if malformed || (parent_session.is_some() && parent.is_none()) {
            None
        } else {
            match (explicit, parent) {
                (Some(a), Some(b)) if a != b => None,
                (Some(a), _) => Some(a.to_owned()),
                (_, Some(b)) => Some(b.to_owned()),
                _ => None,
            }
        };
        let key = (Arc::as_ptr(connection) as usize, target_id.to_owned());
        let mut lineage = self
            .capture
            .handoff_lineage
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !retain_lineage(&mut lineage, key, value) {
            self.capture
                .handoff_lineage_complete
                .store(false, Ordering::Release);
        }
    }

    pub(super) fn main_resource_completion_owner(
        &self,
        connection: &Arc<Connection>,
        destination: &Arc<Owner>,
        params: &Value,
    ) -> Option<Arc<Owner>> {
        if !self
            .capture
            .handoff_lineage_complete
            .load(Ordering::Acquire)
            || connection.is_closed()
            || !self.capture.browser.current(connection)
            || destination.retired.load(Ordering::Acquire)
        {
            return None;
        }
        let request_id = params["requestId"].as_str()?;
        let timestamp = params["timestamp"].as_f64()?;
        let (public, source_id) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            // An evicted collision is no longer observable. Do not adopt when
            // the retained ledger cannot establish complete request history.
            if state["network"]["dropped"].as_u64() != Some(0) {
                return None;
            }
            let mut candidates = state["network"]["requests"]
                .as_array()?
                .iter()
                .filter(|row| row["protocol_request_id"] == request_id);
            let row = candidates.next()?;
            // Even a retained completed collision makes adoption unsafe. Never
            // zip unrelated sessions merely because their request IDs match.
            if candidates.next().is_some()
                || row["state"] != "pending"
                || row["capture_owner"] == destination.id
            {
                return None;
            }
            (
                row["id"].as_str()?.to_owned(),
                row["capture_owner"].as_str()?.to_owned(),
            )
        };
        let owners = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let source = owners.values().find(|owner| owner.id == source_id)?.clone();
        if source.retired.load(Ordering::Acquire)
            || source.session.is_none()
            || destination.session.is_none()
            || source.session == destination.session
            || !source
                .connection
                .as_ref()
                .is_some_and(|c| Arc::ptr_eq(c, connection))
            || !destination
                .connection
                .as_ref()
                .is_some_and(|c| Arc::ptr_eq(c, connection))
        {
            return None;
        }
        let lineage = self
            .capture
            .handoff_lineage
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut current = destination.target["id"].as_str()?;
        let source_target = source.target["id"].as_str()?;
        let mut visited = BTreeSet::new();
        let mut known = false;
        let relation = loop {
            if !visited.insert(current.to_owned()) {
                break Some(false);
            }
            match lineage.get(&(Arc::as_ptr(connection) as usize, current.to_owned())) {
                Some(Some(parent)) if parent == source_target => break Some(true),
                Some(Some(parent)) => {
                    known = true;
                    current = parent;
                }
                Some(None) => break Some(false),
                None => break if known { Some(false) } else { None },
            }
        };
        let resources = self
            .capture
            .main_resources
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let resource = resources.get(&public)?;
        let info = |owner: &Owner| {
            Some(OwnerInfo {
                target_id: owner.target["id"].as_str()?.to_owned(),
                target_type: owner.target["type"].as_str()?.to_owned(),
                url: owner.target["url"].as_str()?.to_owned(),
            })
        };
        proof(
            &info(&source)?,
            &info(destination)?,
            relation,
            resource,
            timestamp,
        )
        .then_some(source.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_is_bounded_and_conflicts_are_sticky() {
        let mut lineage = BTreeMap::new();
        let key = (1, "child".to_owned());
        assert!(retain_lineage(
            &mut lineage,
            key.clone(),
            Some("parent".into())
        ));
        assert!(retain_lineage(
            &mut lineage,
            key.clone(),
            Some("other".into())
        ));
        assert!(retain_lineage(
            &mut lineage,
            key.clone(),
            Some("parent".into())
        ));
        assert_eq!(lineage[&key], None);
        for index in 1..512 {
            assert!(retain_lineage(&mut lineage, (1, index.to_string()), None));
        }
        assert!(!retain_lineage(&mut lineage, (1, "overflow".into()), None));
        assert_eq!(lineage.len(), 512);
        assert!(retain_lineage(&mut lineage, key, None));
    }
}
