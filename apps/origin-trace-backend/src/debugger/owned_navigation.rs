//! A bounded blank -> armed owner -> navigation transaction for owned pages.
use super::{Debugger, connection::Connection, network_capture::Owner};
use crate::error::{Code, Error, Result};
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

const TRANSACTION: Duration = Duration::from_secs(15);
const CLEANUP: Duration = Duration::from_secs(3);

// Cancellation must not leave a known newly-created blank page behind. Never
// reconnect to clean it up: target IDs are meaningful only in this browser.
struct NewPage {
    connection: Arc<Connection>,
    target: Option<String>,
}
impl Drop for NewPage {
    fn drop(&mut self) {
        if let Some(target) = self.target.take() {
            let connection = self.connection.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    CLEANUP,
                    connection.command("Target.closeTarget", json!({"targetId":target}), CLEANUP),
                )
                .await;
            });
        }
    }
}

impl Debugger {
    fn owned_page_live(&self, connection: &Arc<Connection>, context: &str) -> Result<()> {
        if self.stopping.load(Ordering::Acquire)
            || connection.is_closed()
            || !self.capture.browser.current(connection)
            || self.experiment.context().as_deref() != Some(context)
        {
            return Err(Error::conflict(
                "Owned page creation lost its browser or context",
            ));
        }
        Ok(())
    }

    fn owned_page_owner(
        &self,
        connection: &Arc<Connection>,
        target: &str,
        pinned: &mut Option<Arc<Owner>>,
    ) -> Result<Option<Arc<Owner>>> {
        let owner = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(target)
            .cloned();
        if let Some(previous) = pinned.as_ref() {
            if previous.retired.load(Ordering::Acquire)
                || owner
                    .as_ref()
                    .is_none_or(|current| !Arc::ptr_eq(previous, current))
            {
                return Err(Error::conflict("Owned page capture owner changed"));
            }
        }
        let Some(owner) = owner else {
            return Ok(None);
        };
        if owner.retired.load(Ordering::Acquire)
            || owner
                .connection
                .as_ref()
                .is_none_or(|c| !Arc::ptr_eq(c, connection))
            || owner.target["id"] != target
            || owner.session.is_none()
        {
            return Err(Error::conflict("Owned page capture owner is unavailable"));
        }
        *pinned = Some(owner.clone());
        if !owner.ready.load(Ordering::Acquire)
            || self.has_capture_hold(connection, owner.session.as_deref().unwrap())
        {
            return Ok(None);
        }
        Ok(Some(owner))
    }

    pub(super) async fn create_owned_capture_page(
        self: &Arc<Self>,
        address: &str,
    ) -> Result<Value> {
        let context = self
            .experiment
            .context()
            .ok_or_else(|| Error::conflict("Disposable context is unavailable"))?;
        let connection = self
            .capture
            .browser
            .owned_ready_connection()
            .ok_or_else(|| Error::conflict("Owned browser capture is not armed"))?;
        let mut page = NewPage {
            connection: connection.clone(),
            target: None,
        };
        let result = tokio::time::timeout(TRANSACTION, async {
            self.owned_page_live(&connection, &context)?;
            let created = connection
                .command_guarded(
                    "Target.createTarget",
                    json!({"url":"about:blank","browserContextId":context,"background":true}),
                    TRANSACTION,
                    || {
                        self.owned_page_live(&connection, &context).is_ok()
                            && self.require_scope_idle().is_ok()
                    },
                )
                .await?
                .ok_or_else(|| {
                    Error::conflict("Owned page creation authority expired before send")
                })?;
            let target = created["targetId"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 4096)
                .ok_or_else(|| Error::conflict("Browser returned an invalid owned page identity"))?
                .to_owned();
            page.target = Some(target.clone());
            let mut pinned = None;
            let owner = loop {
                self.owned_page_live(&connection, &context)?;
                if let Some(owner) = self.owned_page_owner(&connection, &target, &mut pinned)? {
                    break owner;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            };
            let info = connection
                .command(
                    "Target.getTargetInfo",
                    json!({"targetId":target}),
                    TRANSACTION,
                )
                .await?;
            let info = &info["targetInfo"];
            if info["targetId"] != target
                || info["browserContextId"] != context
                || info["type"] != "page"
                || info["url"] != "about:blank"
            {
                return Err(Error::conflict(
                    "Owned page is no longer the expected blank page",
                ));
            }
            self.owned_page_live(&connection, &context)?;
            if self
                .owned_page_owner(&connection, &target, &mut pinned)?
                .is_none()
            {
                return Err(Error::conflict("Owned page capture readiness was lost"));
            }
            self.require_scope_idle()?;
            if address != "about:blank" {
                let reply = connection
                    .command_in_session_guarded(
                        "Page.navigate",
                        json!({"url":address}),
                        TRANSACTION,
                        owner.session.as_deref().unwrap(),
                        || {
                            self.owned_page_live(&connection, &context).is_ok()
                                && self
                                    .owned_page_owner(&connection, &target, &mut pinned)
                                    .is_ok_and(|owner| owner.is_some())
                                && self.require_scope_idle().is_ok()
                        },
                    )
                    .await?
                    .ok_or_else(|| {
                        Error::conflict("Owned page navigation authority expired before send")
                    })?;
                if reply.get("errorText").is_some() {
                    return Err(Error::conflict("Owned page navigation failed"));
                }
            }
            self.owned_page_live(&connection, &context)?;
            self.refresh_experiment().await?;
            self.owned_page_live(&connection, &context)?;
            Ok(json!({"targetId":target}))
        })
        .await
        .unwrap_or_else(|_| {
            Err(Error::conflict("Owned page creation timed out").with_code(Code::Timeout))
        });
        if result.is_ok() {
            page.target = None;
        }
        result
    }
}
