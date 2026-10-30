//! Tenant setup owns only intent. Reads reuse existing domain observations.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs
use super::settings;
use crate::{Error, Failure};
use model::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::credential::RequestCredential;
use rss_mdm_authorization_service::{
    Permission,
    context::{AuthorizedPrincipal, RequestAuth},
};
pub(crate) mod http;
pub(crate) mod model;
use rss_mdm_registration_service::{admission::State, quotas::Channel};
use std::sync::Arc;
mod store;
pub(crate) const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

/// Observation calls may label their own operation. Restore the outer request even on cancellation.
struct ObservationAction<'a> {
    audit: &'a RequestAudit,
    original: &'static str,
    intent: rss_mdm_audit_integration::AuditIntent,
}
impl Drop for ObservationAction<'_> {
    fn drop(&mut self) {
        self.audit.set_action(self.original, self.intent);
    }
}

pub(crate) struct FirstUse {
    pub directory: Arc<settings::Directory>,
    pub tenant: rss_request_context::TenantId,
    pub instance: rss_identity_core::InstanceId,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub admission: rss_mdm_registration_service::admission::Admission,
    pub channels: Arc<crate::registration_channels::Channels>,
}
impl FirstUse {
    fn proof(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        write: bool,
    ) -> Result<(), Error> {
        p.session()?;
        if p.tenant_id() != self.tenant.to_string() || p.instance_id() != self.instance.to_string()
        {
            return Err(Error::Forbidden);
        }
        p.require(
            if write {
                Permission::RegistrationConfigurationWrite
            } else {
                Permission::RegistrationConfigurationRead
            },
            None,
        )?;
        p.bind_audit(audit)?;
        Ok(())
    }
    async fn progress(
        &self,
        auth: &RequestAuth,
        audit: &RequestAudit,
        continuation: &RequestCredential,
        saved: Saved,
    ) -> Result<Progress, Error> {
        let mut steps = Vec::new();
        for channel in &saved.intent.channels {
            steps.push(self.channel_step(&auth.proof, *channel).await);
        }
        if saved.intent.channels.contains(&Channel::Agent) {
            steps.push(
                self.items_step(
                    auth,
                    audit,
                    continuation,
                    "agent_registration",
                    &["registration"],
                )
                .await?,
            );
        }
        if saved.intent.channels.contains(&Channel::MacosMdm) {
            steps.push(
                self.items_step(
                    auth,
                    audit,
                    continuation,
                    "apple_materials",
                    &["apns-cert", "profile-cert"],
                )
                .await?,
            );
        }
        for (capability, decision) in &saved.intent.capabilities {
            let id = serde_json::to_value(capability)
                .map_err(|_| Error::Malformed)?
                .as_str()
                .ok_or(Error::Malformed)?
                .to_owned();
            steps.push(match decision {
                Decision::Skip { reason } => Step {
                    id,
                    status: Status::Skipped,
                    reason: Some(reason.clone()),
                    evidence: vec![],
                },
                Decision::Configure => {
                    self.items_step(auth, audit, continuation, &id, capability.items())
                        .await?
                }
            });
        }
        auth.proof.check_live()?;
        Ok(Progress::new(auth.proof.tenant_id().into(), saved, steps))
    }
    async fn channel_step(&self, proof: &AuthorizedPrincipal, channel: Channel) -> Step {
        use crate::registration_channels::Availability;
        let observed = self.channels.status(channel);
        let mut step = Step {
            id: channel.as_str().into(),
            status: match observed.availability {
                Availability::Ready => Status::Ready,
                Availability::Unconfigured => Status::Unconfigured,
                Availability::Fault => Status::Unavailable,
            },
            reason: observed
                .reason
                .and_then(|r| serde_json::to_value(r).ok())
                .and_then(|v| v.as_str().map(str::to_owned)),
            evidence: vec![],
        };
        let admission = self.admission.read(proof).await;
        match admission {
            Ok(settings) => {
                if settings
                    .iter()
                    .find(|s| s.channel == channel)
                    .is_none_or(|s| s.admission != State::Allowed)
                {
                    step.status = Status::Pending;
                    step.reason = Some("registration_not_allowed".into());
                }
            }
            Err(_) => {
                step.status = Status::Unavailable;
                step.reason = Some("admission_read_unavailable".into());
            }
        }
        step
    }
    async fn items_step(
        &self,
        auth: &RequestAuth,
        audit: &RequestAudit,
        continuation: &RequestCredential,
        id: &str,
        ids: &[&str],
    ) -> Result<Step, Error> {
        let catalog = settings::model::catalog(&auth.proof, false)?;
        let items: Vec<_> = catalog
            .into_iter()
            .filter(|i| ids.contains(&i.id))
            .collect();
        if items.len() != ids.len() {
            return Ok(Step {
                id: id.into(),
                status: Status::Forbidden,
                reason: Some("owner_permission_required".into()),
                evidence: vec![],
            });
        }
        let action = ObservationAction {
            audit,
            original: audit.snapshot().action,
            intent: audit.snapshot().intent,
        };
        let entries = self
            .directory
            .project(auth.proof.clone(), audit.clone(), continuation, items)
            .await;
        drop(action);
        projected_step(id, ids, entries)
    }
}
fn projected_step(
    id: &str,
    ids: &[&str],
    entries: Result<Vec<settings::model::Entry>, Error>,
) -> Result<Step, Error> {
    let (status, reason, evidence) = match entries {
        Ok(entries) => {
            if entries.len() != ids.len()
                || ids
                    .iter()
                    .any(|id| !entries.iter().any(|e| e.item.id == *id))
            {
                return Err(Error::Conflict);
            }
            let failed = entries.iter().find(|e| !e.projection.ready);
            let status = failed.map_or(Status::Ready, |e| match e.projection.status {
                settings::model::Status::Unknown => Status::Unknown,
                settings::model::Status::Unconfigured => Status::Unconfigured,
                settings::model::Status::Unavailable => Status::Unavailable,
                _ => Status::Pending,
            });
            let reason = failed.and_then(|e| e.projection.reason.map(str::to_owned));
            (status, reason, entries)
        }
        Err(error) if super::permission_denied(&error) => (
            Status::Forbidden,
            Some("owner_permission_required".into()),
            vec![],
        ),
        Err(_) => (
            Status::Unavailable,
            Some("owner_read_unavailable".into()),
            vec![],
        ),
    };
    Ok(Step {
        id: id.into(),
        status,
        reason,
        evidence,
    })
}
impl FirstUse {
    pub(crate) async fn read(
        &self,
        auth: &RequestAuth,
        audit: &RequestAudit,
        continuation: &RequestCredential,
    ) -> Result<Progress, Error> {
        self.proof(&auth.proof, audit, false)?;
        let saved = store::read(&self.audit, &auth.proof, audit).await?;
        self.progress(auth, audit, continuation, saved).await
    }
    pub(crate) async fn operation(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        id: uuid::Uuid,
    ) -> Result<Receipt, Error> {
        self.proof(proof, audit, false)?;
        store::operation(
            &self.audit,
            proof,
            audit,
            id,
            Permission::RegistrationConfigurationRead,
        )
        .await?
        .ok_or(Error::FirstUseOperationMissing)
    }
    pub(crate) async fn update(
        &self,
        auth: &RequestAuth,
        audit: &RequestAudit,
        continuation: &RequestCredential,
        id: uuid::Uuid,
        input: Update,
    ) -> Result<Receipt, Error> {
        self.proof(&auth.proof, audit, true)?;
        input.intent.validate()?;
        if id.is_nil() || input.expected_revision < 0 || input.expected_revision == i64::MAX {
            return Err(Error::Malformed);
        }
        let fingerprint = store::fingerprint(&auth.proof, &input)?;
        // Resolve durable outcomes before asking current owners. Expired materials
        // or unavailable providers cannot invalidate an already committed receipt.
        let previous = store::operation(
            &self.audit,
            &auth.proof,
            audit,
            id,
            Permission::RegistrationConfigurationWrite,
        )
        .await?;
        let observed = if previous.is_none() && input.intent.completion_requested {
            Some(
                self.progress(
                    auth,
                    audit,
                    continuation,
                    Saved {
                        revision: input.expected_revision,
                        intent: input.intent.clone(),
                    },
                )
                .await?,
            )
        } else {
            None
        };
        audit.operation(
            id,
            "first_use_update",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let receipt = store::update(
            &self.audit,
            &auth.proof,
            audit,
            id,
            &input,
            &fingerprint,
            observed.as_ref(),
        )
        .await?;
        Ok(receipt)
    }
}
fn database(_: sqlx::Error) -> Error {
    Error::Unavailable(Failure::Database)
}

#[cfg(test)]
#[path = "../../../tests/settings/first_use.rs"]
pub(crate) mod tests;

#[cfg(test)]
mod unit {
    use super::*;
    #[test]
    fn loaded_display_is_not_owner_qualified_and_missing_observation_is_rejected() {
        let item = *settings::model::CATALOG
            .iter()
            .find(|i| i.id == "apns-cert")
            .unwrap();
        let mut projection = settings::model::Projection::unknown(None);
        projection.status = settings::model::Status::Loaded;
        let step = projected_step(
            "apple_materials",
            &["apns-cert"],
            Ok(vec![settings::model::Entry {
                item,
                projection: projection.clone(),
            }]),
        )
        .unwrap();
        assert_eq!(step.status, Status::Pending);
        projection.ready = true;
        let step = projected_step(
            "apple_materials",
            &["apns-cert"],
            Ok(vec![settings::model::Entry { item, projection }]),
        )
        .unwrap();
        assert_eq!(step.status, Status::Ready);
        assert!(matches!(
            projected_step("apple_materials", &["apns-cert"], Ok(vec![])),
            Err(Error::Conflict)
        ));
        assert_eq!(
            projected_step(
                "apple_materials",
                &["apns-cert"],
                Err(Error::Unavailable(Failure::Database))
            )
            .unwrap()
            .status,
            Status::Unavailable
        );
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;
    #[test]
    fn owner_permission_rejections_remain_forbidden_in_progress() {
        for error in [
            Error::Forbidden,
            Error::Authorization(rss_mdm_authorization_service::Error::Unauthorized),
            Error::Webhook(rss_mdm_webhook_service::Error::Denied),
            Error::Execution(rss_mdm_execution_service::Error::Forbidden),
        ] {
            let step = projected_step("webhook", &["webhook-own"], Err(error)).unwrap();
            assert_eq!(step.status, Status::Forbidden);
            assert!(step.evidence.is_empty());
        }
    }
}
