//! Tenant setup owns only intent. Reads reuse existing domain observations.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{
    Permission,
    context::{AuthorizedPrincipal, RequestAuth},
};
use rss_mdm_management_http::{
    Error, Failure,
    first_use::*,
    http_operation::RequestContinuation,
    settings::{self, Source as _},
};
use rss_mdm_registration_service::{admission::State, quotas::Channel};
use std::sync::Arc;
mod store;
pub(crate) const ACCESS_CONTRACT: &str = include_str!("first_use/access-contract.json");

/// Observation calls may label their own operation. Restore the outer request even on cancellation.
struct ObservationAction<'a> {
    audit: &'a RequestAudit,
    original: &'static str,
}
impl Drop for ObservationAction<'_> {
    fn drop(&mut self) {
        self.audit.set_action(self.original);
    }
}

pub(crate) struct FirstUse {
    pub directory: crate::settings::Directory,
    pub channels: Arc<dyn rss_mdm_management_http::enrollment::channels::Source>,
}
impl FirstUse {
    fn proof(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        write: bool,
    ) -> Result<(), Error> {
        let identity = &self.directory.state.identity;
        p.session()?;
        if p.tenant_id() != identity.tenant.to_string()
            || p.instance_id() != identity.instance.to_string()
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
        continuation: RequestContinuation,
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
                    continuation.clone(),
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
                    continuation.clone(),
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
                    self.items_step(auth, audit, continuation.clone(), &id, capability.items())
                        .await?
                }
            });
        }
        auth.proof.check_live()?;
        Ok(Progress::new(auth.proof.tenant_id().into(), saved, steps))
    }
    async fn channel_step(&self, proof: &AuthorizedPrincipal, channel: Channel) -> Step {
        use rss_mdm_management_http::enrollment::channels::Availability;
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
        let admission = rss_mdm_registration_service::admission::Admission::new(
            self.directory.state.access.registration(),
            self.directory.state.audit_store.clone(),
        )
        .read(proof)
        .await;
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
        continuation: RequestContinuation,
        id: &str,
        ids: &[&str],
    ) -> Result<Step, Error> {
        let catalog = settings::catalog(&auth.proof, false)?;
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
    entries: Result<Vec<settings::Entry>, Error>,
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
                settings::Status::Unknown => Status::Unknown,
                settings::Status::Unconfigured => Status::Unconfigured,
                settings::Status::Unavailable => Status::Unavailable,
                _ => Status::Pending,
            });
            let reason = failed.and_then(|e| e.projection.reason.map(str::to_owned));
            (status, reason, entries)
        }
        Err(Error::Forbidden | Error::Unauthorized) => (
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
impl Source for FirstUse {
    fn execute<'a>(
        &'a self,
        auth: RequestAuth,
        audit: RequestAudit,
        continuation: RequestContinuation,
        command: Command,
    ) -> futures::future::BoxFuture<'a, Result<Output, Error>> {
        Box::pin(async move {
            self.proof(&auth.proof, &audit, matches!(command, Command::Update(..)))?;
            match command {
                Command::Read => {
                    let saved =
                        store::read(&self.directory.state.audit_store, &auth.proof, &audit).await?;
                    Ok(Output::Progress(
                        self.progress(&auth, &audit, continuation, saved).await?,
                    ))
                }
                Command::Operation(id) => Ok(Output::Receipt(
                    store::operation(
                        &self.directory.state.audit_store,
                        &auth.proof,
                        &audit,
                        id,
                        Permission::RegistrationConfigurationRead,
                    )
                    .await?
                    .ok_or(Error::FirstUseOperationMissing)?,
                )),
                Command::Update(id, input) => {
                    input.intent.validate()?;
                    if id.is_nil()
                        || input.expected_revision < 0
                        || input.expected_revision == i64::MAX
                    {
                        return Err(Error::Malformed);
                    }
                    let fingerprint = store::fingerprint(&auth.proof, &input)?;
                    // Resolve durable outcomes before asking current owners. Expired materials
                    // or unavailable providers cannot invalidate an already committed receipt.
                    let previous = store::operation(
                        &self.directory.state.audit_store,
                        &auth.proof,
                        &audit,
                        id,
                        Permission::RegistrationConfigurationWrite,
                    )
                    .await?;
                    let observed = if previous.is_none() && input.intent.completion_requested {
                        Some(
                            self.progress(
                                &auth,
                                &audit,
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
                    audit.operation(id, "first_use_update");
                    audit.require_request_settlement();
                    let receipt = store::update(
                        &self.directory.state.audit_store,
                        &auth.proof,
                        &audit,
                        id,
                        &input,
                        &fingerprint,
                        observed.as_ref(),
                    )
                    .await?;
                    Ok(Output::Receipt(receipt))
                }
            }
        })
    }
}
fn database(_: sqlx::Error) -> Error {
    Error::Unavailable(Failure::Database)
}

#[cfg(test)]
#[path = "../tests/settings/first_use.rs"]
mod tests;

#[cfg(test)]
mod unit {
    use super::*;
    #[test]
    fn loaded_display_is_not_owner_qualified_and_missing_observation_is_rejected() {
        let item = *settings::CATALOG
            .iter()
            .find(|i| i.id == "apns-cert")
            .unwrap();
        let mut projection = settings::Projection::unknown(None);
        projection.status = settings::Status::Loaded;
        let step = projected_step(
            "apple_materials",
            &["apns-cert"],
            Ok(vec![settings::Entry {
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
            Ok(vec![settings::Entry { item, projection }]),
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
