//! The enrollment owner consumed independently of the MDM application composition.
use crate::delivery::{EventEffects, Pending, Tasks};
use crate::{Error, Failure};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_registration_service::{DevicePrincipal, enrollment::tasks as enrollment};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
use uuid::Uuid;

pub struct EnrollmentTasks {
    service: Arc<enrollment::Service>,
}
impl EnrollmentTasks {
    pub fn new(service: Arc<enrollment::Service>) -> Self {
        Self { service }
    }
}
impl Tasks for EnrollmentTasks {
    fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.service.profile()
    }
    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()> {
        Box::pin(async move { self.service.agent_prepare_in(tx, p).await.map_err(fault) })
    }
    fn offer<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        input: &'a wire::TaskClaimRequest,
        attempt: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, Option<(wire::TaskPayload, Fact, i64)>> {
        Box::pin(async move {
            let profile = self.profile();
            self.service.validate_in(tx).map_err(fault)?;
            let now = enrollment::storage::now(tx).await.map_err(fault)?;
            let after = crate::delivery::offer_after_in(profile, tx, p.registration()).await?;
            // The selected owner and its enrollment capability are fixed before this bounded page.
            let candidates =
                enrollment::poll::offer_candidates(profile, tx, p.registration(), now, after)
                    .await
                    .map_err(fault)?;
            self.service
                .agent_admit_in(tx, p, input)
                .await
                .map_err(fault)?;
            let full = candidates.len() == 128;
            let mut inspected = None;
            let mut result = None;
            for coordinate in candidates {
                inspected = Some(coordinate);
                result = self
                    .service
                    .agent_offer_one_in(tx, p, coordinate.1, attempt, audit)
                    .await
                    .map_err(fault)?;
                if result.is_some() {
                    break;
                }
            }
            let next = if result.is_some() || full {
                inspected
            } else {
                None
            };
            crate::delivery::offer_through_in(profile, tx, p.registration(), next).await?;
            Ok(result)
        })
    }
    fn replay_offer<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        signed: &'a wire::SignedTask,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if !matches!(signed.payload, wire::TaskPayload::Enrollment(_)) {
                return Err(Error::Forbidden);
            }
            self.service
                .agent_replay_offer_in(tx, p, signed, audit)
                .await
                .map_err(fault)
        })
    }
    fn replay_event<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a wire::TaskEventRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.service
                .agent_replay_event_in(tx, p, task, input, audit)
                .await
                .map_err(fault)
        })
    }
    fn event<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a wire::TaskEventRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, EventEffects> {
        Box::pin(async move {
            let effect = self
                .service
                .agent_event_in(tx, p, task, input, audit)
                .await
                .map_err(fault)?;
            Ok(EventEffects {
                start: effect.start,
                cancelled: effect.cancelled,
                credentials: Vec::new(),
                fact: effect.fact,
            })
        })
    }
    fn cancellations<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        registration: Uuid,
        after: Option<Uuid>,
    ) -> Pending<'a, Vec<wire::TaskCancellation>> {
        Box::pin(async move {
            self.service.validate_in(tx).map_err(fault)?;
            enrollment::poll::cancellations(self.profile(), tx, registration, after)
                .await
                .map_err(fault)
        })
    }
    fn content<'a>(
        &'a self,
        _tx: &'a mut PgTransaction<'_>,
        _p: &'a DevicePrincipal,
        _task: Uuid,
        _attempt: Uuid,
        _key: Option<&'a str>,
        _audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_resource::Artifact> {
        Box::pin(async { Err(Error::Unsupported) })
    }
}
fn fault(error: enrollment::transaction::Fault) -> Error {
    use enrollment::{Error as E, transaction::Fault as F};
    match error {
        F::Sql(e) => e.into(),
        F::Storage(e) => e.into(),
        F::Request(e) => match e {
            E::Unsupported => Error::Unsupported,
            E::Malformed => Error::Malformed,
            E::Conflict => Error::Conflict,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::NotFound => Error::NotFound,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Invariant | E::Unavailable => Error::Unavailable(Failure::Business),
            E::Audit(e) => e.as_ref().into(),
        },
    }
}
