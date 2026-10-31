//! Static DTO mappings for configuration facts consumed by the shared operation query surface.
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use rss_mdm_execution_service::{
    Error, Failure, authorization_decision,
    queries::{configuration::*, records},
    transaction::Fault,
};
use rss_mdm_policy_service::configuration as cfg;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;
pub(crate) struct ConfigurationQueries(pub Arc<cfg::Transactions>);
fn fault(e: rss_mdm_policy_service::transaction::Fault) -> Fault {
    match e {
        rss_mdm_policy_service::transaction::Fault::Request(e) => {
            super::configuration_cleanup::error(e).into()
        }
        rss_mdm_policy_service::transaction::Fault::Storage(e) => e.into(),
        rss_mdm_policy_service::transaction::Fault::Sql(e) => e.into(),
    }
}
fn convert<T: serde::de::DeserializeOwned>(v: &impl serde::Serialize) -> Result<T, Error> {
    serde_json::to_value(v)
        .and_then(serde_json::from_value)
        .map_err(|_| Error::Unavailable(Failure::CommandInvariant))
}
fn observation(
    v: cfg::queries::records::NativeObservation,
) -> Result<records::NativeObservation, Error> {
    use cfg::queries::records::NativeObservation as C;
    use records::NativeObservation as E;
    Ok(match v {
        C::Apple {
            facts,
            progress,
            effect_confirmed,
        } => E::Apple {
            facts,
            progress: records::CommandStatus(progress),
            effect_confirmed,
        },
        C::Declarations { facts, progress } => E::Declarations {
            facts,
            progress: records::CommandStatus(progress),
        },
        C::Windows {
            receipts,
            progress,
            effect,
            reason,
        } => E::Windows {
            receipts: convert(&receipts)?,
            progress: records::CommandStatus(progress),
            effect,
            reason,
        },
    })
}
impl ConfigurationReads for ConfigurationQueries {
    fn partition_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        ids: &'a [Uuid],
    ) -> Pending<'a, BTreeSet<Uuid>> {
        Box::pin(async move {
            if ids.len() > 1000 {
                return Err(Error::Malformed.into());
            }
            let configuration = super::native_ownership::batch_on(c, tenant, ids)
                .await
                .map_err(super::configuration_cleanup::error)?
                .into_iter()
                .filter_map(|(id, owner)| {
                    (owner == super::native_ownership::Owner::Configuration).then_some(id)
                })
                .collect();
            Ok(configuration)
        })
    }
    fn assignment_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        policy: Uuid,
        target: &'a rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    ) -> Pending<'a, Assignment> {
        Box::pin(async move {
            self.0
                .assignment_on(c, policy, target)
                .await
                .map(|v| Assignment {
                    diagnosis: v.diagnosis,
                    operations: v.operations,
                })
                .map_err(fault)
        })
    }
    fn classify_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a Snapshot,
        ids: Vec<Uuid>,
        now: i64,
    ) -> Pending<'a, BTreeMap<Uuid, authorization_decision::Decision>> {
        Box::pin(async move {
            self.0
                .classify_on(c, proof, grant, ids, now)
                .await
                .map_err(fault)?
                .into_iter()
                .map(|(id, authorization)| {
                    Ok((
                        id,
                        authorization_decision::Decision {
                            authorization: convert(&authorization)?,
                            reauthorization: authorization_decision::Reauthorization::NotApplicable,
                        },
                    ))
                })
                .collect()
        })
    }
    fn detail_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a Snapshot,
        now: i64,
        device: &'a str,
        id: Uuid,
    ) -> Pending<'a, records::CommandDetail> {
        Box::pin(async move {
            let v = self
                .0
                .detail_on(c, proof, grant, now, device, id)
                .await
                .map_err(fault)?;
            Ok(records::CommandDetail {
                operation_id: v.operation_id,
                command_id: v.command_id,
                revision: v.revision,
                task: convert(&v.task)?,
                target: convert(&v.target)?,
                input_version: v.input_version,
                deadline: v.deadline,
                dispatch_failure: convert(&v.dispatch_failure)?,
                authorization: convert(&v.authorization)?,
                reauthorization: authorization_decision::Reauthorization::NotApplicable,
                command_status: records::CommandStatus(v.command_status),
                observation: observation(v.observation)?,
                agent_installation: None,
            })
        })
    }
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a Snapshot,
        ids: Vec<Uuid>,
    ) -> Pending<'a, BTreeMap<Uuid, records::CommandEvidence>> {
        Box::pin(async move {
            self.0
                .evidence_on(c, proof, grant, ids)
                .await
                .map_err(fault)?
                .into_iter()
                .map(|(id, v)| {
                    Ok((
                        id,
                        records::CommandEvidence {
                            command_status: records::CommandStatus(v.command_status),
                            observation: observation(v.observation)?,
                            dispatch_failure: convert(&v.dispatch_failure)?,
                            agent_installation: None,
                        },
                    ))
                })
                .collect()
        })
    }
    fn declarations_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        grant: &'a Snapshot,
        device: &'a str,
        registration: Uuid,
        generation: i64,
        ids: Vec<Uuid>,
    ) -> Pending<'a, BTreeMap<Uuid, Declaration>> {
        Box::pin(async move {
            self.0
                .declarations_on(c, proof, grant, device, registration, generation, ids)
                .await
                .map_err(fault)?
                .into_iter()
                .map(|(id, v)| {
                    Ok((
                        id,
                        Declaration {
                            registration: v.registration,
                            generation: v.generation,
                            redacted: v.redacted,
                            observation: observation(v.observation)?,
                        },
                    ))
                })
                .collect()
        })
    }
}
