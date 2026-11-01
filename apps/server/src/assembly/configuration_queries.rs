//! Static DTO mappings for configuration facts consumed by the shared operation query surface.
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use rss_mdm_execution_service::{
    Error, authorization_decision,
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
fn map_phase(v: cfg::model::AttemptPhase) -> rss_mdm_execution_service::AttemptPhase {
    use cfg::model::AttemptPhase as C;
    use rss_mdm_execution_service::AttemptPhase as E;
    match v {
        C::Prepare => E::Prepare,
        C::Execute => E::Execute,
        C::Observe => E::Observe,
    }
}
fn receipt(v: cfg::queries::records::WindowsReceipt) -> records::WindowsReceipt {
    let cfg::queries::records::WindowsReceipt {
        phase,
        ordinal,
        session,
        message,
        command,
        parent_command,
        item,
        kind,
        uri,
        status,
        value,
        accepted,
        received_at,
        result_accepted,
        result_received_at,
        frames,
        redacted,
    } = v;
    records::WindowsReceipt {
        phase: map_phase(phase),
        ordinal,
        session,
        message,
        command,
        parent_command,
        item,
        kind,
        uri,
        status,
        value,
        accepted,
        received_at,
        result_accepted,
        result_received_at,
        frames: frames.into_iter().map(frame).collect(),
        redacted,
    }
}
fn frame(v: cfg::queries::records::WindowsFrame) -> records::WindowsFrame {
    let cfg::queries::records::WindowsFrame {
        message,
        command,
        start_byte,
        end_byte,
        total_bytes,
        status,
        accepted,
        received_at,
    } = v;
    records::WindowsFrame {
        message,
        command,
        start_byte,
        end_byte,
        total_bytes,
        status,
        accepted,
        received_at,
    }
}
fn authorization(v: cfg::queries::records::Authorization) -> authorization_decision::Authorization {
    use authorization_decision::{Authorization as E, BlockReason as EB};
    use cfg::queries::records::{Authorization as C, BlockReason as CB};
    match v {
        C::Authorized => E::Authorized,
        C::NotApplicable => E::NotApplicable,
        C::Blocked { reason } => E::Blocked {
            reason: match reason {
                CB::LifecycleBlocked => EB::LifecycleBlocked,
                CB::RegistrationChanged => EB::RegistrationChanged,
                CB::InputMismatch => EB::InputMismatch,
                CB::SourceInvalid => EB::SourceInvalid,
            },
        },
    }
}
fn task(v: cfg::model::TaskSummary) -> rss_mdm_execution_service::TaskSummary {
    use cfg::model::TaskKind as C;
    use rss_mdm_execution_service::model::TaskKind as E;
    let cfg::model::TaskSummary {
        platform,
        kind,
        name,
        objects,
    } = v;
    rss_mdm_execution_service::TaskSummary {
        platform,
        name,
        objects,
        kind: match kind {
            C::SyncMl => E::SyncMl,
            C::Msi => E::Msi,
            C::Command => E::Command,
            C::InstallProfile => E::InstallProfile,
            C::RemoveProfile => E::RemoveProfile,
            C::Declarations => E::Declarations,
        },
    }
}
fn target(v: cfg::NativeTarget) -> rss_mdm_execution_service::NativeTarget {
    match v {
        cfg::NativeTarget::Device => rss_mdm_execution_service::NativeTarget::Device,
        cfg::NativeTarget::User { user_id } => {
            rss_mdm_execution_service::NativeTarget::User { user_id }
        }
    }
}
fn dispatch_failure(v: cfg::model::DispatchFailure) -> rss_mdm_execution_service::DispatchFailure {
    use cfg::model::DispatchFailure as C;
    use rss_mdm_execution_service::DispatchFailure as E;
    match v {
        C::Macos { reason } => E::Macos { reason },
        C::Windows {
            reason,
            phase: attempt,
            context,
        } => E::Windows {
            reason,
            phase: attempt.map(map_phase),
            context,
        },
    }
}
fn observation(v: cfg::queries::records::NativeObservation) -> records::NativeObservation {
    use cfg::queries::records::NativeObservation as C;
    use records::NativeObservation as E;
    match v {
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
            receipts: receipts.into_iter().map(receipt).collect(),
            progress: records::CommandStatus(progress),
            effect,
            reason,
        },
    }
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
                .map(|(id, value)| {
                    Ok((
                        id,
                        authorization_decision::Decision {
                            authorization: authorization(value),
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
                task: task(v.task),
                target: target(v.target),
                input_version: v.input_version,
                deadline: v.deadline,
                dispatch_failure: v.dispatch_failure.map(dispatch_failure),
                authorization: authorization(v.authorization),
                reauthorization: authorization_decision::Reauthorization::NotApplicable,
                command_status: records::CommandStatus(v.command_status),
                observation: observation(v.observation),
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
                            observation: observation(v.observation),
                            dispatch_failure: v.dispatch_failure.map(dispatch_failure),
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
        target: &'a rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
        ids: Vec<Uuid>,
    ) -> Pending<'a, BTreeMap<Uuid, Declaration>> {
        Box::pin(async move {
            self.0
                .declarations_on(c, proof, grant, target, ids)
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
                            observation: observation(v.observation),
                        },
                    ))
                })
                .collect()
        })
    }
}
