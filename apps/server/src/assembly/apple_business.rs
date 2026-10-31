//! Static mapping to current Apple business implementations.
use super::native_ownership::{self, Owner};
use rss_mdm_apple_channel::{participants::*, protocol_types::*};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::DevicePrincipal;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct AppleBusiness(
    pub Arc<rss_mdm_execution_service::ExecutionService>,
    pub Arc<rss_mdm_policy_service::configuration::Transactions>,
);
pub(super) fn error(e: rss_mdm_execution_service::Error) -> rss_mdm_apple_channel::Error {
    use rss_mdm_apple_channel::Missing;
    use rss_mdm_apple_channel::{Error as A, Failure};
    use rss_mdm_execution_service::Error as E;
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::EnrollmentPaused=> A::EnrollmentPaused, E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
            E::NotFound => A::NotFound, E::Resource(_) => A::Missing(Missing::Resource),
            E::Execution(e) => A::Missing(match e { rss_mdm_execution_service::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_execution_service::missing::ExecutionError::MissingTask => Missing::Task }),
            E::Publication(e) => A::Missing(match e { rss_mdm_software_service::management::publication::error::PublicationError::MissingSource => Missing::SoftwareSource, rss_mdm_software_service::management::publication::error::PublicationError::MissingPublication => Missing::SoftwarePublication }),
            E::Configuration(_) => A::Unavailable(Failure::BusinessConfiguration),
            E::Unavailable(f) => A::Unavailable(match f {
                rss_mdm_execution_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_execution_service::Failure::Audit => Failure::Audit,
                rss_mdm_execution_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_execution_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_execution_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_execution_service::Failure::AuditContract => Failure::AuditContract,

                _ => Failure::Business,
            }),
        }
}
fn fault(e: rss_mdm_execution_service::transaction::Fault) -> rss_mdm_apple_channel::Error {
    use rss_mdm_execution_service::transaction::Fault;
    match e {
        Fault::Request(e) => error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}

pub(super) fn target(t: rss_mdm_execution_service::NativeTarget) -> Target {
    match t {
        rss_mdm_execution_service::NativeTarget::Device => Target::Device,
        rss_mdm_execution_service::NativeTarget::User { user_id } => Target::User { user_id },
    }
}
pub(super) fn command(c: rss_mdm_execution_service::apple_facts::AppleCommand) -> AppleCommand {
    AppleCommand {
        recovery: c.recovery,
        operation: c.operation,
        owner: c.owner,
        authorized_declarations: c.authorized_declarations,
        assets: c.assets,
        deadline: c.deadline,
        input_version: c.input_version,
        target: target(c.target),
        request: c.request,
    }
}
fn admission(a: rss_mdm_execution_service::apple_business::AppleAdmission) -> Admission {
    Admission {
        eligible: a.eligible,
        dispatch: a.dispatch,
        command: command(a.command),
        target: AppleRegistration {
            tenant: a.target.tenant,
            device: a.target.device,
            registration: a.target.registration,
            generation: a.target.generation,
        },
    }
}
impl Business for AppleBusiness {
    fn prepare_wake<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        devices: Vec<String>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .apple_prepare_wake_in(tx, devices, audit)
                .await
                .map_err(fault)
        })
    }
    fn wake_commands<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        registration: Uuid,
        generation: i64,
        after: Uuid,
    ) -> Pending<'a, WakePage> {
        Box::pin(async move {
            let left = self
                .0
                .apple_wake_commands_in(tx, registration, generation, after)
                .await
                .map_err(fault)?;
            let right = self
                .1
                .apple_wake_commands_in(tx, registration, generation, after)
                .await
                .map_err(policy_fault)?;
            let mut next = left.next.into_iter().chain(right.next).min();
            let mut commands = left.commands;
            commands.extend(right.commands);
            commands.sort_by_key(|v| v.0);
            if commands.len() > 64 {
                next = Some(next.map_or(commands[63].0, |n| n.min(commands[63].0)));
            }
            if let Some(last) = next {
                commands.retain(|v| v.0 <= last);
            }
            for (id, _) in &commands {
                native_ownership::in_transaction(tx, *id)
                    .await
                    .map_err(policy_fault)?;
            }
            Ok(WakePage { next, commands })
        })
    }

    fn software_enabled(&self) -> bool {
        self.0.native_software_enabled()
    }
    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move { self.0.apple_prepare_in(tx, p, audit).await.map_err(fault) })
    }
    fn authenticated<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()> {
        Box::pin(async move { self.0.apple_authenticated_in(tx, p).await.map_err(fault) })
    }
    fn finish<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        collection: Option<Uuid>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .apple_finish_in(tx, p, collection, audit)
                .await
                .map_err(fault)
        })
    }
    fn settle_failures<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .apple_settle_failures_in(tx, p, audit)
                .await
                .map_err(fault)?;
            rss_mdm_policy_service::configuration::protocol::settle_dispatch_failures(
                &self.1, tx, p, audit,
            )
            .await
            .map_err(policy_fault)
        })
    }
    fn candidates<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        user: &'a str,
        after: Uuid,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move {
            let mut ids = self
                .0
                .apple_candidates_in(tx, p, user, after)
                .await
                .map_err(fault)?;
            ids.extend(
                self.1
                    .apple_candidates_in(tx, p, user, after)
                    .await
                    .map_err(policy_fault)?,
            );
            ids.sort();
            ids.truncate(64);
            for id in &ids {
                native_ownership::in_transaction(tx, *id)
                    .await
                    .map_err(policy_fault)?;
            }
            Ok(ids)
        })
    }
    fn command<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
    ) -> Pending<'a, Admission> {
        Box::pin(async move {
            match native_ownership::in_transaction(tx, id)
                .await
                .map_err(policy_fault)?
            {
                Owner::Configuration => self
                    .1
                    .apple_command_in(tx, p, id)
                    .await
                    .map(configuration_admission)
                    .map_err(policy_fault),
                Owner::Execution => self
                    .0
                    .apple_command_in(tx, p, id)
                    .await
                    .map(admission)
                    .map_err(fault),
            }
        })
    }
    fn settle<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
        input_version: &'a str,
        fact: rss_mdm_apple_mdm::native::evidence::Settlement,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            match native_ownership::in_transaction(tx, id)
                .await
                .map_err(policy_fault)?
            {
                Owner::Configuration => self
                    .1
                    .apple_settle_in(tx, p, id, input_version, fact, audit)
                    .await
                    .map_err(policy_fault),
                Owner::Execution => self
                    .0
                    .apple_settle_in(tx, p, id, input_version, fact, audit)
                    .await
                    .map_err(fault),
            }
        })
    }
    fn synchronized<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        fact: &'a Synchronized,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            match native_ownership::in_transaction(tx, fact.operation)
                .await
                .map_err(policy_fault)?
            {
                Owner::Configuration => self
                    .1
                    .apple_synchronized_in(
                        tx,
                        p,
                        fact.operation,
                        &fact.input_version,
                        &fact.user,
                        fact.registration,
                        fact.generation,
                    )
                    .await
                    .map_err(policy_fault),
                Owner::Execution => self
                    .0
                    .apple_synchronized_in(
                        tx,
                        p,
                        fact.operation,
                        &fact.input_version,
                        &fact.user,
                        fact.registration,
                        fact.generation,
                    )
                    .await
                    .map_err(fault),
            }
        })
    }
    fn rejected<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
        reason: String,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            match native_ownership::in_transaction(tx, id)
                .await
                .map_err(policy_fault)?
            {
                Owner::Configuration => self
                    .1
                    .apple_rejected_in(tx, p, id, reason)
                    .await
                    .map_err(policy_fault),
                Owner::Execution => self
                    .0
                    .apple_rejected_in(tx, p, id, reason)
                    .await
                    .map_err(fault),
            }
        })
    }
    fn declarations<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        user: &'a str,
        ids: Vec<Uuid>,
    ) -> Pending<'a, Vec<Admission>> {
        Box::pin(async move {
            let mut configuration = Vec::new();
            let mut execution = Vec::new();
            for id in ids {
                match native_ownership::in_transaction(tx, id)
                    .await
                    .map_err(policy_fault)?
                {
                    Owner::Configuration => configuration.push(id),
                    Owner::Execution => execution.push(id),
                }
            }
            let mut rows = self
                .0
                .apple_declarations_in(tx, p, user, execution)
                .await
                .map_err(fault)?
                .into_iter()
                .map(admission)
                .collect::<Vec<_>>();
            rows.extend(
                self.1
                    .apple_declarations_in(tx, p, user, configuration)
                    .await
                    .map_err(policy_fault)?
                    .into_iter()
                    .map(configuration_admission),
            );
            rows.sort_by_key(|v| v.command.operation);
            Ok(rows)
        })
    }
    fn collection_eligible<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        delivery: bool,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .apple_collection_eligible_on(c, p, id, delivery)
                .await
                .map_err(error)
        })
    }
    fn collection_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_execution_service::actions::native_collection::sent(c, tenant, id)
                .await
                .map_err(error)
        })
    }
    fn artifact<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        asset: &'a rss_mdm_apple_mdm::native::ddm::AssetInput,
    ) -> Pending<'a, ConfigurationArtifact> {
        Box::pin(async move {
            let a = self
                .1
                .apple_configuration_artifact_in(tx, asset)
                .await
                .map_err(policy_fault)?;
            Ok(ConfigurationArtifact {
                artifact: a.artifact,
                apple_silicon: a.apple_silicon,
                verified: a.verified,
            })
        })
    }
    fn asset_authority<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
    ) -> Pending<'a, (rss_mdm_apple_mdm::native::request::Request, Target)> {
        Box::pin(async move {
            match native_ownership::in_transaction(tx, id)
                .await
                .map_err(policy_fault)?
            {
                Owner::Configuration => self
                    .1
                    .apple_asset_authority_in(tx, p, id)
                    .await
                    .map(|(r, t)| (r, super::configuration_channels::target(t)))
                    .map_err(policy_fault),
                Owner::Execution => self
                    .0
                    .apple_asset_authority_in(tx, p, id)
                    .await
                    .map(|(r, t)| (r, target(t)))
                    .map_err(fault),
            }
        })
    }
    fn detection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Pending<'a, DetectionCatalog> {
        Box::pin(async move {
            let v = rss_mdm_execution_service::agent_install::detection_on(
                c,
                tenant,
                rss_mdm_inventory::ReportSource::MdmApple,
            )
            .await
            .map_err(error)?;
            let digest = v.digest().map_err(error)?;
            let bundles = v
                .identities
                .into_iter()
                .map(|i| match i {
                    rss_mdm_execution_service::agent_install::Identity::Macos {
                        bundle, ..
                    } => Ok(bundle),
                    _ => Err(rss_mdm_apple_channel::Error::Conflict),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DetectionCatalog {
                bundles,
                complete: v.complete,
                digest,
            })
        })
    }
}
impl PlatformAccess for AppleBusiness {
    fn supported_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        registration: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .platform_sso_supported_on(c, registration)
                .await
                .map_err(Into::into)
        })
    }
    fn registration_binding_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        binding: Uuid,
        generation: i64,
    ) -> Pending<'a, rss_mdm_registration_service::device_access::Binding> {
        Box::pin(async move {
            self.0
                .registration_access_binding_on(c, p, binding, generation)
                .await
                .map_err(Into::into)
        })
    }
    fn active_binding_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: Uuid,
        generation: i64,
    ) -> Pending<'a, rss_mdm_registration_service::device_access::Binding> {
        Box::pin(async move {
            self.0
                .active_access_binding_on(c, binding, generation)
                .await
                .map_err(Into::into)
        })
    }
}
impl Departure for AppleBusiness {
    fn departed<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        registration: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_execution_service::unmanage::native_departure_in(c, tenant, registration, true)
                .await
                .map_err(error)
        })
    }
}

fn policy_error(e: rss_mdm_policy_service::Error) -> rss_mdm_apple_channel::Error {
    use rss_mdm_apple_channel::{Error as C, Failure};
    use rss_mdm_policy_service::Error as P;
    match e {
        P::CommitUnknown => C::CommitUnknown,
        P::RollbackFailed => C::RollbackFailed,
        P::Malformed => C::Malformed,
        P::Unauthorized => C::Unauthorized,
        P::Forbidden | P::MdmSoftwareDisabled => C::Forbidden,
        P::ReadConflict | P::Conflict | P::WindowsDeclaredEnrollmentNotReady => C::Conflict,
        P::NotFound | P::PolicyMissing | P::ResourceMissing => C::NotFound,
        P::Unsupported => C::Unsupported,
        P::Unavailable(_) => C::Unavailable(Failure::Business),
    }
}
fn policy_fault(e: rss_mdm_policy_service::transaction::Fault) -> rss_mdm_apple_channel::Error {
    match e {
        rss_mdm_policy_service::transaction::Fault::Request(e) => policy_error(e),
        rss_mdm_policy_service::transaction::Fault::Storage(e) => e.into(),
        rss_mdm_policy_service::transaction::Fault::Sql(e) => e.into(),
    }
}

fn configuration_admission(
    a: rss_mdm_policy_service::configuration::apple::AppleAdmission,
) -> Admission {
    Admission {
        eligible: a.eligible,
        dispatch: a.dispatch,
        target: AppleRegistration {
            tenant: a.target.tenant,
            device: a.target.device,
            registration: a.target.registration,
            generation: a.target.generation,
        },
        command: AppleCommand {
            recovery: None,
            operation: a.command.operation,
            owner: a.command.owner,
            authorized_declarations: Vec::new(),
            assets: Vec::new(),
            deadline: a.command.deadline,
            input_version: a.command.input_version,
            target: super::configuration_channels::target(a.command.target),
            request: a.command.request,
        },
    }
}
