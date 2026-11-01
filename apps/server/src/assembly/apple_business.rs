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
    pub Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
    pub Arc<rss_mdm_software_service::deployment::SoftwareService>,
    pub Arc<rss_mdm_registration_service::installation::Service>,
    pub Option<Arc<rss_mdm_recovery_credentials::native::Service>>,
    pub Arc<rss_mdm_registration_service::device_access::execution::Service>,
);
pub(super) fn error(e: rss_mdm_execution_service::Error) -> rss_mdm_apple_channel::Error {
    use rss_mdm_apple_channel::Missing;
    use rss_mdm_apple_channel::{Error as A, Failure};
    use rss_mdm_execution_service::Error as E;
    match e {
        E::Malformed => A::Malformed,
        E::CertificateRequest => A::CertificateRequest,
        E::Unauthorized => A::Unauthorized,
        E::Forbidden => A::Forbidden,
        E::ReadConflict
        | E::CursorInvalidated
        | E::Conflict
        | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
        E::EnrollmentPaused => A::EnrollmentPaused,
        E::CommitUnknown => A::CommitUnknown,
        E::RollbackFailed => A::RollbackFailed,
        E::Unsupported => A::Unsupported,
        E::NotFound => A::NotFound,
        E::Resource(_) => A::Missing(Missing::Resource),
        E::Execution(e) => A::Missing(match e {
            rss_mdm_execution_service::missing::ExecutionError::MissingOperation => {
                Missing::Operation
            }
            rss_mdm_execution_service::missing::ExecutionError::MissingTask => Missing::Task,
        }),

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
            self.3
                .apple_prepare_wake_in(tx, devices.clone(), audit)
                .await
                .map_err(software_fault)?;
            self.4
                .apple_prepare_wake_in(tx, devices.clone(), audit)
                .await
                .map_err(registration_fault)?;
            if let Some(recovery) = &self.5 {
                recovery
                    .apple_prepare_wake_in(tx, devices.clone(), audit)
                    .await
                    .map_err(recovery_fault)?;
            }
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
            let software = self
                .3
                .apple_wake_commands_in(tx, registration, generation, after)
                .await
                .map_err(software_fault)?;
            let bootstrap = self
                .4
                .apple_wake_commands_in(tx, registration, generation, after)
                .await
                .map_err(registration_fault)?;
            let recovery = match &self.5 {
                Some(recovery) => Some(
                    recovery
                        .apple_wake_commands_in(tx, registration, generation, after)
                        .await
                        .map_err(recovery_fault)?,
                ),
                None => None,
            };
            let mut next = left
                .next
                .into_iter()
                .chain(right.next)
                .chain(software.next)
                .chain(bootstrap.next)
                .chain(recovery.as_ref().and_then(|v| v.next))
                .min();
            let mut commands = left.commands;
            commands.extend(right.commands);
            commands.extend(software.commands);
            commands.extend(bootstrap.commands);
            if let Some(recovery) = recovery {
                commands.extend(recovery.commands);
            }
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
        self.3.native_software_enabled()
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
        Box::pin(async move {
            self.2
                .authenticated_in(tx, p)
                .await
                .map_err(collection_fault)
        })
    }
    fn finish<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        collection: Option<Uuid>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if let Some(id) = collection {
                self.2
                    .finished_in(tx, p, &[id])
                    .await
                    .map_err(collection_fault)?;
            }
            self.3
                .apple_finish_in(tx, p, audit)
                .await
                .map_err(software_fault)?;
            self.4
                .apple_finish_in(tx, p, audit)
                .await
                .map_err(registration_fault)?;
            Ok(())
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
            self.3
                .apple_settle_failures_in(tx, p, audit)
                .await
                .map_err(software_fault)?;
            self.4
                .apple_settle_failures_in(tx, p, audit)
                .await
                .map_err(registration_fault)?;
            if let Some(recovery) = &self.5 {
                recovery
                    .apple_settle_failures_in(tx, p, audit)
                    .await
                    .map_err(recovery_fault)?;
            }
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
            ids.extend(
                self.3
                    .apple_candidates_in(tx, p, user, after)
                    .await
                    .map_err(software_fault)?,
            );
            ids.extend(
                self.4
                    .apple_candidates_in(tx, p, user, after)
                    .await
                    .map_err(registration_fault)?,
            );
            if let Some(recovery) = &self.5 {
                ids.extend(
                    recovery
                        .apple_candidates_in(tx, p, user, after)
                        .await
                        .map_err(recovery_fault)?,
                );
            }
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
                Owner::Software => self
                    .3
                    .apple_command_in(tx, p, id)
                    .await
                    .map(software_admission)
                    .map_err(software_fault),
                Owner::Registration => self
                    .4
                    .apple_command_in(tx, p, id)
                    .await
                    .map(registration_admission)
                    .map_err(registration_fault),
                Owner::Recovery => self
                    .5
                    .as_ref()
                    .ok_or(rss_mdm_apple_channel::Error::Unsupported)?
                    .apple_command_in(tx, p, id)
                    .await
                    .map(recovery_admission)
                    .map_err(recovery_fault),
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
                Owner::Software => self
                    .3
                    .apple_settle_in(tx, p, id, input_version, fact, audit)
                    .await
                    .map_err(software_fault),
                Owner::Registration => self
                    .4
                    .apple_settle_in(tx, p, id, input_version, fact, audit)
                    .await
                    .map_err(registration_fault),
                Owner::Recovery => self
                    .5
                    .as_ref()
                    .ok_or(rss_mdm_apple_channel::Error::Unsupported)?
                    .apple_settle_in(tx, p, id, input_version, fact, audit)
                    .await
                    .map_err(recovery_fault),
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
                Owner::Software => self
                    .3
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
                    .map_err(software_fault),
                Owner::Registration | Owner::Recovery => {
                    Err(rss_mdm_apple_channel::Error::Forbidden)
                }
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
                Owner::Software => self
                    .3
                    .apple_rejected_in(tx, p, id, reason)
                    .await
                    .map_err(software_fault),
                Owner::Registration => self
                    .4
                    .apple_rejected_in(tx, p, id, reason)
                    .await
                    .map_err(registration_fault),
                Owner::Recovery => self
                    .5
                    .as_ref()
                    .ok_or(rss_mdm_apple_channel::Error::Unsupported)?
                    .apple_rejected_in(tx, p, id, reason)
                    .await
                    .map_err(recovery_fault),
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
            let mut software = Vec::new();
            for id in ids {
                match native_ownership::in_transaction(tx, id)
                    .await
                    .map_err(policy_fault)?
                {
                    Owner::Configuration => configuration.push(id),
                    Owner::Execution => execution.push(id),
                    Owner::Software => software.push(id),
                    Owner::Registration | Owner::Recovery => {
                        return Err(rss_mdm_apple_channel::Error::Forbidden);
                    }
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
            rows.extend(
                self.3
                    .apple_declarations_in(tx, p, user, software)
                    .await
                    .map_err(software_fault)?
                    .into_iter()
                    .map(software_admission),
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
            self.2
                .eligible_on(c, p, id, delivery)
                .await
                .map_err(collection_fault)
        })
    }
    fn collection_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_inventory_service::collection::execution::native::sent_on(c, tenant, id)
                .await
                .map_err(collection_fault)
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
                Owner::Software => self
                    .3
                    .apple_asset_authority_in(tx, p, id)
                    .await
                    .map(|(r, t)| (r, software_target(t)))
                    .map_err(software_fault),
                Owner::Registration | Owner::Recovery => {
                    Err(rss_mdm_apple_channel::Error::Forbidden)
                }
            }
        })
    }
    fn detection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Pending<'a, DetectionCatalog> {
        Box::pin(async move {
            let v = rss_mdm_software_service::deployment::agent_install::detection_on(
                c,
                tenant,
                rss_mdm_inventory::ReportSource::MdmApple,
            )
            .await
            .map_err(software_error)?;
            let digest = v.digest().map_err(software_error)?;
            let bundles = v
                .identities
                .into_iter()
                .map(|i| match i {
                    rss_mdm_software_service::installation::package::Identity::Macos {
                        bundle,
                        ..
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
            self.6
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
            self.6
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
            self.6
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

fn collection_fault(
    e: rss_mdm_inventory_service::transaction::Fault,
) -> rss_mdm_apple_channel::Error {
    use rss_mdm_inventory_service::transaction::Fault;
    match e {
        Fault::Request(e) => e.into(),
        Fault::Sql(e) => e.into(),
        Fault::Storage(e) => e.into(),
    }
}

pub(super) fn software_error(
    e: rss_mdm_software_service::deployment::Error,
) -> rss_mdm_apple_channel::Error {
    use rss_mdm_apple_channel::Missing;
    use rss_mdm_apple_channel::{Error as A, Failure};
    use rss_mdm_software_service::deployment::Error as E;
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::EnrollmentPaused=> A::EnrollmentPaused, E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
            E::NotFound => A::NotFound, E::Resource(_) => A::Missing(Missing::Resource),
            E::Execution(e) => A::Missing(match e { rss_mdm_software_service::deployment::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_software_service::deployment::missing::ExecutionError::MissingTask => Missing::Task }),
            E::Publication(e) => A::Missing(match e { rss_mdm_software_service::management::publication::error::PublicationError::MissingSource => Missing::SoftwareSource, rss_mdm_software_service::management::publication::error::PublicationError::MissingPublication => Missing::SoftwarePublication }),
            E::Configuration(_) => A::Unavailable(Failure::BusinessConfiguration),
            E::Unavailable(f) => A::Unavailable(match f {
                rss_mdm_software_service::deployment::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_software_service::deployment::Failure::Audit => Failure::Audit,
                rss_mdm_software_service::deployment::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_software_service::deployment::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_software_service::deployment::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_software_service::deployment::Failure::AuditContract => Failure::AuditContract,

                _ => Failure::Business,
            }),
        }
}

fn software_fault(
    e: rss_mdm_software_service::deployment::transaction::Fault,
) -> rss_mdm_apple_channel::Error {
    use rss_mdm_software_service::deployment::transaction::Fault;
    match e {
        Fault::Request(e) => software_error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}

pub(super) fn software_target(t: rss_mdm_software_service::deployment::NativeTarget) -> Target {
    match t {
        rss_mdm_software_service::deployment::NativeTarget::Device => Target::Device,
        rss_mdm_software_service::deployment::NativeTarget::User { user_id } => {
            Target::User { user_id }
        }
    }
}

pub(super) fn software_command(
    c: rss_mdm_software_service::deployment::apple_facts::AppleCommand,
) -> AppleCommand {
    AppleCommand {
        operation: c.operation,
        owner: c.owner,
        authorized_declarations: c.authorized_declarations,
        assets: c.assets,
        deadline: c.deadline,
        input_version: c.input_version,
        target: software_target(c.target),
        request: c.request,
    }
}

fn software_admission(
    a: rss_mdm_software_service::deployment::apple_business::AppleAdmission,
) -> Admission {
    Admission {
        eligible: a.eligible,
        dispatch: a.dispatch,
        command: software_command(a.command),
        target: AppleRegistration {
            tenant: a.target.tenant,
            device: a.target.device,
            registration: a.target.registration,
            generation: a.target.generation,
        },
    }
}

pub(super) fn software_policy_error(
    e: rss_mdm_policy_service::Error,
) -> rss_mdm_software_service::deployment::Error {
    use rss_mdm_policy_service::Error as P;
    use rss_mdm_software_service::deployment::{Error as E, Failure};
    match e {
        P::CommitUnknown => E::CommitUnknown,
        P::RollbackFailed => E::RollbackFailed,
        P::Malformed => E::Malformed,
        P::Unauthorized => E::Unauthorized,
        P::Forbidden | P::MdmSoftwareDisabled => E::Forbidden,
        P::Conflict | P::ReadConflict | P::WindowsDeclaredEnrollmentNotReady => E::Conflict,
        P::NotFound | P::PolicyMissing | P::ResourceMissing => E::NotFound,
        P::Unsupported => E::Unsupported,
        P::Unavailable(_) => E::Unavailable(Failure::CommandStorage),
    }
}

pub(super) fn registration_error(
    e: rss_mdm_registration_service::installation::Error,
) -> rss_mdm_apple_channel::Error {
    use rss_mdm_apple_channel::Missing;
    use rss_mdm_apple_channel::{Error as A, Failure};
    use rss_mdm_registration_service::installation::Error as E;
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::EnrollmentPaused=> A::EnrollmentPaused, E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
            E::NotFound => A::NotFound, E::Resource(_) => A::Missing(Missing::Resource),
            E::Execution(e) => A::Missing(match e { rss_mdm_registration_service::installation::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_registration_service::installation::missing::ExecutionError::MissingTask => Missing::Task }),

            E::Configuration(_) => A::Unavailable(Failure::BusinessConfiguration),
            E::Unavailable(f) => A::Unavailable(match f {
                rss_mdm_registration_service::installation::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_registration_service::installation::Failure::Audit => Failure::Audit,
                rss_mdm_registration_service::installation::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_registration_service::installation::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_registration_service::installation::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_registration_service::installation::Failure::AuditContract => Failure::AuditContract,

                _ => Failure::Business,
            }),
        }
}

fn registration_fault(
    e: rss_mdm_registration_service::installation::transaction::Fault,
) -> rss_mdm_apple_channel::Error {
    use rss_mdm_registration_service::installation::transaction::Fault;
    match e {
        Fault::Request(e) => registration_error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}

pub(super) fn registration_target(
    t: rss_mdm_registration_service::installation::NativeTarget,
) -> Target {
    match t {
        rss_mdm_registration_service::installation::NativeTarget::Device => Target::Device,
        rss_mdm_registration_service::installation::NativeTarget::User { user_id } => {
            Target::User { user_id }
        }
    }
}

pub(super) fn registration_command(
    c: rss_mdm_registration_service::installation::apple_facts::AppleCommand,
) -> AppleCommand {
    AppleCommand {
        operation: c.operation,
        owner: c.owner,
        authorized_declarations: c.authorized_declarations,
        assets: c.assets,
        deadline: c.deadline,
        input_version: c.input_version,
        target: registration_target(c.target),
        request: c.request,
    }
}

fn registration_admission(
    a: rss_mdm_registration_service::installation::apple_business::AppleAdmission,
) -> Admission {
    Admission {
        eligible: a.eligible,
        dispatch: a.dispatch,
        command: registration_command(a.command),
        target: AppleRegistration {
            tenant: a.target.tenant,
            device: a.target.device,
            registration: a.target.registration,
            generation: a.target.generation,
        },
    }
}

pub(super) fn registration_policy_error(
    e: rss_mdm_policy_service::Error,
) -> rss_mdm_registration_service::installation::Error {
    use rss_mdm_policy_service::Error as P;
    use rss_mdm_registration_service::installation::{Error as E, Failure};
    match e {
        P::CommitUnknown => E::CommitUnknown,
        P::RollbackFailed => E::RollbackFailed,
        P::Malformed => E::Malformed,
        P::Unauthorized => E::Unauthorized,
        P::Forbidden | P::MdmSoftwareDisabled => E::Forbidden,
        P::Conflict | P::ReadConflict | P::WindowsDeclaredEnrollmentNotReady => E::Conflict,
        P::NotFound | P::PolicyMissing | P::ResourceMissing => E::NotFound,
        P::Unsupported => E::Unsupported,
        P::Unavailable(_) => E::Unavailable(Failure::CommandStorage),
    }
}

pub(super) fn recovery_error(
    e: rss_mdm_recovery_credentials::native::Error,
) -> rss_mdm_apple_channel::Error {
    use rss_mdm_apple_channel::Missing;
    use rss_mdm_apple_channel::{Error as A, Failure};
    use rss_mdm_recovery_credentials::native::Error as E;
    match e {
        E::MdmSoftwareDisabled => A::Forbidden,
        E::Malformed => A::Malformed,
        E::CertificateRequest => A::CertificateRequest,
        E::Unauthorized => A::Unauthorized,
        E::Forbidden => A::Forbidden,
        E::ReadConflict
        | E::CursorInvalidated
        | E::Conflict
        | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
        E::EnrollmentPaused => A::EnrollmentPaused,
        E::CommitUnknown => A::CommitUnknown,
        E::RollbackFailed => A::RollbackFailed,
        E::Unsupported => A::Unsupported,
        E::NotFound => A::NotFound,
        E::Resource(_) => A::Missing(Missing::Resource),
        E::Execution(e) => A::Missing(match e {
            rss_mdm_recovery_credentials::native::missing::ExecutionError::MissingOperation => {
                Missing::Operation
            }
            rss_mdm_recovery_credentials::native::missing::ExecutionError::MissingTask => {
                Missing::Task
            }
        }),

        E::Configuration(_) => A::Unavailable(Failure::BusinessConfiguration),
        E::Unavailable(f) => A::Unavailable(match f {
            rss_mdm_recovery_credentials::native::Failure::RequestDeadline => {
                Failure::RequestDeadline
            }
            rss_mdm_recovery_credentials::native::Failure::Audit => Failure::Audit,
            rss_mdm_recovery_credentials::native::Failure::AuditIntegrity => {
                Failure::AuditIntegrity
            }
            rss_mdm_recovery_credentials::native::Failure::AuditAdmission => {
                Failure::AuditAdmission
            }
            rss_mdm_recovery_credentials::native::Failure::AuditIsolation => {
                Failure::AuditIsolation
            }
            rss_mdm_recovery_credentials::native::Failure::AuditContract => Failure::AuditContract,

            _ => Failure::Business,
        }),
    }
}

fn recovery_fault(
    e: rss_mdm_recovery_credentials::native::transaction::Fault,
) -> rss_mdm_apple_channel::Error {
    use rss_mdm_recovery_credentials::native::transaction::Fault;
    match e {
        Fault::Request(e) => recovery_error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}

pub(super) fn recovery_target(t: rss_mdm_recovery_credentials::native::NativeTarget) -> Target {
    match t {
        rss_mdm_recovery_credentials::native::NativeTarget::Device => Target::Device,
        rss_mdm_recovery_credentials::native::NativeTarget::User { user_id } => {
            Target::User { user_id }
        }
    }
}

pub(super) fn recovery_command(
    c: rss_mdm_recovery_credentials::native::apple_facts::AppleCommand,
) -> AppleCommand {
    AppleCommand {
        operation: c.operation,
        owner: c.owner,
        authorized_declarations: c.authorized_declarations,
        assets: c.assets,
        deadline: c.deadline,
        input_version: c.input_version,
        target: recovery_target(c.target),
        request: c.request,
    }
}

fn recovery_admission(
    a: rss_mdm_recovery_credentials::native::apple_business::AppleAdmission,
) -> Admission {
    Admission {
        eligible: a.eligible,
        dispatch: a.dispatch,
        command: recovery_command(a.command),
        target: AppleRegistration {
            tenant: a.target.tenant,
            device: a.target.device,
            registration: a.target.registration,
            generation: a.target.generation,
        },
    }
}
