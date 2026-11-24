//! Operation directory composition; each business owner interprets only its own rows.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, Snapshot as Grant, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, Failure, execution::operations::*};
use rss_mdm_query::{cursor::CursorCodec, directory::Query};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
mod declarations;
mod hydrate;
mod selection;
pub(super) mod sources;

#[derive(Clone, Copy)]
pub(crate) struct Budgets {
    pub page: usize,
    pub statistics: usize,
}
impl Default for Budgets {
    fn default() -> Self { Self { page: 1_048_576, statistics: 4_194_304 } }
}
pub(crate) struct Operations {
    pub budgets: Budgets,
    pub apple: Arc<rss_mdm_apple_channel::flow_store::Store>,
    pub tasks: Arc<super::task_reads::Reads>,
    pub registration: Arc<rss_mdm_registration_service::installation::Service>,
    pub recovery: Option<Arc<rss_mdm_recovery_credentials::native::Service>>,
    pub execution: Arc<rss_mdm_device_service::control::Service>,
}
fn sql(e: sqlx::Error) -> Error {
    super::task_reads::sql(e)
}
fn execution_fault(e: rss_mdm_device_service::control::transaction::Fault) -> Error {
    super::task_reads::history::execution_fault(e)
}
fn software_fault(e: rss_mdm_software_service::deployment::transaction::Fault) -> Error {
    super::task_reads::software_fault(e)
}
fn registration_fault(e: rss_mdm_registration_service::installation::transaction::Fault) -> Error {
    use rss_mdm_registration_service::installation::transaction::Fault as F;
    match e {
        F::Request(e) => super::owner_errors::installation_http(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}
fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::QueryCursorInvalidated,
        _ => Error::Malformed,
    }
}
fn column(name: &str) -> rss_mdm_query::Result<&'static str> {
    use ExecutionColumn::*;
    Ok(match execution_column(name)? {
        Id => "id",
        Kind => "kind COLLATE \"C\"",
        Device => "device",
        Policy => "policy",
        Status => "status COLLATE \"C\"",
        Origin => "source_kind COLLATE \"C\"",
        Deadline => "deadline",
        AuthorizationState => "(authorization_summary->>'state') COLLATE \"C\"",
        AuthorizationReason => "(authorization_summary->>'reason') COLLATE \"C\"",
        ReauthorizationState => "(reauthorization_summary->>'state') COLLATE \"C\"",
        ReauthorizationReason => "(reauthorization_summary->>'reason') COLLATE \"C\"",
        ConfirmationRequired => "(reauthorization_summary->>'confirmationRequired')::boolean",
    })
}
static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::mapped(&SCHEMA, column)
            .expect("Complete operation SQL dispatch")
    });
const CONFIGURATION_RELATION: &str = "SELECT id,device,kind,source_kind,policy_version,policy,deadline,status,input_bytes FROM mdm_planning.configuration_execution_facts WHERE tenant_id=$1::uuid";
impl Operations {
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit owner participants and caller authority retain the borrowed connection and exact operation identity"
    )]
    async fn detail_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Grant,
        now: i64,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        redacted: bool,
    ) -> Result<Detail, Error> {
        grant.require(proof, Permission::OperationRead, Some(device))?;
        let owner = super::native_ownership::on(c, proof.binding().tenant(), id).await?;
        self.detail_owned_on(c, proof, grant, now, device, id, redacted, owner)
            .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "one existing owner read with exact namespace and current authority"
    )]
    async fn detail_owned_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Grant,
        now: i64,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        redacted: bool,
        owner: super::native_ownership::Owner,
    ) -> Result<Detail, Error> {
        grant.require(proof, Permission::OperationRead, Some(device))?;
        use super::native_ownership::Owner;
        match owner {
            Owner::Device => self
                .tasks
                .execution
                .read_on(c, proof, grant, now, device, id, redacted)
                .await
                .map(rss_mdm_management_http::execution::projection::command)
                .map(Detail::Device)
                .map_err(execution_fault),
            Owner::Configuration => {
                let mut detail = self
                    .tasks
                    .configuration
                    .detail_on(c, proof, grant, now, device, id)
                    .await
                    .map_err(super::task_reads::configuration_fault)?;
                if redacted {
                    detail.observation = self
                        .tasks
                        .configuration
                        .evidence_on(c, proof, grant, vec![id])
                        .await
                        .map_err(super::task_reads::configuration_fault)?
                        .remove(&id)
                        .ok_or(Error::Conflict)?
                        .observation;
                }
                Ok(Detail::Configuration(
                    rss_mdm_management_http::execution::projection::configuration_command(detail),
                ))
            }
            Owner::Software => self
                .tasks
                .software
                .read_on(c, proof, grant, now, device, id, redacted)
                .await
                .map(rss_mdm_management_http::execution::projection::software_command)
                .map(Box::new)
                .map(Detail::Software)
                .map_err(software_fault),
            Owner::Recovery => self
                .recovery
                .as_ref()
                .ok_or(Error::Unsupported)?
                .read_on(c, proof, grant, device, id)
                .await
                .map(rss_mdm_management_http::execution::projection::recovery_command)
                .map(Detail::Recovery)
                .map_err(recovery_fault),
            Owner::Registration => self
                .registration
                .read_on(c, proof, grant, device, id)
                .await
                .map(rss_mdm_management_http::execution::projection::registration_command)
                .map(Detail::Registration)
                .map_err(registration_fault),
        }
    }
    async fn decisions(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Grant,
        rows: &[Value],
        now: i64,
    ) -> Result<BTreeMap<Uuid, (Authorization, Reauthorization)>, Error> {
        use super::native_ownership::Owner;
        let (mut execution, mut software, mut registration) = (Vec::new(), Vec::new(), Vec::new());
        let mut recovery = Vec::new();
        let mut configuration = Vec::new();
        for row in rows {
            let sources::Owner::Command(owner) = sources::owner(row)? else { continue };
            let id = selection::id(row)?;
            match owner {
                Owner::Device => execution.push(id),
                Owner::Configuration => configuration.push(id),
                Owner::Software => software.push(id),
                Owner::Registration => registration.push(id),
                Owner::Recovery => recovery.push(id),
            }
        }
        let mut result = BTreeMap::new();
        result.extend(
            self.tasks
                .configuration
                .classify_on(c, proof, grant, configuration, now)
                .await
                .map_err(super::task_reads::configuration_fault)?
                .into_iter()
                .map(|(id, value)| {
                    (
                        id,
                        (
                            configuration_authorization(value),
                            Reauthorization::NotApplicable,
                        ),
                    )
                }),
        );

        for (id, d) in self
            .tasks
            .execution
            .decisions_on(c, proof, grant, execution, now)
            .await
            .map_err(execution_fault)?
        {
            result.insert(
                id,
                (
                    execution_authorization(d.authorization),
                    execution_reauthorization(d.reauthorization),
                ),
            );
        }
        for (id, d) in self
            .tasks
            .software
            .decisions_on(c, proof, grant, software, now)
            .await
            .map_err(software_fault)?
        {
            result.insert(
                id,
                (
                    software_authorization(d.authorization),
                    software_reauthorization(d.reauthorization),
                ),
            );
        }
        for (id, d) in self
            .registration
            .decisions_on(proof.binding(), c, registration)
            .await
            .map_err(registration_fault)?
        {
            result.insert(
                id,
                (
                    registration_authorization(d.authorization),
                    Reauthorization::NotApplicable,
                ),
            );
        }
        if !recovery.is_empty() {
            for (id, d) in self
                .recovery
                .as_ref()
                .ok_or(Error::Unsupported)?
                .decisions_on(proof.binding().tenant(), c, recovery)
                .await
                .map_err(recovery_fault)?
            {
                use rss_mdm_recovery_credentials::native::queries::Authorization as A;
                result.insert(
                    id,
                    (
                        match d.authorization {
                            A::Authorized => Authorization::Authorized,
                            A::Blocked { .. } => Authorization::Blocked {
                                reason: BlockReason::SourceInvalid,
                            },
                        },
                        Reauthorization::NotApplicable,
                    ),
                );
            }
        }
        Ok(result)
    }
}

fn configuration_authorization(
    value: rss_mdm_policy_service::configuration::queries::records::Authorization,
) -> Authorization {
    use rss_mdm_policy_service::configuration::queries::records::{
        Authorization as A, BlockReason as B,
    };
    match value {
        A::Authorized => Authorization::Authorized,
        A::NotApplicable => Authorization::NotApplicable,
        A::Blocked { reason } => Authorization::Blocked {
            reason: match reason {
                B::LifecycleBlocked => BlockReason::LifecycleBlocked,
                B::DeviceInactive => BlockReason::DeviceInactive,
                B::InputMismatch => BlockReason::InputMismatch,
                B::SourceInvalid => BlockReason::SourceInvalid,
            },
        },
    }
}
fn execution_authorization(
    v: rss_mdm_device_service::control::authorization_decision::Authorization,
) -> Authorization {
    use rss_mdm_device_service::control::authorization_decision::{
        Authorization as A, BlockReason as R,
    };
    match v {
        A::Authorized => Authorization::Authorized,
        A::NotApplicable => Authorization::NotApplicable,
        A::Blocked { reason } => Authorization::Blocked {
            reason: match reason {
                R::LifecycleBlocked => BlockReason::LifecycleBlocked,
                R::DeviceInactive => BlockReason::DeviceInactive,

                R::InputMismatch => BlockReason::InputMismatch,
                R::SourceInvalid => BlockReason::SourceInvalid,
            },
        },
    }
}
fn execution_reauthorization(
    v: rss_mdm_device_service::control::authorization_decision::Reauthorization,
) -> Reauthorization {
    use rss_mdm_device_service::control::authorization_decision::{
        Reauthorization as A, ReauthorizationReason as R,
    };
    match v {
        A::Available {
            confirmation_required,
        } => Reauthorization::Available {
            confirmation_required,
        },
        A::NotApplicable => Reauthorization::NotApplicable,
        A::Unavailable { reason } => Reauthorization::Unavailable {
            reason: match reason {
                R::PermissionDenied => ReauthorizationReason::PermissionDenied,
                R::Terminal => ReauthorizationReason::Terminal,
                R::AlreadyReceived => ReauthorizationReason::AlreadyReceived,
                R::Expired => ReauthorizationReason::Expired,
                R::DeviceInactive => ReauthorizationReason::DeviceInactive,

                R::InputMismatch => ReauthorizationReason::InputMismatch,
                R::Unsupported => ReauthorizationReason::Unsupported,
            },
        },
    }
}

fn software_authorization(
    v: rss_mdm_software_service::deployment::authorization_decision::Authorization,
) -> Authorization {
    use rss_mdm_software_service::deployment::authorization_decision::{
        Authorization as A, BlockReason as R,
    };
    match v {
        A::Authorized => Authorization::Authorized,
        A::NotApplicable => Authorization::NotApplicable,
        A::Blocked { reason } => Authorization::Blocked {
            reason: match reason {
                R::LifecycleBlocked => BlockReason::LifecycleBlocked,
                R::DeviceInactive => BlockReason::DeviceInactive,

                R::InputMismatch => BlockReason::InputMismatch,
                R::SourceInvalid => BlockReason::SourceInvalid,
            },
        },
    }
}
fn software_reauthorization(
    v: rss_mdm_software_service::deployment::authorization_decision::Reauthorization,
) -> Reauthorization {
    use rss_mdm_software_service::deployment::authorization_decision::{
        Reauthorization as A, ReauthorizationReason as R,
    };
    match v {
        A::Available {
            confirmation_required,
        } => Reauthorization::Available {
            confirmation_required,
        },
        A::NotApplicable => Reauthorization::NotApplicable,
        A::Unavailable { reason } => Reauthorization::Unavailable {
            reason: match reason {
                R::PermissionDenied => ReauthorizationReason::PermissionDenied,
                R::Terminal => ReauthorizationReason::Terminal,
                R::AlreadyReceived => ReauthorizationReason::AlreadyReceived,
                R::Expired => ReauthorizationReason::Expired,
                R::DeviceInactive => ReauthorizationReason::DeviceInactive,

                R::InputMismatch => ReauthorizationReason::InputMismatch,
                R::Unsupported => ReauthorizationReason::Unsupported,
            },
        },
    }
}

fn registration_authorization(
    v: rss_mdm_registration_service::installation::queries::Authorization,
) -> Authorization {
    use rss_mdm_registration_service::installation::queries::Authorization as A;
    match v {
        A::Authorized => Authorization::Authorized,
        A::Blocked { .. } => Authorization::Blocked {
            reason: BlockReason::SourceInvalid,
        },
    }
}
impl rss_mdm_management_http::execution::operations::Reads for Operations {
    fn declarations<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        device: &'a rss_mdm_agent_wire::DeviceId,
        query: &'a rss_mdm_query::window::Query,
        audit: &'a RequestAudit,
        codec: &'a CursorCodec,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<
        'a,
        rss_mdm_management_http::execution::declarations::Page,
    > {
        Box::pin(self.declarations_read(request, device, query, audit, codec))
    }

    fn directory<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        q: &'a Query,
        codec: &'a CursorCodec,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<'a, Page> {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            q.require_schema(&SCHEMA).map_err(query_error)?;
            self.tasks.snapshot(request,(self,proof,q,codec),|ctx,c,grant,now|Box::pin(async move{
                let(s,p,q,codec)=*ctx;let authority=grant.query_binding(p)?;
                let binding=q.binding(&(p.tenant_id(),p.instance_id(),p.principal_id(),"live-operations",&authority)).map_err(query_error)?;
                let page=selection::page(s,c,(p,grant),q,codec,&binding,now).await?;
                s.hydrate(c, (p, grant), q, now, page).await
            })).await.inspect(|_|audit.require_final_request())
        })
    }
    fn statistics<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        q: &'a Query,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<
        'a,
        rss_mdm_query::Statistics<Statistics>,
    > {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            q.require_schema(&SCHEMA).map_err(query_error)?;
            self.tasks
                .snapshot(request, (self, proof, q), |ctx, c, grant, now| {
                    Box::pin(async move {
                        let (s, p, q) = *ctx;
                        let allowed = grant
                            .devices_for(p, Permission::OperationRead)?
                            .map(|ids| ids.into_iter().collect());
                        let value = selection::statistics(s, c, p, grant, q, allowed, now).await?;
                        serde_json::from_value(value)
                            .map_err(|_| Error::Unavailable(Failure::CommandInvariant))
                    })
                })
                .await
                .inspect(|_| audit.require_final_request())
        })
    }
    fn detail<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        device: &'a rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<'a, Detail> {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            self.tasks
                .snapshot(request, (self, proof, device, id), |ctx, c, grant, now| {
                    Box::pin(async move {
                        let (s, p, d, id) = *ctx;
                        s.detail_on(c, p, grant, now, d, id, false).await
                    })
                })
                .await
                .inspect(|_| audit.require_final_request())
        })
    }
    fn change<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        device: &'a rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        change: &'a rss_mdm_device_service::control::Change,
        reauthorization: Option<
            &'a rss_mdm_device_service::control::device_control::Reauthorization,
        >,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<
        'a,
        rss_mdm_device_service::control::ChangedReceipt,
    > {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            let owner = self
                .tasks
                .snapshot(request, (self, proof, device, id), |ctx, c, grant, _| {
                    Box::pin(async move {
                        let (_, p, d, id) = *ctx;
                        grant.require(p, Permission::OperationRead, Some(d))?;
                        super::native_ownership::on(c, p.binding().tenant(), id)
                            .await
                            .map_err(Into::into)
                    })
                })
                .await?;
            // Only direct device controls support management cancel/reauthorization; policies own desired work.
            if owner != super::native_ownership::Owner::Device {
                return Err(Error::Conflict);
            }
            self.execution
                .change(proof, device, id, change, reauthorization, audit)
                .await
                .map_err(Into::into)
        })
    }
}

fn recovery_fault(e: rss_mdm_recovery_credentials::native::transaction::Fault) -> Error {
    use rss_mdm_recovery_credentials::native::transaction::Fault as F;
    match e {
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
        F::Request(e) => e.into(),
    }
}

mod diagnostics;
