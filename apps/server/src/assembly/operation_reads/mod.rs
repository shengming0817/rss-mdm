//! Operation directory composition; each business owner interprets only its own rows.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, Snapshot as Grant, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, Failure, execution::operations::*};
use rss_mdm_query::{cursor::CursorCodec, directory::Query};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
mod declarations;
mod selection;
pub(crate) struct Operations {
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
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "kind" => "kind COLLATE \"C\"",
        "device" => "device COLLATE \"C\"",
        "policy" => "policy::text COLLATE \"C\"",
        "status" => "status COLLATE \"C\"",
        "registrationId" => "registration::text COLLATE \"C\"",
        "generation" => "generation",
        "origin" => "source_kind COLLATE \"C\"",
        "deadline" => "deadline",
        "authorization.state" => "authorization_summary->>'state'",
        "authorization.reason" => "authorization_summary->>'reason'",
        "reauthorization.state" => "reauthorization_summary->>'state'",
        _ => unreachable!("checked execution field"),
    }
}
const PAGE_SOURCES: i64 = 1_048_576;
const STATISTICS_SOURCES: i64 = 4_194_304;
fn check_sources(rows: i64, limit: i64, stage: &'static str) -> Result<(), Error> {
    if rows < 0 {
        return Err(Error::Unavailable(Failure::CommandInvariant));
    }
    if !rss_mdm_query_postgres::within_budget(
        stage,
        rows as u64,
        rows as u64 * 16,
        limit as u64,
        limit as u64 * 16,
    ) {
        return Err(Error::Unavailable(Failure::Capacity));
    }
    Ok(())
}

fn relation(
    tenant: String,
    allowed: Option<Vec<String>>,
    source_limit: i64,
    source_rows: Option<i64>,
) -> sqlx::QueryBuilder<sqlx::Postgres> {
    let mut sql = sqlx::QueryBuilder::new("WITH tenant_context AS(SELECT ");
    sql.push_bind(tenant).push("::uuid),executions AS(");
    sql.push("SELECT id,device,kind,registration,generation,source_kind,policy_version,policy,deadline,status,input_bytes FROM mdm_planning.configuration_execution_facts WHERE tenant_id=$1::uuid UNION ALL ").push(rss_mdm_device_service::control::directory::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_software_service::deployment::directory::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_registration_service::installation::queries::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_registration_service::enrollment::tasks::queries::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_device_access_postgres::device_access::execution::queries::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_recovery_credentials::tasks::queries::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_recovery_credentials::tasks::queries::DA_RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_recovery_credentials::native::queries::RELATION_SQL)
        .push(" UNION ALL ").push(rss_mdm_script_service::queries::RELATION_SQL)
        .push(" UNION ALL ").push(rss_mdm_inventory_service::collection::execution::queries::relation_sql());
    sql.push("),source_probe AS MATERIALIZED(SELECT id FROM executions LIMIT ")
        .push_bind(source_limit + 1)
        .push("),source_count AS MATERIALIZED (");
    if let Some(rows) = source_rows {
        sql.push("SELECT ").push_bind(rows).push("::bigint AS rows");
    } else {
        sql.push("SELECT count(*) AS rows FROM source_probe");
    }
    sql.push("),source_budget AS MATERIALIZED(SELECT CASE WHEN EXISTS(SELECT id FROM source_probe GROUP BY id HAVING count(*)>1) THEN -1 ELSE rows END AS rows FROM source_count),visible AS(SELECT * FROM executions WHERE (SELECT rows FROM source_budget) BETWEEN 0 AND ").push_bind(source_limit);
    if let Some(ids) = allowed {
        sql.push(" AND device=ANY(").push_bind(ids).push(")");
    }
    sql.push(") ");
    sql
}
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
        device: &str,
        id: Uuid,
        redacted: bool,
    ) -> Result<Detail, Error> {
        grant.require(proof, Permission::OperationRead, Some(device))?;
        use super::native_ownership::{self, Owner};
        match native_ownership::on(c, self.tasks.tenant, id).await? {
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
        ids: Vec<Uuid>,
        now: i64,
    ) -> Result<BTreeMap<Uuid, (Authorization, Reauthorization)>, Error> {
        use super::native_ownership::{self, Owner};
        let (mut execution, mut software, mut registration) = (Vec::new(), Vec::new(), Vec::new());
        let mut recovery = Vec::new();
        let mut configuration = Vec::new();
        for (id, owner) in native_ownership::batch_on(c, self.tasks.tenant, &ids).await? {
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
            .decisions_on(c, registration)
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
                .decisions_on(c, recovery)
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
                B::RegistrationChanged => BlockReason::RegistrationChanged,
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
                R::RegistrationChanged => BlockReason::RegistrationChanged,
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
                R::RegistrationChanged => ReauthorizationReason::RegistrationChanged,
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
                R::RegistrationChanged => BlockReason::RegistrationChanged,
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
                R::RegistrationChanged => ReauthorizationReason::RegistrationChanged,
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
        proof: &'a AuthorizedPrincipal,
        device: &'a str,
        query: &'a rss_mdm_query::window::Query,
        audit: &'a RequestAudit,
        codec: &'a CursorCodec,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<
        'a,
        rss_mdm_management_http::execution::declarations::Page,
    > {
        Box::pin(self.declarations_read(proof, device, query, audit, codec))
    }

    fn directory<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        q: &'a Query,
        codec: &'a CursorCodec,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<'a, Page> {
        Box::pin(async move {
            q.require_schema(&SCHEMA).map_err(query_error)?;
            self.tasks.snapshot(proof,(self,proof,q,codec),|ctx,c,grant,now|Box::pin(async move{
                let(s,p,q,codec)=*ctx;let authority=grant.query_binding(p)?;
                let binding=q.binding(&(p.tenant_id(),p.instance_id(),p.principal_id(),"live-operations",&authority)).map_err(query_error)?;
                let page=selection::page(s,c,(p,grant),q,codec,&binding,now).await?;
                let mut run_ids=Vec::new();
                if q.selects("evidence"){for row in &page.items{if row["kind"]=="action_run"{run_ids.push(uuid::Uuid::parse_str(row["id"].as_str().ok_or(Error::Malformed)?).map_err(|_|Error::Malformed)?);}}}
                let execution_ids=rss_mdm_device_service::control::capacity::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let software_ids=rss_mdm_software_service::deployment::capacity::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let enrollment_ids=rss_mdm_registration_service::enrollment::tasks::storage::owned_ids_on(rss_mdm_install_support::StorageProfile::Mdm, c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let access_ids=rss_mdm_device_access_postgres::device_access::execution::storage::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let credential_ids=rss_mdm_recovery_credentials::tasks::storage::owned_ids_on(rss_mdm_install_support::StorageProfile::Mdm, c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let da_credential_ids=rss_mdm_recovery_credentials::tasks::storage::owned_ids_on(rss_mdm_install_support::StorageProfile::Da, c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let script_ids=rss_mdm_script_service::storage::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let collection_ids=rss_mdm_inventory_service::collection::execution::storage::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                for id in &run_ids{if [access_ids.contains(id),credential_ids.contains(id),da_credential_ids.contains(id),execution_ids.contains(id),software_ids.contains(id),enrollment_ids.contains(id),script_ids.contains(id),collection_ids.contains(id)].into_iter().filter(|v|*v).count()!=1{return Err(Error::Unavailable(Failure::CommandInvariant));}}
                let mut execution=rss_mdm_device_service::control::directory::run_summaries_on(c,s.tasks.tenant,execution_ids.into_iter().collect()).await.map_err(execution_fault)?;
                let mut software=rss_mdm_software_service::deployment::directory::run_summaries_on(c,s.tasks.tenant,software_ids.into_iter().collect()).await.map_err(software_fault)?;
                let mut scripts=rss_mdm_script_service::queries::run_summaries_on(c,s.tasks.tenant,script_ids).await.map_err(super::task_reads::script_fault)?;
                let mut collections=rss_mdm_inventory_service::collection::execution::queries::run_summaries_on(c,s.tasks.tenant,collection_ids).await?;
                let mut items=Vec::with_capacity(page.items.len());
                for row in page.items{
                    let authorization=row.get("authorization").cloned().map(serde_json::from_value).transpose().map_err(|_|Error::Unavailable(Failure::CommandInvariant))?;
                    let reauthorization=row.get("reauthorization").cloned().map(serde_json::from_value).transpose().map_err(|_|Error::Unavailable(Failure::CommandInvariant))?;
                    let metadata:Metadata=serde_json::from_value(row).map_err(|_|Error::Unavailable(Failure::CommandInvariant))?;
                    let evidence=if !q.selects("evidence"){None}else{Some(match metadata.kind{
                        KindOfOperation::Command=>Evidence::Native { detail: Box::new(s.detail_on(c,p,grant,now,&metadata.device,metadata.id,true).await?) },
                        KindOfOperation::ActionRun=>{
                            if let Some(v)=execution.remove(&metadata.id){Evidence::Device(v)}
                            else if let Some(v)=software.remove(&metadata.id){Evidence::Software(v)}
                            else if let Some(v)=scripts.remove(&metadata.id){Evidence::Script(Box::new(v))}
                            else if let Some(v)=collections.remove(&metadata.id){Evidence::Collection(Box::new(v))}
                            else if access_ids.contains(&metadata.id){Evidence::Access(rss_mdm_device_access_postgres::device_access::execution::queries::detail_on(c,&s.tasks.tenant.to_string(),metadata.policy.ok_or(Error::Conflict)?,metadata.id,p,grant).await.map_err(super::task_reads::access_fault)?)}
                            else if credential_ids.contains(&metadata.id){Evidence::Credential(rss_mdm_recovery_credentials::tasks::queries::detail_on(rss_mdm_install_support::StorageProfile::Mdm, c,&s.tasks.tenant.to_string(),metadata.policy.ok_or(Error::Conflict)?,metadata.id,p,grant).await.map_err(super::task_reads::credential_fault)?)}
                            else if da_credential_ids.contains(&metadata.id){Evidence::Credential(rss_mdm_recovery_credentials::tasks::queries::detail_on(rss_mdm_install_support::StorageProfile::Da, c,&s.tasks.tenant.to_string(),metadata.policy.ok_or(Error::Conflict)?,metadata.id,p,grant).await.map_err(super::task_reads::credential_fault)?)}
                            else if enrollment_ids.contains(&metadata.id){Evidence::Enrollment(rss_mdm_registration_service::enrollment::tasks::queries::detail_on(rss_mdm_install_support::StorageProfile::Mdm, c,&s.tasks.tenant.to_string(),metadata.policy.ok_or(Error::Conflict)?,metadata.id,p,grant).await.map_err(super::task_reads::enrollment_fault)?)}
                            else{return Err(Error::Unavailable(Failure::CommandInvariant));}
                        }
                    })};
                    let detail_url=match metadata.kind{KindOfOperation::Command=>format!("/api/v1/devices/{}/operations/{}",url::form_urlencoded::byte_serialize(metadata.device.as_bytes()).collect::<String>().replace('+',"%20"),metadata.id),KindOfOperation::ActionRun=>format!("/api/v1/policies/{}/runs/{}",metadata.policy.ok_or(Error::Conflict)?,metadata.id)};
                    items.push(Item{metadata,evidence,authorization,reauthorization,detail_url});
                }
                Ok(Page{items,next_cursor:page.next_cursor})
            })).await.inspect(|_|audit.require_final_request())
        })
    }
    fn statistics<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        q: &'a Query,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<
        'a,
        rss_mdm_query::Statistics<Statistics>,
    > {
        Box::pin(async move {
            q.require_schema(&SCHEMA).map_err(query_error)?;
            self.tasks
                .snapshot(proof, (self, proof, q), |ctx, c, grant, now| {
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
        proof: &'a AuthorizedPrincipal,
        device: &'a str,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<'a, Detail> {
        Box::pin(async move {
            self.tasks
                .snapshot(proof, (self, proof, device, id), |ctx, c, grant, now| {
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
        proof: &'a AuthorizedPrincipal,
        device: &'a str,
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
        Box::pin(async move {
            let owner = self
                .tasks
                .snapshot(proof, (self, proof, device, id), |ctx, c, grant, _| {
                    Box::pin(async move {
                        let (s, p, d, id) = *ctx;
                        grant.require(p, Permission::OperationRead, Some(d))?;
                        super::native_ownership::on(c, s.tasks.tenant, id)
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
