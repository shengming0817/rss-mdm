//! Operation directory composition; each business owner interprets only its own rows.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, Snapshot as Grant, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, Failure, execution::operations::*};
use rss_mdm_query::{cursor::CursorCodec, directory::Query};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
mod selection;
pub(crate) struct Operations {
    pub tasks: Arc<super::task_reads::Reads>,
    pub registration: Arc<rss_mdm_registration_service::installation::Service>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
}
fn sql(e: sqlx::Error) -> Error {
    super::task_reads::sql(e)
}
fn execution_fault(e: rss_mdm_execution_service::transaction::Fault) -> Error {
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
    sql.push(rss_mdm_execution_service::directory::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_software_service::deployment::directory::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_registration_service::installation::queries::RELATION_SQL)
        .push(" UNION ALL ")
        .push(rss_mdm_registration_service::enrollment::tasks::queries::RELATION_SQL);
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
            Owner::Execution | Owner::Configuration => self
                .tasks
                .execution
                .read_on(c, proof, grant, now, device, id, redacted)
                .await
                .map(rss_mdm_management_http::execution::projection::command)
                .map(Detail::Execution)
                .map_err(execution_fault),
            Owner::Software => self
                .tasks
                .software
                .read_on(c, proof, grant, now, device, id, redacted)
                .await
                .map(rss_mdm_management_http::execution::projection::software_command)
                .map(Box::new)
                .map(Detail::Software)
                .map_err(software_fault),
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
        for (id, owner) in native_ownership::batch_on(c, self.tasks.tenant, &ids).await? {
            match owner {
                Owner::Execution | Owner::Configuration => execution.push(id),
                Owner::Software => software.push(id),
                Owner::Registration => registration.push(id),
            }
        }
        let mut result = BTreeMap::new();
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
        Ok(result)
    }
}

fn execution_authorization(
    v: rss_mdm_execution_service::authorization_decision::Authorization,
) -> Authorization {
    use rss_mdm_execution_service::authorization_decision::{Authorization as A, BlockReason as R};
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
    v: rss_mdm_execution_service::authorization_decision::Reauthorization,
) -> Reauthorization {
    use rss_mdm_execution_service::authorization_decision::{
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
                let execution_ids=rss_mdm_execution_service::capacity::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let software_ids=rss_mdm_software_service::deployment::capacity::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                let enrollment_ids=rss_mdm_registration_service::enrollment::tasks::storage::owned_ids_on(c,s.tasks.tenant,&run_ids).await.map_err(sql)?;
                for id in &run_ids{if [execution_ids.contains(id),software_ids.contains(id),enrollment_ids.contains(id)].into_iter().filter(|v|*v).count()!=1{return Err(Error::Unavailable(Failure::CommandInvariant));}}
                let mut execution=rss_mdm_execution_service::directory::run_summaries_on(c,s.tasks.tenant,execution_ids.into_iter().collect()).await.map_err(execution_fault)?;
                let mut software=rss_mdm_software_service::deployment::directory::run_summaries_on(c,s.tasks.tenant,software_ids.into_iter().collect()).await.map_err(software_fault)?;
                let mut items=Vec::with_capacity(page.items.len());
                for row in page.items{
                    let authorization=row.get("authorization").cloned().map(serde_json::from_value).transpose().map_err(|_|Error::Unavailable(Failure::CommandInvariant))?;
                    let reauthorization=row.get("reauthorization").cloned().map(serde_json::from_value).transpose().map_err(|_|Error::Unavailable(Failure::CommandInvariant))?;
                    let metadata:Metadata=serde_json::from_value(row).map_err(|_|Error::Unavailable(Failure::CommandInvariant))?;
                    let evidence=if !q.selects("evidence"){None}else{Some(match metadata.kind{
                        KindOfOperation::Command=>Evidence::Native(Box::new(s.detail_on(c,p,grant,now,&metadata.device,metadata.id,true).await?)),
                        KindOfOperation::ActionRun=>{
                            if let Some(v)=execution.remove(&metadata.id){Evidence::Execution(v)}
                            else if let Some(v)=software.remove(&metadata.id){Evidence::Software(v)}
                            else{Evidence::Enrollment(rss_mdm_registration_service::enrollment::tasks::queries::detail_on(c,&s.tasks.tenant.to_string(),metadata.policy.ok_or(Error::Conflict)?,metadata.id,p,grant).await.map_err(super::task_reads::enrollment_fault)?)}
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
        change: &'a rss_mdm_execution_service::Change,
        reauthorization: Option<&'a rss_mdm_execution_service::device_control::Reauthorization>,
        audit: &'a RequestAudit,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<
        'a,
        rss_mdm_execution_service::ChangedReceipt,
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
            if owner != super::native_ownership::Owner::Execution {
                return Err(Error::Conflict);
            }
            self.execution
                .change(proof, device, id, change, reauthorization, audit)
                .await
                .map_err(Into::into)
        })
    }
}
