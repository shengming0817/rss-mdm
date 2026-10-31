//! Keyset composition includes every original owner and Policy version in one snapshot.
use super::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_management_http::execution::task_reads::{RUNS_SCHEMA, RunDetail, RunPage, RunSummary};
use rss_mdm_query::{cursor::CursorCodec, window::Query};
use uuid::Uuid;
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Position {
    available_at: i64,
    task_id: Uuid,
}
pub(super) fn execution_fault(error: rss_mdm_execution_service::transaction::Fault) -> Error {
    use rss_mdm_execution_service::transaction::Fault as F;
    match error {
        F::Request(e) => e.into(),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}
impl Reads {
    pub(super) async fn runs(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        policy: Uuid,
        page: &Query,
        codec: &CursorCodec,
    ) -> Result<RunPage, Error> {
        page.require_schema(&RUNS_SCHEMA)
            .map_err(|_| Error::Malformed)?;
        self.snapshot(
            proof,
            (self, proof, policy, page, codec),
            |ctx, c, grant, now| {
                Box::pin(async move {
                    let (s, proof, policy, page, codec) = *ctx;
                    grant.require(proof, Permission::PolicyRead, None)?;
                    grant.require_all_devices(proof, Permission::OperationRead)?;
                    let binding = rss_mdm_query::cursor::fingerprint(&(
                        "policy-business-runs",
                        RUNS_SCHEMA.id,
                        proof.tenant_id(),
                        proof.instance_id(),
                        proof.principal_id(),
                        grant.query_binding(proof)?,
                        policy,
                    ))
                    .map_err(|_| Error::Malformed)?;
                    let position: Option<Position> = page
                        .cursor()
                        .as_ref()
                        .map(|v| {
                            codec
                                .decode(
                                    &rss_contract::PageCursor::parse(v)
                                        .map_err(|_| Error::Malformed)?,
                                    &binding,
                                )
                                .map_err(|_| Error::QueryCursorInvalidated)
                        })
                        .transpose()?;
                    let after = position.map(|p| (p.available_at, p.task_id));
                    let limit = page.limit();
                    let mut items = s
                        .execution
                        .run_page_on(c, policy, after, limit + 1, now)
                        .await
                        .map_err(execution_fault)?
                        .into_iter()
                        .map(RunSummary::Execution)
                        .collect::<Vec<_>>();
                    items.extend(
                        rss_mdm_script_service::queries::page_on(
                            c,
                            &s.tenant.to_string(),
                            policy,
                            after,
                            limit + 1,
                        )
                        .await
                        .map_err(script_fault)?
                        .into_iter()
                        .map(RunSummary::Script),
                    );
                    items.extend(
                        rss_mdm_inventory_service::collection::execution::queries::page_on(
                            c,
                            &s.tenant.to_string(),
                            policy,
                            after,
                            limit + 1,
                        )
                        .await?
                        .into_iter()
                        .map(RunSummary::Collection),
                    );
                    items.sort_by_key(|v| std::cmp::Reverse(v.position()));
                    let mut ids = std::collections::BTreeSet::new();
                    if items.iter().any(|v| !ids.insert(v.position().1)) {
                        return Err(Error::Unavailable(Failure::CommandInvariant));
                    }
                    let more = items.len() > limit;
                    items.truncate(limit);
                    let next_cursor = if more {
                        items
                            .last()
                            .map(|item| {
                                let (available_at, task_id) = item.position();
                                codec
                                    .encode(
                                        &binding,
                                        &Position {
                                            available_at,
                                            task_id,
                                        },
                                    )
                                    .map(|v| v.as_str().to_owned())
                                    .map_err(|_| Error::Malformed)
                            })
                            .transpose()?
                    } else {
                        None
                    };
                    Ok(RunPage { items, next_cursor })
                })
            },
        )
        .await
        .inspect(|_| audit.require_final_request())
    }
    pub(super) async fn run(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        policy: Uuid,
        id: Uuid,
    ) -> Result<RunDetail, Error> {
        self.snapshot(proof, (self, proof, policy, id), |ctx, c, grant, now| {
            Box::pin(async move {
                let (s, proof, policy, id) = *ctx;
                grant.require(proof, Permission::PolicyRead, None)?;
                use super::super::task_ownership::{self, Owner};
                let owner = task_ownership::on(c, s.tenant, id)
                    .await
                    .map_err(|e| match e {
                        sqlx::Error::RowNotFound => Error::NotFound,
                        other => sql(other),
                    })?;
                match owner {
                    Owner::Execution => s
                        .execution
                        .run_detail_on(c, proof, grant, policy, id, now)
                        .await
                        .map(RunDetail::Execution)
                        .map_err(execution_fault),
                    Owner::Script => rss_mdm_script_service::queries::detail_on(
                        c,
                        &s.tenant.to_string(),
                        policy,
                        id,
                        proof,
                        grant,
                    )
                    .await
                    .map(RunDetail::Script)
                    .map_err(script_fault),
                    Owner::Collection => {
                        rss_mdm_inventory_service::collection::execution::queries::detail_on(
                            c,
                            &s.tenant.to_string(),
                            policy,
                            id,
                            proof,
                            grant,
                        )
                        .await
                        .map(RunDetail::Collection)
                        .map_err(Into::into)
                    }
                }
            })
        })
        .await
        .inspect(|_| audit.require_final_request())
    }
}
