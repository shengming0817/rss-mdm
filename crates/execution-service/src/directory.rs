//! Cross-device read projections retain the existing command and action-run owners.
use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::{Value, json};
mod selection;
pub static SCHEMA: Schema = Schema {
    id: "executions",
    keys: &["id", "kind"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("kind", Kind::Enum(&["command", "action_run"])),
        Field::scalar("device", Kind::Text),
        Field::scalar("policy", Kind::Uuid),
        Field::scalar("status", Kind::Text),
        Field::scalar("registrationId", Kind::Uuid),
        Field::scalar("generation", Kind::Integer),
        Field::scalar("origin", Kind::Enum(&["direct", "policy"])),
        Field::scalar("deadline", Kind::Integer),
        Field::output("authorization"),
        Field::output("reauthorization"),
        Field::filter_only(
            "authorization.state",
            Kind::Enum(&["authorized", "blocked", "not_applicable"]),
        ),
        Field::filter_only(
            "authorization.reason",
            Kind::Enum(&[
                "lifecycle_blocked",
                "registration_changed",
                "input_mismatch",
                "source_invalid",
            ]),
        ),
        Field::filter_only(
            "reauthorization.state",
            Kind::Enum(&["available", "unavailable", "not_applicable"]),
        ),
        Field::output("evidence"),
        Field::output("detailUrl"),
    ],
};
fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
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
fn check_sources(rows: i64, limit: i64, stage: &'static str) -> crate::transaction::Result<()> {
    if !rss_mdm_query_postgres::within_budget(
        stage,
        rows as u64,
        rows as u64 * 16,
        limit as u64,
        limit as u64 * 16,
    ) {
        return Err(Error::Unavailable(Failure::Capacity).into());
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
    sql.push_bind(tenant)
        .push("::uuid), source_budget AS MATERIALIZED (");
    if let Some(rows) = source_rows {
        sql.push("SELECT ").push_bind(rows).push("::bigint AS rows");
    } else {
        sql.push("SELECT count(*) AS rows FROM(SELECT tenant_id FROM mdm_commands.operations WHERE tenant_id=$1::uuid UNION ALL SELECT tenant_id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid LIMIT ").push_bind(source_limit+1).push(") probe");
    }
    sql.push("), executions AS (SELECT o.id,o.device,'command'::text AS kind,o.registration,o.registration_generation AS generation,o.source_kind,o.policy_version,v.policy,(o.input_context->>'deadline')::bigint AS deadline,coalesce(d.status,'unknown') AS status FROM mdm_commands.operations o LEFT JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) WHERE o.tenant_id=$1::uuid UNION ALL SELECT r.id,r.device,'action_run',r.registration,r.generation,r.source_kind,r.policy_version,v.policy,r.deadline,coalesce(r.state->>'execution','unknown') FROM mdm_commands.action_runs r LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid), visible AS (SELECT * FROM executions WHERE (SELECT rows FROM source_budget)<=").push_bind(source_limit);
    if let Some(ids) = allowed {
        sql.push(" AND device=ANY(").push_bind(ids).push(")");
    }
    sql.push(") ");
    sql
}
async fn run_summaries(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: Vec<Uuid>,
) -> crate::transaction::Result<std::collections::BTreeMap<Uuid, Value>> {
    use sqlx::Row;
    if ids.is_empty() {
        return Ok(Default::default());
    }
    if ids.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    let count = ids.len();
    let tenant = tenant.to_string();
    let rows = {
        let c = &mut *c;
        let mut sql = sqlx::QueryBuilder::new(
            "WITH selected AS MATERIALIZED (SELECT r.id,jsonb_build_object('state',r.state,'effect',coalesce(r.result->>'effect','unverified'),'result',",
        );
        sql.push(actions::history::RESULT_SUMMARY_SQL).push(") AS document FROM mdm_commands.action_runs r WHERE r.tenant_id=").push_bind(tenant).push("::uuid AND r.id=ANY(").push_bind(ids).push(")),budget AS(SELECT coalesce(sum(octet_length(document::text)),0)::bigint AS bytes FROM selected) SELECT selected.*,budget.bytes FROM budget LEFT JOIN selected ON budget.bytes<=16777216");
        sql.build().fetch_all(c).await
    }?;
    rss_mdm_query_postgres::observe_rows("execution.runs", &rows)?;
    let bytes: i64 = rows.first().ok_or(Error::Conflict)?.try_get("bytes")?;
    if !rss_mdm_query_postgres::within_budget(
        "execution.runs",
        count as u64,
        bytes as u64,
        1000,
        16 * 1024 * 1024,
    ) {
        return Err(Error::Unavailable(Failure::Capacity).into());
    }
    if rows.len() != count {
        return Err(Error::Conflict.into());
    }
    rows.into_iter()
        .map(|r| Ok((r.try_get("id")?, r.try_get("document")?)))
        .collect()
}
impl crate::queries::Queries {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &Query,
        codec: &CursorCodec,
        audit: &RequestAudit,
    ) -> std::result::Result<crate::queries::records::ExecutionDirectory, crate::queries::QueryError>
    {
        q.require_schema(&SCHEMA).map_err(query_error)?;
        proof
            .authorization()?
            .devices_for(proof, Permission::OperationRead)?;
        self.snapshot(proof, (self, proof, q, codec, audit), |ctx, c, basis| {
            Box::pin(async move {
                let (s, p, q, codec, _audit) = *ctx;
                let current = &basis.grant;
                let grant = current.query_binding(p)?;
                let binding = q
                    .binding(&(
                        p.tenant_id(),
                        p.instance_id(),
                        p.principal_id(),
                        "live-executions",
                        &grant,
                    ))
                    .map_err(query_error)?;
                let page =
                    selection::page(s, c, (p, current), q, codec, &binding, basis.now).await?;
                let run_ids = if q.selects("evidence") {
                    page.items
                        .iter()
                        .filter(|v| v["kind"] == "action_run")
                        .map(|v| {
                            v["id"]
                                .as_str()
                                .ok_or(Error::Malformed)
                                .and_then(|id| Uuid::parse_str(id).map_err(|_| Error::Malformed))
                        })
                        .collect::<std::result::Result<Vec<_>, _>>()?
                } else {
                    Vec::new()
                };
                let mut runs = run_summaries(c, s.tenant, run_ids).await?;
                use crate::queries::records::{self, ExecutionEvidence, ExecutionSummary};
                let command_ids = if q.selects("evidence") {
                    page.items
                        .iter()
                        .filter(|v| v["kind"] == "command")
                        .map(|v| {
                            v["id"]
                                .as_str()
                                .ok_or(Error::Malformed)
                                .and_then(|id| Uuid::parse_str(id).map_err(|_| Error::Malformed))
                        })
                        .collect::<std::result::Result<Vec<_>, _>>()?
                } else {
                    Vec::new()
                };
                let mut commands =
                    storage::load_many_on(c, s.tenant, &s.protection, command_ids).await?;
                let windows = page
                    .items
                    .iter()
                    .filter_map(|v| {
                        if v["kind"] != "command" {
                            return None;
                        }
                        let id = v["id"].as_str().and_then(|id| Uuid::parse_str(id).ok())?;
                        let op = commands.get(&id)?;
                        if !matches!(op.request.task, Task::Windows { .. }) {
                            return None;
                        }
                        Some(
                            v["status"]
                                .as_str()
                                .ok_or(Error::Malformed)
                                .and_then(|status| {
                                    dc::Status::restore(status).map_err(|_| Error::Malformed)
                                })
                                .map(|status| (op, status)),
                        )
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let mut windows = super::protocol::windows_observations_on(
                    c,
                    s.tenant,
                    &s.protection,
                    &windows,
                    false,
                )
                .await?;
                let apples = page
                    .items
                    .iter()
                    .filter_map(|v| {
                        if v["kind"] != "command" {
                            return None;
                        }
                        let id = v["id"].as_str().and_then(|id| Uuid::parse_str(id).ok())?;
                        let op = commands.get(&id)?;
                        if !matches!(op.request.task, Task::Macos { .. }) {
                            return None;
                        }
                        Some(
                            v["status"]
                                .as_str()
                                .ok_or(Error::Malformed)
                                .and_then(|status| {
                                    dc::Status::restore(status).map_err(|_| Error::Malformed)
                                })
                                .map(|status| (op, status)),
                        )
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let mut apples = super::apple::observations_on(
                    c,
                    s.tenant,
                    s.apple_results.clone(),
                    &apples,
                    false,
                )
                .await?;
                let install_ops = commands
                    .values()
                    .filter(|op| op.authority.agent_package().is_some())
                    .collect::<Vec<_>>();
                let mut installations = super::native_installation::installation_observations_on(
                    c,
                    s.tenant,
                    s.apple_results.clone(),
                    s.agent_store.clone(),
                    &install_ops,
                    false,
                )
                .await?;
                let mut items = Vec::new();
                for value in page.items {
                    let authorization = value
                        .get("authorization")
                        .cloned()
                        .map(records::decode)
                        .transpose()?;
                    let reauthorization = value
                        .get("reauthorization")
                        .cloned()
                        .map(records::decode)
                        .transpose()?;
                    let metadata: records::ExecutionMetadata = records::decode(value)?;
                    let evidence = if !q.selects("evidence") {
                        None
                    } else {
                        Some(match metadata.kind {
                            records::ExecutionKind::Command => {
                                let op = commands.remove(&metadata.id).ok_or(Error::Conflict)?;
                                let command = stored(dc::Status::restore(&metadata.status))?;
                                let mut observation =
                                    if matches!(op.request.task, Task::Windows { .. }) {
                                        windows.remove(&op.id).ok_or(Error::Conflict)?
                                    } else {
                                        apples.remove(&op.id).ok_or(Error::Conflict)?
                                    };
                                observation.redact_values();
                                let agent_installation = if op.authority.agent_package().is_some() {
                                    Some(records::decode(
                                        installations.remove(&op.id).ok_or(Error::Conflict)?,
                                    )?)
                                } else {
                                    None
                                };
                                ExecutionEvidence::Command(Box::new(records::CommandEvidence {
                                    command_status: records::CommandStatus(command),
                                    observation,
                                    dispatch_failure: op.dispatch_failure,
                                    agent_installation,
                                }))
                            }
                            records::ExecutionKind::ActionRun => ExecutionEvidence::Run(
                                records::decode(runs.remove(&metadata.id).ok_or(Error::Conflict)?)?,
                            ),
                        })
                    };
                    items.push(ExecutionSummary {
                        metadata,
                        evidence,
                        authorization,
                        reauthorization,
                    });
                }
                p.check_live()?;
                Ok(records::Page {
                    items,
                    next_cursor: page.next_cursor,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    pub async fn directory_statistics(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<
        rss_mdm_query::Statistics<crate::queries::records::ExecutionStatistics>,
        crate::queries::QueryError,
    > {
        q.require_schema(&SCHEMA).map_err(query_error)?;
        self.snapshot(p, (self, p, q, audit), |ctx, c, basis| {
            Box::pin(async move {
                let (s, p, q, _audit) = *ctx;
                let current = &basis.grant;
                let allowed = current
                    .devices_for(p, Permission::OperationRead)?
                    .map(|v| v.into_iter().collect());
                let value =
                    selection::statistics(s, c, p, current, q, allowed.clone(), basis.now).await?;
                p.check_live()?;
                stored(serde_json::from_value(value))
            })
        })
        .await
        .map_err(Into::into)
    }
    /// Device metadata and execution prerequisites share the existing request snapshot.
    /// Registration and Inventory compose their connection-level reads inside the callback.
    pub async fn directory_device_snapshot<R: Send, F>(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        windows: bool,
        apple: bool,
        load: F,
    ) -> std::result::Result<
        (R, Vec<crate::queries::records::Capability>),
        crate::queries::QueryError,
    >
    where
        F: for<'c> FnOnce(
                &'c mut sqlx::PgConnection,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = crate::Result<R>> + Send + 'c>,
            > + Send,
    {
        proof.require(Permission::InventoryRead, Some(device))?;
        self.snapshot(
            proof,
            (self, proof, device, windows, apple, Some(load)),
            |ctx, c, basis| {
                Box::pin(async move {
                    let (service, proof, device, windows, apple, load) = ctx;
                    basis
                        .grant
                        .require(proof, Permission::InventoryRead, Some(device))?;
                    let value = load.take().expect("one device projection")(c).await?;
                    #[cfg(feature = "integration")]
                    service
                        .read_checkpoint(crate::queries::ReadPhase::Facts)
                        .await?;
                    let capabilities = service
                        .directory_capabilities_on(c, proof, &basis.grant, device, *windows, *apple)
                        .await?;
                    Ok((value, capabilities))
                })
            },
        )
        .await
        .map_err(Into::into)
    }
    pub async fn directory_capabilities(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        windows: bool,
        apple: bool,
    ) -> std::result::Result<Vec<crate::queries::records::Capability>, crate::queries::QueryError>
    {
        self.directory_device_snapshot(proof, device, windows, apple, |_| {
            Box::pin(async { Ok(()) })
        })
        .await
        .map(|(_, capabilities)| capabilities)
    }
    async fn directory_capabilities_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        current: &crate::authorization::Snapshot,
        device: &str,
        windows: bool,
        apple: bool,
    ) -> crate::Result<Vec<crate::queries::records::Capability>> {
        use rss_mdm_registration_service::device::endpoints;
        let tenant = self.tenant.to_string();
        let agent =
            endpoints::current_in(c, &tenant, device, rss_mdm_inventory::Channel::Agent).await?;
        let mdm = endpoints::current_in(c, &tenant, device, rss_mdm_inventory::Channel::Mdm)
            .await?
            .is_some();
        let binding = if let Some(registration) = &agent {
            self.agent_store
                .binding(c, tenant, registration.registration_id)
                .await
                .map_err(Error::from)?
        } else {
            None
        };
        let supported = agent_support(self.signed, self.content_available);
        let result = [
            capability(
                current,
                proof,
                device,
                ("script", Permission::ScriptExecute, "agent", supported),
                agent_prerequisite(
                    agent.is_some(),
                    binding.as_ref().map(channels::AgentBinding::script),
                ),
            ),
            capability(
                current,
                proof,
                device,
                ("software", Permission::SoftwareDeploy, "agent", supported),
                agent_prerequisite(
                    agent.is_some(),
                    binding.as_ref().map(channels::AgentBinding::software),
                ),
            ),
            capability(
                current,
                proof,
                device,
                (
                    "configuration",
                    Permission::ConfigurationWrite,
                    "mdm",
                    windows || apple,
                ),
                if mdm {
                    ("unknown", Some("capability_unknown"))
                } else {
                    ("blocked", Some("not_registered"))
                },
            ),
        ];
        crate::queries::records::decode(json!(result))
    }
}

fn agent_prerequisite(
    registered: bool,
    reported: Option<bool>,
) -> (&'static str, Option<&'static str>) {
    match (registered, reported) {
        (false, _) => ("blocked", Some("not_registered")),
        (true, None) => ("unknown", Some("capability_unknown")),
        (true, Some(false)) => ("unsupported", Some("capability_not_supported")),
        (true, Some(true)) => ("ready", None),
    }
}
fn capability(
    current: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    device: &str,
    spec: (&str, Permission, &str, bool),
    prerequisite: (&str, Option<&str>),
) -> Value {
    let (action, permission, channel, supported) = spec;
    let allowed = current.require(proof, permission, Some(device)).is_ok();
    json!({"action":action,"channel":channel,
        "productSupport":{"state":if supported{"supported"}else{"unsupported"},"reason":if supported{None}else{Some("product_not_configured")}},
        "devicePrerequisite":{"state":prerequisite.0,"reason":prerequisite.1},
        "permission":{"allowed":allowed,"reason":if allowed{None}else{Some("permission_denied")}}})
}

fn agent_support(signed: bool, content: bool) -> bool {
    signed && content
}

#[cfg(test)]
mod tests {
    #[test]
    fn agent_execution_requires_signing_and_content() {
        for (signed, content, expected) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            assert_eq!(super::agent_support(signed, content), expected);
        }
    }
}
