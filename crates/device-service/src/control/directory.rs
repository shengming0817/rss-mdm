use super::*;
pub async fn run_summaries_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: Vec<Uuid>,
) -> crate::control::transaction::Result<
    std::collections::BTreeMap<Uuid, crate::control::queries::records::RunEvidence>,
> {
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
        sql.push(actions::history::RESULT_SUMMARY_SQL).push(") AS document FROM mdm_devices.unmanage_runs r WHERE r.tenant_id=").push_bind(tenant).push("::uuid AND r.id=ANY(").push_bind(ids).push(")),budget AS(SELECT coalesce(sum(octet_length(document::text)),0)::bigint AS bytes FROM selected) SELECT selected.*,budget.bytes FROM budget LEFT JOIN selected ON budget.bytes<=16777216");
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
        .map(|r| {
            Ok((
                r.try_get("id")?,
                crate::control::queries::records::decode(r.try_get("document")?)?,
            ))
        })
        .collect()
}

pub const RELATION_SQL: &str = "SELECT o.id, o.device, CAST('command' AS text) AS kind, o.source_kind, o.policy_version, v.policy, CAST(o.input_context ->> 'deadline' AS bigint) AS deadline, COALESCE(d.status, 'unknown') AS status, CAST(octet_length(o.request) + octet_length(CAST(o.authority AS text)) + octet_length(CAST(o.input_context AS text)) + COALESCE(octet_length(CAST(o.dispatch_failure AS text)), 0) + 1024 AS bigint) AS input_bytes FROM mdm_devices.control_operations AS o LEFT JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) LEFT JOIN mdm_policy.versions AS v ON (v.tenant_id, v.id) = (o.tenant_id, o.policy_version) WHERE o.tenant_id = CAST($1 AS uuid) UNION ALL SELECT r.id, r.device, 'action_run', r.source_kind, r.policy_version, v.policy, r.deadline, COALESCE(r.state ->> 'execution', 'unknown'), CAST(0 AS bigint) FROM mdm_devices.unmanage_runs AS r LEFT JOIN mdm_policy.versions AS v ON (v.tenant_id, v.id) = (r.tenant_id, r.policy_version) WHERE r.tenant_id = CAST($1 AS uuid)";
