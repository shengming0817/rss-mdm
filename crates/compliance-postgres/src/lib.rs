//! Compliance persistence. Every operation borrows the host tenant transaction.
//! No worker, transaction settlement or audit producer lives here.
pub mod directory;
use rss_mdm_compliance::{Assessment, Definition};
use rss_request_context::TenantId;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
/// Immutable installation unit.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");
type Result<T> = std::result::Result<T, sqlx::Error>;
fn corrupt() -> sqlx::Error {
    sqlx::Error::Protocol("compliance storage invariant".into())
}
/// Check the caller's transaction binding, including when no row exists.
pub async fn tenant(c: &mut PgConnection, t: TenantId) -> Result<()> {
    let actual: Option<String> = sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)")
        .fetch_one(c)
        .await?;
    if actual.as_deref() != Some(t.to_string().as_str()) {
        return Err(corrupt());
    }
    Ok(())
}
/// Current rule identity and immutable definition.
#[derive(Clone, Debug)]
pub struct Rule<C> {
    pub id: Uuid,
    pub revision: i64,
    pub enabled: bool,
    pub desired: Option<Uuid>,
    pub current_run: Option<Uuid>,
    pub definition: Definition<C>,
}
fn decode<C: DeserializeOwned>(r: sqlx::postgres::PgRow) -> Result<Rule<C>> {
    let uuid = |key| -> Result<Option<Uuid>> {
        r.try_get::<Option<String>, _>(key)?
            .map(|s| Uuid::parse_str(&s).map_err(|_| corrupt()))
            .transpose()
    };
    let row: Rule<C> = Rule {
        id: uuid("id")?.ok_or_else(corrupt)?,
        revision: r.try_get("revision")?,
        enabled: r.try_get("enabled")?,
        desired: uuid("desired")?,
        current_run: uuid("current_run")?,
        definition: serde_json::from_str(r.try_get("definition")?).map_err(|_| corrupt())?,
    };
    row.definition.validate().map_err(|_| corrupt())?;
    if row.enabled != row.definition.enabled {
        return Err(corrupt());
    }
    Ok(row)
}
/// Read a bounded rule page in identifier order.
pub async fn rules<C: DeserializeOwned>(
    c: &mut PgConnection,
    t: TenantId,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<Rule<C>>> {
    tenant(c, t).await?;
    if !(1..=101).contains(&limit) {
        return Err(corrupt());
    }
    sqlx::query("SELECT r.id::text,r.revision,r.enabled,r.desired::text,r.current_run::text,v.definition::text FROM mdm_compliance.rules r JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision) WHERE r.tenant_id=$1::uuid AND NOT r.deleted AND ($2::uuid IS NULL OR r.id>$2::uuid) ORDER BY r.id LIMIT $3")
 .bind(t.to_string()).bind(after.map(|v|v.to_string())).bind(limit as i64).fetch_all(c).await?.into_iter().map(decode::<C>).collect()
}
/// Read a rule, optionally serializing changes to its current pointer.
pub async fn rule<C: DeserializeOwned>(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
) -> Result<Option<Rule<C>>> {
    tenant(c, t).await?;
    sqlx::query("SELECT r.id::text,r.revision,r.enabled,r.desired::text,r.current_run::text,v.definition::text FROM mdm_compliance.rules r JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision) WHERE r.tenant_id=$1::uuid AND NOT r.deleted AND r.id=$2::uuid")
 .bind(t.to_string()).bind(id.to_string()).fetch_optional(c).await?.map(decode::<C>).transpose()
}
/// Read retained current pointer only for settling already-admitted jobs.
pub async fn retained_rule<C: DeserializeOwned>(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
) -> Result<Option<Rule<C>>> {
    tenant(c, t).await?;
    sqlx::query("SELECT r.id::text,r.revision,r.enabled,r.desired::text,r.current_run::text,v.definition::text FROM mdm_compliance.rules r JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid")
 .bind(t.to_string()).bind(id.to_string()).fetch_optional(c).await?.map(decode::<C>).transpose()
}
/// Write one immutable version and replace only the current dependency indexes.
/// The caller holds its product transaction lock and checks expected revision.
/// Returns false, without writes, when the complete definition exceeds the storage budget.
pub async fn put<C: Serialize>(
    c: &mut PgConnection,
    t: TenantId,
    r: &Rule<C>,
    fields: &[String],
    groups: &[Uuid],
) -> Result<bool> {
    tenant(c, t).await?;
    if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM mdm_compliance.rules WHERE tenant_id=$1::uuid AND id=$2::uuid AND deleted)").bind(t.to_string()).bind(r.id.to_string()).fetch_one(&mut *c).await? {return Ok(false);}
    r.definition.validate().map_err(|_| corrupt())?;
    if r.enabled != r.definition.enabled {
        return Err(corrupt());
    }
    let document = serde_json::to_string(&r.definition).map_err(|_| corrupt())?;
    let fits: bool = sqlx::query_scalar("SELECT octet_length(($1::jsonb)::text)<=65536")
        .bind(&document)
        .fetch_one(&mut *c)
        .await?;
    if document.len() > 65536 || !fits {
        return Ok(false);
    }
    sqlx::query("INSERT INTO mdm_compliance.rules(tenant_id,id,revision,enabled) VALUES($1::uuid,$2::uuid,$3,$4) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,desired=NULL")
 .bind(t.to_string()).bind(r.id.to_string()).bind(r.revision).bind(r.enabled).execute(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_compliance.versions VALUES($1::uuid,$2::uuid,$3,$4::jsonb)")
        .bind(t.to_string())
        .bind(r.id.to_string())
        .bind(r.revision)
        .bind(&document)
        .execute(&mut *c)
        .await?;
    for statement in [
        "DELETE FROM mdm_compliance.fields WHERE tenant_id=$1::uuid AND rule_id=$2::uuid",
        "DELETE FROM mdm_compliance.groups WHERE tenant_id=$1::uuid AND rule_id=$2::uuid",
    ] {
        sqlx::query(statement)
            .bind(t.to_string())
            .bind(r.id.to_string())
            .execute(&mut *c)
            .await?;
    }
    for field in fields {
        sqlx::query("INSERT INTO mdm_compliance.fields VALUES($1::uuid,$2::uuid,$3)")
            .bind(t.to_string())
            .bind(r.id.to_string())
            .bind(field)
            .execute(&mut *c)
            .await?;
    }
    for group in groups {
        sqlx::query("INSERT INTO mdm_compliance.groups VALUES($1::uuid,$2::uuid,$3::uuid)")
            .bind(t.to_string())
            .bind(r.id.to_string())
            .bind(group.to_string())
            .execute(&mut *c)
            .await?;
    }
    Ok(true)
}
/// Bind the only publishable task to a rule revision.
pub async fn desired(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    revision: i64,
    task: Uuid,
) -> Result<bool> {
    tenant(c, t).await?;
    Ok(sqlx::query("UPDATE mdm_compliance.rules SET desired=$4::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid AND revision=$3 AND enabled")
 .bind(t.to_string()).bind(id.to_string()).bind(revision).bind(task.to_string()).execute(c).await?.rows_affected()==1)
}
/// Publish a complete task only when it is still desired.
pub async fn publish(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    revision: i64,
    task: Uuid,
) -> Result<bool> {
    tenant(c, t).await?;
    Ok(sqlx::query("UPDATE mdm_compliance.rules SET current_run=$4::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid AND revision=$3 AND desired=$4::uuid AND enabled")
 .bind(t.to_string()).bind(id.to_string()).bind(revision).bind(task.to_string()).execute(c).await?.rows_affected()==1)
}
/// Append immutable per-device evidence. Host job progress is committed atomically.
pub async fn result(
    c: &mut PgConnection,
    t: TenantId,
    task: Uuid,
    device: &str,
    document: &Assessment,
) -> Result<()> {
    tenant(c, t).await?;
    document.validate().map_err(|_| corrupt())?;
    sqlx::query(
        "INSERT INTO mdm_compliance.results(tenant_id,task,rule_id,rule_revision,device,evaluated_at,document) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7::jsonb)",
    )
    .bind(t.to_string())
    .bind(task.to_string())
    .bind(document.rule_id.to_string())
    .bind(document.rule_version)
    .bind(device)
    .bind(document.evaluated_at)
    .bind(serde_json::to_string(document).map_err(|_| corrupt())?)
    .execute(c)
    .await?;
    Ok(())
}
/// Read one result from a specific immutable run.
pub async fn result_at(
    c: &mut PgConnection,
    t: TenantId,
    task: Uuid,
    device: &str,
) -> Result<Option<Assessment>> {
    tenant(c, t).await?;
    let raw:Option<String>=sqlx::query_scalar("SELECT document::text FROM mdm_compliance.results WHERE tenant_id=$1::uuid AND task=$2::uuid AND device=$3").bind(t.to_string()).bind(task.to_string()).bind(device).fetch_optional(c).await?;
    raw.map(|s| {
        let value: Assessment = serde_json::from_str(&s).map_err(|_| corrupt())?;
        value.validate().map_err(|_| corrupt())?;
        Ok(value)
    })
    .transpose()
}
/// Exact operation receipt; a different fingerprint is rejected by the host.
pub async fn replay(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
) -> Result<Option<(Vec<u8>, Value)>> {
    tenant(c, t).await?;
    sqlx::query("SELECT fingerprint,response::text FROM mdm_compliance.operations WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(t.to_string()).bind(id.to_string()).fetch_optional(c).await?.map(|r|Ok((r.try_get("fingerprint")?,serde_json::from_str(r.try_get("response")?).map_err(|_|corrupt())?))).transpose()
}
/// Append a receipt in the same transaction as the business change.
pub async fn receipt(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    fingerprint: &[u8],
    response: &Value,
) -> Result<()> {
    tenant(c, t).await?;
    sqlx::query("INSERT INTO mdm_compliance.operations VALUES($1::uuid,$2::uuid,$3,$4::jsonb)")
        .bind(t.to_string())
        .bind(id.to_string())
        .bind(fingerprint)
        .bind(response.to_string())
        .execute(c)
        .await?;
    Ok(())
}
/// Every retained current rule prevents deletion, including disabled rules.
pub async fn group_used(c: &mut PgConnection, t: TenantId, id: Uuid) -> Result<bool> {
    tenant(c, t).await?;
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_compliance.groups g JOIN mdm_compliance.rules r ON (r.tenant_id,r.id)=(g.tenant_id,g.rule_id) WHERE g.tenant_id=$1::uuid AND g.group_id=$2::uuid )").bind(t.to_string()).bind(id.to_string()).fetch_one(c).await
}

/// Verify the required runtime authority before using the adapter.
pub async fn admit(c: &mut PgConnection, t: TenantId) -> Result<()> {
    tenant(c, t).await?;
    let valid: bool = sqlx::query_scalar(include_str!("admission.sql"))
        .fetch_one(&mut *c)
        .await?;
    if !valid {
        return Err(corrupt());
    }
    Ok(())
}

/// Read an immutable definition for interpreting a historical assessment.
pub async fn version<C: DeserializeOwned>(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    revision: i64,
) -> Result<Option<Definition<C>>> {
    tenant(c, t).await?;
    let value:Option<String>=sqlx::query_scalar("SELECT definition::text FROM mdm_compliance.versions WHERE tenant_id=$1::uuid AND rule_id=$2::uuid AND revision=$3").bind(t.to_string()).bind(id.to_string()).bind(revision).fetch_optional(c).await?;
    value
        .map(|v| serde_json::from_str(&v).map_err(|_| corrupt()))
        .transpose()
}

/// Invalidate current demand in the same transaction that changes a group.
pub async fn invalidate_group(c: &mut PgConnection, t: TenantId, group: Uuid) -> Result<u64> {
    tenant(c, t).await?;
    sqlx::query("UPDATE mdm_compliance.rules r SET desired=NULL WHERE r.tenant_id=$1::uuid AND r.enabled AND EXISTS(SELECT 1 FROM mdm_compliance.groups g WHERE (g.tenant_id,g.rule_id)=(r.tenant_id,r.id) AND g.group_id=$2::uuid)").bind(t.to_string()).bind(group.to_string()).execute(c).await.map(|r|r.rows_affected())
}
/// One bounded invalidation; its replacement task is the durable acknowledgement.
pub async fn next_invalidated(c: &mut PgConnection, t: TenantId) -> Result<Option<Uuid>> {
    tenant(c, t).await?;
    let value:Option<String>=sqlx::query_scalar("SELECT id::text FROM mdm_compliance.rules WHERE tenant_id=$1::uuid AND enabled AND desired IS NULL ORDER BY id LIMIT 1").bind(t.to_string()).fetch_optional(c).await?;
    value
        .map(|s| Uuid::parse_str(&s).map_err(|_| corrupt()))
        .transpose()
}

/// Number of durably assessed devices in a run; independent of worker restarts.
pub async fn result_count(c: &mut PgConnection, t: TenantId, task: Uuid) -> Result<i64> {
    tenant(c, t).await?;
    sqlx::query_scalar(
        "SELECT count(*) FROM mdm_compliance.results WHERE tenant_id=$1::uuid AND task=$2::uuid",
    )
    .bind(t.to_string())
    .bind(task.to_string())
    .fetch_one(c)
    .await
}

/// Count current compliance definitions referring to a registered asset field.
pub async fn field_references_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    field: &str,
) -> Result<i64> {
    crate::tenant(c, tenant).await?;
    sqlx::query_scalar(
        "SELECT count(*) FROM mdm_compliance.fields WHERE tenant_id=$1::uuid AND field=$2",
    )
    .bind(tenant.to_string())
    .bind(field)
    .fetch_one(c)
    .await
}

/// Compare immutable published assessments; preparation is not visible as a public change.
pub async fn webhook_changes(
    c: &mut PgConnection,
    t: TenantId,
    run: Uuid,
    previous: Option<Uuid>,
    after: Option<String>,
    limit: i64,
) -> Result<Vec<(String, Assessment)>> {
    tenant(c, t).await?;
    if !(1..=33).contains(&limit) {
        return Err(corrupt());
    }
    let rows=sqlx::query("SELECT n.device,n.document::text FROM mdm_compliance.results n LEFT JOIN mdm_compliance.results o ON o.tenant_id=n.tenant_id AND o.task=$3::uuid AND o.device=n.device WHERE n.tenant_id=$1::uuid AND n.task=$2 AND ($4::text IS NULL OR n.device COLLATE \"C\">$4 COLLATE \"C\") AND (o.document->>'status' IS DISTINCT FROM n.document->>'status' OR o.document->>'reason' IS DISTINCT FROM n.document->>'reason') ORDER BY n.device COLLATE \"C\" LIMIT $5")
        .bind(t.to_string()).bind(run).bind(previous).bind(after).bind(limit).fetch_all(c).await?;
    rows.into_iter()
        .map(|r| {
            let a: Assessment =
                serde_json::from_str(r.try_get("document")?).map_err(|_| corrupt())?;
            a.validate().map_err(|_| corrupt())?;
            Ok((r.try_get("device")?, a))
        })
        .collect()
}

/// Terminal removal of the current rule; immutable versions/results remain readable.
pub async fn delete(c: &mut PgConnection, t: TenantId, id: Uuid) -> Result<()> {
    tenant(c, t).await?;
    sqlx::query("UPDATE mdm_compliance.rules SET deleted=true,enabled=false,desired=NULL,current_run=NULL WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(t.to_string()).bind(id.to_string()).execute(&mut *c).await?;
    for statement in [
        "DELETE FROM mdm_compliance.fields WHERE tenant_id=$1::uuid AND rule_id=$2::uuid",
        "DELETE FROM mdm_compliance.groups WHERE tenant_id=$1::uuid AND rule_id=$2::uuid",
    ] {
        sqlx::query(statement)
            .bind(t.to_string())
            .bind(id.to_string())
            .execute(&mut *c)
            .await?;
    }
    Ok(())
}

/// Current Compliance rule reference facts for a tenant-bound composable read ($1 is the tenant).
pub const GROUP_REFERENCE_FACTS_SQL: &str = r#"
SELECT r.tenant_id,r.id,r.revision,r.enabled,
 ARRAY(SELECT e.group_id FROM mdm_compliance.groups e WHERE(e.tenant_id,e.rule_id)=(r.tenant_id,r.id) ORDER BY e.group_id) AS group_ids
FROM mdm_compliance.rules r WHERE r.tenant_id=$1::uuid
"#;
