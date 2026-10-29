//! The original transition predicates, shared by diagnostics and the fenced write transaction.
use super::*;
use sqlx::{Postgres, QueryBuilder};

// No projection join may remove a blocking fact. Missing associations remain nullable.
const RELATIONS: &str = r#"
), rotation AS (
 SELECT r.*,p.now FROM mdm_pki.rotations r JOIN params p ON r.tenant_id=p.tenant AND r.id=p.id
), blockers AS (
 SELECT 'missing_ack'::text AS kind,r.id::text AS id,r.device,r.id AS registration,r.generation,
        r.state,NULL::bigint AS deadline,NULL::text AS revocation_state
 FROM rotation x JOIN mdm_access.registrations r ON r.tenant_id=x.tenant_id
 WHERE x.state='distributing' AND r.state='active'
 AND ((r.channel='agent' AND x.purpose='agent') OR (r.channel='mdm' AND EXISTS(
   SELECT 1 FROM mdm_access.requests q WHERE q.tenant_id=r.tenant_id AND q.id=r.request_id
   AND q.source=CASE x.purpose WHEN 'windows' THEN 'mdm.windows' WHEN 'apple' THEN 'mdm.apple' ELSE x.purpose END)))
 AND NOT EXISTS(SELECT 1 FROM mdm_pki.acknowledgements a WHERE a.tenant_id=r.tenant_id
   AND a.registration=r.id AND a.rotation=x.id AND a.revision>=x.revision)
 UNION ALL
 SELECT 'unresolved_signing',s.attempt::text,NULL,NULL,NULL,s.state,s.deadline,NULL
 FROM rotation x JOIN mdm_pki.signing s ON s.tenant_id=x.tenant_id AND s.purpose=x.purpose AND s.issuer=x.previous
 WHERE x.state='activated' AND (s.state IN ('signing','unknown') OR (s.state='prepared' AND s.deadline>x.now))
 UNION ALL
 SELECT 'unsettled_bootstrap',b.id::text,NULL,NULL,NULL,b.state,b.deadline,NULL
 FROM rotation x JOIN mdm_access.agent_bootstraps b ON b.tenant_id=x.tenant_id AND b.issuer=x.previous
 WHERE x.state='activated' AND x.purpose='agent_bootstrap'
 AND (b.state='signing' OR (b.state IN ('prepared','issued','consumed') AND b.deadline>x.now))
 UNION ALL
 SELECT 'unsettled_scep',s.id::text,NULL,s.registration,s.generation,s.state,
        floor(extract(epoch FROM s.expires_at))::bigint,NULL
 FROM rotation x JOIN mdm_apple.scep_attempts s ON s.tenant_id=x.tenant_id AND encode(s.issuer,'hex')=x.previous
 WHERE x.state='activated' AND x.purpose='apple'
 AND ((s.state='consumed' AND s.certificate IS NULL) OR (s.state='prepared' AND s.expires_at>clock_timestamp()))
 UNION ALL
 SELECT 'outstanding_certificate',encode(c.fingerprint,'hex'),r.device,c.registration,r.generation,
        'issued',c.not_after,v.state
 FROM rotation x JOIN mdm_pki.certificates c ON c.tenant_id=x.tenant_id AND c.purpose=x.purpose AND c.issuer=x.previous
 LEFT JOIN mdm_access.registrations r ON r.tenant_id=c.tenant_id AND r.id=c.registration
 LEFT JOIN mdm_pki.revocations v ON (v.tenant_id,v.purpose,v.issuer,v.serial)=(c.tenant_id,c.purpose,c.issuer,c.serial)
 WHERE x.state='activated' AND c.not_after>x.now AND (v.state IS NULL OR v.state<>'published')
)
"#;
fn sql(tenant: &str, id: Uuid, now: i64) -> QueryBuilder<Postgres> {
    let mut sql = QueryBuilder::new("WITH params AS (SELECT ");
    sql.push_bind(tenant.to_owned())
        .push("::uuid AS tenant,")
        .push_bind(id)
        .push("::uuid AS id,")
        .push_bind(now)
        .push("::bigint AS now")
        .push(RELATIONS);
    sql
}
pub(crate) async fn kinds(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    now: i64,
) -> Result<Vec<BlockerKind>, Error> {
    let values: Vec<String> = sql(tenant, id, now)
        .push("SELECT DISTINCT kind FROM blockers ORDER BY kind")
        .build_query_scalar()
        .fetch_all(c)
        .await
        .map_err(db)?;
    values
        .into_iter()
        .map(|v| serde_json::from_value(serde_json::Value::String(v)).map_err(|_| Error::Storage))
        .collect()
}
pub(crate) async fn require(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    state: RotationState,
    now: i64,
) -> Result<(), Error> {
    let actual: String = sqlx::query_scalar(
        "SELECT state FROM mdm_pki.rotations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if !matches!(
        (actual.as_str(), state),
        ("distributing", RotationState::Activated) | ("activated", RotationState::Retired)
    ) {
        return Err(Error::Conflict);
    }
    let blocked: bool = sql(tenant, id, now)
        .push("SELECT EXISTS(SELECT 1 FROM blockers)")
        .build_query_scalar()
        .fetch_one(c)
        .await
        .map_err(db)?;
    if blocked {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}
pub(super) async fn page(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    now: i64,
    q: &Query,
    codec: &CursorCodec,
    binding: &str,
) -> Result<Page<Projection<Blocker>>, Error> {
    let after = q.after(codec, binding).map_err(query_error)?;
    let mut sql = sql(tenant, id, now);
    sql.push("SELECT jsonb_build_object('kind',kind,'id',id,'device',device,'registration',registration,'generation',generation,'state',state,'deadline',deadline,'revocationState',revocation_state) FROM blockers WHERE true");
    rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(query_error)?;
    let rows: Vec<serde_json::Value> = sql.build_query_scalar().fetch_all(c).await.map_err(db)?;
    let rows = rows
        .into_iter()
        .map(serde_json::from_value::<Blocker>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Storage)?;
    q.page_typed(rows, codec, binding).map_err(query_error)
}
fn column(name: &str) -> &'static str {
    match name {
        "kind" => "kind COLLATE \"C\"",
        "id" => "id COLLATE \"C\"",
        _ => unreachable!("checked blocker field"),
    }
}
