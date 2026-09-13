//! App-owned source coordinates and call facts; publication outcomes stay in ReleaseStore.
use super::{
    Error, InTransaction, Result,
    config::{Driver, Sources},
    spec::Submission,
};
use rss_contract::Timepoint;
use rss_mdm_software_release as rel;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::Row;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Subject {
    pub format: u8,
    pub resource: String,
    pub version: String,
    pub resource_digest: [u8; 32],
    pub expected_resource_revision: u64,
    pub coordinate: String,
    pub submission: Submission,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub format: u8,
    pub candidate: String,
    pub publication: [u8; 32],
    pub attempt: u64,
    pub ring: u8,
    pub binding: Vec<u8>,
    pub coordinate: String,
    pub slot: String,
    pub base: Option<String>,
    pub commit: Option<String>,
    pub at: i64,
    pub commit_at: i64,
}
impl Target {
    pub fn publication_id(&self) -> rel::PublicationId {
        rel::PublicationId::from_digest(rel::Digest::from_bytes(self.publication))
    }
    pub fn key(&self) -> String {
        format!("p:{}:{}", super::hex(&self.publication), self.attempt)
    }
    pub fn withdrawal_key(&self) -> String {
        format!("w:{}:{}", super::hex(&self.publication), self.attempt)
    }
    pub fn ring(&self) -> Result<rel::Ring> {
        match self.ring {
            0 => Ok(rel::Ring::Test),
            1 => Ok(rel::Ring::Pilot),
            2 => Ok(rel::Ring::Production),
            _ => Err(Error::Input),
        }
    }
}
pub(super) struct Call {
    pub target: Target,
    pub attempted: bool,
    pub acknowledged: bool,
    pub complete: bool,
    pub prepared: bool,
}
pub(super) struct Slot {
    pub operation: Option<String>,
    pub cursor: Option<String>,
}
#[derive(Clone, Copy)]
pub(super) enum Table {
    Publish,
    Withdraw,
}

pub(super) fn fault() -> PgError {
    sqlx::Error::Protocol("software composition invariant".into()).into()
}
pub(super) fn required<T>(
    r: std::result::Result<T, impl std::fmt::Debug>,
) -> std::result::Result<T, PgError> {
    r.map_err(|_| fault())
}
pub(super) fn encode(v: &impl Serialize) -> std::result::Result<Vec<u8>, PgError> {
    let bytes = required(serde_json::to_vec(v))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(fault());
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(b: &[u8], digest: &[u8]) -> std::result::Result<T, PgError> {
    if b.len() > 8 * 1024 * 1024 || Sha256::digest(b).as_slice() != digest {
        return Err(fault());
    }
    required(serde_json::from_slice(b))
}
pub(super) async fn lock(
    tx: &mut PgTransaction<'_>,
    kind: &str,
    id: &str,
) -> std::result::Result<(), PgError> {
    let key = format!("mdm-software:{}:{kind}:{id}", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2389))")
                .bind(key)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
pub(super) async fn audit(
    tx: &mut PgTransaction<'_>,
    actor: &rel::ActorId,
    target: &str,
    action: &'static str,
) -> std::result::Result<(), PgError> {
    if actor.tenant() != tx.tenant_id() {
        return Err(fault());
    }
    let audit = crate::audit::Audit::new(tx.tenant_id().to_string(), action);
    audit.identify_service(actor.value());
    audit.target(target);
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result =
                crate::access_store::append_on_connection(c, &audit, 200, "success", None).await;
            audit.finalize(None);
            result.map_err(|_| sqlx::Error::Protocol("software audit unavailable".into()))
        })
    })
    .await
}
pub(super) async fn register(
    tx: &mut PgTransaction<'_>,
    sources: &Sources,
    heads: &[Option<String>; 3],
    actor: &rel::ActorId,
) -> InTransaction<()> {
    verify(tx).await?;
    for (i, b) in sources.bindings.iter().enumerate() {
        let tenant = tx.tenant_id().to_string();
        let identity = b.identity.clone();
        let configuration = b.configuration.clone();
        let created=tx.with_connection(move|c|Box::pin(async move{
 let created=sqlx::query("INSERT INTO mdm_software_composition.bindings(tenant_id,identity,configuration) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING").bind(&tenant).bind(&identity).bind(&configuration).execute(&mut *c).await?.rows_affected();
 let old:Vec<u8>=sqlx::query_scalar("SELECT configuration FROM mdm_software_composition.bindings WHERE tenant_id=$1::uuid AND identity=$2").bind(tenant).bind(identity).fetch_one(c).await?;if old!=configuration{return Err(sqlx::Error::Protocol("source binding conflict".into()));}Ok(created==1)})).await?;
        if matches!(b.driver, Driver::Brew { .. }) {
            let t = tx.tenant_id().to_string();
            let binding = b.identity.clone();
            let head = heads[i].clone();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_software_composition.slots(tenant_id,binding,coordinate,cursor) VALUES($1::uuid,$2,'tap',$3) ON CONFLICT DO NOTHING").bind(t).bind(binding).bind(head).execute(c).await?;Ok(())})).await?;
        }
        if created {
            audit(tx, actor, &sources.logical, "software_binding").await?;
        }
    }
    Ok(Ok(()))
}
pub(super) async fn subject(
    tx: &mut PgTransaction<'_>,
    candidate: &str,
) -> std::result::Result<Option<Subject>, PgError> {
    let (t, id) = (tx.tenant_id().to_string(), candidate.to_owned());
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT resource,version,document,digest FROM mdm_software_composition.subjects WHERE tenant_id=$1::uuid AND candidate=$2").bind(t).bind(id).fetch_optional(c).await})).await?;
    row.map(|r| {
        let s: Subject = decode(
            r.try_get::<&[u8], _>("document")?,
            r.try_get::<&[u8], _>("digest")?,
        )?;
        if s.format != 1
            || s.resource != r.try_get::<String, _>("resource")?
            || s.version != r.try_get::<String, _>("version")?
        {
            return Err(fault());
        }
        Ok(s)
    })
    .transpose()
}
pub(super) async fn insert_subject(
    tx: &mut PgTransaction<'_>,
    candidate: &str,
    s: &Subject,
) -> std::result::Result<(), PgError> {
    let (t, id, resource, version, bytes) = (
        tx.tenant_id().to_string(),
        candidate.to_owned(),
        s.resource.clone(),
        s.version.clone(),
        encode(s)?,
    );
    let hash = Sha256::digest(&bytes).to_vec();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_software_composition.subjects(tenant_id,candidate,resource,version,document,digest) VALUES($1::uuid,$2,$3,$4,$5,$6)").bind(t).bind(id).bind(resource).bind(version).bind(bytes).bind(hash).execute(c).await?;Ok(())})).await
}
pub(super) fn software_key(c: &rel::Content) -> std::result::Result<Vec<u8>, PgError> {
    let s = c.software().fields();
    Ok(Sha256::digest(encode(&serde_json::json!([
        s.source, s.package, s.version, s.platform
    ]))?)
    .to_vec())
}
pub(super) async fn authority(
    tx: &mut PgTransaction<'_>,
    key: &[u8],
) -> std::result::Result<Option<(String, Vec<u8>)>, PgError> {
    let (t, k) = (tx.tenant_id().to_string(), key.to_vec());
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT candidate,material FROM mdm_software_composition.authorities WHERE tenant_id=$1::uuid AND software=$2 FOR UPDATE").bind(t).bind(k).fetch_optional(c).await})).await?;
    row.map(|r| Ok((r.try_get("candidate")?, r.try_get("material")?)))
        .transpose()
}
pub(super) async fn set_authority(
    tx: &mut PgTransaction<'_>,
    key: Vec<u8>,
    material: Vec<u8>,
    candidate: &str,
) -> std::result::Result<(), PgError> {
    let (t, id) = (tx.tenant_id().to_string(), candidate.to_owned());
    let n=tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_software_composition.authorities(tenant_id,software,material,candidate) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,software) DO UPDATE SET candidate=EXCLUDED.candidate WHERE mdm_software_composition.authorities.material=EXCLUDED.material").bind(t).bind(key).bind(material).bind(id).execute(c).await.map(|r|r.rows_affected())})).await?;
    if n != 1 {
        return Err(fault());
    }
    Ok(())
}
pub(super) async fn slot(
    tx: &mut PgTransaction<'_>,
    binding: &[u8],
    coordinate: &str,
) -> std::result::Result<Slot, PgError> {
    let (t, b, c) = (
        tx.tenant_id().to_string(),
        binding.to_vec(),
        coordinate.to_owned(),
    );
    let row=tx.with_connection(move|conn|Box::pin(async move{sqlx::query("SELECT operation,cursor FROM mdm_software_composition.slots WHERE tenant_id=$1::uuid AND binding=$2 AND coordinate=$3").bind(t).bind(b).bind(c).fetch_optional(conn).await})).await?;
    row.map(|r| {
        Ok(Slot {
            operation: r.try_get("operation")?,
            cursor: r.try_get("cursor")?,
        })
    })
    .unwrap_or(Ok(Slot {
        operation: None,
        cursor: None,
    }))
}
pub(super) async fn reserve(
    tx: &mut PgTransaction<'_>,
    t: &Target,
    operation: &str,
) -> std::result::Result<(), PgError> {
    let (tenant, b, coord, base, op) = (
        tx.tenant_id().to_string(),
        t.binding.clone(),
        t.slot.clone(),
        t.base.clone(),
        operation.to_owned(),
    );
    let n=tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_software_composition.slots(tenant_id,binding,coordinate,operation,cursor) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,binding,coordinate) DO UPDATE SET operation=EXCLUDED.operation WHERE mdm_software_composition.slots.operation IS NULL AND mdm_software_composition.slots.cursor IS NOT DISTINCT FROM EXCLUDED.cursor").bind(tenant).bind(b).bind(coord).bind(op).bind(base).execute(c).await.map(|r|r.rows_affected())})).await?;
    if n != 1 {
        return Err(fault());
    }
    Ok(())
}
pub(super) async fn release_slot(
    tx: &mut PgTransaction<'_>,
    t: &Target,
    op: &str,
    cursor: Option<String>,
) -> std::result::Result<(), PgError> {
    let (tenant, b, coord, op) = (
        tx.tenant_id().to_string(),
        t.binding.clone(),
        t.slot.clone(),
        op.to_owned(),
    );
    let n=tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_software_composition.slots SET operation=NULL,cursor=coalesce($5,cursor) WHERE tenant_id=$1::uuid AND binding=$2 AND coordinate=$3 AND operation=$4").bind(tenant).bind(b).bind(coord).bind(op).bind(cursor).execute(c).await.map(|r|r.rows_affected())})).await?;
    if n != 1 {
        return Err(fault());
    }
    Ok(())
}
pub(super) async fn call(
    tx: &mut PgTransaction<'_>,
    table: Table,
    id: &str,
) -> std::result::Result<Option<Call>, PgError> {
    let (t, id) = (tx.tenant_id().to_string(), id.to_owned());
    let q = match table {
        Table::Publish => {
            "SELECT document,digest,attempted,acknowledged,false AS complete,true AS prepared FROM mdm_software_composition.targets WHERE tenant_id=$1::uuid AND id=$2"
        }
        Table::Withdraw => {
            "SELECT coalesce(t.document,w.document) AS document,coalesce(t.digest,w.digest) AS digest,coalesce(t.attempted,false) AS attempted,coalesce(t.acknowledged,false) AS acknowledged,w.complete,t.id IS NOT NULL AS prepared FROM mdm_software_composition.withdrawals w LEFT JOIN mdm_software_composition.targets t ON t.tenant_id=w.tenant_id AND t.id=w.id WHERE w.tenant_id=$1::uuid AND w.id=$2"
        }
    };
    let row = tx
        .with_connection(move |c| {
            Box::pin(async move { sqlx::query(q).bind(t).bind(id).fetch_optional(c).await })
        })
        .await?;
    row.map(|r| {
        let target: Target = decode(
            r.try_get::<&[u8], _>("document")?,
            r.try_get::<&[u8], _>("digest")?,
        )?;
        if target.format != 1
            || target.attempt == 0
            || target.binding.len() != 32
            || target.ring > 2
        {
            return Err(fault());
        }
        Ok(Call {
            target,
            attempted: r.try_get("attempted")?,
            acknowledged: r.try_get("acknowledged")?,
            complete: r.try_get("complete")?,
            prepared: r.try_get("prepared")?,
        })
    })
    .transpose()
}
pub(super) async fn insert_call(
    tx: &mut PgTransaction<'_>,
    table: Table,
    t: &Target,
) -> std::result::Result<(), PgError> {
    let (tenant, id, candidate, bytes) = (
        tx.tenant_id().to_string(),
        if matches!(table, Table::Publish) {
            t.key()
        } else {
            t.withdrawal_key()
        },
        t.candidate.clone(),
        encode(t)?,
    );
    let hash = Sha256::digest(&bytes).to_vec();
    let q = match table {
        Table::Publish => {
            "INSERT INTO mdm_software_composition.targets(tenant_id,id,candidate,document,digest) VALUES($1::uuid,$2,$3,$4,$5)"
        }
        Table::Withdraw => {
            "INSERT INTO mdm_software_composition.withdrawals(tenant_id,id,candidate,document,digest) VALUES($1::uuid,$2,$3,$4,$5)"
        }
    };
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(q)
                .bind(tenant)
                .bind(id)
                .bind(candidate)
                .bind(bytes)
                .bind(hash)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
pub(super) async fn mark(
    tx: &mut PgTransaction<'_>,
    table: Table,
    id: &str,
    ack: bool,
    complete: bool,
) -> std::result::Result<(), PgError> {
    let (tenant, id) = (tx.tenant_id().to_string(), id.to_owned());
    let rows=tx.with_connection(move|c|Box::pin(async move {
  let rows=sqlx::query("UPDATE mdm_software_composition.targets SET attempted=true,acknowledged=acknowledged OR $3 WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(&id).bind(ack).execute(&mut *c).await?.rows_affected();
  if complete && matches!(table,Table::Withdraw) { sqlx::query("UPDATE mdm_software_composition.withdrawals SET complete=true WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).execute(c).await?; }
  Ok(rows)
 })).await?;
    if rows != 1 {
        return Err(fault());
    }
    Ok(())
}
pub(super) async fn projection(
    tx: &mut PgTransaction<'_>,
    t: &Target,
) -> std::result::Result<Option<Vec<u8>>, PgError> {
    let (tenant, b, c) = (
        tx.tenant_id().to_string(),
        t.binding.clone(),
        t.coordinate.clone(),
    );
    tx.with_connection(move|conn|Box::pin(async move{sqlx::query_scalar("SELECT publication FROM mdm_software_composition.projections WHERE tenant_id=$1::uuid AND binding=$2 AND coordinate=$3").bind(tenant).bind(b).bind(c).fetch_optional(conn).await})).await
}
pub(super) async fn project(
    tx: &mut PgTransaction<'_>,
    t: &Target,
    remove: bool,
) -> std::result::Result<(), PgError> {
    let (tenant, b, c, p) = (
        tx.tenant_id().to_string(),
        t.binding.clone(),
        t.coordinate.clone(),
        t.publication.to_vec(),
    );
    let q = if remove {
        "DELETE FROM mdm_software_composition.projections WHERE tenant_id=$1::uuid AND binding=$2 AND coordinate=$3 AND publication=$4"
    } else {
        "INSERT INTO mdm_software_composition.projections(tenant_id,binding,coordinate,publication) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,binding,coordinate) DO UPDATE SET publication=EXCLUDED.publication"
    };
    tx.with_connection(move |conn| {
        Box::pin(async move {
            sqlx::query(q)
                .bind(tenant)
                .bind(b)
                .bind(c)
                .bind(p)
                .execute(conn)
                .await?;
            Ok(())
        })
    })
    .await
}
pub(super) fn core_publication(c: &rel::Candidate, t: &Target) -> Result<rel::Publication> {
    let rel::RingState::Publication(p) = c.snapshot().ring_state(t.ring()?) else {
        return Err(Error::Conflict);
    };
    if p.id() != t.publication_id()
        || p.attempt != t.attempt
        || p.authorized_at.unix_seconds() != t.at
    {
        return Err(Error::Conflict);
    }
    Ok(p.clone())
}
pub(super) fn record_request(
    c: &rel::Candidate,
    t: &Target,
    actor: &rel::ActorId,
    result: rel::PublicationResult,
    at: Timepoint,
) -> Result<rel::Request> {
    Ok(rel::Request {
        id: rel::RequestId::new(actor.tenant(), uuid::Uuid::new_v4().simple().to_string())
            .map_err(|_| Error::Identity)?,
        actor: actor.clone(),
        expected_revision: c.snapshot().revision,
        as_of: at,
        operation: rel::Operation::Record {
            ring: t.ring()?,
            publication: t.publication_id(),
            attempt: t.attempt,
            outcome: result,
        },
    })
}
async fn verify(tx: &mut PgTransaction<'_>) -> std::result::Result<(), PgError> {
    let (ok, catalog) = tx
        .with_connection(|c| {
            Box::pin(async move {
                let ok = sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                    .fetch_one(&mut *c)
                    .await?;
                let catalog = sqlx::query_scalar::<_, String>(include_str!("catalog.sql"))
                    .fetch_one(c)
                    .await?;
                Ok((ok, catalog))
            })
        })
        .await?;
    let expected: serde_json::Value = required(serde_json::from_str(include_str!("catalog.json")))?;
    let actual: serde_json::Value = required(serde_json::from_str(&catalog))?;
    if !ok || actual != expected {
        return Err(fault());
    }
    Ok(())
}
pub(super) async fn prepare_withdrawal(
    tx: &mut PgTransaction<'_>,
    target: &Target,
) -> std::result::Result<(), PgError> {
    let (tenant, id, candidate, bytes) = (
        tx.tenant_id().to_string(),
        target.withdrawal_key(),
        target.candidate.clone(),
        encode(target)?,
    );
    let digest = Sha256::digest(&bytes).to_vec();
    let rows=tx.with_connection(move|c|Box::pin(async move {
 sqlx::query("INSERT INTO mdm_software_composition.targets(tenant_id,id,candidate,document,digest,withdrawal_id) SELECT $1::uuid,$2,$3,$4,$5,$2 WHERE EXISTS(SELECT 1 FROM mdm_software_composition.withdrawals WHERE tenant_id=$1::uuid AND id=$2 AND NOT complete)").bind(tenant).bind(id).bind(candidate).bind(bytes).bind(digest).execute(c).await.map(|r|r.rows_affected())
 })).await?;
    if rows != 1 {
        return Err(fault());
    }
    Ok(())
}
pub(super) async fn complete_noop(
    tx: &mut PgTransaction<'_>,
    id: &str,
) -> std::result::Result<(), PgError> {
    let (tenant, id) = (tx.tenant_id().to_string(), id.to_owned());
    let rows=tx.with_connection(move|c|Box::pin(async move {
 sqlx::query("UPDATE mdm_software_composition.withdrawals w SET complete=true WHERE tenant_id=$1::uuid AND id=$2 AND NOT EXISTS(SELECT 1 FROM mdm_software_composition.targets t WHERE t.tenant_id=w.tenant_id AND t.id=w.id AND t.attempted)").bind(tenant).bind(id).execute(c).await.map(|r|r.rows_affected())
 })).await?;
    if rows != 1 {
        return Err(fault());
    }
    Ok(())
}
