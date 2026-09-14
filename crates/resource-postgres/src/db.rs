use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::Row;
pub(crate) const MAX_DOCUMENT: usize = 64 * 1024 * 1024;
pub(crate) fn fault(stage: &'static str) -> PgError {
    tracing::error!(stage, reason = "storage-invariant", "adapter data rejected");
    sqlx::Error::Protocol("mdm_resource storage invariant".into()).into()
}
#[derive(Debug, thiserror::Error)]
#[error("resource {stage}: {cause}")]
struct Diagnostic {
    stage: &'static str,
    #[source]
    cause: SafeCause,
}
#[derive(Debug, thiserror::Error)]
#[error("{kind}: {reason}")]
struct SafeCause {
    kind: &'static str,
    reason: String,
}
pub(crate) fn data<T, E: 'static>(stage: &'static str, r: Result<T, E>) -> Result<T, PgError> {
    classify(stage, r).map_err(|diagnostic| {
        tracing::error!(stage = diagnostic.stage, kind = diagnostic.cause.kind,
            reason = %diagnostic.cause.reason, "adapter data rejected");
        sqlx::Error::Decode(Box::new(diagnostic)).into()
    })
}
fn classify<T, E: 'static>(stage: &'static str, r: Result<T, E>) -> Result<T, Diagnostic> {
    r.map_err(|e| {
        let value = &e as &dyn std::any::Any;
        let reason = if let Some(e) = value.downcast_ref::<serde_json::Error>() {
            format!("{:?} at {}:{}", e.classify(), e.line(), e.column())
        } else if let Some(e) = value.downcast_ref::<crate::core::Error>() {
            format!("{e:?}")
        } else if value.is::<std::num::TryFromIntError>() {
            "integer-out-of-range".into()
        } else {
            "invalid-value".into()
        };
        Diagnostic {
            stage,
            cause: SafeCause {
                kind: std::any::type_name::<E>(),
                reason,
            },
        }
    })
}
pub(crate) fn encode(v: &impl Serialize) -> Result<Vec<u8>, PgError> {
    let b = data("db::encode", serde_json::to_vec(v))?;
    if b.len() > MAX_DOCUMENT {
        return Err(fault("db::encode"));
    }
    Ok(b)
}
pub(crate) fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T, PgError> {
    if b.len() > MAX_DOCUMENT {
        return Err(fault("db::decode"));
    }
    data("db::decode", serde_json::from_slice(b))
}
pub(crate) fn digest(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}
pub(crate) fn checked(b: Vec<u8>, hash: Vec<u8>) -> Result<Vec<u8>, PgError> {
    if digest(&b) == hash {
        Ok(b)
    } else {
        Err(fault("db::checked"))
    }
}
pub(crate) async fn lock(tx: &mut PgTransaction<'_>, kind: &str, key: &str) -> Result<(), PgError> {
    let key = format!("mdm_resource:{}:{kind}:{key}", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2388))")
                .bind(key)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
pub(crate) async fn read(
    tx: &mut PgTransaction<'_>,
    id: &str,
) -> Result<Option<(u64, Vec<u8>)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT revision,document,digest FROM mdm_resource.aggregates WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await})).await?;
    row.map(|r| {
        Ok((
            data("db::read", u64::try_from(r.try_get::<i64, _>("revision")?))?,
            checked(r.try_get("document")?, r.try_get("digest")?)?,
        ))
    })
    .transpose()
}
pub(crate) async fn write(
    tx: &mut PgTransaction<'_>,
    id: &str,
    old: Option<u64>,
    revision: u64,
    document: Vec<u8>,
) -> Result<(), PgError> {
    let id = id.to_owned();
    let tenant = tx.tenant_id().to_string();
    let hash = digest(&document);
    let revision = data("db::write", i64::try_from(revision))?;
    let old = data("db::write-old-revision", old.map(i64::try_from).transpose())?;
    let rows=tx.with_connection(move|c|Box::pin(async move{
 let q=if old.is_some(){"UPDATE mdm_resource.aggregates SET revision=$3,document=$4,digest=$5 WHERE tenant_id=$1::uuid AND id=$2 AND revision=$6"}else{"INSERT INTO mdm_resource.aggregates(tenant_id,id,revision,document,digest) SELECT $1::uuid,$2,$3,$4,$5 WHERE $6::bigint IS NULL"};
 sqlx::query(q).bind(tenant).bind(id).bind(revision).bind(document).bind(hash).bind(old).execute(c).await.map(|r|r.rows_affected())})).await?;
    if rows != 1 {
        return Err(fault("db::write"));
    }
    Ok(())
}
pub(crate) async fn receipt(
    tx: &mut PgTransaction<'_>,
    id: &str,
) -> Result<Option<(String, Vec<u8>, Vec<u8>)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT owner,fingerprint,request,receipt,digest FROM mdm_resource.requests WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await})).await?;
    row.map(|r| {
        let hash: Vec<u8> = r.try_get("fingerprint")?;
        checked(r.try_get("request")?, hash.clone())?;
        Ok((
            r.try_get("owner")?,
            hash,
            checked(r.try_get("receipt")?, r.try_get("digest")?)?,
        ))
    })
    .transpose()
}
pub(crate) async fn save_receipt(
    tx: &mut PgTransaction<'_>,
    id: &str,
    owner: &str,
    fingerprint: Vec<u8>,
    request: Vec<u8>,
    receipt: Vec<u8>,
) -> Result<(), PgError> {
    let (tenant, id, owner, hash) = (
        tx.tenant_id().to_string(),
        id.to_owned(),
        owner.to_owned(),
        digest(&receipt),
    );
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_resource.requests(tenant_id,id,owner,fingerprint,request,receipt,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)").bind(tenant).bind(id).bind(owner).bind(fingerprint).bind(request).bind(receipt).bind(hash).execute(c).await?;Ok(())})).await
}
pub(crate) async fn immutable(
    tx: &mut PgTransaction<'_>,
    owner: &str,
    kind: &str,
    key: &str,
) -> Result<Option<Vec<u8>>, PgError> {
    let (tenant, owner, kind, key) = (
        tx.tenant_id().to_string(),
        owner.to_owned(),
        kind.to_owned(),
        key.to_owned(),
    );
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT document,digest FROM mdm_resource.immutable WHERE tenant_id=$1::uuid AND owner=$2 AND kind=$3 AND key=$4").bind(tenant).bind(owner).bind(kind).bind(key).fetch_optional(c).await})).await?;
    row.map(|r| checked(r.try_get("document")?, r.try_get("digest")?))
        .transpose()
}
pub(crate) async fn freeze(
    tx: &mut PgTransaction<'_>,
    owner: &str,
    kind: &str,
    key: &str,
    document: Vec<u8>,
) -> Result<(), PgError> {
    let (tenant, o, k, i, hash) = (
        tx.tenant_id().to_string(),
        owner.to_owned(),
        kind.to_owned(),
        key.to_owned(),
        digest(&document),
    );
    tx.with_connection(move|c|Box::pin(async move{
 sqlx::query("INSERT INTO mdm_resource.immutable(tenant_id,owner,kind,key,document,digest) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING").bind(&tenant).bind(&o).bind(&k).bind(&i).bind(&document).bind(&hash).execute(&mut *c).await?;
 let old:Vec<u8>=sqlx::query_scalar("SELECT document FROM mdm_resource.immutable WHERE tenant_id=$1::uuid AND owner=$2 AND kind=$3 AND key=$4").bind(tenant).bind(o).bind(k).bind(i).fetch_one(c).await?;
 if old!=document{return Err(sqlx::Error::Protocol("immutable identity conflict".into()));}Ok(())
 })).await
}
pub(crate) async fn verify(tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
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
    let actual: serde_json::Value = data("db::verify", serde_json::from_str(&catalog))?;
    let expected: serde_json::Value = data(
        "db::verify",
        serde_json::from_str(include_str!("catalog.json")),
    )?;
    if ok && actual == expected {
        Ok(())
    } else {
        Err(fault("db::verify"))
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn json_failures_preserve_stage_and_category_without_input() {
        let error = classify(
            "receipt-decode",
            serde_json::from_str::<u64>("\"secret-token\""),
        )
        .unwrap_err();
        let message = format!("{error:?} {error}");
        assert!(message.contains("receipt-decode"));
        assert!(message.contains("Data"));
        assert!(!message.contains("secret-token"));
        let other = classify("revision", u64::try_from(-1_i64)).unwrap_err();
        assert!(format!("{other}").contains("integer-out-of-range"));
    }
}
