use super::*;
use sqlx::Row;
pub(super) async fn lock(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("mdm-software:{tenant}"))
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub(super) async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}
pub(super) async fn source(
    tx: &mut PgTransaction<'_>,
    id: &str,
    revision: &str,
) -> Result<Option<(SourceDefinition, Admission)>> {
    let t = tx.tenant_id().to_string();
    let id = id.to_owned();
    let revision = revision.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT definition::text,admission::text FROM mdm_software.sources WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3").bind(t).bind(id).bind(revision).fetch_optional(c).await})).await?;
    row.map(|row| {
        Ok((
            decode(&row.try_get::<String, _>("definition")?)?,
            decode(&row.try_get::<String, _>("admission")?)?,
        ))
    })
    .transpose()
}
pub(super) async fn save_source(
    tx: &mut PgTransaction<'_>,
    source: &SourceDefinition,
    a: &Admission,
) -> Result<()> {
    let t = tx.tenant_id().to_string();
    let s = source.clone();
    let definition = encode(source)?;
    let admission = encode(a)?;
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_software.sources VALUES($1::uuid,$2,$3,$4::jsonb,$5::jsonb) ON CONFLICT(tenant_id,id,revision) DO UPDATE SET admission=excluded.admission").bind(t).bind(s.id).bind(s.revision).bind(definition).bind(admission).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub(super) async fn admission(
    tx: &mut PgTransaction<'_>,
    id: &str,
    version: &str,
) -> Result<Option<Admission>> {
    let t = tx.tenant_id().to_string();
    let id = id.to_owned();
    let v = version.to_owned();
    let row:Option<String>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT admission::text FROM mdm_software.approvals WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3").bind(t).bind(id).bind(v).fetch_optional(c).await})).await?;
    row.map(|v| decode(&v)).transpose()
}
pub(super) async fn save_admission(
    tx: &mut PgTransaction<'_>,
    id: &str,
    version: &str,
    a: &Admission,
) -> Result<()> {
    let t = tx.tenant_id().to_string();
    let id = id.to_owned();
    let v = version.to_owned();
    let value = encode(a)?;
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_software.approvals VALUES($1::uuid,$2,$3,$4::jsonb) ON CONFLICT(tenant_id,resource,version) DO UPDATE SET admission=excluded.admission").bind(t).bind(id).bind(v).bind(value).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub(super) async fn replay(
    tx: &mut PgTransaction<'_>,
    id: uuid::Uuid,
    hash: &[u8],
) -> Result<Option<Value>> {
    let t = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT fingerprint,response::text FROM mdm_software.operations WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(t).bind(id.to_string()).fetch_optional(c).await})).await?;
    row.map(|r| {
        if r.try_get::<Vec<u8>, _>("fingerprint")? != hash {
            return Err(Error::Conflict);
        }
        decode(&r.try_get::<String, _>("response")?)
    })
    .transpose()
}
pub(super) async fn receipt(
    tx: &mut PgTransaction<'_>,
    id: uuid::Uuid,
    hash: &[u8],
    value: &Value,
) -> Result<()> {
    let t = tx.tenant_id().to_string();
    let hash = hash.to_vec();
    let value = value.to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_software.operations VALUES($1::uuid,$2::uuid,$3,$4::jsonb)",
            )
            .bind(t)
            .bind(id.to_string())
            .bind(hash)
            .bind(value)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub(super) async fn freeze_materials(
    tx: &mut PgTransaction<'_>,
    version: &r::Version,
) -> Result<()> {
    for variant in version.variants() {
        let r::Declaration::Software { definition } = variant.declaration() else {
            return Err(Error::Input);
        };
        let spec = definition.spec();
        let key = super::fingerprint(&(
            &spec.source.id,
            &spec.package,
            &spec.version,
            variant.platform(),
            variant.architecture(),
            variant.key().as_str(),
        ))?;
        let digest = Sha256::digest(definition.canonical()).to_vec();
        let expected = digest.clone();
        let tenant = tx.tenant_id().to_string();
        let old:Vec<u8>=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query("INSERT INTO mdm_software.materials VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING").bind(&tenant).bind(&key).bind(digest).execute(&mut *c).await?;
            sqlx::query_scalar("SELECT digest FROM mdm_software.materials WHERE tenant_id=$1::uuid AND coordinate=$2").bind(tenant).bind(key).fetch_one(c).await
        })).await?;
        if old != expected {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|_| Error::Integrity)
}
fn encode(value: &impl serde::Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::Input)
}
