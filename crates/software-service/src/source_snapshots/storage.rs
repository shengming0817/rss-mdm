use super::*;
use sqlx::Row;
use uuid::Uuid;
pub(super) const SNAPSHOT_COLUMNS: &str =
    "source,revision,document_sha256,entry_count,imported_at,extraction";
pub(super) fn snapshot_row(row: &sqlx::postgres::PgRow) -> transaction::Result<Snapshot> {
    Ok(Snapshot {
        source: row.try_get("source")?,
        revision: row.try_get("revision")?,
        document_sha256: row
            .try_get::<Vec<u8>, _>("document_sha256")?
            .try_into()
            .map_err(|_| invariant())?,
        entry_count: row.try_get("entry_count")?,
        imported_at: row.try_get("imported_at")?,
        extraction: serde_json::from_value(row.try_get("extraction")?).map_err(|_| invariant())?,
    })
}
pub(super) fn entry_row(row: &sqlx::postgres::PgRow) -> transaction::Result<Entry> {
    Ok(Entry {
        entry_id: row.try_get("id")?,
        source: row.try_get("source")?,
        revision: row.try_get("revision")?,
        package_id: row.try_get("package_id")?,
        name: row.try_get("name")?,
        version: row.try_get("version")?,
    })
}
pub(super) async fn lock(
    tx: &mut PgTransaction<'_>,
    source: &str,
    shared: bool,
) -> transaction::Result<()> {
    let key = format!("mdm-software-snapshot:{}:{source}", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(if shared {
                "SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))"
            } else {
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))"
            })
            .bind(key)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub(super) async fn current(
    tx: &mut PgTransaction<'_>,
    source: &str,
) -> transaction::Result<Snapshot> {
    let tenant = tx.tenant_id().to_string();
    let source = source.to_owned();
    let sql = "SELECT source,revision,document_sha256,entry_count,imported_at,extraction FROM mdm_software_snapshots.current WHERE tenant_id=$1::uuid AND source=$2";
    let row = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(sql)
                    .bind(tenant)
                    .bind(source)
                    .fetch_optional(c)
                    .await
            })
        })
        .await?
        .ok_or(Error::ResourceMissing)?;
    snapshot_row(&row)
}
pub(super) async fn receipt(
    tx: &mut PgTransaction<'_>,
    source: &str,
    operation: Uuid,
    actor: &str,
    fingerprint: Option<&[u8; 32]>,
) -> transaction::Result<Option<Receipt>> {
    let tenant = tx.tenant_id().to_string();
    let source = source.to_owned();
    let row = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT actor,fingerprint,response FROM mdm_software_snapshots.operations WHERE tenant_id=$1::uuid AND source=$2 AND id=$3")
            .bind(tenant).bind(source).bind(operation).fetch_optional(c).await
    })).await?;
    if let Some(row) = &row
        && row.try_get::<String, _>("actor")? != actor
    {
        return if fingerprint.is_some() {
            Err(Error::Conflict.into())
        } else {
            Ok(None)
        };
    }
    row.map(|row| {
        if fingerprint.is_some_and(|f| row.get::<Vec<u8>, _>("fingerprint") != f.as_slice()) {
            return Err(Error::Conflict.into());
        }
        serde_json::from_value(row.try_get("response")?).map_err(|_| invariant().into())
    })
    .transpose()
}
pub(super) async fn save(
    tx: &mut PgTransaction<'_>,
    source: &str,
    expected: i64,
    operation: Uuid,
    actor: &str,
    fingerprint: &[u8; 32],
    prepared: Prepared,
) -> transaction::Result<Receipt> {
    let tenant = tx.tenant_id().to_string();
    let source = source.to_owned();
    let revision = expected.checked_add(1).ok_or_else(invalid)?;
    let digest = prepared.digest;
    let extraction = serde_json::to_value(&prepared.extraction).map_err(|_| invalid())?;
    let count = prepared.entry_count;
    let document: Box<str> = prepared.document.into();
    let document = document.into_string();
    let entries = prepared.entries;
    let actor = actor.to_owned();
    let fingerprint = fingerprint.to_vec();
    let row = tx.with_connection(move |c| Box::pin(async move {
        let old: Option<i64> = sqlx::query_scalar("SELECT revision FROM mdm_software_snapshots.current WHERE tenant_id=$1::uuid AND source=$2")
            .bind(&tenant).bind(&source).fetch_optional(&mut *c).await?;
        if old.unwrap_or(0) != expected { return Ok(None); }
        let sql = "INSERT INTO mdm_software_snapshots.current(tenant_id,source,revision,document,document_sha256,extraction,entry_count,imported_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(tenant_id,source) DO UPDATE SET revision=excluded.revision,document=excluded.document,document_sha256=excluded.document_sha256,extraction=excluded.extraction,entry_count=excluded.entry_count,imported_at=excluded.imported_at RETURNING source,revision,document_sha256,entry_count,imported_at,extraction";
        let row = sqlx::query(sql).bind(&tenant).bind(&source).bind(revision)
            .bind(document).bind(digest.as_slice()).bind(extraction).bind(count).fetch_one(&mut *c).await?;
        sqlx::query("DELETE FROM mdm_software_snapshots.entries WHERE tenant_id=$1::uuid AND source=$2")
            .bind(&tenant).bind(&source).execute(&mut *c).await?;
        sqlx::query("INSERT INTO mdm_software_snapshots.entries(tenant_id,source,id,byte_offset,byte_length,package_id,name,version) SELECT $1::uuid,$2,id,byte_offset,byte_length,package_id,name,version FROM jsonb_to_recordset($3::jsonb) AS e(id uuid,byte_offset bigint,byte_length bigint,package_id text,name text,version text)")
            .bind(&tenant).bind(&source).bind(entries).execute(&mut *c).await?;
        // Only metadata goes into the durable operation receipt; never retain the replaced JSON.
        let response = serde_json::json!({
            "operationId":operation,"source":source,"revision":revision,
            "documentSha256":digest,"entryCount":count,
            "importedAt":row.get::<i64,_>("imported_at"),
            "extraction":row.get::<Value,_>("extraction")
        });
        sqlx::query("INSERT INTO mdm_software_snapshots.operations(tenant_id,source,id,actor,fingerprint,response) VALUES($1::uuid,$2,$3,$4,$5,$6)")
            .bind(&tenant).bind(&source).bind(operation).bind(actor).bind(fingerprint)
            .bind(response).execute(c).await?;
        Ok(Some(row))
    })).await?.ok_or(Error::Conflict)?;
    Ok(Receipt {
        operation_id: operation,
        snapshot: snapshot_row(&row)?,
    })
}
