//! Rebuildable metadata, atomically maintained by the aggregate owner. No query-time decoding scan.
use crate::{STORAGE, codec};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use sqlx::Row;

fn projection(
    document: &[u8],
    tenant: TenantId,
    id: &str,
    revision: i64,
) -> Result<Value, PgError> {
    STORAGE.json(
        "directory projection",
        serde_json::to_value(codec::directory_header(document, tenant, id, revision)?),
    )
}

pub(crate) async fn write_in(
    tx: &mut PgTransaction<'_>,
    id: &str,
    old: Option<u64>,
    revision: u64,
    document: Vec<u8>,
) -> Result<(), PgError> {
    let revision = STORAGE.integer("directory revision", i64::try_from(revision))?;
    let old = STORAGE.integer(
        "directory previous revision",
        old.map(i64::try_from).transpose(),
    )?;
    let directory = projection(&document, tx.tenant_id(), id, revision)?;
    let digest = rss_mdm_backend_postgres_support::digest(&document);
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    let sql = if old.is_some() {
        "UPDATE mdm_resource.aggregates SET revision=$3,document=$4,digest=$5,directory=$7 WHERE tenant_id=$1::uuid AND id=$2 AND revision=$6"
    } else {
        "INSERT INTO mdm_resource.aggregates(tenant_id,id,revision,document,digest,directory) SELECT $1::uuid,$2,$3,$4,$5,$7 WHERE $6::bigint IS NULL"
    };
    let count = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(sqlx::query(sql)
                    .bind(tenant)
                    .bind(id)
                    .bind(revision)
                    .bind(document)
                    .bind(digest)
                    .bind(old)
                    .bind(directory)
                    .execute(c)
                    .await?
                    .rows_affected())
            })
        })
        .await?;
    if count != 1 {
        return Err(STORAGE.fault("directory CAS"));
    }
    Ok(())
}

/// Rebuild through the original decoder in the caller's installation transaction; never commits.
pub async fn rebuild(c: &mut sqlx::PgConnection, tenant: uuid::Uuid) -> Result<(), sqlx::Error> {
    let previous: String =
        sqlx::query_scalar("SELECT coalesce(current_setting('rss.tenant_id',true),'')")
            .fetch_one(&mut *c)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await?;
    let domain = TenantId::parse(&tenant.to_string())
        .map_err(|_| sqlx::Error::Protocol("Resource projection tenant".into()))?;
    let mut after = String::new();
    loop {
        let rows = sqlx::query("SELECT id,revision,document,digest FROM mdm_resource.aggregates WHERE tenant_id=$1 AND id COLLATE \"C\">$2 COLLATE \"C\" ORDER BY id COLLATE \"C\" LIMIT 128").bind(tenant).bind(&after).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let id: String = row.try_get("id")?;
            let document = STORAGE
                .checked(row.try_get("document")?, row.try_get("digest")?)
                .map_err(|_| sqlx::Error::Protocol("Resource projection integrity".into()))?;
            let directory = projection(&document, domain, &id, row.try_get("revision")?)
                .map_err(|_| sqlx::Error::Protocol("Resource projection header".into()))?;
            sqlx::query(
                "UPDATE mdm_resource.aggregates SET directory=$3 WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant)
            .bind(&id)
            .bind(directory)
            .execute(&mut *c)
            .await?;
            after = id;
        }
    }
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(previous)
        .execute(&mut *c)
        .await?;
    Ok(())
}
