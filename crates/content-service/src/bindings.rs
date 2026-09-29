//! Content binding persistence; callers retain their existing transaction and audit ownership.
use crate::Upload;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::Row;
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Content(#[from] crate::Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
pub async fn bind_in(tx: &mut PgTransaction<'_>, upload: &Upload) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let upload = upload.clone();
    let encoded = serde_json::to_value(&upload.binding).map_err(|_| crate::Error::Malformed)?;
    tx.with_connection(move|c|Box::pin(async move{
 let inserted=sqlx::query("INSERT INTO mdm_content.bindings(tenant_id,actor,operation,resource,version,reference,length,sha256,binding) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,actor,operation) DO NOTHING")
 .bind(&tenant).bind(&upload.binding.actor).bind(upload.id).bind(&upload.binding.resource).bind(&upload.binding.version).bind(&upload.binding.reference).bind(upload.binding.length as i64).bind(upload.binding.sha256.to_vec()).bind(&encoded).execute(&mut *c).await?.rows_affected();
 if inserted!=0{return Ok(Ok(true));}
 let old=sqlx::query_scalar::<_,serde_json::Value>("SELECT binding FROM mdm_content.bindings WHERE tenant_id=$1::uuid AND actor=$2 AND operation=$3::uuid").bind(tenant).bind(upload.binding.actor).bind(upload.id).fetch_one(c).await?;
 Ok(if old==encoded{Ok(false)}else{Err(crate::Error::Conflict)})
 })).await?.map_err(Into::into)
}
pub async fn read_in(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: &str,
    operation: Uuid,
) -> Result<Option<serde_json::Value>> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let id = id.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT resource,version,reference,length,sha256 FROM mdm_content.bindings WHERE tenant_id=$1::uuid AND actor=$2 AND operation=$3::uuid AND resource=$4").bind(tenant).bind(actor).bind(operation).bind(id).fetch_optional(c).await})).await?;
    row.map(|row|Ok(serde_json::json!({"operationId":operation,"committed":true,"resource":row.try_get::<String,_>("resource")?,"version":row.try_get::<String,_>("version")?,"reference":row.try_get::<String,_>("reference")?,"length":row.try_get::<i64,_>("length")?,"sha256":row.try_get::<Vec<u8>,_>("sha256")?}))).transpose()
}
