//! Bind the stable comparison identity in the caller's existing transaction.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
pub async fn bind_in(tx: &mut PgTransaction<'_>, key_id: &str) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let key_id = key_id.to_owned();
    tx.with_connection(move|c|Box::pin(async move{
  let admitted:bool=sqlx::query_scalar(include_str!("admission.sql")).fetch_one(&mut *c).await?;
  if !admitted{return Err(sqlx::Error::Protocol("native protection admission".into()))}
  sqlx::query("INSERT INTO mdm_flow.native_protection(tenant_id,key_id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(&key_id).execute(&mut *c).await?;
  let matches:bool=sqlx::query_scalar("SELECT key_id=$2 FROM mdm_flow.native_protection WHERE tenant_id=$1::uuid").bind(tenant).bind(key_id).fetch_one(c).await?;
  if !matches{return Err(sqlx::Error::Protocol("native protection key mismatch".into()))}Ok(())
 })).await
}
