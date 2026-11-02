use super::{Error, Result, journal::Journal};
use sqlx::Connection;
pub async fn no_writers(c: &mut sqlx::PgConnection) -> Result<()> {
    let n:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'").fetch_one(c).await.map_err(|_|Error::Storage)?;
    if n != 0 {
        return Err(Error::Busy);
    }
    Ok(())
}
pub async fn connection_fence(
    c: &mut sqlx::PgConnection,
    journal: &Journal,
    enable: bool,
) -> Result<()> {
    let roles = if let Some(roles) =
        journal.load::<Vec<(String, bool)>>("database-connections.json")?
    {
        roles
    } else {
        if !enable {
            return Err(Error::Corrupt);
        }
        let roles:Vec<(String,bool)>=sqlx::query_as("SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END,bool_or(a.is_grantable) FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.privilege_type='CONNECT' AND a.grantee<>d.datdba GROUP BY 1 ORDER BY 1").fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
        journal.secret(
            "database-connections.json",
            &serde_json::to_vec(&roles).map_err(|_| Error::Corrupt)?,
        )?;
        roles
    };
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.backup.roles',$1,true)")
        .bind(serde_json::to_string(&roles).map_err(|_| Error::Corrupt)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    sqlx::raw_sql(if enable {r#"DO $backup$
DECLARE entry jsonb; role_name text;
BEGIN
 EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC',current_database());
 FOR role_name IN SELECT DISTINCT pg_get_userbyid(a.grantee)::text FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.privilege_type='CONNECT' AND a.grantee NOT IN (0,d.datdba) LOOP
  IF role_name=current_user THEN CONTINUE; END IF;
  EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %s',current_database(),CASE WHEN role_name='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(role_name) END);
 END LOOP;
END $backup$;"#}else{r#"DO $backup$
DECLARE entry jsonb; role_name text;
BEGIN
 FOR entry IN SELECT value FROM jsonb_array_elements(current_setting('rss.backup.roles')::jsonb) LOOP
  role_name:=entry->>0;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %s%s',current_database(),CASE WHEN role_name='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(role_name) END,CASE WHEN (entry->>1)::boolean THEN ' WITH GRANT OPTION' ELSE '' END);
 END LOOP;
END $backup$;"#}).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)
}
