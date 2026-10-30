//! One-time restricted role preparation, owned by the deployment operator.
//! ref: PostgreSQL CREATE ROLE/CREATE DATABASE; sqlx 0.9.0 src/sql_str.rs.
use super::{
    Error, Result,
    install::{Input, ROLES},
};
use sqlx::Connection;
use std::collections::BTreeMap;

pub(super) async fn prepare(input: &Input, instance: uuid::Uuid) -> Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(90),
        prepare_inner(input, instance),
    )
    .await
    .map_err(|_| Error::Storage)?
}
async fn prepare_inner(input: &Input, instance: uuid::Uuid) -> Result<()> {
    let admin = &input.database.administrator;
    let tag = format!("rss-mdm-installation:{instance}");
    let mut passwords = BTreeMap::new();
    for role in ROLES {
        passwords.insert(
            *role,
            crate::config::secret(&input.database(role)?.password_file)
                .map_err(|_| Error::Corrupt)?,
        );
    }
    let secrets =
        zeroize::Zeroizing::new(serde_json::to_string(&passwords).map_err(|_| Error::Input)?);
    let mut c = sqlx::PgConnection::connect_with(&admin.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT pg_advisory_xact_lock(2823,2),set_config('rss.installation.identity',$1,true),set_config('rss.installation.roles',$2,true)")
        .bind(&tag).bind(secrets.as_str()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    sqlx::raw_sql(r#"DO $prepare$
DECLARE tag text := current_setting('rss.installation.identity'); actual text;
BEGIN
 SELECT shobj_description(oid,'pg_authid') INTO actual FROM pg_roles WHERE rolname='mdm_owner';
 IF FOUND THEN
  IF actual IS DISTINCT FROM tag||':reserved' AND actual IS DISTINCT FROM tag||':ready' THEN
   RAISE EXCEPTION 'installation role ownership mismatch';
  END IF;
 ELSE
  CREATE ROLE mdm_owner LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
  EXECUTE format('ALTER ROLE mdm_owner PASSWORD %L',current_setting('rss.installation.roles')::jsonb->>'mdm_owner');
  EXECUTE format('COMMENT ON ROLE mdm_owner IS %L',tag||':reserved');
 END IF;
END $prepare$;"#).execute(&mut *tx).await.map_err(|_|Error::Conflict)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    let owner: Option<String> =
        sqlx::query_scalar("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1")
            .bind(&input.database.name)
            .fetch_optional(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
    if let Some(owner) = owner {
        if owner != "mdm_owner" {
            return Err(Error::Conflict);
        }
    } else {
        // CREATE DATABASE cannot use a bind parameter or run inside a transaction. Only the
        // checked ASCII identifier is interpolated; all credentials remain bind parameters.
        let name = identifier(&input.database.name)?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {name} OWNER mdm_owner TEMPLATE template0"
        )))
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    }
    c.close().await.map_err(|_| Error::Storage)?;
    prepare_roles(input, &tag, &secrets).await
}
async fn prepare_roles(input: &Input, tag: &str, secrets: &str) -> Result<()> {
    let admin = &input.database.administrator;
    let mut target = admin.clone();
    target.name = input.database.name.clone();
    let mut c = sqlx::PgConnection::connect_with(&target.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT pg_advisory_xact_lock(2823,2),set_config('rss.installation.identity',$1,true),set_config('rss.installation.roles',$2,true)")
        .bind(tag).bind(secrets).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    let marker: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_authid') FROM pg_roles WHERE rolname='mdm_owner'",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| Error::Storage)?;
    if marker.as_deref() == Some(format!("{tag}:reserved").as_str()) {
        for sql in [
            "CREATE ROLE mdm_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; CREATE ROLE mdm_api NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; CREATE ROLE mdm_access NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;",
            include_str!("../../schema/business-roles.sql"),
            include_str!("../../schema/software-publication-roles.sql"),
            include_str!("../../schema/commands-roles.sql"),
            include_str!("../../schema/identity-roles.sql"),
            include_str!("../../schema/audit-roles.sql"),
            include_str!("../../schema/webhook-roles.sql"),
            "CREATE ROLE mdm_group_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT rss_tmsg_relay TO mdm_group_owner; GRANT CREATE ON SCHEMA public TO mdm_owner,mdm_group_owner;",
        ] {
            sqlx::raw_sql(sql)
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
        }
        sqlx::raw_sql(r#"DO $profiles$
DECLARE role_name text; secret text;
BEGIN
 EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC',current_database());
 FOR role_name,secret IN SELECT key,value FROM jsonb_each_text(current_setting('rss.installation.roles')::jsonb) LOOP
  EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L',role_name,secret);
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),role_name);
 END LOOP;
 EXECUTE format('GRANT CREATE ON DATABASE %I TO mdm_owner,mdm_audit_owner,mdm_ledger_owner,mdm_group_owner',current_database());
 EXECUTE format('COMMENT ON ROLE mdm_owner IS %L',current_setting('rss.installation.identity')||':ready');
END $profiles$;"#).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    } else if marker.as_deref() != Some(format!("{tag}:ready").as_str()) {
        return Err(Error::Conflict);
    }
    tx.commit().await.map_err(|_| Error::Storage)?;
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(())
}
fn identifier(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(Error::Input);
    }
    Ok(format!("\"{name}\""))
}

#[cfg(test)]
#[path = "../../tests/setup/postgres.rs"]
mod tests;
