//! The product owns one bounded installer; immutable SQL units retain their component owners.
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Row, postgres::PgConnectOptions};
use std::time::Duration;
#[derive(Clone, Debug, thiserror::Error)]
#[error("migration {unit}: {phase} (cleanup_failed={cleanup_failed})")]
pub struct MigrationError {
    unit: &'static str,
    phase: &'static str,
    cleanup_failed: bool,
}
impl MigrationError {
    fn at(unit: &'static str, phase: &'static str) -> Self {
        Self {
            unit,
            phase,
            cleanup_failed: false,
        }
    }
}
type Result<T> = std::result::Result<T, MigrationError>;
pub async fn migrate(options: &PgConnectOptions) -> Result<()> {
    let mut conn =
        tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(options))
            .await
            .map_err(|_| MigrationError::at("installation", "connection deadline"))?
            .map_err(|_| MigrationError::at("installation", "connection unavailable"))?;
    let primary = tokio::time::timeout(Duration::from_secs(60), migrate_on(&mut conn))
        .await
        .map_err(|_| MigrationError::at("installation", "deadline; result unknown"))
        .and_then(|r| r);
    let clean = matches!(
        tokio::time::timeout(Duration::from_secs(5), conn.close()).await,
        Ok(Ok(()))
    );
    match primary {
        Err(mut error) => {
            error.cleanup_failed = !clean;
            Err(error)
        }
        Ok(()) if clean => Ok(()),
        Ok(()) => Err(MigrationError::at(
            "installation",
            "connection close failed",
        )),
    }
}
fn units() -> [(&'static str, &'static str); 9] {
    [
        ("access-v1", include_str!("../migrations/0001_access.sql")),
        ("observation-v2", rss_observation_postgres::MIGRATION_SQL),
        ("projection-v3", rss_projection_postgres::MIGRATION_SQL),
        ("inventory-v1", rss_mdm_inventory_postgres::MIGRATION_SQL),
        (
            "inventory-api-reader-v1",
            rss_mdm_inventory_postgres::READER_MIGRATION_SQL,
        ),
        (
            "access-audit-request-index-v1",
            include_str!("../migrations/0002_audit_request_index.sql"),
        ),
        (
            "device-identity-v1",
            include_str!("../migrations/0003_device_identity.sql"),
        ),
        (
            "windows-enrollment-v1",
            include_str!("../migrations/0004_windows_enrollment.sql"),
        ),
        (
            "windows-collection-v1",
            include_str!("../migrations/0005_collection.sql"),
        ),
    ]
}
/// Exact immutable migration units embedded in this executable, without database access.
pub fn manifest() -> serde_json::Value {
    serde_json::json!({"units":units().map(|(name, sql)| serde_json::json!({"name":name,"sha256":format!("{:x}", Sha256::digest(sql))}))})
}
async fn migrate_on(conn: &mut PgConnection) -> Result<()> {
    sqlx::raw_sql("SET statement_timeout='30s'; SET lock_timeout='10s';")
        .execute(&mut *conn)
        .await
        .map_err(|_| MigrationError::at("installation", "session setup"))?;
    let owner:bool=sqlx::query_scalar(r#"
SELECT current_user='mdm_owner' AND session_user='mdm_owner'
 AND has_database_privilege(current_user,current_database(),'CREATE')
 AND has_schema_privilege(current_user,'public','CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER'))
 AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication))
"#).fetch_one(&mut *conn).await.map_err(|_|MigrationError::at("installation","owner probe unavailable"))?;
    if !owner {
        return Err(MigrationError::at(
            "installation",
            "mdm_owner admission rejected",
        ));
    }
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut *conn)
        .await
        .map_err(|_| MigrationError::at("installation", "installation lock"))?;
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS public.mdm_migrations(name text PRIMARY KEY,digest text NOT NULL,complete boolean NOT NULL DEFAULT false)")
        .execute(&mut *conn).await.map_err(|_|MigrationError::at("installation","ledger initialization"))?;
    for (name, sql) in units() {
        let digest = format!("{:x}", Sha256::digest(sql));
        let old = sqlx::query("SELECT digest,complete FROM public.mdm_migrations WHERE name=$1")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|_| MigrationError::at(name, "ledger read"))?;
        if let Some(row) = old {
            let old_digest: String = row
                .try_get("digest")
                .map_err(|_| MigrationError::at(name, "invalid ledger shape"))?;
            let complete: bool = row
                .try_get("complete")
                .map_err(|_| MigrationError::at(name, "invalid ledger shape"))?;
            if old_digest != digest || !complete {
                return Err(MigrationError::at(
                    name,
                    "changed or interrupted; inspect/restore installation, do not delete ledger",
                ));
            }
            continue;
        }
        sqlx::query("INSERT INTO public.mdm_migrations(name,digest) VALUES($1,$2)")
            .bind(name)
            .bind(digest)
            .execute(&mut *conn)
            .await
            .map_err(|_| MigrationError::at(name, "recording installation intent"))?;
        sqlx::raw_sql(sql).execute(&mut *conn).await.map_err(|_| {
            MigrationError::at(
                name,
                "component SQL failed; inspect incomplete installation",
            )
        })?;
        sqlx::query("UPDATE public.mdm_migrations SET complete=true WHERE name=$1")
            .bind(name)
            .execute(&mut *conn)
            .await
            .map_err(|_| MigrationError::at(name, "completion acknowledgement unknown"))?;
    }
    Ok(())
}
