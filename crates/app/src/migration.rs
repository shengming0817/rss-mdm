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
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub instance_id: String,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub epoch: i64,
    pub tenants: Vec<String>,
}
impl Installation {
    fn configuration(&self) -> serde_json::Value {
        let mut value =
            serde_json::to_value(self).expect("installation contains only scalar values");
        let mut tenants = self.tenants.clone();
        tenants.sort();
        value["tenants"] = serde_json::json!(tenants);
        value
    }
    pub(crate) fn validate(&self) -> Result<rss_identity_core::InstanceId> {
        use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
        let invalid = || MigrationError::at("installation", "invalid instance or storage binding");
        let mut tenants = Vec::new();
        for value in &self.tenants {
            let tenant = rss_request_context::TenantId::parse(value).map_err(|_| invalid())?;
            if tenant.to_string() != *value || tenants.contains(&tenant) {
                return Err(invalid());
            }
            tenants.push(tenant);
        }
        if tenants.is_empty() || tenants.len() > 128 {
            return Err(invalid());
        }
        let epoch = Epoch::new(self.epoch).map_err(|_| invalid())?;
        ExecutionBinding::new(
            StorageIdentity::new(self.target, self.lineage).map_err(|_| invalid())?,
            tenants.into_iter().map(|t| (t, epoch)).collect(),
        )
        .map_err(|_| invalid())?;
        let instance =
            rss_identity_core::InstanceId::parse(&self.instance_id).map_err(|_| invalid())?;
        if instance.to_string() != self.instance_id {
            return Err(invalid());
        }
        Ok(instance)
    }
}
pub async fn migrate(options: &PgConnectOptions, installation: &Installation) -> Result<()> {
    installation.validate()?;
    let mut conn =
        tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(options))
            .await
            .map_err(|_| MigrationError::at("installation", "connection deadline"))?
            .map_err(|_| MigrationError::at("installation", "connection unavailable"))?;
    let primary =
        tokio::time::timeout(Duration::from_secs(60), migrate_on(&mut conn, installation))
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
fn units() -> [(&'static str, &'static str); 37] {
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
        (
            "transactional-messaging-v1",
            rss_transactional_messaging_postgres::MIGRATION_SQL,
        ),
        ("group-v1", rss_mdm_group_postgres::MIGRATION_SQL),
        ("policy-v1", rss_mdm_policy_postgres::MIGRATION_SQL),
        ("resource-v1", rss_mdm_resource_postgres::MIGRATION_SQL),
        (
            "software-release-v1",
            rss_mdm_software_release_postgres::MIGRATION_SQL,
        ),
        (
            "software-publication-v1",
            crate::software_publication::MIGRATION_SQL,
        ),
        (
            "management-v1",
            include_str!("../migrations/0007_management.sql"),
        ),
        (
            "group-outbox-writer-v1",
            rss_mdm_group_postgres::OUTBOX_MIGRATION_SQL,
        ),
        (
            "policy-outbox-writer-v1",
            rss_mdm_policy_postgres::OUTBOX_MIGRATION_SQL,
        ),
        (
            "resource-outbox-writer-v1",
            rss_mdm_resource_postgres::OUTBOX_MIGRATION_SQL,
        ),
        (
            "software-release-outbox-writer-v1",
            rss_mdm_software_release_postgres::OUTBOX_MIGRATION_SQL,
        ),
        (
            "installation-binding-v1",
            include_str!("../migrations/0009_installation.sql"),
        ),
        (
            "identity-authority-v11",
            rss_identity_postgres::MIGRATION_SQL,
        ),
        (
            "embedded-identity-coordinates-v1",
            include_str!("../migrations/0008_embedded_identity_coordinates.sql"),
        ),
        (
            "authorization-v1",
            include_str!("../migrations/0010_authorization.sql"),
        ),
        (
            "device-command-v1",
            rss_device_command_postgres::MIGRATION_SQL,
        ),
        ("reconcile-v1", rss_reconcile_postgres::MIGRATION_SQL),
        (
            "commands-v1",
            include_str!("../migrations/0011_commands.sql"),
        ),
        (
            "inventory-v2",
            rss_mdm_inventory_postgres::ASSETS_MIGRATION_SQL,
        ),
        (
            "assets-management-v1",
            include_str!("../migrations/0011_assets.sql"),
        ),
        (
            "agent-access-v1",
            include_str!("../migrations/0012_agent_access.sql"),
        ),
        (
            "policy-candidates-v2",
            rss_mdm_policy_postgres::CANDIDATES_MIGRATION_SQL,
        ),
        (
            "group-generations-v1",
            rss_mdm_group_postgres::GENERATIONS_MIGRATION_SQL,
        ),
        (
            "asset-history-v1",
            rss_mdm_inventory_postgres::HISTORY_MIGRATION_SQL,
        ),
        (
            "asset-authority-history-v1",
            include_str!("../migrations/0012_asset_history.sql"),
        ),
        (
            "automation-v1",
            include_str!("../migrations/0013_automation.sql"),
        ),
        (
            "collection-history-v1",
            include_str!("../migrations/0014_collection_history.sql"),
        ),
        (
            "group-reverse-index-v1",
            rss_mdm_group_postgres::REVERSE_INDEX_MIGRATION_SQL,
        ),
    ]
}
/// Exact immutable migration units embedded in this executable, without database access.
pub fn manifest() -> serde_json::Value {
    serde_json::json!({"units":units().into_iter().map(|(name, sql)| serde_json::json!({"name":name,"sha256":format!("{:x}", Sha256::digest(sql))})).collect::<Vec<_>>()})
}
async fn migrate_on(conn: &mut PgConnection, installation: &Installation) -> Result<()> {
    let instance = installation.validate()?;
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
    let installed: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations")
            .fetch_all(&mut *conn)
            .await
            .map_err(|_| MigrationError::at("installation", "ledger read"))?;
    let current = units();
    if !installed.is_empty()
        && (installed.len() != current.len()
            || installed.iter().any(|(name, digest, complete)| {
                !complete
                    || !current.iter().any(|(expected, sql)| {
                        name == expected && digest == &format!("{:x}", Sha256::digest(sql))
                    })
            }))
    {
        return Err(MigrationError::at(
            "installation",
            "fresh installation required; existing ledger differs or is incomplete",
        ));
    }
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
        if name == "identity-authority-v11" {
            install_identity(conn, installation, instance).await?;
        } else {
            sqlx::raw_sql(sql).execute(&mut *conn).await.map_err(|_| {
                MigrationError::at(
                    name,
                    "component SQL failed; inspect incomplete installation",
                )
            })?;
        }
        sqlx::query("UPDATE public.mdm_migrations SET complete=true WHERE name=$1")
            .bind(name)
            .execute(&mut *conn)
            .await
            .map_err(|_| MigrationError::at(name, "completion acknowledgement unknown"))?;
    }
    verify_installation(conn, installation, instance).await?;
    Ok(())
}

async fn install_identity(
    conn: &mut PgConnection,
    installation: &Installation,
    instance: rss_identity_core::InstanceId,
) -> Result<()> {
    async fn install(
        conn: &mut PgConnection,
        installation: &Installation,
        instance: rss_identity_core::InstanceId,
    ) -> std::result::Result<(), sqlx::Error> {
        let mut tx = conn.begin().await?;
        rss_identity_postgres::install(&mut tx, instance).await?;
        rss_identity_postgres::grant_profile(
            &mut tx,
            "mdm_identity_runtime",
            rss_identity_postgres::AuthorityProfile::Runtime,
        )
        .await?;
        rss_identity_postgres::grant_profile(
            &mut tx,
            "mdm_identity_maintenance",
            rss_identity_postgres::AuthorityProfile::Maintenance,
        )
        .await?;
        sqlx::query(
            "INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES($1,$2)",
        )
        .bind(installation.target.as_slice())
        .bind(installation.lineage.as_slice())
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO public.mdm_installation(configuration) VALUES($1)")
            .bind(installation.configuration())
            .execute(&mut *tx)
            .await?;
        for tenant in &installation.tenants {
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(tenant)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1::uuid,$2)")
                .bind(tenant).bind(installation.epoch).execute(&mut *tx).await?;
        }
        verify_profiles(&mut tx, instance).await?;
        tx.commit().await
    }
    install(conn, installation, instance).await.map_err(|_| {
        MigrationError::at(
            "identity-authority-v11",
            "installation not confirmed; inspect ledger",
        )
    })
}
async fn verify_profiles(
    conn: &mut PgConnection,
    instance: rss_identity_core::InstanceId,
) -> std::result::Result<(), sqlx::Error> {
    for (statement, profile) in [
        (
            "SET LOCAL ROLE mdm_identity_runtime",
            rss_identity_postgres::AuthorityProfile::Runtime,
        ),
        (
            "SET LOCAL ROLE mdm_identity_maintenance",
            rss_identity_postgres::AuthorityProfile::Maintenance,
        ),
    ] {
        sqlx::raw_sql(statement).execute(&mut *conn).await?;
        rss_identity_postgres::verify_profile(conn, profile, instance)
            .await
            .map_err(|_| sqlx::Error::Protocol("identity profile rejected".into()))?;
        sqlx::raw_sql("SET LOCAL ROLE NONE")
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
async fn verify_installation(
    conn: &mut PgConnection,
    installation: &Installation,
    instance: rss_identity_core::InstanceId,
) -> Result<()> {
    async fn verify(
        conn: &mut PgConnection,
        installation: &Installation,
        instance: rss_identity_core::InstanceId,
    ) -> std::result::Result<(), sqlx::Error> {
        let mut tx = conn.begin().await?;
        let storage: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT target,lineage FROM rss_transactional_messaging.storage_lineage",
        )
        .fetch_all(&mut *tx)
        .await?;
        let installed: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT configuration FROM public.mdm_installation")
                .fetch_all(&mut *tx)
                .await?;
        if storage != [(installation.target.to_vec(), installation.lineage.to_vec())]
            || installed != [installation.configuration()]
        {
            return Err(sqlx::Error::Protocol(
                "installation binding mismatch".into(),
            ));
        }
        for tenant in &installation.tenants {
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(tenant)
                .execute(&mut *tx)
                .await?;
            let epoch: Option<i64> = sqlx::query_scalar("SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid").bind(tenant).fetch_optional(&mut *tx).await?;
            if epoch != Some(installation.epoch) {
                return Err(sqlx::Error::Protocol("tenant epoch mismatch".into()));
            }
        }
        verify_profiles(&mut tx, instance).await?;
        tx.rollback().await
    }
    verify(conn, installation, instance).await.map_err(|_| {
        MigrationError::at(
            "installation",
            "instance, storage binding or runtime profiles differ",
        )
    })
}

#[cfg(test)]
mod tests;
