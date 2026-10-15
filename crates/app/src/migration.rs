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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    Plain,
    Ledger,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub audit_mode: AuditMode,
    pub instance_id: String,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
}
impl Installation {
    pub(crate) fn validate(&self) -> Result<rss_identity_core::InstanceId> {
        let invalid = || MigrationError::at("installation", "invalid instance or storage binding");
        rss_transactional_messaging::fence::StorageIdentity::new(self.target, self.lineage)
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
fn units() -> Vec<(&'static str, &'static str)> {
    vec![
        ("audit-v1", rss_audit_postgres::MIGRATION_SQL),
        ("audit-ledger-v1", rss_ledger_postgres::MIGRATION_SQL),
        (
            "audit-receipts-v1",
            rss_mdm_audit_integration::MIGRATION_SQL,
        ),
        ("observation-v2", rss_observation_postgres::MIGRATION_SQL),
        ("projection-v3", rss_projection_postgres::MIGRATION_SQL),
        ("inventory-v1", rss_mdm_inventory_postgres::MIGRATION_SQL),
        (
            "inventory-api-reader-v1",
            rss_mdm_inventory_postgres::READER_MIGRATION_SQL,
        ),
        (
            "transactional-messaging-v1",
            rss_transactional_messaging_postgres::MIGRATION_SQL,
        ),
        ("group-v1", rss_mdm_group_postgres::MIGRATION_SQL),
        ("policy-v2", rss_mdm_policy_postgres::MIGRATION_SQL),
        ("resource-v1", rss_mdm_resource_postgres::MIGRATION_SQL),
        (
            "software-release-v2",
            rss_mdm_software_release_postgres::MIGRATION_SQL,
        ),
        (
            "registration-service-schema-v1",
            rss_mdm_registration_service::INSTALL_SQL,
        ),
        (
            "software-publication-v2",
            rss_mdm_software_service::publication::MIGRATION_SQL,
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
            "audit-runtime-v1",
            include_str!("../schema/audit-runtime.sql"),
        ),
        (
            "identity-audit-runtime-v1",
            include_str!("../schema/identity-audit-runtime.sql"),
        ),
        (
            "installation-binding-v2",
            include_str!("../schema/installation.sql"),
        ),
        (
            "identity-authority-v12",
            rss_identity_postgres::MIGRATION_SQL,
        ),
        (
            "device-command-v1",
            rss_device_command_postgres::MIGRATION_SQL,
        ),
        ("reconcile-v1", rss_reconcile_postgres::MIGRATION_SQL),
        (
            "inventory-v2",
            rss_mdm_inventory_postgres::ASSETS_MIGRATION_SQL,
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
            "group-reverse-index-v1",
            rss_mdm_group_postgres::REVERSE_INDEX_MIGRATION_SQL,
        ),
        (
            "inventory-enterprise-v1",
            rss_mdm_inventory_postgres::ENTERPRISE_MIGRATION_SQL,
        ),
        (
            "software-catalog-v2",
            rss_mdm_software_service::catalog::INSTALL_SQL,
        ),
        (
            "asset-watermark-fence-v1",
            rss_mdm_inventory_postgres::WATERMARK_FENCE_MIGRATION_SQL,
        ),
        (
            "inventory-unified-v2",
            rss_mdm_inventory_postgres::UNIFIED_COLLECTION_SQL,
        ),
        ("compliance-v1", rss_mdm_compliance_postgres::MIGRATION_SQL),
        (
            "authorization-service-schema-v1",
            rss_mdm_authorization_service::INSTALL_SQL,
        ),
        (
            "inventory-service-schema-v1",
            rss_mdm_inventory_service::INSTALL_SQL,
        ),
        (
            "content-service-schema-v1",
            rss_mdm_content_service::INSTALL_SQL,
        ),
        ("flow-service-schema-v1", rss_mdm_flow_service::INSTALL_SQL),
        (
            "execution-service-schema-v3",
            rss_mdm_execution_service::INSTALL_SQL,
        ),
        (
            "operation-receipts-schema-v1",
            rss_mdm_audit_integration::OPERATION_RECEIPTS_SQL,
        ),
        (
            "agent-channel-schema-v1",
            rss_mdm_agent_channel::INSTALL_SQL,
        ),
        (
            "windows-channel-schema-v2",
            rss_mdm_windows_channel::INSTALL_SQL,
        ),
        (
            "windows-registration-receipts-v1",
            rss_mdm_registration_service::WINDOWS_RECEIPTS_SQL,
        ),
        (
            "apple-channel-schema-v2",
            rss_mdm_apple_channel::INSTALL_SQL,
        ),
        (
            "registration-service-relations-v1",
            rss_mdm_registration_service::RELATIONS_SQL,
        ),
        (
            "authorization-service-relations-v2",
            rss_mdm_authorization_service::RELATIONS_SQL,
        ),
        (
            "inventory-service-relations-v1",
            rss_mdm_inventory_service::RELATIONS_SQL,
        ),
        (
            "content-service-relations-v1",
            rss_mdm_content_service::RELATIONS_SQL,
        ),
        (
            "execution-service-relations-v2",
            rss_mdm_execution_service::RELATIONS_SQL,
        ),
        (
            "operation-receipts-relations-v1",
            rss_mdm_audit_integration::OPERATION_RECEIPT_RELATIONS_SQL,
        ),
        (
            "flow-service-relations-v2",
            rss_mdm_flow_service::RELATIONS_SQL,
        ),
        (
            "agent-channel-relations-v1",
            rss_mdm_agent_channel::RELATIONS_SQL,
        ),
        (
            "windows-channel-relations-v2",
            rss_mdm_windows_channel::RELATIONS_SQL,
        ),
        (
            "apple-channel-relations-v2",
            rss_mdm_apple_channel::RELATIONS_SQL,
        ),
        (
            "registration-quotas-v1",
            rss_mdm_registration_service::QUOTAS_SQL,
        ),
        (
            "timeline-service-schema-v2",
            rss_mdm_timeline_service::INSTALL_SQL,
        ),
        (
            "certificate-archive-schema-v1",
            rss_mdm_certificate_archive_service::INSTALL_SQL,
        ),
        (
            "device-associations-v1",
            rss_mdm_device_service::INSTALL_SQL,
        ),
        ("device-pki-v1", rss_mdm_pki_service::INSTALL_SQL),
        (
            "self-service-access-v1",
            include_str!("../schema/self-service-access.sql"),
        ),
        (
            "enrollment-progress-v1",
            rss_mdm_registration_service::ENROLLMENT_PROGRESS_SQL,
        ),
        (
            "apple-account-authority-v1",
            rss_mdm_registration_service::APPLE_ACCOUNT_SQL,
        ),
        (
            "apple-account-channel-v1",
            rss_mdm_apple_channel::ACCOUNT_ENROLLMENT_SQL,
        ),
        (
            "registration-agent-configurations-v1",
            rss_mdm_registration_service::AGENT_CONFIGURATIONS_SQL,
        ),
        (
            "software-agent-packages-v1",
            rss_mdm_software_service::agent_packages::INSTALL_SQL,
        ),
        (
            "apple-organizations-v1",
            rss_mdm_apple_channel::ORGANIZATIONS_SQL,
        ),
        (
            "apple-ade-authority-v1",
            rss_mdm_registration_service::APPLE_ADE_SQL,
        ),
        ("apple-ade-channel-v1", rss_mdm_apple_channel::ADE_SQL),
        (
            "windows-entra-authority-v1",
            rss_mdm_registration_service::WINDOWS_ENTRA_SQL,
        ),
        (
            "windows-entra-policy-v1",
            rss_mdm_registration_service::WINDOWS_ENTRA_POLICY_SQL,
        ),
        (
            "windows-entra-channel-v2",
            rss_mdm_windows_channel::ENTRA_SQL,
        ),
        (
            "windows-entra-web-v2",
            rss_mdm_windows_channel::ENTRA_WEB_SQL,
        ),
    ]
}

/// Exact immutable migration units embedded in this executable, without database access.
pub fn manifest() -> serde_json::Value {
    serde_json::json!({"units":units().into_iter().map(|(name, sql)| serde_json::json!({"name":name,"sha256":format!("{:x}", Sha256::digest(sql))})).collect::<Vec<_>>()})
}
pub(crate) async fn migrate_on(conn: &mut PgConnection, installation: &Installation) -> Result<()> {
    migrate_units(conn, installation, &units()).await
}
async fn migrate_units(
    conn: &mut PgConnection,
    installation: &Installation,
    current: &[(&'static str, &'static str)],
) -> Result<()> {
    let instance = installation.validate()?;
    sqlx::raw_sql("SET statement_timeout='30s'; SET lock_timeout='10s';")
        .execute(&mut *conn)
        .await
        .map_err(|_| MigrationError::at("installation", "session setup"))?;
    if !owner_admitted(conn).await? {
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
    if !accepted_ledger(&installed, current) {
        return Err(MigrationError::at(
            "installation",
            "existing ledger differs or is incomplete",
        ));
    }
    // Replay never changes an installation addressed by different coordinates.
    if !installed.is_empty() {
        verify_installation(conn, installation, instance).await?;
    }
    for &(name, sql) in current {
        apply_unit(conn, installation, instance, name, sql).await?;
    }
    verify_installation(conn, installation, instance).await?;
    Ok(())
}

async fn apply_unit(
    conn: &mut PgConnection,
    installation: &Installation,
    instance: rss_identity_core::InstanceId,
    name: &'static str,
    sql: &'static str,
) -> Result<()> {
    let digest = format!("{:x}", Sha256::digest(sql));
    if unit_installed(conn, name, &digest).await? {
        return Ok(());
    }
    sqlx::query("INSERT INTO public.mdm_migrations(name,digest) VALUES($1,$2)")
        .bind(name)
        .bind(digest)
        .execute(&mut *conn)
        .await
        .map_err(|_| MigrationError::at(name, "recording installation intent"))?;
    if matches!(name, "audit-v1" | "audit-ledger-v1") {
        install_audit_component(conn, name, sql).await?;
    } else if name == "identity-authority-v12" {
        install_identity(conn, installation, instance).await?;
    } else if name != "identity-audit-runtime-v1" || installation.audit_mode == AuditMode::Ledger {
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
    Ok(())
}

async fn install_audit_component(
    conn: &mut PgConnection,
    name: &'static str,
    sql: &'static str,
) -> Result<()> {
    let mut tx = conn
        .begin()
        .await
        .map_err(|_| MigrationError::at(name, "begin"))?;
    let role = if name == "audit-v1" {
        "mdm_audit_owner"
    } else {
        "mdm_ledger_owner"
    };
    sqlx::query("SELECT set_config('role',$1,true)")
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(|_| MigrationError::at(name, "owner role"))?;
    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .map_err(|_| MigrationError::at(name, "component schema"))?;
    sqlx::query("SET LOCAL ROLE mdm_owner")
        .execute(&mut *tx)
        .await
        .map_err(|_| MigrationError::at(name, "restore installer role"))?;
    tx.commit()
        .await
        .map_err(|_| MigrationError::at(name, "commit acknowledgement unknown"))
}
async fn unit_installed(conn: &mut PgConnection, name: &'static str, digest: &str) -> Result<bool> {
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
        return Ok(true);
    }
    Ok(false)
}

fn accepted_ledger(
    installed: &[(String, String, bool)],
    current: &[(&'static str, &'static str)],
) -> bool {
    use std::collections::BTreeMap;
    if installed.is_empty() {
        return true;
    }
    if installed.iter().any(|(_, _, complete)| !complete) {
        return false;
    }
    let actual = installed
        .iter()
        .map(|(name, digest, _)| (name.as_str(), digest.as_str()))
        .collect::<BTreeMap<_, _>>();
    if actual.len() != installed.len() {
        return false;
    }
    let candidate = current
        .iter()
        .map(|(name, sql)| (*name, format!("{:x}", Sha256::digest(sql))))
        .collect::<BTreeMap<_, _>>();
    let matches = |expected: &BTreeMap<&str, String>| {
        actual.len() == expected.len()
            && actual
                .iter()
                .all(|(name, digest)| expected.get(name).is_some_and(|value| value == digest))
    };
    if matches(&candidate) {
        return true;
    }
    false
}

pub(crate) async fn verify_current_manifest(
    conn: &mut PgConnection,
) -> std::result::Result<(), sqlx::Error> {
    let installed: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations")
            .fetch_all(conn)
            .await?;
    if installed.is_empty() || !accepted_ledger(&installed, &units()) {
        return Err(sqlx::Error::Protocol("incomplete installation".into()));
    }
    Ok(())
}

impl AuditMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Ledger => "ledger",
        }
    }
}
/// Database-authenticated installation operator; runtime profiles never inherit it.
pub(crate) async fn owner_admitted(conn: &mut PgConnection) -> Result<bool> {
    sqlx::query_scalar(r#"
SELECT current_user='mdm_owner' AND session_user='mdm_owner'
 AND has_database_privilege(current_user,current_database(),'CREATE')
 AND has_schema_privilege(current_user,'public','CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER'))
 AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication))
"#).fetch_one(conn).await.map_err(|_| MigrationError::at("installation", "owner probe unavailable"))
}
/// The one stable attestation consumed by installer, operator and runtime.
pub(crate) async fn verify_identity(
    conn: &mut PgConnection,
    installation: &Installation,
) -> std::result::Result<(), sqlx::Error> {
    let matched: bool = sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(instance_id=$1::uuid AND target=$2 AND lineage=$3 AND audit_mode=$4),false) FROM public.mdm_installation")
        .bind(&installation.instance_id).bind(installation.target.as_slice()).bind(installation.lineage.as_slice()).bind(installation.audit_mode.as_str())
        .fetch_one(conn).await?;
    if !matched {
        return Err(sqlx::Error::Protocol(
            "installation identity mismatch".into(),
        ));
    }
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
        rss_identity_postgres::audit::grant_worker(&mut tx, crate::identity_audit::ROLE)
            .await
            .map_err(|_| sqlx::Error::Protocol("identity audit grant rejected".into()))?;
        sqlx::query(
            "INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES($1,$2)",
        )
        .bind(installation.target.as_slice())
        .bind(installation.lineage.as_slice())
        .execute(&mut *tx)
        .await?;
        // Installation allocates the reserved authentication/authorization tenant, never accounts.
        let management = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO public.mdm_tenants(tenant_id,initial_epoch,name,used) VALUES($1,1,'Installation management',true)")
            .bind(management).execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(management.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1,1)",
        )
        .bind(management)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO public.mdm_installation(instance_id,target,lineage,audit_mode,management_tenant_id) VALUES($1::uuid,$2,$3,$4,$5)")
            .bind(&installation.instance_id)
            .bind(installation.target.as_slice())
            .bind(installation.lineage.as_slice())
            .bind(installation.audit_mode.as_str())
            .bind(management)
            .execute(&mut *tx)
            .await?;
        verify_profiles(&mut tx, instance, installation.audit_mode).await?;
        tx.commit().await
    }
    install(conn, installation, instance).await.map_err(|_| {
        MigrationError::at(
            "identity-authority-v12",
            "installation not confirmed; inspect ledger",
        )
    })
}
async fn verify_profiles(
    conn: &mut PgConnection,
    instance: rss_identity_core::InstanceId,
    audit_mode: AuditMode,
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
    crate::identity_audit::verify_profile(conn, audit_mode)
        .await
        .map_err(|_| sqlx::Error::Protocol("identity audit profile rejected".into()))?;
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
        if storage != [(installation.target.to_vec(), installation.lineage.to_vec())] {
            return Err(sqlx::Error::Protocol("storage binding mismatch".into()));
        }
        verify_identity(&mut tx, installation).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',management_tenant_id::text,true) FROM public.mdm_installation WHERE singleton")
            .execute(&mut *tx).await?;
        let management_valid: bool = sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(t.initial_epoch=1 AND t.used AND NOT t.deleted AND t.revision=1 AND e.epoch=1),false) FROM public.mdm_installation i JOIN public.mdm_tenants t ON t.tenant_id=i.management_tenant_id JOIN rss_transactional_messaging.tenant_epoch e USING(tenant_id)")
            .fetch_one(&mut *tx).await?;
        if !management_valid {
            return Err(sqlx::Error::Protocol(
                "management tenant binding mismatch".into(),
            ));
        }
        verify_profiles(&mut tx, instance, installation.audit_mode).await?;
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
#[path = "../tests/migration/mod.rs"]
mod tests;
