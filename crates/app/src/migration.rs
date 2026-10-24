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
mod units;
use units::units;

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
    if !resumable_ledger(&installed, current) {
        return Err(MigrationError::at(
            "installation",
            "existing ledger differs or is incomplete",
        ));
    }
    // Replay never changes an installation addressed by different coordinates.
    if installed
        .iter()
        .any(|(name, _, _)| name == "identity-authority-v17")
    {
        verify_installation(conn, installation, instance).await?;
    }
    qualify_progress(conn, &installed).await?;
    bind_progress(conn, installation).await?;
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
    // The schema effect and its receipt commit together. A lost acknowledgement is recovered
    // by reading the original receipt; there is no ambiguous incomplete marker to erase.
    let mut tx = conn
        .begin()
        .await
        .map_err(|_| MigrationError::at(name, "begin"))?;
    if matches!(name, "audit-v1" | "audit-ledger-v1") {
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
        execute_schema(&mut tx, name, sql, "component schema").await?;
        sqlx::query("SET LOCAL ROLE mdm_owner")
            .execute(&mut *tx)
            .await
            .map_err(|_| MigrationError::at(name, "restore installer role"))?;
    } else if name == "identity-authority-v17" {
        install_identity_in(&mut tx, installation, instance)
            .await
            .map_err(|_| MigrationError::at(name, "identity installation"))?;
    } else if name != "identity-audit-runtime-v1" || installation.audit_mode == AuditMode::Ledger {
        execute_schema(
            &mut tx,
            name,
            sql,
            "component SQL failed; original transaction rolled back",
        )
        .await?;
    }
    sqlx::query("INSERT INTO public.mdm_migrations(name,digest,complete) VALUES($1,$2,true)")
        .bind(name)
        .bind(digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| MigrationError::at(name, "recording completion"))?;
    tx.commit()
        .await
        .map_err(|_| MigrationError::at(name, "commit acknowledgement unknown"))
}

/// Adapt the fixed, pinned component scripts to the installer's transaction. Some components
/// concatenate initial DDL and an explicitly wrapped upgrade. Preserve each static SQL slice and
/// execute all slices in the same transaction as the receipt; never send their transaction controls.
/// This is only for repository SQL, whose standalone control lines are checked in the unit test.
pub(crate) fn transaction_body(sql: &str) -> Result<Vec<&str>> {
    let mut offset = 0;
    let mut start = 0;
    let mut wrapped = false;
    let mut bodies = Vec::new();
    for line in sql.split_inclusive('\n') {
        match line.trim() {
            "BEGIN;" if !wrapped => {
                bodies.push(&sql[start..offset]);
                wrapped = true;
                start = offset + line.len();
            }
            "COMMIT;" if wrapped => {
                bodies.push(&sql[start..offset]);
                wrapped = false;
                start = offset + line.len();
            }
            "BEGIN;" | "COMMIT;" | "ROLLBACK;" | "START TRANSACTION;" => {
                return Err(MigrationError::at(
                    "installation",
                    "unsupported component transaction envelope",
                ));
            }
            _ => {}
        }
        offset += line.len();
    }
    if wrapped {
        return Err(MigrationError::at(
            "installation",
            "unclosed component transaction envelope",
        ));
    }
    bodies.push(&sql[start..]);
    bodies.retain(|body| {
        body.lines()
            .any(|line| !line.trim().is_empty() && !line.trim().starts_with("--"))
    });
    Ok(bodies)
}
async fn bind_progress(conn: &mut PgConnection, installation: &Installation) -> Result<()> {
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS public.mdm_installation_progress(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),instance_id uuid NOT NULL,target bytea NOT NULL CHECK(octet_length(target)=16),lineage bytea NOT NULL CHECK(octet_length(lineage)=16),audit_mode text NOT NULL CHECK(audit_mode IN('plain','ledger'))); REVOKE ALL ON public.mdm_installation_progress FROM PUBLIC")
        .execute(&mut *conn).await.map_err(|_|MigrationError::at("installation","progress storage"))?;
    sqlx::query("INSERT INTO public.mdm_installation_progress(singleton,instance_id,target,lineage,audit_mode) VALUES(true,$1::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(&installation.instance_id).bind(installation.target.as_slice()).bind(installation.lineage.as_slice()).bind(installation.audit_mode.as_str())
        .execute(&mut *conn).await.map_err(|_|MigrationError::at("installation","progress reservation"))?;
    let matched:bool=sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(instance_id=$1::uuid AND target=$2 AND lineage=$3 AND audit_mode=$4),false) FROM public.mdm_installation_progress")
        .bind(&installation.instance_id).bind(installation.target.as_slice()).bind(installation.lineage.as_slice()).bind(installation.audit_mode.as_str())
        .fetch_one(conn).await.map_err(|_|MigrationError::at("installation","progress read"))?;
    if !matched {
        return Err(MigrationError::at(
            "installation",
            "instance, storage binding or runtime profiles differ",
        ));
    }
    Ok(())
}
fn resumable_ledger(
    installed: &[(String, String, bool)],
    current: &[(&'static str, &'static str)],
) -> bool {
    if installed.len() > current.len() || installed.iter().any(|row| !row.2) {
        return false;
    }
    let prefix = &current[..installed.len()];
    installed.iter().all(|(name, digest, _)| {
        prefix
            .iter()
            .any(|(n, sql)| name == n && *digest == format!("{:x}", Sha256::digest(sql)))
    }) && installed
        .iter()
        .map(|row| &row.0)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == installed.len()
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

async fn install_identity_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    installation: &Installation,
    instance: rss_identity_core::InstanceId,
) -> std::result::Result<(), sqlx::Error> {
    rss_identity_postgres::install(tx, instance).await?;
    rss_identity_postgres::grant_platform_subject_admission(tx, "mdm_access").await?;
    rss_identity_postgres::grant_profile(
        tx,
        "mdm_identity_runtime",
        rss_identity_postgres::AuthorityProfile::Runtime,
    )
    .await?;
    rss_identity_postgres::grant_profile(
        tx,
        "mdm_identity_maintenance",
        rss_identity_postgres::AuthorityProfile::Maintenance,
    )
    .await?;
    rss_identity_postgres::grant_profile(
        tx,
        "mdm_identity_provisioning",
        rss_identity_postgres::AuthorityProfile::Provisioning,
    )
    .await?;
    rss_identity_postgres::audit::grant_worker(tx, crate::identity_audit::ROLE)
        .await
        .map_err(|_| sqlx::Error::Protocol("identity audit grant rejected".into()))?;
    rss_transactional_messaging_postgres::grant_local_projection(
        tx,
        crate::audit_projection::ROLE,
        &rss_transactional_messaging::message::MessagingDomain::parse("mdm.audit")
            .expect("fixed domain"),
        &rss_transactional_messaging::inbox::ConsumerGroup::parse("mdm.audit.v1")
            .expect("fixed group"),
    )
    .await
    .map_err(|_| sqlx::Error::Protocol("MDM audit scope rejected".into()))?;
    sqlx::query(
        "INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES($1,$2)",
    )
    .bind(installation.target.as_slice())
    .bind(installation.lineage.as_slice())
    .execute(&mut **tx)
    .await?;
    // Installation allocates the reserved authentication/authorization tenant, never accounts.
    let management = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO public.mdm_tenants(tenant_id,initial_epoch,name,used) VALUES($1,1,'Installation management',true)")
            .bind(management).execute(&mut **tx).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(management.to_string())
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1,1)",
    )
    .bind(management)
    .execute(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO public.mdm_installation(instance_id,target,lineage,audit_mode,management_tenant_id) VALUES($1::uuid,$2,$3,$4,$5)")
            .bind(&installation.instance_id)
            .bind(installation.target.as_slice())
            .bind(installation.lineage.as_slice())
            .bind(installation.audit_mode.as_str())
            .bind(management)
            .execute(&mut **tx)
            .await?;
    verify_profiles(tx, instance, installation.audit_mode).await?;
    Ok(())
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
    // mdm_access deliberately has no role memberships. Its source-admission profile is
    // checked by database::admission using an actual access-role connection at startup.
    crate::audit_projection::verify_profile(conn, audit_mode).await?;
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

async fn qualify_progress(
    conn: &mut PgConnection,
    installed: &[(String, String, bool)],
) -> Result<()> {
    let progress_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.mdm_installation_progress') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await
            .map_err(|_| MigrationError::at("installation", "progress read"))?;
    if !installed.is_empty() && !progress_exists {
        return Err(MigrationError::at(
            "installation",
            "unrecognized resumable installation source",
        ));
    }
    Ok(())
}

async fn execute_schema(
    c: &mut PgConnection,
    name: &'static str,
    sql: &'static str,
    stage: &'static str,
) -> Result<()> {
    for statement in transaction_body(sql)? {
        sqlx::raw_sql(statement)
            .execute(&mut *c)
            .await
            .map_err(|_| MigrationError::at(name, stage))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/migration/mod.rs"]
mod tests;
