//! MDM installation composition. Execution and receipt recovery have one independent owner.
use rss_mdm_install_support::{Error as MigrationError, StorageProfile, execute_schema};
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
type Result<T> = std::result::Result<T, MigrationError>;
pub(crate) mod device_access;
mod units;
use units::units;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    #[default]
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
    let instance = installation.validate()?;
    let binding = rss_mdm_install_support::Binding::new(
        StorageProfile::Mdm,
        uuid::Uuid::parse_str(&installation.instance_id)
            .map_err(|_| MigrationError::at("installation", "invalid instance"))?,
        installation.target,
        installation.lineage,
        installation.audit_mode.as_str().into(),
    )?;
    rss_mdm_install_support::install(
        options,
        &binding,
        &units(),
        &MdmInstallation {
            installation,
            instance,
        },
    )
    .await
}
pub fn manifest() -> serde_json::Value {
    rss_mdm_install_support::manifest(&units())
}
struct MdmInstallation<'a> {
    installation: &'a Installation,
    instance: rss_identity_core::InstanceId,
}
impl rss_mdm_install_support::Host for MdmInstallation<'_> {
    fn check_existing<'a>(
        &'a self,
        c: &'a mut PgConnection,
        receipts: &'a [rss_mdm_install_support::Receipt],
    ) -> rss_mdm_install_support::Pending<'a, ()> {
        Box::pin(async move {
            if receipts
                .iter()
                .any(|(name, _, _)| name == "identity-authority-v17")
            {
                verify_installation(c, self.installation, self.instance).await?;
            }
            Ok(())
        })
    }
    fn apply<'a>(
        &'a self,
        tx: &'a mut sqlx::Transaction<'_, sqlx::Postgres>,
        (name, sql): rss_mdm_install_support::Unit,
    ) -> rss_mdm_install_support::Pending<'a, ()> {
        Box::pin(async move { apply_schema(tx, self.installation, self.instance, name, sql).await })
    }
    fn verify<'a>(&'a self, c: &'a mut PgConnection) -> rss_mdm_install_support::Pending<'a, ()> {
        Box::pin(async move { verify_installation(c, self.installation, self.instance).await })
    }
}
async fn apply_schema(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    installation: &Installation,
    instance: rss_identity_core::InstanceId,
    name: &'static str,
    sql: &'static str,
) -> Result<()> {
    let enabled = installation.audit_mode == AuditMode::Ledger
        || !matches!(name, "audit-ledger-v1" | "audit-ledger-runtime-v1");
    if enabled && matches!(name, "audit-v1" | "audit-ledger-v1") {
        let role = if name == "audit-v1" {
            "mdm_audit_owner"
        } else {
            "mdm_ledger_owner"
        };
        sqlx::query("SELECT set_config('role',$1,true)")
            .bind(role)
            .execute(&mut **tx)
            .await
            .map_err(|_| MigrationError::at(name, "owner role"))?;
        execute_schema(tx, name, sql, "component schema").await?;
        sqlx::query("SET LOCAL ROLE mdm_owner")
            .execute(&mut **tx)
            .await
            .map_err(|_| MigrationError::at(name, "restore installer role"))?;
    } else if name == "identity-authority-v17" {
        install_identity_in(tx, installation, instance)
            .await
            .map_err(|_| MigrationError::at(name, "identity installation"))?;
    } else if enabled {
        execute_schema(
            tx,
            name,
            sql,
            "component SQL failed; original transaction rolled back",
        )
        .await?;
    }
    if name == "scope-group-changes-v1" {
        rss_transactional_messaging_postgres::grant_local_projection(
            tx,
            "mdm_scope_group_consumer",
            &rss_transactional_messaging::message::MessagingDomain::parse(
                rss_mdm_scope_service::group_changes::DOMAIN,
            )
            .expect("constant domain"),
            &rss_transactional_messaging::inbox::ConsumerGroup::parse(
                rss_mdm_scope_service::group_changes::CONSUMER,
            )
            .expect("constant consumer"),
        )
        .await
        .map_err(|_| MigrationError::at(name, "local consumer grant"))?;
    }
    if name == "asset-inputs-v1" {
        rss_transactional_messaging_postgres::grant_local_projection(
            tx,
            "mdm_asset_ingress_consumer",
            &rss_transactional_messaging::message::MessagingDomain::parse(
                crate::asset_inputs::DOMAIN,
            )
            .expect("constant domain"),
            &rss_transactional_messaging::inbox::ConsumerGroup::parse(
                crate::asset_inputs::CONSUMER,
            )
            .expect("constant consumer"),
        )
        .await
        .map_err(|_| MigrationError::at(name, "asset consumer grant"))?;
    }
    Ok(())
}

/// The product receipt is immutable to runtime roles; it is not a live schema snapshot.
pub(crate) async fn verify_runtime_installation(
    conn: &mut PgConnection,
) -> std::result::Result<(), sqlx::Error> {
    let safe: bool = sqlx::query_scalar(include_str!("migration/runtime-admission.sql"))
        .fetch_one(&mut *conn)
        .await?;
    if !safe {
        return Err(sqlx::Error::Protocol(
            "installation receipt authority".into(),
        ));
    }
    verify_current_manifest(conn).await
}

pub(crate) async fn verify_current_manifest(
    conn: &mut PgConnection,
) -> std::result::Result<(), sqlx::Error> {
    rss_mdm_install_support::verify_manifest(conn, StorageProfile::Mdm, &units()).await
}
impl AuditMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Ledger => "ledger",
        }
    }
}
pub(crate) async fn owner_admitted(conn: &mut PgConnection) -> Result<bool> {
    rss_mdm_install_support::owner_admitted(conn, StorageProfile::Mdm).await
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
    rss_identity_postgres::grant_platform_subject_admission(tx, "da_access").await?;
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
    verify_profiles(tx, instance).await?;
    Ok(())
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
    // mdm_access deliberately has no role memberships. Its source-admission profile is
    // checked by database::admission using an actual access-role connection at startup.
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
#[path = "../tests/migration/mod.rs"]
mod tests;
