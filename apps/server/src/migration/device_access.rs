//! DA subassembly installation; independent product binding, shared public component owners.
use super::{Installation, MigrationError};
use rss_mdm_install_support::{Host, Pending, Receipt, StorageProfile, Unit, execute_schema};
use sqlx::{PgConnection, Postgres, Transaction, postgres::PgConnectOptions};
const DA: StorageProfile = StorageProfile::Da;
pub fn units() -> Vec<Unit> {
    vec![
        (
            "authorization-installation-v1",
            rss_mdm_authorization_service::installation::DA_INSTALL_SQL,
        ),
        (
            "registration-identity-v1",
            rss_mdm_registration_service::install_sql(DA),
        ),
        (
            "authorization-v1",
            rss_mdm_authorization_service::install_sql(DA),
        ),
        (
            "authorization-authority-v1",
            rss_mdm_authorization_service::authority_sql(DA),
        ),
        ("pki-v1", rss_mdm_pki_service::install_sql(DA)),
        (
            "pki-observations-v1",
            rss_mdm_pki_service::observations::install_sql(DA),
        ),
        ("signing-v1", rss_mdm_task_trust::trust::install_sql(DA)),
        (
            "signing-observations-v1",
            rss_mdm_task_trust::observations::install_sql(DA),
        ),
        (
            "registration-relations-v1",
            rss_mdm_registration_service::relations_sql(DA),
        ),
        (
            "authorization-relations-v1",
            rss_mdm_authorization_service::relations_sql(DA),
        ),
        (
            "registration-current-da-v1",
            rss_mdm_registration_service::device::endpoints::DA_INSTALL_SQL,
        ),
        ("policy-v1", rss_mdm_policy_postgres::migration_sql(DA)),
        (
            "policy-targets-v1",
            rss_mdm_policy_postgres::device_access::INSTALL_SQL,
        ),
        (
            "bindings-v1",
            rss_mdm_device_access_postgres::device_access::INSTALL_SQL,
        ),
        (
            "authority-v1",
            rss_mdm_device_access_postgres::AUTHORITY_SQL,
        ),
        (
            "enterprise-v1",
            rss_mdm_device_access_postgres::enterprise::INSTALL_SQL,
        ),
        (
            "tasks-v1",
            rss_mdm_device_access_postgres::device_access::execution::INSTALL_SQL,
        ),
        (
            "platform-sso-v1",
            rss_mdm_device_access_postgres::platform_sso::INSTALL_SQL,
        ),
        (
            "recovery-material-v1",
            rss_mdm_recovery_credentials::install_sql(DA),
        ),
        (
            "credential-tasks-v1",
            rss_mdm_recovery_credentials::tasks_sql(DA),
        ),
        (
            "credential-relations-v1",
            rss_mdm_recovery_credentials::task_relations_sql(DA),
        ),
        (
            "directory-v1",
            rss_mdm_device_access_postgres::DIRECTORY_SQL,
        ),
        (
            "identity-proof-v1",
            rss_mdm_device_access_postgres::PROOF_SQL,
        ),
        (
            "host-grants-v1",
            include_str!("../../schema/da-host-grants.sql"),
        ),
    ]
}
fn manifests() -> Vec<&'static str> {
    vec![
        rss_mdm_authorization_service::installation::DA_OBJECT_MANIFEST,
        rss_mdm_registration_service::identity_object_manifest(DA),
        rss_mdm_registration_service::DA_IDENTITY_PROJECTION_MANIFEST,
        rss_mdm_authorization_service::object_manifest(DA),
        rss_mdm_pki_service::object_manifest(DA),
        rss_mdm_task_trust::object_manifest(DA),
        rss_mdm_policy_postgres::object_manifest(DA),
        rss_mdm_recovery_credentials::object_manifest(DA),
        rss_mdm_device_access_postgres::admission::OBJECTS,
    ]
}
pub async fn install(
    options: &PgConnectOptions,
    installation: &Installation,
) -> Result<(), MigrationError> {
    installation.validate()?;
    let instance = uuid::Uuid::parse_str(&installation.instance_id)
        .map_err(|_| MigrationError::at("da", "instance"))?;
    let binding = rss_mdm_install_support::Binding::new(
        DA,
        instance,
        installation.target,
        installation.lineage,
        installation.audit_mode.as_str().into(),
    )?;
    rss_mdm_install_support::install(options, &binding, &units(), &Composition { instance }).await
}
struct Composition {
    instance: uuid::Uuid,
}
impl Host for Composition {
    fn check_existing<'a>(
        &'a self,
        _c: &'a mut PgConnection,
        _r: &'a [Receipt],
    ) -> Pending<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        (name, sql): Unit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            execute_schema(tx, name, sql, "DA owner schema").await?;
            if name == "authorization-installation-v1" {
                let management: uuid::Uuid = sqlx::query_scalar(
                    "SELECT management_tenant_id FROM public.mdm_installation WHERE instance_id=$1",
                )
                .bind(self.instance)
                .fetch_one(&mut **tx)
                .await
                .map_err(|_| MigrationError::at(name, "shared Identity instance"))?;
                rss_mdm_authorization_service::installation::bind_da_in(
                    tx,
                    self.instance,
                    management,
                )
                .await
                .map_err(|_| MigrationError::at(name, "authorization installation"))?;
            }
            Ok(())
        })
    }
    fn verify<'a>(&'a self, c: &'a mut PgConnection) -> Pending<'a, ()> {
        Box::pin(async move {
            verify_runtime(c)
                .await
                .map_err(|_| MigrationError::at("da", "complete owner catalog"))
        })
    }
}
pub async fn verify_runtime(c: &mut PgConnection) -> Result<(), sqlx::Error> {
    rss_mdm_install_support::verify_manifest(c, DA, &units()).await?;
    rss_mdm_install_support::catalog::verify_schema(c, DA, &manifests()).await?;
    rss_mdm_device_access_postgres::admission::verify_authority(c).await
}

/// Exact hosted DA access rights; cross-product Agent reads remain explicit and read-only.
pub async fn verify_access(
    c: &mut PgConnection,
    audit: &crate::config::AuditConfig,
) -> Result<(), sqlx::Error> {
    let mut contracts = vec![
        rss_mdm_registration_service::identity_access_contract(DA),
        rss_mdm_authorization_service::access_contract(DA),
        rss_mdm_task_trust::access_contract(DA),
        rss_mdm_pki_service::access_contract(DA),
        rss_mdm_policy_postgres::device_access::ACCESS_CONTRACT,
        rss_mdm_recovery_credentials::access_contract(DA),
        rss_mdm_device_access_postgres::admission::ACCESS_CONTRACT,
        rss_mdm_audit_integration::ACCESS_CONTRACT,
        include_str!("../../schema/da-access.json"),
    ];
    if matches!(audit, crate::config::AuditConfig::Ledger { .. }) {
        contracts.push(r#"{"tables":[],"functions":[{"name":"rss_ledger.prepare_append","search_path":"search_path=pg_catalog, rss_ledger"},{"name":"rss_ledger.insert_entry","search_path":"search_path=pg_catalog, rss_ledger"}],"external_relations":["rss_ledger.heads","rss_ledger.entries"],"verified_schemas":[]}"#);
    }
    if !rss_mdm_backend_postgres_support::access_admission::verify(c, "da_access", &contracts)
        .await?
    {
        return Err(sqlx::Error::Protocol("DA access contract".into()));
    }
    for table in [
        "mdm_access.devices",
        "mdm_access.registrations",
        "mdm_access.credentials",
        "mdm_access.certificate_issuances",
        "mdm_access.report_sources",
        "mdm_agent.bindings",
        "mdm_access.authorization_rules",
        "mdm_access.user_groups",
        "mdm_access.api_keys",
        "mdm_access.api_network_policy",
    ] {
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_class WHERE oid=to_regclass($1) AND relkind='r' AND relrowsecurity AND relforcerowsecurity AND has_table_privilege(current_user,oid,'SELECT') AND NOT has_table_privilege(current_user,oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND NOT has_any_column_privilege(current_user,oid,'INSERT,UPDATE,REFERENCES'))").bind(table).fetch_one(&mut *c).await?;
        if !valid {
            return Err(sqlx::Error::Protocol(format!(
                "DA Agent read contract: {table}"
            )));
        }
    }
    Ok(())
}
