//! MDM host integration for the single DA installation owner.
use super::{Installation, MigrationError};
use rss_mdm_device_access_runtime::installation as da;
use rss_mdm_install_support::{Host, Pending, Receipt, StorageProfile, Unit};
use sqlx::{Connection, PgConnection, Postgres, Transaction, postgres::PgConnectOptions};
const DA: StorageProfile = StorageProfile::Da;
pub fn units() -> Vec<Unit> {
    let mut units = da::units();
    units.push((
        "mdm-host-grants-v1",
        include_str!("../../schema/da-host-grants.sql"),
    ));
    units
}
pub async fn install(
    options: &PgConnectOptions,
    installation: &Installation,
) -> Result<(), MigrationError> {
    installation.validate()?;
    let instance = uuid::Uuid::parse_str(&installation.instance_id)
        .map_err(|_| MigrationError::at("da", "instance"))?;
    let mut c = PgConnection::connect_with(options)
        .await
        .map_err(|_| MigrationError::at("da", "installation connection"))?;
    let management = sqlx::query_scalar(
        "SELECT management_tenant_id FROM public.mdm_installation WHERE instance_id=$1",
    )
    .bind(instance)
    .fetch_one(&mut c)
    .await;
    c.close()
        .await
        .map_err(|_| MigrationError::at("da", "installation connection close"))?;
    let composition = Composition(da::Composition {
        instance,
        management_tenant: management
            .map_err(|_| MigrationError::at("da", "shared Identity instance"))?,
    });
    let binding = rss_mdm_install_support::Binding::new(
        DA,
        instance,
        installation.target,
        installation.lineage,
        installation.audit_mode.as_str().into(),
    )?;
    rss_mdm_install_support::install(options, &binding, &units(), &composition).await
}
struct Composition(da::Composition);
impl Host for Composition {
    fn check_existing<'a>(&'a self, c: &'a mut PgConnection, r: &'a [Receipt]) -> Pending<'a, ()> {
        self.0.check_existing(c, r)
    }
    fn apply<'a>(&'a self, tx: &'a mut Transaction<'_, Postgres>, unit: Unit) -> Pending<'a, ()> {
        self.0.apply(tx, unit)
    }
    fn verify<'a>(&'a self, c: &'a mut PgConnection) -> Pending<'a, ()> {
        self.0.verify(c)
    }
}
pub async fn verify_runtime(c: &mut PgConnection) -> Result<(), sqlx::Error> {
    rss_mdm_install_support::verify_manifest(c, DA, &units()).await?;
    da::verify_catalog(c).await
}
/// Exact hosted DA access rights; cross-product Agent reads remain explicit and read-only.
pub async fn verify_access(
    c: &mut PgConnection,
    audit: &crate::config::AuditConfig,
) -> Result<(), sqlx::Error> {
    let mut contracts = da::access_contracts();
    contracts.push(include_str!("../../schema/da-access.json"));
    if matches!(audit, crate::config::AuditConfig::Ledger { .. }) {
        contracts.push(r#"{"tables":[],"functions":[{"name":"rss_ledger.prepare_append","search_path":"search_path=pg_catalog, rss_ledger"},{"name":"rss_ledger.insert_entry","search_path":"search_path=pg_catalog, rss_ledger"}],"external_relations":["rss_ledger.heads","rss_ledger.entries"],"verified_schemas":[]}"#);
    }
    if !rss_mdm_install_support::access_admission::verify(c, "da_access", &contracts).await? {
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
