//! Standalone installation consumes capability-owned SQL and the existing resumable executor.
use crate::{
    Error, Result,
    config::{Audit, Database, Installation},
};

use rss_mdm_device_access_runtime::installation as owner;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub database: Database,
    pub installation: Installation,
    pub audit: Audit,
}
pub fn composition(i: &Installation, ledger: bool) -> Result<owner::Standalone> {
    i.validate()?;

    Ok(owner::Standalone {
        product: owner::Composition {
            instance: i.instance,
            management_tenant: i.management_tenant,
        },
        target: i.target,
        lineage: i.lineage,
        tenants: i.tenants()?,
        ledger,
    })
}
pub async fn install(input: Input) -> Result<()> {
    if input.database.user != "da_owner" {
        return Err(Error::Configuration);
    }
    let host = composition(&input.installation, input.audit.ledger())?;

    let binding = host.binding().map_err(|_| Error::Configuration)?;

    rss_mdm_install_support::install(
        &input.database.options()?,
        &binding,
        &owner::standalone_units(input.audit.ledger()),
        &host,
    )
    .await
    .map_err(|_| Error::Storage)
}
pub fn describe() -> serde_json::Value {
    serde_json::json!({"product":"da","version":env!("CARGO_PKG_VERSION"),"plain":rss_mdm_install_support::manifest(&owner::standalone_units(false)),"ledger":rss_mdm_install_support::manifest(&owner::standalone_units(true))})
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseInput {
    pub administrator: Database,
    pub installation: Installation,
    pub passwords: std::collections::BTreeMap<String, std::path::PathBuf>,
}
/// Bootstrap fixed roles in an operator-created empty database. Existing foreign role ownership is rejected.
pub async fn prepare_database(input: DatabaseInput) -> Result<()> {
    use sqlx::Connection;

    input.installation.validate()?;

    const LOGINS: [&str; 5] = [
        "da_owner",
        "da_access",
        "da_identity_runtime",
        "da_identity_maintenance",
        "da_identity_provisioning",
    ];

    if input
        .passwords
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != LOGINS.into_iter().collect()
    {
        return Err(Error::Configuration);
    }
    let mut secrets = std::collections::BTreeMap::<String, zeroize::Zeroizing<String>>::new();

    for (role, path) in &input.passwords {
        secrets.insert(
            role.clone(),
            rss_mdm_install_support::files::secret(path).map_err(|_| Error::Configuration)?,
        );
    }
    let encoded = zeroize::Zeroizing::new(
        serde_json::to_string(
            &secrets
                .iter()
                .map(|(k, v)| (k, v.as_str()))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .map_err(|_| Error::Configuration)?,
    );

    let mut c = sqlx::PgConnection::connect_with(&input.administrator.options()?)
        .await
        .map_err(|_| Error::Storage)?;

    let result=async {
  let mut tx=c.begin().await.map_err(|_|Error::Storage)?;

  sqlx::query("SELECT pg_advisory_xact_lock(3094),set_config('rss.da.installation',$1,true),set_config('rss.da.passwords',$2,true)").bind(input.installation.instance.to_string()).bind(encoded.as_str()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;

  let old:Option<Option<String>>=sqlx::query_scalar("SELECT shobj_description(oid,'pg_authid') FROM pg_roles WHERE rolname='da_owner'").fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;

  let marker=format!("rss-da:{}",input.installation.instance);

  if let Some(old)=old {if old.as_deref()!=Some(&marker){return Err(Error::Admission)}}else{
   let empty:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN('r','p','v','m','S','f'))").fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;

   if !empty{return Err(Error::Admission)}
   sqlx::raw_sql(owner::ROLES_SQL).execute(&mut *tx).await.map_err(|_|Error::Storage)?;

   sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_audit_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_ledger_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; GRANT rss_tmsg_relay,mdm_audit_owner,mdm_ledger_owner,da_identity_runtime,da_identity_maintenance,da_identity_provisioning TO da_owner;").execute(&mut *tx).await.map_err(|_|Error::Storage)?;

   sqlx::raw_sql("DO $$ BEGIN EXECUTE format('COMMENT ON ROLE da_owner IS %L','rss-da:'||current_setting('rss.da.installation')); EXECUTE format('GRANT CREATE ON DATABASE %I TO da_owner,mdm_audit_owner,mdm_ledger_owner',current_database()); END $$;").execute(&mut *tx).await.map_err(|_|Error::Storage)?;

  }
  sqlx::raw_sql("DO $$ DECLARE role_name text; secret text; BEGIN FOR role_name,secret IN SELECT key,value FROM jsonb_each_text(current_setting('rss.da.passwords')::jsonb) LOOP EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L',role_name,secret); EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),role_name); END LOOP; END $$;").execute(&mut *tx).await.map_err(|_|Error::Storage)?;

  tx.commit().await.map_err(|_|Error::Storage)
 }.await;

    let closed = c.close().await.map_err(|_| Error::Storage);

    result.and(closed)
}
