//! Trusted host binding for the DA authorization installation.
use crate::Error;
use sqlx::PgConnection;
/// Apply after the shared installer has reserved the DA installation instance.
macro_rules! installation {
    ($table:literal) => {
        pub const DA_INSTALL_SQL: &str = concat!("CREATE TABLE ", $table, "(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),instance_id uuid NOT NULL UNIQUE REFERENCES rss_da.installation_binding(instance_id),management_tenant_id uuid NOT NULL UNIQUE); REVOKE ALL ON ", $table, " FROM PUBLIC; GRANT SELECT ON ", $table, " TO da_access,da_identity_runtime;");
        pub const DA_OBJECT_MANIFEST: &str = concat!(r#"{"tables":[""#,$table,r#""],"functions":[]}"#);
    };
}
installation!("rss_da.authorization_installation");
/// The host supplies its immutable Identity coordinates, never request input.
pub async fn bind_da_in(
    c: &mut PgConnection,
    instance: uuid::Uuid,
    management_tenant: uuid::Uuid,
) -> Result<(), Error> {
    if instance.is_nil() || management_tenant.is_nil() {
        return Err(Error::Configuration);
    }
    sqlx::query("INSERT INTO rss_da.authorization_installation(instance_id,management_tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(instance).bind(management_tenant).execute(&mut *c).await.map_err(crate::database::db)?;
    let valid: bool = sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(instance_id=$1 AND management_tenant_id=$2),false) FROM rss_da.authorization_installation").bind(instance).bind(management_tenant).fetch_one(c).await.map_err(crate::database::db)?;
    if !valid {
        return Err(Error::Configuration);
    }
    Ok(())
}
