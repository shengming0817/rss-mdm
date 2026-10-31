pub async fn verify_authority(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let bodies = [
        "configuration_device_key",
        "configuration_windows_pending_operations",
        "configuration_windows_wake_candidates",
    ]
    .map(|name| {
        super::INSTALL_SQL
            .split_once(&format!("CREATE FUNCTION mdm_planning.{name}("))
            .expect("owner function")
            .1
            .split("$$")
            .nth(1)
            .expect("owner body")
    });
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(bodies[0])
        .bind(bodies[1])
        .bind(bodies[2])
        .fetch_optional(&mut *c)
        .await?;
    if let Some(name) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "configuration authority rejected: {name}"
        )));
    }
    let valid:bool=sqlx::query_scalar("SELECT relkind='v' AND reloptions @> ARRAY['security_invoker=true','security_barrier=true'] AND relowner=(SELECT oid FROM pg_roles WHERE rolname='mdm_owner') FROM pg_class WHERE oid='mdm_planning.configuration_execution_facts'::regclass").fetch_one(c).await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "configuration directory projection".into(),
        ));
    }
    Ok(())
}
