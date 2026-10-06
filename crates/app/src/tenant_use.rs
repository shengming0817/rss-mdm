use super::*;
/// Read-only binding validation. Never substitutes a current epoch for the caller's expected epoch.
pub(crate) async fn claim_use(
    conn: &mut PgConnection,
    installation: &Installation,
    tenant: &str,
    expected_epoch: i64,
) -> std::result::Result<(), Error> {
    if installation.validate().is_err()
        || rss_request_context::TenantId::parse(tenant).is_err()
        || rss_transactional_messaging::fence::Epoch::new(expected_epoch).is_err()
    {
        return Err(Error::Configuration(ConfigIssue::IdentityConfiguration));
    }
    let mut tx = conn
        .begin()
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','2000',true)",
    )
    .bind(tenant)
    .execute(&mut *tx)
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    verify_read_profile(&mut tx).await?;
    migration::verify_identity(&mut tx, installation)
        .await
        .map_err(|_| Error::Configuration(ConfigIssue::IdentityConfiguration))?;
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.mdm_tenants t JOIN rss_transactional_messaging.tenant_epoch e USING(tenant_id) WHERE tenant_id=$1::uuid AND e.epoch=$2)")
        .bind(tenant).bind(expected_epoch).fetch_one(&mut *tx).await.map_err(|_| Error::Unavailable(Failure::Database))?;
    tx.rollback()
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    if !valid {
        return Err(Error::Configuration(ConfigIssue::IdentityConfiguration));
    }
    Ok(())
}

/// These installation-owned read relations augment the closed access-role union.
pub(crate) const ACCESS_CONTRACT: &str = r#"{"tables":[],"functions":[],"external_relations":["public.mdm_installation","public.mdm_tenants","rss_transactional_messaging.tenant_epoch"],"verified_schemas":[]}"#;
pub(crate) async fn verify_read_profile(conn: &mut PgConnection) -> std::result::Result<(), Error> {
    let valid: bool = sqlx::query_scalar("SELECT has_schema_privilege(current_user,'public','USAGE') AND has_schema_privilege(current_user,'rss_transactional_messaging','USAGE') AND bool_and(has_table_privilege(current_user,r,'SELECT') AND NOT has_table_privilege(current_user,r,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND NOT has_any_column_privilege(current_user,r,'INSERT,UPDATE,REFERENCES')) FROM unnest(ARRAY['public.mdm_installation','public.mdm_tenants','rss_transactional_messaging.tenant_epoch']) r")
        .fetch_one(conn).await.map_err(|_| Error::Unavailable(Failure::AccessAdmission))?;
    if !valid {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    Ok(())
}
pub(crate) async fn claim_database_use(
    database: &config::Database,
    installation: &Installation,
    tenant: &str,
    epoch: i64,
) -> std::result::Result<(), Error> {
    let mut conn = tokio::time::timeout(
        Duration::from_secs(5),
        PgConnection::connect_with(&database.options()?),
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        claim_use(&mut conn, installation, tenant, epoch),
    )
    .await
    .unwrap_or(Err(Error::Unavailable(Failure::Database)));
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(5), conn.close()).await,
        Ok(Ok(()))
    );
    match result {
        Err(error) => Err(error),
        Ok(()) if closed => Ok(()),
        Ok(()) => Err(Error::Unavailable(Failure::Database)),
    }
}
