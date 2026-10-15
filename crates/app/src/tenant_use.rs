use super::*;
/// Commit a permanent first-use claim before any initialization or host startup work.
pub(crate) async fn claim_use(
    conn: &mut PgConnection,
    installation: &Installation,
    tenant: &str,
    expected_epoch: i64,
) -> std::result::Result<(), Error> {
    if validate_tenant(installation, tenant).is_err()
        || rss_transactional_messaging::fence::Epoch::new(expected_epoch).is_err()
    {
        return Err(Error::Configuration(ConfigIssue::IdentityConfiguration));
    }
    let mut tx = conn
        .begin()
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    let result: std::result::Result<(), Error> = async {
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL READ COMMITTED; SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='2s'")
            .execute(&mut *tx).await.map_err(|_| Error::Unavailable(Failure::Database))?;
        sqlx::query("SELECT pg_advisory_xact_lock(2346)")
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        verify_read_profile(&mut tx).await?;
        migration::verify_identity(&mut tx, installation)
            .await
            .map_err(|_| Error::Configuration(ConfigIssue::IdentityConfiguration))?;
        let instance = installation
            .validate()
            .map_err(|_| Error::Configuration(ConfigIssue::IdentityConfiguration))?;
        let mode = match installation.audit_mode {
            migration::AuditMode::Plain => "plain",
            migration::AuditMode::Ledger => "ledger",
        };
        let valid: bool =
            sqlx::query_scalar("SELECT public.claim_tenant_use($1::uuid,$2,$3::uuid,$4,$5,$6)")
                .bind(tenant)
                .bind(expected_epoch)
                .bind(instance.to_string())
                .bind(&installation.target[..])
                .bind(&installation.lineage[..])
                .bind(mode)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| Error::Unavailable(Failure::Database))?;
        if !valid {
            return Err(Error::Configuration(ConfigIssue::IdentityConfiguration));
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        tx.rollback()
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        return Err(error);
    }
    tx.commit()
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    Ok(())
}

/// These installation-owned read relations augment the closed access-role union.
pub(crate) const ACCESS_CONTRACT: &str = r#"{"tables":[],"functions":[{"name":"public.claim_tenant_use","search_path":"search_path=pg_catalog, pg_temp"}],"external_relations":["public.mdm_installation","public.mdm_tenants","rss_transactional_messaging.tenant_epoch"],"verified_schemas":[]}"#;
pub(crate) async fn verify_read_profile(conn: &mut PgConnection) -> std::result::Result<(), Error> {
    let valid: bool = sqlx::query_scalar("SELECT has_schema_privilege(current_user,'public','USAGE') AND has_schema_privilege(current_user,'rss_transactional_messaging','USAGE') AND bool_and(has_table_privilege(current_user,r,'SELECT') AND NOT has_table_privilege(current_user,r,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND NOT has_any_column_privilege(current_user,r,'INSERT,UPDATE,REFERENCES')) FROM unnest(ARRAY['public.mdm_installation','public.mdm_tenants','rss_transactional_messaging.tenant_epoch']) r")
        .fetch_one(&mut *conn).await.map_err(|_| Error::Unavailable(Failure::AccessAdmission))?;
    if !valid {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    // Pin the complete function, not merely its name or SECURITY DEFINER flag.
    let body = include_str!("../schema/installation.sql")
        .split("$tenant_use$")
        .nth(1)
        .expect("installation function body");
    let valid:bool=sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(p.prosecdef AND p.provolatile='v' AND p.prokind='f' AND p.prorettype='boolean'::regtype AND l.lanname='plpgsql' AND pg_get_userbyid(p.proowner)='mdm_owner' AND p.proargtypes='2950 20 2950 17 17 25'::oidvector AND p.proargnames=ARRAY['tenant','expected_epoch','instance','expected_target','expected_lineage','expected_audit_mode'] AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND p.prosrc=$1 AND has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 OR a.is_grantable OR pg_get_userbyid(a.grantee) NOT IN ('mdm_owner','mdm_access','mdm_identity_runtime','mdm_identity_maintenance','mdm_identity_provisioning'))),false) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname='claim_tenant_use'")
        .bind(body).fetch_one(conn).await.map_err(|_| Error::Unavailable(Failure::AccessAdmission))?;
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
