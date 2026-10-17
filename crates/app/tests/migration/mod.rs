use super::*;
use anyhow::{Result, ensure};
use sqlx::Executor;
use std::str::FromStr;

#[tokio::test]
#[ignore = "make t2: fresh installation and rejected ledger in a disposable database"]
async fn fresh_installation_replay_and_mismatch_rejection() -> Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
    };
    let mut owner = PgConnection::connect_with(&options).await?;
    migrate_on(&mut owner, &installation).await?;
    let before: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(before.len() == units().len() && before.iter().all(|r| r.2));
    migrate_on(&mut owner, &installation).await?;
    owner.execute("UPDATE public.mdm_migrations SET name='windows-channel-schema-v1' WHERE name='windows-channel-schema-v2'").await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    owner.execute("UPDATE public.mdm_migrations SET name='windows-channel-schema-v2' WHERE name='windows-channel-schema-v1'").await?;
    migrate_on(&mut owner, &installation).await?;
    for field in ["instance_id", "target", "lineage", "audit_mode"] {
        let mut changed = serde_json::to_value(&installation)?;
        changed[field] = match field {
            "instance_id" => serde_json::json!("55555555-5555-4555-8555-555555555555"),
            "audit_mode" => serde_json::json!("ledger"),
            "target" => serde_json::json!(vec![3; 16]),
            _ => serde_json::json!(vec![4; 16]),
        };
        let changed: Installation = serde_json::from_value(changed)?;
        ensure!(migrate_on(&mut owner, &changed).await.is_err());
    }
    for (grant, revoke) in [
        (
            "GRANT SELECT ON identity_authority.accounts TO mdm_identity_audit",
            "REVOKE SELECT ON identity_authority.accounts FROM mdm_identity_audit",
        ),
        (
            "GRANT INSERT ON rss_audit.records TO mdm_identity_audit",
            "REVOKE INSERT ON rss_audit.records FROM mdm_identity_audit",
        ),
        (
            "GRANT DELETE ON identity_authority.accounts TO mdm_identity_runtime",
            "REVOKE DELETE ON identity_authority.accounts FROM mdm_identity_runtime",
        ),
        (
            "GRANT SELECT ON identity_authority.sessions TO mdm_identity_maintenance",
            "REVOKE SELECT ON identity_authority.sessions FROM mdm_identity_maintenance",
        ),
    ] {
        sqlx::raw_sql(grant).execute(&mut owner).await?;
        ensure!(migrate_on(&mut owner, &installation).await.is_err());
        sqlx::raw_sql(revoke).execute(&mut owner).await?;
    }
    audit_privilege_drift(&options, &installation, false).await?;
    migrate_on(&mut owner, &installation).await?;
    owner.execute("CREATE TABLE public.installation_evidence(value text); INSERT INTO public.installation_evidence VALUES('preserve')").await?;
    for statement in [
        "UPDATE public.mdm_migrations SET digest=repeat('0',64) WHERE name='transactional-messaging-v1'",
        "UPDATE public.mdm_migrations SET complete=false WHERE name='transactional-messaging-v1'",
    ] {
        sqlx::raw_sql(statement).execute(&mut owner).await?;
        ensure!(migrate_on(&mut owner, &installation).await.is_err());
        ensure!(
            sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
                .fetch_one(&mut owner)
                .await?
                == "preserve"
        );
        // Only this disposable test repairs its injected damage; the installer never does.
        let original = before
            .iter()
            .find(|r| r.0 == "transactional-messaging-v1")
            .unwrap();
        sqlx::query("UPDATE public.mdm_migrations SET digest=$1,complete=true WHERE name=$2")
            .bind(&original.1)
            .bind(&original.0)
            .execute(&mut owner)
            .await?;
    }
    // Missing current schema units must fail without repairing the ledger.
    owner
        .execute("DELETE FROM public.mdm_migrations WHERE name IN ('inventory-v2','inventory-service-schema-v1')")
        .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 - 2
    );
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
            .fetch_one(&mut owner)
            .await?
            == "preserve"
    );
    for (name, digest, complete) in &before {
        if name == "inventory-v2" || name == "inventory-service-schema-v1" {
            sqlx::query("INSERT INTO public.mdm_migrations VALUES($1,$2,$3)")
                .bind(name)
                .bind(digest)
                .bind(complete)
                .execute(&mut owner)
                .await?;
        }
    }
    owner.execute("INSERT INTO public.mdm_migrations VALUES('unrecognized-installation',repeat('a',64),true)").await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 + 1
    );
    owner.close().await?;
    Ok(())
}

#[test]
fn installation_validates_stable_coordinates() {
    let mut installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
    };
    assert!(installation.validate().is_ok());
    installation.target = [0; 16];
    assert!(installation.validate().is_err());
}

#[tokio::test]
#[ignore = "MODULE=installation.migration: incompatible state rejection across forced RLS"]
async fn field_scope_migration_rejects_hidden_state_and_restores_rls() -> Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
    };
    let mut owner = PgConnection::connect_with(&options).await?;
    migrate_on(&mut owner, &installation).await?;
    let tenant = uuid::Uuid::new_v4().to_string();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&tenant)
        .execute(&mut owner)
        .await?;
    owner.execute("INSERT INTO mdm.manual_assignments VALUES(current_setting('rss.tenant_id')::uuid,'old-device','custom.old',1,'{}')").await?;
    owner
        .execute("SELECT set_config('rss.tenant_id','',false)")
        .await?;
    let error = sqlx::raw_sql(rss_mdm_inventory_postgres::FIELD_SCOPES_SQL)
        .execute(&mut owner)
        .await
        .expect_err("occupied legacy state must reject the field-scope migration");
    let database_error = error
        .as_database_error()
        .expect("migration rejection must be a database error");
    ensure!(database_error.code().as_deref() == Some("P0001"));
    ensure!(
        database_error.message()
            == "incompatible state in mdm.manual_assignments; matching fresh installation required"
    );
    owner.execute("ROLLBACK").await?;
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT relforcerowsecurity FROM pg_class WHERE oid='mdm.manual_assignments'::regclass"
        )
        .fetch_one(&mut owner)
        .await?
    );
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&tenant)
        .execute(&mut owner)
        .await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mdm.manual_assignments WHERE device='old-device'"
        )
        .fetch_one(&mut owner)
        .await?
            == 1
    );
    Ok(())
}

async fn audit_privilege_drift(
    options: &PgConnectOptions,
    installation: &Installation,
    ledger: bool,
) -> Result<()> {
    let admin_options = PgConnectOptions::from_str(&std::env::var("MDM_ADMIN_URL")?)?
        .database(options.get_database().unwrap())
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut admin = PgConnection::connect_with(&admin_options).await?;
    let observer = &mut admin;
    let role = format!("audit_set_{}", uuid::Uuid::new_v4().simple());
    for (grant, revoke) in [
        (
            "GRANT CREATE ON SCHEMA rss_ledger TO mdm_identity_audit",
            "REVOKE CREATE ON SCHEMA rss_ledger FROM mdm_identity_audit",
        ),
        (
            "GRANT INSERT ON rss_ledger.entries TO mdm_identity_audit",
            "REVOKE INSERT ON rss_ledger.entries FROM mdm_identity_audit",
        ),
        (
            "GRANT UPDATE(tag) ON rss_ledger.entries TO mdm_identity_audit",
            "REVOKE UPDATE(tag) ON rss_ledger.entries FROM mdm_identity_audit",
        ),
        (
            "CREATE ROLE audit_set_only NOLOGIN; GRANT audit_set_only TO mdm_identity_audit WITH INHERIT FALSE; GRANT DELETE ON rss_ledger.entries TO audit_set_only",
            "REVOKE DELETE ON rss_ledger.entries FROM audit_set_only; REVOKE audit_set_only FROM mdm_identity_audit; DROP ROLE audit_set_only",
        ),
        (
            "GRANT INSERT ON rss_ledger.entries TO PUBLIC",
            "REVOKE INSERT ON rss_ledger.entries FROM PUBLIC",
        ),
        (
            "CREATE FUNCTION rss_ledger.unexpected() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            "DROP FUNCTION rss_ledger.unexpected()",
        ),
    ] {
        let grant = grant.replace("audit_set_only", &role);
        let revoke = revoke.replace("audit_set_only", &role);
        sqlx::raw_sql(sqlx::AssertSqlSafe(grant.clone()))
            .execute(&mut *observer)
            .await?;
        ensure!(
            crate::migration::migrate(options, installation)
                .await
                .is_err(),
            "installer accepted {grant}"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(revoke))
            .execute(&mut *observer)
            .await?;
        crate::migration::migrate(options, installation).await?;
    }
    if !ledger {
        for (grant, revoke) in [
            (
                "GRANT USAGE ON SCHEMA rss_ledger TO mdm_identity_audit",
                "REVOKE USAGE ON SCHEMA rss_ledger FROM mdm_identity_audit",
            ),
            (
                "GRANT SELECT ON rss_ledger.entries TO mdm_identity_audit",
                "REVOKE SELECT ON rss_ledger.entries FROM mdm_identity_audit",
            ),
            (
                "GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) TO mdm_identity_audit",
                "REVOKE EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) FROM mdm_identity_audit",
            ),
        ] {
            sqlx::raw_sql(grant).execute(&mut *observer).await?;
            ensure!(
                crate::migration::migrate(options, installation)
                    .await
                    .is_err()
            );
            sqlx::raw_sql(revoke).execute(&mut *observer).await?;
            crate::migration::migrate(options, installation).await?;
        }
    }
    crate::migration::migrate(options, installation).await?;
    admin.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=installation.migration: Ledger installer privileges"]
async fn ledger_installation_rejects_audit_privilege_drift() -> Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        audit_mode: AuditMode::Ledger,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
    };
    migrate(&options, &installation).await?;
    audit_privilege_drift(&options, &installation, true).await
}
