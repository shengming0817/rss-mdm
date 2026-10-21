use super::*;
use anyhow::{Result, ensure};
use sqlx::Executor;
use std::str::FromStr;

fn rejected(result: super::Result<()>, phase: &str) {
    let error = result.expect_err("injected migration fault must be rejected");
    assert_eq!(error.unit, "installation");
    assert_eq!(error.phase, phase);
}

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
    migrate(&options, &installation).await?;
    audit_privilege_drift(&options, &installation, false).await?;
    let mut owner = PgConnection::connect_with(&options).await?;
    let before: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(before.len() == units().len() && before.iter().all(|r| r.2));
    migrate_on(&mut owner, &installation).await?;
    let replay: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(replay == before);
    owner.execute("UPDATE public.mdm_migrations SET name='unrecognized-unit' WHERE name='windows-channel-schema-v1'").await?;
    rejected(
        migrate_on(&mut owner, &installation).await,
        "existing ledger differs or is incomplete",
    );
    owner.execute("UPDATE public.mdm_migrations SET name='windows-channel-schema-v1' WHERE name='unrecognized-unit'").await?;
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
        rejected(
            migrate_on(&mut owner, &changed).await,
            "instance, storage binding or runtime profiles differ",
        );
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
        rejected(
            migrate_on(&mut owner, &installation).await,
            "instance, storage binding or runtime profiles differ",
        );
        sqlx::raw_sql(revoke).execute(&mut owner).await?;
        migrate_on(&mut owner, &installation).await?;
    }
    migrate_on(&mut owner, &installation).await?;
    owner.execute("CREATE TABLE public.installation_evidence(value text); INSERT INTO public.installation_evidence VALUES('preserve')").await?;
    for statement in [
        "UPDATE public.mdm_migrations SET digest=repeat('0',64) WHERE name='transactional-messaging-v1'",
        "UPDATE public.mdm_migrations SET complete=false WHERE name='transactional-messaging-v1'",
        // An older catalog/contract candidate cannot attach to the current binary.
        "UPDATE public.mdm_migrations SET digest=repeat('0',64) WHERE name='inventory-tenant-seed-v1'",
    ] {
        sqlx::raw_sql(statement).execute(&mut owner).await?;
        rejected(
            migrate_on(&mut owner, &installation).await,
            "existing ledger differs or is incomplete",
        );
        ensure!(
            sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
                .fetch_one(&mut owner)
                .await?
                == "preserve"
        );
        // Only this disposable test repairs its injected damage; the installer never does.
        let original = before
            .iter()
            .find(|r| {
                r.0 == if statement.contains("inventory-tenant-seed-v1") {
                    "inventory-tenant-seed-v1"
                } else {
                    "transactional-messaging-v1"
                }
            })
            .unwrap();
        sqlx::query("UPDATE public.mdm_migrations SET digest=$1,complete=true WHERE name=$2")
            .bind(&original.1)
            .bind(&original.0)
            .execute(&mut owner)
            .await?;
        migrate_on(&mut owner, &installation).await?;
    }
    // Missing current schema units must fail without repairing the ledger.
    owner
        .execute("DELETE FROM public.mdm_migrations WHERE name IN ('inventory-v1','inventory-service-schema-v1')")
        .await?;
    rejected(
        migrate_on(&mut owner, &installation).await,
        "existing ledger differs or is incomplete",
    );
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
        if name == "inventory-v1" || name == "inventory-service-schema-v1" {
            sqlx::query("INSERT INTO public.mdm_migrations VALUES($1,$2,$3)")
                .bind(name)
                .bind(digest)
                .bind(complete)
                .execute(&mut owner)
                .await?;
        }
    }
    migrate_on(&mut owner, &installation).await?;
    owner.execute("INSERT INTO public.mdm_migrations VALUES('unrecognized-installation',repeat('a',64),true)").await?;
    rejected(
        migrate_on(&mut owner, &installation).await,
        "existing ledger differs or is incomplete",
    );
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 + 1
    );
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
            .fetch_one(&mut owner)
            .await?
            == "preserve"
    );
    owner
        .execute("DELETE FROM public.mdm_migrations WHERE name='unrecognized-installation'")
        .await?;
    migrate_on(&mut owner, &installation).await?;
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
        rejected(
            crate::migration::migrate(options, installation).await,
            "instance, storage binding or runtime profiles differ",
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
            rejected(
                crate::migration::migrate(options, installation).await,
                "instance, storage binding or runtime profiles differ",
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

#[test]
fn resumable_prefix_requires_exact_complete_ordered_source_units() {
    let source = vec![("a", "SELECT 1;"), ("b", "SELECT 2;"), ("c", "SELECT 3;")];
    let row = |i: usize| {
        (
            source[i].0.to_owned(),
            format!("{:x}", Sha256::digest(source[i].1)),
            true,
        )
    };
    assert!(resumable_ledger(&[], &source));
    assert!(resumable_ledger(&[row(0)], &source));
    assert!(resumable_ledger(&[row(1), row(0)], &source)); // Database row order is irrelevant.
    assert!(!resumable_ledger(&[row(0), row(2)], &source));
    assert!(!resumable_ledger(&[row(0), row(0)], &source));
    let mut incomplete = row(0);
    incomplete.2 = false;
    assert!(!resumable_ledger(&[incomplete], &source));
    let mut changed = row(0);
    changed.1 = "changed".into();
    assert!(!resumable_ledger(&[changed], &source));
    assert!(!accepted_ledger(&[row(0)], &source)); // Runtime never admits a partial installation.
}
#[test]
fn every_component_keeps_transaction_control_with_the_installer() {
    for (name, sql) in units() {
        assert!(
            transaction_body(sql).is_ok(),
            "unsupported transaction envelope in {name}"
        );
    }
    assert_eq!(
        transaction_body("-- header\nBEGIN;\nSELECT 1;\nCOMMIT;\n-- end").unwrap(),
        vec!["SELECT 1;\n"]
    );
    assert_eq!(
        transaction_body("SELECT 1;\nBEGIN;\nSELECT 2;\nCOMMIT;\nBEGIN;\nSELECT 3;\nCOMMIT;")
            .unwrap(),
        vec!["SELECT 1;\n", "SELECT 2;\n", "SELECT 3;\n"]
    );
    assert!(transaction_body("BEGIN;\nBEGIN;\nSELECT 1;\nCOMMIT;\nCOMMIT;").is_err());
    assert!(transaction_body("SELECT 1;\nCOMMIT;\nSELECT 2;").is_err());
    assert!(transaction_body("BEGIN;\nSELECT 1;").is_err());
}
#[tokio::test]
#[ignore = "MODULE=installation.migration: SQL effect and completion receipt recover atomically"]
async fn failed_unit_rolls_back_schema_and_can_resume_original_name() -> Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
    };
    migrate(&options, &installation).await?;
    let mut owner = PgConnection::connect_with(&options).await?;
    let name = "test-resumable-unit";
    let failed = apply_unit(
        &mut owner,
        &installation,
        installation.validate()?,
        name,
        "BEGIN;\nCREATE TABLE public.resumable_unit_evidence(value integer);\nSELECT 1/0;\nCOMMIT;",
    )
    .await;
    ensure!(failed.is_err());
    // Force SQLx's queued rollback to finish before querying both effects.
    ensure!(sqlx::query_scalar::<_,bool>("SELECT to_regclass('public.resumable_unit_evidence') IS NULL AND NOT EXISTS(SELECT 1 FROM public.mdm_migrations WHERE name='test-resumable-unit')").fetch_one(&mut owner).await?);
    let sql = "BEGIN;\nCREATE TABLE public.resumable_unit_evidence(value integer);\nINSERT INTO public.resumable_unit_evidence VALUES(7);\nCOMMIT;";
    apply_unit(
        &mut owner,
        &installation,
        installation.validate()?,
        name,
        sql,
    )
    .await?;
    apply_unit(
        &mut owner,
        &installation,
        installation.validate()?,
        name,
        sql,
    )
    .await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.resumable_unit_evidence WHERE value=7"
        )
        .fetch_one(&mut owner)
        .await?
            == 1
    );
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT complete FROM public.mdm_migrations WHERE name='test-resumable-unit'"
        )
        .fetch_one(&mut owner)
        .await?
    );
    owner.execute("DROP TABLE public.resumable_unit_evidence; DELETE FROM public.mdm_migrations WHERE name='test-resumable-unit'").await?;
    owner.close().await?;
    Ok(())
}
