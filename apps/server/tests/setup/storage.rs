//! Product startup owns installation compatibility; capability owners retain security checks.
use super::*;
use crate::test_support::{Config, authority::Authority, http::Browser, runtime};
use anyhow::{Result, ensure};
use axum::http::{Method, StatusCode};

fn configuration() -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(std::env::var(
        "MDM_TEST_CONFIG",
    )?)?)?)
}

fn administrator(journal: &Journal) -> Result<crate::config::Database> {
    let url = url::Url::parse(&std::env::var("MDM_ADMIN_URL")?)?;
    Ok(crate::config::Database {
        host: url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("admin host"))?
            .into(),
        port: url.port().ok_or_else(|| anyhow::anyhow!("admin port"))?,
        name: url.path().trim_start_matches('/').into(),
        user: url.username().into(),
        password_file: journal.secret(
            "administrator-password",
            url.password()
                .ok_or_else(|| anyhow::anyhow!("admin password"))?
                .as_bytes(),
        )?,
        ca_file: std::env::var("PG_CA_FILE")?.into(),
    })
}

async fn connected(config: &Config) -> Result<()> {
    let db = crate::Database::connect(config.access_options()?, &config.audit).await?;
    db.close().await;
    Ok(())
}

async fn reject_and_restore(
    root: &mut sqlx::PgConnection,
    config: &Config,
    damage: String,
    restore: String,
) -> Result<()> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(damage.clone()))
        .execute(&mut *root)
        .await?;
    let admitted = crate::Database::connect(config.access_options()?, &config.audit).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
        .execute(root)
        .await?;
    let rejected = match admitted {
        Ok(db) => {
            db.close().await;
            false
        }
        Err(_) => true,
    };
    ensure!(rejected, "unsafe startup admitted: {damage}");
    connected(config).await
}

async fn reject_changed_authority(root: &mut sqlx::PgConnection, config: &Config) -> Result<()> {
    for (signature, from, to) in [
        (
            "mdm_devices.advance_relation_revision()",
            "relation_revision+1",
            "relation_revision",
        ),
        (
            "mdm_devices.capture_identity_watermark()",
            "identity_watermark=NEW.revision",
            "identity_watermark=mdm_devices.checkpoints.identity_watermark",
        ),
        (
            "mdm_devices.guard_object_evidence()",
            "object evidence is immutable",
            "object evidence altered",
        ),
        (
            "mdm_apple.profile_qualifications(uuid[])",
            "THEN p.verification ELSE 'unknown'",
            "THEN 'matched'::text ELSE 'matched'::text",
        ),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_functiondef(to_regprocedure($1))")
            .bind(signature)
            .fetch_one(&mut *root)
            .await?;
        let damaged = original.replace(from, to);
        ensure!(damaged != original, "fault was not injected: {signature}");
        reject_and_restore(root, config, damaged, original).await?;
    }
    Ok(())
}

async fn reject_missing_fences(root: &mut sqlx::PgConnection, config: &Config) -> Result<()> {
    for (relation, trigger) in [
        ("mdm_devices.associations", "association_revision"),
        ("mdm_devices.members", "association_member_revision"),
        ("mdm.asset_changes", "device_identity_watermark"),
        ("mdm_devices.object_cuts", "immutable_object_cut"),
        ("mdm_devices.object_versions", "immutable_object_evidence"),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid=to_regclass($1) AND tgname=$2")
            .bind(relation).bind(trigger).fetch_one(&mut *root).await?;
        reject_and_restore(
            root,
            config,
            format!("DROP TRIGGER {trigger} ON {relation}"),
            original,
        )
        .await?;
    }
    reject_and_restore(
        root,
        config,
        "ALTER TABLE mdm_devices.associations DISABLE TRIGGER association_revision".into(),
        "ALTER TABLE mdm_devices.associations ENABLE TRIGGER association_revision".into(),
    )
    .await
}

#[tokio::test]
#[ignore = "MODULE=installation.storage: runtime installation and safety prerequisites"]
async fn incomplete_installation_and_unsafe_authority_are_rejected() -> Result<()> {
    let config: Config = serde_json::from_value(configuration()?)?;
    let temp = tempfile::tempdir()?;
    let journal = Journal::open(&temp.path().canonicalize()?.join("proof"))?;
    let mut root = sqlx::PgConnection::connect_with(&administrator(&journal)?.options()?).await?;
    connected(&config).await?;
    for (damage, restore) in [
        (
            "UPDATE public.mdm_migrations SET complete=false WHERE name='execution-service-schema-v1'",
            "UPDATE public.mdm_migrations SET complete=true WHERE name='execution-service-schema-v1'",
        ),
        (
            "GRANT UPDATE ON public.mdm_migrations TO mdm_access",
            "REVOKE UPDATE ON public.mdm_migrations FROM mdm_access",
        ),
        (
            "ALTER TABLE mdm_access.authorization_rules DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_access.authorization_rules ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant ON mdm_policy.versions USING(true)",
            "ALTER POLICY tenant ON mdm_policy.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "ALTER FUNCTION mdm_access.operation_authority_valid(jsonb,text,bigint) SET search_path=public",
            "ALTER FUNCTION mdm_access.operation_authority_valid(jsonb,text,bigint) SET search_path=pg_catalog",
        ),
        (
            "GRANT EXECUTE ON FUNCTION mdm_commands.active_access_binding(uuid,bigint,bigint) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION mdm_commands.active_access_binding(uuid,bigint,bigint) FROM PUBLIC",
        ),
        (
            "ALTER TABLE mdm_access.collection_runs DISABLE TRIGGER immutable_collection",
            "ALTER TABLE mdm_access.collection_runs ENABLE TRIGGER immutable_collection",
        ),
        (
            "ALTER TABLE mdm_commands.operations RENAME TO missing_operations",
            "ALTER TABLE mdm_commands.missing_operations RENAME TO operations",
        ),
    ] {
        let changed = sqlx::raw_sql(damage).execute(&mut root).await?;
        if damage.starts_with("UPDATE") {
            ensure!(changed.rows_affected() == 1, "missing installation unit");
        }
        let admitted = crate::Database::connect(config.access_options()?, &config.audit).await;
        sqlx::raw_sql(restore).execute(&mut root).await?;
        let rejected = match admitted {
            Ok(db) => {
                db.close().await;
                false
            }
            Err(_) => true,
        };
        ensure!(rejected, "unsafe startup admitted: {damage}");
        connected(&config).await?;
    }
    // A valid ledger is not proof of a trustworthy authorization implementation.
    for (signature, declaration) in [
        (
            "mdm_access.operation_authority_valid(jsonb,text,bigint)",
            "mdm_access.operation_authority_valid(authority jsonb,requested text,as_of bigint)",
        ),
        (
            "mdm_devices.association_grant_current(uuid,bigint,uuid,bigint)",
            "mdm_devices.association_grant_current(p_id uuid,p_version bigint,p_registration uuid,p_generation bigint)",
        ),
        (
            "mdm_apple.platform_registration_matches(uuid,bigint,jsonb)",
            "mdm_apple.platform_registration_matches(p_source uuid,p_version bigint,p_binding jsonb)",
        ),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_functiondef(to_regprocedure($1))")
            .bind(signature)
            .fetch_one(&mut root)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE OR REPLACE FUNCTION {declaration} RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT true'"))).execute(&mut root).await?;
        let admitted = crate::Database::connect(config.access_options()?, &config.audit).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(original))
            .execute(&mut root)
            .await?;
        let rejected = match admitted {
            Ok(db) => {
                db.close().await;
                false
            }
            Err(_) => true,
        };
        ensure!(rejected, "always-allow authority accepted: {signature}");
        connected(&config).await?;
    }
    reject_missing_fences(&mut root, &config).await?;
    reject_changed_authority(&mut root, &config).await?;
    root.close().await?;
    Ok(())
}

async fn open_and_write(
    base: &Value,
    path: &str,
    input: &Value,
    replay: Option<&Value>,
) -> Result<Value> {
    let (router, resources) = runtime::app(base).await?;
    resources
        .finish(async {
            let mut browser: Browser = Authority::prepared_browser("admin")?;
            let (status, receipt) = browser
                .call(&router, Method::PUT, path, Some(input.clone()))
                .await?;
            ensure!(
                status == StatusCode::OK,
                "product write after startup: {status} {receipt}"
            );
            if let Some(expected) = replay {
                ensure!(&receipt == expected, "recovery changed original receipt");
            }
            let (status, record) = browser.call(&router, Method::GET, path, None).await?;
            ensure!(
                status == StatusCode::OK && !record.is_null(),
                "restored read: {status} {record}"
            );
            Ok(receipt)
        })
        .await
}

#[tokio::test]
#[ignore = "MODULE=installation.storage: real product restart and pg_dump/pg_restore"]
async fn product_restarts_and_restores_without_structural_snapshot() -> Result<()> {
    let base = configuration()?;
    let path = format!("/api/v1/user-attribute-definitions/{}", Uuid::new_v4());
    let definition = serde_json::json!({"key":"restoreProof","displayName":"Restore proof","source":{"kind":"identity_local"},"pointer":"/extensions/restoreProof","valueType":"string","maxLength":64,"maxItems":null,"minimum":null,"maximum":null,"enabled":true,"sensitive":false,"visibility":"both","displayUse":"profile","required":false,"useExistingObservation":false});
    let input =
        serde_json::json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":definition});
    let receipt = open_and_write(&base, &path, &input, None).await?;
    open_and_write(&base, &path, &input, Some(&receipt)).await?;

    let temp = tempfile::tempdir()?;
    let journal = Journal::open(&temp.path().canonicalize()?.join("proof"))?;
    let admin = administrator(&journal)?;
    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    // Ordinary shape changes do not change the installation receipt or runtime authority.
    sqlx::raw_sql("CREATE VIEW public.restore_diagnostic AS SELECT 1 AS value; CREATE OR REPLACE VIEW public.restore_diagnostic AS SELECT * FROM (SELECT 1 AS value) equivalent; ALTER INDEX mdm.inventory_source RENAME TO restored_source_lookup; CREATE INDEX restore_diagnostic_index ON mdm_commands.operations(tenant_id); ALTER TABLE mdm.manual_assignments ADD COLUMN restore_note text; ALTER TABLE mdm_agent_packages.releases ADD COLUMN restore_note text; ALTER TABLE mdm_agent_packages.releases ADD CONSTRAINT restore_note_check CHECK(restore_note IS NULL OR length(restore_note)<=128)")
        .execute(&mut root).await?;
    leave_incomplete_ordinary_index(&mut root, &admin).await?;
    root.close().await?;
    open_and_write(&base, &path, &input, Some(&receipt)).await?;

    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    connection_fence(&mut root, &journal, true).await?;
    no_writers(&mut root).await?;
    root.close().await?;
    // This case proves the database seam; the complete bundle has its own backup tests.
    let backup = archive::capture(&journal, &admin).await?;
    let hash = backup.sha256;
    telemetry_fixture::recreate(&admin).await?;
    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    reserve_restore(&mut root, Uuid::new_v4(), &hash).await?;
    root.close().await?;
    archive::restore_database(&journal, &admin).await?;
    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    connection_fence(&mut root, &journal, false).await?;
    root.close().await?;
    open_and_write(&base, &path, &input, Some(&receipt)).await?;
    let mut update = input;
    update["operationId"] = Uuid::new_v4().to_string().into();
    update["expectedRevision"] = 1.into();
    update["value"]["displayName"] = "After recovery".into();
    let changed = open_and_write(&base, &path, &update, None).await?;
    ensure!(
        changed["definition"]["revision"] == 2,
        "post-restore write was not committed"
    );
    Ok(())
}

// A cancelled concurrent build leaves a real invalid optimization index, not a failed identity key.
async fn leave_incomplete_ordinary_index(
    root: &mut sqlx::PgConnection,
    admin: &crate::config::Database,
) -> Result<()> {
    let mut blocker = root.begin().await?;
    sqlx::query("LOCK TABLE mdm_agent_packages.releases IN ROW EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let mut builder = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    sqlx::query("SET statement_timeout='500ms'")
        .execute(&mut builder)
        .await?;
    let result = sqlx::query(
        "CREATE INDEX CONCURRENTLY restore_package_lookup ON mdm_agent_packages.releases(platform)",
    )
    .execute(&mut builder)
    .await;
    blocker.rollback().await?;
    builder.close().await?;
    ensure!(
        result.is_err_and(|error| error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("57014")),
        "concurrent build must be cancelled while waiting for the writer"
    );
    let invalid: bool = sqlx::query_scalar("SELECT NOT indisvalid AND NOT indisunique FROM pg_index WHERE indexrelid='mdm_agent_packages.restore_package_lookup'::regclass")
        .fetch_one(root).await?;
    ensure!(invalid, "missing incomplete ordinary index");
    Ok(())
}
