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
            "UPDATE public.mdm_migrations SET complete=false WHERE name='flow-service-schema-v1'",
            "UPDATE public.mdm_migrations SET complete=true WHERE name='flow-service-schema-v1'",
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
    let original: String = sqlx::query_scalar("SELECT pg_get_functiondef('mdm_access.operation_authority_valid(jsonb,text,bigint)'::regprocedure)").fetch_one(&mut root).await?;
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION mdm_access.operation_authority_valid(authority jsonb,requested text,as_of bigint) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT true'").execute(&mut root).await?;
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
    ensure!(rejected, "always-allow authority accepted");
    connected(&config).await?;
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
    let view: String = sqlx::query_scalar(
        "SELECT pg_get_viewdef('mdm_apple.profile_qualifications'::regclass,true)",
    )
    .fetch_one(&mut root)
    .await?;
    // Equivalent subquery rendering and an ordinary index change the old snapshot.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE OR REPLACE VIEW mdm_apple.profile_qualifications WITH(security_barrier=true) AS SELECT * FROM ({}) equivalent", view.trim().trim_end_matches(';')))).execute(&mut root).await?;
    sqlx::raw_sql("CREATE INDEX restore_diagnostic_index ON mdm_commands.operations(tenant_id)")
        .execute(&mut root)
        .await?;
    root.close().await?;
    open_and_write(&base, &path, &input, Some(&receipt)).await?;

    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    connection_fence(&mut root, &journal, true).await?;
    no_writers(&mut root).await?;
    root.close().await?;
    archive::capture(&journal, &admin).await?;
    let hash = archive::seal(&journal, Uuid::new_v4())?;
    archive::verify(&journal, &hash)?;
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
