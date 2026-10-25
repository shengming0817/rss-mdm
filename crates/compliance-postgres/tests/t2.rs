//! Adapter contracts against the formal product migration, without App dependencies.
use anyhow::{Result, ensure};
use rss_mdm_compliance::{
    Applicability, Assessment, Decision, Definition, Platform, Reason, Status,
};
use rss_mdm_compliance_postgres as storage;
use rss_request_context::TenantId;
use serde_json::{Value, json};
use sqlx::{
    Connection, Executor, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};
use uuid::Uuid;

#[path = "../../../tests/support/context.rs"]
mod case;
fn case_tenant() -> &'static str {
    case::tenant()
}
async fn connect(owner: bool) -> Result<PgConnection> {
    let mut options: PgConnectOptions = std::env::var(if owner {
        "MDM_ADMIN_URL"
    } else {
        "DATABASE_URL"
    })?
    .parse()?;
    if !owner {
        options = options
            .username("mdm_flow_runtime")
            .password("runtime-fixture");
    }
    Ok(PgConnection::connect_with(
        &options
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?),
    )
    .await?)
}
async fn bind(connection: &mut PgConnection, tenant: &str) -> Result<()> {
    connection.execute("BEGIN").await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(connection)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=compliance.storage: borrowed transactions, immutable evidence and tenant isolation"]
async fn immutable_versions_results_and_tenant_transactions() -> Result<()> {
    let tenant = TenantId::parse(case_tenant())?;
    let mut connection = connect(false).await?;
    // Even an empty read must reject an unbound transaction.
    ensure!(matches!(
        storage::rules::<Value>(&mut connection, tenant, None, 1).await,
        Err(sqlx::Error::Protocol(_))
    ));
    bind(&mut connection, case_tenant()).await?;
    storage::admit(&mut connection, tenant).await?;
    let id = Uuid::new_v4();
    let mut definition: Definition<Value> = serde_json::from_value(json!({
        "presentation":{"name":"adapter policy","vendor":{"padding":"","values":[0,1]}},"severity":"high","enabled":true,"platform":"all",
        "target":{"kind":"all"},"criteria":{"kind":"predicate","field":"custom.is_loaner","op":"eq","value":{"kind":"boolean","value":false}}
    }))?;
    let base_bytes: i32 = sqlx::query_scalar("SELECT octet_length(($1::jsonb)::text)")
        .bind(serde_json::to_value(&definition)?)
        .fetch_one(&mut connection)
        .await?;
    definition.presentation.get_mut("vendor").unwrap()["padding"] =
        json!("x".repeat(65536 - base_bytes as usize));
    let rule = storage::Rule {
        id,
        revision: 1,
        enabled: true,
        desired: None,
        current_run: None,
        definition,
    };
    ensure!(
        storage::put(
            &mut connection,
            tenant,
            &rule,
            &["custom.is_loaner".into()],
            &[],
        )
        .await?
    );
    let restored = storage::rule::<Value>(&mut connection, tenant, id)
        .await?
        .unwrap();
    ensure!(restored.definition.presentation == rule.definition.presentation);
    let mut oversized = rule.clone();
    oversized.id = Uuid::new_v4();
    let Value::String(padding) =
        &mut oversized.definition.presentation.get_mut("vendor").unwrap()["padding"]
    else {
        unreachable!()
    };
    padding.push('x');
    ensure!(serde_json::to_vec(&oversized.definition)?.len() < 65536);
    ensure!(!storage::put(&mut connection, tenant, &oversized, &[], &[]).await?);
    ensure!(
        storage::rule::<Value>(&mut connection, tenant, oversized.id)
            .await?
            .is_none()
    );
    let assessment = Assessment {
        rule_id: id,
        rule_version: 1,
        dictionary_version: "fixture-v1".into(),
        fact_watermark: 0,
        evaluated_at: 1,
        groups: vec![],
        status: Status::Unknown,
        reason: Reason::FactsUnknown,
        condition: Decision::Unknown,
        applicability: Applicability {
            platform: Platform::All,
            platform_decision: Decision::Match,
            sources: vec![],
            groups: vec![],
        },
        explanations: vec![],
        evidence: vec![],
    };
    let task = Uuid::new_v4();
    storage::result(&mut connection, tenant, task, "device-a", &assessment).await?;
    let operation = Uuid::new_v4();
    storage::receipt(
        &mut connection,
        tenant,
        operation,
        &[1; 32],
        &json!({"revision":1}),
    )
    .await?;
    connection.execute("COMMIT").await?;

    bind(&mut connection, case_tenant()).await?;
    let stored = storage::result_at(&mut connection, tenant, task, "device-a")
        .await?
        .unwrap();
    ensure!(stored.rule_id == id && stored.rule_version == 1 && stored.status == Status::Unknown);
    ensure!(
        storage::replay(&mut connection, tenant, operation).await?
            == Some((vec![1; 32], json!({"revision":1})))
    );
    connection.execute("SAVEPOINT invalid_version").await?;
    let mut nonexistent = assessment.clone();
    nonexistent.rule_version += 999;
    let error = storage::result(
        &mut connection,
        tenant,
        Uuid::new_v4(),
        "device-a",
        &nonexistent,
    )
    .await
    .unwrap_err();
    ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503"));
    connection.execute("ROLLBACK TO invalid_version").await?;
    connection.execute("SAVEPOINT mismatched_document").await?;
    ensure!(sqlx::query("INSERT INTO mdm_compliance.results SELECT tenant_id,$1::uuid,rule_id,rule_revision,device,evaluated_at,jsonb_set(document,'{ruleVersion}',to_jsonb(rule_revision+1)) FROM mdm_compliance.results")
        .bind(Uuid::new_v4().to_string()).execute(&mut connection).await.unwrap_err().as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"));
    connection
        .execute("ROLLBACK TO mismatched_document")
        .await?;
    connection.execute("SAVEPOINT immutable").await?;
    ensure!(
        connection
            .execute("DELETE FROM mdm_compliance.results")
            .await
            .unwrap_err()
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref()
            == Some("42501")
    );
    connection.execute("ROLLBACK TO immutable").await?;
    for mutation in [
        "UPDATE mdm_compliance.versions SET revision=revision+1",
        "DELETE FROM mdm_compliance.versions",
    ] {
        connection.execute("SAVEPOINT immutable_version").await?;
        ensure!(
            connection
                .execute(mutation)
                .await
                .unwrap_err()
                .as_database_error()
                .and_then(|e| e.code())
                .as_deref()
                == Some("42501")
        );
        connection.execute("ROLLBACK TO immutable_version").await?;
    }
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_compliance.versions")
        .fetch_one(&mut connection)
        .await?;
    connection.execute("SAVEPOINT version_rollback").await?;
    sqlx::query("INSERT INTO mdm_compliance.versions SELECT tenant_id,rule_id,100,definition FROM mdm_compliance.versions WHERE rule_id=$1::uuid AND revision=1").bind(id.to_string()).execute(&mut connection).await?;
    connection.execute("ROLLBACK TO version_rollback").await?;
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mdm_compliance.versions")
            .fetch_one(&mut connection)
            .await?
            == before
    );
    connection.execute("ROLLBACK").await?;

    let foreign = case::peer();
    bind(&mut connection, foreign).await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mdm_compliance.results WHERE task=$1 AND device='device-a'"
        )
        .bind(task)
        .fetch_one(&mut connection)
        .await?
            == 0
    );
    ensure!(
        storage::rule::<Value>(&mut connection, TenantId::parse(foreign)?, id)
            .await?
            .is_none()
    );
    ensure!(
        storage::result_at(&mut connection, tenant, task, "device-a")
            .await
            .is_err()
    );
    connection.execute("ROLLBACK").await?;
    connection.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=compliance.storage: reject schema and permission drift"]
async fn admission_rejects_unrelated_grantees_and_disabled_rls() -> Result<()> {
    let mut owner = connect(true).await?;
    bind(&mut owner, case_tenant()).await?;
    for change in [
        "SELECT 1",
        "GRANT SELECT ON mdm_compliance.results TO mdm_api",
        "GRANT UPDATE(desired) ON mdm_compliance.rules TO mdm_api",
        "GRANT SELECT ON mdm_compliance.results TO PUBLIC",
        "ALTER TABLE mdm_compliance.results DISABLE ROW LEVEL SECURITY",
    ] {
        owner.execute("SAVEPOINT drift").await?;
        owner.execute(change).await?;
        owner.execute("SET LOCAL ROLE mdm_flow_runtime").await?;
        let admitted = storage::admit(&mut owner, TenantId::parse(case_tenant())?).await;
        ensure!(
            admitted.is_ok() == (change == "SELECT 1"),
            "unexpected admission for {change}: {admitted:?}"
        );
        owner.execute("ROLLBACK TO drift").await?;
    }
    owner.execute("ROLLBACK").await?;
    owner.close().await?;
    Ok(())
}
