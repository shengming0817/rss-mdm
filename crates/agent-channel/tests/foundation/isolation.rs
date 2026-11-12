//! Negative proofs at the actual storage/profile and privileged-function boundaries.
use super::*;
use rss_mdm_install_support::Host;

pub async fn profiles(
    c: &Context,
    p: &registration::DevicePrincipal,
    context: &w::SoftwareExecutionContext,
) -> Result<()> {
    // The independent journey has already asserted that no MDM private schema exists.
    // Install the real second Agent storage profile solely for an identical-ID collision proof.
    let mut tx = c.seed().await?;
    sqlx::query("SET LOCAL ROLE mdm_owner")
        .execute(&mut *tx)
        .await?;
    rss_mdm_install_support::execute_schema(
        &mut tx,
        "second-agent-profile",
        rss_mdm_agent_channel::install_sql(StorageProfile::Mdm),
        "fixture schema",
    )
    .await?;
    sqlx::query("INSERT INTO mdm_agent.bindings (tenant_id, device, wire_version, capabilities, platform, architecture, execution_context) VALUES (CAST($1 AS uuid), $2, 1, $3, 'windows', 'x86_64', $4)")
        .bind(c.tenant.to_string()).bind(p.device().into_uuid()).bind(serde_json::to_string(&[w::Capability::InventoryCollectionV1])?).bind(serde_json::to_value(context)?).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut tx = c.seed().await?;
    let mdm = rss_mdm_agent_channel::Bindings::new(StorageProfile::Mdm)
        .binding(&mut tx, c.tenant.to_string(), *p.device())
        .await?
        .unwrap();
    let da = rss_mdm_agent_channel::Bindings::new(DA)
        .binding(&mut tx, c.tenant.to_string(), *p.device())
        .await?
        .unwrap();
    assert!(!mdm.enrollment());
    assert!(da.enrollment());
    let isolated:bool=sqlx::query_scalar("SELECT NOT has_table_privilege('da_access','mdm_agent.bindings','SELECT,INSERT,UPDATE,DELETE') AND NOT has_table_privilege('mdm_access','rss_da.agent_bindings','SELECT,INSERT,UPDATE,DELETE') AND NOT has_any_column_privilege('mdm_command_runtime','rss_da.agent_bindings','SELECT,INSERT,UPDATE,REFERENCES')")
        .fetch_one(&mut *tx).await?;
    assert!(isolated);
    tx.rollback().await?;
    let mut tx = c.access.begin().await?;
    let foreign = Uuid::new_v4();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let denied =
        sqlx::query("INSERT INTO rss_da.devices(tenant_id,id) VALUES($1,'00000000-0000-0000-0000-000000000001')")
            .bind(foreign)
            .execute(&mut *tx)
            .await
            .unwrap_err();
    assert_eq!(
        denied.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    tx.rollback().await?;
    Ok(())
}

pub async fn authority(c: &Context) -> Result<()> {
    let mut runtime = c.access.begin().await?;
    registration::verify_common_authority(DA, &mut runtime).await?;
    rss_mdm_authorization_service::verify_authority(DA, &mut runtime).await?;
    rss_mdm_inventory_service::verify_authority(DA, &mut runtime).await?;
    rss_mdm_agent_channel::signature_retirement::verify_authority(DA, &mut runtime).await?;
    // This host consumes Enrollment tasks, without DA business or credential execution.
    let product_tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM unnest(ARRAY['rss_da.agent_delivery','rss_da.bindings','rss_da.access_runs','rss_da.recovery_entries','rss_da.recovery_versions','rss_da.credential_runs','rss_da.credential_agent_admission','rss_da.credential_policy_recovery']) name WHERE to_regclass(name) IS NOT NULL",
    )
    .fetch_all(&mut *runtime)
    .await?;
    assert!(
        product_tables.is_empty(),
        "unconsumed product tables installed: {product_tables:?}"
    );
    runtime.rollback().await?;
    // Function metadata drift must reject the same real runtime before it can expose work.
    let mut altered = c.operator.begin().await?;
    sqlx::query("ALTER FUNCTION rss_da.asset_sources_at(uuid[],jsonb) SET search_path TO public")
        .execute(&mut *altered)
        .await?;
    sqlx::query("SET LOCAL ROLE da_access")
        .execute(&mut *altered)
        .await?;
    assert!(
        registration::verify_common_authority(DA, &mut altered)
            .await
            .is_err()
    );
    altered.rollback().await?;
    let host = installation::Installation {
        inputs: &c.inputs,
        fail_before: None,
    };
    for tamper in [
        "ALTER TABLE rss_da.devices DISABLE ROW LEVEL SECURITY",
        "CREATE TABLE rss_da.unowned_data(id uuid)",
        "GRANT SELECT ON rss_da.devices TO PUBLIC",
    ] {
        let mut altered = c.operator.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(tamper))
            .execute(&mut *altered)
            .await?;
        assert!(
            host.verify(&mut altered).await.is_err(),
            "catalog accepted {tamper}"
        );
        altered.rollback().await?;
    }
    Ok(())
}
