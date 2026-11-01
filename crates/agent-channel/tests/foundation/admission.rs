//! Fixture host composes owner admission; no installer role can stand in for runtime proof.
use super::*;
pub async fn access(c: &Context) -> Result<()> {
    let mut tx = c.access.begin().await?;
    let contracts = [
        registration::access_contract(DA),
        registration::enrollment_access_contract(DA),
        rss_mdm_authorization_service::access_contract(DA),
        rss_mdm_agent_channel::access_contract(DA),
        rss_mdm_task_trust::access_contract(DA),
        rss_mdm_pki_service::access_contract(DA),
        rss_mdm_policy_postgres::access_contract(DA),
        rss_mdm_scope_postgres::access_contract(DA),
        rss_mdm_recovery_credentials::access_contract(DA),
        rss_mdm_inventory_service::access_contract(DA),
        rss_mdm_audit_integration::ACCESS_CONTRACT,
        include_str!("access-contract.json"),
    ];
    anyhow::ensure!(
        rss_mdm_backend_postgres_support::access_admission::verify(
            &mut tx,
            "da_access",
            &contracts
        )
        .await?,
        "DA access contract rejected"
    );
    rss_identity_postgres::verify_platform_subject_admission(
        &mut tx,
        rss_identity_core::InstanceId::parse(&c.inputs.installation.instance_id)?,
    )
    .await?;
    rss_mdm_inventory_postgres::verify_collections(&mut tx).await?;
    rss_mdm_inventory_postgres::verify_asset_history(&mut tx).await?;
    // Installation metadata is intentionally not tenant data. Its narrow, read-only host
    // contract is verified separately from tenant tables and excludes grants or mutable columns.
    let valid:bool=sqlx::query_scalar("SELECT count(*)=1 AND bool_and(b.instance_id=$1 AND b.target=$2 AND b.lineage=$3 AND a.instance_id=b.instance_id) FROM rss_da.installation_binding b JOIN rss_da.authorization_installation a USING(instance_id)")
        .bind(Uuid::parse_str(&c.inputs.installation.instance_id)?).bind(c.inputs.installation.target.as_slice()).bind(c.inputs.installation.lineage.as_slice()).fetch_one(&mut *tx).await?;
    anyhow::ensure!(valid, "runtime installation binding differs");
    let safe:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_da' AND c.relname IN('installation_binding','installation_units','authorization_installation') AND (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))) AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='rss_da' AND c.relname IN('installation_binding','installation_units','authorization_installation') AND (a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))").fetch_one(&mut *tx).await?;
    anyhow::ensure!(safe, "runtime can modify installation identity");
    tx.rollback().await?;
    Ok(())
}
