use super::*;

async fn accepted(c: &Context) -> Result<bool> {
    let mut tx = c.access.begin().await?;
    let contracts = rss_mdm_device_access_runtime::installation::access_contracts();
    let result =
        rss_mdm_install_support::access_admission::verify(&mut tx, "da_access", &contracts).await?;
    rss_identity_postgres::verify_platform_subject_admission(
        &mut tx,
        rss_identity_core::InstanceId::parse(&c.inputs.installation.instance_id)?,
    )
    .await?;
    tx.rollback().await?;
    Ok(result)
}

pub async fn verify_and_reject_drift(c: &Context) -> Result<()> {
    anyhow::ensure!(accepted(c).await?, "standalone DA access admission");
    sqlx::query("GRANT DELETE ON rss_da.signing_keys TO da_access")
        .execute(&c.operator)
        .await?;
    let drift = accepted(c).await;
    sqlx::query("REVOKE DELETE ON rss_da.signing_keys FROM da_access")
        .execute(&c.operator)
        .await?;
    anyhow::ensure!(
        !drift?,
        "unexpected key deletion privilege must fail admission"
    );
    let mut tx = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    let forbidden = sqlx::query("INSERT INTO rss_da.devices(tenant_id,id) VALUES($1::uuid,$2)")
        .bind(c.tenant.to_string())
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await;
    anyhow::ensure!(
        forbidden
            .as_ref()
            .err()
            .and_then(sqlx::Error::as_database_error)
            .is_some_and(|e| e.code().as_deref() == Some("42501")),
        "cross-tenant insertion must fail RLS"
    );
    tx.rollback().await?;
    Ok(())
}
