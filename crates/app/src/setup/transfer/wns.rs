//! 保留原 WNS 应用和设备通道身份，只导入明确的 V4 字段。
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    package_family_name: String,
    sid: String,
    client_secret_file: PathBuf,
}
pub(super) async fn import(
    c: &mut PgConnection,
    runtime: &mut Value,
    operation: Uuid,
    key: &rss_mdm_native_protection::Protector,
) -> Result<()> {
    if runtime["native_protocols"]["windows"]["push"].is_null() {
        return Ok(());
    }
    let source: Legacy =
        serde_json::from_value(runtime["native_protocols"]["windows"]["push"].clone())
            .map_err(|_| Error::Input)?;
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Corrupt)?;
    let secret = crate::config::secret(&source.client_secret_file).map_err(|_| Error::Corrupt)?;
    let old = rss_mdm_windows_channel::push::Push::new(
        source.package_family_name.clone(),
        source.sid.clone(),
        secret.to_string(),
        crate::clock::monotonic(),
    )
    .map_err(|_| Error::Input)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let receipt = rss_mdm_windows_channel::wns_materials::prepare(
        &mut tx,
        tenant,
        operation,
        "offline-v4-transfer",
        &rss_mdm_windows_channel::wns_materials::Request {
            expected_revision: 0,
            package_family_name: source.package_family_name,
            sid: source.sid.into(),
            client_secret: secret,
        },
        key,
    )
    .await
    .map_err(|_| Error::Conflict)?;
    sqlx::query(
        "UPDATE mdm_wns.versions SET configuration=$3 WHERE tenant_id=$1::uuid AND operation_id=$2",
    )
    .bind(tenant)
    .bind(operation)
    .bind(old.configuration.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(|_| Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    // 不在数据库事务内持有外部请求。超时不换操作或生成替代应用身份。
    old.validate_credentials()
        .await
        .map_err(|_| Error::Storage)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
    rss_mdm_windows_channel::wns_materials::qualify(&mut tx, tenant, receipt.revision, now)
        .await
        .map_err(|_| Error::Conflict)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    runtime["native_protocols"]["windows"]["push"] = json!({"revision":receipt.revision});
    Ok(())
}
