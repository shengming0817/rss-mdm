//! Durable operator receipts and compensation on the original installation.
use super::*;
use rss_transactional_messaging::fence::ExecutionBinding;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    product: Input,
    tenant: Uuid,
    operation_id: Uuid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cancel {
    product: Input,
    installation: Request,
    tenant: Uuid,
    operation_id: Uuid,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    #[serde(flatten)]
    receipt: TenantReceipt,
    state: String,
}

pub(super) async fn record(
    c: &mut PgConnection,
    input: &TenantRequest,
    tenant: TenantId,
    supplied: &Option<Reader>,
    protection: &Protector,
    receipt: &TenantReceipt,
) -> Result<String> {
    let identity =
        Zeroizing::new(serde_json::to_vec(&(input, supplied)).map_err(|_| Error::Input)?);
    let aad = ProtectionContext::new(
        tenant,
        &input.operation_id.to_string(),
        "telemetry.operation",
        1,
    )
    .map_err(|_| Error::Input)?
    .derive();
    let action = match input.action {
        Action::Reader { .. } => "reader",
        Action::Select => "select",
        Action::Retire => "retire",
    };
    let mac = serde_json::json!([
        protection.fingerprint_id(),
        protection
            .mac(&identity, &aad)
            .map_err(|_| Error::Storage)?
    ]);
    sqlx::query("INSERT INTO mdm_telemetry.reader_operations(operation_id,tenant_id,resource_id,revision,request_mac,action,state) VALUES($1,$2,$3,$4,$5,$6,'draining') ON CONFLICT DO NOTHING")
      .bind(input.operation_id).bind(input.tenant).bind(receipt.installation_id).bind(receipt.material_revision).bind(mac).bind(action).execute(&mut *c).await.map_err(|_|Error::Storage)?;
    let (value,resource,revision,kind,state):(serde_json::Value,Uuid,i64,String,String)=sqlx::query_as("SELECT request_mac,resource_id,revision,action,state FROM mdm_telemetry.reader_operations WHERE tenant_id=$1 AND operation_id=$2")
      .bind(input.tenant).bind(input.operation_id).fetch_optional(c).await.map_err(|_|Error::Storage)?.ok_or(Error::Conflict)?;
    let (key, tag): (String, Vec<u8>) =
        serde_json::from_value(value).map_err(|_| Error::Corrupt)?;
    protection
        .verify_mac_with_key(&key, &identity, &aad, &tag)
        .map_err(|_| Error::Conflict)?;
    if (resource, revision, kind.as_str())
        != (receipt.installation_id, receipt.material_revision, action)
    {
        return Err(Error::Conflict);
    }
    Ok(state)
}
pub(super) async fn set(c: &mut PgConnection, op: Uuid, state: &str) -> Result<()> {
    if sqlx::query("UPDATE mdm_telemetry.reader_operations SET state=$2 WHERE operation_id=$1")
        .bind(op)
        .bind(state)
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?
        .rows_affected()
        != 1
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub(super) async fn drain(
    c: &mut PgConnection,
    tenant: TenantId,
    execution: ExecutionBinding,
    input: &TenantRequest,
) -> Result<()> {
    let mut tx = tenant_transaction(c, tenant, input.tenant, execution).await?;
    selection::lock_change(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let drained=sqlx::query("UPDATE mdm_telemetry.storage_binding b SET changing=true WHERE b.tenant_id=$1 AND b.pending->>'operation_id'=$2 AND NOT EXISTS(SELECT FROM mdm_telemetry.batches WHERE tenant_id=$1 AND delivery<>'published')")
      .bind(input.tenant).bind(input.operation_id.to_string()).execute(&mut *tx).await.map_err(|_|Error::Storage)?.rows_affected();
    if drained != 1 {
        return Err(Error::Busy);
    }
    set(&mut tx, input.operation_id, "applying").await?;
    tx.commit().await.map_err(|_| Error::Storage)
}
async fn read(c: &mut PgConnection, tenant: Uuid, operation_id: Uuid) -> Result<Status> {
    let (installation_id,material_revision,state):(Uuid,i64,String)=sqlx::query_as("SELECT resource_id,revision,state FROM mdm_telemetry.reader_operations WHERE tenant_id=$1 AND operation_id=$2")
      .bind(tenant).bind(operation_id).fetch_optional(c).await.map_err(|_|Error::Storage)?.ok_or(Error::Input)?;
    Ok(Status {
        receipt: TenantReceipt {
            operation_id,
            installation_id,
            tenant,
            material_revision,
        },
        state,
    })
}
fn installed(product: &Input) -> Result<(Journal, crate::config::Config)> {
    let root = Journal::open(&product.directory)?;
    let config =
        serde_json::from_value(runtime_files::current(&root)?).map_err(|_| Error::Corrupt)?;
    Ok((root, config))
}
pub async fn status(query: Query) -> Result<Status> {
    let (_lock, config) = installed(&query.product)?;
    let mut c = product_connection(&query.product, &config).await?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(query.tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    read(&mut tx, query.tenant, query.operation_id).await
}
fn check_cancellation(status: &Status, input: &Cancel) -> Result<()> {
    if status.receipt.installation_id != input.installation.configuration.resource_id
        || status.state == "published"
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn check_markers(root: &Journal) -> Result<()> {
    for marker in [
        "backup-operation.json",
        "configuration-operation.json",
        "protection-operation.json",
    ] {
        if root.load::<Option<Uuid>>(marker)?.flatten().is_some() {
            return Err(Error::Busy);
        }
    }
    Ok(())
}
async fn cancellation_target(
    input: &Cancel,
    config: &crate::config::Config,
    tenant: TenantId,
) -> Result<(Journal, [u8; 32])> {
    let binding = installed_target(config, &input.installation.configuration, tenant)?
        .configuration_binding()
        .map_err(|_| Error::Input)?;
    let storage = Journal::open(&input.installation.directory)?;
    verify_installation(&input.installation, &storage).await?;
    Ok((storage, binding))
}
pub async fn cancel(input: Cancel) -> Result<Status> {
    let (root, config) = installed(&input.product)?;
    check_markers(&root)?;
    let tenant = TenantId::parse(&input.tenant.to_string()).map_err(|_| Error::Input)?;
    let (_storage_lock, binding) = cancellation_target(&input, &config, tenant).await?;
    let execution = config
        .storage_binding
        .execution(tenant)
        .map_err(|_| Error::Input)?;
    let mut c = product_connection(&input.product, &config).await?;
    let mut tx = tenant_transaction(&mut c, tenant, input.tenant, execution).await?;
    selection::lock_change(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let status = read(&mut tx, input.tenant, input.operation_id).await?;
    check_cancellation(&status, &input)?;
    if status.state == "cancelled" {
        return Ok(status);
    }
    let candidate = selection::pending(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Conflict)?;
    if candidate.operation_id != Some(input.operation_id) || candidate.binding != binding {
        return Err(Error::Conflict);
    }
    let previous = selection::load(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Corrupt)?;
    let changing: bool =
        sqlx::query_scalar("SELECT changing FROM mdm_telemetry.storage_binding WHERE tenant_id=$1")
            .bind(input.tenant)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
    set(&mut tx, input.operation_id, "cancelling").await?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    if changing {
        let key = config.native_protector().map_err(|_| Error::Corrupt)?;
        compensate(&input.installation, tenant, &candidate, &previous, &key).await?;
    }
    finish_cancel(&mut c, tenant, execution, &input).await?;
    Ok(Status {
        state: "cancelled".into(),
        ..status
    })
}
async fn finish_cancel(
    c: &mut PgConnection,
    tenant: TenantId,
    execution: ExecutionBinding,
    input: &Cancel,
) -> Result<()> {
    let mut tx = tenant_transaction(c, tenant, input.tenant, execution).await?;
    selection::lock_change(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    if sqlx::query("UPDATE mdm_telemetry.storage_binding SET pending=NULL,changing=false,probe_ready=false,qualified=NULL WHERE tenant_id=$1 AND pending->>'operation_id'=$2").bind(input.tenant).bind(input.operation_id.to_string()).execute(&mut *tx).await.map_err(|_|Error::Storage)?.rows_affected()!=1 {return Err(Error::Conflict);}
    set(&mut tx, input.operation_id, "cancelled").await?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    Ok(())
}
async fn compensate(
    installation: &Request,
    tenant: TenantId,
    candidate: &Selection,
    previous: &Selection,
    key: &Protector,
) -> Result<()> {
    let Some(next) = candidate.reader(key, tenant).map_err(|_| Error::Corrupt)? else {
        return Ok(());
    };
    if previous.binding == candidate.binding
        && let Some(old) = previous.reader(key, tenant).map_err(|_| Error::Corrupt)?
    {
        return clickhouse::provision_reader(installation, tenant, &old, Some(&next)).await;
    }
    let retired = Reader {
        user: next.user.clone(),
        password: None,
        cursor: next.cursor.clone(),
    };
    clickhouse::provision_reader(installation, tenant, &retired, Some(&next)).await
}
