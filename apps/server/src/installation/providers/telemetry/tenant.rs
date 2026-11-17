//! Operator-only tenant selection on an already installed physical resource.
use super::*;
use crate::installation::{install::Input, runtime_files};
use rss_mdm_native_protection::{ProtectionContext, Protector};
use rss_mdm_telemetry_service::selection::{self, Reader, Selection};
use rss_request_context::TenantId;
use zeroize::Zeroizing;
mod operation;
pub use operation::{cancel, status};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRequest {
    product: Input,
    installation: Request,
    operation_id: Uuid,
    tenant: Uuid,
    expected_revision: i64,
    action: Action,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Select,
    Reader {
        password_file: PathBuf,
        worker_password_file: Option<PathBuf>,
        cursor_key_file: PathBuf,
    },
    Retire,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantReceipt {
    operation_id: Uuid,
    tenant: Uuid,
    installation_id: Uuid,
    material_revision: i64,
}

pub async fn prepare_tenant(input: TenantRequest) -> Result<TenantReceipt> {
    tokio::time::timeout(std::time::Duration::from_secs(180), select(input))
        .await
        .map_err(|_| Error::Storage)?
}

async fn verify_installation(input: &Request, journal: &Journal) -> Result<()> {
    let original: serde_json::Value = journal.load("request.json")?.ok_or(Error::Corrupt)?;
    let receipt: Receipt = journal.load("receipt.json")?.ok_or(Error::Corrupt)?;
    if original != serde_json::to_value(input).map_err(|_| Error::Input)?
        || !receipt.admitted
        || receipt.installation_id != input.configuration.resource_id
    {
        return Err(Error::Conflict);
    }
    let mut c =
        PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    verify_identity(&mut c, receipt.installation_id, &original).await?;
    if input.clickhouse.is_some() {
        let control: String = sqlx::query_scalar("SELECT id::text FROM rss_ts_ch.installation")
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
        if clickhouse::execute(
            input,
            "reader-installation",
            "SELECT id FROM rss_ts_ch.installation FORMAT TabSeparated",
        )
        .await?
        .trim()
            != control
        {
            return Err(Error::Conflict);
        }
    }
    c.close().await.map_err(|_| Error::Storage)
}

async fn select(input: TenantRequest) -> Result<TenantReceipt> {
    let (_host_lock, config) = open_host(&input)?;
    let tenant = TenantId::parse(&input.tenant.to_string()).map_err(|_| Error::Input)?;
    let target = installed_target(&config, &input.installation.configuration, tenant)?;
    let storage = Journal::open(&input.installation.directory)?;
    verify_installation(&input.installation, &storage).await?;
    let protection = config.native_protector().map_err(|_| Error::Corrupt)?;
    let supplied = supplied_reader(&input, target)?;
    let mut c = product_connection(&input.product, &config).await?;
    let execution = config
        .storage_binding
        .execution(tenant)
        .map_err(|_| Error::Input)?;
    let mut tx = tenant_transaction(&mut c, tenant, input.tenant, execution).await?;
    selection::lock_change(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let previous = selection::load(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let revision = input.expected_revision.checked_add(1).ok_or(Error::Input)?;
    let result = TenantReceipt {
        operation_id: input.operation_id,
        installation_id: target.resource_id,
        tenant: input.tenant,
        material_revision: revision,
    };
    let previous = previous.ok_or(Error::Conflict)?;
    let phase = operation::record(&mut tx, &input, tenant, &supplied, &protection, &result).await?;
    if phase == "published" {
        return Ok(result);
    }
    if matches!(phase.as_str(), "cancelled" | "cancelling") {
        return Err(Error::Conflict);
    }
    let change = reserved(
        &mut tx,
        &input,
        &previous,
        supplied,
        tenant,
        &protection,
        revision,
    )
    .await?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    let old = if previous.binding == change.binding {
        previous
            .reader(&protection, tenant)
            .map_err(|_| Error::Corrupt)?
    } else {
        None
    };
    let future = change
        .reader(&protection, tenant)
        .map_err(|_| Error::Corrupt)?;
    clickhouse::reconcile(&input.installation, tenant, old.as_ref(), future.as_ref()).await?;
    publish_qualified(&mut c, tenant, execution, &input).await?;
    Ok(result)
}
async fn reserved(
    tx: &mut PgConnection,
    input: &TenantRequest,
    previous: &Selection,
    supplied: Option<Reader>,
    tenant: TenantId,
    protection: &Protector,
    revision: i64,
) -> Result<Selection> {
    let pending = selection::pending(tx, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let change = if let Some(pending) = pending {
        if pending.operation_id != Some(input.operation_id) || pending.revision != revision {
            return Err(Error::Conflict);
        }
        pending
    } else {
        let retain_worker = matches!(input.action, Action::Retire)
            && selection::has_work(tx, tenant)
                .await
                .map_err(|_| Error::Storage)?;
        let next =
            next_selection(input, previous, supplied, tenant, protection, retain_worker).await?;
        selection::reserve(tx, tenant, previous, &next)
            .await
            .map_err(|_| Error::Conflict)?;
        next
    };
    Ok(change)
}
async fn publish_qualified(
    c: &mut PgConnection,
    tenant: TenantId,
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    input: &TenantRequest,
) -> Result<()> {
    let mut tx = tenant_transaction(c, tenant, input.tenant, execution).await?;
    operation::set(&mut tx, input.operation_id, "qualifying").await?;
    selection::ready(&mut tx, tenant, input.operation_id)
        .await
        .map_err(|_| Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    let wait = tokio::time::sleep(std::time::Duration::from_secs(12));
    tokio::pin!(wait);
    loop {
        let mut tx = tenant_transaction(c, tenant, input.tenant, execution).await?;
        selection::lock_change(&mut tx, tenant)
            .await
            .map_err(|_| Error::Storage)?;
        let published = selection::publish(&mut tx, tenant, input.operation_id)
            .await
            .map_err(|_| Error::Storage)?;
        if published {
            operation::set(&mut tx, input.operation_id, "published").await?;
        }
        tx.commit().await.map_err(|_| Error::Storage)?;
        if published {
            break;
        }
        tokio::select! {()=&mut wait=>return Err(Error::Busy),()=tokio::time::sleep(std::time::Duration::from_millis(200))=>{}}
    }
    Ok(())
}
fn open_host(input: &TenantRequest) -> Result<(Journal, crate::config::Config)> {
    input.installation.validate()?;
    if input.operation_id.is_nil() || input.tenant.is_nil() || input.expected_revision < 0 {
        return Err(Error::Input);
    }
    let root = Journal::open(&input.product.directory)?;
    for marker in [
        "backup-operation.json",
        "configuration-operation.json",
        "protection-operation.json",
    ] {
        if root.load::<Option<Uuid>>(marker)?.flatten().is_some() {
            return Err(Error::Busy);
        }
    }
    let config: crate::config::Config =
        serde_json::from_value(runtime_files::current(&root)?).map_err(|_| Error::Corrupt)?;
    Ok((root, config))
}
fn installed_target<'a>(
    config: &'a crate::config::Config,
    physical: &crate::telemetry::Config,
    tenant: TenantId,
) -> Result<&'a crate::telemetry::Config> {
    let target = config
        .telemetry
        .iter()
        .find(|r| r.resource_id == physical.resource_id)
        .ok_or(Error::Input)?;
    let binding = target.configuration_binding().map_err(|_| Error::Input)?;
    if binding != physical.configuration_binding().map_err(|_| Error::Input)?
        || target
            .tenant()
            .map_err(|_| Error::Input)?
            .is_some_and(|t| t != tenant)
    {
        return Err(Error::Conflict);
    }
    Ok(target)
}
async fn next_selection(
    input: &TenantRequest,
    previous: &Selection,
    supplied: Option<Reader>,
    tenant: TenantId,
    protection: &Protector,
    retain_worker: bool,
) -> Result<Selection> {
    let target = &input.installation.configuration;
    let binding = target.configuration_binding().map_err(|_| Error::Input)?;
    let revision = input.expected_revision.checked_add(1).ok_or(Error::Input)?;
    if previous.revision != input.expected_revision {
        return Err(Error::Conflict);
    }
    let old = previous
        .reader(protection, tenant)
        .map_err(|_| Error::Corrupt)?;
    let old = if previous.binding == binding {
        old
    } else {
        if old.is_some_and(|r| r.password.is_some()) {
            return Err(Error::Conflict);
        }
        None
    };
    let reader = changed_reader(input, supplied, old, retain_worker).await?;
    Ok(Selection {
        binding: binding.to_vec(),
        resource_id: Some(target.resource_id),
        revision,
        operation_id: Some(input.operation_id),
        material: reader
            .map(|r| r.seal(protection, tenant, target.resource_id, revision))
            .transpose()
            .map_err(|_| Error::Storage)?,
    })
}

async fn tenant_transaction(
    c: &mut PgConnection,
    tenant: TenantId,
    tenant_uuid: Uuid,
    execution: rss_transactional_messaging::fence::ExecutionBinding,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true)")
        .bind(tenant.to_string()).bind(Uuid::from_bytes(execution.storage().target()).simple().to_string()).bind(Uuid::from_bytes(execution.storage().lineage()).simple().to_string()).bind(execution.epoch().get().to_string()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Conflict)?;
    sqlx::query_scalar::<_, Uuid>(
        "SELECT t.tenant_id FROM public.mdm_tenants t CROSS JOIN public.mdm_installation i WHERE t.tenant_id=$1 AND t.used AND NOT t.deleted AND t.tenant_id<>i.management_tenant_id FOR SHARE OF t",
    )
    .bind(tenant_uuid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| Error::Storage)?
    .ok_or(Error::Conflict)?;
    Ok(tx)
}
fn supplied_reader(input: &TenantRequest, target: &Config) -> Result<Option<Reader>> {
    Ok(match (&input.action, &target.backend) {
        (
            Action::Reader {
                password_file,
                worker_password_file,
                cursor_key_file,
            },
            Storage::ClickHouse {
                writer,
                maintenance,
                ..
            },
        ) => {
            let suffix = Uuid::new_v5(&target.resource_id, input.tenant.as_bytes());
            let user = format!("mdm_reader_{}", suffix.simple());
            let worker_user = format!("mdm_work_{}", suffix.simple());
            let installer = &input
                .installation
                .clickhouse
                .as_ref()
                .ok_or(Error::Input)?
                .installer;
            if [&writer.user, &maintenance.user, &installer.user]
                .into_iter()
                .any(|role| role == &user || role == &worker_user)
            {
                return Err(Error::Input);
            }
            let worker = worker_password_file
                .as_deref()
                .map(reader_password)
                .transpose()?
                .map(|password| selection::Worker {
                    user: worker_user,
                    password,
                });
            Some(Reader {
                worker,
                user,
                password: Some(reader_password(password_file)?),
                cursor: Zeroizing::new(
                    crate::config::read(cursor_key_file, 32, true)
                        .map_err(|_| Error::Input)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Input)?,
                ),
            })
        }
        (Action::Retire, Storage::ClickHouse { .. }) => None,
        (
            Action::Select,
            Storage::TimescaleShared { .. }
            | Storage::Postgres { .. }
            | Storage::TimescaleDedicated { .. },
        ) => None,
        _ => return Err(Error::Input),
    })
}

async fn product_connection(
    product: &Input,
    config: &crate::config::Config,
) -> Result<PgConnection> {
    let mut c = PgConnection::connect_with(
        &product
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    if !crate::migration::owner_admitted(&mut c)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Input);
    }
    crate::migration::verify_identity(
        &mut c,
        &crate::migration::Installation {
            instance_id: config.identity.instance_id.clone(),
            target: config.storage_binding.target,
            lineage: config.storage_binding.lineage,
            audit_mode: config.audit.mode(),
        },
    )
    .await
    .map_err(|_| Error::Conflict)?;
    Ok(c)
}

fn reader_password(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let password = crate::config::secret(path).map_err(|_| Error::Input)?;
    if password.trim() != password.as_str() || !password.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(Error::Input);
    }
    Ok(password)
}

async fn changed_reader(
    input: &TenantRequest,
    supplied: Option<Reader>,
    old: Option<Reader>,
    retain_worker: bool,
) -> Result<Option<Reader>> {
    Ok(match (&input.action, supplied) {
        (Action::Reader { .. }, Some(reader)) => {
            Some(prepare_reader(&input.installation, reader, old).await?)
        }
        (Action::Retire, None) => {
            let mut old = old.ok_or(Error::Conflict)?;
            old.password.take();
            if !retain_worker {
                old.worker = None;
            }
            Some(old)
        }
        (Action::Select, None) => None,
        _ => return Err(Error::Input),
    })
}

async fn prepare_reader(
    installation: &Request,
    mut reader: Reader,
    old: Option<Reader>,
) -> Result<Reader> {
    let existing_worker = if let Some(old) = old {
        if old.user != reader.user
            || *old.cursor != *reader.cursor
            || old.password == reader.password
        {
            return Err(Error::Conflict);
        }
        old.worker
    } else {
        if clickhouse::reader_exists(installation, &reader.user).await? {
            return Err(Error::Conflict);
        }
        None
    };
    let worker = match (existing_worker, reader.worker.take()) {
        (Some(existing), None) => existing,
        (None, Some(new)) => {
            if clickhouse::reader_exists(installation, &new.user).await? {
                return Err(Error::Conflict);
            }
            new
        }
        _ => return Err(Error::Input),
    };
    if reader.password.as_ref() == Some(&worker.password) {
        return Err(Error::Input);
    }
    reader.worker = Some(worker);
    Ok(reader)
}
