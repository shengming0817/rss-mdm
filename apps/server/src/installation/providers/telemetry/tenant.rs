//! Operator-only tenant selection on an already installed physical resource.
use super::*;
use crate::installation::{install::Input, runtime_files};
use rss_mdm_native_protection::{ProtectionContext, Protector};
use rss_mdm_telemetry_service::selection::{self, Reader, Selection};
use rss_request_context::TenantId;
use zeroize::Zeroizing;

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
    let (id, binding): (Uuid, Vec<u8>) =
        sqlx::query_as("SELECT id,binding FROM public.mdm_telemetry_installation")
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
    if id != receipt.installation_id
        || binding
            != Sha256::digest(serde_json::to_vec(&original).map_err(|_| Error::Corrupt)?).as_slice()
    {
        return Err(Error::Conflict);
    }
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
    let physical = &input.installation.configuration;
    let target = config
        .telemetry
        .iter()
        .find(|r| r.resource_id == physical.resource_id)
        .ok_or(Error::Input)?;
    let tenant = TenantId::parse(&input.tenant.to_string()).map_err(|_| Error::Input)?;
    let binding = target.configuration_binding().map_err(|_| Error::Input)?;
    if binding != physical.configuration_binding().map_err(|_| Error::Input)?
        || target
            .tenant()
            .map_err(|_| Error::Input)?
            .is_some_and(|t| t != tenant)
    {
        return Err(Error::Conflict);
    }
    let storage = Journal::open(&input.installation.directory)?;
    verify_installation(&input.installation, &storage).await?;
    let journal = Journal::open(&root.path(&format!("telemetry-tenant-{}", input.operation_id))?)?;
    let protection = config.native_protector().map_err(|_| Error::Corrupt)?;
    let supplied = supplied_reader(&input, target)?;
    freeze_request(&input, tenant, &supplied, &protection, &journal)?;
    if let Some(receipt) = journal.load("receipt.json")? {
        return Ok(receipt);
    }
    let mut c = product_connection(&input.product, &config).await?;
    let execution = config
        .storage_binding
        .execution(tenant)
        .map_err(|_| Error::Input)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true)")
        .bind(tenant.to_string()).bind(Uuid::from_bytes(execution.storage().target()).simple().to_string()).bind(Uuid::from_bytes(execution.storage().lineage()).simple().to_string()).bind(execution.epoch().get().to_string()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Conflict)?;
    sqlx::query_scalar::<_, Uuid>(
        "SELECT tenant_id FROM public.mdm_tenants WHERE tenant_id=$1 AND NOT deleted FOR SHARE",
    )
    .bind(input.tenant)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| Error::Storage)?
    .ok_or(Error::Conflict)?;
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
    if !previous
        .as_ref()
        .is_some_and(|p| p.operation_id == Some(input.operation_id) && p.revision == revision)
    {
        if previous.as_ref().map_or(0, |p| p.revision) != input.expected_revision {
            return Err(Error::Conflict);
        }
        // Before superseding a selection, repair the original receipt if its DB commit
        // survived a process failure between commit and the journal rename.
        if let Some(previous) = &previous
            && let (Some(op), Some(resource)) = (previous.operation_id, previous.resource_id)
        {
            let old_journal = Journal::open(&root.path(&format!("telemetry-tenant-{op}"))?)?;
            old_journal.save(
                "receipt.json",
                &TenantReceipt {
                    operation_id: op,
                    tenant: input.tenant,
                    installation_id: resource,
                    material_revision: previous.revision,
                },
            )?;
        }
        if previous.as_ref().is_some_and(|p| p.binding != binding) {
            let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.batches WHERE tenant_id=$1) OR EXISTS(SELECT FROM mdm_telemetry.definition_progress WHERE tenant_id=$1) OR EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1)").bind(input.tenant).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
            if used
                || old_reader(previous.as_ref(), &protection, tenant)?
                    .is_some_and(|r| r.password.is_some())
            {
                return Err(Error::Conflict);
            }
        }
        let old = old_reader(
            previous.as_ref().filter(|p| p.binding == binding),
            &protection,
            tenant,
        )?;
        let reader = changed_reader(&input, supplied, old, &journal).await?;
        let material = if let Some(reader) = reader {
            clickhouse::provision_reader(&input.installation, tenant, &reader).await?;
            Some(
                reader
                    .seal(&protection, tenant, target.resource_id, revision)
                    .map_err(|_| Error::Storage)?,
            )
        } else {
            None
        };
        sqlx::query("INSERT INTO mdm_telemetry.storage_binding(tenant_id,binding,expected_epoch,resource_id,revision,operation_id,material) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id) DO UPDATE SET binding=excluded.binding,expected_epoch=excluded.expected_epoch,resource_id=excluded.resource_id,revision=excluded.revision,operation_id=excluded.operation_id,material=excluded.material")
            .bind(input.tenant).bind(binding.as_slice()).bind(execution.epoch().get()).bind(target.resource_id).bind(revision).bind(input.operation_id).bind(material).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    }
    tx.commit().await.map_err(|_| Error::Storage)?;
    journal.save("receipt.json", &result)?;
    Ok(result)
}
fn old_reader(
    selection: Option<&Selection>,
    key: &Protector,
    tenant: TenantId,
) -> Result<Option<Reader>> {
    selection
        .map(|s| s.reader(key, tenant))
        .transpose()
        .map(Option::flatten)
        .map_err(|_| Error::Corrupt)
}

fn supplied_reader(input: &TenantRequest, target: &Config) -> Result<Option<Reader>> {
    Ok(match (&input.action, &target.backend) {
        (
            Action::Reader {
                password_file,
                cursor_key_file,
            },
            Storage::ClickHouse {
                writer,
                maintenance,
                ..
            },
        ) => {
            let user = format!(
                "mdm_reader_{}",
                Uuid::new_v5(&target.resource_id, input.tenant.as_bytes()).simple()
            );
            let installer = &input
                .installation
                .clickhouse
                .as_ref()
                .ok_or(Error::Input)?
                .installer;
            if [&writer.user, &maintenance.user, &installer.user].contains(&&user) {
                return Err(Error::Input);
            }
            Some(Reader {
                user,
                password: Some(crate::config::secret(password_file).map_err(|_| Error::Input)?),
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

fn freeze_request(
    input: &TenantRequest,
    tenant: TenantId,
    supplied: &Option<Reader>,
    protection: &Protector,
    journal: &Journal,
) -> Result<()> {
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
    if let Some((key, tag)) = journal.load::<(String, Vec<u8>)>("request.json")? {
        protection
            .verify_mac_with_key(&key, &identity, &aad, &tag)
            .map_err(|_| Error::Conflict)?;
    } else {
        journal.save(
            "request.json",
            &(
                protection.fingerprint_id(),
                protection
                    .mac(&identity, &aad)
                    .map_err(|_| Error::Storage)?,
            ),
        )?;
    }
    Ok(())
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

async fn changed_reader(
    input: &TenantRequest,
    supplied: Option<Reader>,
    old: Option<Reader>,
    journal: &Journal,
) -> Result<Option<Reader>> {
    Ok(match (&input.action, supplied) {
        (Action::Reader { .. }, Some(reader)) => {
            if let Some(old) = old {
                if old.user != reader.user || *old.cursor != *reader.cursor {
                    return Err(Error::Conflict);
                }
            } else if !journal
                .load::<bool>("reader-reserved.json")?
                .unwrap_or(false)
            {
                if clickhouse::reader_exists(&input.installation, &reader.user).await? {
                    return Err(Error::Conflict);
                }
                journal.save("reader-reserved.json", &true)?;
            }
            Some(reader)
        }
        (Action::Retire, None) => {
            let mut old = old.ok_or(Error::Conflict)?;
            old.password.take();
            Some(old)
        }
        (Action::Select, None) => None,
        _ => return Err(Error::Input),
    })
}
