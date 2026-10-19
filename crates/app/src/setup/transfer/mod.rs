//! 固定 V4 来源的一次性离线转交。检查点只覆盖停写、迁移和外部宿主副作用。
pub(super) mod accounts;
pub(super) mod backup;
mod containers;
pub(super) mod ledger;
mod materials;
pub mod recovery;
pub(super) mod storage;
mod wns;
use super::{Error, Result, deployment, installation, local::Journal};
pub use accounts::OriginalAccount;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInput {
    pub container_id: String,
    pub administrator: OriginalAccount,
    pub deployment: deployment::Config,
    pub apple_material_roots: Vec<PathBuf>,
    /// Required for retained task keys when the V4 Agent endpoint was not configured yet.
    pub task_runtime_origin: Option<String>,
    pub storage_profile: Option<String>,
    #[serde(default)]
    pub create_storage_identity: bool,
    pub storage_expires_at: Option<i64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation_id: Uuid,
    pub deployment: installation::Input,
    pub owner: crate::config::Database,
    pub source_candidate: PathBuf,
    pub source_manifest_sha256: String,
    pub platform_administrator: OriginalAccount,
    pub hosts: Vec<HostInput>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Stopped,
    BackedUp,
    Migrated,
    Imported,
    Transferred,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub phase: Phase,
    pub source_revision: String,
    pub hosts: Vec<Uuid>,
    pub backup_manifest_sha256: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Host {
    id: Uuid,
    operation: Uuid,
    authorization: Uuid,
    storage_operation: Uuid,
    wns_operation: Uuid,
    keys: BTreeMap<String, Uuid>,
    source: Value,
    runtime: Option<Value>,
    input: HostInput,
}
#[derive(Serialize, Deserialize)]
struct Saved {
    receipt: Receipt,
    evidence: super::source::Evidence,
    containers: Vec<containers::Container>,
    installation: crate::migration::Installation,
    owner: crate::config::Database,
    platform: OriginalAccount,
    operator: installation::Input,
    hosts: Vec<Host>,
}
fn clone<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> Result<T> {
    serde_json::from_value(serde_json::to_value(value).map_err(|_| Error::Input)?)
        .map_err(|_| Error::Input)
}
fn copy_file(
    journal: &Journal,
    name: &str,
    path: &std::path::Path,
    private: bool,
) -> Result<PathBuf> {
    journal.secret(
        name,
        &crate::config::read(path, 64 * 1024 * 1024, private).map_err(|_| Error::Input)?,
    )
}
fn own_gateway(journal: &Journal, prefix: &str, config: &mut deployment::Config) -> Result<()> {
    config.certificate_file = copy_file(
        journal,
        &format!("{prefix}-certificate.pem"),
        &config.certificate_file,
        false,
    )?;
    config.private_key_file = copy_file(
        journal,
        &format!("{prefix}-private.key"),
        &config.private_key_file,
        true,
    )?;
    config.trust_file = copy_file(
        journal,
        &format!("{prefix}-trust.pem"),
        &config.trust_file,
        false,
    )?;
    Ok(())
}
fn own_provider(
    journal: &Journal,
    index: usize,
    profile: &mut super::providers::storage::Profile,
) -> Result<()> {
    profile.ca_file = copy_file(
        journal,
        &format!("storage-{index}-ca.pem"),
        &profile.ca_file,
        false,
    )?;
    for (kind, administrator) in [
        ("admin", &mut profile.rustfs_administrator),
        ("verifier", &mut profile.boundary_verifier),
    ] {
        if let Some(administrator) = administrator {
            administrator.access_key_file = copy_file(
                journal,
                &format!("storage-{index}-{kind}-access"),
                &administrator.access_key_file,
                true,
            )?;
            administrator.secret_key_file = copy_file(
                journal,
                &format!("storage-{index}-{kind}-secret"),
                &administrator.secret_key_file,
                true,
            )?;
            if let Some(token) = &mut administrator.session_token_file {
                *token = copy_file(
                    journal,
                    &format!("storage-{index}-{kind}-token"),
                    token,
                    true,
                )?;
            }
        }
    }
    Ok(())
}
async fn prepare(input: &Request, journal: &Journal) -> Result<Saved> {
    if input.operation_id.is_nil()
        || input.hosts.is_empty()
        || input.hosts.len() > 1024
        || input.owner.user != "mdm_owner"
        || input.owner.name != input.deployment.database.name
        || input.owner.host != input.deployment.database.administrator.host
        || input.owner.port != input.deployment.database.administrator.port
    {
        return Err(Error::Input);
    }
    if journal.load::<Value>("installation.json")?.is_some()
        || journal.load::<Value>("runtime.json")?.is_some()
    {
        return Err(Error::Conflict);
    }
    let evidence = super::source::qualify(&input.source_candidate, &input.source_manifest_sha256)?;
    let mut containers = Vec::new();
    let mut hosts = Vec::new();
    let mut tenants = std::collections::BTreeSet::new();
    for source in &input.hosts {
        let container = containers::inspect(&source.container_id, &evidence.image).await?;
        let id = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let material = Journal::open(
            &input
                .deployment
                .directory
                .join(format!("source-{}", id.simple())),
        )?;
        let mut runtime = container.runtime.clone();
        container.copy_inputs(&material, &mut runtime)?;
        let tenant = runtime["identity"]["tenant_id"]
            .as_str()
            .ok_or(Error::Input)?;
        if Uuid::parse_str(tenant).map_err(|_| Error::Input)?.is_nil()
            || !tenants.insert(tenant.to_owned())
        {
            return Err(Error::Conflict);
        }
        let mut owned: HostInput = clone(source)?;
        own_gateway(&material, "gateway", &mut owned.deployment)?;
        if runtime["content"]["storage"]["kind"] == "volume" {
            let volume = container.resolve(std::path::Path::new(
                runtime["content"]["storage"]["directory"]
                    .as_str()
                    .ok_or(Error::Input)?,
            ))?;
            if owned
                .deployment
                .content_volume
                .as_ref()
                .is_some_and(|configured| configured != &volume)
            {
                return Err(Error::Conflict);
            }
            owned.deployment.content_volume = Some(volume);
        }

        owned.administrator.password_file = copy_file(
            &material,
            "administrator-password",
            &source.administrator.password_file,
            true,
        )?;
        for (index, root) in owned.apple_material_roots.iter_mut().enumerate() {
            *root = copy_file(&material, &format!("apple-root-{index}.pem"), root, false)?;
        }
        if !runtime["task_signing"].is_null() {
            materials::task_origin(&runtime, source.task_runtime_origin.as_deref())?;
        }
        let keys = materials::apple_keys(&runtime)?;
        material.secret(
            "source.json",
            &serde_json::to_vec(&runtime).map_err(|_| Error::Input)?,
        )?;
        hosts.push(Host {
            id,
            operation,
            authorization: Uuid::new_v4(),
            storage_operation: Uuid::new_v4(),
            wns_operation: Uuid::new_v4(),
            keys,
            source: runtime,
            runtime: None,
            input: owned,
        });
        containers.push(container);
    }
    let first = &hosts[0].source;
    let installation = crate::migration::Installation {
        instance_id: first["identity"]["instance_id"]
            .as_str()
            .ok_or(Error::Input)?
            .into(),
        target: serde_json::from_value(first["flow"]["storage"]["target"].clone())
            .map_err(|_| Error::Input)?,
        lineage: serde_json::from_value(first["flow"]["storage"]["lineage"].clone())
            .map_err(|_| Error::Input)?,
        audit_mode: serde_json::from_value::<crate::config::AuditConfig>(first["audit"].clone())
            .map_err(|_| Error::Input)?
            .mode(),
    };
    installation.validate().map_err(|_| Error::Input)?;
    for host in &hosts {
        if host.source["identity"]["instance_id"] != first["identity"]["instance_id"]
            || host.source["flow"]["storage"]["target"] != first["flow"]["storage"]["target"]
            || host.source["flow"]["storage"]["lineage"] != first["flow"]["storage"]["lineage"]
            || host.source["audit"]["mode"] != first["audit"]["mode"]
        {
            return Err(Error::Conflict);
        }
    }
    let mut owner = input.owner.clone();
    owner.password_file = copy_file(
        journal,
        "database-mdm_owner.password",
        &owner.password_file,
        true,
    )?;
    owner.ca_file = copy_file(journal, "database-ca.pem", &owner.ca_file, false)?;
    let mut platform: OriginalAccount = clone(&input.platform_administrator)?;
    platform.password_file =
        copy_file(journal, "platform-password", &platform.password_file, true)?;
    let mut operator: installation::Input = clone(&input.deployment)?;
    operator.database.administrator.password_file = copy_file(
        journal,
        "database-administrator.password",
        &operator.database.administrator.password_file,
        true,
    )?;
    operator.database.administrator.ca_file = copy_file(
        journal,
        "database-administrator-ca.pem",
        &operator.database.administrator.ca_file,
        false,
    )?;
    // 原管理员凭据已由明确主体保存；安装器的新用户输入不参与离线恢复。
    operator.platform_password_file = Some(platform.password_file.clone());
    operator.administrator_password_file = Some(hosts[0].input.administrator.password_file.clone());
    for (index, slot) in operator.additional_hosts.iter_mut().enumerate() {
        own_gateway(journal, &format!("capacity-{index}"), &mut slot.deployment)?;
    }
    for (index, profile) in operator.storage_profiles.iter_mut().enumerate() {
        own_provider(journal, index, profile)?;
    }
    operator.origin = first["product_origin"].as_str().ok_or(Error::Input)?.into();
    operator.listen = serde_json::from_value(first["listen"].clone()).map_err(|_| Error::Input)?;
    operator.trusted_gateway =
        serde_json::from_value(first["trusted_gateway"].clone()).map_err(|_| Error::Input)?;
    operator.deployment = clone(&hosts[0].input.deployment)?;
    for host in hosts.iter().skip(1) {
        operator.additional_hosts.push(super::tenant_hosts::Slot {
            origin: host.source["product_origin"]
                .as_str()
                .ok_or(Error::Input)?
                .into(),
            listen: serde_json::from_value(host.source["listen"].clone())
                .map_err(|_| Error::Input)?,
            deployment: clone(&host.input.deployment)?,
        });
    }
    for (index, profile) in operator.mail_profiles.iter_mut().enumerate() {
        profile.ca_file = copy_file(
            journal,
            &format!("smtp-{index}-ca.pem"),
            &profile.ca_file,
            false,
        )?;
    }
    super::tenant_hosts::validate_slots(&operator)?;
    Ok(Saved {
        receipt: Receipt {
            operation_id: input.operation_id,
            phase: Phase::Prepared,
            source_revision: evidence.source_revision.clone(),
            hosts: hosts.iter().map(|h| h.id).collect(),
            backup_manifest_sha256: None,
        },
        evidence,
        containers,
        installation,
        owner,
        platform,
        operator,
        hosts,
    })
}

pub async fn run(input: Request) -> Result<Receipt> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Input);
    }
    let journal = Journal::open(&input.deployment.directory)?;
    journal.secret(
        "transfer-request.json",
        &serde_json::to_vec(&input).map_err(|_| Error::Input)?,
    )?;
    let saved: Saved = if let Some(saved) = journal.load("transfer.json")? {
        saved
    } else {
        let saved = prepare(&input, &journal).await?;
        journal.save("transfer.json", &saved)?;
        saved
    };
    if saved.receipt.operation_id != input.operation_id {
        return Err(Error::Conflict);
    }
    resume(saved, &journal).await
}
async fn resume(mut saved: Saved, journal: &Journal) -> Result<Receipt> {
    if saved.receipt.phase == Phase::Transferred {
        return Ok(saved.receipt);
    }
    let mut c = source_connection(&saved).await?;
    let administrator = super::backup::administrator(&saved.operator)?;
    super::backup::recovery_administrator(&administrator).await?;
    if saved.receipt.phase == Phase::Prepared {
        stop_source(&mut saved, journal, &mut c).await?;
    }
    if saved.receipt.phase == Phase::Stopped {
        backup_source(&mut saved, journal, &mut c, &administrator).await?;
    }
    if saved.receipt.phase == Phase::BackedUp {
        migrate_source(&mut saved, journal, &mut c).await?;
    }
    if saved.receipt.phase == Phase::Migrated {
        import_materials(&mut saved, journal, &mut c).await?;
    }
    if saved.receipt.phase == Phase::Imported {
        activate_source(&mut saved, journal, &mut c).await?;
    }
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(saved.receipt)
}

async fn exact_source(c: &mut PgConnection) -> Result<()> {
    let actual: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(c)
            .await
            .map_err(|_| Error::Storage)?;
    let manifest = crate::migration::source_manifest();
    let mut expected = manifest["units"]
        .as_array()
        .ok_or(Error::Corrupt)?
        .iter()
        .map(|v| {
            Ok((
                v["name"].as_str().ok_or(Error::Corrupt)?.to_owned(),
                v["sha256"].as_str().ok_or(Error::Corrupt)?.to_owned(),
                true,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    expected.sort();
    if actual != expected {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn stopped(c: &mut PgConnection) -> Result<()> {
    let others:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'").fetch_one(c).await.map_err(|_|Error::Storage)?;
    if others != 0 {
        return Err(Error::Busy);
    }
    Ok(())
}
async fn check_protection(c: &mut PgConnection, source: &Value) -> Result<()> {
    let mut runtime = source.clone();
    let protection = materials::protection(&mut runtime)?;
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let key: Option<String> = sqlx::query_scalar(
        "SELECT key_id FROM mdm_flow.native_protection WHERE tenant_id=$1::uuid",
    )
    .bind(tenant)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| Error::Storage)?;
    if key.as_deref() != Some(protection.fingerprint_id()) {
        return Err(Error::Conflict);
    }
    let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.mdm_tenants t JOIN rss_transactional_messaging.tenant_epoch e USING(tenant_id) WHERE t.tenant_id=$1::uuid AND NOT t.deleted AND e.epoch=$2 AND t.tenant_id<>(SELECT management_tenant_id FROM public.mdm_installation))").bind(tenant).bind(runtime["flow"]["storage"]["epoch"].as_i64().ok_or(Error::Input)?).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
    if !live {
        return Err(Error::Conflict);
    }
    tx.rollback().await.map_err(|_| Error::Storage)
}
async fn qualify_database(c: &mut PgConnection, saved: &Saved) -> Result<()> {
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS public.mdm_installation_transfer(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),operation_id uuid NOT NULL,instance_id uuid NOT NULL,source_revision text NOT NULL,inputs_sha256 text NOT NULL,manifest_sha256 text NOT NULL,phase text NOT NULL CHECK(phase IN('verified','transferred'))); REVOKE ALL ON public.mdm_installation_transfer FROM PUBLIC")
        .execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    sqlx::query("INSERT INTO public.mdm_installation_transfer VALUES(true,$1,$2::uuid,$3,$4,$5,'verified') ON CONFLICT DO NOTHING").bind(saved.receipt.operation_id).bind(&saved.installation.instance_id).bind(&saved.evidence.source_revision).bind(&saved.evidence.inputs_sha256).bind(&saved.evidence.manifest_sha256).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    let matched:bool=sqlx::query_scalar("SELECT count(*)=1 AND bool_and(operation_id=$1 AND instance_id=$2::uuid AND source_revision=$3 AND inputs_sha256=$4 AND manifest_sha256=$5) FROM public.mdm_installation_transfer").bind(saved.receipt.operation_id).bind(&saved.installation.instance_id).bind(&saved.evidence.source_revision).bind(&saved.evidence.inputs_sha256).bind(&saved.evidence.manifest_sha256).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
    if !matched {
        return Err(Error::Conflict);
    }
    tx.commit().await.map_err(|_| Error::Storage)
}
async fn activate(c: &mut PgConnection, journal: &Journal, saved: &mut Saved) -> Result<()> {
    use super::model::{Phase as ProvisioningPhase, Provisioning};
    // migrate_on 使用会话锁；宿主准入也需要同一安装锁，部署前释放本连接的锁。
    sqlx::query("SELECT pg_advisory_unlock_all()")
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    let management: String =
        sqlx::query_scalar("SELECT management_tenant_id::text FROM public.mdm_installation")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    let epoch: i64 = sqlx::query_scalar(
        "SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid",
    )
    .bind(&management)
    .fetch_one(&mut *c)
    .await
    .map_err(|_| Error::Storage)?;
    let first: crate::config::Config =
        serde_json::from_value(saved.hosts[0].runtime.clone().ok_or(Error::Corrupt)?)
            .map_err(|_| Error::Corrupt)?;
    accounts::verify(
        &first,
        &management,
        epoch,
        &saved.platform,
        Some(saved.receipt.operation_id),
    )
    .await?;
    for host in &saved.hosts {
        let config: crate::config::Config =
            serde_json::from_value(host.runtime.clone().ok_or(Error::Corrupt)?)
                .map_err(|_| Error::Corrupt)?;
        accounts::verify(
            &config,
            &config.identity.tenant_id,
            config.flow.storage.epoch,
            &host.input.administrator,
            Some(host.authorization),
        )
        .await?;
    }
    sqlx::query("UPDATE public.mdm_installation_transfer SET phase='transferred' WHERE singleton AND operation_id=$1").bind(saved.receipt.operation_id).execute(&mut *c).await.map_err(|_|Error::Storage)?;
    let mut reservations: BTreeMap<Uuid, usize> =
        journal.load("host-reservations.json")?.unwrap_or_default();
    let offset = saved
        .operator
        .additional_hosts
        .len()
        .checked_sub(saved.hosts.len() - 1)
        .ok_or(Error::Corrupt)?;
    for (index, host) in saved.hosts.iter().enumerate() {
        let runtime = host.runtime.as_ref().ok_or(Error::Corrupt)?;
        let config: crate::config::Config =
            serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
        if index > 0 {
            reservations.insert(host.id, offset + index - 1);
        }
        journal.save("host-reservations.json", &reservations)?;
        let tenant = Uuid::parse_str(&config.identity.tenant_id).map_err(|_| Error::Corrupt)?;
        let mut progress = Provisioning {
            operation_id: host.operation,
            tenant_id: tenant,
            administrator_id: Some(host.input.administrator.principal_id),
            host_id: host.id,
            revision: 1,
            phase: ProvisioningPhase::HostPending,
            blocked: None,
            origin: Some(config.product_origin.clone()),
            application: None,
        };
        publish(c, saved, host, &progress).await?;
        let result = super::tenant_hosts::activate(
            &saved.operator.directory,
            &host.input.deployment,
            runtime,
            &mut progress,
        )
        .await;
        publish(c, saved, host, &progress).await?;
        result?;
    }
    journal.save(
        "runtime.json",
        saved.hosts[0].runtime.as_ref().ok_or(Error::Corrupt)?,
    )?;
    journal.save("transferred-installation.json",&json!({"operationId":saved.receipt.operation_id,"instanceId":saved.installation.instance_id,"source":saved.evidence}))?;
    super::supervisor::install(
        journal,
        &saved.operator,
        Uuid::parse_str(&saved.installation.instance_id).map_err(|_| Error::Corrupt)?,
    )
    .await
}
async fn publish(
    c: &mut PgConnection,
    saved: &Saved,
    host: &Host,
    progress: &super::model::Provisioning,
) -> Result<()> {
    let request = json!({"transferOperation":saved.receipt.operation_id,"manifestSha256":saved.evidence.manifest_sha256});
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT pg_advisory_xact_lock(2346)")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let existing: Option<(Value, Value)> = sqlx::query_as(
        "SELECT request,receipt FROM public.mdm_tenant_operations WHERE operation_id=$1",
    )
    .bind(host.operation)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| Error::Storage)?;
    let mut progress = progress.clone();
    if let Some((old, receipt)) = &existing {
        if old != &request {
            return Err(Error::Conflict);
        }
        let previous: crate::tenant_registry::Receipt =
            serde_json::from_value(receipt.clone()).map_err(|_| Error::Corrupt)?;
        let crate::tenant_registry::ReceiptResult::Provisioning(previous) = previous.result else {
            return Err(Error::Corrupt);
        };
        progress.revision = previous.revision.checked_add(1).ok_or(Error::Corrupt)?;
    }
    let tenant = progress.tenant_id;
    let receipt = crate::tenant_registry::Receipt {
        operation_id: host.operation,
        action: crate::tenant_registry::Action::Provision,
        result: crate::tenant_registry::ReceiptResult::Provisioning(progress),
    };
    if existing.is_some() {
        sqlx::query("UPDATE public.mdm_tenant_operations SET receipt=$2 WHERE operation_id=$1")
            .bind(host.operation)
            .bind(serde_json::to_value(receipt).map_err(|_| Error::Corrupt)?)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
    } else {
        sqlx::query("INSERT INTO public.mdm_tenant_operations(operation_id,tenant_id,action,request,receipt,operator) VALUES($1,$2,'provision',$3,$4,$5)").bind(host.operation).bind(tenant).bind(request).bind(serde_json::to_value(receipt).map_err(|_|Error::Corrupt)?).bind(json!({"kind":"offline_transfer","instanceId":saved.installation.instance_id,"principalId":saved.platform.principal_id})).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    }
    tx.commit().await.map_err(|_| Error::Storage)
}

async fn backup_source(
    saved: &mut Saved,
    journal: &Journal,
    c: &mut PgConnection,
    administrator: &crate::config::Database,
) -> Result<()> {
    super::backup::connection_fence(&mut *c, journal, true).await?;
    stopped(&mut *c).await?;
    let mut heads = Vec::new();
    for host in &saved.hosts {
        let tenant = host.source["identity"]["tenant_id"]
            .as_str()
            .ok_or(Error::Corrupt)?
            .to_owned();
        check_protection(&mut *c, &host.source).await?;
        heads.extend(ledger::verify_operator(&host.source, &[tenant], administrator).await?);
    }
    let management: String =
        sqlx::query_scalar("SELECT management_tenant_id::text FROM public.mdm_installation")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    heads.extend(
        ledger::verify_operator(&saved.hosts[0].source, &[management], administrator).await?,
    );
    journal.secret(
        "ledger-checkpoints.json",
        &serde_json::to_vec(&heads).map_err(|_| Error::Corrupt)?,
    )?;
    let mut database = saved.operator.database.administrator.clone();
    database.name = saved.owner.name.clone();
    backup::capture(journal, &database).await?;
    for host in &saved.hosts {
        if let Some(source) = &host.input.deployment.content_volume {
            backup::volume(journal, host.id, source)?;
        }
        storage::backup(&mut *c, journal, host.id, &host.source).await?;
    }
    saved.receipt.phase = Phase::BackedUp;
    journal.secret(
        "restore-source.json",
        &serde_json::to_vec(saved).map_err(|_| Error::Corrupt)?,
    )?;
    saved.receipt.backup_manifest_sha256 = Some(backup::seal(journal, saved.receipt.operation_id)?);
    journal.save("transfer.json", saved)?;

    Ok(())
}

async fn import_materials(
    saved: &mut Saved,
    journal: &Journal,
    c: &mut PgConnection,
) -> Result<()> {
    for index in 0..saved.hosts.len() {
        let host = &mut saved.hosts[index];
        let mut runtime = host.source.clone();
        let protection = materials::protection(&mut runtime)?;
        materials::bootstrap(&mut runtime)?;
        if let Some(windows) = runtime["native_protocols"]["windows"].as_object_mut() {
            let original = windows.remove("protocol_key_file").ok_or(Error::Corrupt)?;
            windows.insert(
                "protocol_protection".into(),
                json!({"active_file":original,"historical_files":[],"fingerprint_file":original}),
            );
        }
        let tenant = runtime["identity"]["tenant_id"]
            .as_str()
            .ok_or(Error::Corrupt)?
            .to_owned();
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(&tenant)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
        materials::webhooks(&mut tx, &mut runtime, host.operation, &protection, now).await?;
        materials::signing(
            &mut tx,
            &mut runtime,
            host.operation,
            &protection,
            host.input.task_runtime_origin.as_deref(),
        )
        .await?;
        let deferred_apple = materials::apple(
            &mut tx,
            &mut runtime,
            &host.keys,
            &host.input.apple_material_roots,
            now,
            &protection,
        )
        .await?;
        if let Some(settings) = deferred_apple {
            journal.secret(
                &format!("deferred-apple-{}.json", host.id.simple()),
                &serde_json::to_vec(&settings).map_err(|_| Error::Corrupt)?,
            )?;
        }
        tx.commit().await.map_err(|_| Error::Storage)?;
        let profile = host
            .input
            .storage_profile
            .as_ref()
            .and_then(|id| saved.operator.storage_profiles.iter().find(|p| &p.id == id));
        storage::import(
            &mut *c,
            &mut runtime,
            &protection,
            storage::Request {
                directory: &saved.operator.directory,
                profile,
                operation: host.storage_operation,
                expires: host.input.storage_expires_at,
                generate: host.input.create_storage_identity,
            },
        )
        .await?;
        wns::import(&mut *c, &mut runtime, host.wns_operation, &protection).await?;
        let digest = super::application::fingerprint(&runtime)?;
        runtime["runtime_binding"] = json!({"host_id":host.id,"operation_id":host.operation,"revision":1,"material_digest":digest});
        let config: crate::config::Config =
            serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
        config.compile().map_err(|_| Error::Corrupt)?;
        host.runtime = Some(runtime);
        journal.save("transfer.json", saved)?;
    }
    saved.receipt.phase = Phase::Imported;
    journal.save("transfer.json", saved)?;

    Ok(())
}

async fn source_connection(saved: &Saved) -> Result<PgConnection> {
    let mut c = PgConnection::connect_with(&saved.owner.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    sqlx::raw_sql("SET statement_timeout='30s'; SET lock_timeout='10s'")
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    if !crate::migration::owner_admitted(&mut c)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Input);
    }
    crate::migration::verify_identity(&mut c, &saved.installation)
        .await
        .map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(c)
}

async fn stop_source(saved: &mut Saved, journal: &Journal, c: &mut PgConnection) -> Result<()> {
    exact_source(&mut *c).await?;
    super::backup::connection_fence(&mut *c, journal, true).await?;
    containers::stop(&saved.containers).await?;
    saved.receipt.phase = Phase::Stopped;
    journal.save("transfer.json", saved)?;

    Ok(())
}

async fn migrate_source(saved: &mut Saved, journal: &Journal, c: &mut PgConnection) -> Result<()> {
    stopped(&mut *c).await?;
    qualify_database(&mut *c, saved).await?;
    crate::migration::migrate_on(&mut *c, &saved.installation)
        .await
        .map_err(|_| Error::Storage)?;
    saved.receipt.phase = Phase::Migrated;
    journal.save("transfer.json", saved)?;

    Ok(())
}

async fn activate_source(saved: &mut Saved, journal: &Journal, c: &mut PgConnection) -> Result<()> {
    // Immutable backup, migration and material transfer finished; only now admit
    // runtime connections for real authentication and new-authority activation.
    super::backup::connection_fence(&mut *c, journal, false).await?;
    activate(&mut *c, journal, saved).await?;
    sqlx::query("UPDATE public.mdm_installation_transfer SET phase='transferred' WHERE singleton AND operation_id=$1").bind(saved.receipt.operation_id).execute(&mut *c).await.map_err(|_|Error::Storage)?;
    saved.receipt.phase = Phase::Transferred;
    journal.save("transfer.json", saved)?;

    Ok(())
}
