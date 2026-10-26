//! Quiesced current-installation backup. Original CA, database, content and protection identities travel together.
mod accounts;
pub(super) mod archive;
mod ledger;
pub(super) mod storage;
mod telemetry;
use super::{Error, Result, installation::Input, local::Journal, snapshot_tree};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Connection;
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalAccount {
    pub principal_id: Uuid,
    pub login: String,
    pub password_file: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub purpose: rss_mdm_agent_wire::pki::Purpose,
    pub issuer: String,
    pub configuration_file: PathBuf,
    pub online_directory: PathBuf,
    pub offline_directory: PathBuf,
    pub root_private_key_file: PathBuf,
    pub root_password_file: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: Input,
    pub operation_id: Uuid,
    pub directory: PathBuf,
    pub authorities: Vec<Authority>,
    pub telemetry: Vec<super::providers::telemetry::Request>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Reserved,
    Stopped,
    Sealed,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub stage: Stage,
    pub manifest_sha256: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Host {
    id: Uuid,
    tenant: Uuid,
    slot: Option<usize>,
    runtime: Value,
}
#[derive(Serialize, Deserialize)]
struct Frozen {
    request: Request,
    hosts: Vec<Host>,
    installation: crate::migration::Installation,
}
fn ca_file(authority: &Authority, value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.starts_with(&authority.online_directory)
        || path.canonicalize().map_err(|_| Error::Input)? != path
    {
        return Err(Error::Input);
    }
    Ok(path)
}
fn ca_identity(authority: &Authority) -> Result<()> {
    let configuration = &authority.configuration_file;
    if !configuration.starts_with(&authority.online_directory)
        || !authority
            .root_private_key_file
            .starts_with(&authority.offline_directory)
        || !authority
            .root_password_file
            .starts_with(&authority.offline_directory)
    {
        return Err(Error::Input);
    }
    let config: Value = serde_json::from_slice(
        &crate::config::read(configuration, 1024 * 1024, false).map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    let issuer = openssl::x509::X509::from_pem(
        &crate::config::read(
            &ca_file(authority, config["crt"].as_str().ok_or(Error::Input)?)?,
            131072,
            false,
        )
        .map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    if rss_mdm_device_trust::digest(&issuer.to_der().map_err(|_| Error::Input)?) != authority.issuer
    {
        return Err(Error::Conflict);
    }
    let password =
        crate::config::secret(&authority.root_password_file).map_err(|_| Error::Input)?;
    let key = crate::config::read(&authority.root_private_key_file, 32768, true)
        .map_err(|_| Error::Input)?;
    let key = openssl::pkey::PKey::private_key_from_pem_passphrase(&key, password.as_bytes())
        .map_err(|_| Error::Input)?;
    let roots = match &config["root"] {
        Value::String(root) => vec![root.as_str()],
        Value::Array(roots) => roots
            .iter()
            .map(|r| r.as_str().ok_or(Error::Input))
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(Error::Input),
    };
    let mut matched = 0;
    for root in roots {
        let root = openssl::x509::X509::from_pem(
            &crate::config::read(&ca_file(authority, root)?, 131072, false)
                .map_err(|_| Error::Input)?,
        )
        .map_err(|_| Error::Input)?;
        let public = root.public_key().map_err(|_| Error::Input)?;
        if public.public_eq(&key)
            && issuer.verify(&public).map_err(|_| Error::Input)?
            && issuer.issuer_name().to_der().map_err(|_| Error::Input)?
                == root.subject_name().to_der().map_err(|_| Error::Input)?
        {
            matched += 1;
        }
    }
    if matched != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn no_writers(c: &mut sqlx::PgConnection) -> Result<()> {
    let n:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'").fetch_one(c).await.map_err(|_|Error::Storage)?;
    if n != 0 {
        return Err(Error::Busy);
    }
    Ok(())
}
pub(super) fn administrator(input: &Input) -> Result<crate::config::Database> {
    let mut value =
        serde_json::to_value(&input.database.administrator).map_err(|_| Error::Input)?;
    value["name"] = json!(input.database.name);
    serde_json::from_value(value).map_err(|_| Error::Input)
}
// Cold recovery reconnects after runtime CONNECT grants have been withdrawn. Admit the
// deployment administrator before stopping anything; never discover this after quiescence.
pub(super) async fn recovery_administrator(database: &crate::config::Database) -> Result<()> {
    let mut c = sqlx::PgConnection::connect_with(&database.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    let admitted: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
    c.close().await.map_err(|_| Error::Storage)?;
    if !admitted {
        return Err(Error::Input);
    }
    Ok(())
}
pub(super) async fn connection_fence(
    c: &mut sqlx::PgConnection,
    journal: &Journal,
    enable: bool,
) -> Result<()> {
    let roles = if let Some(roles) =
        journal.load::<Vec<(String, bool)>>("database-connections.json")?
    {
        roles
    } else {
        if !enable {
            return Err(Error::Corrupt);
        }
        let roles:Vec<(String,bool)>=sqlx::query_as("SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END,bool_or(a.is_grantable) FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.privilege_type='CONNECT' AND a.grantee<>d.datdba GROUP BY 1 ORDER BY 1").fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
        journal.secret(
            "database-connections.json",
            &serde_json::to_vec(&roles).map_err(|_| Error::Corrupt)?,
        )?;
        roles
    };
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.backup.roles',$1,true)")
        .bind(serde_json::to_string(&roles).map_err(|_| Error::Corrupt)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    sqlx::raw_sql(if enable {r#"DO $backup$
DECLARE entry jsonb; role_name text;
BEGIN
 EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC',current_database());
 FOR role_name IN SELECT DISTINCT pg_get_userbyid(a.grantee)::text FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.privilege_type='CONNECT' AND a.grantee NOT IN (0,d.datdba) LOOP
  IF role_name=current_user THEN CONTINUE; END IF;
  EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %s',current_database(),CASE WHEN role_name='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(role_name) END);
 END LOOP;
END $backup$;"#}else{r#"DO $backup$
DECLARE entry jsonb; role_name text;
BEGIN
 FOR entry IN SELECT value FROM jsonb_array_elements(current_setting('rss.backup.roles')::jsonb) LOOP
  role_name:=entry->>0;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %s%s',current_database(),CASE WHEN role_name='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(role_name) END,CASE WHEN (entry->>1)::boolean THEN ' WITH GRANT OPTION' ELSE '' END);
 END LOOP;
END $backup$;"#}).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)
}
pub async fn capture(input: Request) -> Result<Receipt> {
    if input.operation_id.is_nil()
        || input.directory.starts_with(&input.installation.directory)
        || input.installation.directory.starts_with(&input.directory)
    {
        return Err(Error::Input);
    }
    let root = Journal::open(&input.installation.directory)?;

    for marker in ["protection-operation.json", "configuration-operation.json"] {
        if root.load::<Option<Uuid>>(marker)?.flatten().is_some() {
            return Err(Error::Busy);
        }
    }
    if root
        .load::<Option<Uuid>>("backup-operation.json")?
        .flatten()
        .is_some_and(|id| id != input.operation_id)
    {
        return Err(Error::Busy);
    }
    let journal = Journal::open(&input.directory)?;
    journal.secret(
        "backup-request.json",
        &serde_json::to_vec(&input).map_err(|_| Error::Input)?,
    )?;
    let mut progress = journal
        .load::<Receipt>("backup-progress.json")?
        .unwrap_or(Receipt {
            operation_id: input.operation_id,
            stage: Stage::Reserved,
            manifest_sha256: None,
        });
    if progress.operation_id != input.operation_id {
        return Err(Error::Conflict);
    }
    if progress.stage == Stage::Complete {
        archive::verify(
            &journal,
            progress.manifest_sha256.as_deref().ok_or(Error::Corrupt)?,
        )?;
        if root
            .load::<Option<Uuid>>("backup-operation.json")?
            .flatten()
            == Some(input.operation_id)
        {
            root.save("backup-operation.json", &Option::<Uuid>::None)?;
        }
        return Ok(progress);
    }
    let frozen = if let Some(frozen) = journal.load::<Frozen>("restore-source.json")? {
        frozen
    } else {
        freeze_backup(input, &root, &journal).await?
    };
    recovery_administrator(&administrator(&frozen.request.installation)?).await?;
    root.save("backup-operation.json", &Some(progress.operation_id))?;
    journal.save("backup-progress.json", &progress)?;
    if progress.stage == Stage::Reserved {
        progress.stage = Stage::Stopped;
        journal.save("backup-progress.json", &progress)?;
    }
    if progress.stage == Stage::Stopped {
        capture_stopped(&frozen, &journal, &mut progress).await?;
    }
    if progress.stage == Stage::Sealed {
        resume_capture(&frozen, &journal, &root, &mut progress).await?;
    }
    Ok(progress)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restore {
    pub directory: PathBuf,
    pub operation_id: Uuid,
    pub backup_manifest_sha256: String,
    pub administrator: crate::config::Database,
    pub accounts: Vec<RestoreAccount>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreAccount {
    pub tenant_id: Uuid,
    pub account: OriginalAccount,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RestoreStage {
    Reserved,
    Files,
    Database,
    Contents,
    Complete,
}
#[derive(Serialize, Deserialize)]
struct RestoreProgress {
    operation: Uuid,
    manifest: String,
    stage: RestoreStage,
}
pub async fn restore(input: Restore) -> Result<Receipt> {
    if input.operation_id.is_nil() {
        return Err(Error::Input);
    }
    let journal = Journal::open(&input.directory)?;
    let bundle = archive::verify(&journal, &input.backup_manifest_sha256)?;
    let frozen: Frozen = journal.load("restore-source.json")?.ok_or(Error::Corrupt)?;
    if bundle.operation != frozen.request.operation_id
        || frozen.request.directory != input.directory
    {
        return Err(Error::Conflict);
    }
    journal.secret(
        "restore-request.json",
        &serde_json::to_vec(&input).map_err(|_| Error::Input)?,
    )?;
    let mut progress = journal
        .load::<RestoreProgress>("restore-progress.json")?
        .unwrap_or(RestoreProgress {
            operation: input.operation_id,
            manifest: input.backup_manifest_sha256.clone(),
            stage: RestoreStage::Reserved,
        });
    if progress.operation != input.operation_id || progress.manifest != input.backup_manifest_sha256
    {
        return Err(Error::Conflict);
    }
    if progress.stage == RestoreStage::Complete {
        let root = Journal::open(&frozen.request.installation.directory)?;
        if root
            .load::<Option<Uuid>>("backup-operation.json")?
            .flatten()
            == Some(frozen.request.operation_id)
        {
            root.save("backup-operation.json", &Option::<Uuid>::None)?;
        }
        return Ok(Receipt {
            operation_id: input.operation_id,
            stage: Stage::Complete,
            manifest_sha256: Some(input.backup_manifest_sha256),
        });
    }
    journal.save("restore-progress.json", &progress)?;
    if input.administrator.host != frozen.request.installation.database.administrator.host
        || input.administrator.port != frozen.request.installation.database.administrator.port
        || input.administrator.name != frozen.request.installation.database.name
    {
        return Err(Error::Conflict);
    }
    recovery_administrator(&input.administrator).await?;
    if progress.stage != RestoreStage::Contents {
        restore_stopped(&input, &frozen, &journal, &mut progress).await?;
    }
    let root = Journal::open(&frozen.request.installation.directory)?;
    let mut c =
        sqlx::PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    if let Err(error) = async {
        connection_fence(&mut c, &journal, false).await?;
        c.close().await.map_err(|_| Error::Storage)?;
        telemetry::release(&frozen, &journal).await?;
        telemetry::admit(&frozen).await?;
        activate_restored(&input, &frozen, &journal, &root).await
    }
    .await
    {
        let _ = telemetry::fence(&frozen, &journal).await;
        let mut c = sqlx::PgConnection::connect_with(
            &input.administrator.options().map_err(|_| Error::Input)?,
        )
        .await
        .map_err(|_| Error::Storage)?;
        connection_fence(&mut c, &journal, true).await?;
        c.close().await.map_err(|_| Error::Storage)?;
        return Err(error);
    }
    progress.stage = RestoreStage::Complete;
    journal.save("restore-progress.json", &progress)?;
    root.save("backup-operation.json", &Option::<Uuid>::None)?;
    Ok(Receipt {
        operation_id: input.operation_id,
        stage: Stage::Complete,
        manifest_sha256: Some(input.backup_manifest_sha256),
    })
}

async fn freeze_backup(input: Request, root: &Journal, journal: &Journal) -> Result<Frozen> {
    let runtime: Value = root.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let config: crate::config::Config =
        serde_json::from_value(runtime).map_err(|_| Error::Corrupt)?;
    let installation = crate::migration::Installation {
        instance_id: config.identity.instance_id,
        target: config.flow.storage.target,
        lineage: config.flow.storage.lineage,
        audit_mode: config.audit.mode(),
    };
    let mut c = sqlx::PgConnection::connect_with(
        &input
            .installation
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    crate::migration::verify_identity(&mut c, &installation)
        .await
        .map_err(|_| Error::Conflict)?;
    let slots: BTreeMap<Uuid, usize> = root.load("host-reservations.json")?.unwrap_or_default();
    let receipts:Vec<Value>=sqlx::query_scalar("SELECT receipt FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='enabled' ORDER BY operation_id").fetch_all(&mut c).await.map_err(|_|Error::Storage)?;
    c.close().await.map_err(|_| Error::Storage)?;
    let mut hosts = Vec::new();
    for receipt in receipts {
        hosts.push(freeze_host(&input, &slots, receipt).await?);
    }
    if hosts.is_empty() {
        return Err(Error::Conflict);
    }
    for authority in &input.authorities {
        if !authority.online_directory.is_absolute()
            || !authority.offline_directory.is_absolute()
            || authority
                .offline_directory
                .starts_with(&authority.online_directory)
            || authority
                .online_directory
                .starts_with(&authority.offline_directory)
        {
            return Err(Error::Input);
        }
        ca_identity(authority)?;
    }
    let frozen = Frozen {
        request: input,
        hosts,
        installation,
    };
    telemetry::validate(&frozen)?;
    journal.secret(
        "restore-source.json",
        &serde_json::to_vec(&frozen).map_err(|_| Error::Input)?,
    )?;
    Ok(frozen)
}

async fn freeze_host(
    input: &Request,
    slots: &BTreeMap<Uuid, usize>,
    receipt: Value,
) -> Result<Host> {
    let receipt: crate::tenant_registry::Receipt =
        serde_json::from_value(receipt).map_err(|_| Error::Corrupt)?;
    let crate::tenant_registry::ReceiptResult::Provisioning(p) = receipt.result else {
        return Err(Error::Corrupt);
    };
    let owner = Journal::open(
        &input
            .installation
            .directory
            .join(format!("rss-mdm-{}", p.host_id.simple())),
    )?;
    let runtime: Value = owner
        .load("requested-runtime.json")?
        .ok_or(Error::Corrupt)?;
    let applied: super::runtime_files::Applied =
        owner.load("applied.json")?.ok_or(Error::Corrupt)?;
    if runtime["runtime_binding"]["operation_id"] != json!(applied.operation_id)
        || applied.host_id != p.host_id
        || applied.tenant_id != p.tenant_id.to_string()
    {
        return Err(Error::Conflict);
    }
    for provider in runtime["device_pki"].as_array().ok_or(Error::Corrupt)? {
        if !input.authorities.iter().any(|a| {
            json!(a.purpose) == provider["purpose"] && json!(a.issuer) == provider["issuer"]
        }) {
            return Err(Error::Conflict);
        }
    }
    host_deployment(&input.installation, slots.get(&p.host_id).copied())?
        .content_snapshot(&runtime)?;
    Ok(Host {
        id: p.host_id,
        tenant: p.tenant_id,
        slot: slots.get(&p.host_id).copied(),
        runtime,
    })
}

fn host_deployment(input: &Input, slot: Option<usize>) -> Result<&super::runtime_files::Config> {
    match slot {
        Some(index) => input
            .additional_hosts
            .get(index)
            .map(|s| &s.deployment)
            .ok_or(Error::Corrupt),
        None => Ok(&input.deployment),
    }
}

async fn capture_stopped(frozen: &Frozen, journal: &Journal, progress: &mut Receipt) -> Result<()> {
    let owner = frozen.request.installation.database("mdm_owner")?;
    let mut c = sqlx::PgConnection::connect_with(&owner.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    connection_fence(&mut c, journal, true).await?;
    no_writers(&mut c).await?;
    telemetry::capture(frozen, journal).await?;
    capture_ledger_heads(&mut c, frozen, journal).await?;
    for host in &frozen.hosts {
        let deployment = host_deployment(&frozen.request.installation, host.slot)?;
        let volume = deployment.content_snapshot(&host.runtime)?;
        snapshot_tree::capture(journal, &format!("volume-{}", host.id.simple()), &volume)?;
        storage::capture(&mut c, journal, host.id, &host.runtime).await?;
    }
    no_writers(&mut c).await?;
    // Forced RLS must not filter a whole-installation archive. The deployment
    // administrator was admitted before quiescence; runtime roles remain fenced.
    archive::capture(journal, &administrator(&frozen.request.installation)?).await?;
    c.close().await.map_err(|_| Error::Storage)?;
    for (index, authority) in frozen.request.authorities.iter().enumerate() {
        snapshot_tree::capture(journal, &format!("ca-{index}"), &authority.online_directory)?;
        snapshot_tree::capture(
            journal,
            &format!("ca-offline-{index}"),
            &authority.offline_directory,
        )?;
    }
    let mut inputs =
        vec![serde_json::to_value(&frozen.request.installation).map_err(|_| Error::Corrupt)?];
    inputs.extend(frozen.hosts.iter().map(|h| h.runtime.clone()));
    inputs.extend(
        frozen
            .request
            .telemetry
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Input)?,
    );
    snapshot_tree::capture_inputs(journal, &inputs)?;
    snapshot_tree::capture(
        journal,
        "installation",
        &frozen.request.installation.directory,
    )?;
    progress.manifest_sha256 = Some(archive::seal(journal, progress.operation_id)?);
    progress.stage = Stage::Sealed;
    journal.save("backup-progress.json", progress)?;

    Ok(())
}

async fn resume_capture(
    frozen: &Frozen,
    journal: &Journal,
    root: &Journal,
    progress: &mut Receipt,
) -> Result<()> {
    let mut c = sqlx::PgConnection::connect_with(
        &frozen
            .request
            .installation
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    telemetry::release(frozen, journal).await?;
    connection_fence(&mut c, journal, false).await?;
    c.close().await.map_err(|_| Error::Storage)?;

    progress.stage = Stage::Complete;
    journal.save("backup-progress.json", progress)?;
    root.save("backup-operation.json", &Option::<Uuid>::None)?;

    Ok(())
}

async fn restore_stopped(
    input: &Restore,
    frozen: &Frozen,
    journal: &Journal,
    progress: &mut RestoreProgress,
) -> Result<()> {
    let mut c =
        sqlx::PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    no_writers(&mut c).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(2823,4)")
        .fetch_one(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    if !locked {
        return Err(Error::Busy);
    }
    reserve_restore(&mut c, input.operation_id, &input.backup_manifest_sha256).await?;
    connection_fence(&mut c, journal, true).await?;
    no_writers(&mut c).await?;
    if progress.stage == RestoreStage::Reserved {
        restore_files(frozen, journal, progress).await?;
    }
    if progress.stage == RestoreStage::Files {
        restore_database_snapshot(input, frozen, journal, progress, &mut c).await?;
    }
    c.close().await.map_err(|_| Error::Storage)?;
    if progress.stage == RestoreStage::Database {
        telemetry::restore(input, frozen, journal).await?;
        restore_contents(input, frozen, journal, progress).await?;
    }

    Ok(())
}

async fn restore_files(
    frozen: &Frozen,
    journal: &Journal,
    progress: &mut RestoreProgress,
) -> Result<()> {
    for index in 0..frozen.request.authorities.len() {
        snapshot_tree::restore(journal, &format!("ca-{index}"))?;
        snapshot_tree::restore(journal, &format!("ca-offline-{index}"))?;
    }
    snapshot_tree::restore(journal, "installation")?;
    snapshot_tree::restore_inputs(journal)?;
    progress.stage = RestoreStage::Files;
    journal.save("restore-progress.json", progress)?;

    Ok(())
}

async fn restore_contents(
    input: &Restore,
    frozen: &Frozen,
    journal: &Journal,
    progress: &mut RestoreProgress,
) -> Result<()> {
    let owner = frozen.request.installation.database("mdm_owner")?;
    let mut c = sqlx::PgConnection::connect_with(&owner.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    connection_fence(&mut c, journal, true).await?;
    no_writers(&mut c).await?;
    for host in &frozen.hosts {
        let deployment = host_deployment(&frozen.request.installation, host.slot)?;
        deployment.content_snapshot(&host.runtime)?;
        snapshot_tree::restore(journal, &format!("volume-{}", host.id.simple()))?;
        storage::restore(&mut c, journal, host.id, &host.runtime).await?;
    }
    let expected: Vec<ledger::Head> = journal
        .load("ledger-checkpoints.json")?
        .ok_or(Error::Corrupt)?;
    for head in expected {
        let host = frozen
            .hosts
            .iter()
            .find(|host| host.tenant.to_string() == head.tenant)
            .unwrap_or(&frozen.hosts[0]);
        let actual = ledger::verify_operator(
            &host.runtime,
            std::slice::from_ref(&head.tenant),
            &input.administrator,
        )
        .await?;
        if serde_json::to_value(&actual[0]).map_err(|_| Error::Corrupt)?
            != serde_json::to_value(&head).map_err(|_| Error::Corrupt)?
        {
            return Err(Error::Corrupt);
        }
    }
    c.close().await.map_err(|_| Error::Storage)?;
    progress.stage = RestoreStage::Contents;
    journal.save("restore-progress.json", progress)?;

    Ok(())
}

async fn activate_restored(
    input: &Restore,
    frozen: &Frozen,
    _journal: &Journal,
    _root: &Journal,
) -> Result<()> {
    for host in &frozen.hosts {
        let deployment = host_deployment(&frozen.request.installation, host.slot)?;
        super::runtime_files::prepare(
            &frozen.request.installation.directory,
            deployment,
            &host.runtime,
        )
        .await?;
    }
    let mut c =
        sqlx::PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    let management: Uuid =
        sqlx::query_scalar("SELECT management_tenant_id FROM public.mdm_installation")
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
    let mut required = frozen
        .hosts
        .iter()
        .map(|h| h.tenant)
        .collect::<std::collections::BTreeSet<_>>();
    required.insert(management);
    let supplied = input
        .accounts
        .iter()
        .map(|a| a.tenant_id)
        .collect::<std::collections::BTreeSet<_>>();
    if supplied != required || supplied.len() != input.accounts.len() {
        return Err(Error::Input);
    }
    for account in &input.accounts {
        let host = frozen
            .hosts
            .iter()
            .find(|h| h.tenant == account.tenant_id)
            .unwrap_or(&frozen.hosts[0]);
        let config: crate::config::Config =
            serde_json::from_value(host.runtime.clone()).map_err(|_| Error::Corrupt)?;
        let epoch: i64 = sqlx::query_scalar(
            "SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1",
        )
        .bind(account.tenant_id)
        .fetch_one(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
        accounts::verify_restored(
            &config,
            &account.tenant_id.to_string(),
            epoch,
            &account.account,
            account.tenant_id == management,
        )
        .await?;
    }
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(())
}

pub(super) async fn reserve_restore(
    c: &mut sqlx::PgConnection,
    operation: Uuid,
    manifest: &str,
) -> Result<()> {
    let reserved: bool =
        sqlx::query_scalar("SELECT to_regclass('public.mdm_restore_operation') IS NOT NULL")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    if !reserved {
        let tables:i64=sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN('r','p','v','m','S','f')").fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
        if tables != 0 {
            return Err(Error::Conflict);
        }
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        sqlx::raw_sql("CREATE TABLE public.mdm_restore_operation(singleton boolean PRIMARY KEY CHECK(singleton),operation uuid NOT NULL,manifest text NOT NULL); REVOKE ALL ON public.mdm_restore_operation FROM PUBLIC").execute(&mut *tx).await.map_err(|_|Error::Storage)?;
        sqlx::query("INSERT INTO public.mdm_restore_operation VALUES(true,$1,$2)")
            .bind(operation)
            .bind(manifest)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
    }
    let marker: (Uuid, String) = sqlx::query_as(
        "SELECT operation,manifest FROM public.mdm_restore_operation WHERE singleton",
    )
    .fetch_one(&mut *c)
    .await
    .map_err(|_| Error::Storage)?;
    if marker != (operation, manifest.to_owned()) {
        return Err(Error::Conflict);
    }
    Ok(())
}

async fn capture_ledger_heads(
    c: &mut sqlx::PgConnection,
    frozen: &Frozen,
    journal: &Journal,
) -> Result<()> {
    let admin = administrator(&frozen.request.installation)?;
    let tenants: Vec<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM public.mdm_tenants UNION SELECT management_tenant_id FROM public.mdm_installation ORDER BY 1")
            .fetch_all(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    let mut checkpoints = Vec::new();
    for tenant in tenants {
        let runtime = frozen
            .hosts
            .iter()
            .find(|h| h.tenant == tenant)
            .unwrap_or(&frozen.hosts[0]);
        checkpoints.extend(
            ledger::verify_operator(&runtime.runtime, &[tenant.to_string()], &admin).await?,
        );
    }
    journal.secret(
        "ledger-checkpoints.json",
        &serde_json::to_vec(&checkpoints).map_err(|_| Error::Corrupt)?,
    )?;
    Ok(())
}

async fn restore_database_snapshot(
    input: &Restore,
    frozen: &Frozen,
    journal: &Journal,
    progress: &mut RestoreProgress,
    c: &mut sqlx::PgConnection,
) -> Result<()> {
    let committed: bool =
        sqlx::query_scalar("SELECT to_regclass('public.mdm_installation') IS NOT NULL")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    if !committed {
        archive::restore_database(journal, &input.administrator).await?;
    }
    crate::migration::verify_identity(&mut *c, &frozen.installation)
        .await
        .map_err(|_| Error::Conflict)?;
    progress.stage = RestoreStage::Database;
    journal.save("restore-progress.json", progress)?;

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/setup/backup.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/setup/telemetry_backup.rs"]
pub(crate) mod telemetry_fixture;

#[cfg(test)]
#[path = "../../tests/setup/storage.rs"]
mod storage_tests;
