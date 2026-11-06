//! Cold DA backup: original installation, CA, protected material and Audit history move together.
use crate::{
    Error, Result,
    config::{self, Config, Database},
};

use rss_mdm_install_support::{
    StorageProfile,
    maintenance::{archive, fence, journal::Journal, snapshot_tree},
};

use serde::{Deserialize, Serialize};

use sqlx::Connection;

use std::path::PathBuf;

use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation_id: Uuid,
    pub directory: PathBuf,
    pub installation_directory: PathBuf,
    pub runtime_file: PathBuf,
    pub administrator: Database,
    pub authorities: Vec<rss_mdm_pki_service::backup::Authority>,
}
#[derive(Serialize, Deserialize)]
struct Frozen {
    request: Request,
    runtime: serde_json::Value,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Reserved,
    Sealed,
    Complete,
}
#[derive(Serialize, Deserialize)]
struct Progress {
    operation: Uuid,
    stage: Stage,
    digest: Option<String>,
}
fn storage(_: rss_mdm_install_support::maintenance::Error) -> Error {
    Error::Storage
}
async fn administrator(db: &Database) -> Result<sqlx::PgConnection> {
    let mut c = sqlx::PgConnection::connect_with(&db.options()?)
        .await
        .map_err(|_| Error::Storage)?;

    let admitted: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;

    if !admitted {
        c.close().await.map_err(|_| Error::Storage)?;

        return Err(Error::Admission);
    }
    Ok(c)
}
fn config(frozen: &Frozen) -> Result<Config> {
    let c: Config =
        serde_json::from_value(frozen.runtime.clone()).map_err(|_| Error::Configuration)?;

    c.validate()?;

    if !frozen.request.administrator.same_database(&c.database) {
        return Err(Error::Configuration);
    }
    Ok(c)
}
fn authorities(frozen: &Frozen, c: &Config) -> Result<()> {
    let expected = c
        .registration
        .providers
        .iter()
        .map(|p| p.issuer.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let supplied = frozen
        .request
        .authorities
        .iter()
        .map(|p| p.issuer.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    if supplied != expected || supplied.len() != frozen.request.authorities.len() {
        return Err(Error::Configuration);
    }
    for authority in &frozen.request.authorities {
        if authority.purpose != rss_mdm_agent_wire::pki::Purpose::DaDevice {
            return Err(Error::Configuration);
        }
        rss_mdm_pki_service::backup::verify(authority).map_err(storage)?;
    }
    Ok(())
}
async fn heads(
    config: &Config,
    db: &Database,
) -> Result<Vec<rss_mdm_audit_integration::backup::Head>> {
    let key = match &config.audit {
        config::Audit::Plain => None,
        config::Audit::Ledger { key_id, .. } => Some(key_id.as_str()),
    };

    rss_mdm_audit_integration::backup::verify_operator(
        StorageProfile::Da,
        config.audit.integrity()?,
        key,
        &config
            .installation
            .tenants()?
            .iter()
            .map(|(t, _)| t.to_string())
            .collect::<Vec<_>>(),
        &db.options()?,
    )
    .await
    .map_err(storage)
}
async fn verify_owner(c: &mut sqlx::PgConnection, config: &Config) -> Result<()> {
    rss_mdm_device_access_runtime::installation::verify_catalog(c)
        .await
        .map_err(|_| Error::Admission)?;

    rss_mdm_install_support::verify_manifest(
        c,
        StorageProfile::Da,
        &rss_mdm_device_access_runtime::installation::standalone_units(config.audit.ledger()),
    )
    .await
    .map_err(|_| Error::Admission)?;

    let host = crate::installation::composition(&config.installation, config.audit.ledger())?;

    rss_mdm_install_support::verify_binding(
        c,
        &host.binding().map_err(|_| Error::Configuration)?,
        &rss_mdm_device_access_runtime::installation::standalone_units(config.audit.ledger()),
    )
    .await
    .map_err(|_| Error::Admission)?;

    Ok(())
}
pub async fn capture(input: Request) -> Result<()> {
    if input.operation_id.is_nil()
        || !input
            .runtime_file
            .starts_with(&input.installation_directory)
        || input.directory.starts_with(&input.installation_directory)
        || input.installation_directory.starts_with(&input.directory)
    {
        return Err(Error::Configuration);
    }
    let root = Journal::open(&input.installation_directory).map_err(storage)?;

    if root
        .load::<Option<Uuid>>("backup-operation.json")
        .map_err(storage)?
        .flatten()
        .is_some_and(|id| id != input.operation_id)
    {
        return Err(Error::Admission);
    }
    let journal = Journal::open(&input.directory).map_err(storage)?;

    journal
        .secret(
            "backup-request.json",
            &serde_json::to_vec(&input).map_err(|_| Error::Configuration)?,
        )
        .map_err(storage)?;

    let mut progress = journal
        .load::<Progress>("backup-progress.json")
        .map_err(storage)?
        .unwrap_or(Progress {
            operation: input.operation_id,
            stage: Stage::Reserved,
            digest: None,
        });

    if progress.operation != input.operation_id {
        return Err(Error::Admission);
    }
    if progress.stage == Stage::Complete {
        archive::verify(&journal, progress.digest.as_deref().ok_or(Error::Storage)?)
            .map_err(storage)?;

        root.save("backup-operation.json", &Option::<Uuid>::None)
            .map_err(storage)?;
        println!(
            "{}",
            serde_json::to_string(&progress).map_err(|_| Error::Storage)?
        );

        return Ok(());
    }
    let frozen = match journal
        .load::<Frozen>("restore-source.json")
        .map_err(storage)?
    {
        Some(v) => v,
        None => {
            let runtime = config::load::<serde_json::Value>(&input.runtime_file)?;

            let f = Frozen {
                request: input,
                runtime,
            };

            let c = config(&f)?;

            authorities(&f, &c)?;

            journal
                .secret(
                    "restore-source.json",
                    &serde_json::to_vec(&f).map_err(|_| Error::Configuration)?,
                )
                .map_err(storage)?;

            f
        }
    };

    let config = config(&frozen)?;

    let mut c = administrator(&frozen.request.administrator).await?;

    let result = async {
        root.save("backup-operation.json", &Some(progress.operation))
            .map_err(storage)?;

        journal
            .save("backup-progress.json", &progress)
            .map_err(storage)?;

        fence::connection_fence(&mut c, &journal, true)
            .await
            .map_err(storage)?;

        fence::no_writers(&mut c).await.map_err(storage)?;

        if progress.stage == Stage::Reserved {
            verify_owner(&mut c, &config).await?;

            authorities(&frozen, &config)?;

            journal
                .secret(
                    "ledger-checkpoints.json",
                    &serde_json::to_vec(&heads(&config, &frozen.request.administrator).await?)
                        .map_err(|_| Error::Storage)?,
                )
                .map_err(storage)?;

            snapshot_tree::capture_excluding(
                &journal,
                "installation",
                &frozen.request.installation_directory,
                &[PathBuf::from("backup-operation.json")],
            )
            .map_err(storage)?;

            snapshot_tree::capture_inputs(
                &journal,
                &[
                    frozen.runtime.clone(),
                    serde_json::to_value(&frozen.request).map_err(|_| Error::Configuration)?,
                ],
            )
            .map_err(storage)?;

            for (i, a) in frozen.request.authorities.iter().enumerate() {
                snapshot_tree::capture(&journal, &format!("ca-{i}"), &a.online_directory)
                    .map_err(storage)?;

                snapshot_tree::capture(&journal, &format!("ca-offline-{i}"), &a.offline_directory)
                    .map_err(storage)?;
            }
            archive::capture(&journal, &frozen.request.administrator.archive()?)
                .await
                .map_err(storage)?;

            fence::no_writers(&mut c).await.map_err(storage)?;

            progress.digest = Some(archive::seal(&journal, progress.operation).map_err(storage)?);

            progress.stage = Stage::Sealed;

            journal
                .save("backup-progress.json", &progress)
                .map_err(storage)?;
        }
        archive::verify(&journal, progress.digest.as_deref().ok_or(Error::Storage)?)
            .map_err(storage)?;

        fence::connection_fence(&mut c, &journal, false)
            .await
            .map_err(storage)?;

        progress.stage = Stage::Complete;

        journal
            .save("backup-progress.json", &progress)
            .map_err(storage)?;

        root.save("backup-operation.json", &Option::<Uuid>::None)
            .map_err(storage)?;

        Ok(())
    }
    .await;

    let closed = c.close().await.map_err(|_| Error::Storage);

    result.and(closed)?;

    println!(
        "{}",
        serde_json::to_string(&progress).map_err(|_| Error::Storage)?
    );

    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restore {
    pub operation_id: Uuid,
    pub directory: PathBuf,
    pub backup_manifest_sha256: String,
    pub administrator: Database,
    pub accounts: Vec<crate::maintenance::OriginalAccount>,
}
pub async fn restore(input: Restore) -> Result<()> {
    if input.operation_id.is_nil() {
        return Err(Error::Configuration);
    }
    let journal = Journal::open(&input.directory).map_err(storage)?;

    let bundle = archive::verify(&journal, &input.backup_manifest_sha256).map_err(storage)?;

    let frozen: Frozen = journal
        .load("restore-source.json")
        .map_err(storage)?
        .ok_or(Error::Storage)?;

    if bundle.operation != frozen.request.operation_id
        || input.directory != frozen.request.directory
        || !input
            .administrator
            .same_database(&frozen.request.administrator)
    {
        return Err(Error::Admission);
    }
    journal
        .secret(
            "restore-request.json",
            &serde_json::to_vec(&input).map_err(|_| Error::Configuration)?,
        )
        .map_err(storage)?;

    let config = config(&frozen)?;

    let mut c = administrator(&input.administrator).await?;

    let result=async {
  fence::connection_fence(&mut c,&journal,true).await.map_err(storage)?;

  fence::no_writers(&mut c).await.map_err(storage)?;

  let marker:bool=sqlx::query_scalar("SELECT to_regclass('public.da_restore_operation') IS NOT NULL").fetch_one(&mut c).await.map_err(|_|Error::Storage)?;

  if !marker {
   let empty:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN('r','p','v','m','S','f'))").fetch_one(&mut c).await.map_err(|_|Error::Storage)?;

   if !empty{return Err(Error::Admission)}
   let mut tx=c.begin().await.map_err(|_|Error::Storage)?;

   sqlx::raw_sql("CREATE TABLE public.da_restore_operation(singleton boolean PRIMARY KEY CHECK(singleton),operation uuid NOT NULL,manifest text NOT NULL,baseline_verified boolean NOT NULL DEFAULT false,complete boolean NOT NULL DEFAULT false); REVOKE ALL ON public.da_restore_operation FROM PUBLIC; GRANT SELECT(complete) ON public.da_restore_operation TO da_access;").execute(&mut *tx).await.map_err(|_|Error::Storage)?;

   sqlx::query("INSERT INTO public.da_restore_operation(singleton,operation,manifest) VALUES(true,$1,$2)").bind(input.operation_id).bind(&input.backup_manifest_sha256).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
tx.commit().await.map_err(|_|Error::Storage)?;

  }
  let bound:(Uuid,String,bool,bool)=sqlx::query_as("SELECT operation,manifest,baseline_verified,complete FROM public.da_restore_operation").fetch_one(&mut c).await.map_err(|_|Error::Storage)?;

  if bound.0!=input.operation_id||bound.1!=input.backup_manifest_sha256{return Err(Error::Admission)}
  if bound.3 {
   let root=Journal::open(&frozen.request.installation_directory).map_err(storage)?;

   root.save("backup-operation.json",&Option::<Uuid>::None).map_err(storage)?;

   fence::connection_fence(&mut c,&journal,false).await.map_err(storage)?;
return Ok(())
  }
  if !bound.2 {
  for i in 0..frozen.request.authorities.len(){snapshot_tree::restore(&journal,&format!("ca-{i}")).map_err(storage)?;
snapshot_tree::restore(&journal,&format!("ca-offline-{i}")).map_err(storage)?;
}
  snapshot_tree::restore(&journal,"installation").map_err(storage)?;
snapshot_tree::restore_inputs(&journal).map_err(storage)?;
authorities(&frozen,&config)?;

  let restored:bool=sqlx::query_scalar("SELECT to_regclass('rss_da.installation_binding') IS NOT NULL").fetch_one(&mut c).await.map_err(|_|Error::Storage)?;

  if !restored {archive::restore_database(&journal,&input.administrator.archive()?).await.map_err(storage)?;
}
  verify_owner(&mut c,&config).await?;

  let expected:serde_json::Value=journal.load("ledger-checkpoints.json").map_err(storage)?.ok_or(Error::Storage)?;

  if serde_json::to_value(heads(&config,&input.administrator).await?).map_err(|_|Error::Storage)?!=expected{return Err(Error::Admission)}
  sqlx::query("UPDATE public.da_restore_operation SET baseline_verified=true WHERE singleton").execute(&mut c).await.map_err(|_|Error::Storage)?;

  } else {
   // Login verification appends audit records. On retry validate the chain, without
   // comparing its advanced head with the already-verified backup baseline.
   verify_owner(&mut c,&config).await?;

   authorities(&frozen,&config)?;

   heads(&config,&input.administrator).await?;

  }
  // Freeze outside the restored database. Retries reuse this incarnation; a new
  // restore directory/operation creates a new one before writers can reconnect.
  let vault_incarnation = match journal.load::<Uuid>("vault-incarnation.json").map_err(storage)? {
   Some(value) => value,
   None => { let value=Uuid::new_v4(); journal.save("vault-incarnation.json", &value).map_err(storage)?; value }
  };
  rss_mdm_vault_sync::restore_incarnation(&mut c,vault_incarnation).await.map_err(|_|Error::Storage)?;

  // Admit the exact production role while ordinary CONNECT remains fenced.
  sqlx::query("SET SESSION AUTHORIZATION da_access").execute(&mut c).await.map_err(|_|Error::Storage)?;

  let admitted=rss_mdm_device_access_runtime::installation::verify_standalone_access(&mut c,config.audit.ledger()).await;

  sqlx::query("RESET SESSION AUTHORIZATION").execute(&mut c).await.map_err(|_|Error::Storage)?;
admitted.map_err(|_|Error::Admission)?;

  let expected=config.installation.tenants()?.iter().map(|(t,_)|t.to_string()).collect::<std::collections::BTreeSet<_>>();

  let supplied=input.accounts.iter().map(|a|a.tenant.to_string()).collect::<std::collections::BTreeSet<_>>();

  if expected!=supplied||input.accounts.len()!=expected.len(){return Err(Error::Configuration)}
  fence::connection_fence(&mut c,&journal,false).await.map_err(storage)?;

  let verify=async {for account in &input.accounts{crate::maintenance::verify_account(&config,account).await?;
} Ok::<(),Error>(())}.await;

  if let Err(error)=verify {fence::connection_fence(&mut c,&journal,true).await.map_err(storage)?;
return Err(error)}
  let root=Journal::open(&frozen.request.installation_directory).map_err(storage)?;
root.save("backup-operation.json",&Option::<Uuid>::None).map_err(storage)?;

  sqlx::query("UPDATE public.da_restore_operation SET complete=true WHERE singleton").execute(&mut c).await.map_err(|_|Error::Storage)?;

  Ok(())
 }.await;

    let closed = c.close().await.map_err(|_| Error::Storage);

    result.and(closed)
}
