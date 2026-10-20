//! One-shot runtime input preparation and observation for provisioned tenants.
//! Compose/Kubernetes owns all infrastructure and process lifecycle.
use super::{
    Error, Result,
    installation::Input,
    local::Journal,
    model::{Application, BlockedReason, Observation, Phase},
    runtime_files,
};
use crate::tenant_registry::{Receipt, ReceiptResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Connection;
use std::{collections::BTreeMap, net::SocketAddr};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub origin: String,
    pub listen: SocketAddr,
    pub deployment: runtime_files::Config,
}
/// Explicit one-shot maintenance; there is no resident deployment process.
pub async fn reconcile(input: &Input) -> Result<usize> {
    validate_slots(input)?;
    let journal = Journal::open(&input.directory)?;
    admit_reconciliation(&journal).await?;
    for (index, slot) in input.additional_hosts.iter().enumerate() {
        journal.secret(
            &format!("host-slot-{index}.json"),
            &serde_json::to_vec(slot).map_err(|_| Error::Input)?,
        )?;
    }
    let runtime: Value = journal.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let decoded: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
    let compiled = decoded.compile().map_err(|_| Error::Corrupt)?;
    let base = &compiled.config;
    let mut c = operator_connection(input, base).await?;
    super::providers::reconcile::storage(input, &compiled.config, &mut c).await?;
    super::providers::reconcile::wns(input, &mut c).await?;
    super::providers::mail::reconcile(input, &mut c).await?;
    super::providers::webhook::reconcile(input, &mut c).await?;
    let mut reservations: BTreeMap<Uuid, usize> =
        journal.load("host-reservations.json")?.unwrap_or_default();
    let pending: Vec<Value> = sqlx::query_scalar("SELECT receipt FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='host_pending' ORDER BY operation_id LIMIT 32")
        .fetch_all(&mut c).await.map_err(|_|Error::Storage)?;
    let mut completed = 0;
    for original in pending {
        completed += usize::from(
            provision_pending(
                input,
                &runtime,
                &journal,
                &mut reservations,
                &mut c,
                original,
            )
            .await?,
        );
    }
    completed += super::application::reconcile(input, &reservations, &mut c).await?;
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(completed)
}

pub(super) fn validate_slots(input: &Input) -> Result<()> {
    let mut origins = std::collections::BTreeSet::from([input.origin.clone()]);
    let mut ports = std::collections::BTreeSet::from([url::Url::parse(&input.origin)
        .map_err(|_| Error::Input)?
        .port_or_known_default()
        .ok_or(Error::Input)?]);
    if input.additional_hosts.len() > 1023 {
        return Err(Error::Input);
    }
    for slot in &input.additional_hosts {
        let url = url::Url::parse(&slot.origin).map_err(|_| Error::Input)?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != slot.origin
            || !url.username().is_empty()
            || url.password().is_some()
            || !slot.listen.ip().is_loopback()
            || slot.listen.port() == 0
            || !ports.insert(url.port_or_known_default().ok_or(Error::Input)?)
            || !origins.insert(slot.origin.clone())
        {
            return Err(Error::Input);
        }
    }
    Ok(())
}

/// The same host completion transition is used by installation and later provisioning.
pub(super) async fn activate(
    directory: &std::path::Path,
    deployment: &runtime_files::Config,
    runtime: &Value,
    progress: &mut super::model::Provisioning,
) -> Result<()> {
    let binding: super::host::Binding =
        serde_json::from_value(runtime["runtime_binding"].clone()).map_err(|_| Error::Input)?;
    if binding.host_id != progress.host_id
        || binding.operation_id != progress.operation_id
        || runtime["identity"]["tenant_id"].as_str()
            != Some(progress.tenant_id.to_string().as_str())
    {
        return Err(Error::Conflict);
    }
    progress.origin = runtime["product_origin"].as_str().map(str::to_owned);
    progress.application = Some(Application {
        requested_revision: binding.revision,
        material_digest: binding.material_digest,
        operation_id: progress.operation_id,
        observation: None,
    });
    match runtime_files::apply(directory, deployment, runtime).await {
        Ok(observed) => {
            let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)
                .map_err(|_| Error::Storage)?;
            progress
                .application
                .as_mut()
                .ok_or(Error::Corrupt)?
                .observation = Some(Observation {
                host_id: observed.host_id,
                process_generation: observed.process_generation,
                applied_revision: observed.revision,
                material_digest: observed.material_digest,
                observed_at: now,
                failure: None,
            });
            progress.blocked = None;
            progress.phase = Phase::Enabled;
            Ok(())
        }
        Err(error) => {
            progress.blocked = Some(BlockedReason::HostUnavailable);
            Err(error)
        }
    }
}

async fn admit_reconciliation(journal: &Journal) -> Result<()> {
    if journal
        .load::<Option<Uuid>>("backup-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    if journal
        .load::<Option<Uuid>>("configuration-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }

    if journal
        .load::<Option<Uuid>>("protection-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    Ok(())
}

async fn provision_pending(
    input: &Input,
    runtime: &Value,
    journal: &Journal,
    reservations: &mut BTreeMap<Uuid, usize>,
    c: &mut sqlx::PgConnection,
    original: Value,
) -> Result<bool> {
    let mut completed = 0;

    let mut receipt: Receipt =
        serde_json::from_value(original.clone()).map_err(|_| Error::Corrupt)?;
    let ReceiptResult::Provisioning(progress) = &mut receipt.result else {
        return Err(Error::Corrupt);
    };
    let before = progress.clone();
    if progress.administrator_id.is_none() || progress.phase != Phase::HostPending {
        return Err(Error::Corrupt);
    }
    let primary: super::installation::Receipt = {
        let saved: Value = journal.load("installation.json")?.ok_or(Error::Corrupt)?;
        serde_json::from_value(saved["receipt"].clone()).map_err(|_| Error::Corrupt)?
    };
    if progress.host_id == primary.host_id {
        let mut value = runtime.clone();
        let owner = Journal::open(
            &input
                .directory
                .join(format!("rss-mdm-{}", progress.host_id.simple())),
        )?;
        if let Some(requested) = owner.load::<Value>("requested-runtime.json")? {
            value = requested;
        }
        drop(owner);
        let _ = activate(&input.directory, &input.deployment, &value, progress).await;
    } else {
        let slot = if let Some(index) = reservations.get(&progress.host_id) {
            Some(*index)
        } else {
            (0..input.additional_hosts.len())
                .find(|index| !reservations.values().any(|used| used == index))
        };
        if let Some(index) = slot {
            let slot = input.additional_hosts.get(index).ok_or(Error::Conflict)?;
            // Reserve the runtime output position before writing files; retries retain the binding.
            reservations.insert(progress.host_id, index);
            journal.save("host-reservations.json", reservations)?;
            let mut candidate = runtime.clone();
            candidate["native_protocols"] = serde_json::json!({});
            candidate["agent_pki"] = serde_json::json!({"mode":"disabled"});
            candidate["device_pki"] = serde_json::json!([]);
            for field in ["task_signing", "recovery_credentials", "content"] {
                candidate[field] = Value::Null;
            }
            candidate["identity"]["oidc"] = Value::Null;
            candidate["webhooks"]["networks"] = serde_json::json!([]);
            candidate["identity"]["tenant_id"] = serde_json::json!(progress.tenant_id);
            candidate["product_origin"] = serde_json::json!(slot.origin);
            candidate["listen"] = serde_json::json!(slot.listen);
            candidate["trusted_gateway"] = serde_json::json!(slot.listen.ip());
            let digest = {
                use sha2::{Digest, Sha256};
                format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&(
                            progress.operation_id,
                            progress.host_id,
                            progress.tenant_id,
                            &slot.origin,
                            slot.listen,
                            &candidate
                        ))
                        .map_err(|_| Error::Input)?
                    )
                )
            };
            candidate["runtime_binding"] = serde_json::json!({"host_id":progress.host_id,"operation_id":progress.operation_id,"revision":1,"material_digest":digest});
            if activate(&input.directory, &slot.deployment, &candidate, progress)
                .await
                .is_ok()
            {
                completed += 1;
            }
        } else {
            progress.blocked = Some(BlockedReason::Capacity);
        }
    }
    if *progress == before {
        return Ok(false);
    }
    progress.revision = progress.revision.checked_add(1).ok_or(Error::Corrupt)?;
    let updated = sqlx::query("UPDATE public.mdm_tenant_operations SET receipt=$2 WHERE operation_id=$1 AND action='provision' AND receipt=$3")
        .bind(receipt.operation_id).bind(serde_json::to_value(&receipt).map_err(|_|Error::Corrupt)?).bind(original).execute(&mut *c).await.map_err(|_|Error::Storage)?;
    if updated.rows_affected() != 1 {
        return Err(Error::Conflict);
    }

    Ok(completed == 1)
}

async fn operator_connection(
    input: &Input,
    base: &crate::config::Config,
) -> Result<sqlx::PgConnection> {
    let installation = crate::migration::Installation {
        instance_id: base.identity.instance_id.clone(),
        target: base.flow.storage.target,
        lineage: base.flow.storage.lineage,
        audit_mode: base.audit.mode(),
    };
    let mut c = sqlx::PgConnection::connect_with(
        &input
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    sqlx::raw_sql("SET statement_timeout='10s'; SET lock_timeout='6s'")
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    if !crate::migration::owner_admitted(&mut c)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Input);
    }
    crate::migration::verify_identity(&mut c, &installation)
        .await
        .map_err(|_| Error::Conflict)?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(2823,1)")
        .fetch_one(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    if !locked {
        return Err(Error::Busy);
    }
    Ok(c)
}
