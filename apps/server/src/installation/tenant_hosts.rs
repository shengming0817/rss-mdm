//! One-shot runtime input preparation and observation for provisioned tenants.
//! Compose/Kubernetes owns all infrastructure and process lifecycle.
use super::{
    Error, Result,
    install::Input,
    local::Journal,
    model::{Application, BlockedReason, Observation, Phase},
    runtime_files,
};
use crate::administration::tenants::{Receipt, ReceiptResult};
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
    let mut runtime: Value = journal.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let decoded: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
    let compiled = decoded.compile().map_err(|_| Error::Corrupt)?;
    let base = &compiled.config;
    validate_declaration(input, &journal, base.background.database_host_instances)?;
    let mut c = operator_connection(input, base).await?;
    let capacity = Capacity::new(
        input.additional_hosts.len(),
        super::postgres::connection_budget(&mut c).await?,
    )?;
    capacity.preflight(&runtime, &input.content_storage)?;
    capacity.project(&mut runtime)?;
    let mut reservations: BTreeMap<Uuid, usize> =
        journal.load("host-reservations.json")?.unwrap_or_default();
    if reservations
        .values()
        .any(|index| *index >= input.additional_hosts.len())
    {
        return Err(Error::Conflict);
    }
    // Validate every existing host before publishing any part of the new allocation.
    // Optional modules have different physical pools; the primary alone is insufficient.
    super::application::preflight(input, &mut c, capacity).await?;
    let pending: Vec<Value> = sqlx::query_scalar("SELECT receipt FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='host_pending' ORDER BY operation_id LIMIT 32")
        .fetch_all(&mut c).await.map_err(|_|Error::Storage)?;
    let mut planned = reservations.clone();
    for original in &pending {
        let receipt: Receipt =
            serde_json::from_value(original.clone()).map_err(|_| Error::Corrupt)?;
        let ReceiptResult::Provisioning(progress) = receipt.result else {
            return Err(Error::Corrupt);
        };
        if progress.host_id == base.runtime_binding.host_id {
            continue;
        }
        let index = planned.get(&progress.host_id).copied().or_else(|| {
            (0..input.additional_hosts.len())
                .find(|index| !planned.values().any(|used| used == index))
        });
        if let Some(index) = index {
            planned.insert(progress.host_id, index);
            let candidate = additional_runtime(
                &input.directory,
                &runtime,
                &input.additional_hosts[index],
                &progress,
            )?;
            capacity.preflight(&candidate, &input.content_storage)?;
        }
    }
    save_slots(input, &journal)?;
    journal.save("runtime.json", &runtime)?;
    super::providers::reconcile::storage(input, &compiled.config, &mut c).await?;
    super::providers::reconcile::wns(input, &mut c).await?;
    super::providers::mail::reconcile(input, &mut c).await?;
    super::providers::webhook::reconcile(input, &mut c).await?;
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
                capacity,
            )
            .await?,
        );
    }
    completed += super::application::reconcile(input, &reservations, &mut c, capacity).await?;
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(completed)
}

/// One allocation for every tenant process sharing the product database.
#[derive(Clone, Copy)]
pub(super) struct Capacity {
    instances: u32,
    connections: u32,
}
impl Capacity {
    pub(super) fn new(additional: usize, connections: u32) -> Result<Self> {
        if additional > 1023 {
            return Err(Error::Input);
        }
        Ok(Self {
            instances: additional as u32 + 1,
            connections,
        })
    }
    pub(super) fn from_config(config: &crate::config::Config) -> Self {
        Self {
            instances: config.background.database_host_instances,
            connections: config.background.database_connection_budget,
        }
    }
    pub(super) fn current(input: &Input, journal: &Journal) -> Result<Self> {
        let runtime: Value = journal.load("runtime.json")?.ok_or(Error::Corrupt)?;
        let config: crate::config::Config =
            serde_json::from_value(runtime).map_err(|_| Error::Corrupt)?;
        validate_declaration(input, journal, config.background.database_host_instances)?;
        if input.additional_hosts.len() + 1 != config.background.database_host_instances as usize {
            return Err(Error::Conflict);
        }
        Ok(Self::from_config(&config))
    }
    pub(super) fn project(self, runtime: &mut Value) -> Result<()> {
        runtime["background"]["database_host_instances"] = serde_json::json!(self.instances);
        runtime["background"]["database_connection_budget"] = serde_json::json!(self.connections);
        let config: crate::config::Config =
            serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
        config.compile().map_err(|_| Error::Input)?;
        Ok(())
    }
    pub(super) fn preflight(
        self,
        runtime: &Value,
        storage: &super::install::ContentStorage,
    ) -> Result<()> {
        let mut candidate = runtime.clone();
        // S3 bootstrap defers credentials, not its declared physical connection pools.
        // Qualification in this same command must not invalidate the allocation.
        if candidate["content"].is_null() && matches!(storage, super::install::ContentStorage::S3) {
            candidate["content"] = super::application::s3_content(1);
        }
        self.project(&mut candidate)
    }
    pub(super) fn require_current(self, runtime: &Value) -> Result<()> {
        if runtime["background"]["database_host_instances"] != serde_json::json!(self.instances)
            || runtime["background"]["database_connection_budget"]
                != serde_json::json!(self.connections)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

fn validate_declaration(input: &Input, journal: &Journal, previous: u32) -> Result<()> {
    if input.additional_hosts.len() + 1 < previous as usize {
        return Err(Error::Conflict);
    }
    // Also inspect a partially saved append after an interrupted preparation.
    for index in 0..1023 {
        let Some(saved) = journal.load::<Value>(&format!("host-slot-{index}.json"))? else {
            break;
        };
        let slot = input.additional_hosts.get(index).ok_or(Error::Conflict)?;
        if serde_json::to_value(slot).map_err(|_| Error::Input)? != saved {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

pub(super) fn save_slots(input: &Input, journal: &Journal) -> Result<()> {
    for (index, slot) in input.additional_hosts.iter().enumerate() {
        journal.secret(
            &format!("host-slot-{index}.json"),
            &serde_json::to_vec(slot).map_err(|_| Error::Input)?,
        )?;
    }
    Ok(())
}

pub(super) fn validate_slots(input: &Input) -> Result<()> {
    let mut origins = std::collections::BTreeSet::from([input.origin.clone()]);
    let mut listeners = std::collections::BTreeSet::from([input.listen]);
    let mut outputs = std::collections::BTreeSet::from([input.deployment.directory.clone()]);
    if input.additional_hosts.len() > 1023 {
        return Err(Error::Input);
    }
    for slot in &input.additional_hosts {
        let url = url::Url::parse(&slot.origin).map_err(|_| Error::Input)?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != slot.origin
            || !url.username().is_empty()
            || url.password().is_some()
            || slot.listen.ip().is_unspecified()
            || slot.listen.port() == 0
            || !listeners.insert(slot.listen)
            || !origins.insert(slot.origin.clone())
            || !outputs.insert(slot.deployment.directory.clone())
        {
            return Err(Error::Input);
        }
    }
    Ok(())
}

/// The same host completion transition is used by installation and later provisioning.
pub(super) async fn activate(
    c: &mut sqlx::PgConnection,
    directory: &std::path::Path,
    deployment: &runtime_files::Config,
    runtime: &Value,
    progress: &mut super::model::Provisioning,
) -> Result<()> {
    let binding: super::host::Binding =
        serde_json::from_value(runtime["runtime_binding"].clone()).map_err(|_| Error::Input)?;
    if binding.host_id != progress.host_id
        || runtime["identity"]["tenant_id"].as_str()
            != Some(progress.tenant_id.to_string().as_str())
    {
        return Err(Error::Conflict);
    }
    progress.origin = runtime["product_origin"].as_str().map(str::to_owned);
    progress.application = Some(Application {
        requested_revision: binding.revision,
        material_digest: binding.material_digest,
        operation_id: binding.operation_id,
        observation: None,
    });
    match runtime_files::apply(directory, deployment, runtime).await {
        Ok(observed) => {
            runtime_files::record_observation(c, runtime, &observed).await?;
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
    capacity: Capacity,
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
    let primary: super::install::Receipt = {
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
        let before = super::application::fingerprint(&value)?;
        capacity.project(&mut value)?;
        super::application::bind_change(&mut value, &before)?;
        let _ = activate(c, &input.directory, &input.deployment, &value, progress).await;
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
            match additional_runtime(&input.directory, runtime, slot, progress) {
                Ok(mut candidate) => {
                    let before = super::application::fingerprint(&candidate)?;
                    capacity.project(&mut candidate)?;
                    super::application::bind_change(&mut candidate, &before)?;
                    if activate(c, &input.directory, &slot.deployment, &candidate, progress)
                        .await
                        .is_ok()
                    {
                        completed += 1;
                    }
                }
                Err(_) => progress.blocked = Some(BlockedReason::HostUnavailable),
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

// ref: compose-spec/compose-go loader/normalize.go (target service owns its volumes).
pub(super) fn additional_runtime(
    directory: &std::path::Path,
    runtime: &Value,
    slot: &Slot,
    progress: &super::model::Provisioning,
) -> Result<Value> {
    let owner = Journal::open(&directory.join(format!("rss-mdm-{}", progress.host_id.simple())))?;
    // Pending hosts may already have newer domain materials awaiting a process restart.
    if let Some(requested) = owner.load("requested-runtime.json")? {
        return Ok(requested);
    }
    drop(owner);
    let mut candidate = runtime.clone();
    if !candidate["content"].is_null() {
        candidate["content"]["storage"] = slot.deployment.prepare_content_storage()?;
    }
    candidate["native_protocols"] = serde_json::json!({});
    candidate["agent_pki"] = serde_json::json!({"mode":"disabled"});
    candidate["device_pki"] = serde_json::json!([]);
    for field in ["task_signing", "recovery_credentials"] {
        candidate[field] = Value::Null;
    }
    candidate["identity"]["oidc"] = Value::Null;
    candidate["webhooks"]["networks"] = serde_json::json!([]);
    candidate["identity"]["tenant_id"] = serde_json::json!(progress.tenant_id);
    candidate["product_origin"] = serde_json::json!(slot.origin);
    candidate["listen"] = serde_json::json!(slot.listen);
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
    Ok(candidate)
}

async fn operator_connection(
    input: &Input,
    base: &crate::config::Config,
) -> Result<sqlx::PgConnection> {
    let installation = crate::migration::Installation {
        instance_id: base.identity.instance_id.clone(),
        target: base.storage_binding.target,
        lineage: base.storage_binding.lineage,
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

#[cfg(test)]
#[path = "../../tests/setup/host_capacity.rs"]
mod tests;
