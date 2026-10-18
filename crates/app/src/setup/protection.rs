//! 原生密文写钥的受控切换：先分发读取能力，再切换写入，最后按领域事务重加密。
use super::{Error, Result, deployment, installation::Input, local::Journal};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Connection;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: Input,
    pub operation_id: Uuid,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Distributing,
    Activating,
    Rewrapping,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub phase: Phase,
    pub key_id: String,
    pub rewritten: u64,
    pub historical_keys_retained: bool,
}
#[derive(Serialize, Deserialize)]
struct Host {
    id: Uuid,
    tenant: Uuid,
    slot: Option<usize>,
    read: Value,
    write: Value,
}
#[derive(Serialize, Deserialize)]
struct Saved {
    receipt: Receipt,
    base: Value,
    hosts: Vec<Host>,
}

fn successor(mut runtime: Value, protection: Value) -> Result<Value> {
    runtime["native_protection"] = protection;
    let revision = runtime["runtime_binding"]["revision"]
        .as_u64()
        .and_then(|r| r.checked_add(1))
        .filter(|r| *r <= i64::MAX as u64)
        .ok_or(Error::Corrupt)?;
    let digest = super::application::fingerprint(&runtime)?;
    runtime["runtime_binding"]["revision"] = json!(revision);
    runtime["runtime_binding"]["operation_id"] = json!(Uuid::new_v4());
    runtime["runtime_binding"]["material_digest"] = json!(digest);
    Ok(runtime)
}
pub async fn rotate(request: Request) -> Result<Receipt> {
    if request.operation_id.is_nil() {
        return Err(Error::Input);
    }
    let input = &request.installation;
    let journal = Journal::open(&input.directory)?;
    let operation = Journal::open(
        &input
            .directory
            .join(format!("protection-{}", request.operation_id)),
    )?;
    operation.secret(
        "request.json",
        &serde_json::to_vec(&request).map_err(|_| Error::Input)?,
    )?;
    let base: Value = journal.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let decoded: crate::config::Config =
        serde_json::from_value(base.clone()).map_err(|_| Error::Corrupt)?;
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
    let identity = crate::migration::Installation {
        instance_id: decoded.identity.instance_id.clone(),
        target: decoded.flow.storage.target,
        lineage: decoded.flow.storage.lineage,
        audit_mode: decoded.audit.mode(),
    };
    crate::migration::verify_identity(&mut c, &identity)
        .await
        .map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT pg_advisory_lock(2823,1)")
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    let mut saved: Saved = if let Some(saved) = operation.load("rotation.json")? {
        saved
    } else {
        let existing = journal
            .load::<Option<Uuid>>("protection-operation.json")?
            .flatten();
        if existing.is_some_and(|id| id != request.operation_id) {
            return Err(Error::Busy);
        }
        let next_path = operation.path("encryption.key")?;
        if !next_path.exists() {
            use ring::rand::SecureRandom;
            let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
            ring::rand::SystemRandom::new()
                .fill(bytes.as_mut())
                .map_err(|_| Error::Storage)?;
            operation.secret("encryption.key", bytes.as_slice())?;
        }
        let next = crate::config::read(&next_path, 32, true).map_err(|_| Error::Corrupt)?;
        let key_id = rss_mdm_native_protection::Protector::new(&next)
            .map_err(|_| Error::Corrupt)?
            .id()
            .to_owned();
        let mut read_protection = base["native_protection"].clone();
        let history = read_protection["historical_files"]
            .as_array_mut()
            .ok_or(Error::Corrupt)?;
        if history.len() >= 15 {
            return Err(Error::Conflict);
        }
        history.push(json!(next_path));
        let mut write_protection = base["native_protection"].clone();
        let previous = write_protection["active_file"].clone();
        write_protection["active_file"] = json!(next_path);
        write_protection["historical_files"]
            .as_array_mut()
            .ok_or(Error::Corrupt)?
            .push(previous);
        let slots: BTreeMap<Uuid, usize> =
            journal.load("host-reservations.json")?.unwrap_or_default();
        let records:Vec<Value>=sqlx::query_scalar("SELECT receipt FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='enabled' ORDER BY operation_id").fetch_all(&mut c).await.map_err(|_|Error::Storage)?;
        let mut hosts = Vec::new();
        for record in records {
            let receipt: crate::tenant_registry::Receipt =
                serde_json::from_value(record).map_err(|_| Error::Corrupt)?;
            let crate::tenant_registry::ReceiptResult::Provisioning(progress) = receipt.result
            else {
                return Err(Error::Corrupt);
            };
            let root = Journal::open(
                &input
                    .directory
                    .join(format!("rss-mdm-{}", progress.host_id.simple())),
            )?;
            let runtime: Value = root.load("requested-runtime.json")?.ok_or(Error::Corrupt)?;
            // 同一次安装的全部宿主必须从同一钥集合出发，不能覆盖异常分叉。
            if runtime["native_protection"] != base["native_protection"] {
                return Err(Error::Conflict);
            }
            let read = successor(runtime, read_protection.clone())?;
            let write = successor(read.clone(), write_protection.clone())?;
            hosts.push(Host {
                id: progress.host_id,
                tenant: progress.tenant_id,
                slot: slots.get(&progress.host_id).copied(),
                read,
                write,
            });
        }
        if hosts.is_empty() {
            return Err(Error::Conflict);
        }
        let mut next_base = base.clone();
        next_base["native_protection"] = write_protection;
        let saved = Saved {
            receipt: Receipt {
                operation_id: request.operation_id,
                phase: Phase::Distributing,
                key_id,
                rewritten: 0,
                historical_keys_retained: true,
            },
            base: next_base,
            hosts,
        };
        operation.save("rotation.json", &saved)?;
        saved
    };
    if saved.receipt.phase != Phase::Complete {
        let active = journal
            .load::<Option<Uuid>>("protection-operation.json")?
            .flatten();
        if active.is_some_and(|id| id != request.operation_id) {
            return Err(Error::Busy);
        }
        journal.save("protection-operation.json", &request.operation_id)?;
    }
    let candidate: crate::config::Config =
        serde_json::from_value(saved.base.clone()).map_err(|_| Error::Corrupt)?;
    if candidate
        .native_protector()
        .map_err(|_| Error::Corrupt)?
        .id()
        != saved.receipt.key_id
    {
        return Err(Error::Conflict);
    }
    if saved.receipt.phase == Phase::Distributing {
        for host in &saved.hosts {
            apply(input, host, &host.read).await?;
        }
        saved.receipt.phase = Phase::Activating;
        operation.save("rotation.json", &saved)?;
    }
    if saved.receipt.phase == Phase::Activating {
        for host in &saved.hosts {
            apply(input, host, &host.write).await?;
        }
        // 只有全部实际进程均加载新写钥和旧读钥后，才改变后续宿主的基础输入。
        journal.save("runtime.json", &saved.base)?;
        saved.receipt.phase = Phase::Rewrapping;
        operation.save("rotation.json", &saved)?;
    }
    if saved.receipt.phase == Phase::Rewrapping {
        let config: crate::config::Config =
            serde_json::from_value(saved.base.clone()).map_err(|_| Error::Corrupt)?;
        let protector = config.native_protector().map_err(|_| Error::Corrupt)?;
        let mut rewritten = 0;
        for host in &saved.hosts {
            let tenant = rss_request_context::TenantId::parse(&host.tenant.to_string())
                .map_err(|_| Error::Corrupt)?;
            let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(host.tenant.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
            rewritten += rss_mdm_content_service::connections::rewrap(&mut tx, tenant, &protector)
                .await
                .map_err(|_| Error::Corrupt)?;
            rewritten +=
                rss_mdm_execution_service::task_signing::trust::rewrap(&mut tx, tenant, &protector)
                    .await
                    .map_err(|_| Error::Corrupt)?;
            rewritten += rss_mdm_apple_channel::runtime_materials::rewrap(
                &mut tx,
                &host.tenant.to_string(),
                &protector,
            )
            .await
            .map_err(|_| Error::Corrupt)?;
            tx.commit().await.map_err(|_| Error::Storage)?;
        }
        saved.receipt.rewritten = saved
            .receipt
            .rewritten
            .checked_add(rewritten)
            .ok_or(Error::Corrupt)?;
        if rewritten == 0 {
            saved.receipt.phase = Phase::Complete;
        }
        operation.save("rotation.json", &saved)?;
    }
    if saved.receipt.phase == Phase::Complete
        && journal
            .load::<Option<Uuid>>("protection-operation.json")?
            .flatten()
            == Some(request.operation_id)
    {
        journal.save("protection-operation.json", &Option::<Uuid>::None)?;
    }
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(saved.receipt)
}
async fn apply(input: &Input, host: &Host, runtime: &Value) -> Result<()> {
    let config = match host.slot {
        Some(index) => {
            &input
                .additional_hosts
                .get(index)
                .ok_or(Error::Corrupt)?
                .deployment
        }
        None => &input.deployment,
    };
    let observed = deployment::apply(&input.directory, config, runtime).await?;
    if observed.host_id != host.id || observed.tenant_id != host.tenant.to_string() {
        return Err(Error::Conflict);
    }
    Ok(())
}
