//! 已启用宿主的领域版本应用。仅保存跨进程副作用检查点，不复制领域材料状态。
use super::{
    Error, Result, deployment,
    installation::Input,
    local::Journal,
    model::{Application, BlockedReason, Observation},
};
use crate::tenant_registry::{Receipt, ReceiptResult};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use std::collections::BTreeMap;
use uuid::Uuid;

async fn desired(c: &mut PgConnection, tenant: Uuid, runtime: &mut Value) -> Result<()> {
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let signing: Option<i64> = sqlx::query_scalar("SELECT h.revision FROM mdm_task_signing.heads h JOIN mdm_task_signing.versions v USING(tenant_id,revision) WHERE h.tenant_id=$1 AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'state'='active')").bind(tenant).fetch_optional(&mut *tx).await.map_err(|_| Error::Storage)?;
    if let Some(revision) = signing {
        runtime["task_signing"] = json!({"revision":revision});
    }
    let storage: Option<i64> = sqlx::query_scalar("SELECT desired_revision FROM mdm_content_connections.heads WHERE tenant_id=$1 AND desired_revision IS NOT NULL").bind(tenant).fetch_optional(&mut *tx).await.map_err(|_| Error::Storage)?;
    if let Some(revision) = storage {
        if runtime["content"].is_null() {
            runtime["content"] = json!({"storage":null,"imports":{},"max_artifact_bytes":8589934592u64,"max_temporary_bytes":17179869184u64,"max_uploads":8,"transfer_seconds":300,"retention_seconds":86400,"max_bundle_bytes":8589934592u64,"max_bundle_entries":1000,"max_expansion_ratio":100});
        }
        runtime["content"]["storage"] =
            json!({"kind":"s3","revision":revision,"max_concurrent":8,"connect_seconds":5});
    }
    if runtime["native_protocols"]["windows"].is_object() {
        let revision:Option<i64>=sqlx::query_scalar("SELECT desired_revision FROM mdm_wns.heads WHERE tenant_id=$1 AND desired_revision IS NOT NULL").bind(tenant).fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;
        if let Some(revision) = revision {
            runtime["native_protocols"]["windows"]["push"] = json!({"revision":revision});
        }
    }
    // 通道其余供应方材料尚未就绪时不凭空启用 Apple。
    if runtime["native_protocols"]["apple"].is_object() {
        let versions: Vec<(String,i64)> = sqlx::query_as("SELECT purpose,desired_revision FROM mdm_apple_runtime.heads WHERE tenant_id=$1 AND desired_revision IS NOT NULL").bind(tenant).fetch_all(&mut *tx).await.map_err(|_| Error::Storage)?;
        for (purpose, revision) in versions {
            if purpose == "apns" || purpose == "profile" {
                runtime["native_protocols"]["apple"]["materials"][purpose] = json!(revision);
            }
        }
        let accounts:Vec<(String,i64)>=sqlx::query_as("SELECT alias,revision FROM mdm_apple_runtime.account_bindings WHERE tenant_id=$1 ORDER BY alias").bind(tenant).fetch_all(&mut *tx).await.map_err(|_|Error::Storage)?;
        for (alias, revision) in accounts {
            runtime["native_protocols"]["apple"]["materials"]["accounts"][alias] = json!(revision);
        }
    }
    tx.commit().await.map_err(|_| Error::Storage)
}
pub(super) fn fingerprint(runtime: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut value = runtime.clone();
    value
        .as_object_mut()
        .ok_or(Error::Corrupt)?
        .remove("runtime_binding");
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&value).map_err(|_| Error::Corrupt)?)
    ))
}
async fn save(c: &mut PgConnection, receipt: &Receipt, original: &Value) -> Result<Value> {
    let value = serde_json::to_value(receipt).map_err(|_| Error::Corrupt)?;
    let result=sqlx::query("UPDATE public.mdm_tenant_operations SET receipt=$2 WHERE operation_id=$1 AND action='provision' AND receipt=$3").bind(receipt.operation_id).bind(&value).bind(original).execute(c).await.map_err(|_|Error::Storage)?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(value)
}
pub(super) async fn reconcile(
    input: &Input,
    slots: &BTreeMap<Uuid, usize>,
    c: &mut PgConnection,
) -> Result<usize> {
    let receipts: Vec<Value> = sqlx::query_scalar("SELECT receipt FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='enabled' ORDER BY operation_id").fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
    let mut completed = 0;
    for mut original in receipts {
        let mut receipt: Receipt =
            serde_json::from_value(original.clone()).map_err(|_| Error::Corrupt)?;
        let ReceiptResult::Provisioning(progress) = &mut receipt.result else {
            return Err(Error::Corrupt);
        };
        let deployment = match slots.get(&progress.host_id) {
            Some(index) => {
                &input
                    .additional_hosts
                    .get(*index)
                    .ok_or(Error::Corrupt)?
                    .deployment
            }
            None => &input.deployment,
        };
        let root = input
            .directory
            .join(format!("rss-mdm-{}", progress.host_id.simple()));
        let journal = Journal::open(&root)?;
        let mut runtime: Value = journal
            .load("requested-runtime.json")?
            .ok_or(Error::Corrupt)?;
        if runtime["runtime_binding"]["host_id"] != json!(progress.host_id)
            || runtime["identity"]["tenant_id"] != json!(progress.tenant_id)
        {
            return Err(Error::Conflict);
        }
        let before = fingerprint(&runtime)?;
        desired(c, progress.tenant_id, &mut runtime).await?;
        let digest = fingerprint(&runtime)?;
        if digest != before {
            let revision = runtime["runtime_binding"]["revision"]
                .as_u64()
                .and_then(|r| r.checked_add(1))
                .filter(|r| *r <= i64::MAX as u64)
                .ok_or(Error::Corrupt)?;
            runtime["runtime_binding"] = json!({"host_id":progress.host_id,"operation_id":Uuid::new_v4(),"revision":revision,"material_digest":digest});
            // 稳定应用操作先落盘；崩溃后不会生成另一个请求身份。
            journal.save("requested-runtime.json", &runtime)?;
        }
        let binding: super::host::Binding =
            serde_json::from_value(runtime["runtime_binding"].clone())
                .map_err(|_| Error::Corrupt)?;
        let old_observation = progress
            .application
            .as_ref()
            .and_then(|a| a.observation.clone());
        progress.application = Some(Application {
            requested_revision: binding.revision,
            material_digest: binding.material_digest.clone(),
            operation_id: binding.operation_id,
            observation: old_observation,
        });
        progress.revision = progress.revision.checked_add(1).ok_or(Error::Corrupt)?;
        original = save(c, &receipt, &original).await?;
        drop(journal);
        let applied = deployment::apply(&input.directory, deployment, &runtime).await;
        let ReceiptResult::Provisioning(progress) = &mut receipt.result else {
            return Err(Error::Corrupt);
        };
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(|_| Error::Storage)?;
        match applied {
            Ok(observed) => {
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
                completed += 1;
            }
            Err(_) => {
                progress.blocked = Some(BlockedReason::HostUnavailable);
                // 历史成功可供排查，但不能继续充当本次健康观察。
                if let Some(observation) = progress
                    .application
                    .as_mut()
                    .and_then(|a| a.observation.as_mut())
                {
                    observation.failure = Some(BlockedReason::HostUnavailable);
                    observation.observed_at = now;
                }
            }
        }
        progress.revision = progress.revision.checked_add(1).ok_or(Error::Corrupt)?;
        save(c, &receipt, &original).await?;
    }
    Ok(completed)
}
