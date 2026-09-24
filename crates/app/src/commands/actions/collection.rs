//! Task result intake shares the existing durable CollectionRun delivery owner.
use super::{model::Frozen, storage::Run};
use crate::commands::{Result, corrupt};
use rss_mdm_inventory::{CollectedValue, FieldKey, Scalar};
use rss_mdm_resource::{ScriptField, ScriptPurpose};
use rss_observation::{Batch, Body, Change, Id};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

pub(super) async fn accept(
    tx: &mut PgTransaction<'_>,
    frozen: &Frozen,
    run: &Run,
    output: &Value,
    trusted: bool,
    now: i64,
) -> Result<()> {
    let ScriptPurpose::Collection { mappings } = &frozen.definition.spec().purpose else {
        return Ok(());
    };
    for (field, pointer) in mappings {
        let field = match field {
            ScriptField::CorporateAgentVersion => FieldKey::CorporateAgentVersion,
            ScriptField::CorporateAgentHealthy => FieldKey::CorporateAgentHealthy,
            ScriptField::OsqueryVersion => FieldKey::OsqueryVersion,
        };
        let value = if trusted {
            let value = output.pointer(pointer).ok_or(crate::Error::Malformed)?;
            let scalar = if field == FieldKey::CorporateAgentHealthy {
                Scalar::Boolean(value.as_bool().ok_or(crate::Error::Malformed)?)
            } else {
                Scalar::String(value.as_str().ok_or(crate::Error::Malformed)?.into())
            };
            Some(corrupt(CollectedValue::Scalar(scalar).encode(field))?)
        } else {
            None
        };
        let tenant = tx.tenant_id();
        let target = run.target.clone();
        let task = run.id;
        let attempt = run.state.attempt().ok_or(crate::Error::Conflict)?;
        let source = field.definition().sources[0];
        tx.with_connection(move |c| Box::pin(async move {
            let row = sqlx::query("UPDATE mdm_access.report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND enabled AND coverage='enterprise-task-v1' AND next_sequence<9223372036854775807 RETURNING epoch::text,next_sequence-1 AS sequence")
                .bind(tenant.to_string()).bind(target.registration.to_string()).bind(source.as_str()).fetch_one(&mut *c).await?;
            let epoch: String = row.try_get("epoch")?;
            let sequence: i64 = row.try_get("sequence")?;
            let encode_error = |_| sqlx::Error::Protocol("invalid enterprise collection".into());
            let scope = crate::device::scope_dataset(tenant,target.registration,source.as_str(),Uuid::parse_str(&epoch).map_err(|_|sqlx::Error::Protocol("invalid epoch".into()))?,field.as_str()).map_err(encode_error)?;
            let id = Uuid::new_v4();
            let body = match value {
                Some(value) => Body::Snapshot(vec![Change::upsert(Id::new(field.as_str()).expect("fixed field"), value)]),
                None => Body::Failed { code: Id::new("untrusted-output").expect("fixed code") },
            };
            let batch = Batch::new(Id::new(id.to_string()).expect("UUID"),sequence as u64,rss_contract::Timepoint::try_from(now).map_err(|_|sqlx::Error::Protocol("invalid time".into()))?,rss_mdm_inventory::enterprise_coverage(field),body).map_err(|_|sqlx::Error::Protocol("invalid batch".into()))?;
            let digest = batch.fingerprint(&scope).map_err(|_|sqlx::Error::Protocol("invalid fingerprint".into()))?.iter().map(|v|format!("{v:02x}")).collect::<String>();
            let quality = crate::collection::EnterpriseAttempt { field, quality:if trusted {crate::collection::Quality::Success} else {crate::collection::Quality::Invalid},received_at:now,task_id:task,attempt_id:attempt };
            sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,sealed_at,attempts,result,reason,batch,digest,delivery_pending) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7,$8,$8,$9,$10,'complete',$11,$12,true)")
                .bind(tenant.to_string()).bind(id.to_string()).bind(target.registration.to_string()).bind(source.as_str()).bind(epoch).bind(scope.encode().map_err(|_|sqlx::Error::Protocol("invalid scope".into()))?).bind(sequence).bind(now).bind(serde_json::to_string(&quality).expect("closed quality")).bind(if trusted {"snapshot"} else {"failed"}).bind(batch.encode()).bind(digest).execute(c).await?;
            Ok(())
        })).await?;
    }
    Ok(())
}
