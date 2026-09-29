//! Durable task-output collection, on the command owner's borrowed transaction.
use rss_mdm_inventory::FieldKey;
use rss_observation::{Batch, Body, Change, Id};
use sqlx::Row;
use uuid::Uuid;
pub(crate) struct Report {
    pub registration: Uuid,
    pub task: Uuid,
    pub attempt: Uuid,
    pub field: FieldKey,
    pub value: Option<Vec<u8>>,
    pub trusted: bool,
    pub now: i64,
}
pub(crate) async fn accept_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    report: Report,
) -> Result<(), sqlx::Error> {
    let Report {
        registration,
        task,
        attempt,
        field,
        value,
        trusted,
        now,
    } = report;
    let source = field.definition().sources[0];
    let row = sqlx::query("UPDATE mdm_access.report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND enabled AND coverage='enterprise-task-v1' AND next_sequence<9223372036854775807 RETURNING epoch::text,next_sequence-1 AS sequence")
                .bind(tenant.to_string()).bind(registration.to_string()).bind(source.as_str()).fetch_one(&mut *c).await?;
    let epoch: String = row.try_get("epoch")?;
    let sequence: i64 = row.try_get("sequence")?;
    let encode_error = |_| sqlx::Error::Protocol("invalid enterprise collection".into());
    let scope = crate::device::scope_dataset(
        tenant,
        registration,
        source.as_str(),
        Uuid::parse_str(&epoch).map_err(|_| sqlx::Error::Protocol("invalid epoch".into()))?,
        field.as_str(),
    )
    .map_err(encode_error)?;
    let id = Uuid::new_v4();
    let body = match value {
        Some(value) => Body::Snapshot(vec![Change::upsert(
            Id::new(field.as_str()).expect("fixed field"),
            value,
        )]),
        None => Body::Failed {
            code: Id::new("untrusted-output").expect("fixed code"),
        },
    };
    let batch = Batch::new(
        Id::new(id.to_string()).expect("UUID"),
        sequence as u64,
        rss_contract::Timepoint::try_from(now)
            .map_err(|_| sqlx::Error::Protocol("invalid time".into()))?,
        rss_mdm_inventory::enterprise_coverage(field),
        body,
    )
    .map_err(|_| sqlx::Error::Protocol("invalid batch".into()))?;
    let digest = batch
        .fingerprint(&scope)
        .map_err(|_| sqlx::Error::Protocol("invalid fingerprint".into()))?
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let quality = crate::collection::EnterpriseAttempt {
        field,
        quality: if trusted {
            crate::collection::Quality::Success
        } else {
            crate::collection::Quality::Invalid
        },
        received_at: now,
        task_id: task,
        attempt_id: attempt,
    };
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,sealed_at,attempts,result,reason,batch,digest,delivery_pending) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7,$8,$8,$9,$10,'complete',$11,$12,true)")
                .bind(tenant.to_string()).bind(id.to_string()).bind(registration.to_string()).bind(source.as_str()).bind(epoch).bind(scope.encode().map_err(|_|sqlx::Error::Protocol("invalid scope".into()))?).bind(sequence).bind(now).bind(serde_json::to_string(&quality).expect("closed quality")).bind(if trusted {"snapshot"} else {"failed"}).bind(batch.encode()).bind(digest).execute(&mut *c).await?;
    crate::worker_wake::notify(c, crate::worker_wake::Work::Inventory).await?;
    Ok(())
}
