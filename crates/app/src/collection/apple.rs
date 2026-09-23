//! DeviceInformation remains a CollectionRun; it never creates a device command or Applied event.
use super::{Attempts, store};
use crate::{
    Error,
    access_store::{Operation, db},
    api::{App, RequestAuth},
    apple::protocol as wire,
    audit::Audit,
    authorization::{Approval, Permission},
    device::DevicePrincipal,
    enrollment::store::{actor, uuid},
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use rss_mdm_inventory::ReportSource;
use serde::Deserialize;
use sqlx::{PgConnection, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Create {
    source: ReportSource,
    request_id: Uuid,
}
pub(crate) async fn create(
    State(app): State<Arc<App>>,
    Path(device): Path<String>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<serde_json::Value>), Error> {
    let input = input.map_err(|_| Error::Malformed)?.0;
    app.apple()?;
    if input.source != ReportSource::MdmApple || input.request_id.is_nil() {
        return Err(Error::Malformed);
    }
    let proof = &auth.proof;
    proof.require(Permission::InventoryCollect, Some(&device))?;
    let tenant = proof.tenant_id();
    audit.operation(input.request_id, "collection_start");
    audit.target(&device);
    let mut tx = app.access.begin(tenant).await?;
    crate::authorization::lock_on(&mut tx, tenant, proof.instance_id()).await?;
    let snapshot = crate::authorization::snapshot_on(&mut tx, tenant, proof.instance_id()).await?;
    snapshot.require(proof, Permission::InventoryCollect, Some(&device))?;
    let digest =
        crate::enrollment::digest(&("mdm.apple.collection-create/v1", &device, input.source));
    let operation = Operation {
        actor: actor(proof),
        key: input.request_id,
        digest: &digest,
    };
    if let Some(old) = crate::AccessStore::replay(&mut tx, &operation).await? {
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::from_str(&old).map_err(|_| super::corrupt())?),
        ));
    }
    crate::device::store::lock_channel(&mut tx, tenant, &device, rss_mdm_inventory::Channel::Mdm)
        .await?;
    let row=sqlx::query("SELECT r.id::text,r.generation,s.epoch::text FROM mdm_access.registrations r JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.state='active' AND c.state='active' AND s.source='mdm.apple' AND s.enabled AND s.coverage=$3 AND a.state='active' FOR SHARE OF r,c,a FOR UPDATE OF s")
        .bind(tenant).bind(&device).bind(crate::device::coverage_key()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Conflict)?;
    let registration = uuid(&row, "id")?;
    let scope = crate::device::scope(
        app.identity.tenant,
        registration,
        "mdm.apple",
        uuid(&row, "epoch")?,
    )?;
    let sequence:i64=sqlx::query_scalar("UPDATE mdm_access.report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source='mdm.apple' AND next_sequence<9223372036854775807 RETURNING next_sequence-1")
        .bind(tenant).bind(registration.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
    let id = Uuid::new_v4();
    let approval = Approval::from_proof(&snapshot, proof, &device, Permission::InventoryCollect)?;
    let request = wire::command(
        id,
        wire::dictionary([
            ("RequestType", "DeviceInformation".into()),
            (
                "Queries",
                plist::Value::Array(vec!["Model".into(), "OSVersion".into()]),
            ),
        ]),
    )?;
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,apple_approval,apple_deadline) VALUES($1::uuid,$2::uuid,$3::uuid,'mdm.apple',$4::uuid,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint,$7,'pending',$8::jsonb,clock_timestamp()+interval '10 minutes')")
        .bind(tenant).bind(id.to_string()).bind(registration.to_string()).bind(scope.epoch().as_str()).bind(scope.encode().map_err(|_|super::corrupt())?).bind(sequence)
        .bind(serde_json::to_string(&Attempts::default()).expect("closed attempts")).bind(serde_json::to_string(&approval).expect("closed approval")).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,collection,phase,request,state,deadline) SELECT tenant_id,id,registration,$3,id,'collect',$4,'pending',apple_deadline FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(tenant).bind(id.to_string()).bind(row.try_get::<i64,_>("generation").map_err(db)?).bind(request).execute(&mut *tx).await.map_err(db)?;
    let receipt = serde_json::json!({"runId":id,"result":"pending"});
    proof.check_live()?;
    app.access
        .finish_status(tx, &operation, &receipt.to_string(), &audit, None, 202)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

pub(crate) async fn expire(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    let ids=sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND source='mdm.apple' AND sealed_at IS NULL AND apple_deadline<=clock_timestamp() ORDER BY apple_deadline,id LIMIT 32 FOR UPDATE SKIP LOCKED")
        .bind(tenant).fetch_all(&mut *c).await.map_err(db)?;
    for id in ids {
        let mut run = store::load_on(
            c,
            tenant,
            Uuid::parse_str(&id).map_err(|_| super::corrupt())?,
        )
        .await?;
        store::seal(c, &mut run, "timeout").await?;
    }
    Ok(())
}
async fn approved(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<bool, Error> {
    let row=sqlx::query("SELECT apple_approval::text,apple_deadline>clock_timestamp() AND sealed_at IS NULL AND EXISTS(SELECT 1 FROM mdm_access.report_sources s WHERE (s.tenant_id,s.registration,s.source,s.epoch)=(collection_runs.tenant_id,collection_runs.registration,collection_runs.source,collection_runs.epoch) AND s.enabled) AS live,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND source='mdm.apple' FOR UPDATE")
        .bind(tenant).bind(id.to_string()).fetch_one(&mut *c).await.map_err(db)?;
    let approval: Approval =
        serde_json::from_str(&row.try_get::<String, _>("apple_approval").map_err(db)?)
            .map_err(|_| super::corrupt())?;
    Ok(row.try_get::<bool, _>("live").map_err(db)?
        && approval
            .valid(
                c,
                Permission::InventoryCollect,
                row.try_get("now").map_err(db)?,
            )
            .await?)
}
pub(crate) async fn receive(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    id: Uuid,
    status: wire::Status,
    d: &plist::Dictionary,
    bytes: &[u8],
) -> Result<bool, Error> {
    use sha2::{Digest, Sha256};
    let tenant = p.tenant().to_string();
    let row=sqlx::query("SELECT state,response_digest FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND registration=$3::uuid AND generation=$4 AND collection IS NOT NULL FOR UPDATE")
        .bind(&tenant).bind(id.to_string()).bind(p.registration().to_string()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else { return Ok(false) };
    let state: String = row.try_get("state").map_err(db)?;
    let digest = Sha256::digest(bytes).to_vec();
    if matches!(state.as_str(), "acknowledged" | "error") {
        return if row
            .try_get::<Option<Vec<u8>>, _>("response_digest")
            .map_err(db)?
            == Some(digest)
        {
            Ok(true)
        } else {
            Err(Error::Conflict)
        };
    }
    if !matches!(state.as_str(), "sent" | "not_now") || !approved(c, &tenant, id).await? {
        return Err(Error::Forbidden);
    }
    let state = match status {
        wire::Status::Acknowledged => "acknowledged",
        wire::Status::Error => "error",
        wire::Status::NotNow => "not_now",
        wire::Status::Idle => return Err(Error::Malformed),
    };
    sqlx::query("UPDATE mdm_apple.attempts SET state=$3,response=$4,response_digest=$5,received_at=floor(extract(epoch FROM clock_timestamp()))::bigint,next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(&tenant).bind(id.to_string()).bind(state).bind(bytes).bind(digest).execute(&mut *c).await.map_err(db)?;
    if status != wire::Status::NotNow {
        let mut run = store::load_on(c, &tenant, id).await?;
        let now = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
        let values = if status == wire::Status::Acknowledged {
            Some(
                d.get("QueryResponses")
                    .and_then(plist::Value::as_dictionary)
                    .ok_or(Error::Malformed)?,
            )
        } else {
            None
        };
        run.attempts = Attempts::apple(values, now);
        store::seal(c, &mut run, "complete").await?;
    }
    Ok(true)
}
pub(crate) async fn send(c: &mut PgConnection, p: &DevicePrincipal) -> Result<Vec<u8>, Error> {
    let tenant = p.tenant().to_string();
    let rows=sqlx::query("SELECT a.id::text,a.request FROM mdm_apple.attempts a JOIN mdm_access.collection_runs r ON (r.tenant_id,r.id)=(a.tenant_id,a.collection) WHERE a.tenant_id=$1::uuid AND a.registration=$2::uuid AND a.generation=$3 AND a.state IN ('pending','sent','not_now') AND a.next_attempt<=clock_timestamp() AND r.sealed_at IS NULL AND r.apple_deadline>clock_timestamp() ORDER BY r.sequence LIMIT 32 FOR UPDATE OF a")
        .bind(&tenant).bind(p.registration().to_string()).bind(p.generation()).fetch_all(&mut *c).await.map_err(db)?;
    for row in rows {
        let id = uuid(&row, "id")?;
        if !approved(c, &tenant, id).await? {
            sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(&tenant).bind(id.to_string()).execute(&mut *c).await.map_err(db)?;
            continue;
        }
        sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(&tenant).bind(id.to_string()).execute(&mut *c).await.map_err(db)?;
        return row.try_get("request").map_err(db);
    }
    Ok(Vec::new())
}
