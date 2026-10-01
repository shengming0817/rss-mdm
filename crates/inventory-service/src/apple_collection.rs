//! Inventory-owned collection intake; the channel participates on the same connection.
use crate::{Error, collection::Attempts, database::db};
use receipts::Operation;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_inventory::ReportSource;
use serde::Deserialize;
use sqlx::{PgConnection, Row};
use std::{future::Future, pin::Pin, sync::Arc};
use uuid::Uuid;
#[path = "apple_collection_receipts.rs"]
mod receipts;
pub trait Participant: Send + Sync {
    #[allow(
        clippy::too_many_arguments,
        reason = "borrowed channel participant preserves separate tenant, device, run and deadline coordinates"
    )]
    fn start<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
        registration: Uuid,
        generation: i64,
        sequence: i64,
        deadline: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
pub struct Service {
    pub tenant: rss_request_context::TenantId,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub participant: Option<Arc<dyn Participant>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub source: ReportSource,
    pub request_id: Uuid,
}
pub async fn create(
    app: &Service,
    proof: &AuthorizedPrincipal,
    device: String,
    input: Create,
    audit: &RequestAudit,
) -> Result<serde_json::Value, Error> {
    if input.source != ReportSource::MdmApple || input.request_id.is_nil() {
        return Err(Error::Malformed);
    }
    let participant = app.participant.as_ref().ok_or(Error::Conflict)?;

    proof.require(Permission::InventoryCollect, Some(&device))?;
    audit.operation(input.request_id, "collection_start");
    audit.target(&device);
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let attempt = app
        .audit_store
        .write(
            app.tenant,
            &control,
            (
                &app.audit_store,
                proof,
                device.as_str(),
                &input,
                &audit,
                app.tenant,
                participant.as_ref(),
            ),
            |(store, proof, device, input, audit, tenant, participant), tx| {
                Box::pin(async move {
                    let (receipt, replayed, digest) = tx
                        .with_connection_context(
                            &mut (*proof, *device, *input, *audit, *tenant),
                            |(proof, device, input, audit, tenant), c| {
                                Box::pin(create_on(
                                    c,
                                    proof,
                                    device,
                                    input,
                                    audit,
                                    *tenant,
                                    *participant,
                                ))
                            },
                        )
                        .await?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!(
                            "apple-collection:{}:{}",
                            proof.principal_id(),
                            input.request_id
                        ),
                        digest.as_bytes(),
                        202,
                        "success",
                        None,
                    )
                    .and_then(|fact| fact.with_details(receipt.clone()))
                    .map_err(Error::from)?;
                    store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    audit.mark_commit_started();
                    Ok(receipt)
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
async fn create_on(
    tx: &mut PgConnection,
    proof: &crate::authorization::context::AuthorizedPrincipal,
    device: &str,
    input: &Create,
    audit: &RequestAudit,
    tenant_id: rss_request_context::TenantId,
    participant: &dyn Participant,
) -> Result<(serde_json::Value, bool, String), Error> {
    let tenant = proof.tenant_id();
    crate::authorization::lock_on(tx, tenant, proof.instance_id()).await?;
    let snapshot = crate::authorization::snapshot_on(tx, tenant, proof.instance_id()).await?;
    snapshot.require(proof, Permission::InventoryCollect, Some(device))?;
    let digest = rss_mdm_registration_service::enrollment::digest(&(
        "mdm.apple.collection-create/v1",
        &device,
        input.source,
    ));
    let operation = Operation {
        actor: receipts::Actor::from_authorized(proof),
        key: input.request_id,
        digest: &digest,
    };
    if let Some(old) = receipts::replay(tx, &operation).await? {
        return Ok((
            serde_json::from_str(&old).map_err(|_| Error::Unavailable(crate::Failure::Database))?,
            true,
            digest,
        ));
    }
    let target =
        crate::device::store::allocate_collection_in(tx, tenant, device, input.source).await?;
    let registration = target.registration;
    let scope = crate::device::scope(tenant_id, registration, input.source.as_str(), target.epoch)?;
    let sequence = target.sequence;
    let id = Uuid::new_v4();
    let definition = crate::collection::store::freeze_in(
        tx,
        &scope,
        1,
        &[
            rss_mdm_inventory::builtin::MODEL,
            rss_mdm_inventory::builtin::OS_VERSION,
        ],
    )
    .await?;
    let attempts = Attempts::new(definition);
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,deadline) VALUES($1::uuid,$2::uuid,$3::uuid,'mdm.apple',$4::uuid,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint,$7,'pending',clock_timestamp()+interval '10 minutes')")
        .bind(tenant).bind(id.to_string()).bind(registration.to_string()).bind(scope.epoch().as_str()).bind(scope.encode().map_err(|_|Error::Unavailable(crate::Failure::Database))?).bind(sequence)
        .bind(serde_json::to_string(&attempts).expect("closed attempts")).execute(&mut *tx).await.map_err(db)?;
    let deadline:String=sqlx::query_scalar("SELECT deadline::text FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).fetch_one(&mut *tx).await.map_err(db)?;
    participant
        .start(
            tx,
            tenant,
            id,
            registration,
            target.generation,
            sequence,
            deadline,
        )
        .await?;
    crate::wake::notify(tx).await.map_err(db)?;
    let receipt = serde_json::json!({"runId":id,"result":"pending"});
    proof.check_live()?;
    receipts::save(tx, &operation, &receipt.to_string(), audit).await?;
    Ok((receipt, false, digest))
}

pub async fn current(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<bool, Error> {
    let row=sqlx::query("SELECT registration,epoch,deadline>clock_timestamp() AND sealed_at IS NULL AS live,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND source='mdm.apple' FOR UPDATE").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    let current = crate::device::store::source_current_in(
        c,
        tenant,
        row.try_get("registration").map_err(db)?,
        ReportSource::MdmApple,
        row.try_get("epoch").map_err(db)?,
    )
    .await?;
    Ok(current && row.try_get::<bool, _>("live").map_err(db)?)
}
