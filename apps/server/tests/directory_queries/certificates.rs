//! Native and Agent metadata consumers retain the original enrollment/signing coordinates.
use super::*;
use crate::{
    command_runtime_t2_support::seed_transaction, device_material_support as material,
    native_identity_t2_support as native,
};
use sha2::{Digest, Sha256};
pub(super) async fn seed(
    c: &Context,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    cases: &mut Vec<(String, String, Value)>,
) -> Result<()> {
    let n = native::seed(c, "windows").await?;
    let _windows = crate::windows_t2::windows(c, &n).await?;
    let (device, grant) = material::seed_registration(c).await?;
    let _agent = material::authenticated_agent(
        c,
        grant,
        &device,
        vec![rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1],
    )
    .await?;
    let mut tx = seed_transaction(c).await?;
    let issuer = format!("{:x}", Sha256::digest(&n.root));
    let operation = Uuid::new_v4();
    let rotation = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_pki.issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'windows',$2,1,'active',$3,'legacy',$4)").bind(c.tenant.to_string()).bind(&issuer).bind(&n.root).bind(time::OffsetDateTime::now_utc().unix_timestamp()+86400).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.signing(tenant_id,attempt,purpose,issuer,binding,deadline,digest,state) VALUES($1::uuid,$2,'windows',$3,$4,1700000900,$5,'unknown')").bind(c.tenant.to_string()).bind(n.attempt).bind(&issuer).bind(b"retained original signing request".to_vec()).bind(vec![17u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.operations(tenant_id,actor,instance,operation,phase,digest,receipt,signing_recovery_attempt) VALUES($1::uuid,$2,$3,$4,'signing_recovery',$5,$6,$7)").bind(c.tenant.to_string()).bind(p.principal_id()).bind(p.instance_id()).bind(operation).bind(vec![17u8;32]).bind(b"null".to_vec()).bind(n.attempt).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.rotations VALUES($1::uuid,$2,'windows',$3,$4,1,'activated')")
        .bind(c.tenant.to_string())
        .bind(rotation)
        .bind(&issuer)
        .bind("b".repeat(64))
        .execute(&mut *tx)
        .await?;
    let issuance: Uuid = sqlx::query_scalar(
        "SELECT id FROM mdm_access.certificate_issuances WHERE tenant_id=$1::uuid AND grant_id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(grant)
    .fetch_one(&mut *tx)
    .await?;
    let recovery = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.registration_operations(tenant_id,actor,operation_id,digest,result,instance,agent_issuance_recovery) VALUES($1::uuid,$2,$3,repeat('a',64),$4,$5,$6)").bind(c.tenant.to_string()).bind(p.principal_id()).bind(recovery).bind(serde_json::to_string(&issuance)?).bind(p.instance_id()).bind(issuance).execute(&mut *tx).await?;
    cases.extend([
        (
            format!("/api/v1/devices/{}/windows-certificate-requests", n.device),
            format!(
                "attempt=={};kind==enrollment;enrollmentId=={}",
                n.attempt, n.request
            ),
            json!(n.attempt),
        ),
        (
            format!(
                "/api/v1/devices/{}/windows-certificate-requests/{}/recovery-operations",
                n.device, n.attempt
            ),
            format!("operationId=={operation};instance=={}", p.instance_id()),
            json!(operation),
        ),
        (
            format!("/api/v1/pki/windows/rotations/{rotation}/blockers"),
            format!("kind==unresolved_signing;id=={}", n.attempt),
            json!(n.attempt),
        ),
        (
            format!("/api/v1/devices/{device}/agent-requests"),
            format!("device=={device};issuanceState==issued;activated==true"),
            json!(grant),
        ),
        (
            format!("/api/v1/agent-issuances/{issuance}/recovery-operations"),
            format!("operationId=={recovery};instance=={}", p.instance_id()),
            json!(recovery),
        ),
    ]);
    tx.commit().await?;
    Ok(())
}
