//! The Agent participant owns its profile and receipt; Flow owns install authorization.
use crate::{
    Error, Failure,
    device::DevicePrincipal,
    operations::{self, Actor, Operation},
    wire,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::enrollment::managed::Authority;
use sqlx::PgConnection;
fn digest(input: &wire::ManagedRegistrationRequest) -> String {
    rss_mdm_registration_service::enrollment::digest(&("mdm.agent.managed-registration/v5", input))
}
pub async fn replay(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    input: &wire::ManagedRegistrationRequest,
    audit: &RequestAudit,
) -> Result<Option<wire::RegistrationReceipt>, Error> {
    let tenant = p.tenant().to_string();
    let subject = format!("device:{}", p.registration());
    let digest = digest(input);
    let op = Operation {
        actor: Actor::from_device(&tenant, &subject),
        key: input.operation_id,
        digest: &digest,
    };
    let Some(old) = operations::replay(c, &op).await? else {
        return Ok(None);
    };
    let receipt: wire::RegistrationReceipt =
        serde_json::from_str(&old).map_err(|_| Error::Unavailable(Failure::Database))?;
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r JOIN mdm_access.requests e ON(e.tenant_id,e.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.state='active' AND e.authority_kind='managed_installation' AND e.issuance_operation=$3)").bind(tenant).bind(receipt.registration_id).bind(input.installation_operation).fetch_one(c).await.map_err(crate::database::db)?;
    if !active {
        return Err(Error::Conflict);
    }
    audit.registration(receipt.registration_id);
    Ok(Some(receipt))
}
pub async fn register(
    c: &mut PgConnection,
    authority: Authority,
    input: &wire::ManagedRegistrationRequest,
    audit: &RequestAudit,
) -> Result<wire::RegistrationReceipt, Error> {
    let tenant = authority.principal().tenant().to_string();
    let subject = format!("device:{}", authority.principal().registration());
    if authority.installation() != input.installation_operation {
        return Err(Error::Forbidden);
    }
    let mount = crate::device::ChannelMount::new(
        authority.principal().tenant(),
        rss_mdm_inventory::ReportSource::AgentBuiltin,
    );
    let credential = crate::credential(&mount, &input.credential);
    let receipt = rss_mdm_registration_service::enrollment::managed::bind_in(
        c,
        authority,
        &credential,
        input.operation_id,
    )
    .await?;
    crate::bindings::bind_agent_in(
        c,
        &tenant,
        receipt.registration,
        &serde_json::to_string(&input.capabilities).map_err(|_| Error::Malformed)?,
        input.platform,
        input.architecture,
    )
    .await?;
    let output = wire::RegistrationReceipt {
        wire_version: wire::WIRE_VERSION,
        operation_id: input.operation_id,
        device_id: receipt.device,
        registration_id: receipt.registration,
        generation: receipt
            .generation
            .try_into()
            .map_err(|_| Error::Malformed)?,
        source: wire::ReportSource::AgentBuiltin,
        epoch: receipt.epoch,
        capabilities: input.capabilities.clone(),
        collections: crate::builtin_collections(
            c,
            rss_request_context::TenantId::parse(&tenant).map_err(|_| Error::Malformed)?,
            receipt.registration,
            receipt.epoch,
        )
        .await?,
    };
    let digest = digest(input);
    let operation = Operation {
        actor: Actor::from_device(&tenant, &subject),
        key: input.operation_id,
        digest: &digest,
    };
    audit.registration(output.registration_id);
    operations::save(
        c,
        &operation,
        &serde_json::to_string(&output).map_err(|_| Error::Malformed)?,
        audit,
    )
    .await?;
    Ok(output)
}
