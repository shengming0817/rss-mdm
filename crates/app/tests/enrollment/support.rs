use crate::authorization::context::AuthorizedPrincipal;
use crate::enrollment::Password;
use rss_mdm_audit_integration::RequestAudit;
use uuid::Uuid;
pub(crate) fn audit(
    proof: &AuthorizedPrincipal,
    key: Uuid,
    device: &str,
    action: &'static str,
) -> RequestAudit {
    let a = RequestAudit::new(proof.tenant_id().into(), action);
    proof.bind_audit(&a).unwrap();
    a.target(device);
    a.operation(key, action);
    a
}
pub(crate) async fn create(
    store: &rss_mdm_audit_integration::AuditStore,
    proof: &AuthorizedPrincipal,
    device: &str,
    password: &Password,
    reference: Uuid,
    key: Uuid,
) -> anyhow::Result<crate::enrollment::Receipt> {
    create_windows(
        store,
        proof,
        device,
        password,
        reference,
        key,
        rss_mdm_registration_service::enrollment::WindowsProfile::Full,
    )
    .await
}
pub(crate) async fn create_windows(
    store: &rss_mdm_audit_integration::AuditStore,
    proof: &AuthorizedPrincipal,
    device: &str,
    password: &Password,
    reference: Uuid,
    key: Uuid,
    profile: rss_mdm_registration_service::enrollment::WindowsProfile,
) -> anyhow::Result<crate::enrollment::Receipt> {
    let a = audit(proof, key, device, "enrollment_create");
    let receipt = crate::enrollment::store::create_enrollment(
        store,
        proof.enrollment(device)?,
        password,
        rss_mdm_inventory::ReportSource::MdmWindows,
        Some(profile),
        reference,
        key,
        &a,
    )
    .await;
    a.finalize(None);
    Ok(receipt?)
}
