//! Capabilities consumed by Agent ingress, implemented by the product composition root.
use crate::delivery::Pending;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_registration_service::DevicePrincipal;
use uuid::Uuid;
pub trait SelfService: Send + Sync {
    fn resolve<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        input: &'a wire::SelfServiceResolve,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceDirectoryItem>;
    fn directory<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        query: &'a str,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceDirectoryResponse>;
    fn invoke<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        input: &'a wire::SelfServiceInvoke,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceAccepted>;
    fn status<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceStatus>;
}
pub trait Installation: Send + Sync {
    fn enrollment<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a rss_mdm_agent_wire::enroll::NativeEnrollmentRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_agent_wire::enroll::NativeEnrollmentReceipt>;
    fn content<'a>(
        &'a self,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_content_service::Verified>;
}
pub trait RecoveryUse: Send + Sync {
    fn record<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        input: &'a wire::AccessRecoveryUse,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
}
