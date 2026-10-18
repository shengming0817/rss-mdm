pub(crate) use rss_mdm_flow_service::operation::Operation;

/// Request-local continuation for enrollment and long content-operation revalidation.
#[derive(Clone)]
pub struct RequestContinuation(
    std::sync::Arc<rss_mdm_authorization_service::credential::RequestCredential>,
);
impl RequestContinuation {
    pub fn new(secret: rss_mdm_authorization_service::credential::RequestCredential) -> Self {
        Self(std::sync::Arc::new(secret))
    }
    pub fn secret(&self) -> &rss_mdm_authorization_service::credential::RequestCredential {
        &self.0
    }
}
