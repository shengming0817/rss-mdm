pub(crate) use rss_mdm_flow_service::operation::Operation;

/// Request-local continuation for enrollment and long content-operation revalidation.
#[derive(Clone)]
pub struct SessionContinuation(std::sync::Arc<rss_identity_core::session::SessionSecret>);
impl SessionContinuation {
    pub fn new(secret: rss_identity_core::session::SessionSecret) -> Self {
        Self(std::sync::Arc::new(secret))
    }
    pub fn secret(&self) -> &rss_identity_core::session::SessionSecret {
        &self.0
    }
}
