//! Transport wrapper around the product request error; no duplicate error algebra.
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[error(transparent)]
#[serde(transparent)]
pub struct Error(pub rss_mdm_flow_service::Error);
impl Error {
    pub fn is_not_found(&self) -> bool {
        self.0.is_not_found()
    }
}
