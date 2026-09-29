#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum ResourceError {
    #[error("resource_not_found")]
    Missing,
}
