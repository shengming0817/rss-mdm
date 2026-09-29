#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum PublicationError {
    #[error("software_source_not_found")]
    MissingSource,
    #[error("software_candidate_not_found")]
    MissingCandidate,
}
