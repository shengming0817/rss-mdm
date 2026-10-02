#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum PublicationError {
    #[error("software_source_not_found")]
    MissingSource,
    #[error("software_candidate_not_found")]
    MissingCandidate,
}

impl PublicationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingSource => "software_source_not_found",
            Self::MissingCandidate => "software_candidate_not_found",
        }
    }
}
