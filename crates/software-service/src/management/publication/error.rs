#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum PublicationError {
    #[error("software_source_not_found")]
    MissingSource,
    #[error("software_publication_not_found")]
    MissingPublication,
}

impl PublicationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingSource => "software_source_not_found",
            Self::MissingPublication => "software_publication_not_found",
        }
    }
}
