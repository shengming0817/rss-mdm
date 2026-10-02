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

impl From<rss_mdm_execution_service::Error> for Error {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        Self(e.into())
    }
}

impl From<rss_mdm_execution_service::queries::QueryError> for Error {
    fn from(e: rss_mdm_execution_service::queries::QueryError) -> Self {
        use rss_mdm_execution_service::queries::{Missing, QueryError as Read};
        use rss_mdm_flow_service::Error as Wire;
        Self(match e {
   Read::Malformed=>Wire::Malformed,Read::Unauthorized=>Wire::Unauthorized,Read::Forbidden=>Wire::Forbidden,Read::Conflict=>Wire::Conflict,
   Read::Unsupported=>Wire::Unsupported,Read::CommitUnknown=>Wire::CommitUnknown,Read::RollbackFailed=>Wire::RollbackFailed,
   Read::Unavailable(f)=>rss_mdm_execution_service::Error::Unavailable(f).into(),
   Read::Missing(m)=>match m {
    Missing::Inventory=>Wire::NotFound,Missing::Resource=>Wire::Resource(rss_mdm_flow_service::resource_catalog::error::ResourceError::Missing),
    Missing::Operation=>Wire::Execution(rss_mdm_execution_service::missing::ExecutionError::MissingOperation),
    Missing::Task=>Wire::Execution(rss_mdm_execution_service::missing::ExecutionError::MissingTask),
    Missing::SoftwareSource=>Wire::Publication(rss_mdm_software_service::management::publication::error::PublicationError::MissingSource),
    Missing::SoftwareCandidate=>Wire::Publication(rss_mdm_software_service::management::publication::error::PublicationError::MissingCandidate),
   },
  })
    }
}
