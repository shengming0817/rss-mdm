//! Transaction-borrowing action-plan authority. The host coordinates execution handoff.
pub(crate) mod model;

mod service;
mod storage;
mod targets;
use std::sync::Arc;
pub(crate) struct ActionPlans {
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) content: Option<Arc<dyn crate::task_content::ArtifactReader>>,
}

pub(crate) mod admission;
