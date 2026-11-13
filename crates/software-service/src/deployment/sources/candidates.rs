//! Remaining execution policy candidate reads.
use crate::deployment::scope::*;
use uuid::Uuid;
#[derive(Clone, Copy, Debug)]
pub enum CandidateKind {
    AgentInstall,
}
impl CandidateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentInstall => "ensure_agent_installed",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PolicyCandidate {
    pub policy: Uuid,
    pub version: Uuid,
    pub scope: Uuid,
    pub admission: ScopeAdmission,
}
/// A bounded scan page. Empty items do not mean completion while has_more is true.
pub struct CandidatePage {
    pub items: Vec<PolicyCandidate>,
    pub scanned_after: Uuid,
    pub has_more: bool,
}

/// Convert the pure authored action channel at the service boundary.
pub fn action_channel(
    action: &rss_mdm_policy::Action,
) -> Result<Channel, crate::deployment::Error> {
    match action.target_channel() {
        Some(rss_mdm_policy::SoftwareChannel::Mdm) => Ok(Channel::Mdm),
        Some(rss_mdm_policy::SoftwareChannel::Agent) => Ok(Channel::Agent),
        None => Err(crate::deployment::Error::Malformed),
    }
}

use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::sync::Arc;
pub struct PolicyCandidates {
    pub objects: Arc<dyn crate::deployment::scope::Sources>,
}
impl PolicyCandidates {
    pub fn native_interests_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        devices: &'a [rss_mdm_agent_wire::DeviceId],
    ) -> Pending<'a, Vec<rss_mdm_agent_wire::DeviceId>> {
        let kinds = ["ensure_agent_installed", "software"];
        Box::pin(async move {
            Ok(rss_mdm_policy_postgres::candidates::native_interests_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                connection,
                tenant,
                devices,
                &kinds,
            )
            .await?)
        })
    }

    pub fn candidates_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a rss_mdm_agent_wire::DeviceId,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, CandidatePage> {
        Box::pin(async move {
            let rows = rss_mdm_policy_postgres::candidates::candidates_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                tenant,
                after,
                kind.as_str(),
            )
            .await?;
            let has_more = rows.len() > 16;
            let mut scanned_after = after;
            let mut items = Vec::new();
            for row in rows.into_iter().take(16) {
                scanned_after = row.try_get("id")?;
                let version = row.try_get("current_version")?;
                let scope = row.try_get("scope")?;
                let admission = {
                    self.objects
                        .admission_on(c, tenant, scope, Channel::Mdm, device)
                        .await?
                };
                if admission != ScopeAdmission::Excluded {
                    items.push(PolicyCandidate {
                        policy: scanned_after,
                        version,
                        scope,
                        admission,
                    });
                }
            }
            Ok(CandidatePage {
                items,
                scanned_after,
                has_more,
            })
        })
    }
}
