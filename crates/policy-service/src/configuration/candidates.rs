//! Bounded candidates for configuration ownership.
use rss_mdm_scope_service::channels::*;
use uuid::Uuid;
#[derive(Clone, Copy, Debug)]
pub enum CandidateKind {
    Configuration,
}
impl CandidateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PolicyCandidate {
    pub policy: Uuid,
    pub version: Uuid,
}
/// A bounded scan page. Empty items do not mean completion while has_more is true.
pub struct CandidatePage {
    pub items: Vec<PolicyCandidate>,
    pub scanned_after: Uuid,
    pub has_more: bool,
}
pub struct ConfigurationCandidates {
    pub items: Vec<(String, PolicyCandidate)>,
    pub scanned_after: Option<(Uuid, String)>,
    pub has_more: bool,
}

use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::sync::Arc;
pub struct PolicyCandidates {
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
}
impl PolicyCandidates {
    pub fn configuration_candidates_batch_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        devices: &'a [String],
        after: Option<&'a (Uuid, String)>,
    ) -> Pending<'a, ConfigurationCandidates> {
        Box::pin(async move {
            let rows = rss_mdm_policy_postgres::candidates::configuration_candidates_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                tenant,
                devices,
                after,
            )
            .await?;
            let has_more = rows.len() > 1000;
            let mut scanned_after = None;
            let mut items = Vec::new();
            for row in rows.into_iter().take(1000) {
                let policy = row.try_get("id")?;
                let device: String = row.try_get("device")?;
                scanned_after = Some((policy, device.clone()));
                let admission: ScopeAdmission = serde_json::from_value(row.try_get("admission")?)
                    .map_err(|_| SourceError::Invariant)?;
                if admission != ScopeAdmission::Excluded {
                    items.push((
                        device,
                        PolicyCandidate {
                            policy,
                            version: row.try_get("current_version")?,
                        },
                    ));
                }
            }
            Ok(ConfigurationCandidates {
                items,
                scanned_after,
                has_more,
            })
        })
    }
    pub fn candidates_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
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
                    rss_mdm_scope_service::channels::targets::admission_on(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        Some(self.objects.as_ref()),
                        c,
                        tenant,
                        scope,
                        Channel::Mdm,
                        device,
                    )
                    .await?
                };
                if admission != ScopeAdmission::Excluded {
                    items.push(PolicyCandidate {
                        policy: scanned_after,
                        version,
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
