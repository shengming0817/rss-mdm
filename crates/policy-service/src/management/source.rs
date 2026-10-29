//! Policy candidate and assignment facts for Execution's consuming port.
use rss_mdm_execution_service::source_authority::*;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::sync::Arc;
use uuid::Uuid;
pub struct PolicySource {
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
}
pub fn execution(
    objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
) -> rss_mdm_execution_service::scope::source::ExecutionSource {
    rss_mdm_execution_service::scope::source::ExecutionSource::new(
        objects.clone(),
        Arc::new(PolicySource { objects }),
    )
}
impl rss_mdm_execution_service::scope::source::PolicySource for PolicySource {
    fn native_interests_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        devices: &'a [String],
    ) -> Pending<'a, Vec<String>> {
        let kinds = rss_mdm_policy::AssignmentBehavior::NativeDesired.kinds();
        Box::pin(async move {
            Ok(rss_mdm_policy_postgres::candidates::native_interests_on(
                connection, tenant, devices, &kinds,
            )
            .await?)
        })
    }
    fn configuration_candidates_batch_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        devices: &'a [String],
        after: Option<&'a (Uuid, String)>,
    ) -> Pending<'a, ConfigurationCandidates> {
        Box::pin(async move {
            let rows = rss_mdm_policy_postgres::candidates::configuration_candidates_on(
                c, tenant, devices, after,
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
                            scope: row.try_get("scope")?,
                            admission,
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
    fn candidates_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, CandidatePage> {
        Box::pin(async move {
            let rows =
                rss_mdm_policy_postgres::candidates::candidates_on(c, tenant, after, kind.as_str())
                    .await?;
            let has_more = rows.len() > 16;
            let mut scanned_after = after;
            let mut items = Vec::new();
            for row in rows.into_iter().take(16) {
                scanned_after = row.try_get("id")?;
                let version = row.try_get("current_version")?;
                let scope = row.try_get("scope")?;
                let admission = {
                    rss_mdm_execution_service::scope::targets::admission_on(
                        self.objects.as_ref(),
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
