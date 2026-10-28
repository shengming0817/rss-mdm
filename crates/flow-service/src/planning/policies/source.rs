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
    fn native_interest_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, bool> {
        let kinds = rss_mdm_policy::AssignmentBehavior::NativeDesired.kinds();
        Box::pin(async move {
            Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies p JOIN mdm_planning.policy_assignments a ON(a.tenant_id,a.policy,a.version)=(p.tenant_id,p.id,p.current_version) WHERE p.tenant_id=$1::uuid AND (p.state='enabled') AND (p.definition->'action'->>'kind'=ANY($3::text[]) OR (p.definition->'action'->>'kind'='software' AND p.definition->'action'->>'channel'='mdm')) AND a.channel='mdm' AND a.target->>'device'=$2 AND a.input->'admission'->>'state'<>'excluded')")
                .bind(tenant.to_string()).bind(device).bind(kinds).fetch_one(connection).await?)
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
            let rows=sqlx::query("WITH candidates AS MATERIALIZED (SELECT p.id,p.current_version,(p.definition->>'scope')::uuid AS scope,d.device FROM mdm_policy.policies p CROSS JOIN (SELECT DISTINCT unnest($2::text[]) AS device) d WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND p.definition->'action'->>'kind'='configuration' AND ($3::uuid IS NULL OR (p.id,d.device COLLATE \"C\")>($3,$4 COLLATE \"C\")) ORDER BY p.id,d.device COLLATE \"C\" LIMIT 1001) SELECT *,mdm_commands.channel_admission(scope,'mdm',device) AS admission FROM candidates ORDER BY id,device COLLATE \"C\"")
                .bind(tenant.to_string()).bind(devices).bind(after.map(|v|v.0)).bind(after.map(|v|v.1.as_str())).fetch_all(c).await?;
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
            let rows=sqlx::query("SELECT id,current_version,(definition->>'scope')::uuid AS scope FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (state='enabled') AND id>$2 AND definition->'action'->>'kind'=$3 ORDER BY id LIMIT 17").bind(tenant.to_string()).bind(after).bind(kind.as_str()).fetch_all(&mut *c).await?;
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
