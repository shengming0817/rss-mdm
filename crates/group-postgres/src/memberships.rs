//! Reverse membership over published changes; sparse calculations do not erase unchanged members.
use crate::*;
use serde_json::Value;
use sqlx::PgConnection;
impl GroupStore {
    /// Read a bounded live directory for one endpoint and its owner-resolved associated objects.
    /// Objects in the associated universe use their existing typed-key encoding.
    pub async fn memberships_on(
        &self,
        c: &mut PgConnection,
        endpoint: &rss_mdm_agent_wire::DeviceId,
        objects: &[rss_mdm_agent_wire::ObjectRef],
        after: Option<uuid::Uuid>,
        limit: usize,
    ) -> InTransaction<Vec<Value>> {
        let bound: Option<String> =
            sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)")
                .fetch_one(&mut *c)
                .await?;
        if bound.as_deref() != Some(self.tenant.to_string().as_str()) {
            return Ok(Err(Rejection::TenantMismatch));
        }
        if !(1..=1000).contains(&limit)
            || objects.len() > 32
            || objects.iter().any(|o| o.uuid().is_nil())
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let tenant = self.tenant.to_string();
        let endpoint = endpoint.to_owned();
        let kinds = objects.iter().map(|o| o.kind()).collect::<Vec<_>>();
        let ids = objects.iter().map(|o| o.uuid()).collect::<Vec<_>>();
        Ok(Ok(sqlx::query_scalar(r#"
WITH candidates AS (
 SELECT DISTINCT ON(m.group_id,m.object_kind,m.object_id) m.group_id,m.object_kind,m.object_id,m.added
 FROM mdm_group.member_changes m JOIN mdm_group.groups g ON(g.tenant_id,g.id)=(m.tenant_id,m.group_id)
 WHERE m.tenant_id=$1::uuid AND NOT g.deleted AND ($5::uuid IS NULL OR g.id>$5)
 AND ((g.asset_context='endpoint' AND m.object_kind=0 AND m.object_id=$2) OR (g.asset_context='associated_device' AND EXISTS(SELECT FROM unnest($3::smallint[],$4::uuid[]) s(kind,id) WHERE (m.object_kind,m.object_id)=(s.kind,s.id))))
 AND m.revision<=g.calculation_revision
 AND EXISTS(SELECT 1 FROM mdm_group.member_runs b WHERE b.tenant_id=m.tenant_id AND b.id=m.run_id AND b.phase='published')
 ORDER BY m.group_id,m.object_kind,m.object_id,m.revision DESC
), hits AS (SELECT group_id,jsonb_agg(jsonb_build_object('kind',CASE object_kind WHEN 0 THEN 'endpoint' ELSE 'association' END,'id',object_id) ORDER BY object_kind,object_id) AS objects FROM candidates WHERE added GROUP BY group_id)
SELECT jsonb_build_object('id',g.id,'presentation',g.presentation,'kind',g.kind,'assetContext',g.asset_context,
'revision',g.revision,'memberVersion',g.member_version,'calculationRevision',g.calculation_revision,
'memberSet',g.member_set,'currentRuleVersion',g.rule_version,'evaluatedRuleVersion',b.rule_version,
'inputVersion',b.input_version,'asOf',b.as_of,'ruleCurrent',g.rule_version IS NOT DISTINCT FROM b.rule_version,'objects',h.objects)
FROM hits h JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=h.group_id
JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(g.tenant_id,g.member_set)
ORDER BY g.id LIMIT $6
"#).bind(tenant).bind(endpoint.into_uuid()).bind(kinds).bind(ids).bind(after).bind((limit+1) as i64).fetch_all(c).await
        ?))
    }
}

/// Test membership in any currently published endpoint group on the caller's tenant connection.
/// No transaction is started or settled. Unknown/deleted/stale groups do not match.
pub async fn published_endpoint_member_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    groups: &[uuid::Uuid],
    endpoint: &rss_mdm_agent_wire::DeviceId,
) -> InTransaction<bool> {
    let actual: Option<String> = sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)")
        .fetch_one(&mut *c)
        .await?;
    if actual.as_deref() != Some(tenant.to_string().as_str()) {
        return Ok(Err(Rejection::TenantMismatch));
    }
    if groups.is_empty() || groups.len() > 16 || groups.iter().any(uuid::Uuid::is_nil) {
        return Ok(Err(Rejection::InvalidInput));
    }
    let tenant = uuid::Uuid::parse_str(&tenant.to_string())
        .map_err(|_| sqlx::Error::Protocol("invalid group tenant".into()))?;
    Ok(Ok(sqlx::query_scalar(r#"SELECT EXISTS(SELECT 1 FROM mdm_group.groups g JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(g.tenant_id,g.member_set) WHERE g.tenant_id=$1 AND g.id=ANY($2) AND NOT g.deleted AND g.asset_context='endpoint' AND b.phase='published' AND g.rule_version IS NOT DISTINCT FROM b.rule_version AND (SELECT m.added FROM mdm_group.member_changes m JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE m.tenant_id=g.tenant_id AND m.group_id=g.id AND m.object_kind=0 AND m.object_id=$3 AND m.revision<=g.calculation_revision AND r.phase='published' ORDER BY m.revision DESC LIMIT 1)=true)"#).bind(tenant).bind(groups).bind(endpoint.into_uuid()).fetch_one(c).await?))
}
