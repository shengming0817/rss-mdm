//! Reverse membership over published changes; sparse calculations do not erase unchanged members.
use crate::{store::input, *};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
impl GroupStore {
    /// Read a bounded live directory for one endpoint and its owner-resolved associated objects.
    /// Objects in the associated universe use their existing typed-key encoding.
    pub async fn memberships_in(
        &self,
        tx: &mut PgTransaction<'_>,
        endpoint: &str,
        objects: &[String],
        after: Option<uuid::Uuid>,
        limit: usize,
    ) -> InTransaction<Vec<Value>> {
        input!(self.check_transaction(tx)?);
        if !(1..=1000).contains(&limit)
            || endpoint.is_empty()
            || endpoint.len() > 255
            || objects.len() > 32
            || objects.iter().any(|s| s.len() > 256)
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let tenant = self.tenant.to_string();
        let endpoint = endpoint.to_owned();
        let objects = objects.to_vec();
        Ok(Ok(tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar(r#"
WITH candidates AS (
 SELECT DISTINCT ON(m.group_id,m.object_id) m.group_id,m.object_id,m.added
 FROM mdm_group.member_changes m JOIN mdm_group.groups g ON(g.tenant_id,g.id)=(m.tenant_id,m.group_id)
 WHERE m.tenant_id=$1::uuid AND NOT g.deleted AND ($4::uuid IS NULL OR g.id>$4)
 AND ((g.asset_context='endpoint' AND m.object_id=$2) OR (g.asset_context='associated_device' AND m.object_id=ANY($3)))
 AND m.revision<=g.calculation_revision
 AND EXISTS(SELECT 1 FROM mdm_group.member_runs b WHERE b.tenant_id=m.tenant_id AND b.id=m.run_id AND b.phase='published')
 ORDER BY m.group_id,m.object_id,m.revision DESC
), hits AS (SELECT group_id,jsonb_agg(object_id ORDER BY object_id) AS objects FROM candidates WHERE added GROUP BY group_id)
SELECT jsonb_build_object('id',g.id,'presentation',g.presentation,'kind',g.kind,'assetContext',g.asset_context,
'revision',g.revision,'memberVersion',g.member_version,'calculationRevision',g.calculation_revision,
'memberSet',g.member_set,'currentRuleVersion',g.rule_version,'evaluatedRuleVersion',b.rule_version,
'inputVersion',b.input_version,'asOf',b.as_of,'ruleCurrent',g.rule_version IS NOT DISTINCT FROM b.rule_version,'objects',h.objects)
FROM hits h JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=h.group_id
JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(g.tenant_id,g.member_set)
ORDER BY g.id LIMIT $5
"#).bind(tenant).bind(endpoint).bind(objects).bind(after).bind((limit+1) as i64).fetch_all(c).await
        })).await?))
    }
}
