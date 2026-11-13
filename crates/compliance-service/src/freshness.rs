//! One bounded cross-owner read, not a per-rule/per-group round-trip loop.
use super::*;
use std::collections::BTreeSet;
impl Compliance {
    pub(crate) async fn inputs_current(
        &self,
        tx: &mut PgTransaction<'_>,
        inputs: &[Input],
    ) -> Result<BTreeSet<Uuid>> {
        if inputs.len() > 100 {
            return Err(Error::Unavailable(Failure::ComplianceStorage).into());
        }
        for input in inputs {
            stored(input.validate())?;
        }
        let mut coordinates = std::collections::BTreeMap::new();
        for input in inputs {
            for g in &input.groups {
                let key = (g.id, g.revision, g.member_set, g.member_version);
                coordinates.entry(key).or_insert(
                    rss_mdm_group_postgres::sources::CurrentMembership {
                        id: g.id,
                        revision: g.revision,
                        member_set: g.member_set,
                        member_version: g.member_version,
                    },
                );
            }
        }
        let coordinates = coordinates.into_values().collect::<Vec<_>>();
        let current = checked(self.groups.current_memberships_in(tx, &coordinates).await?)?;
        let current = current.into_iter().map(|state| {
            let cut = state.input_version.as_deref().map(rss_mdm_inventory::AssetCut::from_input_version)
                .transpose().map_err(|_|Error::Unavailable(Failure::ComplianceStorage))?;
            let m=state.membership;
            Ok(serde_json::json!({"id":m.id,"revision":m.revision,"member_set":m.member_set,"member_version":m.member_version,"assetCut":cut}))
        }).collect::<Result<Vec<_>>>()?;
        let current = checked_input(serde_json::to_string(&current))?;
        let tenant = self.tenant().to_string();
        let document = checked_input(serde_json::to_string(inputs))?;
        let ids:Vec<String>=tx.with_connection(move|c|Box::pin(async move{
   sqlx::query_scalar(r#"
    WITH inputs AS MATERIALIZED(SELECT * FROM jsonb_to_recordset($2::jsonb) x(rule uuid,revision bigint,"assetCut" jsonb,definition jsonb,groups jsonb)),
    memberships AS MATERIALIZED(SELECT * FROM jsonb_to_recordset($3::jsonb) m(id uuid,revision bigint,member_set uuid,member_version bigint,"assetCut" jsonb)),
    cut_values AS MATERIALIZED(SELECT x."assetCut" AS cut FROM inputs x UNION SELECT m."assetCut" FROM memberships m WHERE m."assetCut" IS NOT NULL),
    cuts AS MATERIALIZED(SELECT c.cut,v.* FROM cut_values c CROSS JOIN LATERAL mdm.asset_cut_context(c.cut) v)
    SELECT x.rule::text FROM inputs x
    JOIN mdm_compliance.rules r ON r.tenant_id=$1::uuid AND r.id=x.rule
    JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision)
    WHERE r.enabled AND r.revision=x.revision AND v.definition=x.definition
    AND NOT EXISTS(
      SELECT 1 FROM jsonb_to_recordset(x.groups) g(id uuid,revision bigint,"memberSet" uuid,"memberVersion" bigint,"assetCut" jsonb,ready boolean)
      WHERE NOT g.ready OR NOT EXISTS(SELECT 1 FROM memberships m
       WHERE m.id=g.id AND m.revision=g.revision AND m.member_set IS NOT DISTINCT FROM g."memberSet" AND m.member_version=g."memberVersion"
       AND (m."assetCut" IS NULL OR NOT EXISTS(
         SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,c.source_epoch,c.writer_xid) FROM cuts WHERE cut=m."assetCut"),false)
         AND(c.kind IN('device','source','credential') OR EXISTS(SELECT 1 FROM mdm_assets.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=g.id AND f.field=ANY(c.fields)))
       )))
    )
    AND NOT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,c.source_epoch,c.writer_xid) FROM cuts WHERE cut=x."assetCut"),false)
      AND(c.kind IN('device','source','credential') OR EXISTS(SELECT 1 FROM mdm_compliance.fields f WHERE f.tenant_id=c.tenant_id AND f.rule_id=x.rule AND f.field=ANY(c.fields)))
      AND(c.identity->>'device' IS NULL OR jsonb_array_length(x.groups)=0 OR EXISTS(
        SELECT FROM mdm_group.input_candidate_groups(ARRAY(SELECT (g->>'id')::uuid FROM jsonb_array_elements(x.groups) g),ARRAY[(c.identity->>'device')::uuid]))))
   "#).bind(tenant).bind(document).bind(current).fetch_all(c).await
  })).await?;
        ids.into_iter()
            .map(|s| stored(Uuid::parse_str(&s)))
            .collect()
    }
}
