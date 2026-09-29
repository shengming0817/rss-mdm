//! One bounded cross-owner read, not a per-rule/per-group round-trip loop.
use super::*;
use std::collections::BTreeSet;
impl Compliance {
    pub(super) async fn inputs_current(
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
        let tenant = self.tenant().to_string();
        let document = checked_input(serde_json::to_string(inputs))?;
        let ids:Vec<String>=tx.with_connection(move|c|Box::pin(async move{
   sqlx::query_scalar(r#"
    SELECT x.rule::text FROM jsonb_to_recordset($2::jsonb) x(rule uuid,revision bigint,watermark bigint,definition jsonb,groups jsonb)
    JOIN mdm_compliance.rules r ON r.tenant_id=$1::uuid AND r.id=x.rule
    JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision)
    WHERE r.enabled AND r.revision=x.revision AND v.definition=x.definition
    AND NOT EXISTS(
      SELECT 1 FROM jsonb_to_recordset(x.groups) g(id uuid,revision bigint,"memberSet" uuid,"memberVersion" bigint,"assetWatermark" bigint,ready boolean)
      LEFT JOIN mdm_group.groups actual ON actual.tenant_id=$1::uuid AND actual.id=g.id
      WHERE NOT g.ready OR actual.id IS NULL OR actual.deleted OR actual.revision<>g.revision
       OR actual.member_set IS DISTINCT FROM g."memberSet" OR actual.member_version<>g."memberVersion"
       OR (g."assetWatermark" IS NOT NULL AND EXISTS(
         SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>g."assetWatermark"
         AND(c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_assets.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=g.id AND f.field=ANY(c.fields)))
       ))
    )
    AND NOT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>x.watermark
      AND(c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_compliance.fields f WHERE f.tenant_id=c.tenant_id AND f.rule_id=x.rule AND f.field=ANY(c.fields))))
   "#).bind(tenant).bind(document).fetch_all(c).await
  })).await?;
        ids.into_iter()
            .map(|s| stored(Uuid::parse_str(&s)))
            .collect()
    }
}
