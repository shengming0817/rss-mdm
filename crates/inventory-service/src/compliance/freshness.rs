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
        let current = checked_input(serde_json::to_string(&checked(
            self.groups.current_memberships_in(tx, &coordinates).await?,
        )?))?;
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
      WHERE NOT g.ready OR NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($3::jsonb) m(id uuid,revision bigint,member_set uuid,member_version bigint) WHERE m.id=g.id AND m.revision=g.revision AND m.member_set IS NOT DISTINCT FROM g."memberSet" AND m.member_version=g."memberVersion")
       OR (g."assetWatermark" IS NOT NULL AND EXISTS(
         SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>g."assetWatermark"
         AND(c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_assets.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=g.id AND f.field=ANY(c.fields)))
       ))
    )
    AND NOT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>x.watermark
      AND(c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_compliance.fields f WHERE f.tenant_id=c.tenant_id AND f.rule_id=x.rule AND f.field=ANY(c.fields))))
   "#).bind(tenant).bind(document).bind(current).fetch_all(c).await
  })).await?;
        ids.into_iter()
            .map(|s| stored(Uuid::parse_str(&s)))
            .collect()
    }
}
