//! Bounded reference reads; durable traversal belongs to the existing Group task.
use super::*;
use std::collections::BTreeSet;
pub async fn used_in(tx: &mut PgTransaction<'_>, group: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_group.groups g JOIN mdm_assets.group_selections s ON(s.tenant_id,s.group_id,s.rule_version)=(g.tenant_id,g.id,g.rule_version) WHERE g.tenant_id=$1::uuid AND NOT g.deleted AND s.group_ids @> ARRAY[$2::uuid])")
            .bind(tenant).bind(group).fetch_one(c).await
    })).await?)
}

impl Groups {
    pub async fn definition_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<GroupChange>,
    ) -> Result<(rss_mdm_group::AssetContext, Vec<Uuid>)> {
        let gid = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        let (context, condition) = match &op.input {
            GroupChange::Create {
                asset_context,
                criteria: Some(c),
                ..
            } => {
                if op.expected_revision != 0 {
                    return Err(Error::Conflict.into());
                }
                let tenant = self.tenant.to_string();
                let exists: bool = tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2::uuid)")
                        .bind(tenant).bind(id.to_string()).fetch_one(c).await
                })).await?;
                if exists {
                    return Err(Error::Conflict.into());
                }
                (*asset_context, c)
            }
            GroupChange::Rule { criteria } => {
                let group = group_checked(self.groups.get_in(tx, gid).await?)?
                    .filter(|g| !g.deleted)
                    .ok_or(Error::Group(GroupMissing::Group))?;
                if group.revision.get() as u64 != op.expected_revision {
                    return Err(Error::Conflict.into());
                }
                (group.asset_context, criteria)
            }
            _ => return Err(Error::Malformed.into()),
        };
        condition.validate()?;
        let catalog = assets::catalog_in(tx, self.tenant, i64::MAX).await?;
        let rule = criteria::rule(self.tenant, op.operation_id, &condition.criteria, &catalog)?;
        assets::filter::require_visible_rule(&catalog, &rule)?;
        let references = rule
            .groups()
            .iter()
            .map(|s| checked_input(Uuid::parse_str(s)))
            .collect::<Result<BTreeSet<_>>>()?;
        if references.contains(&id) {
            return Err(Error::Malformed.into());
        }
        Ok((context, references.into_iter().collect()))
    }
    pub async fn reference_edges_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        context: rss_mdm_group::AssetContext,
    ) -> Result<Vec<Uuid>> {
        let gid = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        let group = group_checked(self.groups.get_in(tx, gid).await?)?
            .filter(|g| !g.deleted)
            .ok_or(Error::Group(GroupMissing::Group))?;
        if group.asset_context != context {
            return Err(Error::Malformed.into());
        }
        let Some(version) = group.rule_version else {
            return Ok(vec![]);
        };
        let rule =
            group_checked(self.groups.rule_in(tx, gid, &version).await?)?.ok_or(Error::Conflict)?;
        let catalog = assets::catalog_in(tx, self.tenant, i64::MAX).await?;
        assets::filter::require_visible_rule(&catalog, &rule)?;
        rule.groups()
            .iter()
            .map(|s| checked_input(Uuid::parse_str(s)))
            .collect()
    }
}
