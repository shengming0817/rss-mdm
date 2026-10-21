//! Frozen group coordinates and decisions; Group and Scope use this same capture path.
use super::*;
use rss_mdm_group_postgres as g;
impl Planning {
    pub(in crate::planning) async fn capture_group_source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<g::GroupSource> {
        let gid = checked_input(g::GroupId::parse(&id.to_string()))?;
        let group = group_checked(self.groups.lock_reference_target_in(tx, gid).await?)?;
        let member_set = checked(self.groups.current_member_set_in(tx, gid).await?)?;
        let authority = checked(
            self.sources
                .reference_in(tx, &format!("group-authority.{id}"))
                .await?,
        )?
        .ok_or(Error::Conflict)?;
        let definition = checked(
            self.sources
                .reference_in(tx, &format!("group-definition.{id}"))
                .await?,
        )?
        .ok_or(Error::Conflict)?;
        Ok(g::GroupSource {
            group: gid,
            coordinates: g::SourceCoordinates {
                member_set,
                member_version: group.member_version as u64,
                definition_version: definition,
                authority_version: authority,
                asset_context: group.asset_context,
            },
        })
    }
    pub(super) async fn group_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: g::GroupId,
        version: Option<&str>,
    ) -> Result<Vec<g::GroupSource>> {
        let Some(version) = version else {
            return Ok(vec![]);
        };
        let rule = group_checked(self.groups.rule_in(tx, group, version).await?)?
            .ok_or(Error::Conflict)?;
        let mut sources = Vec::new();
        for id in rule.groups() {
            sources.push(
                self.capture_group_source_in(tx, checked_input(Uuid::parse_str(&id))?)
                    .await?,
            );
        }
        Ok(sources)
    }
    pub(in crate::planning) async fn source_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &g::GroupSource,
    ) -> Result<bool> {
        let current = self
            .capture_group_source_in(
                tx,
                checked_input(Uuid::parse_str(&source.group.to_string()))?,
            )
            .await?;
        if &current != source {
            return Ok(false);
        }
        if let Some(run) = source.coordinates.member_set {
            let build = checked(self.groups.build_in(tx, run).await?)?;
            if let Some(snapshot) = super::groups::object_snapshot(&build.request.input_version)? {
                let reader = self.objects.clone();
                let tenant = self.tenant;
                if !tx
                    .with_connection(move |c| {
                        Box::pin(async move { reader.current(c, tenant, &snapshot).await })
                    })
                    .await?
                {
                    return Ok(false);
                }
            }
        }
        let id = source.group.to_string();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT mdm_planning.group_current($1::uuid)")
                        .bind(id)
                        .fetch_one(c)
                        .await
                })
            })
            .await?)
    }
    pub(super) async fn fill_group_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        sources: &[g::GroupSource],
        objects: &mut [g::core::ObjectSnapshot],
    ) -> Result<()> {
        let keys: Vec<_> = objects.iter().map(|o| o.key.id().to_string()).collect();
        for source in sources {
            let decisions = if let Some(run) = source.coordinates.member_set {
                group_checked(self.groups.source_decisions_in(tx, run, &keys).await?)?
            } else {
                std::collections::BTreeMap::new()
            };
            for object in objects.iter_mut() {
                let outcome = decisions.get(object.key.id()).copied().unwrap_or(
                    if source.coordinates.member_set.is_none() {
                        g::core::Outcome::NoMatch
                    } else {
                        g::core::Outcome::Unknown(g::core::UnknownReason::Missing)
                    },
                );
                object.memberships.insert(source.group.to_string(), outcome);
            }
        }
        Ok(())
    }
}
