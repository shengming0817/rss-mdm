//! Frozen group coordinates and decisions; Group and Scope use this same capture path.
use super::*;
use rss_mdm_group_postgres as g;
impl Groups {
    pub(super) async fn capture_group_source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<rss_mdm_group::GroupSource> {
        let gid = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        group_checked(self.groups.capture_source_in(tx, gid).await?)
    }
    pub(super) async fn group_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: rss_mdm_group::GroupId,
        version: Option<&str>,
    ) -> Result<Vec<rss_mdm_group::GroupSource>> {
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
    pub(super) async fn source_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &rss_mdm_group::GroupSource,
    ) -> Result<bool> {
        group_checked(self.groups.source_current_in(tx, source).await?)
    }
    // Waiting is progress on the same durable task. Only a ready replacement
    // source invalidates the frozen input and requires a new calculation.
    pub(super) async fn source_ready_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &rss_mdm_group::GroupSource,
    ) -> Result<bool> {
        group_checked(self.groups.source_ready_in(tx, source).await?)
    }
    pub(super) async fn fill_group_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        sources: &[rss_mdm_group::GroupSource],
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
