//! Current definition edges. Immutable selections are indexed, never a second rule owner.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_GRAPH: usize = 4096;
pub const MAX_DEPTH: usize = 16;
pub type Graph = BTreeMap<Uuid, BTreeSet<Uuid>>;
pub async fn graph_in(tx: &mut PgTransaction<'_>) -> Result<Graph> {
    let tenant = tx.tenant_id().to_string();
    let rows:Vec<(Uuid,Uuid)>=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as("SELECT g.id,ref FROM mdm_group.groups g JOIN mdm_assets.group_selections s ON(s.tenant_id,s.group_id,s.rule_version)=(g.tenant_id,g.id,g.rule_version) CROSS JOIN LATERAL unnest(s.group_ids) ref WHERE g.tenant_id=$1::uuid AND NOT g.deleted ORDER BY g.id,ref LIMIT 4097").bind(tenant).fetch_all(c).await
    })).await?;
    if rows.len() > MAX_GRAPH {
        return Err(Error::Malformed.into());
    }
    let mut graph = Graph::new();
    for (from, to) in rows {
        graph.entry(from).or_default().insert(to);
    }
    Ok(graph)
}
fn visit(graph: &Graph, id: Uuid, path: &mut BTreeSet<Uuid>, visited: &mut usize) -> Result<usize> {
    if path.len() >= MAX_DEPTH {
        return Err(Error::Malformed.into());
    }
    *visited += 1;
    if *visited > MAX_GRAPH || !path.insert(id) {
        return Err(Error::Malformed.into());
    }
    let mut depth = 0;
    if let Some(children) = graph.get(&id) {
        for child in children {
            depth = depth.max(visit(graph, *child, path, visited)?);
        }
    }
    path.remove(&id);
    if depth >= MAX_DEPTH {
        return Err(Error::Malformed.into());
    }
    Ok(depth + 1)
}
pub fn validate_graph(graph: &Graph) -> Result<()> {
    for id in graph.keys() {
        visit(graph, *id, &mut BTreeSet::new(), &mut 0)?;
    }
    Ok(())
}
impl Groups {
    pub(super) async fn validate_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        context: rss_mdm_group_postgres::AssetContext,
        rule: &rss_mdm_group_postgres::core::Rule,
        sensitive: bool,
    ) -> Result<Vec<Uuid>> {
        let refs = rule
            .groups()
            .iter()
            .map(|s| checked_input(Uuid::parse_str(s)))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut graph = graph_in(tx).await?;
        graph.insert(id, refs.clone());
        validate_graph(&graph)?;
        let catalog = assets::catalog_in(tx, self.tenant, i64::MAX).await?;
        let mut pending = refs.clone();
        let mut seen = BTreeSet::new();
        while let Some(target) = pending.pop_first() {
            if !seen.insert(target) {
                continue;
            }
            let gid = checked_input(rss_mdm_group_postgres::GroupId::parse(&target.to_string()))?;
            let group = group_checked(self.groups.lock_reference_target_in(tx, gid).await?)?;
            if group.asset_context != context {
                return Err(Error::Malformed.into());
            }
            if let Some(version) = group.rule_version {
                let rule = group_checked(self.groups.rule_in(tx, gid, &version).await?)?
                    .ok_or(Error::Conflict)?;
                assets::filter::require_visible_rule(&catalog, &rule, sensitive)?;
            }
            if let Some(children) = graph.get(&target) {
                pending.extend(children);
            }
        }
        Ok(refs.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_rejects_self_cycles_and_overdepth_but_accepts_shared_ancestors() {
        let ids: Vec<_> = (0..18).map(|_| Uuid::new_v4()).collect();
        let mut graph = Graph::new();
        graph.insert(ids[0], [ids[0]].into());
        assert!(validate_graph(&graph).is_err());
        graph.insert(ids[0], [ids[1]].into());
        graph.insert(ids[1], [ids[0]].into());
        assert!(validate_graph(&graph).is_err());
        graph.clear();
        graph.insert(ids[0], [ids[1], ids[2]].into());
        graph.insert(ids[1], [ids[3]].into());
        graph.insert(ids[2], [ids[3]].into());
        assert!(validate_graph(&graph).is_ok());
        graph.clear();
        for i in 0..15 {
            graph.insert(ids[i], [ids[i + 1]].into());
        }
        assert!(validate_graph(&graph).is_ok());
        graph.insert(ids[15], [ids[16]].into());
        assert!(validate_graph(&graph).is_err());
    }
}
