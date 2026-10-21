//! Read-only aggregation of current Group, Scope, Policy and Compliance owners.
use super::*;
use rss_mdm_inventory_service::groups::{
    dependencies,
    references::{Entry, Freshness, Kind, Lifecycle, Object, Relation},
};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
fn object(kind: Kind, id: Uuid) -> Object {
    Object { kind, id }
}
fn relation(path: &[Object]) -> Relation {
    if path.len() == 2 {
        Relation::Direct
    } else {
        Relation::Indirect
    }
}
fn merge(out: &mut BTreeMap<(Kind, Uuid, Relation), Entry>, mut entry: Entry) {
    entry.roles.sort();
    entry.roles.dedup();
    let key = entry.key();
    if let Some(old) = out.get_mut(&key) {
        old.roles.extend(entry.roles);
        old.roles.sort();
        old.roles.dedup();
        if (entry.via.len(), &entry.via) < (old.via.len(), &old.via) {
            old.via = entry.via;
        }
    } else {
        out.insert(key, entry);
    }
}
fn entry(
    kind: Kind,
    id: Uuid,
    revision: i64,
    path: Vec<Object>,
    roles: Vec<String>,
    state: Lifecycle,
    current: bool,
) -> Entry {
    Entry {
        source: object(kind, id),
        revision,
        relation: relation(&path),
        roles,
        via: path,
        lifecycle_state: state,
        freshness: if current {
            Freshness::Current
        } else {
            Freshness::Pending
        },
        effective: current && matches!(state, Lifecycle::Active | Lifecycle::Enabled),
        blocks_deletion: true,
    }
}
impl Planning {
    pub(super) async fn group_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        root: Uuid,
    ) -> Result<Vec<Entry>> {
        let graph = dependencies::graph_in(tx).await?;
        let mut paths: BTreeMap<(Uuid, Relation), Vec<Object>> = BTreeMap::new();
        let mut queue = VecDeque::from([(root, vec![object(Kind::Group, root)])]);
        while let Some((target, path)) = queue.pop_front() {
            for (parent, children) in &graph {
                if !children.contains(&target) {
                    continue;
                }
                let mut next = path.clone();
                next.push(object(Kind::Group, *parent));
                if next.len() > dependencies::MAX_DEPTH + 1 || paths.len() > dependencies::MAX_GRAPH
                {
                    return Err(Error::Malformed.into());
                }
                let key = (*parent, relation(&next));
                if !paths.contains_key(&key) {
                    paths.insert(key, next.clone());
                    queue.push_back((*parent, next));
                }
            }
        }
        let mut out = BTreeMap::new();
        for ((id, _), path) in &paths {
            let gid = checked_input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
            let group =
                group_checked(self.groups.get_in(tx, gid).await?)?.ok_or(Error::NotFound)?;
            let rule = group_checked(
                self.groups
                    .rule_in(
                        tx,
                        gid,
                        group.rule_version.as_deref().ok_or(Error::Conflict)?,
                    )
                    .await?,
            )?
            .ok_or(Error::Conflict)?;
            let target = path[path.len() - 2].id.to_string();
            let mut roles = BTreeSet::new();
            fn collect(
                c: &rss_mdm_group_postgres::core::Criteria,
                target: &str,
                roles: &mut BTreeSet<String>,
            ) {
                use rss_mdm_group_postgres::core::CriteriaView as C;
                match c.view() {
                    C::Membership { group, negated } if group == target => {
                        roles.insert(
                            if negated {
                                "not_member_of"
                            } else {
                                "member_of"
                            }
                            .into(),
                        );
                    }
                    C::And(cs) | C::Or(cs) => {
                        for c in cs {
                            collect(c, target, roles);
                        }
                    }
                    _ => {}
                }
            }
            collect(rule.view().criteria, &target, &mut roles);
            let frozen = self.capture_group_source_in(tx, *id).await?;
            let current = self.source_current_in(tx, &frozen).await?;
            merge(
                &mut out,
                entry(
                    Kind::Group,
                    *id,
                    group.revision.get(),
                    path.clone(),
                    roles.into_iter().collect(),
                    Lifecycle::Active,
                    current,
                ),
            );
        }
        // The root itself is a dependency source only when another owner references it.
        paths.insert((root, Relation::Direct), vec![object(Kind::Group, root)]);
        let ids: Vec<Uuid> = paths
            .keys()
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let selected: Vec<String> = ids.iter().map(ToString::to_string).collect();
        let tenant = self.tenant.to_string();
        let scopes=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT s.id,s.revision,v.definition::text,mdm_planning.scope_admission(s.id,NULL)->>'state'='fresh' AS current FROM mdm_planning.scopes s JOIN mdm_planning.scope_versions v USING(tenant_id,id,revision) WHERE s.tenant_id=$1::uuid AND NOT s.deleted AND EXISTS(SELECT 1 FROM mdm_planning.scope_sources edge WHERE edge.tenant_id=s.tenant_id AND edge.scope=s.id AND edge.kind='group' AND edge.target=ANY($2)) ORDER BY s.id LIMIT 4097").bind(tenant).bind(selected).fetch_all(c).await
        })).await?;
        if scopes.len() > dependencies::MAX_GRAPH {
            return Err(Error::Malformed.into());
        }
        let mut scope_paths: BTreeMap<(Uuid, Relation), Entry> = BTreeMap::new();
        for row in scopes {
            let id: Uuid = row.try_get("id")?;
            let revision: i64 = row.try_get("revision")?;
            let definition: ScopeDefinition =
                stored(serde_json::from_str(row.try_get("definition")?))?;
            let current: bool = row.try_get("current")?;
            for ((target, _), path) in &paths {
                let reference = Reference::Group(*target);
                let mut roles = Vec::new();
                if definition.targets.contains(&reference) {
                    roles.push("target".into());
                }
                if definition
                    .limitations
                    .as_ref()
                    .is_some_and(|s| s.contains(&reference))
                {
                    roles.push("limitation".into());
                }
                if definition.exclusions.contains(&reference) {
                    roles.push("exclusion".into());
                }
                if roles.is_empty() {
                    continue;
                }
                let mut path = path.clone();
                path.push(object(Kind::Scope, id));
                let item = entry(
                    Kind::Scope,
                    id,
                    revision,
                    path,
                    roles,
                    Lifecycle::Active,
                    current,
                );
                merge(&mut out, item);
            }
        }
        for ((kind, id, relation), value) in &out {
            if *kind == Kind::Scope {
                scope_paths.insert((*id, *relation), value.clone());
            }
        }
        let scopes: Vec<_> = scope_paths
            .keys()
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if !scopes.is_empty() {
            let tenant = self.tenant.to_string();
            let rows=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("SELECT id,revision,state,definition::text FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND ((definition->>'scope')::uuid=ANY($2) OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(definition->'action'->'rollout'->'stages','[]'::jsonb)) stage WHERE (stage->>'scope')::uuid=ANY($2))) ORDER BY id LIMIT 4097").bind(tenant).bind(scopes).fetch_all(c).await
            })).await?;
            if rows.len() > dependencies::MAX_GRAPH {
                return Err(Error::Malformed.into());
            }
            for row in rows {
                let id: Uuid = row.try_get("id")?;
                let revision: i64 = row.try_get("revision")?;
                let state: Lifecycle = stored(serde_json::from_value(serde_json::json!(
                    row.try_get::<String, _>("state")?
                )))?;
                let definition: Value = stored(serde_json::from_str(row.try_get("definition")?))?;
                for ((scope, _), source) in &scope_paths {
                    let mut roles = Vec::new();
                    if definition["scope"].as_str() == Some(scope.to_string().as_str()) {
                        roles.push("policy_scope".into());
                    }
                    if definition["action"]["rollout"]["stages"]
                        .as_array()
                        .is_some_and(|stages| {
                            stages.iter().any(|stage| {
                                stage["scope"].as_str() == Some(scope.to_string().as_str())
                            })
                        })
                    {
                        roles.push("rollout_stage".into());
                    }
                    if roles.is_empty() {
                        continue;
                    }
                    let mut path = source.via.clone();
                    path.push(object(Kind::Policy, id));
                    merge(
                        &mut out,
                        entry(
                            Kind::Policy,
                            id,
                            revision,
                            path,
                            roles,
                            state,
                            source.freshness == Freshness::Current,
                        ),
                    );
                }
            }
        }
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT r.id,r.revision,r.enabled,g.group_id FROM mdm_compliance.rules r JOIN mdm_compliance.groups g ON(g.tenant_id,g.rule_id)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND g.group_id=ANY($2) ORDER BY r.id,g.group_id LIMIT 4097").bind(tenant).bind(ids).fetch_all(c).await
        })).await?;
        if rows.len() > dependencies::MAX_GRAPH {
            return Err(Error::Malformed.into());
        }
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            let target: Uuid = row.try_get("group_id")?;
            for ((group, _), path) in &paths {
                if *group != target {
                    continue;
                }
                let frozen = self.capture_group_source_in(tx, target).await?;
                let current = self.source_current_in(tx, &frozen).await?;
                let mut path = path.clone();
                path.push(object(Kind::ComplianceRule, id));
                merge(
                    &mut out,
                    entry(
                        Kind::ComplianceRule,
                        id,
                        row.try_get("revision")?,
                        path,
                        vec!["compliance_target".into()],
                        if row.try_get("enabled")? {
                            Lifecycle::Enabled
                        } else {
                            Lifecycle::Disabled
                        },
                        current,
                    ),
                );
            }
        }
        if out.len() > dependencies::MAX_GRAPH {
            return Err(Error::Malformed.into());
        }
        Ok(out.into_values().collect())
    }
}
