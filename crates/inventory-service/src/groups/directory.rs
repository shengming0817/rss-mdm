use super::*;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{Parameters, cursor::CursorCodec, directory::Query};
#[derive(Clone, Debug)]
pub struct DirectoryQuery {
    pub query: Query,
    pub referenceable_for: Option<Uuid>,
}
pub fn parse(raw: &str) -> rss_mdm_query::Result<DirectoryQuery> {
    let (parameters, context) = Parameters::parse_with_context(raw, &["referenceableFor"])?;
    let referenceable_for = context
        .get("referenceableFor")
        .map(|s| Uuid::parse_str(s).map_err(|_| rss_mdm_query::Error::Invalid))
        .transpose()?;
    if referenceable_for.is_some_and(|id| id.is_nil()) {
        return Err(rss_mdm_query::Error::Invalid);
    }
    let mut query = Query::new(&rss_mdm_group_postgres::directory::SCHEMA, parameters)?;
    query.default_filter("deleted", "false")?;
    Ok(DirectoryQuery {
        query,
        referenceable_for,
    })
}
fn row(g: &rss_mdm_group_postgres::Group) -> Value {
    let mut value = serde_json::json!({"id":g.id,"kind":g.kind,"systemSelector":g.system_selector,"assetContext":g.asset_context,"presentation":g.presentation,"revision":g.revision,"calculationRevision":g.calculation_revision,"memberVersion":g.member_version,"memberCount":g.member_count,"ruleVersion":g.rule_version,"deleted":g.deleted});
    value["name"] = value["presentation"]["name"].clone();
    value
}
impl Groups {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &DirectoryQuery,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> std::result::Result<Value, Error> {
        q.query
            .require_schema(&rss_mdm_group_postgres::directory::SCHEMA)
            .map_err(crate::query_error)?;
        proof.manage(Permission::GroupRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, q, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, _audit) = *ctx;
                    let current = query_authority(tx, p).await?;
                    current.require(p, Permission::GroupRead, None)?;
                    current.require_all_devices(p, Permission::InventoryRead)?;
                    let binding = q
                        .query
                        .binding(&(
                            p.tenant_id(),
                            p.instance_id(),
                            current.query_binding(p)?,
                            q.referenceable_for,
                        ))
                        .map_err(crate::query_error)?;
                    let codec = CursorCodec::from_key(s.cursor_key.clone());
                    let mut after = q
                        .query
                        .after(&codec, &binding)
                        .map_err(crate::query_error)?;
                    let mut graph = if q.referenceable_for.is_some() {
                        Some(dependencies::graph_in(tx).await?)
                    } else {
                        None
                    };
                    let context = if let Some(id) = q.referenceable_for {
                        let gid =
                            checked_input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
                        Some(
                            group_checked(s.groups.lock_reference_target_in(tx, gid).await?)?
                                .asset_context,
                        )
                    } else {
                        None
                    };
                    let selecting = context.is_some() || q.query.mentions("assetContext");
                    let sensitive = current
                        .require(p, Permission::InventorySensitiveRead, None)
                        .is_ok();
                    let mut items = Vec::new();
                    let mut scanned = 0;
                    loop {
                        let page = group_checked(
                            s.groups
                                .directory_in(tx, &q.query, after.as_ref(), context)
                                .await?,
                        )?;
                        let count = page.len();
                        if count == 0 {
                            break;
                        }
                        let last = page
                            .last()
                            .map(|g| q.query.position(&row(g)))
                            .transpose()
                            .map_err(crate::query_error)?;
                        for group in page {
                            scanned += 1;
                            if scanned > dependencies::MAX_GRAPH {
                                return Err(Error::Malformed.into());
                            }
                            let id = stored(Uuid::parse_str(&group.id.to_string()))?;
                            if let (Some(owner), Some(graph)) =
                                (q.referenceable_for, graph.as_mut())
                            {
                                let previous = graph.insert(owner, [id].into());
                                let valid = dependencies::validate_graph(graph).is_ok();
                                if let Some(previous) = previous {
                                    graph.insert(owner, previous);
                                } else {
                                    graph.remove(&owner);
                                }
                                if !valid {
                                    continue;
                                }
                            }
                            if selecting && let Some(version) = &group.rule_version {
                                let rule =
                                    group_checked(s.groups.rule_in(tx, group.id, version).await?)?
                                        .ok_or(Error::Conflict)?;
                                let catalog = assets::catalog_in(tx, s.tenant, i64::MAX).await?;
                                match assets::filter::require_visible_rule(
                                    &catalog, &rule, sensitive,
                                ) {
                                    Err(Fault::Request(Error::Forbidden)) => continue,
                                    result => result?,
                                }
                                match s
                                    .validate_references_in(
                                        tx,
                                        id,
                                        group.asset_context,
                                        &rule,
                                        sensitive,
                                    )
                                    .await
                                {
                                    Err(Fault::Request(Error::Forbidden)) => continue,
                                    result => {
                                        result?;
                                    }
                                }
                            }
                            items.push(row(&group));
                            if items.len() > q.query.limit() {
                                break;
                            }
                        }
                        if items.len() > q.query.limit() || count <= q.query.limit() {
                            break;
                        }
                        after = last;
                    }
                    p.check_live()?;

                    json(
                        &q.query
                            .page(items, &codec, &binding)
                            .map_err(crate::query_error)?,
                    )
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
}

pub fn schema() -> &'static rss_mdm_query::directory::Schema {
    &rss_mdm_group_postgres::directory::SCHEMA
}
