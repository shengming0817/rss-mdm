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
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub id: rss_mdm_group_postgres::GroupId,
    pub kind: rss_mdm_group_postgres::GroupKind,
    pub system_selector: Option<rss_mdm_group_postgres::SystemSelector>,
    pub asset_context: rss_mdm_group_postgres::AssetContext,
    #[schemars(extend("x-rss-extension"="Group presentation metadata"))]
    pub presentation: serde_json::Map<String, Value>,
    pub name: Option<String>,
    pub revision: rss_mdm_group_postgres::Revision,
    pub calculation_revision: i64,
    pub member_version: i64,
    pub member_count: usize,
    pub rule_version: Option<String>,
    pub deleted: bool,
}
fn row(g: &rss_mdm_group_postgres::Group) -> Row {
    Row {
        id: g.id,
        kind: g.kind,
        system_selector: g.system_selector,
        asset_context: g.asset_context,
        presentation: g.presentation.clone(),
        name: g
            .presentation
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        revision: g.revision,
        calculation_revision: g.calculation_revision,
        member_version: g.member_version,
        member_count: g.member_count,
        rule_version: g.rule_version.clone(),
        deleted: g.deleted,
    }
}
impl Groups {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &DirectoryQuery,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> std::result::Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Row>>, Error>
    {
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
                    let mut items = Vec::new();
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
                            .map(|g| {
                                q.query.position(
                                    &serde_json::to_value(row(g))
                                        .expect("group directory serializes"),
                                )
                            })
                            .transpose()
                            .map_err(crate::query_error)?;
                        for group in page {
                            let id = stored(Uuid::parse_str(&group.id.to_string()))?;
                            if q.referenceable_for == Some(id) {
                                continue;
                            }
                            if selecting && let Some(version) = &group.rule_version {
                                let rule =
                                    group_checked(s.groups.rule_in(tx, group.id, version).await?)?
                                        .ok_or(Error::Conflict)?;
                                let catalog = assets::catalog_in(tx, s.tenant, i64::MAX).await?;
                                match assets::filter::require_visible_rule(&catalog, &rule) {
                                    Err(Fault::Request(Error::Forbidden)) => continue,
                                    result => result?,
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

                    Ok(q.query
                        .page_typed(items, &codec, &binding)
                        .map_err(crate::query_error)?)
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
