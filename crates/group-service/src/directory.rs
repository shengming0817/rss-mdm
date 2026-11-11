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
    let mut query = Query::new(schema(), parameters)?;
    query.default_filter("deleted", "false")?;
    Ok(DirectoryQuery {
        query,
        referenceable_for,
    })
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
            .require_schema(schema())
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
                        let gid = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
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
                                .directory_in(tx, &q.query, after.as_ref(), context, &BINDINGS)
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
                                let catalog = assets::catalog_in(tx, s.tenant).await?;
                                match assets::filter::require_visible_rule(&catalog, &rule) {
                                    Err(
                                        rss_mdm_inventory_service::transaction::Fault::Request(
                                            rss_mdm_inventory_service::Error::Forbidden,
                                        ),
                                    ) => continue,
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
        )
        .await
    }
}

pub fn schema() -> &'static rss_mdm_query::directory::Schema {
    BINDINGS.schema()
}

impl Groups {
    /// Safe historical management result from the original actor's receipt.
    pub async fn operation_receipt(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        p.manage(Permission::GroupRead)?;
        crate::transaction::inspect(&self.runtime,self.tenant,(self,p),|(_,p),tx|Box::pin(async move {
            let grant=crate::transaction::query_authority(tx,p).await?;
            grant.require(p,Permission::GroupRead,None)?;
            grant.require_all_devices(p,Permission::InventoryRead)?;
            let tenant=p.tenant_id().to_owned();let actor=p.principal_id().to_owned();let instance=p.instance_id().to_owned();
            let value:Option<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move{
                sqlx::query_scalar("SELECT response FROM mdm_assets.group_operations WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3 AND instance=$4::uuid")
                    .bind(tenant).bind(actor).bind(id).bind(instance).fetch_optional(c).await
            })).await?;
            value.map(|v|{
                let mut s=rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                match crate::response::Response::decode(v)? {
                    crate::response::Response::GroupReceipt(v)=>{s.object=Some(v.group.id.to_string());s.revision=Some(v.group.revision);s.executions.extend(v.task);},
                    crate::response::Response::JobAccepted(v)=>{s.object=Some(v.target);s.accepted=Some(true);s.executions.push(v.task);},
                    _=>return Err(Error::Conflict.into()),
                }
                Ok(s)
            }).transpose()
        })).await
    }
}

use rss_mdm_query::directory::Schema;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Row>("groups", &["id"], 64, 1000, &[])
        .and_then(|s| s.no_range("ruleVersion"))
        .expect("Group public model is fully described")
});

#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
/// Public directory row before selection removes unrequested output fields.
pub struct Row {
    /// Stable object identity within the tenant.
    pub id: rss_mdm_group::GroupId,
    /// Declared business kind.
    pub kind: rss_mdm_group_postgres::GroupKind,
    /// Optional built-in membership selection.
    pub system_selector: Option<rss_mdm_group_postgres::SystemSelector>,
    /// Asset universe in which membership is evaluated.
    pub asset_context: rss_mdm_group::AssetContext,
    #[schemars(with = "rss_mdm_group_postgres::Presentation")]
    /// Bounded descriptive metadata, including retained extensions.
    pub presentation: serde_json::Map<String, serde_json::Value>,
    /// Human-readable name; no authorization meaning.
    pub name: Option<String>,
    /// Current compare-and-swap revision.
    pub revision: rss_mdm_group_postgres::Revision,
    /// Last calculation revision.
    pub calculation_revision: i64,
    /// Published membership version.
    pub member_version: i64,
    /// Published member count.
    pub member_count: usize,
    /// Optional opaque rule revision.
    pub rule_version: Option<String>,
    /// Whether the object is a retained tombstone.
    pub deleted: bool,
}

static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(&SCHEMA, rss_mdm_group_postgres::directory::SOURCES)
            .expect("Complete service model binding")
    });

/// Public model with every executable selector checked by this storage owner.
pub fn execution() -> &'static rss_mdm_query::directory::Execution {
    BINDINGS.execution()
}
