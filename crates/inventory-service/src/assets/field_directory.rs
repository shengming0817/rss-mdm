//! Field metadata uses the canonical bounded Catalog; values never enter this directory.
use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
pub static SCHEMA: Schema = Schema {
    id: "asset_fields",
    keys: &["key"],
    default_limit: 100,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    fields: &[
        Field::scalar("key", Kind::Text),
        Field::scalar("version", Kind::Integer),
        Field::scalar("nullable", Kind::Boolean),
        Field::scalar("manual", Kind::Boolean),
        Field::scalar("searchable", Kind::Boolean),
        Field::scalar(
            "sensitivity",
            Kind::Enum(&["standard", "sensitive", "secret"]),
        ),
        Field::output("valueType"),
        Field::output("sources"),
        Field::output("platforms"),
        Field::output("unit"),
        Field::output("itemKey"),
        Field::output("timeSeries"),
        Field::output("operations"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "key" => "(document->>'key') COLLATE \"C\"",
        "version" => "(document->>'version')::bigint",
        "nullable" => "(document->>'nullable')::boolean",
        "manual" => "(document->>'manual')::boolean",
        "searchable" => "(document->>'searchable')::boolean",
        "sensitivity" => "(document->>'sensitivity') COLLATE \"C\"",
        _ => unreachable!("checked field descriptor"),
    }
}
fn entry(definition: &rss_mdm_inventory::FieldDefinition) -> Result<Value> {
    let mut value = stored(serde_json::to_value(FieldView {
        definition: crate::collection::wire::to_wire_field(definition)?,
        operations: definition.operations(),
    }))?;
    for name in ["unit", "itemKey", "timeSeries"] {
        if value.get(name).is_none() {
            value[name] = Value::Null;
        }
    }
    Ok(value)
}
impl AssetService {
    pub async fn fields(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        q.require_schema(&SCHEMA).map_err(crate::query_error)?;
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, p, q, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, _audit) = *ctx;
                    let current = query_authority(tx, p).await?;
                    let editor = current
                        .require(p, Permission::InventoryFieldsWrite, None)
                        .is_ok();
                    if !editor {
                        current.inventory_devices(p)?;
                    }
                    let watermark = s.list_watermark(tx).await?;
                    let catalog = catalog_in(tx, s.tenant, watermark).await?;
                    let codec = CursorCodec::from_key(s.asset_cursor_key.clone());
                    let binding = q
                        .binding(&(
                            p.tenant_id(),
                            p.instance_id(),
                            p.principal_id(),
                            current.query_binding(p)?,
                            watermark,
                        ))
                        .map_err(crate::query_error)?;
                    let after = q.after(&codec, &binding).map_err(crate::query_error)?;
                    let entries = catalog.fields().map(entry).collect::<Result<Vec<_>>>()?;
                    let mut sql =
                        sqlx::QueryBuilder::new("SELECT document FROM jsonb_array_elements(");
                    sql.push_bind(serde_json::json!(entries))
                        .push("::jsonb) AS d(document) WHERE true");
                    rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column)
                        .map_err(crate::query_error)?;
                    let rows = tx
                        .with_connection(move |c| {
                            Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
                        })
                        .await?;
                    let page = q.page(rows, &codec, &binding).map_err(crate::query_error)?;
                    p.check_live()?;

                    json(&AssetEnvelope {
                        tenant_id: p.tenant_id().into(),
                        asset: Response::FieldList {
                            dictionary: rss_mdm_inventory::DICTIONARY.into(),
                            items: page.items,
                            next_cursor: page.next_cursor,
                        },
                    })
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
    pub async fn field(
        &self,
        p: &AuthorizedPrincipal,
        key: FieldKey,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, p, key, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, key, _audit) = *ctx;
                    let current = query_authority(tx, p).await?;
                    let editor = current
                        .require(p, Permission::InventoryFieldsWrite, None)
                        .is_ok();
                    if !editor {
                        current.inventory_devices(p)?;
                    }
                    let catalog = catalog_in(tx, s.tenant, i64::MAX).await?;
                    let field = catalog.definition(key).map_err(|_| Error::NotFound)?;
                    // Catalog descriptors are discoverable metadata. Sensitive conditions
                    // and values remain checked by their existing read/compile owners.
                    let value = entry(field)?;
                    p.check_live()?;

                    json(&AssetEnvelope {
                        tenant_id: p.tenant_id().into(),
                        asset: Response::FieldDescriptor { field: value },
                    })
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
}
