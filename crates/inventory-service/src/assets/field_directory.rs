//! Field metadata uses the canonical bounded Catalog; values never enter this directory.
use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Query, Schema},
};
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<FieldView>("asset_fields", &["key"], 100, rss_mdm_query::MAX_PAGE_LIMIT, &[rss_mdm_query::directory::Exclusion { path: "valueType", reason: "Recursive asset value-type grammar is interpreted by the asset catalog, not arbitrary directory paths" }, rss_mdm_query::directory::Exclusion { path: "sources", reason: "Source-priority map keys contain literal dots; priorities require the source catalog semantics" }]).expect("Public directory model")
});
fn entry(definition: &rss_mdm_inventory::FieldDefinition) -> Result<FieldView> {
    Ok(FieldView {
        definition: crate::collection::wire::to_wire_field(definition)?,
        operations: definition.operations(),
    })
}

impl AssetService {
    pub async fn fields(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<AssetEnvelope<DirectoryResponse>, Error> {
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
                    let catalog = catalog_in(tx, s.tenant).await?;
                    let entries = catalog.fields().map(entry).collect::<Result<Vec<_>>>()?;
                    let codec = CursorCodec::from_key(s.asset_cursor_key.clone());
                    let binding = q
                        .binding(&(
                            p.tenant_id(),
                            p.instance_id(),
                            p.principal_id(),
                            current.query_binding(p)?,
                            &entries,
                        ))
                        .map_err(crate::query_error)?;
                    let after = q.after(&codec, &binding).map_err(crate::query_error)?;
                    let mut sql =
                        sqlx::QueryBuilder::new("SELECT document FROM jsonb_array_elements(");
                    sql.push_bind(serde_json::json!(entries))
                        .push("::jsonb) AS d(document) WHERE true");
                    rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*BINDINGS)
                        .map_err(crate::query_error)?;
                    let rows: Vec<Value> = tx
                        .with_connection(move |c| {
                            Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
                        })
                        .await?;
                    let rows = stored(
                        rows.into_iter()
                            .map(serde_json::from_value::<FieldView>)
                            .collect::<std::result::Result<Vec<_>, _>>(),
                    )?;
                    let page = q
                        .page_typed(rows, &codec, &binding)
                        .map_err(crate::query_error)?;
                    p.check_live()?;

                    Ok(AssetEnvelope {
                        tenant_id: p.tenant_id().into(),
                        asset: DirectoryResponse::FieldList {
                            dictionary: rss_mdm_inventory::DICTIONARY.into(),
                            page,
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
    ) -> std::result::Result<AssetEnvelope, Error> {
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
                    let catalog = catalog_in(tx, s.tenant).await?;
                    let field = catalog.definition(key).map_err(|_| Error::NotFound)?;
                    // Catalog descriptors are discoverable metadata. Sensitive conditions
                    // and values remain checked by their existing read/compile owners.
                    let value = entry(field)?;
                    p.check_live()?;

                    Ok(AssetEnvelope {
                        tenant_id: p.tenant_id().into(),
                        asset: Response::FieldDescriptor {
                            field: Box::new(value),
                        },
                    })
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;
    #[test]
    fn native_field_metadata_roundtrips_before_default_projection() {
        let query = SCHEMA.parse("").unwrap();
        for definition in rss_mdm_inventory::builtin::fields() {
            let row = entry(&definition).unwrap();
            let value = serde_json::to_value(&row).unwrap();
            let row: FieldView = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(&row).unwrap(), value);
            query.project_typed(row).unwrap();
        }
    }
}

pub static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &SCHEMA,
            &[rss_mdm_query_postgres::Source::json("", "document")],
        )
        .expect("Complete public model storage binding")
    });

/// The exact successful response of this directory; other Asset variants cannot be returned.
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum DirectoryResponse {
    FieldList {
        dictionary: String,
        #[serde(flatten)]
        page: rss_mdm_query::Page<rss_mdm_query::directory::Projection<super::FieldView>>,
    },
}
