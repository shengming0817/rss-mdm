//! Tenant-shared presentation metadata; field values and authority remain with Inventory.
//! ref: sled src/tree.rs@v0.34.7 (compare_and_swap)
use super::*;
use serde::{Deserialize, Serialize};
use sqlx::Row;

const MAX_BYTES: usize = 16 * 1024;

/// One atomic layout; vector order is display order at both levels.
#[derive(schemars::JsonSchema, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldLayout {
    pub groups: Vec<FieldDisplayGroup>,
}

/// Stable presentation identity, independent of device Group membership.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldDisplayGroup {
    pub id: Uuid,
    pub name: String,
    pub fields: Vec<FieldKey>,
}

/// Server-derived access, rechecked at the existing transaction authorization boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldLayoutAccess {
    Edit,
    Read { scope: ReadScope },
}

impl FieldLayout {
    fn normalized(&self, catalog: &rss_mdm_inventory::Catalog) -> Result<Self> {
        let mut layout = self.clone();
        let mut ids = BTreeSet::new();
        for group in &mut layout.groups {
            group.name = group.name.trim().to_owned();
            if group.id.is_nil()
                || !ids.insert(group.id)
                || group.name.is_empty()
                || group.name.chars().count() > 40
                || group.fields.is_empty()
            {
                return Err(Error::Malformed.into());
            }
            let mut fields = BTreeSet::new();
            for field in &group.fields {
                if !field.as_str().starts_with("custom.")
                    || !fields.insert(*field)
                    || catalog.definition(*field).is_err()
                {
                    return Err(Error::Malformed.into());
                }
            }
        }
        Ok(layout)
    }

    fn project(mut self, catalog: &rss_mdm_inventory::Catalog, access: &FieldLayoutAccess) -> Self {
        for group in &mut self.groups {
            group.fields.retain(|field| {
                catalog
                    .definition(*field)
                    .is_ok_and(|definition| match access {
                        FieldLayoutAccess::Edit => true,
                        FieldLayoutAccess::Read { .. } => fields::visible(definition),
                    })
            });
        }
        if matches!(access, FieldLayoutAccess::Read { .. }) {
            self.groups.retain(|group| !group.fields.is_empty());
        }
        self
    }
}

impl AssetService {
    pub(super) async fn field_layout_read(
        &self,
        tx: &mut PgTransaction<'_>,
        access: &FieldLayoutAccess,
    ) -> Result<Response> {
        let tenant = self.tenant.to_string();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT revision,document::text FROM mdm_assets.field_layouts WHERE tenant_id=$1::uuid")
                .bind(tenant).fetch_optional(c).await
        })).await?;
        let (revision, layout) = match row {
            Some(row) => (
                row.try_get::<i64, _>("revision")? as u64,
                stored(serde_json::from_str::<FieldLayout>(
                    row.try_get("document")?,
                ))?,
            ),
            None => (0, FieldLayout::default()),
        };
        let catalog = catalog_in(tx, self.tenant, i64::MAX).await?;
        Ok(Response::FieldLayout {
            revision,
            editable: matches!(access, FieldLayoutAccess::Edit),
            groups: layout.project(&catalog, access).groups,
        })
    }

    pub(super) async fn field_layout_write(
        &self,
        tx: &mut PgTransaction<'_>,
        change: &Operation<FieldLayout>,
    ) -> Result<Response> {
        if change.expected_revision >= i64::MAX as u64
            || checked_input(serde_json::to_vec(change))?.len() > MAX_BYTES
        {
            return Err(Error::Malformed.into());
        }
        let catalog = catalog_in(tx, self.tenant, i64::MAX).await?;
        let layout = change.input.normalized(&catalog)?;
        let document = checked_input(serde_json::to_string(&layout))?;
        // PostgreSQL's jsonb text adds whitespace. Check the same representation as the
        // CHECK constraint before mutation, including for non-HTTP service consumers.
        let fits = tx
            .with_connection({
                let document = document.clone();
                move |c| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, bool>("SELECT octet_length(($1::jsonb)::text)<=$2")
                            .bind(document)
                            .bind(MAX_BYTES as i32)
                            .fetch_one(c)
                            .await
                    })
                }
            })
            .await?;
        if !fits {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let expected = change.expected_revision as i64;
        let revision = tx.with_connection(move |c| Box::pin(async move {
            if expected == 0 {
                sqlx::query_scalar::<_, i64>("INSERT INTO mdm_assets.field_layouts(tenant_id,revision,document) VALUES($1::uuid,1,$2::jsonb) ON CONFLICT DO NOTHING RETURNING revision")
                    .bind(tenant).bind(document).fetch_optional(c).await
            } else {
                sqlx::query_scalar::<_, i64>("UPDATE mdm_assets.field_layouts SET revision=revision+1,document=$3::jsonb WHERE tenant_id=$1::uuid AND revision=$2 RETURNING revision")
                    .bind(tenant).bind(expected).bind(document).fetch_optional(c).await
            }
        })).await?.ok_or(Error::Conflict)?;
        Ok(Response::FieldLayoutWritten {
            revision: revision as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn layout() -> FieldLayout {
        FieldLayout {
            groups: vec![FieldDisplayGroup {
                id: Uuid::new_v4(),
                name: "  资产管理  ".into(),
                fields: vec![
                    FieldKey::parse("custom.office_floor").unwrap(),
                    FieldKey::parse("custom.asset_tag").unwrap(),
                ],
            }],
        }
    }
    #[test]
    fn layout_normalization_preserves_order_and_allows_cross_group_references() {
        let catalog =
            rss_mdm_inventory::Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
        let mut input = layout();
        let mut second = input.groups[0].clone();
        second.id = Uuid::new_v4();
        second.name = "采购".into();
        input.groups.push(second);
        let result = input.normalized(&catalog).unwrap();
        assert_eq!(result.groups[0].name, "资产管理");
        assert_eq!(result.groups[1].id, input.groups[1].id);
        assert_eq!(result.groups[0].fields, input.groups[0].fields);
        assert!(FieldLayout::default().normalized(&catalog).is_ok());
        for bad in ["", " ", &"中".repeat(41)] {
            let mut input = layout();
            input.groups[0].name = bad.into();
            assert!(input.normalized(&catalog).is_err());
        }
        let mut input = layout();
        input.groups[0].id = Uuid::nil();
        assert!(input.normalized(&catalog).is_err());
        let mut input = layout();
        input.groups.push(input.groups[0].clone());
        assert!(input.normalized(&catalog).is_err());
        for fields in [
            vec![],
            vec![FieldKey::parse("device.model").unwrap()],
            vec![FieldKey::parse("custom.absent").unwrap()],
            vec![input.groups[0].fields[0]; 2],
        ] {
            let mut input = layout();
            input.groups[0].fields = fields;
            assert!(input.normalized(&catalog).is_err());
        }
    }
    #[test]
    fn layout_projection_keeps_management_metadata_without_reinterpreting_value_permissions() {
        let mut definitions = rss_mdm_inventory::builtin::fields();
        let key = FieldKey::parse("custom.office_floor").unwrap();
        definitions
            .iter_mut()
            .find(|f| f.key == key)
            .unwrap()
            .sensitivity = rss_mdm_inventory::Sensitivity::Sensitive;
        let catalog = rss_mdm_inventory::Catalog::new(definitions).unwrap();
        let input = layout();
        let scope = ReadScope::all();
        let reader = input
            .clone()
            .project(&catalog, &FieldLayoutAccess::Read { scope });
        assert_eq!(reader.groups[0].fields, input.groups[0].fields);
        assert_eq!(
            input
                .clone()
                .project(&catalog, &FieldLayoutAccess::Edit)
                .groups[0]
                .fields,
            input.groups[0].fields
        );
        let empty = rss_mdm_inventory::Catalog::new(vec![]).unwrap();
        assert!(
            input
                .clone()
                .project(
                    &empty,
                    &FieldLayoutAccess::Read {
                        scope: ReadScope::all()
                    }
                )
                .groups
                .is_empty()
        );
        assert!(
            input.project(&empty, &FieldLayoutAccess::Edit).groups[0]
                .fields
                .is_empty()
        );
        let response = Response::FieldLayoutWritten { revision: 1 };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({"kind":"field_layout_written","revision":1})
        );
        assert!(
            serde_json::from_value::<FieldLayout>(serde_json::json!({"groups":[],"editable":true}))
                .is_err()
        );
    }
}
