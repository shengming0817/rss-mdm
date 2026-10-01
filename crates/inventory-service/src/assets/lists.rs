//! Bounded list reads pinned to the same asset watermark and source-selection rules as Group.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_inventory::{Evidence, Scalar, State, ValueType};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ListState {
    Known { count: usize, digest: String },
    Missing,
    Null,
    Deleted,
    Unsupported,
    Conflict,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListSource {
    pub state: ListState,
    pub evidence: Evidence,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListSummary {
    pub state: ListState,
    pub sources: Vec<ListSource>,
    pub item_key: Option<String>,
    pub cursor: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    kind: String,
    tenant: String,
    device: String,
    field: FieldKey,
    scope: String,
    watermark: i64,
    offset: usize,
}
fn state(value: &State) -> Result<ListState> {
    Ok(match value {
        State::Known(Scalar::Array(values)) => ListState::Known {
            count: values.len(),
            digest: digest(values)?,
        },
        State::Missing => ListState::Missing,
        State::Null => ListState::Null,
        State::Deleted => ListState::Deleted,
        State::Unsupported => ListState::Unsupported,
        State::Conflict => ListState::Conflict,
        _ => return Err(Error::Unavailable(Failure::AssetsStorage).into()),
    })
}
impl AssetService {
    fn list_cursor(
        &self,
        device: &str,
        field: FieldKey,
        scope: &ReadScope,
        watermark: i64,
        offset: usize,
    ) -> Result<String> {
        let cursor = Cursor {
            kind: "inventory-list-v1".into(),
            tenant: self.tenant.to_string(),
            device: device.into(),
            field,
            scope: digest(scope)?,
            watermark,
            offset,
        };
        let mut bytes = checked_input(serde_json::to_vec(&cursor))?;
        bytes.extend(ring::hmac::sign(&self.asset_cursor_key, &bytes).as_ref());
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
    pub(super) async fn list_watermark(&self, tx: &mut PgTransaction<'_>) -> Result<i64> {
        let tenant = self.tenant;
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, tenant)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset watermark unavailable".into()))
                })
            })
            .await?)
    }
    pub(super) fn summarize_lists(
        &self,
        view: &mut DeviceView,
        catalog: &rss_mdm_inventory::Catalog,
        scope: &ReadScope,
        watermark: i64,
    ) -> Result<()> {
        let keys: Vec<_> = view
            .fields
            .keys()
            .filter(|key| {
                catalog
                    .definition(**key)
                    .is_ok_and(|f| matches!(f.value_type, ValueType::Array { .. }))
            })
            .copied()
            .collect();
        for key in keys {
            let field = view.fields.remove(&key).expect("selected key");
            let definition = stored(catalog.definition(key))?;
            view.lists.insert(
                key,
                ListSummary {
                    state: state(&field.state)?,
                    sources: field
                        .sources
                        .iter()
                        .map(|s| {
                            Ok(ListSource {
                                state: state(&s.state)?,
                                evidence: s.evidence.clone(),
                            })
                        })
                        .collect::<Result<_>>()?,
                    item_key: definition.item_key.clone(),
                    cursor: self.list_cursor(&view.device, key, scope, watermark, 0)?,
                },
            );
        }
        Ok(())
    }
    pub(super) async fn list_items(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        field: FieldKey,
        scope: &ReadScope,
        limit: usize,
        token: Option<&str>,
    ) -> Result<Response> {
        if !(1..=100).contains(&limit)
            || scope
                .devices
                .as_ref()
                .is_some_and(|ids| !ids.contains(device))
        {
            return Err(Error::Forbidden.into());
        }
        let (watermark, offset) = if let Some(token) = token {
            if token.len() > 4096 {
                return Err(Error::Malformed.into());
            }
            let bytes = checked_input(URL_SAFE_NO_PAD.decode(token))?;
            if bytes.len() <= 32 {
                return Err(Error::Malformed.into());
            }
            let (payload, signature) = bytes.split_at(bytes.len() - 32);
            ring::hmac::verify(&self.asset_cursor_key, payload, signature)
                .map_err(|_| Error::Conflict)?;
            let c: Cursor = checked_input(serde_json::from_slice(payload))?;
            if c.kind != "inventory-list-v1"
                || c.tenant != self.tenant.to_string()
                || c.device != device
                || c.field != field
                || c.scope != digest(scope)?
                || c.watermark < 0
                || c.offset > 100000
            {
                return Err(Error::Conflict.into());
            }
            (c.watermark, c.offset)
        } else {
            (self.list_watermark(tx).await?, 0)
        };
        let restricted = ReadScope {
            subject: scope.subject.clone(),
            sensitive: scope.sensitive,
            devices: Some([device.to_owned()].into()),
        };
        let page = planning::SnapshotReader {
            tenant: self.tenant,
        }
        .asset_page_in(tx, watermark, None, 1, &restricted)
        .await?;
        let view = page.devices.first().ok_or(Error::NotFound)?;
        let definition = checked_input(page.catalog.definition(field))?;
        if definition.sensitivity == rss_mdm_inventory::Sensitivity::Sensitive && !scope.sensitive {
            return Err(Error::Forbidden.into());
        }
        let resolved = view.fields.get(&field).ok_or(Error::NotFound)?;
        let State::Known(Scalar::Array(values)) = &resolved.state else {
            return Err(Error::Conflict.into());
        };
        if offset > values.len() {
            return Err(Error::Conflict.into());
        }
        let mut items = Vec::new();
        let mut bytes = 0;
        for value in values.iter().skip(offset).take(limit) {
            let size = stored(serde_json::to_vec(value))?.len();
            if bytes + size > 16 * 1024 * 1024 {
                if items.is_empty() {
                    return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
                }
                break;
            }
            bytes += size;
            items.push(value.clone());
        }
        let next = offset + items.len();
        Ok(Response::ListItems {
            device: device.into(),
            field,
            watermark,
            total: values.len(),
            items,
            next_cursor: if next < values.len() {
                Some(self.list_cursor(device, field, scope, watermark, next)?)
            } else {
                None
            },
        })
    }
}
