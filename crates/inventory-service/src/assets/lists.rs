//! Bounded list reads pinned to the same asset watermark and source-selection rules as Group.
use super::*;
use rss_mdm_inventory::{Evidence, ValueType};
use rss_mdm_query::cursor::CursorCodec;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ListState {
    Unknown {
        reason: rss_mdm_inventory::UnknownReason,
    },
    Known {
        count: usize,
        digest: String,
    },
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
    pub cursor: String,
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
    source: Option<(rss_mdm_inventory::Source, Option<String>)>,
}
impl AssetService {
    fn list_cursor(
        &self,
        device: &str,
        field: FieldKey,
        scope: &ReadScope,
        watermark: i64,
        offset: usize,
        source: Option<(rss_mdm_inventory::Source, Option<String>)>,
    ) -> Result<String> {
        let cursor = Cursor {
            kind: "inventory-list-v1".into(),
            tenant: self.tenant.to_string(),
            device: device.into(),
            field,
            scope: digest(scope)?,
            watermark,
            offset,
            source,
        };
        Ok(checked_input(
            CursorCodec::from_key(self.asset_cursor_key.clone()).encode("inventory-list", &cursor),
        )?
        .as_str()
        .to_owned())
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
    pub(super) fn summary_view(
        &self,
        mut summary: DeviceSummary,
        catalog: &rss_mdm_inventory::Catalog,
        scope: &ReadScope,
        watermark: i64,
    ) -> Result<DeviceView> {
        for (field, resolved) in summary.arrays {
            let definition = stored(catalog.definition(field))?;
            summary.scalars.lists.insert(
                field,
                ListSummary {
                    state: metadata_state(&resolved.state),
                    sources: resolved
                        .sources
                        .iter()
                        .map(|s| {
                            Ok(ListSource {
                                state: metadata_state(&s.state),
                                evidence: s.evidence.clone(),
                                cursor: self.list_cursor(
                                    &summary.scalars.device,
                                    field,
                                    scope,
                                    watermark,
                                    0,
                                    Some((s.evidence.source, s.evidence.dataset.clone())),
                                )?,
                            })
                        })
                        .collect::<Result<_>>()?,
                    item_key: definition.item_key.clone(),
                    cursor: self.list_cursor(
                        &summary.scalars.device,
                        field,
                        scope,
                        watermark,
                        0,
                        None,
                    )?,
                },
            );
        }
        Ok(summary.scalars)
    }
    pub(super) async fn detail_metadata(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        scope: &ReadScope,
        watermark: i64,
    ) -> Result<DeviceView> {
        let reader = planning::SnapshotReader {
            tenant: self.tenant,
        };
        let ids = vec![device.to_owned()];
        let tenant = self.tenant.to_string();
        let selected = ids.clone();
        let present = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::device::read::page_at(c, tenant, watermark, None, false, selected, 1)
                        .await
                })
            })
            .await?;
        if present.is_empty() {
            return Err(Error::NotFound.into());
        }
        let read_scope = scope.clone();
        let tenant = self.tenant;
        let (catalog, summary) = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(async move {
                        let catalog = stored(
                            rss_mdm_inventory_postgres::catalog_at_in(c, tenant, watermark).await,
                        )?;
                        let mut values = reader
                            .scoped_summary_devices_on(
                                c,
                                watermark,
                                &ids,
                                &catalog,
                                &read_scope.collection_scope,
                            )
                            .await?;
                        Ok::<_, crate::transaction::Fault>((
                            catalog,
                            values.pop().ok_or(Error::NotFound)?,
                        ))
                    }
                    .await)
                })
            })
            .await??;
        self.summary_view(summary, &catalog, scope, watermark)
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
        if !(1..=1000).contains(&limit)
            || scope
                .devices
                .as_ref()
                .is_some_and(|ids| !ids.contains(device))
        {
            return Err(Error::Forbidden.into());
        }
        let (watermark, offset, source) = if let Some(token) = token {
            if token.len() > 4096 {
                return Err(Error::Malformed.into());
            }
            let c: Cursor = CursorCodec::from_key(self.asset_cursor_key.clone())
                .decode(
                    &checked_input(rss_contract::PageCursor::parse(token))?,
                    "inventory-list",
                )
                .map_err(|_| Error::Conflict)?;
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
            (c.watermark, c.offset, c.source)
        } else {
            (self.list_watermark(tx).await?, 0, None)
        };
        let tenant = self.tenant;
        let device_id = device.to_owned();
        let read_scope = scope.clone();
        let selected_source = source.clone();
        let (total, items, next) = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(async move {
                        let catalog = stored(
                            rss_mdm_inventory_postgres::catalog_at_in(c, tenant, watermark).await,
                        )?;
                        let definition = checked_input(catalog.definition(field))?;
                        if !fields::visible(definition) {
                            return Err(Error::Forbidden.into());
                        }
                        if !matches!(definition.value_type, ValueType::Array { .. }) {
                            return Err(Error::Malformed.into());
                        }
                        let catalog =
                            stored(rss_mdm_inventory::Catalog::new(vec![definition.clone()]))?;
                        let mut summary = planning::SnapshotReader { tenant }
                            .scoped_summary_devices_on(
                                c,
                                watermark,
                                &[device_id],
                                &catalog,
                                &read_scope.collection_scope,
                            )
                            .await?;
                        let view = summary.pop().ok_or(Error::NotFound)?;
                        let resolved = view.arrays.get(&field).ok_or(Error::NotFound)?;
                        let state = match selected_source {
                            None => &resolved.state,
                            Some((source, dataset)) => {
                                &resolved
                                    .sources
                                    .iter()
                                    .find(|s| {
                                        s.evidence.source == source && s.evidence.dataset == dataset
                                    })
                                    .ok_or(Error::Conflict)?
                                    .state
                            }
                        };
                        let rss_mdm_inventory::ArrayState::Known(value) = state else {
                            return Err(Error::Conflict.into());
                        };
                        if offset > value.count {
                            return Err(Error::Conflict.into());
                        }
                        let page = stored(
                            rss_mdm_inventory_postgres::arrays::page(
                                c,
                                tenant,
                                &value.version,
                                offset,
                                limit,
                                16 * 1024 * 1024,
                            )
                            .await,
                        )?;
                        Ok::<_, crate::transaction::Fault>((value.count, page.items, page.next))
                    }
                    .await)
                })
            })
            .await??;
        Ok(Response::ListItems {
            device: device.into(),
            field,
            watermark,
            total,
            items,
            next_cursor: next
                .map(|offset| self.list_cursor(device, field, scope, watermark, offset, source))
                .transpose()?,
        })
    }
}

fn metadata_state(state: &rss_mdm_inventory::ArrayState) -> ListState {
    use rss_mdm_inventory::ArrayState as S;
    match state {
        S::Known(value) => ListState::Known {
            count: value.count,
            digest: value.digest.clone(),
        },
        S::Unknown { reason } => ListState::Unknown { reason: *reason },
        S::Missing => ListState::Missing,
        S::Null => ListState::Null,
        S::Deleted => ListState::Deleted,
        S::Unsupported => ListState::Unsupported,
        S::Conflict => ListState::Conflict,
    }
}
