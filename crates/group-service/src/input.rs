//! Fixed condition inputs shared by published calculations and request-local previews.
use super::*;
use assets::evaluation::{EvaluationProgress, EvaluationStep};
use rss_mdm_inventory_service::objects::ObjectSnapshot;

pub(crate) struct ConditionPageRequest<'a> {
    pub cut: &'a rss_mdm_inventory::AssetCut,
    pub snapshot: Option<&'a ObjectSnapshot>,
    pub condition: &'a criteria::Condition,
    pub rule: &'a rss_mdm_group::Rule,
    pub after: Option<String>,
    pub limit: usize,
    pub selected: Option<Vec<String>>,
    pub progress: Option<EvaluationProgress>,
}

pub(crate) struct ConditionPage {
    pub evaluation: EvaluationStep,
    pub count: usize,
    pub more: bool,
}

impl Groups {
    pub(crate) async fn condition_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: ConditionPageRequest<'_>,
    ) -> Result<ConditionPage> {
        let ConditionPageRequest {
            cut,
            snapshot,
            condition,
            rule,
            after,
            limit,
            selected,
            progress,
        } = request;
        let reader = self.asset_reader();
        let (catalog, devices, associated, more) = if let Some(snapshot) = snapshot {
            let objects = self.objects.clone();
            let tenant = self.tenant;
            let snapshot_id = snapshot.id;
            let inputs = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        objects
                            .page(c, tenant, snapshot_id, after, limit, selected)
                            .await
                    })
                })
                .await?;
            let ids: Vec<_> = inputs
                .iter()
                .flat_map(|o| o.members.iter().map(|m| m.device.clone()))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let catalog = assets::catalog_at_in(tx, tenant, cut).await?;
            let devices = reader.summary_devices_in(tx, cut, &ids, &catalog).await?;
            let more = inputs.len() == limit;
            (catalog, devices, Some(inputs), more)
        } else {
            let page = reader
                .asset_page_in(
                    tx,
                    cut,
                    after,
                    limit,
                    &assets::ReadScope {
                        collection_scope: rss_mdm_inventory::CollectionScope::Device,
                        subject: "group".into(),
                        authority: "internal".into(),
                        devices: selected.map(|ids| ids.into_iter().collect()),
                    },
                )
                .await?;
            (page.catalog, page.devices, None, page.next.is_some())
        };
        let count = associated.as_ref().map_or(devices.len(), Vec::len);
        let evaluation = reader
            .condition_inputs_in(
                tx,
                progress,
                assets::planning::ConditionRequest {
                    cut,
                    devices: &devices,
                    catalog: &catalog,
                    authorization: &assets::ReadScope::all(),
                    selection: condition.selection(),
                    rule,
                    associated: associated.as_deref(),
                },
            )
            .await?;
        Ok(ConditionPage {
            evaluation,
            count,
            more,
        })
    }
}
