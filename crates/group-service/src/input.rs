//! Fixed condition inputs shared by published calculations and request-local previews.
use super::*;
use assets::evaluation::{EvaluationProgress, EvaluationStep};
use rss_mdm_inventory_service::objects::ObjectSnapshot;

pub(crate) struct ConditionPageRequest<'a> {
    pub cut: &'a rss_mdm_inventory::AssetCut,
    pub snapshot: Option<&'a ObjectSnapshot>,
    pub condition: &'a criteria::Condition,
    pub rule: &'a rss_mdm_group::Rule,
    pub after: Option<rss_mdm_agent_wire::ObjectRef>,
    pub limit: usize,
    pub selected: Option<Vec<rss_mdm_agent_wire::ObjectRef>>,
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
                .flat_map(|o| o.members.iter().map(|m| m.device))
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
                    after.map(endpoint).transpose()?,
                    limit,
                    &assets::ReadScope {
                        collection_scope: rss_mdm_inventory::CollectionScope::Device,
                        subject: "group".into(),
                        authority: "internal".into(),
                        devices: selected
                            .map(|ids| ids.into_iter().map(endpoint).collect::<Result<_>>())
                            .transpose()?,
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

impl Groups {
    /// Record a demand which was merged into an already frozen calculation.
    pub(crate) async fn request_followup_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: Uuid,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_group.groups SET input_revision=input_revision+1,input_epoch=(SELECT id FROM mdm.asset_epochs WHERE active),input_xid=pg_current_xact_id() WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted")
                .bind(tenant).bind(group).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    /// Cover only demands visible in the very same snapshot as the frozen AssetCut.
    /// A newer request conservatively leaves coverage at zero; no numeric event frontier is inferred.
    pub(crate) async fn covered_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: Uuid,
        cut: &rss_mdm_inventory::AssetCut,
    ) -> Result<i64> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let cut = cut.to_json();
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT CASE WHEN input_revision=0 OR mdm.asset_cut_contains($3,input_epoch,input_xid) THEN input_revision ELSE 0 END FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(group).bind(cut).fetch_one(c).await
        })).await?)
    }
    pub(crate) async fn inputs_uncovered_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: Uuid,
        covered: i64,
    ) -> Result<bool> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT input_revision>$3 FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted")
                .bind(tenant).bind(group).bind(covered).fetch_optional(c).await
        })).await?.unwrap_or(false))
    }
}

/// Endpoint-only catalog inputs reject associations instead of dropping the kind.
pub(crate) fn endpoint(
    object: rss_mdm_agent_wire::ObjectRef,
) -> Result<rss_mdm_agent_wire::DeviceId> {
    match object {
        rss_mdm_agent_wire::ObjectRef::Endpoint(id) => Ok(id),
        rss_mdm_agent_wire::ObjectRef::Association(_) => Err(Error::Conflict.into()),
    }
}
