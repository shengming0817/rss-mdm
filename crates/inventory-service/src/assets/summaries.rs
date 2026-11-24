//! Display projections read immutable array metadata while scalar consumers retain their values.
use super::*;
use rss_mdm_inventory::{Catalog, CollectionScope, ResolvedArray};

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeviceSummary {
    pub personnel: BTreeMap<FieldKey, super::personnel::Fact>,
    pub scalars: DeviceView,
    pub arrays: BTreeMap<FieldKey, ResolvedArray>,
}
impl planning::SnapshotReader {
    pub(super) async fn scoped_summary_devices_on(
        &self,
        tenant: rss_request_context::TenantId,
        c: &mut sqlx::PgConnection,
        cut: &AssetCut,
        ids: &[rss_mdm_agent_wire::DeviceId],
        catalog: &Catalog,

        scope: &CollectionScope,
    ) -> Result<Vec<DeviceSummary>> {
        super::raw_snapshot::read_on(self.profile, c, tenant, cut, ids, catalog, scope).await
    }
}
