//! Display projections read immutable array metadata while scalar consumers retain their values.
use super::*;
use rss_mdm_inventory::{Catalog, CollectionScope, ResolvedArray};

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeviceSummary {
    pub scalars: DeviceView,
    pub arrays: BTreeMap<FieldKey, ResolvedArray>,
}
impl planning::SnapshotReader {
    pub async fn summary_devices_on(
        &self,
        c: &mut sqlx::PgConnection,
        cut: &AssetCut,
        ids: &[String],
        catalog: &Catalog,
    ) -> Result<Vec<DeviceSummary>> {
        self.scoped_summary_devices_on(c, cut, ids, catalog, &CollectionScope::Device)
            .await
    }
    pub async fn scoped_summary_devices_on(
        &self,
        c: &mut sqlx::PgConnection,
        cut: &AssetCut,
        ids: &[String],
        catalog: &Catalog,

        scope: &CollectionScope,
    ) -> Result<Vec<DeviceSummary>> {
        super::raw_snapshot::read_on(c, self.tenant, cut, ids, catalog, scope).await
    }
}
