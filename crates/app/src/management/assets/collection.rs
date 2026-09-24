use crate::authorization::context::InventoryRead;
use crate::{Error, device::DeviceService};
use rss_mdm_inventory::ReportSource;
use serde::Serialize;
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TimeBasis {
    ServerReceived,
}
#[derive(Serialize)]
struct RunSummary {
    run_id: uuid::Uuid,
    sequence: u64,
    result: crate::collection::RunResult,
    reason: Option<crate::collection::FinishReason>,
    started_at: i64,
    finished_at: Option<i64>,
    time_basis: TimeBasis,
}
#[derive(Serialize)]
struct RunField {
    field: &'static str,
    quality: crate::collection::Quality,
    status: Option<u16>,
    received_at: Option<i64>,
    time_basis: TimeBasis,
}
#[derive(Serialize)]
pub(crate) struct CollectionResponse {
    run: RunSummary,
    registration: String,
    source: ReportSource,
    epoch: String,
    coverage: rss_observation::Coverage,
    fields: Vec<RunField>,
    delivery: crate::inventory_runtime::DeliveryStatus,
}

pub(crate) struct CollectionService {
    devices: std::sync::Arc<DeviceService>,
    access: std::sync::Arc<crate::Database>,
    runtime: std::sync::Arc<crate::inventory_runtime::InventoryRuntime>,
}
impl CollectionService {
    pub(crate) fn new(
        devices: std::sync::Arc<DeviceService>,
        access: std::sync::Arc<crate::Database>,
        runtime: std::sync::Arc<crate::inventory_runtime::InventoryRuntime>,
    ) -> Self {
        Self {
            devices,
            access,
            runtime,
        }
    }
    pub(crate) async fn run(
        &self,
        grant: InventoryRead<'_>,
        id: uuid::Uuid,
    ) -> Result<CollectionResponse, Error> {
        let scope = self
            .devices
            .current_scope(grant.proof, &grant.device, grant.coordinates)
            .await?;
        let run = crate::collection::store::collection(&self.access, &scope, Some(id))
            .await?
            .ok_or(Error::NotFound)?;
        let fields = rss_mdm_inventory::FieldKey::observed()
            .zip(&run.attempts.fields)
            .map(|(key, attempt)| RunField {
                field: key.as_str(),
                quality: attempt.quality,
                status: attempt.status,
                received_at: attempt.received_at,
                time_basis: TimeBasis::ServerReceived,
            })
            .collect();
        grant.proof.inventory(&grant.device, grant.coordinates)?;
        Ok(CollectionResponse {
            run: run_summary(&run),
            registration: scope.registration().as_str().to_owned(),
            source: grant.coordinates.source,
            epoch: scope.epoch().as_str().to_owned(),
            coverage: rss_mdm_inventory::coverage(),
            fields,
            delivery: self.runtime.inspect(&run).await?,
        })
    }
    pub(crate) async fn inspect_agent(
        &self,
        report: &crate::collection::DurableReport,
    ) -> Result<crate::inventory_runtime::DeliveryStatus, Error> {
        self.runtime
            .inspect_report(report.scope(), report.batch())
            .await
    }
}
fn run_summary(run: &crate::collection::Run) -> RunSummary {
    RunSummary {
        run_id: run.id,
        sequence: run.sequence,
        result: run.result,
        reason: run.reason,
        started_at: run.started_at,
        finished_at: run.sealed_at,
        time_basis: TimeBasis::ServerReceived,
    }
}
