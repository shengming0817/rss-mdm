//! Current asset projection preserves the existing Observation/Inventory ownership.
use crate::{Error, admission::Accepted};
use rss_mdm_agent_wire::runtime::TelemetryReading;
use rss_mdm_inventory::{CollectedValue, CollectionDefinition, CollectionField, CollectionScope};
use rss_observation::{Batch, Body, Change, Id};
use rss_request_context::TenantId;
use sqlx::PgConnection;
/// Preflight the actual destination encoding before durable reception.
pub(crate) fn prepare(input: &Accepted) -> Result<(CollectionDefinition, Vec<Batch>), Error> {
    let definition = CollectionDefinition::new(
        &format!("telemetry.{}", input.input.policy),
        input.input.policy_version.to_string(),
        input.source,
        input
            .profile
            .spec()
            .fields
            .iter()
            .map(|f| {
                Ok(CollectionField {
                    definition: f.clone(),
                    scope: CollectionScope::Device,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?,
    )
    .map_err(|_| Error::Invalid)?;
    let mut batches = Vec::new();
    for point in &input.input.observations {
        let mut changes = Vec::new();
        for (key, value) in &point.values {
            if let TelemetryReading::Valid { value, .. } = value {
                let field = definition
                    .fields()
                    .find(|f| f.key.as_str() == key.as_str())
                    .ok_or(Error::Invalid)?;
                let value = CollectedValue::Value(
                    rss_mdm_inventory_service::collection::wire::scalar(value),
                );
                changes.push(Change::upsert(
                    Id::new(key.as_str()).map_err(|_| Error::Invalid)?,
                    value.encode(field).map_err(|_| Error::Invalid)?,
                ));
            }
        }
        let body = if changes.len() == point.values.len() {
            Body::Snapshot(changes)
        } else if changes.is_empty() {
            Body::Failed {
                code: Id::new("collection_failed").map_err(|_| Error::Invalid)?,
            }
        } else {
            Body::Partial(changes)
        };
        // The current asset owner uses seconds; ordering still preserves the original sequence.
        let batch = Batch::new(
            Id::new(point.id.to_string()).map_err(|_| Error::Invalid)?,
            point.sequence,
            rss_contract::Timepoint::try_from(point.observed_at / 1_000_000)
                .map_err(|_| Error::Invalid)?,
            definition.coverage().map_err(|_| Error::Invalid)?,
            body,
        )
        .map_err(|_| Error::Invalid)?;
        batches.push(batch);
    }
    Ok((definition, batches))
}
pub(crate) async fn deliver_on(
    c: &mut PgConnection,
    tenant: TenantId,
    input: &Accepted,
) -> Result<(), Error> {
    let (definition, batches) = prepare(input)?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        tenant,
        input.registration,
        input.source.as_str(),
        input.epoch,
        definition.dataset(),
    )
    .map_err(|_| Error::Invalid)?;
    for batch in batches {
        rss_mdm_inventory_service::collection::telemetry::accept_on(
            c,
            &scope,
            &definition,
            &batch,
            input.received_at / 1_000_000,
        )
        .await
        .map_err(|_| Error::Storage)?;
    }
    Ok(())
}
