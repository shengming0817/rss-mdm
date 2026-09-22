//! One collection-quality projection for live detail and fixed-watermark query pages.
use super::*;
use sqlx::Row;

pub(super) fn decode(row: &sqlx::postgres::PgRow, generation: u64) -> Result<QualityRun> {
    let attempts: crate::collection::Attempts =
        stored(serde_json::from_str(row.try_get("attempts")?))?;
    let coordinate: rss_observation::Scope = stored(serde_json::from_str(row.try_get("scope")?))?;
    let source = stored(rss_mdm_inventory::ReportSource::parse(
        coordinate.source().as_str(),
    ))?;
    Ok(QualityRun {
        source,
        channel: source.channel(),
        registration: stored(Uuid::parse_str(coordinate.registration().as_str()))?,
        epoch: stored(Uuid::parse_str(coordinate.epoch().as_str()))?,
        registration_generation: generation,
        run_id: stored(Uuid::parse_str(row.try_get("id")?))?,
        sequence: row.try_get("sequence")?,
        result: crate::collection::RunResult::parse(row.try_get("result")?)?,
        delivery_pending: row.try_get("delivery_pending")?,
        fields: FieldKey::observed()
            .zip(attempts.fields)
            .map(|(field, a)| QualityField {
                field,
                quality: a.quality,
                status: a.status,
                received_at: a.received_at,
            })
            .collect(),
    })
}
