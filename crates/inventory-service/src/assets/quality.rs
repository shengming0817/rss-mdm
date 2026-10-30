//! One collection-quality projection for live detail and fixed-cut query pages.
use super::*;

#[derive(serde::Deserialize)]
pub(super) struct Record {
    pub scope: String,
    metadata: String,
    id: String,
    sequence: i64,
    result: String,
    delivery_pending: bool,
}
pub(super) fn decode_record(row: &Record, generation: u64) -> Result<QualityRun> {
    let coordinate: rss_observation::Scope = stored(serde_json::from_str(&row.scope))?;
    let source = stored(rss_mdm_inventory::Source::parse(
        coordinate.source().as_str(),
    ))?;
    let attempts: crate::collection::summary::Summary =
        stored(crate::collection::summary::Summary::decode(&row.metadata))?;
    stored(attempts.definition.validate_scope(&coordinate))?;
    let fields = attempts
        .fields
        .iter()
        .map(|(field, a)| QualityField {
            reason: a.reason.clone(),
            scope: attempts
                .definition
                .field_scope(*field)
                .expect("frozen field")
                .clone(),
            item_count: a.item_count,
            invalid_items: a.invalid_items,
            field: *field,
            quality: a.quality,
            status: a.status,
            received_at: a.received_at,
        })
        .collect();
    Ok(QualityRun {
        dataset: attempts.definition.dataset().into(),
        template_version: attempts.definition.version().into(),
        fingerprint: stored(attempts.definition.fingerprint())?,
        coverage: stored(attempts.definition.coverage())?,
        complete: attempts.coverage_complete(),
        source,
        channel: source.channel().ok_or(Error::Malformed)?,
        registration: stored(Uuid::parse_str(coordinate.registration().as_str()))?,
        epoch: stored(Uuid::parse_str(coordinate.epoch().as_str()))?,
        registration_generation: generation,
        run_id: stored(Uuid::parse_str(&row.id))?,
        sequence: row.sequence,
        result: crate::collection::RunResult::parse(&row.result)?,
        delivery_pending: row.delivery_pending,
        fields,
    })
}
