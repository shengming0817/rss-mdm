//! Deterministic, bounded mapping from configured typed observations to RSS samples.
use crate::Error;
use rss_mdm_agent_wire::runtime::{Scalar, TelemetryReading, TelemetryUpload};
use rss_mdm_inventory::TelemetryKind;
use rss_mdm_resource::{TelemetryProfile, TelemetryProjection};
use rss_timeseries::{
    Batch, FiniteF64, Id, Interval, Number, Reading, Sample, SampleInput, Series, Stream,
    Timestamp, Value,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn id(v: impl Into<String>) -> Result<Id, Error> {
    Id::new(v).map_err(Into::into)
}
fn path<'a>(mut value: &'a Scalar, names: &[String]) -> Result<&'a Scalar, Error> {
    for name in names {
        let Scalar::Object(properties) = value else {
            return Err(Error::Invalid);
        };
        value = properties.get(name).ok_or(Error::Invalid)?;
    }
    Ok(value)
}
fn dimension(v: &Scalar) -> Result<String, Error> {
    Ok(match v {
        Scalar::String(v) => v.clone(),
        Scalar::Integer(v) => v.to_string(),
        Scalar::Boolean(v) => v.to_string(),
        _ => return Err(Error::Invalid),
    })
}
fn reading(v: &Scalar) -> Result<Reading, Error> {
    Ok(Reading::Valid(match v {
        Scalar::Integer(v) => Value::Number(Number::I64(*v)),
        Scalar::Number(v) => Value::Number(Number::F64(FiniteF64::new(v.into_inner())?)),
        Scalar::Boolean(v) => Value::Bool(*v),
        Scalar::String(v) => Value::State(id(v)?),
        _ => return Err(Error::Invalid),
    }))
}
/// Resource identity is typed and content-stable, independent of row position or display labels.
fn resource(key: &Scalar) -> Result<Id, Error> {
    if !matches!(key, Scalar::String(_) | Scalar::Integer(_)) {
        return Err(Error::Invalid);
    }
    Ok(id(format!(
        "item:{:x}",
        Sha256::digest(serde_json::to_vec(key)?)
    ))?)
}
pub(crate) fn prepare(
    profile: &TelemetryProfile,
    input: &TelemetryUpload,
    stream: Stream,
    device: &str,
    received_at: i64,
) -> Result<Option<Batch>, Error> {
    input.validate().map_err(|_| Error::Invalid)?;
    let spec = profile.spec();
    if input
        .observations
        .iter()
        .map(|point| point.values.len())
        .sum::<usize>()
        > spec.budget.points as usize
        || serde_json::to_vec(input)?.len() > spec.budget.bytes as usize
    {
        return Err(Error::Capacity);
    }
    let fields = spec
        .fields
        .iter()
        .map(|f| {
            f.validate().map_err(|_| Error::Invalid)?;
            Ok((f.key.as_str(), f))
        })
        .collect::<Result<BTreeMap<_, _>, Error>>()?;
    let mut samples = Vec::new();
    let mut resources = BTreeSet::new();
    for observation in &input.observations {
        if observation.observed_at > received_at
            || received_at.saturating_sub(observation.observed_at)
                > i64::from(spec.backfill_seconds) * 1_000_000
            || observation.values.len() != fields.len()
        {
            return Err(Error::Invalid);
        }
        for (key, value) in &observation.values {
            let field = fields.get(key.as_str()).ok_or(Error::Invalid)?;
            if let TelemetryReading::Valid { value: v, .. } = value {
                let domain_value = rss_mdm_inventory_service::collection::wire::scalar(v);
                field
                    .validate_scalar(&domain_value)
                    .map_err(|_| Error::Invalid)?;
            }
            if spec.projection == TelemetryProjection::Current && field.time_series.is_none() {
                continue;
            }
            let binding = field.time_series.as_ref().ok_or(Error::Invalid)?;
            let counter = matches!(
                binding.kind,
                TelemetryKind::CumulativeCounter | TelemetryKind::DeltaCounter
            );
            let reading_start = match value {
                TelemetryReading::Valid { interval_start, .. } => *interval_start,
                _ => None,
            };
            if reading_start.is_some() && (!counter || binding.interval_start_path.is_some()) {
                return Err(Error::Invalid);
            }
            if counter && !matches!(value, TelemetryReading::Valid { .. }) {
                continue;
            }
            let definition = field
                .time_series_definition(stream.scope().clone())
                .map_err(|_| Error::Invalid)?;
            let values: Vec<(Id, Option<&Scalar>)> = match value {
                TelemetryReading::Valid {
                    value: Scalar::Array(items),
                    ..
                } => {
                    if items.len() > binding.max_resources as usize {
                        return Err(Error::Capacity);
                    }
                    let key = field.item_key.as_ref().ok_or(Error::Invalid)?;
                    items
                        .iter()
                        .map(|item| {
                            Ok((
                                resource(path(item, std::slice::from_ref(key))?)?,
                                Some(item),
                            ))
                        })
                        .collect::<Result<_, Error>>()?
                }
                TelemetryReading::Valid { value, .. } => vec![(id("device")?, Some(value))],
                _ if field.item_key.is_some() || !binding.dimensions.is_empty() => Vec::new(),
                _ => vec![(id("device")?, None)],
            };
            let mut local_resources = BTreeSet::new();
            for (resource, scalar) in values {
                if !local_resources.insert(resource.clone()) {
                    return Err(Error::Conflict);
                }
                resources.insert((field.key, resource.clone()));
                if resources.len() > spec.budget.resources as usize {
                    return Err(Error::Capacity);
                }
                let dimensions = binding
                    .dimensions
                    .iter()
                    .map(|(name, rule)| {
                        let value = dimension(path(scalar.ok_or(Error::Invalid)?, &rule.path)?)?;
                        if !rule.values.contains(&value) {
                            return Err(Error::Invalid);
                        }
                        Ok((id(name)?, id(value)?))
                    })
                    .collect::<Result<_, Error>>()?;
                let value = match (value, scalar) {
                    (TelemetryReading::Valid { .. }, Some(scalar)) => {
                        reading(path(scalar, &binding.value_path)?)?
                    }
                    (TelemetryReading::Missing, _) => Reading::Missing,
                    (TelemetryReading::Failed, _) => Reading::Failed,
                    _ => return Err(Error::Invalid),
                };
                let observed_at = Timestamp::new(observation.observed_at)?;
                let interval = match binding.kind {
                    TelemetryKind::CumulativeCounter | TelemetryKind::DeltaCounter => {
                        Some(Interval::new(
                            Timestamp::new(
                                if let Some(start_path) = &binding.interval_start_path {
                                    match path(scalar.ok_or(Error::Invalid)?, start_path)? {
                                        Scalar::Integer(start) => *start,
                                        _ => return Err(Error::Invalid),
                                    }
                                } else {
                                    reading_start.ok_or(Error::Invalid)?
                                },
                            )?,
                            observed_at,
                        )?)
                    }
                    _ => None,
                };
                let name = serde_json::to_vec(&(field.key, &resource))?;
                let sample_id = uuid::Uuid::new_v5(&observation.id, &name);
                samples.push(Sample::new(SampleInput {
                    stream: stream.clone(),
                    series: Series::new(definition.clone(), id(device)?, resource, dimensions)?,
                    id: id(sample_id.to_string())?,
                    sequence: observation.sequence,
                    observed_at,
                    interval,
                    reading: value,
                })?);
                if samples.len() > spec.budget.points as usize {
                    return Err(Error::Capacity);
                }
            }
        }
    }
    if samples.is_empty() || spec.projection == TelemetryProjection::Current {
        return Ok(None);
    }
    Ok(Some(Batch::new(
        stream,
        id(input.batch_id.to_string())?,
        samples,
    )?))
}
