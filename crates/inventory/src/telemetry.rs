//! Field-catalog interpretation of protocol telemetry declarations.
use crate::{FieldDefinition, Invalid, Result, Source, ValueType};
use crate::{TelemetryKind, TimeSeriesBinding};
use rss_timeseries::{
    Definition, DefinitionSpec, DimensionRules, Id, Metric, NumberKind, Scope, Temporality,
};

fn selected<'a>(root: &'a ValueType, path: &[String]) -> Result<&'a ValueType> {
    path.iter().try_fold(root, |ty, part| {
        ty.properties()
            .find(|(name, _, required)| *name == part && *required)
            .map(|(_, ty, _)| ty)
            .ok_or(Invalid::TypeMismatch)
    })
}
fn id(s: &str) -> Result<Id> {
    Id::new(s).map_err(|_| Invalid::Value)
}
fn metric(ty: &ValueType, kind: TelemetryKind) -> Result<Metric> {
    let number = match ty {
        ValueType::Integer => Some(NumberKind::I64),
        ValueType::Number => Some(NumberKind::F64),
        _ => None,
    };
    Ok(match kind {
        TelemetryKind::Gauge => Metric::Gauge {
            number: number.ok_or(Invalid::TypeMismatch)?,
        },
        TelemetryKind::CumulativeCounter | TelemetryKind::DeltaCounter => Metric::Counter {
            number: number.ok_or(Invalid::TypeMismatch)?,
            temporality: if kind == TelemetryKind::CumulativeCounter {
                Temporality::Cumulative
            } else {
                Temporality::Delta
            },
        },
        TelemetryKind::State => match ty {
            ValueType::Boolean => Metric::Bool,
            ValueType::Enum { values } => Metric::State {
                members: values.iter().map(|v| id(v)).collect::<Result<_>>()?,
            },
            _ => return Err(Invalid::TypeMismatch),
        },
    })
}
impl FieldDefinition {
    /// Validate the binding against this exact field; no independent metric catalog exists.
    pub fn validate_time_series(&self) -> Result<()> {
        let Some(binding) = &self.time_series else {
            return Ok(());
        };
        binding.validate().map_err(|_| Invalid::Value)?;
        if !self.sources.keys().any(|s| {
            matches!(
                s,
                Source::AgentBuiltin
                    | Source::AgentNative
                    | Source::AgentScript
                    | Source::AgentOsquery
            )
        }) {
            return Err(Invalid::SourceNotAllowed);
        }
        let root = match &self.value_type {
            ValueType::Array { items, max_items } => {
                if self.item_key.is_none() || binding.max_resources > *max_items {
                    return Err(Invalid::Value);
                }
                items.as_ref()
            }
            ty => {
                if binding.max_resources != 1 {
                    return Err(Invalid::Value);
                }
                ty
            }
        };
        metric(selected(root, &binding.value_path)?, binding.kind)?;
        if let Some(path) = &binding.interval_start_path {
            if !matches!(selected(root, path)?, ValueType::Integer) {
                return Err(Invalid::TypeMismatch);
            }
        } else if self.item_key.is_some()
            && matches!(
                binding.kind,
                TelemetryKind::CumulativeCounter | TelemetryKind::DeltaCounter
            )
        {
            return Err(Invalid::Value);
        }

        for dimension in binding.dimensions.values() {
            let ty = selected(root, &dimension.path)?;
            for v in &dimension.values {
                let valid = match ty {
                    ValueType::Enum { values } => values.contains(v),
                    ValueType::Boolean => matches!(v.as_str(), "true" | "false"),
                    ValueType::Integer => v.parse::<i64>().is_ok_and(|n| n.to_string() == *v),
                    ValueType::String { max_length, .. } => {
                        v.chars().count() <= *max_length as usize
                    }
                    _ => false,
                };
                if !valid {
                    return Err(Invalid::TypeMismatch);
                }
            }
        }
        Ok(())
    }
    /// Build the RSS definition from the catalog snapshot and a trusted product scope.
    pub fn time_series_definition(&self, scope: Scope) -> Result<Definition> {
        self.validate()?;
        let binding = self.time_series.as_ref().ok_or(Invalid::Value)?;
        let root = match &self.value_type {
            ValueType::Array { items, .. } => items.as_ref(),
            ty => ty,
        };
        let keys = binding
            .dimensions
            .keys()
            .map(|k| id(k))
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        Definition::new(DefinitionSpec {
            scope,
            key: id(self.key.as_str())?,
            version: self.version,
            unit: id(self.unit.as_deref().unwrap_or("1"))?,
            metric: metric(selected(root, &binding.value_path)?, binding.kind)?,
            dimensions: DimensionRules {
                max_count: keys.len() as u16,
                allowed: keys.clone(),
                required: keys,
                max_value_bytes: 256,
                max_total_bytes: 32768,
            },
        })
        .map_err(|_| Invalid::Value)
    }
    /// New revisions may change retention policy, but never reinterpret a bound series.
    pub fn time_series_extends(&self, previous: &Self) -> bool {
        match (&self.time_series, &previous.time_series) {
            (_, None) => true,
            (Some(new), Some(old)) => {
                let TimeSeriesBinding {
                    kind,
                    value_path,
                    interval_start_path,
                    dimensions,
                    aggregations,
                    retention: _,
                    max_resources,
                } = new;
                kind == &old.kind
                    && value_path == &old.value_path
                    && interval_start_path == &old.interval_start_path
                    && dimensions.len() == old.dimensions.len()
                    && old.dimensions.iter().all(|(key, value)| {
                        dimensions.get(key).is_some_and(|new| {
                            new.path == value.path && new.values.is_superset(&value.values)
                        })
                    })
                    && aggregations.is_superset(&old.aggregations)
                    && max_resources >= &old.max_resources
            }
            (None, Some(_)) => false,
        }
    }
}
