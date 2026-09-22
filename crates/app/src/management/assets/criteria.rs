use super::*;
use rss_mdm_group_postgres::core as g;
pub(super) fn scalar(value: &Scalar) -> Result<g::Scalar> {
    input(value.validate())?;
    Ok(match value {
        Scalar::String(v) => g::Scalar::String(v.clone()),
        Scalar::Integer(v) => g::Scalar::Integer(*v),
        Scalar::Boolean(v) => g::Scalar::Boolean(*v),
        Scalar::Time(v) => g::Scalar::Time(input(Timepoint::try_from(*v))?),
    })
}
pub(super) fn op(value: Operator) -> g::Op {
    match value {
        Operator::Eq => g::Op::Eq,
        Operator::Ne => g::Op::Ne,
        Operator::In => g::Op::In,
        Operator::NotIn => g::Op::NotIn,
        Operator::Lt => g::Op::Lt,
        Operator::Le => g::Op::Le,
        Operator::Gt => g::Op::Gt,
        Operator::Ge => g::Op::Ge,
        Operator::Contains => g::Op::Contains,
        Operator::NotContains => g::Op::NotContains,
        Operator::IsNull => g::Op::IsNull,
        Operator::IsNotNull => g::Op::IsNotNull,
    }
}
fn kind(value: rss_mdm_inventory::Kind) -> g::ScalarType {
    match value {
        rss_mdm_inventory::Kind::String => g::ScalarType::String,
        rss_mdm_inventory::Kind::Integer => g::ScalarType::Integer,
        rss_mdm_inventory::Kind::Boolean => g::ScalarType::Boolean,
        rss_mdm_inventory::Kind::Time => g::ScalarType::Time,
    }
}
fn criteria(c: &Criteria, depth: usize, nodes: &mut usize) -> Result<g::Criteria> {
    *nodes += 1;
    if depth > g::limits::DEPTH || *nodes > g::limits::NODES {
        return Err(Error::Malformed.into());
    }
    match c {
        Criteria::And { children } => input(g::Criteria::and(
            children
                .iter()
                .map(|c| criteria(c, depth + 1, nodes))
                .collect::<Result<_>>()?,
        )),
        Criteria::Or { children } => input(g::Criteria::or(
            children
                .iter()
                .map(|c| criteria(c, depth + 1, nodes))
                .collect::<Result<_>>()?,
        )),
        Criteria::Predicate {
            field,
            op: operation,
            value,
            values,
        } => {
            let operand = match operation {
                Operator::IsNull | Operator::IsNotNull if value.is_none() && values.is_none() => {
                    None
                }
                Operator::In | Operator::NotIn if value.is_none() && values.is_some() => {
                    let values = values.as_ref().expect("checked set");
                    if values.len() > g::limits::SET_ITEMS {
                        return Err(Error::Malformed.into());
                    }
                    Some(g::Value::Set {
                        element: kind(field.definition().kind),
                        values: values.iter().map(scalar).collect::<Result<_>>()?,
                    })
                }
                Operator::IsNull | Operator::IsNotNull | Operator::In | Operator::NotIn => {
                    return Err(Error::Malformed.into());
                }
                _ if values.is_none() && value.is_some() => Some(g::Value::Scalar(scalar(
                    value.as_ref().expect("checked scalar"),
                )?)),
                _ => return Err(Error::Malformed.into()),
            };
            input(g::Criteria::predicate(g::Predicate {
                field: field.as_str().into(),
                op: op(*operation),
                operand: operand.map(|value| g::Operand { value, unit: None }),
            }))
        }
    }
}
pub(in crate::management) fn rule(tenant: TenantId, id: Uuid, c: &Criteria) -> Result<g::Rule> {
    input(g::Rule::new(
        tenant,
        id.to_string(),
        rss_mdm_inventory::DICTIONARY,
        FieldKey::ALL
            .into_iter()
            .map(|key| {
                let f = key.definition();
                g::Field {
                    key: key.as_str().into(),
                    kind: g::FieldType::Scalar(kind(f.kind)),
                    unit: None,
                    operations: f.operations.into_iter().map(op).collect(),
                    nullable: f.nullable,
                }
            })
            .collect(),
        criteria(c, 1, &mut 0)?,
    ))
}
pub(in crate::management) fn criteria_view(c: &g::Criteria) -> Result<Criteria> {
    fn value(v: &g::Scalar) -> Scalar {
        match v {
            g::Scalar::String(s) => Scalar::String(s.clone()),
            g::Scalar::Integer(i) => Scalar::Integer(*i),
            g::Scalar::Boolean(b) => Scalar::Boolean(*b),
            g::Scalar::Time(t) => Scalar::Time(t.unix_seconds()),
        }
    }
    Ok(match c.view() {
        g::CriteriaView::And(cs) => Criteria::And {
            children: cs.iter().map(criteria_view).collect::<Result<_>>()?,
        },
        g::CriteriaView::Or(cs) => Criteria::Or {
            children: cs.iter().map(criteria_view).collect::<Result<_>>()?,
        },
        g::CriteriaView::Predicate(p) => {
            let field = input(FieldKey::parse(&p.field))?;
            let operation = field
                .definition()
                .operations
                .into_iter()
                .find(|o| op(*o) == p.op)
                .ok_or(Error::Malformed)?;
            let (v, vs) = match p.operand.as_ref().map(|o| &o.value) {
                None => (None, None),
                Some(g::Value::Scalar(v)) => (Some(value(v)), None),
                Some(g::Value::Set { values, .. }) => {
                    (None, Some(values.iter().map(value).collect()))
                }
            };
            Criteria::Predicate {
                field,
                op: operation,
                value: v,
                values: vs,
            }
        }
    })
}
pub(in crate::management) fn snapshot(
    tenant: TenantId,
    devices: &[DeviceView],
) -> Result<g::Snapshot> {
    let version = digest(devices)?;
    let objects = devices
        .iter()
        .map(|device| {
            let facts = device
                .fields
                .iter()
                .map(|(key, f)| {
                    let state = match &f.state {
                        rss_mdm_inventory::State::Known(v) => {
                            g::FactState::Known(g::Value::Scalar(scalar(v)?))
                        }
                        rss_mdm_inventory::State::Null => g::FactState::Null,
                        rss_mdm_inventory::State::Missing => g::FactState::Missing,
                        rss_mdm_inventory::State::Unsupported => g::FactState::Unsupported,
                        rss_mdm_inventory::State::Deleted => g::FactState::Deleted,
                        rss_mdm_inventory::State::Conflict => g::FactState::Conflict,
                    };
                    Ok((
                        key.as_str().into(),
                        g::Fact {
                            state,
                            source: "resolved-inventory".into(),
                            snapshot_id: digest(f)?,
                            observed_at: input(Timepoint::try_from(
                                f.sources
                                    .iter()
                                    .map(|s| s.evidence.observed_at)
                                    .max()
                                    .unwrap_or(0),
                            ))?,
                        },
                    ))
                })
                .collect::<Result<_>>()?;
            Ok(g::ObjectSnapshot {
                key: input(g::ObjectKey::new(tenant, device.device.clone()))?,
                facts,
            })
        })
        .collect::<Result<_>>()?;
    Ok(g::Snapshot {
        tenant,
        id: "assets".into(),
        version,
        dictionary_version: rss_mdm_inventory::DICTIONARY.into(),
        complete: true,
        coverage: FieldKey::ALL
            .into_iter()
            .map(|k| k.as_str().into())
            .collect(),
        objects,
    })
}
