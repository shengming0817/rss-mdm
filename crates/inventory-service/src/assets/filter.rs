use super::*;
use rss_mdm_group_postgres::core as g;
use rss_mdm_inventory::{Catalog, FieldPath, ValueType};
pub fn scalar(value: &Scalar) -> Result<g::Scalar> {
    checked_input(value.validate())?;
    Ok(match value {
        Scalar::String(v) => g::Scalar::String(v.clone()),
        Scalar::Integer(v) => g::Scalar::Integer(*v),
        Scalar::Number(v) => g::Scalar::Number(*v),
        Scalar::Array(_) | Scalar::Object(_) => return Err(Error::Malformed.into()),
        Scalar::Boolean(v) => g::Scalar::Boolean(*v),
        Scalar::Time(v) => g::Scalar::Time(checked_input(Timepoint::try_from(*v))?),
    })
}
pub fn op(value: Operator) -> g::Op {
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
        Operator::ContainsAny => g::Op::ContainsAny,
        Operator::ContainsAll => g::Op::ContainsAll,
        Operator::IsNull => g::Op::IsNull,
        Operator::IsNotNull => g::Op::IsNotNull,
    }
}
fn kind(value: rss_mdm_inventory::Kind) -> Result<g::ScalarType> {
    Ok(match value {
        rss_mdm_inventory::Kind::String => g::ScalarType::String,
        rss_mdm_inventory::Kind::Integer => g::ScalarType::Integer,
        rss_mdm_inventory::Kind::Number => g::ScalarType::Number,
        rss_mdm_inventory::Kind::Array | rss_mdm_inventory::Kind::Object => {
            return Err(Error::Malformed.into());
        }
        rss_mdm_inventory::Kind::Boolean => g::ScalarType::Boolean,
        rss_mdm_inventory::Kind::Time => g::ScalarType::Time,
    })
}
fn criteria(
    c: &Criteria,
    catalog: &Catalog,
    fields: &mut BTreeMap<String, g::Field>,
    depth: usize,
    nodes: &mut usize,
) -> Result<g::Criteria> {
    *nodes += 1;
    if depth > g::limits::DEPTH || *nodes > g::limits::NODES {
        return Err(Error::Malformed.into());
    }
    match c {
        Criteria::And { children } => checked_input(g::Criteria::and(
            children
                .iter()
                .map(|c| criteria(c, catalog, fields, depth + 1, nodes))
                .collect::<Result<_>>()?,
        )),
        Criteria::Or { children } => checked_input(g::Criteria::or(
            children
                .iter()
                .map(|c| criteria(c, catalog, fields, depth + 1, nodes))
                .collect::<Result<_>>()?,
        )),
        Criteria::Predicate {
            field,
            op: operation,
            value,
            values,
        } => {
            let path = checked_input(catalog.path(*field))?;
            let definition = dictionary_field(*field, &path)?;
            let unit = definition.unit.clone();
            fields.insert(field.as_str().into(), definition);
            let operand = match operation {
                Operator::IsNull | Operator::IsNotNull if value.is_none() && values.is_none() => {
                    None
                }
                Operator::In | Operator::NotIn | Operator::ContainsAny | Operator::ContainsAll
                    if value.is_none() && values.is_some() =>
                {
                    let values = values.as_ref().expect("checked set");
                    if values.len() > g::limits::SET_ITEMS {
                        return Err(Error::Malformed.into());
                    }
                    Some(g::Value::Set {
                        element: kind(path.value_type.kind())?,
                        values: values.iter().map(scalar).collect::<Result<_>>()?,
                    })
                }
                Operator::IsNull
                | Operator::IsNotNull
                | Operator::In
                | Operator::NotIn
                | Operator::ContainsAny
                | Operator::ContainsAll => {
                    return Err(Error::Malformed.into());
                }
                _ if values.is_none() && value.is_some() => Some(g::Value::Scalar(scalar(
                    value.as_ref().expect("checked scalar"),
                )?)),
                _ => return Err(Error::Malformed.into()),
            };
            checked_input(g::Criteria::predicate(g::Predicate {
                field: field.as_str().into(),
                op: op(*operation),
                operand: operand.map(|value| g::Operand { value, unit }),
            }))
        }
    }
}
fn dictionary_field(key: FieldKey, path: &FieldPath<'_>) -> Result<g::Field> {
    if !path.root.searchable {
        return Err(Error::Malformed.into());
    }
    let element = kind(path.value_type.kind())?;
    let mut operations = if path.many {
        vec![g::Op::ContainsAny, g::Op::ContainsAll]
    } else {
        vec![g::Op::Eq, g::Op::Ne, g::Op::In, g::Op::NotIn]
    };
    if !path.many {
        match path.value_type {
            ValueType::String { .. } => operations.extend([g::Op::Contains, g::Op::NotContains]),
            ValueType::Integer | ValueType::Number | ValueType::Time => {
                operations.extend([g::Op::Lt, g::Op::Le, g::Op::Gt, g::Op::Ge])
            }
            _ => (),
        }
    }
    if path.root.nullable {
        operations.extend([g::Op::IsNull, g::Op::IsNotNull]);
    }
    Ok(g::Field {
        key: key.as_str().into(),
        kind: if path.many {
            g::FieldType::Set(element)
        } else {
            g::FieldType::Scalar(element)
        },
        unit: if key == path.root.key {
            path.root.unit.clone()
        } else {
            None
        },
        operations: operations.into_iter().collect(),
        nullable: path.root.nullable,
    })
}
pub fn rule(tenant: TenantId, id: Uuid, c: &Criteria, catalog: &Catalog) -> Result<g::Rule> {
    let mut fields = BTreeMap::new();
    let criteria = criteria(c, catalog, &mut fields, 1, &mut 0)?;
    checked_input(g::Rule::new(
        tenant,
        id.to_string(),
        rss_mdm_inventory::DICTIONARY,
        fields.into_values().collect(),
        criteria,
    ))
}
pub fn criteria_view(c: &g::Criteria) -> Result<Criteria> {
    fn value(v: &g::Scalar) -> Scalar {
        match v {
            g::Scalar::String(s) => Scalar::String(s.clone()),
            g::Scalar::Integer(i) => Scalar::Integer(*i),
            g::Scalar::Number(n) => Scalar::Number(*n),
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
            let field = checked_input(FieldKey::parse(&p.field))?;
            let operation = match p.op {
                g::Op::Eq => Operator::Eq,
                g::Op::Ne => Operator::Ne,
                g::Op::In => Operator::In,
                g::Op::NotIn => Operator::NotIn,
                g::Op::Lt => Operator::Lt,
                g::Op::Le => Operator::Le,
                g::Op::Gt => Operator::Gt,
                g::Op::Ge => Operator::Ge,
                g::Op::Contains => Operator::Contains,
                g::Op::NotContains => Operator::NotContains,
                g::Op::ContainsAny => Operator::ContainsAny,
                g::Op::ContainsAll => Operator::ContainsAll,
                g::Op::IsNull => Operator::IsNull,
                g::Op::IsNotNull => Operator::IsNotNull,
            };
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
pub fn page(
    tenant: TenantId,
    devices: &[DeviceView],
    catalog: &Catalog,
    rule: &g::Rule,
) -> Result<FactPage> {
    let mut objects = Vec::with_capacity(devices.len());
    for device in devices {
        let mut facts = BTreeMap::new();
        for (name, expected) in rule.view().fields {
            let key = checked_input(FieldKey::parse(name))?;
            let path = checked_input(catalog.path(key))?;
            if &dictionary_field(key, &path)? != expected {
                return Err(Error::Malformed.into());
            }
            let f = device.fields.get(&path.root.key).ok_or(Error::Malformed)?;
            let state = match &f.state {
                rss_mdm_inventory::State::Known(v) => {
                    let leaves = checked_input(path.values(v))?;
                    let value = if path.many {
                        g::Value::Set {
                            element: kind(path.value_type.kind())?,
                            values: leaves.into_iter().map(scalar).collect::<Result<_>>()?,
                        }
                    } else {
                        g::Value::Scalar(scalar(leaves.first().ok_or(Error::Malformed)?)?)
                    };
                    g::FactState::Known(value)
                }
                rss_mdm_inventory::State::Null => g::FactState::Null,
                rss_mdm_inventory::State::Missing => g::FactState::Missing,
                rss_mdm_inventory::State::Unsupported => g::FactState::Unsupported,
                rss_mdm_inventory::State::Deleted => g::FactState::Deleted,
                rss_mdm_inventory::State::Conflict => g::FactState::Conflict,
            };
            facts.insert(
                name.clone(),
                g::Fact {
                    state,
                    source: "resolved-inventory".into(),
                    snapshot_id: digest(f)?,
                    observed_at: checked_input(Timepoint::try_from(
                        f.sources
                            .iter()
                            .map(|s| s.evidence.observed_at)
                            .max()
                            .unwrap_or(0),
                    ))?,
                },
            );
        }
        objects.push(g::ObjectSnapshot {
            key: checked_input(g::ObjectKey::new(tenant, device.device.clone()))?,
            facts,
        });
    }
    Ok(FactPage {
        coverage: rule.view().fields.keys().cloned().collect(),
        objects,
    })
}

pub struct FactPage {
    pub coverage: BTreeSet<String>,
    pub objects: Vec<g::ObjectSnapshot>,
}
