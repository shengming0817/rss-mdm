//! Rule-bound projection and resumable integrity evidence, never an array value cache.
use super::*;
use rss_mdm_group_postgres::core as g;
use rss_mdm_inventory::{ArrayState, ArrayValue, Catalog, Scalar};
use rss_mdm_inventory_postgres::arrays::{self, ArrayScanState};
use serde::{Deserialize, Serialize};

/// Task-owned, frozen-object evaluation identity and per-version progress.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationProgress {
    pub binding: String,
    pub arrays: BTreeMap<String, ArrayProgress>,
}
/// One version's validation state and rule-relevant leaves, not the original items.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrayProgress {
    pub scan: ArrayScanState,
    pub hits: BTreeMap<FieldKey, BTreeSet<Scalar>>,
}
pub(super) type Operands = BTreeMap<FieldKey, BTreeSet<Scalar>>;
pub(super) fn operands(rule: &g::Rule) -> Result<Operands> {
    fn convert(v: &g::Scalar) -> Scalar {
        match v {
            g::Scalar::String(v) => Scalar::String(v.clone()),
            g::Scalar::Integer(v) => Scalar::Integer(*v),
            g::Scalar::Boolean(v) => Scalar::Boolean(*v),
            g::Scalar::Number(v) => Scalar::Number(*v),
            g::Scalar::Time(v) => Scalar::Time(v.unix_seconds()),
        }
    }
    fn visit(node: &g::Criteria, out: &mut Operands) -> Result<()> {
        match node.view() {
            g::CriteriaView::Predicate(p) => {
                if matches!(p.op, g::Op::ContainsAny | g::Op::ContainsAll) {
                    let key = checked_input(FieldKey::parse(&p.field))?;
                    let Some(g::Operand {
                        value: g::Value::Set { values, .. },
                        ..
                    }) = &p.operand
                    else {
                        return Err(Error::Malformed.into());
                    };
                    out.entry(key)
                        .or_default()
                        .extend(values.iter().map(convert));
                }
            }
            g::CriteriaView::And(children) | g::CriteriaView::Or(children) => {
                for c in children {
                    visit(c, out)?;
                }
            }
            g::CriteriaView::Membership { .. } => (),
        }
        Ok(())
    }
    let mut out = Operands::new();
    visit(rule.view().criteria, &mut out)?;
    Ok(out)
}
pub(super) fn versions(
    devices: &[DeviceSummary],
    catalog: &Catalog,
    rule: &g::Rule,
) -> Result<BTreeMap<String, ArrayValue>> {
    let roots: BTreeSet<_> = rule
        .view()
        .fields
        .keys()
        .map(|name| {
            Ok::<_, crate::transaction::Fault>(
                checked_input(catalog.path(checked_input(FieldKey::parse(name))?))?
                    .root
                    .key,
            )
        })
        .collect::<Result<_>>()?;
    let mut versions = BTreeMap::new();
    for device in devices {
        for (key, field) in &device.arrays {
            if !roots.contains(key) {
                continue;
            }
            let mut add = |value: &ArrayValue| {
                versions.insert(value.version.clone(), value.clone());
            };
            if let ArrayState::Known(value) = &field.state {
                add(value);
            }
            for source in &field.sources {
                if let ArrayState::Known(value) = &source.state {
                    add(value);
                }
                if let Some(old) = &source.last_known {
                    add(&old.value);
                }
            }
        }
    }
    Ok(versions)
}
/// Advance at most one payload chunk, preserving all per-field validation across retries.
pub(super) async fn advance_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    expected: &BTreeMap<String, ArrayValue>,
    catalog: &Catalog,
    operands: &Operands,
    progress: &mut EvaluationProgress,
) -> Result<bool> {
    if progress
        .arrays
        .keys()
        .any(|key| !expected.contains_key(key))
    {
        return Err(Error::Conflict.into());
    }
    for (version, value) in expected {
        if !progress.arrays.contains_key(version) {
            let scan = stored(arrays::start_scan(c, tenant, version).await)?;
            progress.arrays.insert(
                version.clone(),
                ArrayProgress {
                    scan,
                    hits: BTreeMap::new(),
                },
            );
        }
        let entry = progress.arrays.get_mut(version).expect("inserted scan");
        let m = entry.scan.metadata();
        if m.version != value.version
            || m.count != value.count
            || m.bytes != value.bytes
            || m.digest != value.digest
        {
            return Err(Error::Conflict.into());
        }
        if entry.scan.verified() {
            continue;
        }
        let chunk = stored(arrays::advance_scan(c, tenant, entry.scan.clone()).await)?;
        let field = chunk.state.metadata().field;
        let current = stored(catalog.definition(field))?;
        for item in &chunk.items {
            stored(current.validate_item(item))?;
        }
        for (key, wanted) in operands {
            let path = checked_input(catalog.path(*key))?;
            if path.root.key != field {
                continue;
            }
            let hits = entry.hits.entry(*key).or_default();
            for item in &chunk.items {
                for leaf in checked_input(path.item_values(item))? {
                    if wanted.contains(leaf) {
                        hits.insert(leaf.clone());
                    }
                }
            }
        }
        entry.scan = chunk.state;
        return Ok(expected
            .keys()
            .all(|v| progress.arrays.get(v).is_some_and(|p| p.scan.verified())));
    }
    Ok(true)
}
pub(super) fn array_state(
    state: &ArrayState,
    key: FieldKey,
    kind: g::ScalarType,
    progress: &EvaluationProgress,
) -> Result<g::FactState> {
    Ok(match state {
        ArrayState::Known(value) => {
            let entry = progress
                .arrays
                .get(&value.version)
                .filter(|p| p.scan.verified())
                .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
            let values = entry
                .hits
                .get(&key)
                .into_iter()
                .flatten()
                .map(filter::scalar)
                .collect::<Result<_>>()?;
            g::FactState::Known(g::Value::Set {
                element: kind,
                values,
            })
        }
        ArrayState::Null => g::FactState::Null,
        ArrayState::Unknown { .. } | ArrayState::Missing => g::FactState::Missing,
        ArrayState::Deleted => g::FactState::Deleted,
        ArrayState::Unsupported => g::FactState::Unsupported,
        ArrayState::Conflict => g::FactState::Conflict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn condition(op: Operator, values: &[&str]) -> Criteria {
        Criteria::Predicate {
            field: FieldKey::parse("custom.stream").unwrap(),
            op,
            value: None,
            values: Some(values.iter().map(|s| Scalar::String((*s).into())).collect()),
        }
    }
    #[test]
    fn rule_projection_preserves_all_leaf_explanations_and_empty_sets() {
        let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let mut definition = rss_mdm_inventory::builtin::fields()
            .into_iter()
            .find(|f| f.key == rss_mdm_inventory::builtin::OFFICE_FLOOR)
            .unwrap();
        definition.key = FieldKey::parse("custom.stream").unwrap();
        definition.value_type = rss_mdm_inventory::ValueType::Array {
            items: Box::new(rss_mdm_inventory::ValueType::String {
                max_length: 64,
                allow_empty: true,
            }),
            max_items: 100,
        };
        let catalog = Catalog::new(vec![definition]).unwrap();
        let criteria = Criteria::And {
            children: vec![
                condition(Operator::ContainsAll, &["a", "b"]),
                Criteria::Or {
                    children: vec![
                        condition(Operator::ContainsAny, &["c"]),
                        condition(Operator::ContainsAll, &[]),
                    ],
                },
                condition(Operator::ContainsAny, &[]),
            ],
        };
        let rule = filter::rule(tenant, Uuid::nil(), &criteria, &catalog).unwrap();
        let wanted = operands(&rule).unwrap();
        let key = FieldKey::parse("custom.stream").unwrap();
        let coverage = [key.as_str().to_owned()].into();
        for raw in [
            vec![],
            vec!["outside"],
            vec!["a", "a", "outside"],
            vec!["a", "b", "c", "outside"],
        ] {
            let all: BTreeSet<_> = raw.iter().map(|s| Scalar::String((*s).into())).collect();
            let selected: BTreeSet<_> = all.intersection(&wanted[&key]).cloned().collect();
            let evaluate = |values: &BTreeSet<Scalar>| {
                let fact = g::Fact {
                    state: g::FactState::Known(g::Value::Set {
                        element: g::ScalarType::String,
                        values: values
                            .iter()
                            .map(filter::scalar)
                            .collect::<Result<_>>()
                            .unwrap(),
                    }),
                    source: "source".into(),
                    snapshot_id: "full-source-manifest".into(),
                    observed_at: Timepoint::try_from(1).unwrap(),
                };
                let objects = [g::ObjectSnapshot::single(
                    g::ObjectKey::new(tenant, "device").unwrap(),
                    [(key.as_str().into(), fact)].into(),
                )];
                rule.evaluate_page(
                    &g::PageInput {
                        tenant,
                        id: "input",
                        version: "frozen",
                        dictionary_version: rss_mdm_inventory::DICTIONARY,
                        coverage: &coverage,
                        objects: &objects,
                        after: None,
                    },
                    Timepoint::try_from(2).unwrap(),
                )
                .unwrap()
            };
            assert_eq!(evaluate(&all), evaluate(&selected));
            assert_eq!(
                evaluate(&selected).objects[0].contexts["default"]
                    .explanations
                    .len(),
                4
            );
        }
    }
    #[test]
    fn field_evidence_changes_when_only_last_known_content_changes() {
        use rss_mdm_inventory::{
            ArrayFact, ArrayKnownValue, CollectionScope, Evidence, ResolvedArray, Source,
        };
        let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let mut definition = rss_mdm_inventory::builtin::fields()
            .into_iter()
            .find(|f| f.key == rss_mdm_inventory::builtin::OFFICE_FLOOR)
            .unwrap();
        definition.key = FieldKey::parse("custom.stream").unwrap();
        definition.value_type = rss_mdm_inventory::ValueType::Array {
            items: Box::new(rss_mdm_inventory::ValueType::String {
                max_length: 64,
                allow_empty: true,
            }),
            max_items: 100,
        };
        let key = definition.key;
        let catalog = Catalog::new(vec![definition]).unwrap();
        let rule = filter::rule(
            tenant,
            Uuid::nil(),
            &condition(Operator::ContainsAny, &["wanted"]),
            &catalog,
        )
        .unwrap();
        let value = ArrayValue {
            version: "a".repeat(64),
            digest: "b".repeat(64),
            bytes: 100,
            count: 2,
        };
        let evidence = Evidence {
            scope: CollectionScope::Device,
            source: Source::Manual,
            dataset: None,
            registration: None,
            registration_generation: None,
            epoch: None,
            snapshot_id: "source".into(),
            observed_at: 1,
            received_at: 1,
            actor: Some("actor".into()),
        };
        let mut device = DeviceSummary {
            scalars: DeviceView {
                collection_scope: CollectionScope::Device,
                device: "device".into(),
                channels: BTreeSet::new(),
                fields: BTreeMap::new(),
                lists: BTreeMap::new(),
                quality: vec![],
                revisions: BTreeMap::new(),
            },
            arrays: [(
                key,
                ResolvedArray {
                    field: key,
                    state: ArrayState::Deleted,
                    sources: vec![ArrayFact {
                        state: ArrayState::Deleted,
                        last_known: Some(ArrayKnownValue {
                            value,
                            evidence: evidence.clone(),
                        }),
                        evidence,
                    }],
                },
            )]
            .into(),
        };
        let progress = EvaluationProgress {
            binding: String::new(),
            arrays: BTreeMap::new(),
        };
        let before = filter::page(tenant, &[device.clone()], &catalog, &rule, &progress).unwrap();
        device.arrays.get_mut(&key).unwrap().sources[0]
            .last_known
            .as_mut()
            .unwrap()
            .value
            .digest = "c".repeat(64);
        let after = filter::page(tenant, &[device], &catalog, &rule, &progress).unwrap();
        let original = &before.objects[0].contexts["default"][key.as_str()];
        let changed = &after.objects[0].contexts["default"][key.as_str()];
        assert_eq!(original.state, changed.state);
        assert_ne!(original.snapshot_id, changed.snapshot_id);
    }
}

/// Task-owned persistence required by resumable asset evaluation.
/// Implementations borrow the initiating transaction and never settle it.
pub trait EvaluationStore: Send + Sync {
    fn evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
    ) -> crate::tasks::Pending<'a, Option<EvaluationProgress>>;
    fn save_evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
        progress: &'a EvaluationProgress,
    ) -> crate::tasks::Pending<'a, ()>;
    fn clear_evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
    ) -> crate::tasks::Pending<'a, ()>;
}
