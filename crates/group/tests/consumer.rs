use rss_mdm_group::{ObjectKey, diff};
use rss_request_context::TenantId;

#[test]
fn member_difference_is_a_stable_tenant_scoped_set_operation() {
    let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let key = |s| ObjectKey::new(tenant, s).unwrap();
    let old = vec![key("c"), key("a"), key("b"), key("b")];
    let new = vec![key("d"), key("c"), key("b"), key("c")];
    let result = diff(tenant, &old, &new).unwrap();
    assert_eq!(result.added, vec![key("d")]);
    assert_eq!(result.removed, vec![key("a")]);
    assert_eq!(result.unchanged, vec![key("b"), key("c")]);
    assert_eq!(result, diff(tenant, &old, &new).unwrap());
    let again = diff(tenant, &new, &new).unwrap();
    assert!(again.added.is_empty() && again.removed.is_empty());
}

use rss_contract::Timepoint;
use rss_mdm_group::*;
use std::collections::{BTreeMap, BTreeSet};

fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
fn time(t: i64) -> Timepoint {
    Timepoint::try_from(t).unwrap()
}
fn string(s: &str) -> Value {
    Value::Scalar(Scalar::String(s.into()))
}
fn integer(i: i64) -> Value {
    Value::Scalar(Scalar::Integer(i))
}
fn set(t: ScalarType, values: Vec<Scalar>) -> Value {
    Value::Set {
        element: t,
        values: values.into_iter().collect(),
    }
}
fn field(kind: FieldType, ops: &[Op]) -> Field {
    Field {
        key: "device.model".into(),
        kind,
        unit: None,
        operations: ops.iter().copied().collect(),
        nullable: true,
    }
}
fn leaf(op: Op, value: Option<Value>) -> Criteria {
    Criteria::predicate(Predicate {
        field: "device.model".into(),
        op,
        operand: value.map(|value| Operand { value, unit: None }),
    })
    .unwrap()
}
fn rule(kind: FieldType, op: Op, value: Option<Value>) -> Rule {
    Rule::new(
        "rule-1",
        "dictionary-1",
        vec![field(kind, &[op])],
        leaf(op, value),
    )
    .unwrap()
}
fn snapshot(state: FactState) -> Snapshot {
    Snapshot {
        tenant: tenant(),
        id: "resolved-assets".into(),
        version: "revision-1".into(),
        dictionary_version: "dictionary-1".into(),
        complete: true,
        coverage: BTreeSet::from(["device.model".into()]),
        objects: vec![ObjectSnapshot {
            key: ObjectKey::new(tenant(), "device-a").unwrap(),
            facts: BTreeMap::from([(
                "device.model".into(),
                Fact {
                    state,
                    source: "fixture-collector".into(),
                    snapshot_id: "collection-1".into(),
                    observed_at: time(10),
                    valid_until: Some(time(20)),
                },
            )]),
        }],
    }
}
fn evaluate(rule: &Rule, snapshot: &Snapshot, t: i64) -> ObjectEvaluation {
    rule.evaluate(snapshot, time(t)).unwrap().objects.remove(0)
}

#[test]
fn preview_and_recalculation_share_decisions_and_provenance() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("主机-α😀")),
    );
    let mut s = snapshot(FactState::Known(string("主机-α😀")));
    let mut unknown = s.objects[0].clone();
    unknown.key = ObjectKey::new(tenant(), "device-b").unwrap();
    unknown.facts.get_mut("device.model").unwrap().state = FactState::Missing;
    s.objects.push(unknown);
    let old = vec![s.objects[1].key.clone()];
    let preview = r.evaluate(&s, time(10)).unwrap();
    let result = r.recalculate(&s, time(10), &old).unwrap();
    assert_eq!(preview, result.evaluation);
    assert_eq!(result.difference.added, vec![s.objects[0].key.clone()]);
    assert_eq!(result.difference.removed, old);
    assert_eq!(result.unknown, old);
    assert_eq!(
        result.evaluation.objects[0].provenance["device.model"].snapshot_id,
        "collection-1"
    );
    assert_eq!(result.evaluation.rule_version, "rule-1");
    s.objects.reverse();
    s.objects.push(s.objects[0].clone());
    assert_eq!(result, r.recalculate(&s, time(10), &old).unwrap());
}

#[test]
fn null_missing_expiry_and_unsupported_never_become_negative_matches() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Ne,
        Some(string("x")),
    );
    for (state, expected) in [
        (FactState::Null, UnknownReason::Null),
        (FactState::Missing, UnknownReason::Missing),
        (FactState::Unsupported, UnknownReason::Unsupported),
    ] {
        let e = evaluate(&r, &snapshot(state), 10);
        assert_eq!(e.decision, Decision::Unknown);
        assert_eq!(e.explanations[0].outcome, Outcome::Unknown(expected));
    }
    let s = snapshot(FactState::Known(string("")));
    assert_eq!(evaluate(&r, &s, 10).decision, Decision::Match);
    assert_eq!(evaluate(&r, &s, 19).decision, Decision::Match);
    assert_eq!(
        evaluate(&r, &s, 20).explanations[0].outcome,
        Outcome::Unknown(UnknownReason::Stale)
    );
    assert_eq!(
        evaluate(&r, &s, 9).explanations[0].outcome,
        Outcome::Unknown(UnknownReason::Future)
    );
    for op in [Op::IsNull, Op::IsNotNull] {
        let r = rule(FieldType::Scalar(ScalarType::String), op, None);
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Null), 10).decision,
            if op == Op::IsNull {
                Decision::Match
            } else {
                Decision::NoMatch
            }
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Missing), 10).decision,
            Decision::Unknown
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Null), 20).decision,
            Decision::Unknown
        );
    }
}

#[test]
fn all_comparisons_are_typed_and_have_exact_boundaries() {
    for (op, equal, lower, higher) in [
        (Op::Eq, true, false, false),
        (Op::Ne, false, true, true),
        (Op::Lt, false, true, false),
        (Op::Le, true, true, false),
        (Op::Gt, false, false, true),
        (Op::Ge, true, false, true),
    ] {
        for is_time in [false, true] {
            let val = |n| {
                if is_time {
                    Value::Scalar(Scalar::Time(time(n)))
                } else {
                    integer(n)
                }
            };
            let kind = if is_time {
                ScalarType::Time
            } else {
                ScalarType::Integer
            };
            let r = rule(FieldType::Scalar(kind), op, Some(val(8192)));
            for (n, expected) in [(8192, equal), (4096, lower), (16384, higher)] {
                assert_eq!(
                    evaluate(&r, &snapshot(FactState::Known(val(n))), 10).decision,
                    if expected {
                        Decision::Match
                    } else {
                        Decision::NoMatch
                    }
                );
            }
        }
    }
    let r = rule(
        FieldType::Scalar(ScalarType::Boolean),
        Op::Eq,
        Some(Value::Scalar(Scalar::Boolean(false))),
    );
    assert_eq!(
        evaluate(
            &r,
            &snapshot(FactState::Known(Value::Scalar(Scalar::Boolean(false)))),
            10
        )
        .decision,
        Decision::Match
    );
    assert_eq!(
        evaluate(&r, &snapshot(FactState::Missing), 10).decision,
        Decision::Unknown
    );
}

#[test]
fn strings_are_exact_literal_unicode_data() {
    for text in ["主机-α😀", "a\"\\%_.*", "", "e\u{301}"] {
        let r = rule(
            FieldType::Scalar(ScalarType::String),
            Op::Eq,
            Some(string(text)),
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Known(string(text))), 10).decision,
            Decision::Match
        );
    }
    for (op, needle, expected) in [
        (Op::Contains, "TOP", true),
        (Op::Contains, "top", false),
        (Op::Contains, "%", false),
        (Op::NotContains, "top", true),
    ] {
        let r = rule(
            FieldType::Scalar(ScalarType::String),
            op,
            Some(string(needle)),
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Known(string("DESKTOP"))), 10).decision,
            if expected {
                Decision::Match
            } else {
                Decision::NoMatch
            }
        );
    }
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("é")),
    );
    assert_eq!(
        evaluate(&r, &snapshot(FactState::Known(string("e\u{301}"))), 10).decision,
        Decision::NoMatch
    );
}

#[test]
fn collection_operators_use_homogeneous_set_semantics() {
    let t = ScalarType::Integer;
    for op in [Op::In, Op::NotIn] {
        let r = rule(
            FieldType::Scalar(t),
            op,
            Some(set(t, vec![Scalar::Integer(1), Scalar::Integer(1)])),
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Known(integer(1))), 10).decision,
            if op == Op::In {
                Decision::Match
            } else {
                Decision::NoMatch
            }
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Missing), 10).decision,
            Decision::Unknown
        );
    }
    for (op, requested, expected) in [
        (Op::ContainsAny, vec![], false),
        (Op::ContainsAll, vec![], true),
        (
            Op::ContainsAny,
            vec![Scalar::Integer(1), Scalar::Integer(3)],
            true,
        ),
        (
            Op::ContainsAll,
            vec![Scalar::Integer(1), Scalar::Integer(3)],
            false,
        ),
    ] {
        let r = rule(FieldType::Set(t), op, Some(set(t, requested)));
        assert_eq!(
            evaluate(
                &r,
                &snapshot(FactState::Known(set(
                    t,
                    vec![Scalar::Integer(1), Scalar::Integer(2)]
                ))),
                10
            )
            .decision,
            if expected {
                Decision::Match
            } else {
                Decision::NoMatch
            }
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Missing), 10).decision,
            Decision::Unknown
        );
    }
}

#[test]
fn nested_logic_collects_stable_explanations_and_checks_every_branch() {
    let mut f = field(FieldType::Scalar(ScalarType::String), &[Op::Eq]);
    let mut g = f.clone();
    g.key = "unknown".into();
    let unknown = Criteria::predicate(Predicate {
        field: "unknown".into(),
        op: Op::Eq,
        operand: Some(Operand {
            value: string("x"),
            unit: None,
        }),
    })
    .unwrap();
    let yes = leaf(Op::Eq, Some(string("yes")));
    let no = leaf(Op::Eq, Some(string("no")));
    for (and, first, expected) in [
        (true, yes.clone(), Decision::Unknown),
        (true, no.clone(), Decision::NoMatch),
        (false, yes.clone(), Decision::Match),
        (false, no, Decision::Unknown),
    ] {
        for reverse in [false, true] {
            let mut children = vec![first.clone(), unknown.clone()];
            if reverse {
                children.reverse();
            }
            let c = if and {
                Criteria::and(children)
            } else {
                Criteria::or(children)
            }
            .unwrap();
            let r = Rule::new("1", "dictionary-1", vec![f.clone(), g.clone()], c).unwrap();
            let mut s = snapshot(FactState::Known(string("yes")));
            s.complete = false;
            let e = evaluate(&r, &s, 10);
            assert_eq!(e.decision, expected);
            assert_eq!(e.explanations.len(), 2);
            assert_eq!(e.explanations[0].path, vec![0]);
            assert_eq!(e.explanations[1].path, vec![1]);
        }
    }
    f.operations.insert(Op::Contains);
    let nested =
        Criteria::and(vec![yes.clone(), Criteria::or(vec![yes, unknown]).unwrap()]).unwrap();
    assert!(matches!(
        Rule::new("1", "1", vec![f], nested),
        Err(Error::UnknownField)
    ));
}

#[test]
fn incomplete_and_malformed_inputs_never_return_a_difference() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("x")),
    );
    let valid = snapshot(FactState::Known(string("x")));
    let old = vec![valid.objects[0].key.clone()];
    let mut partial = valid.clone();
    partial.complete = false;
    partial.coverage.clear();
    partial.objects[0].facts.clear();
    assert_eq!(evaluate(&r, &partial, 10).decision, Decision::Unknown);
    assert_eq!(
        r.recalculate(&partial, time(10), &old),
        Err(Error::IncompleteSnapshot)
    );
    for (mut s, error) in [
        (valid.clone(), Error::IncompleteSnapshot),
        (valid.clone(), Error::VersionMismatch),
        (valid.clone(), Error::InvalidTime),
        (valid.clone(), Error::PermissionDenied),
        (valid.clone(), Error::InvalidType),
        (valid.clone(), Error::UnknownField),
    ] {
        match error {
            Error::IncompleteSnapshot => {
                s.objects[0].facts.clear();
            }
            Error::VersionMismatch => s.dictionary_version = "other".into(),
            Error::InvalidTime => {
                s.objects[0]
                    .facts
                    .get_mut("device.model")
                    .unwrap()
                    .valid_until = Some(time(10))
            }
            Error::PermissionDenied => {
                s.objects[0].facts.get_mut("device.model").unwrap().state = FactState::Denied
            }
            Error::InvalidType => {
                s.objects[0].facts.get_mut("device.model").unwrap().state =
                    FactState::Known(integer(2))
            }
            Error::UnknownField => {
                let fact = s.objects[0].facts["device.model"].clone();
                s.objects[0].facts.insert("typo".into(), fact);
            }
            _ => unreachable!(),
        }
        assert_eq!(r.recalculate(&s, time(10), &old), Err(error));
    }
    let mut conflict = valid.clone();
    let mut other = conflict.objects[0].clone();
    other.facts.get_mut("device.model").unwrap().state = FactState::Missing;
    conflict.objects.push(other);
    assert_eq!(
        r.recalculate(&conflict, time(10), &old),
        Err(Error::ConflictingObject)
    );
    let foreign = ObjectKey::new(
        TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
        "device-a",
    )
    .unwrap();
    assert_eq!(
        diff(tenant(), &old, std::slice::from_ref(&foreign)),
        Err(Error::TenantMismatch)
    );
    assert_eq!(
        r.recalculate(&valid, time(10), std::slice::from_ref(&foreign)),
        Err(Error::TenantMismatch)
    );
    let mut s = valid;
    s.objects[0].key = foreign;
    assert_eq!(r.evaluate(&s, time(10)), Err(Error::TenantMismatch));
}

#[test]
fn rule_types_units_and_operations_fail_before_any_evaluation() {
    let kind = FieldType::Scalar(ScalarType::String);
    assert!(matches!(
        Rule::new(
            "1",
            "1",
            vec![field(kind, &[Op::Lt])],
            leaf(Op::Lt, Some(string("x")))
        ),
        Err(Error::InvalidOperation)
    ));
    assert!(matches!(
        Rule::new(
            "1",
            "1",
            vec![field(kind, &[Op::Eq])],
            leaf(Op::Eq, Some(integer(1)))
        ),
        Err(Error::InvalidType)
    ));
    assert!(matches!(
        Rule::new("1", "1", vec![field(kind, &[Op::Eq])], leaf(Op::Eq, None)),
        Err(Error::InvalidOperation)
    ));
    let mut f = field(FieldType::Scalar(ScalarType::Integer), &[Op::Eq]);
    f.unit = Some("MiB".into());
    assert!(matches!(
        Rule::new("1", "1", vec![f.clone()], leaf(Op::Eq, Some(integer(1)))),
        Err(Error::InvalidUnit)
    ));
    let c = Criteria::predicate(Predicate {
        field: f.key.clone(),
        op: Op::Eq,
        operand: Some(Operand {
            value: integer(1),
            unit: Some("MiB".into()),
        }),
    })
    .unwrap();
    assert!(Rule::new("1", "1", vec![f], c).is_ok());
    let mixed = set(
        ScalarType::Integer,
        vec![Scalar::Integer(1), Scalar::Boolean(true)],
    );
    assert!(matches!(
        Criteria::predicate(Predicate {
            field: "f".into(),
            op: Op::In,
            operand: Some(Operand {
                value: mixed,
                unit: None
            })
        }),
        Err(Error::InvalidType)
    ));
    let mut f = field(kind, &[Op::Eq]);
    f.nullable = false;
    let r = Rule::new(
        "1",
        "dictionary-1",
        vec![f],
        leaf(Op::Eq, Some(string("x"))),
    )
    .unwrap();
    assert_eq!(
        r.evaluate(&snapshot(FactState::Null), time(10)),
        Err(Error::InvalidType)
    );
}

#[test]
fn depth_nodes_sets_and_string_limits_have_inclusive_boundaries() {
    assert!(matches!(
        Criteria::and(vec![]),
        Err(Error::InvalidStructure)
    ));
    assert!(matches!(Criteria::or(vec![]), Err(Error::InvalidStructure)));
    let mut c = leaf(Op::Eq, Some(string("x")));
    for _ in 1..limits::DEPTH {
        c = Criteria::and(vec![c]).unwrap();
    }
    assert!(matches!(Criteria::or(vec![c]), Err(Error::LimitExceeded)));
    let leaf = leaf(Op::Eq, Some(string("x")));
    assert!(Criteria::and(vec![leaf.clone(); limits::NODES - 1]).is_ok());
    assert!(matches!(
        Criteria::and(vec![leaf; limits::NODES]),
        Err(Error::LimitExceeded)
    ));
    for (count, ok) in [(limits::SET_ITEMS, true), (limits::SET_ITEMS + 1, false)] {
        let value = set(
            ScalarType::Integer,
            (0..count).map(|i| Scalar::Integer(i as i64)).collect(),
        );
        assert_eq!(
            Criteria::predicate(Predicate {
                field: "f".into(),
                op: Op::In,
                operand: Some(Operand { value, unit: None })
            })
            .is_ok(),
            ok
        );
    }
    for (len, ok) in [
        (limits::STRING_BYTES, true),
        (limits::STRING_BYTES + 1, false),
    ] {
        assert_eq!(ObjectKey::new(tenant(), "x".repeat(len)).is_ok(), ok);
    }
    let c = Criteria::and(
        (0..17)
            .map(|_| crate::leaf(Op::Eq, Some(string(&"x".repeat(4096)))))
            .collect(),
    )
    .unwrap();
    assert!(matches!(
        Rule::new(
            "1",
            "1",
            vec![field(FieldType::Scalar(ScalarType::String), &[Op::Eq])],
            c
        ),
        Err(Error::LimitExceeded)
    ));
}

#[test]
fn batch_work_and_size_limits_are_enforced_without_partial_results() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("x")),
    );
    let mut s = snapshot(FactState::Known(string("x")));
    s.objects = vec![s.objects[0].clone(); limits::OBJECTS];
    assert_eq!(r.evaluate(&s, time(10)).unwrap().objects.len(), 1);
    s.objects.push(s.objects[0].clone());
    assert_eq!(r.evaluate(&s, time(10)), Err(Error::LimitExceeded));
    let key = ObjectKey::new(tenant(), "a").unwrap();
    assert!(diff(tenant(), &vec![key.clone(); limits::OBJECTS], &[]).is_ok());
    assert_eq!(
        diff(tenant(), &vec![key; limits::OBJECTS + 1], &[]),
        Err(Error::LimitExceeded)
    );
    let key = ObjectKey::new(tenant(), "a".repeat(4096)).unwrap();
    assert!(diff(tenant(), &vec![key.clone(); 4096], &[]).is_ok());
    assert_eq!(
        diff(tenant(), &vec![key; 4097], &[]),
        Err(Error::LimitExceeded)
    );
    let c = Criteria::and(vec![leaf(Op::Eq, Some(string("x"))); 99]).unwrap();
    let r = Rule::new(
        "1",
        "dictionary-1",
        vec![field(FieldType::Scalar(ScalarType::String), &[Op::Eq])],
        c,
    )
    .unwrap();
    s.objects.pop();
    assert!(r.evaluate(&s, time(10)).is_ok()); // exactly 1,000,000 visits before deduplication
    let c = Criteria::and(vec![leaf(Op::Eq, Some(string("x"))); 100]).unwrap();
    let r = Rule::new(
        "1",
        "dictionary-1",
        vec![field(FieldType::Scalar(ScalarType::String), &[Op::Eq])],
        c,
    )
    .unwrap();
    assert_eq!(r.evaluate(&s, time(10)), Err(Error::LimitExceeded));
}

#[test]
fn dictionary_limits_duplicates_and_unused_denied_fields_are_checked() {
    let kind = FieldType::Scalar(ScalarType::String);
    let mut fields = vec![field(kind, &[Op::Eq])];
    for i in 1..limits::FIELDS {
        let mut f = field(kind, &[Op::Eq]);
        f.key = format!("field-{i}");
        fields.push(f);
    }
    let c = leaf(Op::Eq, Some(string("x")));
    let r = Rule::new("1", "dictionary-1", fields.clone(), c.clone()).unwrap();
    assert_eq!(r.predicate_at(&[]).unwrap().field, "device.model");
    assert!(r.predicate_at(&[0]).is_none());
    let mut s = snapshot(FactState::Known(string("x")));
    let mut denied = s.objects[0].facts["device.model"].clone();
    denied.state = FactState::Denied;
    s.coverage.insert("field-1".into());
    s.objects[0].facts.insert("field-1".into(), denied);
    assert_eq!(r.evaluate(&s, time(10)), Err(Error::PermissionDenied));
    fields.push(fields[0].clone());
    assert!(matches!(
        Rule::new("1", "1", fields, c.clone()),
        Err(Error::LimitExceeded)
    ));
    assert!(matches!(
        Rule::new("1", "1", vec![field(kind, &[Op::Eq]); 2], c),
        Err(Error::InvalidStructure)
    ));
}

#[test]
fn historical_nested_criteria_has_one_literal_interpretation() {
    // Historical rule_compiler_test.go TestCriteriaCompiler_Compile_NestedGroups:
    // channel == mdm AND (hostname contains DESKTOP OR hostname contains LAPTOP).
    // Current input names are caller-owned; no legacy field-name translation is implemented.
    let kind = FieldType::Scalar(ScalarType::String);
    let model = field(kind, &[Op::Contains]);
    let mut os = field(kind, &[Op::Eq]);
    os.key = "device.os.version".into();
    let os_criterion = Criteria::predicate(Predicate {
        field: os.key.clone(),
        op: Op::Eq,
        operand: Some(Operand {
            value: string("10.0.26100"),
            unit: None,
        }),
    })
    .unwrap();
    let tree = Criteria::and(vec![
        os_criterion,
        Criteria::or(vec![
            leaf(Op::Contains, Some(string("DESKTOP"))),
            leaf(Op::Contains, Some(string("LAPTOP"))),
        ])
        .unwrap(),
    ])
    .unwrap();
    let r = Rule::new("historical-shape-1", "dictionary-1", vec![model, os], tree).unwrap();
    let mut s = snapshot(FactState::Known(string("DESKTOP-001")));
    let mut os_fact = s.objects[0].facts["device.model"].clone();
    os_fact.state = FactState::Known(string("10.0.26100"));
    s.coverage.insert("device.os.version".into());
    s.objects[0]
        .facts
        .insert("device.os.version".into(), os_fact);
    let e = evaluate(&r, &s, 10);
    assert_eq!(e.decision, Decision::Match);
    assert_eq!(
        e.explanations
            .iter()
            .map(|e| e.path.clone())
            .collect::<Vec<_>>(),
        vec![vec![0], vec![1, 0], vec![1, 1]]
    );
    for explanation in e.explanations {
        assert!(r.predicate_at(&explanation.path).is_some());
    }
    assert!(r.predicate_at(&[1]).is_none());
}
