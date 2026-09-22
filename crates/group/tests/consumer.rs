#![warn(clippy::cognitive_complexity)]

use rss_mdm_group::ObjectKey;
use rss_request_context::TenantId;

#[test]
fn page_evaluation_requires_ordered_partial_universe_and_complete_field_coverage() {
    let rule = Rule::new(
        tenant(),
        "r",
        "d",
        vec![field(FieldType::Scalar(ScalarType::String), &[Op::Eq])],
        leaf(Op::Eq, Some(string("a"))),
    )
    .unwrap();
    let mut page = snapshot(FactState::Known(string("a")));
    page.dictionary_version = "d".into();
    let expected = rule.evaluate_page(&page.input(), time(1)).unwrap();
    let input = |objects, coverage, after| PageInput {
        tenant: page.tenant,
        id: &page.id,
        version: &page.version,
        dictionary_version: &page.dictionary_version,
        coverage,
        objects,
        after,
    };
    assert_eq!(
        rule.evaluate_page(&input(&page.objects, &page.coverage, None), time(1))
            .unwrap(),
        expected
    );
    let last = page.objects[0].key.clone();
    assert!(
        rule.evaluate_page(&input(&page.objects, &page.coverage, Some(&last)), time(1))
            .is_err()
    );
    let duplicated = vec![page.objects[0].clone(), page.objects[0].clone()];
    assert!(
        rule.evaluate_page(&input(&duplicated, &page.coverage, None), time(1))
            .is_err()
    );
    assert_eq!(
        rule.evaluate_page(&input(&page.objects, &BTreeSet::new(), None), time(1)),
        Err(Error::IncompleteSnapshot)
    );
}

use rss_contract::Timepoint;
use rss_mdm_group::*;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn borrowed_rule_views_preserve_structure_for_independent_persistence() {
    fn rebuild(c: &Criteria) -> Criteria {
        match c.view() {
            CriteriaView::Predicate(p) => Criteria::predicate(p.clone()).unwrap(),
            CriteriaView::And(children) => {
                Criteria::and(children.iter().map(rebuild).collect()).unwrap()
            }
            CriteriaView::Or(children) => {
                Criteria::or(children.iter().map(rebuild).collect()).unwrap()
            }
        }
    }
    let criteria = Criteria::and(vec![
        leaf(Op::Eq, Some(string("a"))),
        Criteria::or(vec![
            leaf(Op::Eq, Some(string("b"))),
            leaf(Op::Eq, Some(string("c"))),
        ])
        .unwrap(),
    ])
    .unwrap();
    let original = Rule::new(
        tenant(),
        "r",
        "d",
        vec![field(FieldType::Scalar(ScalarType::String), &[Op::Eq])],
        criteria,
    )
    .unwrap();
    let v = original.view();
    let restored = Rule::new(
        v.tenant,
        v.version,
        v.dictionary_version,
        v.fields.values().cloned().collect(),
        rebuild(v.criteria),
    )
    .unwrap();
    let mut s = snapshot(FactState::Known(string("a")));
    s.dictionary_version = "d".into();
    assert_eq!(
        original.evaluate_page(&s.input(), time(10)),
        restored.evaluate_page(&s.input(), time(10))
    );
    assert_eq!(
        original.predicate_at(&[1, 0]),
        restored.predicate_at(&[1, 0])
    );
}

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
        tenant(),
        "rule-1",
        "dictionary-1",
        vec![field(kind, &[op])],
        leaf(op, value),
    )
    .unwrap()
}
fn snapshot(state: FactState) -> FixturePage {
    FixturePage {
        tenant: tenant(),
        id: "resolved-assets".into(),
        version: "revision-1".into(),
        dictionary_version: "dictionary-1".into(),
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
                },
            )]),
        }],
    }
}
fn evaluate(rule: &Rule, snapshot: &FixturePage, t: i64) -> ObjectEvaluation {
    rule.evaluate_page(&snapshot.input(), time(t))
        .unwrap()
        .objects
        .remove(0)
}

#[test]
fn unavailable_values_never_become_negative_matches() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Ne,
        Some(string("x")),
    );
    for (state, expected) in [
        (FactState::Null, UnknownReason::Null),
        (FactState::Missing, UnknownReason::Missing),
        (FactState::Unsupported, UnknownReason::Unsupported),
        (FactState::Deleted, UnknownReason::Deleted),
        (FactState::Conflict, UnknownReason::Conflict),
    ] {
        for at in [0, 10, 2_000_000_000] {
            let e = evaluate(&r, &snapshot(state.clone()), at);
            assert_eq!(e.decision, Decision::Unknown);
            assert_eq!(e.explanations[0].outcome, Outcome::Unknown(expected));
        }
    }
    for op in [Op::IsNull, Op::IsNotNull] {
        let r = rule(FieldType::Scalar(ScalarType::String), op, None);
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Null), 20).decision,
            if op == Op::IsNull {
                Decision::Match
            } else {
                Decision::NoMatch
            }
        );
        assert_eq!(
            evaluate(&r, &snapshot(FactState::Missing), 20).decision,
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
            let r =
                Rule::new(tenant(), "1", "dictionary-1", vec![f.clone(), g.clone()], c).unwrap();
            let mut s = snapshot(FactState::Known(string("yes")));
            s.coverage.insert("unknown".into());
            let mut missing = s.objects[0].facts["device.model"].clone();
            missing.state = FactState::Missing;
            s.objects[0].facts.insert("unknown".into(), missing);
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
        Rule::new(tenant(), "1", "1", vec![f], nested),
        Err(Error::UnknownField)
    ));
}

#[test]
fn rule_types_units_and_operations_fail_before_any_evaluation() {
    let kind = FieldType::Scalar(ScalarType::String);
    assert!(matches!(
        Rule::new(
            tenant(),
            "1",
            "1",
            vec![field(kind, &[Op::Lt])],
            leaf(Op::Lt, Some(string("x")))
        ),
        Err(Error::InvalidOperation)
    ));
    assert!(matches!(
        Rule::new(
            tenant(),
            "1",
            "1",
            vec![field(kind, &[Op::Eq])],
            leaf(Op::Eq, Some(integer(1)))
        ),
        Err(Error::InvalidType)
    ));
    assert!(matches!(
        Rule::new(
            tenant(),
            "1",
            "1",
            vec![field(kind, &[Op::Eq])],
            leaf(Op::Eq, None)
        ),
        Err(Error::InvalidOperation)
    ));
    let mut f = field(FieldType::Scalar(ScalarType::Integer), &[Op::Eq]);
    f.unit = Some("MiB".into());
    assert!(matches!(
        Rule::new(
            tenant(),
            "1",
            "1",
            vec![f.clone()],
            leaf(Op::Eq, Some(integer(1)))
        ),
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
    assert!(Rule::new(tenant(), "1", "1", vec![f], c).is_ok());
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
        tenant(),
        "1",
        "dictionary-1",
        vec![f],
        leaf(Op::Eq, Some(string("x"))),
    )
    .unwrap();
    assert_eq!(
        r.evaluate_page(&snapshot(FactState::Null).input(), time(10)),
        Err(Error::InvalidType)
    );
}

#[test]
fn depth_and_node_limits_have_inclusive_boundaries() {
    assert!(matches!(
        Criteria::and(vec![]),
        Err(Error::InvalidStructure)
    ));
    assert!(matches!(Criteria::or(vec![]), Err(Error::InvalidStructure)));
    let mut c = leaf(Op::Eq, Some(string("x")));
    for _ in 1..limits::DEPTH {
        c = Criteria::and(vec![c]).unwrap();
    }
    assert!(matches!(
        Criteria::or(vec![c]),
        Err(Error::LimitExceeded(LimitKind::Depth))
    ));
    let leaf = leaf(Op::Eq, Some(string("x")));
    assert!(Criteria::and(vec![leaf.clone(); limits::NODES - 1]).is_ok());
    assert!(matches!(
        Criteria::and(vec![leaf; limits::NODES]),
        Err(Error::LimitExceeded(LimitKind::Nodes))
    ));
}

#[test]
fn set_item_limits_have_inclusive_boundaries() {
    for (count, expected) in [
        (limits::SET_ITEMS, Ok(())),
        (
            limits::SET_ITEMS + 1,
            Err(Error::LimitExceeded(LimitKind::SetItems)),
        ),
    ] {
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
            .map(|_| ()),
            expected
        );
    }
}

#[test]
fn string_byte_limits_have_inclusive_boundaries() {
    for (len, ok) in [
        (limits::STRING_BYTES, true),
        (limits::STRING_BYTES + 1, false),
    ] {
        assert_eq!(ObjectKey::new(tenant(), "x".repeat(len)).is_ok(), ok);
    }
}

#[test]
fn rule_byte_limit_accumulates_across_predicates() {
    let c = Criteria::and(
        (0..17)
            .map(|_| crate::leaf(Op::Eq, Some(string(&"x".repeat(4096)))))
            .collect(),
    )
    .unwrap();
    assert!(matches!(
        Rule::new(
            tenant(),
            "1",
            "1",
            vec![field(FieldType::Scalar(ScalarType::String), &[Op::Eq])],
            c
        ),
        Err(Error::LimitExceeded(LimitKind::RuleBytes))
    ));
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
    let r = Rule::new(tenant(), "1", "dictionary-1", fields.clone(), c.clone()).unwrap();
    assert_eq!(r.predicate_at(&[]).unwrap().field, "device.model");
    assert!(r.predicate_at(&[0]).is_none());
    let mut s = snapshot(FactState::Known(string("x")));
    let mut denied = s.objects[0].facts["device.model"].clone();
    denied.state = FactState::Denied;
    s.coverage.insert("field-1".into());
    s.objects[0].facts.insert("field-1".into(), denied);
    assert_eq!(
        r.evaluate_page(&s.input(), time(10)),
        Err(Error::PermissionDenied)
    );
    fields.push(fields[0].clone());
    assert!(matches!(
        Rule::new(tenant(), "1", "1", fields, c.clone()),
        Err(Error::LimitExceeded(LimitKind::Fields))
    ));
    assert!(matches!(
        Rule::new(tenant(), "1", "1", vec![field(kind, &[Op::Eq]); 2], c),
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
    let r = Rule::new(
        tenant(),
        "historical-shape-1",
        "dictionary-1",
        vec![model, os],
        tree,
    )
    .unwrap();
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
    for (os, model, expected, outcomes) in [
        (
            "other",
            "DESKTOP-001",
            Decision::NoMatch,
            [Outcome::NoMatch, Outcome::Match, Outcome::NoMatch],
        ),
        (
            "10.0.26100",
            "SERVER-001",
            Decision::NoMatch,
            [Outcome::Match, Outcome::NoMatch, Outcome::NoMatch],
        ),
        (
            "10.0.26100",
            "LAPTOP-001",
            Decision::Match,
            [Outcome::Match, Outcome::NoMatch, Outcome::Match],
        ),
    ] {
        s.objects[0]
            .facts
            .get_mut("device.os.version")
            .unwrap()
            .state = FactState::Known(string(os));
        s.objects[0].facts.get_mut("device.model").unwrap().state = FactState::Known(string(model));
        let e = evaluate(&r, &s, 10);
        assert_eq!(e.decision, expected);
        assert_eq!(
            e.explanations.iter().map(|e| e.outcome).collect::<Vec<_>>(),
            outcomes
        );
    }
}

#[test]
fn empty_results_keep_the_tenant_coordinate() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("x")),
    );
    let mut s = snapshot(FactState::Missing);
    s.objects.clear();
    let first = r.evaluate_page(&s.input(), time(10)).unwrap();
    s.tenant = TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    let r = Rule::new(
        s.tenant,
        "rule-1",
        "dictionary-1",
        vec![field(FieldType::Scalar(ScalarType::String), &[Op::Eq])],
        leaf(Op::Eq, Some(string("x"))),
    )
    .unwrap();
    let second = r.evaluate_page(&s.input(), time(10)).unwrap();
    assert_ne!(first, second);
}

#[test]
fn rules_cannot_be_applied_to_another_tenants_consistent_snapshot() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("x")),
    );
    let mut s = snapshot(FactState::Known(string("x")));
    s.tenant = TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    s.objects[0].key = ObjectKey::new(s.tenant, "device-a").unwrap();
    for empty in [false, true] {
        if empty {
            s.objects.clear();
        }
        assert_eq!(
            r.evaluate_page(&s.input(), time(10)),
            Err(Error::TenantMismatch)
        );
    }
}

#[test]
fn explanation_materialization_is_bounded_before_output_allocation() {
    let mut fields = Vec::new();
    let mut criteria = Vec::new();
    let mut s = snapshot(FactState::Known(string("x")));
    let fact = s.objects[0].facts["device.model"].clone();
    s.objects[0].facts.clear();
    s.coverage.clear();
    for i in 0..128 {
        let key = format!("field-{i}");
        let mut f = field(FieldType::Scalar(ScalarType::String), &[Op::Eq]);
        f.key = key.clone();
        fields.push(f);
        criteria.push(
            Criteria::predicate(Predicate {
                field: key.clone(),
                op: Op::Eq,
                operand: Some(Operand {
                    value: string("x"),
                    unit: None,
                }),
            })
            .unwrap(),
        );
        s.coverage.insert(key.clone());
        s.objects[0].facts.insert(key, fact.clone());
    }
    let r = Rule::new(
        tenant(),
        "1",
        "dictionary-1",
        fields,
        Criteria::and(criteria).unwrap(),
    )
    .unwrap();
    let object = s.objects[0].clone();
    s.objects = (0..512)
        .map(|i| {
            let mut o = object.clone();
            o.key = ObjectKey::new(tenant(), format!("device-{i:07}")).unwrap();
            o
        })
        .collect();
    let result = r.evaluate_page(&s.input(), time(10)).unwrap();
    assert_eq!(
        result
            .objects
            .iter()
            .map(|o| o.explanations.len())
            .sum::<usize>(),
        65_536
    );
    assert_eq!(
        result
            .objects
            .iter()
            .map(|o| o.provenance.len())
            .sum::<usize>(),
        65_536
    );
    s.objects.push(s.objects[0].clone()); // duplicate inputs do not multiply output
    assert!(r.evaluate_page(&s.input(), time(10)).is_err());
    s.objects.pop();
    let mut extra = object;
    extra.key = ObjectKey::new(tenant(), "extra").unwrap();
    s.objects.push(extra);
    assert_eq!(
        r.evaluate_page(&s.input(), time(10)),
        Err(Error::LimitExceeded(LimitKind::Explanations))
    );
}

#[test]
fn batch_scalar_items_are_bounded_across_objects_and_unused_fields() {
    for kind in [ScalarType::Integer, ScalarType::Time] {
        let value = set(
            kind,
            (0..250)
                .map(|i| match kind {
                    ScalarType::Time => Scalar::Time(time(i)),
                    _ => Scalar::Integer(i),
                })
                .collect(),
        );
        let mut fields = vec![field(FieldType::Set(kind), &[Op::ContainsAll])];
        for i in 1..32 {
            let mut f = fields[0].clone();
            f.key = format!("field-{i}");
            fields.push(f);
        }
        let mut s = snapshot(FactState::Known(value.clone()));
        let fact = s.objects[0].facts["device.model"].clone();
        s.coverage = fields.iter().map(|f| f.key.clone()).collect();
        s.objects[0].facts = fields
            .iter()
            .map(|f| (f.key.clone(), fact.clone()))
            .collect();
        s.objects = (0..125)
            .map(|n| {
                let mut o = s.objects[0].clone();
                o.key = ObjectKey::new(tenant(), format!("d{n:07}")).unwrap();
                o
            })
            .collect(); // 125 * 32 * 250 = 1,000,000
        let r = Rule::new(
            tenant(),
            "1",
            "dictionary-1",
            fields,
            leaf(Op::ContainsAll, Some(value)),
        )
        .unwrap();
        assert!(r.evaluate_page(&s.input(), time(10)).is_ok());

        let final_fact = s
            .objects
            .last_mut()
            .unwrap()
            .facts
            .iter_mut()
            .next_back()
            .unwrap()
            .1;
        let FactState::Known(Value::Set { values, .. }) = &mut final_fact.state else {
            unreachable!()
        };
        values.insert(match kind {
            ScalarType::Time => Scalar::Time(time(250)),
            _ => Scalar::Integer(250),
        }); // exactly 1,000,001 items across the batch
        assert_eq!(
            r.evaluate_page(&s.input(), time(10)),
            Err(Error::LimitExceeded(LimitKind::Items))
        );

        *s.objects.last_mut().unwrap() = s.objects[0].clone();
        s.objects.push(s.objects[0].clone());
        for (n, object) in s.objects.iter_mut().enumerate() {
            object.key = ObjectKey::new(tenant(), format!("d{n:07}")).unwrap();
        }
        assert_eq!(
            r.evaluate_page(&s.input(), time(10)),
            Err(Error::LimitExceeded(LimitKind::Items))
        );
    }
}

#[test]
fn limit_diagnostics_distinguish_categories_without_input_values() {
    let secret = "private-device".repeat(limits::STRING_BYTES);
    let string_error = ObjectKey::new(tenant(), secret.clone()).unwrap_err();
    let node_error =
        Criteria::and(vec![leaf(Op::Eq, Some(string("x"))); limits::NODES]).unwrap_err();
    assert_eq!(string_error, Error::LimitExceeded(LimitKind::StringBytes));
    assert_eq!(node_error, Error::LimitExceeded(LimitKind::Nodes));
    assert!(!string_error.to_string().contains(&secret));
}

#[test]
fn asset_facts_do_not_expire_or_wait_for_observation_time() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("x")),
    );
    let s = snapshot(FactState::Known(string("x")));
    for at in [0, 10, 20, 2_000_000_000] {
        assert_eq!(evaluate(&r, &s, at).decision, Decision::Match);
    }
}

#[derive(Clone)]
struct FixturePage {
    tenant: TenantId,
    id: String,
    version: String,
    dictionary_version: String,
    coverage: BTreeSet<String>,
    objects: Vec<ObjectSnapshot>,
}
impl FixturePage {
    fn input(&self) -> PageInput<'_> {
        PageInput {
            tenant: self.tenant,
            id: &self.id,
            version: &self.version,
            dictionary_version: &self.dictionary_version,
            coverage: &self.coverage,
            objects: &self.objects,
            after: None,
        }
    }
}
#[test]
fn bounded_page_rejects_missing_coverage_foreign_cursor_and_oversized_universe() {
    let r = rule(
        FieldType::Scalar(ScalarType::String),
        Op::Eq,
        Some(string("x")),
    );
    let mut s = snapshot(FactState::Known(string("x")));
    s.coverage.clear();
    assert_eq!(
        r.evaluate_page(&s.input(), time(10)),
        Err(Error::IncompleteSnapshot)
    );
    s = snapshot(FactState::Known(string("x")));
    let other = TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    let cursor = ObjectKey::new(other, "a").unwrap();
    let mut page = s.input();
    page.after = Some(&cursor);
    assert_eq!(r.evaluate_page(&page, time(10)), Err(Error::TenantMismatch));
    s.objects = (0..1001)
        .map(|n| {
            let mut o = s.objects[0].clone();
            o.key = ObjectKey::new(tenant(), format!("d{n:07}")).unwrap();
            o
        })
        .collect();
    assert_eq!(
        r.evaluate_page(&s.input(), time(10)),
        Err(Error::LimitExceeded(LimitKind::Objects))
    );
    s.objects.truncate(1000);
    assert_eq!(
        r.evaluate_page(&s.input(), time(10)).unwrap().objects.len(),
        1000
    );
}
