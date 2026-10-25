use super::*;
#[test]
fn wire_has_one_language_and_internal_query_roundtrips() {
    for old in [
        serde_json::json!({"criteria":null}),
        serde_json::json!({"select":[]}),
        serde_json::json!({"sort":null}),
    ] {
        assert!(serde_json::from_value::<QueryInput>(old).is_err());
    }
    let criteria = Criteria::And {
        children: vec![
            Criteria::Predicate {
                field: FieldKey::parse("device.name").unwrap(),
                op: Operator::Contains,
                value: Some(Scalar::String("a'b\\c,*".into())),
                values: None,
            },
            Criteria::Predicate {
                field: FieldKey::parse("custom.value").unwrap(),
                op: Operator::IsNull,
                value: None,
                values: None,
            },
        ],
    };
    let input = QueryInput::from_query(Query {
        criteria: Some(InventoryCondition {
            selector: ScopeSelector::Device,
            quantifier: ScopeQuantifier::One,
            criteria,
        }),
        fields: vec![],
        sort: vec![],
    })
    .unwrap();
    let parsed = rss_mdm_query::parse_filter(input.filter.as_ref().unwrap()).unwrap();
    let Expression::And(parts) = parsed else {
        panic!("conjunction")
    };
    assert!(matches!(&parts[0],Expression::Compare{values,..} if values==&["a'b\\c,*"]));
    assert!(
        matches!(&parts[1],Expression::Compare{operator:Op::IsNull,values,..} if values==&["true"])
    );
}
#[test]
fn numeric_binding_does_not_coerce_strings_or_non_finite_values() {
    assert_eq!(
        scalar(Kind::Integer, "42".into()).unwrap(),
        Scalar::Integer(42)
    );
    assert!(scalar(Kind::Integer, "42.1".into()).is_err());
    assert!(scalar(Kind::Number, "NaN".into()).is_err());
    assert!(scalar(Kind::Boolean, "1".into()).is_err());
    assert!(scalar(Kind::Array, "[]".into()).is_err());
}

#[test]
fn typed_rsql_and_structured_conditions_have_one_canonical_definition() {
    let catalog = Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    for (text, field, op, value, values) in [
        (
            "custom.office_floor=ge=3",
            "custom.office_floor",
            Operator::Ge,
            Some(Scalar::Integer(3)),
            None,
        ),
        (
            "custom.office_floor=isnull=true",
            "custom.office_floor",
            Operator::IsNull,
            None,
            None,
        ),
        (
            "device.name=contains='Repair Tool'",
            "device.name",
            Operator::Contains,
            Some(Scalar::String("Repair Tool".into())),
            None,
        ),
        (
            "device.software.windows.system.is_provisioned_native=containsany=(2)",
            "device.software.windows.system.is_provisioned_native",
            Operator::ContainsAny,
            None,
            Some(vec![Scalar::Integer(2)]),
        ),
        (
            "device.software.windows.system.is_provisioned=containsany=(false)",
            "device.software.windows.system.is_provisioned",
            Operator::ContainsAny,
            None,
            Some(vec![Scalar::Boolean(false)]),
        ),
        (
            "device.software.installations.name=containsany=('A','B')",
            "device.software.installations.name",
            Operator::ContainsAny,
            None,
            Some(vec![Scalar::String("A".into()), Scalar::String("B".into())]),
        ),
    ] {
        let expected = Criteria::Predicate {
            field: FieldKey::parse(field).unwrap(),
            op,
            value,
            values,
        };
        let parsed = QueryInput {
            filter: Some(text.into()),
            ..Default::default()
        }
        .compile(&catalog)
        .unwrap();
        let parsed = parsed.criteria.unwrap().criteria;
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        let left = filter::rule(tenant, Uuid::nil(), &expected, &catalog).unwrap();
        let right = filter::rule(tenant, Uuid::nil(), &parsed, &catalog).unwrap();
        assert_eq!(
            serde_json::to_value(criteria_view(left.view().criteria).unwrap()).unwrap(),
            serde_json::to_value(criteria_view(right.view().criteria).unwrap()).unwrap()
        );
    }
    for text in [
        "device.software.windows.system.is_provisioned_native=containsany=(true)",
        "device.software.windows.system.is_provisioned=containsany=(2)",
        "custom.office_floor==wat",
        "device.name=icontains=x",
        "custom.office_floor=isnull=false",
        "unknown.key==x",
    ] {
        assert!(
            QueryInput {
                filter: Some(text.into()),
                ..Default::default()
            }
            .compile(&catalog)
            .is_err()
        );
    }
}
#[test]
fn scope_constraints_are_not_erased_by_rsql() {
    let catalog = Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    let mut input = QueryInput {
        filter: Some("device.name==x".into()),
        scope: QueryScope {
            selector: ScopeSelector::AllAuthorized,
            quantifier: ScopeQuantifier::One,
        },
        ..Default::default()
    };
    assert!(input.compile(&catalog).is_err());
    input.scope.quantifier = ScopeQuantifier::Any;
    assert!(input.compile(&catalog).is_ok());
    input.scope.selector = ScopeSelector::Device;
    assert!(input.compile(&catalog).is_err());
}

#[test]
fn maximum_filter_roundtrips_without_formatting_growth() {
    let catalog = Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    let text = vec![format!("device.name=={}", "z".repeat(1010)); 8].join(";");
    assert_eq!(text.len(), 8191);
    for suffix in ["", "z"] {
        let input = SavedDefinition {
            name: "boundary".into(),
            query: QueryInput {
                filter: Some(format!("{text}{suffix}")),
                ..Default::default()
            },
        };
        let view = StoredDefinition::compile(&input, &catalog)
            .unwrap()
            .into_view()
            .unwrap();
        assert_eq!(view.query.filter, input.query.filter);
        assert!(StoredDefinition::compile(&view, &catalog).is_ok());
    }
}

#[test]
fn canonical_precedence_and_escaped_values_keep_their_meaning() {
    let catalog = Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    for text in [
        "device.name==a;(device.name==b,device.name==c)",
        "(device.name==a;device.name==b),device.name==c",
        "device.name=in=('a,b','c;d',\"a'b\",'c\\\\d','*','')",
    ] {
        let query = QueryInput {
            filter: Some(text.into()),
            ..Default::default()
        }
        .compile(&catalog)
        .unwrap();
        let view = QueryInput::from_query(query.clone()).unwrap();
        let replay = view.compile(&catalog).unwrap();
        assert_eq!(
            serde_json::to_value(query).unwrap(),
            serde_json::to_value(replay).unwrap()
        );
    }
}

#[test]
fn saved_numeric_spelling_does_not_expand_short_exponents() {
    let catalog = Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    let input = SavedDefinition {
        name: "expanded".into(),
        query: QueryInput {
            filter: Some(vec!["device.hardware.apple.capacity_gb==1e300"; 30].join(";")),
            ..Default::default()
        },
    };
    assert!(input.query.compile(&catalog).is_ok());
    let view = StoredDefinition::compile(&input, &catalog)
        .unwrap()
        .into_view()
        .unwrap();
    assert!(view.query.filter.as_ref().unwrap().len() < 2048);
    assert!(StoredDefinition::compile(&view, &catalog).is_ok());
}

#[test]
fn typed_definitions_cannot_emit_over_budget_public_syntax() {
    let criteria = Criteria::And {
        children: (0..9)
            .map(|_| Criteria::Predicate {
                field: FieldKey::parse("device.name").unwrap(),
                op: Operator::Eq,
                value: Some(Scalar::String("z".repeat(1024))),
                values: None,
            })
            .collect(),
    };
    assert!(formatted(&criteria).is_err());
}

#[test]
fn escaped_bare_values_at_the_filter_limit_remain_replayable() {
    let catalog = Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    let text = vec![format!("device.name=={}\\'", "z".repeat(1008)); 8].join(";");
    assert_eq!(text.len(), 8191);
    let input = SavedDefinition {
        name: "escaped".into(),
        query: QueryInput {
            filter: Some(text.clone()),
            ..Default::default()
        },
    };
    let view = StoredDefinition::compile(&input, &catalog)
        .unwrap()
        .into_view()
        .unwrap();
    assert_eq!(view.query.filter.as_deref(), Some(text.as_str()));
    assert!(StoredDefinition::compile(&view, &catalog).is_ok());
}
