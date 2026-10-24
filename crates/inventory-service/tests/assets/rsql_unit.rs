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
