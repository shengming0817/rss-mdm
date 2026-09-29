use super::*;
#[test]
fn persisted_asset_fingerprint_keeps_its_original_encoding() {
    let audit = RequestAudit::new(
        "11111111-1111-4111-8111-111111111111".into(),
        "management_write",
    );
    audit.set_principal("operator", "mdm");
    let id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
    let command = Command::Search {
        request: Operation {
            operation_id: id,
            expected_revision: 0,
            input: Query::default(),
        },
        scope: ReadScope {
            subject: "operator".into(),
            devices: None,
        },
    };
    let original=br#"["11111111-1111-4111-8111-111111111111","operator","mdm",{"kind":"Asset","command":{"kind":"search","request":{"operationId":"22222222-2222-4222-8222-222222222222","expectedRevision":0,"input":{"criteria":null,"select":[],"sort":null}},"scope":{"subject":"operator","devices":null}}}]"#;
    let (operation, digest) = operation_identity(&command, &audit).unwrap();
    assert_eq!(operation, Some(id));
    assert_eq!(digest, Sha256::digest(original).to_vec());
    audit.finalize(None);
}
#[test]
fn closed_manual_and_query_wire_rejects_legacy_deadlines() {
    for input in [
        serde_json::json!({"action":"delete","ttl":1}),
        serde_json::json!({"action":"null","validUntil":1}),
        serde_json::json!({"action":"set","value":{"kind":"integer","value":3},"expiresAt":1}),
    ] {
        assert!(serde_json::from_value::<ManualChange>(input).is_err());
    }
    assert!(serde_json::from_value::<Query>(serde_json::json!({"validUntil":1})).is_err());
    assert!(
        serde_json::from_value::<Criteria>(
            serde_json::json!({"kind":"eq","field":"device.model","value":"old"})
        )
        .is_err()
    );
}
#[test]
fn one_typed_condition_round_trips_through_the_existing_group_core() {
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let c = Criteria::Predicate {
        field: FieldKey::OfficeFloor,
        op: Operator::Ge,
        value: Some(Scalar::Integer(3)),
        values: None,
    };
    let r = rule(tenant, Uuid::new_v4(), &c).unwrap();
    assert_eq!(
        serde_json::to_value(&c).unwrap(),
        serde_json::to_value(criteria_view(r.view().criteria).unwrap()).unwrap()
    );
    let invalid = Criteria::Predicate {
        field: FieldKey::OfficeFloor,
        op: Operator::Eq,
        value: Some(Scalar::String("3".into())),
        values: None,
    };
    assert!(rule(tenant, Uuid::new_v4(), &invalid).is_err());
}
