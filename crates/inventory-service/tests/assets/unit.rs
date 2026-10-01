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
            sensitive: false,
            devices: None,
        },
    };
    let original=br#"["11111111-1111-4111-8111-111111111111","operator","mdm",{"kind":"Asset","command":{"kind":"search","request":{"operationId":"22222222-2222-4222-8222-222222222222","expectedRevision":0,"input":{"criteria":null,"select":[],"sort":null}},"scope":{"subject":"operator","sensitive":false,"devices":null}}}]"#;
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
        field: rss_mdm_inventory::builtin::OFFICE_FLOOR,
        op: Operator::Ge,
        value: Some(Scalar::Integer(3)),
        values: None,
    };
    let r = rule(
        tenant,
        Uuid::new_v4(),
        &c,
        &rss_mdm_inventory::Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&c).unwrap(),
        serde_json::to_value(criteria_view(r.view().criteria).unwrap()).unwrap()
    );
    let invalid = Criteria::Predicate {
        field: rss_mdm_inventory::builtin::OFFICE_FLOOR,
        op: Operator::Eq,
        value: Some(Scalar::String("3".into())),
        values: None,
    };
    assert!(
        rule(
            tenant,
            Uuid::new_v4(),
            &invalid,
            &rss_mdm_inventory::Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap()
        )
        .is_err()
    );
}

#[test]
fn registered_paths_feed_group_sets_and_sensitive_conditions_need_an_explicit_grant() {
    use rss_mdm_group_postgres::core as g;
    use rss_mdm_inventory::{Catalog, ResolvedField, Sensitivity, State};
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let mut fields = rss_mdm_inventory::builtin::fields();
    let mut custom = fields[0].clone();
    custom.key = FieldKey::parse("custom.security_agent.build").unwrap();
    custom.sensitivity = Sensitivity::Sensitive;
    fields.push(custom.clone());
    let catalog = Catalog::new(fields).unwrap();
    let sensitive = Criteria::Predicate {
        field: custom.key,
        op: Operator::Eq,
        value: Some(Scalar::String("private".into())),
        values: None,
    };
    assert!(filter::require_visible(&catalog, &sensitive, false).is_err());
    assert!(filter::require_visible(&catalog, &sensitive, true).is_ok());
    let path = FieldKey::parse("device.software.installed.name").unwrap();
    let root = FieldKey::parse("device.software.installed").unwrap();
    let condition = Criteria::Predicate {
        field: path,
        op: Operator::ContainsAny,
        value: None,
        values: Some(vec![Scalar::String("Repair Tool".into())]),
    };
    let rule = rule(tenant, Uuid::new_v4(), &condition, &catalog).unwrap();
    let software = Scalar::Array(vec![Scalar::Object(
        [
            ("id".into(), Scalar::String("tool".into())),
            ("name".into(), Scalar::String("Repair Tool".into())),
            ("version".into(), Scalar::String("1".into())),
            ("publisher".into(), Scalar::String("".into())),
            ("scope".into(), Scalar::String("system".into())),
        ]
        .into(),
    )]);
    let mut device = DeviceView {
        lists: BTreeMap::new(),
        device: "device".into(),
        channels: BTreeSet::new(),
        quality: vec![],
        revisions: BTreeMap::new(),
        fields: [
            (
                root,
                ResolvedField {
                    field: root,
                    state: State::Known(software),
                    sources: vec![],
                },
            ),
            (
                custom.key,
                ResolvedField {
                    field: custom.key,
                    state: State::Known(Scalar::String("private".into())),
                    sources: vec![],
                },
            ),
        ]
        .into(),
    };
    let page = filter::page(tenant, &[device.clone()], &catalog, &rule).unwrap();
    let decision = rule
        .evaluate_page(
            &g::PageInput {
                tenant,
                id: "inventory",
                version: "1",
                dictionary_version: rss_mdm_inventory::DICTIONARY,
                coverage: &page.coverage,
                objects: &page.objects,
                after: None,
            },
            Timepoint::try_from(1).unwrap(),
        )
        .unwrap();
    assert_eq!(decision.objects[0].decision, g::Decision::Match);
    restrict_fields(&mut device, &catalog, false);
    assert!(!device.fields.contains_key(&custom.key));
    assert!(device.fields.contains_key(&root));
}
