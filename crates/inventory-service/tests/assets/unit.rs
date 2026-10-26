use super::*;
#[test]
fn asset_fingerprint_binds_explicit_collection_scope() {
    let audit = RequestAudit::new(
        "11111111-1111-4111-8111-111111111111".into(),
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.set_principal("operator", "mdm");
    let id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
    let command = Command::Search {
        request: Operation {
            operation_id: id,
            expected_revision: 0,
            input: rsql::QueryInput::default(),
        }
        .into(),
        scope: ReadScope {
            authority: "internal".into(),
            collection_scope: rss_mdm_inventory::CollectionScope::Device,
            subject: "operator".into(),
            devices: None,
        },
    };
    let original=br#"["11111111-1111-4111-8111-111111111111","operator","mdm",{"kind":"Asset","command":{"kind":"search","request":{"operationId":"22222222-2222-4222-8222-222222222222","expectedRevision":0,"input":{"filter":null,"scope":{"selector":{"kind":"device"},"quantifier":"one"},"fields":[],"sort":[]}},"scope":{"authority":"internal","collection_scope":{"kind":"device"},"subject":"operator","devices":null}}}]"#;
    let (operation, digest) = operation_identity(&command, &audit).unwrap();
    assert_eq!(operation, Some(id));
    assert_eq!(digest, Sha256::digest(original).to_vec());
    audit.finalize(None);
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
fn registered_sensitive_paths_feed_group_sets_without_an_extra_grant() {
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
    assert!(filter::require_visible(&catalog, &sensitive).is_ok());
    let path = FieldKey::parse("device.software.installations.name").unwrap();
    let root = FieldKey::parse("device.software.installations").unwrap();
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
            ("scope".into(), Scalar::String("device".into())),
            ("native_id".into(), Scalar::String("".into())),
            ("owner".into(), Scalar::String("".into())),
            ("origin".into(), Scalar::String("fixture".into())),
            (
                "installation_state".into(),
                Scalar::String("installed".into()),
            ),
            ("location".into(), Scalar::String("".into())),
        ]
        .into(),
    )]);
    let mut device = DeviceView {
        collection_scope: rss_mdm_inventory::CollectionScope::Device,
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
    let page = filter::page(
        tenant,
        &[DeviceSummary {
            scalars: device.clone(),
            arrays: BTreeMap::new(),
        }],
        &catalog,
        &rule,
        &evaluation::EvaluationProgress {
            binding: String::new(),
            arrays: BTreeMap::new(),
        },
    )
    .unwrap();
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
    restrict_fields(&mut device, &catalog);
    assert!(device.fields.contains_key(&custom.key));
    assert!(device.fields.contains_key(&root));
    assert!(filter::require_visible(&catalog, &condition).is_ok());
}

#[test]
fn installed_id_groups_use_existing_sets_and_preserve_unknown_states() {
    use rss_mdm_group_postgres::core as g;
    use rss_mdm_inventory::{Catalog, ResolvedField, State};
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let catalog = Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap();
    let root = FieldKey::parse("device.software.installations").unwrap();
    let criteria = Criteria::Predicate {
        field: FieldKey::parse("device.software.installations.id").unwrap(),
        op: Operator::ContainsAny,
        value: None,
        values: Some(vec![Scalar::String("acme.app".into())]),
    };
    let rule = rule(tenant, Uuid::new_v4(), &criteria, &catalog).unwrap();
    let item = |id: &str, version: &str| {
        Scalar::Object(
            [
                ("id".into(), Scalar::String(id.into())),
                ("name".into(), Scalar::String(id.into())),
                ("version".into(), Scalar::String(version.into())),
                ("publisher".into(), Scalar::String("Acme".into())),
                ("scope".into(), Scalar::String("device".into())),
                ("native_id".into(), Scalar::String("".into())),
                ("owner".into(), Scalar::String("".into())),
                ("origin".into(), Scalar::String("fixture".into())),
                (
                    "installation_state".into(),
                    Scalar::String("installed".into()),
                ),
                ("location".into(), Scalar::String("".into())),
            ]
            .into(),
        )
    };
    let installed = Scalar::Array(vec![item("acme.app", "1"), item("other.app", "2")]);
    for (state, expected) in [
        (State::Known(installed.clone()), g::Decision::Match),
        (State::Known(Scalar::Array(vec![])), g::Decision::NoMatch),
        (State::Missing, g::Decision::Unknown),
        (State::Unsupported, g::Decision::Unknown),
        (State::Conflict, g::Decision::Unknown),
    ] {
        let device = DeviceView {
            collection_scope: rss_mdm_inventory::CollectionScope::Device,
            lists: BTreeMap::new(),
            device: "device".into(),
            channels: BTreeSet::new(),
            quality: vec![],
            revisions: BTreeMap::new(),
            fields: [(
                root,
                ResolvedField {
                    field: root,
                    state,
                    sources: vec![],
                },
            )]
            .into(),
        };
        let page = filter::page(
            tenant,
            &[DeviceSummary {
                scalars: device,
                arrays: BTreeMap::new(),
            }],
            &catalog,
            &rule,
            &evaluation::EvaluationProgress {
                binding: String::new(),
                arrays: BTreeMap::new(),
            },
        )
        .unwrap();
        let result = rule
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
        assert_eq!(result.objects[0].decision, expected);
    }
    // The original typed items retain correlation; flattened Group sets do not.
    let Scalar::Array(items) = installed else {
        panic!("expected array")
    };
    let target = items
        .iter()
        .find_map(|v| match v {
            Scalar::Object(fields) if fields["id"] == Scalar::String("acme.app".into()) => {
                Some(fields)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(target["version"], Scalar::String("1".into()));
    assert_ne!(target["version"], Scalar::String("2".into()));
}

#[test]
fn secret_fields_and_paths_are_never_visible_to_group_inputs() {
    use rss_mdm_inventory::{Catalog, Sensitivity};
    let mut secret = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.software.installations")
        .unwrap();
    secret.key = FieldKey::parse("custom.secret_material").unwrap();
    secret.sensitivity = Sensitivity::Secret;
    secret.manual = false;
    secret.sources.remove(&rss_mdm_inventory::Source::Manual);
    secret.searchable = false;
    let catalog = Catalog::new(vec![secret.clone()]).unwrap();
    assert!(!fields::visible(&secret));
    for key in ["custom.secret_material", "custom.secret_material.name"] {
        let criteria = Criteria::Predicate {
            field: FieldKey::parse(key).unwrap(),
            op: Operator::IsNotNull,
            value: None,
            values: None,
        };
        assert!(filter::require_visible(&catalog, &criteria).is_err());
    }
}

#[test]
fn projected_directories_preserve_null_but_cannot_be_replayed_as_write_receipts() {
    let query = saved_directory::SCHEMA
        .parse("fields=name,definition")
        .unwrap();
    let projected = query
        .project_typed(saved_directory::Row {
            id: Uuid::nil(),
            revision: 1,
            name: None,
            deleted: true,
            definition: None,
        })
        .unwrap();
    let envelope = AssetEnvelope {
        tenant_id: "tenant".into(),
        asset: Response::SavedList {
            items: vec![projected],
            next_cursor: None,
        },
    };
    let wire = serde_json::to_value(envelope).unwrap();
    assert_eq!(
        wire["asset"]["items"][0],
        serde_json::json!({"name":null,"definition":null})
    );
    assert!(serde_json::from_value::<AssetEnvelope>(wire).is_err());
    assert!(serde_json::from_value::<AssetEnvelope>(serde_json::json!({"tenantId":"tenant","asset":{"kind":"field_list","dictionary":"fields","items":[],"nextCursor":null}})).is_err());
}
