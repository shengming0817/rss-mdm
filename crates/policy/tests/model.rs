use rss_mdm_policy::*;
use serde_json::{Value, json};
use uuid::Uuid;

#[test]
fn stored_execution_identities_survive_typed_resource_selection() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/semantic-identities.json")).unwrap();
    for fixture in fixtures.as_array().unwrap() {
        let definition: Definition = serde_json::from_value(fixture["definition"].clone()).unwrap();
        definition.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&definition).unwrap(),
            fixture["definition"]
        );
        let digest: String = definition
            .semantic()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest,
            fixture["digest"].as_str().unwrap(),
            "{:?}",
            definition.action.kind()
        );
    }
}

#[test]
fn resource_selection_matches_the_authored_action() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/semantic-identities.json")).unwrap();
    let exact = fixtures[0]["definition"]["action"]["resource"].clone();
    let software = fixtures[3]["definition"]["action"]["resource"].clone();
    for index in [0, 1, 2, 3, 4] {
        let mut invalid = fixtures[index]["definition"].clone();
        invalid["action"]["resource"] = if index < 3 {
            software.clone()
        } else {
            exact.clone()
        };
        assert!(serde_json::from_value::<Definition>(invalid).is_err());
    }
}

#[test]
fn closed_action_identity_parses_every_kind_and_rejects_unknown() {
    for kind in ActionKind::ALL {
        assert_eq!(
            serde_json::from_value::<ActionKind>(json!(kind.as_str())).unwrap(),
            kind
        );
    }
    assert!(serde_json::from_value::<ActionKind>(json!("plugin")).is_err());
}
#[test]
fn targets_and_enablement_do_not_create_execution_versions() {
    let id = Uuid::new_v4();
    let definition:Definition=serde_json::from_value(json!({"scope":"11111111-1111-1111-1111-111111111111","action": {"resource": {"id":"r","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"execution","parameters":{},"runLifetimeSeconds":300}})).unwrap();
    let first = Policy::apply(
        id,
        None,
        0,
        &Change::Put {
            definition: Box::new(definition.clone()),
            enabled: true,
        },
        Uuid::new_v4(),
        None,
    )
    .unwrap();
    let disabled = Policy::apply(
        id,
        Some(&first.policy),
        1,
        &Change::Disable,
        Uuid::new_v4(),
        None,
    )
    .unwrap();
    assert_eq!(disabled.policy.version, first.policy.version);
    assert!(!disabled.semantic_changed);
    assert_eq!(disabled.policy.revision, 2);
    let mut expanded = definition;
    expanded.scope = Uuid::new_v4();
    let second = Policy::apply(
        id,
        Some(&disabled.policy),
        2,
        &Change::Put {
            definition: Box::new(expanded),
            enabled: true,
        },
        Uuid::new_v4(),
        None,
    )
    .unwrap();
    assert_eq!(second.policy.number, 1);
    assert!(!second.semantic_changed);
    assert!(matches!(
        Policy::apply(
            id,
            Some(&second.policy),
            2,
            &Change::Disable,
            Uuid::new_v4(),
            None
        ),
        Err(Error::Conflict)
    ));
}

#[test]
fn invalid_restored_aggregate_cannot_produce_checked_change() {
    let definition:Definition=serde_json::from_value(json!({"scope":Uuid::new_v4(),"action": {"resource": {"id":"r","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration"}})).unwrap();
    let id = Uuid::new_v4();
    for (revision, number, version) in [
        (0, 0, Uuid::nil()),
        (1, 0, Uuid::new_v4()),
        (1, 1, Uuid::nil()),
        (1, 2, Uuid::new_v4()),
    ] {
        let old = Policy {
            execution_binding: None,
            id,
            revision,
            number,
            version,
            state: rss_mdm_policy::State::Enabled,
            definition: definition.clone(),
        };
        assert!(matches!(
            Policy::apply(
                id,
                Some(&old),
                revision as u64,
                &Change::Enable,
                Uuid::new_v4(),
                None
            ),
            Err(Error::Malformed)
        ));
    }
}
#[test]
fn native_delivery_source_and_ring_are_execution_semantics() {
    let id = uuid::Uuid::new_v4();
    let mut value = serde_json::json!({"scope":id,"action":{"kind":"software","channel":"agent","resource":{"kind":"software","id":"acme","version":"1","variants":{"windows_x86_64":"default"}},"delivery":{"kind":"direct"},"intent":"required_install","runLifetimeSeconds":600,"rollout":{"stages":[{"scope":id,"opensAt":0}]}}});
    let direct: rss_mdm_policy::Definition = serde_json::from_value(value.clone()).unwrap();
    value["action"]["delivery"] =
        serde_json::json!({"kind":"native","source":"enterprise","ring":"test"});
    let test: rss_mdm_policy::Definition = serde_json::from_value(value.clone()).unwrap();
    value["action"]["delivery"]["ring"] = serde_json::json!("production");
    let production: rss_mdm_policy::Definition = serde_json::from_value(value.clone()).unwrap();
    assert_ne!(direct.semantic().unwrap(), test.semantic().unwrap());
    assert_ne!(test.semantic().unwrap(), production.semantic().unwrap());
    value["action"].as_object_mut().unwrap().remove("delivery");
    assert!(serde_json::from_value::<rss_mdm_policy::Definition>(value).is_err());
}

#[test]
fn parameter_sources_and_self_service_have_independent_versions() {
    let id = Uuid::new_v4();
    let mut value = json!({"scope":id,"action":{"kind":"execution","resource":{"id":"r","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"parameters":{"path":{"kind":"fixed","value":"/Applications"},"name":{"kind":"input"}},"schedule":{"trigger":{"kind":"manual"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null},"runLifetimeSeconds":300},"selfService":{"access":{"kind":"authenticated_user"},"published":true,"displayName":"Repair","description":"Repair application","prerequisites":"","sideEffects":"Restart","category":"Support","keywords":[]}});
    let apply = |old: Option<&Policy>, v: serde_json::Value| {
        Policy::apply(
            id,
            old,
            old.map_or(0, |p| p.revision as u64),
            &Change::Put {
                definition: Box::new(serde_json::from_value(v).unwrap()),
                enabled: true,
            },
            Uuid::new_v4(),
            None,
        )
        .unwrap()
    };
    let first = apply(None, value.clone());
    let config = first.policy.definition.self_service.as_ref().unwrap();
    assert_eq!(config.allow_ai, Some(true));
    assert_eq!(config.risk_level, Some(ScriptRisk::CONFIRM));
    value["selfService"]["allowAi"] = json!(false);
    value["selfService"]["riskLevel"] = json!(1);
    let second = apply(Some(&first.policy), value.clone());
    assert!(!second.semantic_changed);
    assert_eq!(second.policy.version, first.policy.version);
    value["selfService"]
        .as_object_mut()
        .unwrap()
        .remove("allowAi");
    value["selfService"]
        .as_object_mut()
        .unwrap()
        .remove("riskLevel");
    let third = apply(Some(&second.policy), value.clone());
    assert_eq!(
        third
            .policy
            .definition
            .self_service
            .as_ref()
            .unwrap()
            .allow_ai,
        Some(false)
    );
    assert_eq!(
        third
            .policy
            .definition
            .self_service
            .as_ref()
            .unwrap()
            .risk_level,
        Some(ScriptRisk::DIRECT)
    );
    value["action"]["parameters"]["path"]["value"] = json!("/Library");
    assert!(apply(Some(&third.policy), value.clone()).semantic_changed);
    value["action"]["schedule"]["trigger"] = json!({"kind":"check_in","minimumSeconds":60});
    assert!(
        serde_json::from_value::<Definition>(value)
            .unwrap()
            .validate()
            .is_err()
    );
}
#[test]
fn input_is_exact_and_cannot_override_fixed_values() {
    let sources: ParameterSources = serde_json::from_value(
        json!({"path":{"kind":"fixed","value":"/Applications"},"name":{"kind":"input"}}),
    )
    .unwrap();
    assert_eq!(
        sources.resolve(&json!({"name":"App"})).unwrap(),
        json!({"name":"App","path":"/Applications"})
    );
    for invalid in [
        json!({}),
        json!({"path":"/tmp"}),
        json!({"name":"App","path":"/tmp"}),
        json!({"name":"App","extra":1}),
    ] {
        assert!(sources.resolve(&invalid).is_err());
    }
    for invalid in [
        json!({"name":"old literal"}),
        json!({"name":{"kind":"input","default":"x"}}),
        json!({"name":{"kind":"fixed","value":[],"schema":{}}}),
    ] {
        assert!(serde_json::from_value::<ParameterSources>(invalid).is_err());
    }
    for invalid in [0, 3, 255] {
        assert!(serde_json::from_value::<ScriptRisk>(json!(invalid)).is_err());
    }
}

#[test]
fn self_service_requires_explicit_bounded_access_and_supports_only_available_software() {
    let id = Uuid::new_v4();
    let base = json!({"scope":id,"action":{"kind":"execution","resource":{"id":"r","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"parameters":{},"runLifetimeSeconds":300},"selfService":{"access":{"kind":"device"},"published":true,"displayName":"Repair","description":"","prerequisites":"","sideEffects":"","category":"Support","keywords":[]}});
    let mut missing = base.clone();
    missing["selfService"]
        .as_object_mut()
        .unwrap()
        .remove("access");
    assert!(serde_json::from_value::<Definition>(missing).is_err());
    for access in [
        json!(null),
        json!({"kind":"users","selectors":[]}),
        json!({"kind":"users","selectors":[{"kind":"user_group","id":id},{"kind":"user_group","id":id}]}),
        json!({"kind":"users","selectors":(0..257).map(|_|json!({"kind":"user_group","id":Uuid::new_v4()})).collect::<Vec<_>>()}),
    ] {
        let mut invalid = base.clone();
        invalid["selfService"]["access"] = access;
        assert!(
            serde_json::from_value::<Definition>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut draft = base.clone();
    draft["selfService"]["access"] = Value::Null;
    draft["selfService"]["published"] = json!(false);
    assert!(
        serde_json::from_value::<Definition>(draft)
            .unwrap()
            .validate()
            .is_ok()
    );
    for kind in ["device", "authenticated_user"] {
        let mut valid = base.clone();
        valid["selfService"]["access"] = json!({"kind":kind});
        assert!(
            serde_json::from_value::<Definition>(valid)
                .unwrap()
                .validate()
                .is_ok()
        );
    }
    for intent in [
        "available_install",
        "required_install",
        "explicit_uninstall",
    ] {
        let mut software = base.clone();
        software["action"] = json!({"kind":"software","channel":"agent","resource":{"kind":"software","id":"acme","version":"1","variants":{"macos_aarch64":"default"}},"delivery":{"kind":"direct"},"intent":intent,"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":id,"opensAt":0}]}});
        assert_eq!(
            serde_json::from_value::<Definition>(software.clone())
                .unwrap()
                .validate()
                .is_ok(),
            intent == "available_install"
        );
        software["selfService"]["riskLevel"] = json!(1);
        assert!(
            serde_json::from_value::<Definition>(software)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

#[test]
fn software_lifecycle_generation_requires_a_new_execution_version() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/semantic-identities.json")).unwrap();
    let definition: Definition = serde_json::from_value(fixtures[3]["definition"].clone()).unwrap();
    let change = Change::Put {
        definition: Box::new(definition.clone()),
        enabled: true,
    };
    let id = Uuid::new_v4();
    assert!(Policy::apply(id, None, 0, &change, Uuid::new_v4(), None).is_err());
    let initial = Policy::apply(id, None, 0, &change, Uuid::new_v4(), Some([1; 32])).unwrap();
    let unchanged = Policy::apply(
        id,
        Some(&initial.policy),
        1,
        &change,
        Uuid::new_v4(),
        Some([1; 32]),
    )
    .unwrap();
    assert_eq!(initial.policy.version, unchanged.policy.version);
    let renewed = Policy::apply(
        id,
        Some(&unchanged.policy),
        2,
        &change,
        Uuid::new_v4(),
        Some([2; 32]),
    )
    .unwrap();
    assert_ne!(initial.policy.version, renewed.policy.version);
    assert_eq!(renewed.policy.number, 2);
    let mut retired = serde_json::to_value(definition).unwrap();
    retired["action"]["admissionOperation"] = json!(Uuid::new_v4());
    assert!(serde_json::from_value::<Definition>(retired).is_err());
}

#[test]
fn archive_is_terminal_and_preserves_semantic_history() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/semantic-identities.json")).unwrap();
    let definition: Definition = serde_json::from_value(fixtures[0]["definition"].clone()).unwrap();
    let id = Uuid::new_v4();
    let enabled = Policy::apply(
        id,
        None,
        0,
        &Change::Put {
            definition: Box::new(definition.clone()),
            enabled: true,
        },
        Uuid::new_v4(),
        None,
    )
    .unwrap()
    .policy;
    assert_eq!(
        Policy::apply(
            id,
            Some(&enabled),
            1,
            &Change::Archive,
            Uuid::new_v4(),
            None
        )
        .err(),
        Some(Error::Conflict)
    );
    let disabled = Policy::apply(
        id,
        Some(&enabled),
        1,
        &Change::Disable,
        Uuid::new_v4(),
        None,
    )
    .unwrap()
    .policy;
    let archived = Policy::apply(
        id,
        Some(&disabled),
        2,
        &Change::Archive,
        Uuid::new_v4(),
        None,
    )
    .unwrap();
    assert!(!archived.semantic_changed);
    assert_eq!(archived.policy.version, enabled.version);
    assert_eq!(archived.policy.number, enabled.number);
    assert_eq!(archived.policy.state, State::Archived);
    for command in [
        Change::Enable,
        Change::Disable,
        Change::Archive,
        Change::Put {
            definition: Box::new(definition),
            enabled: false,
        },
    ] {
        assert_eq!(
            Policy::apply(
                id,
                Some(&archived.policy),
                3,
                &command,
                Uuid::new_v4(),
                None
            )
            .err(),
            Some(Error::Conflict)
        );
    }
    assert!(serde_json::from_value::<Change>(json!({"action":"archive"})).is_err());
    let view = serde_json::to_value(View::from(&archived.policy)).unwrap();
    assert_eq!(view["state"], "archived");
    assert!(view.get("enabled").is_none());
    assert_eq!(
        serde_json::to_value(Change::Archive).unwrap(),
        json!({"action":"archive"})
    );
}

#[test]
fn software_channel_defaults_only_at_the_management_boundary() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/semantic-identities.json")).unwrap();
    let mut definition = fixtures[3]["definition"].clone();
    definition["action"]
        .as_object_mut()
        .unwrap()
        .remove("channel");
    assert!(serde_json::from_value::<Definition>(definition.clone()).is_err());
    let change: Change =
        serde_json::from_value(json!({"action":"put","enabled":false,"definition":definition}))
            .unwrap();
    let Change::Put { definition, .. } = change else {
        panic!("put")
    };
    assert_eq!(
        definition.action.target_channel(),
        Some(SoftwareChannel::Agent)
    );
    let agent = definition.semantic().unwrap();
    let mut mdm = (*definition).clone();
    if let Action::Software { channel, .. } = &mut mdm.action {
        *channel = SoftwareChannel::Mdm;
    }
    assert_ne!(agent, mdm.semantic().unwrap());
    assert_eq!(mdm.action.target_channel(), Some(SoftwareChannel::Mdm));
}
