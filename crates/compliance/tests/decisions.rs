use rss_mdm_compliance::{Current as C, Decision as D, Status as S, aggregate, assess};
#[test]
fn applicability_and_missing_evidence_cannot_pass() {
    for condition in [D::Match, D::NoMatch, D::Unknown] {
        assert_eq!(assess(D::NoMatch, condition), S::NotApplicable);
        assert_eq!(assess(D::Unknown, condition), S::Unknown);
    }
    assert_eq!(assess(D::Match, D::Match), S::Compliant);
    assert_eq!(assess(D::Match, D::NoMatch), S::NonCompliant);
    assert_eq!(assess(D::Match, D::Unknown), S::Unknown);
}
#[test]
fn complete_current_summary_distinguishes_missing_rules_and_unfinished_work() {
    assert_eq!(aggregate([]), C::Unknown);
    assert_eq!(aggregate([C::NotApplicable]), C::NotApplicable);
    assert_eq!(aggregate([C::NotApplicable, C::Compliant]), C::Compliant);
    assert_eq!(aggregate([C::Pending, C::Compliant]), C::Pending);
    assert_eq!(aggregate([C::Pending, C::Unknown]), C::Unknown);
    assert_eq!(
        aggregate([C::NonCompliant, C::Unknown, C::Pending]),
        C::NonCompliant
    );
}

#[test]
fn assessment_preserves_all_platform_sources_and_field_datasets() {
    use rss_mdm_compliance::{
        Applicability, Assessment, Definition, FactReference, FieldEvidence, Input, Platform,
        Severity, SourceReference, Target,
    };
    let input = Input {
        rule: uuid::Uuid::new_v4(),
        revision: 1,
        asset_cut: "fixture-cut".to_owned(),
        evaluated_at: 1,
        definition: Definition {
            presentation: serde_json::json!({"name":"Agent policy"})
                .as_object()
                .unwrap()
                .clone(),
            severity: Severity::High,
            enabled: true,
            platform: Platform::All,
            target: Target::All,
            criteria: (),
        },
        groups: vec![],
    };
    let sources = ["agent.builtin", "agent.script", "agent.osquery"]
        .map(|source| SourceReference {
            source: source.into(),
            device_id: rss_mdm_agent_wire::DeviceId::parse("921af465-7e0a-5bc3-80bf-96ae31b07ccd")
                .unwrap(),
            epoch: "epoch".into(),
        })
        .to_vec();
    let datasets = ["device_identity", "hardware", "inventory"];
    let evidence = FieldEvidence {
        context: "device".into(),
        field: "device.os.name".into(),
        sources: datasets
            .map(|dataset| FactReference {
                source: "mdm.windows".into(),
                dataset: Some(dataset.into()),
                device_id: Some(
                    rss_mdm_agent_wire::DeviceId::parse("00000000-0000-0000-0000-000000000001")
                        .unwrap(),
                ),
                epoch: Some("epoch".into()),
                snapshot_id: format!("{dataset}-snapshot"),
                observed_at: 1,
                received_at: 1,
                actor: None,
            })
            .to_vec(),
    };
    let result = Assessment::evaluate(
        &input,
        "dictionary",
        D::Match,
        Applicability {
            platform: Platform::All,
            platform_decision: D::Match,
            sources,
            groups: vec![],
        },
        vec![],
        vec![evidence],
    )
    .unwrap();
    assert_eq!(result.status, S::Compliant);
    assert_eq!(
        result.evidence[0]
            .sources
            .iter()
            .map(|source| source.dataset.as_deref().unwrap())
            .collect::<Vec<_>>(),
        datasets,
    );
    assert_eq!(
        result
            .applicability
            .sources
            .iter()
            .map(|v| v.source.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        ["agent.builtin", "agent.script", "agent.osquery"]
            .into_iter()
            .collect()
    );
}

#[test]
fn validation_errors_are_closed_and_do_not_echo_inputs() {
    use rss_mdm_compliance::{
        Applicability, Assessment, Definition, FieldEvidence, Input, Invalid, Platform, Severity,
        Target,
    };
    let mut definition = Definition {
        presentation: serde_json::json!({"name":"secret\nvalue"})
            .as_object()
            .unwrap()
            .clone(),
        severity: Severity::High,
        enabled: true,
        platform: Platform::All,
        target: Target::All,
        criteria: (),
    };
    assert_eq!(definition.validate(), Err(Invalid::Definition));
    assert_eq!(
        definition.validate().unwrap_err().to_string(),
        "invalid compliance definition"
    );
    definition
        .presentation
        .insert("name".into(), serde_json::json!("policy"));
    let mut input = Input {
        rule: uuid::Uuid::nil(),
        revision: 1,
        asset_cut: "fixture-cut".to_owned(),
        evaluated_at: 1,
        definition,
        groups: vec![],
    };
    assert_eq!(input.validate(), Err(Invalid::Input));
    input.rule = uuid::Uuid::new_v4();
    let applicable = Applicability {
        platform: Platform::All,
        platform_decision: D::Match,
        sources: vec![],
        groups: vec![],
    };
    assert_eq!(
        Assessment::evaluate(&input, "", D::Match, applicable.clone(), vec![], vec![]).unwrap_err(),
        Invalid::Assessment
    );
    assert_eq!(
        Assessment::evaluate(
            &input,
            "dictionary",
            D::Match,
            applicable,
            vec![],
            vec![FieldEvidence {
                context: "default".into(),
                field: "".into(),
                sources: vec![]
            }]
        )
        .unwrap_err(),
        Invalid::Evidence
    );
}
