use super::codec;
use rss_contract::Timepoint;
use rss_mdm_group::*;
use rss_request_context::TenantId;
use std::collections::{BTreeMap, BTreeSet};
fn inputs() -> (Rule, FixturePage, Timepoint) {
    let t = TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let now = Timepoint::try_from(10).unwrap();
    let field = Field {
        key: "model".into(),
        kind: FieldType::Scalar(ScalarType::String),
        unit: None,
        operations: BTreeSet::from([Op::Eq]),
        nullable: true,
    };
    let rule = Rule::new(
        t,
        "r1",
        "d1",
        vec![field],
        Criteria::predicate(Predicate {
            field: "model".into(),
            op: Op::Eq,
            operand: Some(Operand {
                value: Value::Scalar(Scalar::String("设备\n%".into())),
                unit: None,
            }),
        })
        .unwrap(),
    )
    .unwrap();
    let snapshot = FixturePage {
        tenant: t,
        id: "s".into(),
        version: "v1".into(),
        dictionary_version: "d1".into(),
        coverage: BTreeSet::from(["model".into()]),
        objects: vec![ObjectSnapshot {
            key: ObjectKey::new(t, "device").unwrap(),
            facts: BTreeMap::from([(
                "model".into(),
                Fact {
                    state: FactState::Missing,
                    source: "fixture".into(),
                    snapshot_id: "s".into(),
                    observed_at: now,
                },
            )]),
        }],
    };
    (rule, snapshot, now)
}
#[test]
fn rule_round_trip_and_bounded_page_encoding_preserve_decisions() {
    let (rule, page, at) = inputs();
    let restored = codec::decode_rule(&codec::encode_rule(&rule).unwrap()).unwrap();
    assert_eq!(
        rule.evaluate_page(&page.input(), at),
        restored.evaluate_page(&page.input(), at)
    );
    let encoded = codec::encode_page(&page.input()).unwrap();
    assert_eq!(encoded, codec::encode_page(&page.input()).unwrap());
    let mut changed = page.clone();
    changed.objects[0].facts.get_mut("model").unwrap().state = FactState::Null;
    assert_ne!(encoded, codec::encode_page(&changed.input()).unwrap());
}
#[test]
fn page_encoding_rejects_duplicate_devices() {
    let (_, mut page, _) = inputs();
    page.objects.push(page.objects[0].clone());
    assert!(codec::encode_page(&page.input()).is_err());
}
#[test]
fn corrupt_or_unknown_codec_is_rejected() {
    assert!(codec::decode_rule(br#"{"v":99}"#).is_err());
    let (r, _, _) = inputs();
    let mut value: serde_json::Value =
        serde_json::from_slice(&codec::encode_rule(&r).unwrap()).unwrap();
    value["extra"] = true.into();
    assert!(codec::decode_rule(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn nested_typed_rules_and_all_fact_states_keep_their_meaning() {
    let (base, mut s, t) = inputs();
    let scalar_values = [
        Scalar::String("控制\0'\\%_".into()),
        Scalar::Boolean(true),
        Scalar::Integer(i64::MIN),
        Scalar::Time(t),
    ];
    for literal in scalar_values {
        for set in [false, true] {
            let op = if set { Op::ContainsAll } else { Op::Eq };
            let value = if set {
                Value::Set {
                    element: literal.kind(),
                    values: BTreeSet::from([literal.clone()]),
                }
            } else {
                Value::Scalar(literal.clone())
            };
            let field = Field {
                key: "model".into(),
                kind: if set {
                    FieldType::Set(literal.kind())
                } else {
                    FieldType::Scalar(literal.kind())
                },
                unit: None,
                operations: BTreeSet::from([op]),
                nullable: true,
            };
            let leaf = Criteria::predicate(Predicate {
                field: "model".into(),
                op,
                operand: Some(Operand {
                    value: value.clone(),
                    unit: None,
                }),
            })
            .unwrap();
            let tree = Criteria::and(vec![
                leaf.clone(),
                Criteria::or(vec![leaf.clone(), leaf]).unwrap(),
            ])
            .unwrap();
            let r = Rule::new(base.view().tenant, "typed", "d1", vec![field], tree).unwrap();
            let decoded = codec::decode_rule(&codec::encode_rule(&r).unwrap()).unwrap();
            for state in [
                FactState::Known(value.clone()),
                FactState::Null,
                FactState::Missing,
                FactState::Unsupported,
                FactState::Denied,
            ] {
                s.objects[0].facts.get_mut("model").unwrap().state = state;
                assert_eq!(
                    r.evaluate_page(&s.input(), t),
                    decoded.evaluate_page(&s.input(), t)
                );
                assert!(!codec::encode_page(&s.input()).unwrap().is_empty());
            }
        }
    }
}

#[test]
fn storage_diagnostics_survive_redaction_without_exposing_data() {
    use crate::storage::{StorageFault, data, document};
    use std::sync::{Arc, Mutex};
    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let output = bytes.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || Buffer(output.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        StorageFault::Contract.error();
        document(b"private-fact", &[0; 32]).unwrap_err();
        data::<()>(Err("private-document")).unwrap_err();
        StorageFault::RowCount.error();
        let cause = StorageFault::OutboxIdentity.error();
        assert_eq!(
            cause.kind(),
            rss_transactional_messaging::error::MessagingErrorKind::Invariant
        );
        let outcome = crate::Error::RolledBack(cause);
        assert!(matches!(outcome, crate::Error::RolledBack(_)));
        assert!(!format!("{outcome:?}").contains("private"));
    });
    let logs = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    for reason in [
        "storage_contract",
        "document_digest",
        "stored_shape",
        "row_count",
        "outbox_identity",
    ] {
        assert!(
            logs.contains(&format!("reason=\"group.{reason}\"")),
            "{logs}"
        );
    }
    assert_eq!(logs.lines().count(), 5);
    assert!(!logs.contains("private"));
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
