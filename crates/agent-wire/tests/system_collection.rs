use rss_mdm_agent_wire::{CollectionScope, runtime::*};
use serde_json::json;
use std::collections::BTreeMap;
fn query(recipe: NativeSystemQuery) -> NativeQuery {
    NativeQuery {
        version: recipe.engine().contract_version(),
        cardinality: recipe.cardinality(),
        instance_keys: if recipe.cardinality() == NativeCardinality::List {
            vec!["id".into()]
        } else {
            vec![]
        },
        definition: NativeQueryDefinition::System { query: recipe },
        budget: NativeBudget {
            timeout_seconds: 60,
            output_bytes: 65536,
            max_rows: 100,
        },
    }
}
fn plan(q: NativeQuery) -> NativeCollectionPlan {
    NativeCollectionPlan::new(NativePlanSpec {
        version: 1,
        scope: CollectionScope::Device,
        budget: q.budget,
        queries: [("facts".into(), q)].into(),
    })
    .unwrap()
}
fn answer(q: &NativeQuery, rows: serde_json::Value) -> NativeQueryResult {
    NativeQueryResult {
        scan: None,
        query_digest: q.digest(),
        collected_at: 100,
        status: NativeQueryStatus::Complete,
        enumeration_complete: true,
        row_count: rows.as_array().unwrap().len() as u32,
        rows: serde_json::from_value(rows).unwrap(),
        users: None,
    }
}
#[test]
fn certificate_metadata_is_closed_even_for_failed_partial_results() {
    let q = query(NativeSystemQuery::WindowsCertificates {
        store: WindowsCertificateStore::My,
        user: false,
    });
    let p = plan(q.clone());
    let row = json!({"id":"a".repeat(64),"subject":"CN=Device","issuer":"CN=CA","not_before":1,"not_after":200,"scope":"device","owner":"","store":"my"});
    for status in [
        NativeQueryStatus::Complete,
        NativeQueryStatus::Partial,
        NativeQueryStatus::Denied,
        NativeQueryStatus::Failed,
    ] {
        let mut r = answer(&q, json!([row]));
        r.status = status;
        let envelope = |r| NativeCollectionResult {
            plan_digest: p.digest(),
            collected_at: 100,
            queries: [("facts".into(), r)].into(),
        };
        assert!(envelope(r.clone()).validate_for(&p, 100).is_ok());
        for key in [
            "private_key",
            "password",
            "hash",
            "der",
            "pfx",
            "recovery_key",
        ] {
            let mut bad = r.clone();
            bad.rows[0].insert(key.into(), json!("forbidden"));
            assert!(
                envelope(bad).validate_for(&p, 100).is_err(),
                "{status:?}/{key}"
            );
        }
        assert_eq!(
            r.complete_for(&q, 100),
            status == NativeQueryStatus::Complete
        );
    }
    let empty = answer(&q, json!([]));
    assert!(empty.complete_for(&q, 100));
    let mut wrong = answer(&q, json!([row]));
    wrong.rows[0].insert("store".into(), json!("root"));
    assert!(!wrong.complete_for(&q, 100));
}
#[test]
fn updates_require_real_scan_provenance_even_for_empty_sets() {
    for mode in [UpdateScanMode::Local, UpdateScanMode::Online] {
        let q = query(NativeSystemQuery::WindowsUpdates {
            section: UpdateSection::Available,
            mode,
        });
        let mut r = answer(&q, json!([]));
        assert!(!r.complete_for(&q, 100));
        r.scan = Some(NativeScanEvidence {
            mode,
            source: Some("configured-wua".into()),
            started_at: Some(80),
            finished_at: Some(90),
        });
        assert!(r.complete_for(&q, 100));
        for status in [
            NativeQueryStatus::NotScanned,
            NativeQueryStatus::SourceUnavailable,
            NativeQueryStatus::Failed,
            NativeQueryStatus::Partial,
            NativeQueryStatus::Truncated,
        ] {
            let mut failed = r.clone();
            failed.status = status;
            assert!(!failed.complete_for(&q, 100));
        }
        r.scan.as_mut().unwrap().source = Some("https://user:secret@host/".into());
        assert!(!r.complete_for(&q, 100));
    }
    assert!(
        NativeSystemQuery::WindowsUpdates {
            section: UpdateSection::Installed,
            mode: UpdateScanMode::Online
        }
        .validate()
        .is_err()
    );
}
#[test]
fn reboot_observations_do_not_require_a_completed_scan() {
    for recipe in [
        NativeSystemQuery::WindowsUpdates {
            section: UpdateSection::Reboot,
            mode: UpdateScanMode::Local,
        },
        NativeSystemQuery::MacosUpdates {
            section: UpdateSection::Reboot,
            mode: UpdateScanMode::Local,
        },
    ] {
        let q = query(recipe);
        let p = plan(q.clone());
        let envelope = |r| NativeCollectionResult {
            plan_digest: p.digest(),
            collected_at: 100,
            queries: [("facts".into(), r)].into(),
        };
        for state in ["required", "not_required", "unknown"] {
            let mut r = answer(&q, json!([{"state": state}]));
            r.scan = Some(NativeScanEvidence {
                mode: UpdateScanMode::Local,
                source: None,
                started_at: None,
                finished_at: None,
            });
            assert!(r.complete_for(&q, 100));
            assert!(envelope(r.clone()).validate_for(&p, 100).is_ok());
            let encoded = serde_json::to_value(&r).unwrap();
            for invalid_scan in [
                serde_json::Value::Null,
                json!({"mode":"online"}),
                json!({"mode":"local","source":"https://user:secret@host/"}),
                json!({"mode":"local","startedAt":0}),
                json!({"mode":"local","startedAt":101}),
                json!({"mode":"local","finishedAt":90}),
                json!({"mode":"local","startedAt":90,"finishedAt":80}),
                json!({"mode":"local","startedAt":80,"finishedAt":101}),
            ] {
                let mut bad = encoded.clone();
                bad["scan"] = invalid_scan;
                let bad: NativeQueryResult = serde_json::from_value(bad).unwrap();
                assert!(!bad.complete_for(&q, 100));
                assert!(envelope(bad).validate_for(&p, 100).is_err());
            }
        }
    }
}
#[test]
fn scan_backed_sections_still_require_completed_scan_evidence() {
    for section in [
        UpdateSection::Scan,
        UpdateSection::Available,
        UpdateSection::Installed,
        UpdateSection::History,
    ] {
        for recipe in [
            NativeSystemQuery::WindowsUpdates {
                section,
                mode: UpdateScanMode::Local,
            },
            NativeSystemQuery::MacosUpdates {
                section,
                mode: UpdateScanMode::Local,
            },
        ] {
            let q = query(recipe);
            let p = plan(q.clone());
            let mut r = answer(&q, json!([]));
            r.scan = Some(NativeScanEvidence {
                mode: UpdateScanMode::Local,
                source: None,
                started_at: None,
                finished_at: None,
            });
            let envelope = |r| NativeCollectionResult {
                plan_digest: p.digest(),
                collected_at: 100,
                queries: [("facts".into(), r)].into(),
            };
            assert!(!r.complete_for(&q, 100));
            assert!(envelope(r.clone()).validate_for(&p, 100).is_err());
            r.scan = Some(NativeScanEvidence {
                mode: UpdateScanMode::Local,
                source: Some("configured-source".into()),
                started_at: Some(80),
                finished_at: Some(90),
            });
            assert!(envelope(r).validate_for(&p, 100).is_ok());
        }
    }
}
#[test]
fn windows_sid_and_macos_generated_uid_bind_the_current_session() {
    for (platform, recipe, identity, guid) in [
        (
            TaskPlatform::Windows,
            NativeSystemQuery::WindowsCertificates {
                store: WindowsCertificateStore::My,
                user: true,
            },
            "S-1-5-21-1-2-3-1001",
            None,
        ),
        (
            TaskPlatform::Macos,
            NativeSystemQuery::MacosCertificates {
                store: MacosCertificateStore::Login,
            },
            "501",
            Some("00000000-0000-0000-0000-000000000501"),
        ),
    ] {
        let p = plan(query(recipe));
        let context:SoftwareExecutionContext=serde_json::from_value(json!({"revision":1,"osVersion":[15,0,0,0],"systemBroker":true,"userHelper":true,"interactiveUser":{"identity":identity,"generatedUid":guid,"sessionId":uuid::Uuid::new_v4(),"administrator":false},"msixSideload":false,"msixUnsigned":false,"sourceCredentials":[]})).unwrap();
        let binding = NativeExecutionBinding::bind(&p, &context).unwrap();
        if platform == TaskPlatform::Windows {
            for sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"] {
                let mut service = context.clone();
                service.interactive_user.as_mut().unwrap().identity = sid.into();
                assert!(NativeExecutionBinding::bind(&p, &service).is_err());
            }
        }
        assert!(binding.matches_context(&p, &context));
        let mut changed = context.clone();
        changed.interactive_user.as_mut().unwrap().session_id = uuid::Uuid::new_v4();
        assert!(!binding.matches_context(&p, &changed));
        if platform == TaskPlatform::Macos {
            changed = context.clone();
            changed.interactive_user.as_mut().unwrap().generated_uid =
                Some("00000000-0000-0000-0000-000000000502".into());
            assert!(!binding.matches_context(&p, &changed));
        }
        changed = context.clone();
        changed.interactive_user = None;
        assert!(NativeExecutionBinding::bind(&p, &changed).is_err());
    }
}
#[test]
fn configured_presence_and_running_evidence_are_not_interchangeable() {
    let q = query(NativeSystemQuery::WindowsBitlocker);
    let r = answer(
        &q,
        json!([{"id":"volume-guid","conversion":"encrypted","protection":"unprotected","lock":"unlocked","algorithm":"XTS_AES_256","encrypted_percent":100}]),
    );
    assert!(r.complete_for(&q, 100));
    let q = query(NativeSystemQuery::WindowsDefender);
    assert!(answer(&q,json!([{"presence":"present","configured":"enabled","running":"disabled","mode":"passive","health":"passive","signature_version":"1"}])).complete_for(&q,100));
    let q = query(NativeSystemQuery::WindowsFirewall);
    assert!(answer(&q,json!([{"id":"domain","configured":"enabled","running":"enabled"},{"id":"private","configured":"enabled","running":"disabled"},{"id":"public","configured":"disabled","running":"disabled"}])).complete_for(&q,100));
    let q = NativeSystemQuery::MacosSecurity {
        section: MacosSecuritySection::Gatekeeper,
    };
    let row: BTreeMap<_, _> = serde_json::from_value(
        json!({"presence":"present","configured":"enabled","running":"unknown","version":"1"}),
    )
    .unwrap();
    assert!(q.accepts_row(&row));
    assert!(!q.accepts_row(&serde_json::from_value(json!({"running":true})).unwrap()));
}
#[test]
fn selected_accounts_do_not_expand_to_unapproved_identities() {
    let q = query(NativeSystemQuery::MacosAccounts {
        section: AccountSection::Accounts,
        selection: AccountSelection::Selected {
            identities: ["00000000-0000-0000-0000-000000000501".into()].into(),
        },
    });
    let row = json!({"id":"00000000-0000-0000-0000-000000000501","uid":501,"name":"user","account_type":"local","enabled":"enabled"});
    assert!(answer(&q, json!([row])).complete_for(&q, 100));
    let mut bad = row;
    bad["id"] = json!("00000000-0000-0000-0000-000000000502");
    assert!(!answer(&q, json!([bad])).complete_for(&q, 100));
}

#[test]
fn unknown_bitlocker_columns_are_partial_evidence_not_new_inventory_enum_values() {
    let q = query(NativeSystemQuery::WindowsBitlocker);
    let mut rows = json!([{"id":"volume-a","conversion":"encrypted","protection":"protected","lock":"unlocked","algorithm":"XTS_AES_256","encrypted_percent":100},
        {"id":"volume-b","conversion":"encrypted","protection":"unknown","algorithm":"XTS_AES_256","encrypted_percent":100}]);
    // A failed lock read is omitted, preserving the old full list while retaining known evidence.
    let mut result = answer(&q, rows.clone());
    assert!(!result.complete_for(&q, 100));
    result.status = NativeQueryStatus::Partial;
    let p = plan(q.clone());
    assert!(
        NativeCollectionResult {
            plan_digest: p.digest(),
            collected_at: 100,
            queries: [("facts".into(), result)].into()
        }
        .validate_for(&p, 100)
        .is_ok()
    );
    rows[1]["lock"] = json!("unknown");
    assert!(
        !q.definition
            .accepts_row(&serde_json::from_value(rows[1].clone()).unwrap())
    );
}

#[test]
fn system_plan_requires_bounded_inline_output_and_does_not_downgrade_to_chunks() {
    let mut q = query(NativeSystemQuery::WindowsCertificates {
        store: WindowsCertificateStore::My,
        user: false,
    });
    q.budget.output_bytes = NATIVE_SYSTEM_MAX_BYTES;
    let p = plan(q.clone());
    assert!(p.requires_inline());
    q.budget.output_bytes = NATIVE_SYSTEM_MAX_BYTES + 1;
    assert!(q.validate().is_err());
    let mut input = p.spec().clone();
    input.budget.output_bytes = NATIVE_SYSTEM_MAX_BYTES + 1;
    assert!(NativeCollectionPlan::new(input).is_err());
}

#[test]
fn complete_application_probe_cannot_omit_or_duplicate_requested_permissions() {
    let q = query(NativeSystemQuery::MacosApplication {
        target: MacosApplicationTarget::Agent,
        permissions: [ApplicationPermission::FullDiskAccess].into(),
    });
    let mut row = json!({"identity":"io.rss.agent","signer":"RSS","presence":"present","signature":"unknown","running":"unknown","health":"unknown","permissions":[]});
    assert!(!answer(&q, json!([row])).complete_for(&q, 100));
    row["permissions"] = json!(["full_disk_access:unknown"]);
    assert!(answer(&q, json!([row])).complete_for(&q, 100));
    row["permissions"] = json!(["full_disk_access:unknown", "full_disk_access:granted"]);
    assert!(!answer(&q, json!([row])).complete_for(&q, 100));
}
