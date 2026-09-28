use crate::planning::test_support::*;

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=assets.http: real capability storage and transactions"]
async fn asset_commit_unknown_recovers_original_receipts() {
    use assets::{
        Command as AssetCommand, FieldKey, ManualChange, Owner, Query, SavedChange,
        SavedDefinition, Scalar,
    };
    let m = planning(tenant()).await;
    let device = format!("unknown-{}", Uuid::new_v4());
    seed_device(&device);
    let owner = Owner {
        instance: Uuid::new_v4().to_string(),
        principal: Uuid::new_v4().to_string(),
    };
    let id = Uuid::new_v4();
    let execution = [
        AssetCommand::Manual {
            device: device.clone(),
            field: FieldKey::AssetTag,
            change: operation(
                0,
                ManualChange::Set {
                    value: Scalar::String("retained".into()),
                },
            ),
            owner: owner.clone(),
        },
        AssetCommand::SavedWrite {
            id,
            owner,
            change: operation(
                0,
                SavedChange::Put {
                    definition: SavedDefinition {
                        name: "mine".into(),
                        query: Query::default(),
                    },
                },
            ),
        },
    ];
    let service = assets(&m).await;
    for command in execution {
        m.runtime.inject_next_transaction_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        assert!(matches!(
            execute_asset_service(&m, &service, &command).await,
            Err(Error::CommitUnknown)
        ));
        let recovered = execute_asset_service(&m, &service, &command).await.unwrap();
        assert_eq!(
            execute_asset_service(&m, &service, &command).await.unwrap(),
            recovered
        );
    }
    assert_eq!(
        sql(&format!(
            "SELECT revision FROM mdm.manual_assignments WHERE tenant_id='{}' AND device='{device}'",
            tenant()
        )),
        "1"
    );
    assert_eq!(
        sql(&format!(
            "SELECT revision FROM mdm_assets.saved_queries WHERE tenant_id='{}' AND id='{id}'",
            tenant()
        )),
        "1"
    );
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=assets.http: real capability storage and transactions"]
async fn asset_storage_failures_are_not_malformed() {
    let m = planning(tenant()).await;
    let device = format!("storage-stages-{}", Uuid::new_v4());
    seed_device(&device);
    let command = assets::Command::Detail {
        device,
        scope: assets::ReadScope::all(),
    };
    for (table, expected) in [
        ("mdm.inventory", "inventory_query"),
        ("mdm.manual_assignments", "manual_query"),
        ("mdm_access.collection_runs", "collection_query"),
    ] {
        sql(&format!("REVOKE SELECT ON {table} FROM mdm_flow_runtime"));
        let outcome = execute_asset(&m, &command).await;
        sql(&format!("GRANT SELECT ON {table} TO mdm_flow_runtime"));
        let error = outcome.unwrap_err();
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({"kind":"unavailable","reason":expected})
        );
    }
    m.runtime.close().await;
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=assets.http: real capability storage and transactions"]
async fn asset_capability_owns_execution_and_receipt_recovery() {
    for (tenant, ledger) in [
        (tenant(), false),
        (
            TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            true,
        ),
    ] {
        let runtime = runtime(tenant).await;
        let key = crate::flow::storage::cursor_key(&runtime, tenant)
            .await
            .unwrap();
        let service = assets::AssetService::new(
            audit_store_with_integrity(if ledger {
                rss_audit_postgres::Integrity::Ledger(Arc::new(
                    rss_ledger::Authenticator::new(
                        rss_ledger::KeyId::parse("asset-test").unwrap(),
                        vec![19; 32],
                    )
                    .unwrap(),
                ))
            } else {
                rss_audit_postgres::Integrity::Plain
            })
            .await,
            runtime.clone(),
            tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
        );
        let device = format!("independent-{}", Uuid::new_v4());
        seed_device_in(tenant, &device);
        let command = assets::Command::Manual {
            device: device.clone(),
            field: assets::FieldKey::AssetTag,
            change: operation(
                0,
                assets::ManualChange::Set {
                    value: assets::Scalar::String("independent".into()),
                },
            ),
            owner: assets::Owner {
                instance: "mdm".into(),
                principal: "operator".into(),
            },
        };
        let audit = || {
            let audit = RequestAudit::new(tenant.to_string(), "management_write");
            audit.set_principal("operator", "mdm");
            audit
        };
        runtime.inject_next_transaction_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        let first = audit();
        assert!(matches!(
            service.execute(&command, &first, &|| Ok(())).await,
            Err(Error::CommitUnknown)
        ));
        first.finalize(None);
        let canonical = || {
            sql(&format!(
                "SELECT encode(canonical,'hex') FROM rss_audit.records WHERE tenant_id='{tenant}' ORDER BY position"
            ))
        };
        let original = canonical();
        assert!(!original.is_empty());
        let replay = audit();
        let receipt = service
            .execute(&command, &replay, &|| Ok(()))
            .await
            .unwrap();
        replay.finalize(None);
        assert_eq!(canonical(), original);
        assert_eq!(receipt["asset"]["revision"], 1);
        let denied = audit();
        assert!(matches!(
            service
                .execute(&command, &denied, &|| Err(Error::Forbidden))
                .await,
            Err(Error::Forbidden)
        ));
        denied.finalize(None);
        let competing = |value: &str| assets::Command::Manual {
            device: device.clone(),
            field: assets::FieldKey::AssetTag,
            change: operation(
                1,
                assets::ManualChange::Set {
                    value: assets::Scalar::String(value.into()),
                },
            ),
            owner: assets::Owner {
                instance: "mdm".into(),
                principal: "operator".into(),
            },
        };
        let left = competing("left");
        let right = competing("right");
        let a = audit();
        let b = audit();
        let (a_result, b_result) = tokio::join!(
            service.execute(&left, &a, &|| Ok(())),
            service.execute(&right, &b, &|| Ok(()))
        );
        assert_eq!(
            usize::from(a_result.is_ok()) + usize::from(b_result.is_ok()),
            1
        );
        assert!(
            matches!(a_result, Err(Error::Conflict)) || matches!(b_result, Err(Error::Conflict))
        );
        a.finalize(None);
        b.finalize(None);
        assert_eq!(canonical().lines().count(), original.lines().count() + 1);
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM rss_ledger.entries WHERE tenant_id='{tenant}'"
            )),
            if ledger { "2" } else { "0" }
        );
        runtime.close().await;
    }
}
