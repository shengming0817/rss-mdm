use crate::test_support::*;
mod identity_read {
    use crate::test_support::*;
    #[tokio::test]
    #[ignore = "MODULE=assets.http: real read authorization and PostgreSQL projection"]
    async fn persisted_inventory_read_respects_device_scope() -> Result<()> {
        let fixture = authority::Authority::open().await?;
        let (authorized, _) = app_with_access(&fixture.base, fixture.access.clone()).await?;
        let mut browser = fixture.browser("other")?;
        let query = &format!("/api/v2/devices/{}/inventory", case::name("device-1"));
        ensure!(
            browser.call(&authorized, Method::GET, query, None).await?.0 == StatusCode::FORBIDDEN
        );
        set_device_grants(
            &mut browser,
            &authorized,
            crate::test_support::case::name("device-1"),
            &["inventory_read"],
        )
        .await?;
        crate::test_support::inventory::seed_source(
            case::name("device-1"),
            "mdm",
            "mdm.windows",
            "Model-A",
        )?;

        let (status, assets) = browser.call(&authorized, Method::GET, query, None).await?;
        ensure!(
            status == StatusCode::OK
                && assets["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"]
                    == "Model-A"
        );
        ensure!(
            assets["tenantId"] == case_tenant()
                && assets["asset"]["device"]["device"]
                    == crate::test_support::case::name("device-1")
        );
        let outside = "/api/v2/devices/outside/inventory";
        ensure!(
            browser
                .call(&authorized, Method::GET, outside, None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
        // RequestAudit is mandatory for both reads and denied requests; never disclose assets on failure.
        pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access,mdm_flow_runtime")?;
        let read = browser.call(&authorized, Method::GET, query, None).await?;
        let mut anonymous = Browser::default();
        let denied = anonymous
            .call(&authorized, Method::GET, query, None)
            .await?;
        pg("GRANT INSERT ON mdm_audit.receipts TO mdm_access,mdm_flow_runtime")?;
        ensure!(
            read.0 == StatusCode::INTERNAL_SERVER_ERROR
                && read.1["code"] == "audit_contract_error"
                && read.1.get("asset").is_none()
        );
        ensure!(
            denied.0 == StatusCode::INTERNAL_SERVER_ERROR
                && denied.1["code"] == "audit_contract_error"
        );
        browser.operation = None;
        ensure!(browser.call(&authorized, Method::GET, query, None).await?.0 == StatusCode::OK);
        Ok(())
    }
}

mod storage {
    use crate::planning::test_support::*;

    #[cfg(feature = "integration")]
    #[tokio::test]
    #[ignore = "MODULE=assets.http: real capability storage and transactions"]
    async fn asset_commit_unknown_recovers_original_receipts() {
        use assets::{
            Command as AssetCommand, ManualChange, Owner, Query, SavedChange, SavedDefinition,
            Scalar,
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
                field: rss_mdm_inventory::builtin::ASSET_TAG,
                change: inventory_operation(
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
                change: inventory_operation(
                    0,
                    SavedChange::Put {
                        definition: Box::new(SavedDefinition {
                            name: "mine".into(),
                            query: Query::default(),
                        }),
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
                Err(Error::Service(rss_mdm_flow_service::Error::CommitUnknown))
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
            ("mdm.inventory_history", "assets_storage"),
            ("mdm.manual_history", "assets_storage"),
            ("mdm_access.collection_history", "assets_storage"),
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
                TenantId::parse(crate::test_support::case::peer()).unwrap(),
                true,
            ),
        ] {
            let runtime = runtime(tenant).await;
            let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant)
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
                Arc::new(crate::automation::inventory_tasks::InventoryTasks),
            );
            let device = format!("independent-{}", Uuid::new_v4());
            seed_device_in(tenant, &device);
            let command = assets::Command::Manual {
                device: device.clone(),
                field: rss_mdm_inventory::builtin::ASSET_TAG,
                change: inventory_operation(
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
                audit.set_principal("operator", crate::test_support::INSTANCE);
                audit
            };
            runtime.inject_next_transaction_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            let first = audit();
            assert!(matches!(
                service.execute(&command, &first, &|| Ok(())).await,
                Err(rss_mdm_inventory_service::Error::CommitUnknown)
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
                    .execute(&command, &denied, &|| Err(
                        rss_mdm_inventory_service::Error::Forbidden
                    ))
                    .await,
                Err(rss_mdm_inventory_service::Error::Forbidden)
            ));
            denied.finalize(None);
            let competing = |value: &str| assets::Command::Manual {
                device: device.clone(),
                field: rss_mdm_inventory::builtin::ASSET_TAG,
                change: inventory_operation(
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
                matches!(a_result, Err(rss_mdm_inventory_service::Error::Conflict))
                    || matches!(b_result, Err(rss_mdm_inventory_service::Error::Conflict))
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
}

mod manual {
    use crate::assets::t2::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "MODULE=assets.http: real Router and persisted assets"]
    async fn manual_types_replay_cas_and_rollback() -> Result<()> {
        let fixture = Fixture::open().await?;
        let router = &fixture.router;
        let mut browser = fixture.browser.clone();
        let catalog = ok(
            &mut browser,
            router,
            Method::GET,
            "/api/v2/asset-fields",
            None,
        )
        .await?;
        ensure!(
            catalog["asset"]["fields"].as_array().unwrap().len()
                == rss_mdm_inventory::builtin::fields().len()
        );
        let cases = [
            ("custom.asset_tag", "string", json!("A-2463")),
            ("custom.office_floor", "integer", json!(3)),
            ("custom.is_loaner", "boolean", json!(false)),
            ("custom.purchase_date", "time", json!(1_700_000_000)),
        ];
        for (field, kind, value) in cases {
            let path = format!("/api/v2/devices/asset-a/manual-fields/{field}");
            let write = request(
                0,
                json!({"action":"set","value":{"kind":kind,"value":value}}),
            );
            let first = ok(
                &mut browser,
                router,
                Method::PUT,
                &path,
                Some(write.clone()),
            )
            .await?;
            ensure!(first["asset"]["revision"] == 1);
            ensure!(
                ok(
                    &mut browser,
                    router,
                    Method::PUT,
                    &path,
                    Some(write.clone())
                )
                .await?
                    == first
            );
            let mut changed = write.clone();
            changed["input"] = json!({"action":"delete"});
            ensure!(
                browser
                    .call(router, Method::PUT, &path, Some(changed))
                    .await?
                    .0
                    == StatusCode::CONFLICT
            );
            let detail = ok(
                &mut browser,
                router,
                Method::GET,
                "/api/v2/devices/asset-a/inventory",
                None,
            )
            .await?;
            ensure!(
                detail["asset"]["device"]["fields"][field]["state"]["value"]
                    == json!({"kind":kind,"value":value})
            );
            let criteria = predicate(field, kind, value);
            let result = ok(
                &mut browser,
                router,
                Method::POST,
                "/api/v2/device-queries",
                Some(json!({"criteria":criteria})),
            )
            .await?;
            ensure!(
                result["asset"]["summary"]["matched"] == 1
                    && result["asset"]["items"][0]["device"] == "asset-a"
            );
        }
        let floor = "/api/v2/devices/asset-a/manual-fields/custom.office_floor";
        for input in [
            json!({"action":"set","value":{"kind":"string","value":"3"}}),
            json!({"action":"set","value":{"kind":"integer","value":3},"validUntil":1}),
            json!({"action":"delete","ttl":1}),
        ] {
            ensure!(
                browser
                    .call(router, Method::PUT, floor, Some(request(1, input)))
                    .await?
                    .0
                    .is_client_error()
            );
        }
        ensure!(
            browser
                .call(
                    router,
                    Method::PUT,
                    "/api/v2/devices/asset-a/manual-fields/device.model",
                    Some(request(
                        0,
                        json!({"action":"set","value":{"kind":"string","value":"spoof"}})
                    ))
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );
        ensure!(
            browser
                .call(
                    router,
                    Method::GET,
                    "/api/v2/devices/asset-a/inventory?source=mdm.windows",
                    None
                )
                .await?
                .0
                .is_client_error()
        );
        let mut a = browser.clone();
        let mut b = browser.clone();
        let (a, b) = tokio::join!(
            a.call(
                router,
                Method::PUT,
                floor,
                Some(request(
                    1,
                    json!({"action":"set","value":{"kind":"integer","value":4}})
                ))
            ),
            b.call(
                router,
                Method::PUT,
                floor,
                Some(request(
                    1,
                    json!({"action":"set","value":{"kind":"integer","value":5}})
                ))
            )
        );
        let (a, b) = (a?, b?);
        ensure!(
            (a.0 == StatusCode::OK) ^ (b.0 == StatusCode::OK),
            "CAS admitted both/neither: {a:?} {b:?}"
        );
        ok(
            &mut browser,
            router,
            Method::PUT,
            floor,
            Some(request(2, json!({"action":"null"}))),
        )
        .await?;
        let null = ok(
            &mut browser,
            router,
            Method::GET,
            "/api/v2/devices/asset-a/inventory",
            None,
        )
        .await?;
        ensure!(
            null["asset"]["device"]["fields"]["custom.office_floor"]["state"]["kind"] == "null"
        );
        ok(
            &mut browser,
            router,
            Method::PUT,
            floor,
            Some(request(3, json!({"action":"delete"}))),
        )
        .await?;
        let removed = ok(
            &mut browser,
            router,
            Method::GET,
            "/api/v2/devices/asset-a/inventory",
            None,
        )
        .await?;
        ensure!(
            removed["asset"]["device"]["fields"]["custom.office_floor"]["state"]["kind"]
                == "deleted"
        );
        ensure!(
            removed["asset"]["device"]["fields"]["custom.office_floor"]["sources"][0]["lastKnown"]
                ["value"]["kind"]
                == "integer"
        );
        // A deferred business write failure rolls back the assignment, receipt and staged audit.
        pg(
            "CREATE FUNCTION public.reject_asset_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_asset_write AFTER UPDATE ON mdm.manual_assignments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_asset_write();",
        )?;
        let rejected = browser
            .call(
                router,
                Method::PUT,
                floor,
                Some(request(
                    4,
                    json!({"action":"set","value":{"kind":"integer","value":7}}),
                )),
            )
            .await?;
        pg(
            "DROP TRIGGER reject_asset_write ON mdm.manual_assignments; DROP FUNCTION public.reject_asset_write();",
        )?;
        ensure!(rejected.0 == StatusCode::SERVICE_UNAVAILABLE);
        ensure!(pg(&format!("SELECT revision FROM mdm.manual_assignments WHERE tenant_id='{TENANT}' AND device='asset-a' AND field='custom.office_floor'", TENANT = case_tenant()))?.trim()=="4");
        fixture.close().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=assets.http"]
async fn field_catalog_admin_publish_and_reference_checks_need_no_approval() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    use crate::test_support::agent_execution::Fixture;
    let mut fixture = Fixture::new().await?;
    let key = "custom.registry_example";
    let path = format!("/api/v2/asset-fields/{key}");
    let definition = json!({"key":key,"version":1,"valueType":{"kind":"string","maxLength":128,"allowEmpty":false},"nullable":false,"manual":false,"sources":{"agent.script":100},"platforms":["macos"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null});
    let create = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":definition}});
    ensure!(
        fixture
            .author
            .call(&fixture.router, Method::PUT, &path, Some(create.clone()))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    fixture.grants.push(Grant {
        operation: Permission::InventoryFieldsWrite,
        scope: Scope::Tenant,
    });
    crate::test_support::identity::set_grants(
        case_tenant(),
        &fixture.author_id,
        fixture.grants.clone(),
    )
    .await?;
    let published = fixture
        .author
        .call(&fixture.router, Method::PUT, &path, Some(create.clone()))
        .await?;
    ensure!(
        published.0 == StatusCode::OK && published.1["asset"]["version"] == 1,
        "field publish: {published:?}"
    );
    ensure!(
        fixture
            .author
            .call(&fixture.router, Method::PUT, &path, Some(create))
            .await?
            == published,
        "field publication replay changed"
    );
    let saved = format!("/api/v2/saved-queries/{}", Uuid::new_v4());
    let value = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"name":"field reference","query":{"criteria":{"kind":"predicate","field":key,"op":"eq","value":{"kind":"string","value":"yes"}},"select":[key],"sort":null}}}});
    let response = fixture
        .author
        .call(&fixture.router, Method::PUT, &saved, Some(value))
        .await?;
    ensure!(response.0 == StatusCode::OK, "saved query: {response:?}");
    let references = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("{path}/references"),
            None,
        )
        .await?;
    ensure!(
        references.0 == StatusCode::OK && references.1["asset"]["impact"]["savedQueries"] == 1,
        "references: {references:?}"
    );
    let delete =
        || json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}});
    ensure!(
        fixture
            .author
            .call(&fixture.router, Method::PUT, &path, Some(delete()))
            .await?
            .0
            == StatusCode::CONFLICT
    );
    ensure!(
        fixture
            .author
            .call(&fixture.router, Method::PUT, &saved, Some(delete()))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        fixture
            .author
            .call(&fixture.router, Method::PUT, &path, Some(delete()))
            .await?
            .0
            == StatusCode::OK
    );
    let recreate = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":published.1["asset"]["definition"]}});
    let rejected = fixture
        .author
        .call(&fixture.router, Method::PUT, &path, Some(recreate))
        .await?;
    ensure!(
        rejected.0 == StatusCode::CONFLICT,
        "retired field must remain a domain conflict: {rejected:?}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.http: bounded lists retain a single authorized snapshot"]
async fn typed_list_pages_remain_frozen_across_field_updates() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    use crate::test_support::agent_execution::{Fixture, case_device_id};
    let mut f = Fixture::new().await?;
    f.register().await?;
    f.grants.extend([
        Grant {
            operation: Permission::InventoryFieldsWrite,
            scope: Scope::Tenant,
        },
        Grant {
            operation: Permission::InventoryAssign,
            scope: Scope::AllDevices,
        },
    ]);
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let key = "custom.page_values";
    let definition = json!({"key":key,"version":1,"valueType":{"kind":"array","items":{"kind":"integer"},"maxItems":1000},"nullable":true,"manual":true,"sources":{"manual":0},"platforms":["macos","windows"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null});
    let result = f.author.call(&f.router, Method::PUT, &format!("/api/v2/asset-fields/{key}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":definition}}))).await?;
    ensure!(result.0 == StatusCode::OK, "list field: {result:?}");
    let field_path = format!("/api/v2/devices/{}/manual-fields/{key}", case_device_id());
    let values: Vec<_> = (0..205)
        .map(|v| json!({"kind":"integer","value":v}))
        .collect();
    let result = f.author.call(&f.router, Method::PUT, &field_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"set","value":{"kind":"array","value":values}}}))).await?;
    ensure!(result.0 == StatusCode::OK, "list write: {result:?}");
    let list_path = format!("/api/v2/devices/{}/inventory-lists/{key}", case_device_id());
    let first = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("{list_path}?limit=100"),
            None,
        )
        .await?;
    ensure!(
        first.0 == StatusCode::OK && first.1["asset"]["total"] == 205,
        "first list page: {first:?}"
    );
    let cursor = first.1["asset"]["nextCursor"].as_str().unwrap();
    let changed = f.author.call(&f.router, Method::PUT, &field_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"set","value":{"kind":"array","value":[]}}}))).await?;
    ensure!(changed.0 == StatusCode::OK, "list replacement: {changed:?}");
    let second = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("{list_path}?limit=100&cursor={cursor}"),
            None,
        )
        .await?;
    ensure!(
        second.0 == StatusCode::OK
            && second.1["asset"]["total"] == 205
            && second.1["asset"]["watermark"] == first.1["asset"]["watermark"],
        "snapshot drift: {second:?}"
    );
    let cursor = second.1["asset"]["nextCursor"].as_str().unwrap();
    let last = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("{list_path}?limit=100&cursor={cursor}"),
            None,
        )
        .await?;
    ensure!(
        last.0 == StatusCode::OK
            && last.1["asset"]["items"].as_array().unwrap().len() == 5
            && last.1["asset"]["nextCursor"].is_null()
    );
    let combined: Vec<_> = [&first.1, &second.1, &last.1]
        .into_iter()
        .flat_map(|v| v["asset"]["items"].as_array().unwrap().clone())
        .collect();
    ensure!(combined == values, "pagination repeated or lost items");
    let current = f
        .author
        .call(&f.router, Method::GET, &list_path, None)
        .await?;
    ensure!(
        current.0 == StatusCode::OK && current.1["asset"]["total"] == 0,
        "empty complete list: {current:?}"
    );
    let forged = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("{list_path}?cursor={cursor}x"),
            None,
        )
        .await?;
    ensure!(forged.0.is_client_error());
    Ok(())
}
