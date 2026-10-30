use super::{AssetHttp, AssetRuntime};
use crate::test_support::http::Browser;
use crate::test_support::{process::*, runtime::*, *};
mod identity_read {
    use super::AssetHttp;
    use crate::test_support::http::{Browser, change_device_grants};
    use crate::test_support::{process::*, runtime::*, *};
    #[tokio::test]
    #[ignore = "MODULE=assets.http: real read authorization and PostgreSQL projection"]
    async fn persisted_inventory_read_respects_device_scope() -> Result<()> {
        let mut fixture = AssetHttp::open().await?;
        let fixture_resources = std::mem::take(&mut fixture.resources);
        fixture_resources.finish(async {
        let authorized = fixture.router;
        let mut browser = fixture.author;
        crate::test_support::identity::seed_grants(case_tenant(), &fixture.author_id, vec![]).await?;
        let query = &format!("/api/v1/devices/{}/inventory", case::name("device-1"));
        ensure!(
            browser.call(&authorized, Method::GET, query, None).await?.0 == StatusCode::FORBIDDEN
        );
        change_device_grants(&mut browser,
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
        let outside = "/api/v1/devices/outside/inventory";
        ensure!(
            browser
                .call(&authorized, Method::GET, outside, None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
        // Ordinary reads and authentication denials remain independent of audit storage.
        pg("REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_access,mdm_inventory_runtime")?;
        let read = browser.call(&authorized, Method::GET, query, None).await?;
        let mut anonymous = Browser::default();
        let denied = anonymous
            .call(&authorized, Method::GET, query, None)
            .await?;
        pg("GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_access,mdm_inventory_runtime")?;
        ensure!(read.0 == StatusCode::OK && read.1["asset"]["device"]["fields"] == assets["asset"]["device"]["fields"]);
        ensure!(denied.0 == StatusCode::UNAUTHORIZED);
        browser.operation = None;
        let recovered = browser.call(&authorized, Method::GET, query, None).await?;
        ensure!(recovered.0 == StatusCode::OK && recovered.1["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"] == "Model-A");
        Ok(())
        }).await
    }
}

mod storage {
    use crate::planning::test_support::*;

    pub(super) async fn independent_assets(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        resources: &mut crate::test_support::runtime::Resources,
    ) -> Arc<assets::AssetService> {
        let key = crate::planning::test_support::cursor_key(tenant).await;
        resources.resource(super::AssetRuntime(runtime.clone()));
        let inventory = inventory_runtime(tenant).await;
        resources.resource(crate::test_support::runtime::InventoryFixtureResource(
            inventory.clone(),
        ));
        let audit = audit_store_with_integrity(rss_audit_postgres::Integrity::Plain).await;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit = Arc::new(
            audit
                .on_runtime(runtime.clone(), tenant, &budget.control())
                .await
                .unwrap(),
        );
        Arc::new(assets::AssetService::new(
            inventory,
            audit.clone(),
            runtime.clone(),
            tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
            rss_reconcile_postgres::PgMessagingStore::new(
                runtime.clone(),
                tenant,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .unwrap(),
        ))
    }
    async fn execute(
        service: &assets::AssetService,
        command: &assets::Command,
    ) -> Result<Value, rss_mdm_inventory_service::Error> {
        let audit = RequestAudit::new(
            tenant().to_string(),
            "management_write",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.set_principal("operator", crate::test_support::INSTANCE);
        let result = service
            .execute(command, &audit, &|| Ok(()))
            .await
            .map(|v| serde_json::to_value(v).expect("asset response serializes"));
        audit.finalize(None);
        result
    }

    #[cfg(feature = "integration")]
    #[tokio::test]
    #[ignore = "MODULE=assets.http: real capability storage and transactions"]
    async fn asset_commit_unknown_recovers_original_receipts() {
        use assets::{Command as AssetCommand, Owner, SavedChange, SavedDefinition};
        let runtime = runtime_role(tenant(), "mdm_inventory_runtime").await;
        let mut resources = crate::test_support::runtime::Resources::default();
        let service = independent_assets(runtime.clone(), tenant(), &mut resources).await;
        let id = Uuid::new_v4();
        let command = AssetCommand::SavedWrite {
            id,
            owner: Owner {
                instance: Uuid::new_v4().to_string(),
                principal: Uuid::new_v4().to_string(),
            },
            change: inventory_operation(
                0,
                SavedChange::Put {
                    definition: Box::new(SavedDefinition {
                        name: "mine".into(),
                        query: assets::rsql::QueryInput::default(),
                    }),
                },
            ),
        };
        runtime.inject_next_transaction_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        assert!(matches!(
            execute(&service, &command).await,
            Err(rss_mdm_inventory_service::Error::CommitUnknown)
        ));
        let recovered = execute(&service, &command).await.unwrap();
        assert_eq!(execute(&service, &command).await.unwrap(), recovered);
        assert_eq!(
            sql(&format!(
                "SELECT revision FROM mdm_assets.saved_queries WHERE tenant_id='{}' AND id='{id}'",
                tenant()
            )),
            "1"
        );
        resources.finish(async { Ok(()) }).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "MODULE=assets.http: real capability storage and transactions"]
    async fn asset_storage_failures_are_not_malformed() {
        let runtime = runtime_role(tenant(), "mdm_inventory_runtime").await;
        let mut resources = crate::test_support::runtime::Resources::default();
        let service = independent_assets(runtime.clone(), tenant(), &mut resources).await;
        let device = format!("storage-stages-{}", Uuid::new_v4());
        seed_device(&device);
        let command = assets::Command::Detail {
            device: device.clone(),
            scope: assets::ReadScope::all(),
        };
        // Fail the current provider boundary, then restore it before cleanup.
        {
            assert_eq!(
                execute(&service, &command).await.unwrap()["asset"]["device"]["device"],
                device
            );
            sql(
                "REVOKE EXECUTE ON FUNCTION mdm_assets.read_snapshot(text[],text[],jsonb,jsonb) FROM mdm_inventory_runtime",
            );
            let outcome = execute(&service, &command).await;
            sql(
                "GRANT EXECUTE ON FUNCTION mdm_assets.read_snapshot(text[],text[],jsonb,jsonb) TO mdm_inventory_runtime",
            );
            assert_eq!(
                execute(&service, &command).await.unwrap()["asset"]["device"]["device"],
                device
            );
            let error = outcome.unwrap_err();
            let error = rss_mdm_management_http::Error::from(error);
            assert_eq!(
                serde_json::to_value(error).unwrap(),
                json!({"kind":"unavailable","reason":"assets_storage"})
            );
        }
        resources.finish(async { Ok(()) }).await.unwrap();
    }

    #[cfg(feature = "integration")]
    #[tokio::test]
    #[ignore = "MODULE=assets.http: real capability storage and transactions"]
    async fn asset_capability_owns_execution_and_receipt_recovery() {
        let tenant = tenant();
        let runtime = runtime_role(tenant, "mdm_inventory_runtime").await;
        let key = crate::planning::test_support::cursor_key(tenant).await;
        let integrity = rss_audit_postgres::Integrity::Plain;
        let audit = audit_store_with_integrity(integrity.clone()).await;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit = Arc::new(
            audit
                .on_runtime(runtime.clone(), tenant, &budget.control())
                .await
                .unwrap(),
        );
        let service = assets::AssetService::new(
            crate::planning::test_support::inventory_runtime(tenant).await,
            audit.clone(),
            runtime.clone(),
            tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
            rss_reconcile_postgres::PgMessagingStore::new(
                runtime.clone(),
                tenant,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .unwrap(),
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
                instance: crate::test_support::INSTANCE.into(),
                principal: "operator".into(),
            },
        };
        let audit = || {
            let audit = RequestAudit::new(
                tenant.to_string(),
                "management_write",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
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
                "SELECT encode(canonical,'hex') FROM rss_audit.records WHERE tenant_id='{tenant}' ORDER BY source_id,event_id"
            ))
        };
        let original = canonical();
        assert!(!original.is_empty());
        let replay = audit();
        let receipt = service
            .execute(&command, &replay, &|| Ok(()))
            .await
            .map(|value| serde_json::to_value(value).expect("asset response serializes"))
            .unwrap();
        replay.finalize(None);
        assert_eq!(canonical(), original);
        assert_eq!(receipt["asset"]["revision"], 1);
        let repeated = audit();
        assert_eq!(
            service
                .execute(&command, &repeated, &|| Ok(()))
                .await
                .map(|value| serde_json::to_value(value).expect("asset response serializes"))
                .unwrap(),
            receipt
        );
        repeated.finalize(None);
        assert_eq!(canonical(), original);
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
                instance: crate::test_support::INSTANCE.into(),
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
        runtime.close().await;
    }
}

mod manual {
    use super::AssetHttp;
    use crate::assets::t2::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "MODULE=assets.http: real Router and persisted assets"]
    async fn manual_types_replay_cas_and_rollback() -> Result<()> {
        let fixture = AssetHttp::open().await?;
        pg(&format!(
            "INSERT INTO mdm_access.devices VALUES('{}','asset-a');",
            case_tenant()
        ))?;
        let router = &fixture.router;
        let mut browser = fixture.author.clone();
        let cases = [
            ("custom.asset_tag", "string", json!("A-2463")),
            ("custom.office_floor", "integer", json!(3)),
            ("custom.is_loaner", "boolean", json!(false)),
            ("custom.purchase_date", "time", json!(1_700_000_000)),
        ];
        for (field, kind, value) in cases {
            let path = format!("/api/v1/devices/asset-a/manual-fields/{field}");
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
            if kind == "integer" {
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
            }
            let detail = ok(
                &mut browser,
                router,
                Method::GET,
                "/api/v1/devices/asset-a/inventory",
                None,
            )
            .await?;
            ensure!(
                detail["asset"]["device"]["fields"][field]["state"]["value"]
                    == json!({"kind":kind,"value":value})
            );
        }
        let floor = "/api/v1/devices/asset-a/manual-fields/custom.office_floor";
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
                    == StatusCode::BAD_REQUEST
            );
        }
        ensure!(
            browser
                .call(
                    router,
                    Method::PUT,
                    "/api/v1/devices/asset-a/manual-fields/device.model",
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
                    "/api/v1/devices/asset-a/inventory?source=mdm.windows",
                    None
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
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
        ensure!((a.0 == StatusCode::CONFLICT) ^ (b.0 == StatusCode::CONFLICT));
        let last_value = if a.0 == StatusCode::OK { 4 } else { 5 };
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
            "/api/v1/devices/asset-a/inventory",
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
            "/api/v1/devices/asset-a/inventory",
            None,
        )
        .await?;
        ensure!(
            removed["asset"]["device"]["fields"]["custom.office_floor"]["state"]["kind"]
                == "deleted"
        );
        ensure!(
            removed["asset"]["device"]["fields"]["custom.office_floor"]["sources"][0]["lastKnown"]
                ["value"]
                == json!({"kind":"integer","value":last_value})
        );
        // A deferred business write failure rolls back the assignment, receipt and staged audit.
        pg(
            "CREATE FUNCTION public.reject_asset_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_asset_write AFTER UPDATE ON mdm.manual_assignments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_asset_write();",
        )?;
        let failed_write = request(
            4,
            json!({"action":"set","value":{"kind":"integer","value":7}}),
        );
        let failed_id = failed_write["operationId"].as_str().unwrap();
        let business_before = pg(&format!(
            "SELECT event_id FROM rss_audit.records WHERE tenant_id='{0}' AND source_id='mdm.business' ORDER BY event_id",
            case_tenant()
        ))?;
        let rejected = browser
            .call(router, Method::PUT, floor, Some(failed_write.clone()))
            .await?;
        pg(
            "DROP TRIGGER reject_asset_write ON mdm.manual_assignments; DROP FUNCTION public.reject_asset_write();",
        )?;
        ensure!(rejected.0 == StatusCode::SERVICE_UNAVAILABLE);
        ensure!(pg(&format!("SELECT count(*) FROM mdm_assets.operations WHERE tenant_id='{}' AND id='{failed_id}'", case_tenant()))?.trim() == "0");
        // Receipt rows include request facts too; compare only business identities.
        let business_after = pg(&format!(
            "SELECT event_id FROM rss_audit.records WHERE tenant_id='{0}' AND source_id='mdm.business' ORDER BY event_id",
            case_tenant()
        ))?;
        ensure!(!business_before.trim().is_empty());
        ensure!(business_after == business_before);
        let after = ok(
            &mut browser,
            router,
            Method::GET,
            "/api/v1/devices/asset-a/inventory",
            None,
        )
        .await?;
        ensure!(
            after["asset"]["device"]["fields"]["custom.office_floor"]
                == removed["asset"]["device"]["fields"]["custom.office_floor"]
        );

        ensure!(pg(&format!("SELECT revision FROM mdm.manual_assignments WHERE tenant_id='{TENANT}' AND device='asset-a' AND field='custom.office_floor'", TENANT = case_tenant()))?.trim()=="4");
        fixture.resources.finish(async { Ok(()) }).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=assets.http"]
async fn field_catalog_admin_publish_and_reference_checks_need_no_approval() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut fixture = AssetHttp::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let key = "custom.registry_example";
    let path = format!("/api/v1/asset-fields/{key}");
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
    crate::test_support::identity::seed_grants(
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
    let saved = format!("/api/v1/saved-queries/{}", Uuid::new_v4());
    let value = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"name":"field reference","query":{"filter":format!("{key}==yes"),"fields":[key],"sort":[]}}}});
    let response = fixture
        .author
        .call(&fixture.router, Method::PUT, &saved, Some(value))
        .await?;
    ensure!(response.0 == StatusCode::OK, "saved query: {response:?}");
    let denied_refs = fixture.author.call(&fixture.router, Method::GET, &format!("{path}/references"), None).await?;
    ensure!(denied_refs.0 == StatusCode::FORBIDDEN, "resource references require ResourceRead");
    fixture.grants.push(Grant { operation: Permission::ResourceRead, scope: Scope::Tenant });
    crate::test_support::identity::change_grants(case_tenant(), &fixture.author_id, fixture.grants.clone()).await?;
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
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.http: bounded lists retain a single authorized snapshot"]
async fn typed_list_pages_remain_frozen_across_field_updates() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut f = AssetHttp::open().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    let device = case::name("asset-list");
    pg(&format!("INSERT INTO mdm_access.devices VALUES('{}','{device}')", case_tenant()))?;
    f.grants.push(Grant { operation: Permission::InventoryFieldsWrite, scope: Scope::Tenant });
    crate::test_support::identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let key = "custom.page_values";
    let definition = json!({"key":key,"version":1,"valueType":{"kind":"array","items":{"kind":"integer"},"maxItems":1000},"nullable":true,"manual":true,"sources":{"manual":0},"platforms":["macos","windows"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null});
    let result = f.author.call(&f.router, Method::PUT, &format!("/api/v1/asset-fields/{key}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":definition}}))).await?;
    ensure!(result.0 == StatusCode::OK, "list field: {result:?}");
    let field_path = format!("/api/v1/devices/{}/manual-fields/{key}", device);
    let values: Vec<_> = (0..205)
        .map(|v| json!({"kind":"integer","value":v}))
        .collect();
    let result = f.author.call(&f.router, Method::PUT, &field_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"set","value":{"kind":"array","value":values}}}))).await?;
    ensure!(result.0 == StatusCode::OK, "list write: {result:?}");
    let list_path = format!("/api/v1/devices/{}/inventory-lists/{key}", device);
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
    let (cursor, long_cut) = long_asset_cursor(first.1["asset"]["nextCursor"].as_str().unwrap(), "inventory-list").await?;
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
            && second.1["asset"]["assetCut"] == long_cut,
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
    let forged_cursor = format!("{}{}", if cursor.starts_with('A') { "B" } else { "A" }, &cursor[1..]);
    let forged = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("{list_path}?cursor={forged_cursor}"),
            None,
        )
        .await?;
    ensure!(forged.0 == StatusCode::CONFLICT);
    ensure!(f.author.call(&f.router, Method::GET, &format!("{list_path}?limit=100&cursor={cursor}"), None).await? == last);
    Ok(())
    }).await
}

mod field_layout;
mod scopes;

// Expand a captured snapshot with a contiguous range of future in-flight XIDs.
// Every XID at/above the original xmax remains invisible, preserving its exact
// visibility without opening thousands of live connections or changing the provider.
async fn long_asset_cursor(token: &str, context: &str) -> Result<(String, Value)> {
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let key = crate::planning::test_support::cursor_key(tenant).await;
    let codec = rss_mdm_query::cursor::CursorCodec::new(&key)?;
    let mut position: Value = codec.decode(&rss_contract::PageCursor::parse(token)?, context)?;
    let original = position["asset_cut"]["snapshot"].as_str().unwrap();
    let mut parts = original.splitn(3, ':');
    let xmin = parts.next().unwrap();
    let mut xmax: u64 = parts.next().unwrap().parse()?;
    let mut active = parts.next().unwrap().to_owned();
    while active.len() + xmin.len() + 40 < 65_536 {
        if !active.is_empty() {
            active.push(',');
        }
        active.push_str(&xmax.to_string());
        xmax += 1;
    }
    position["asset_cut"]["snapshot"] = format!("{xmin}:{xmax}:{active}").into();
    let cut = position["asset_cut"].clone();
    rss_mdm_inventory::AssetCut::from_json(cut.clone())?;
    let token = codec.encode_bounded(
        context,
        &position,
        rss_mdm_inventory_service::assets::windows::MAX_CURSOR_BYTES,
    )?;
    ensure!(
        token.len() > 32 * 1024,
        "long cursor did not exceed the former transport budget"
    );
    Ok((token, cut))
}

#[tokio::test]
#[ignore = "MODULE=assets.http: field provider faults retain unavailable classification"]
async fn field_authoring_distinguishes_storage_faults_from_missing_versions() -> Result<()> {
    use rss_mdm_inventory_service::collection::resource_authoring::profile_fields_on;
    use rss_mdm_inventory_service::{Error as I, transaction::Fault};
    use rss_mdm_resource as r;
    use sqlx::Connection;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let options =
        crate::device::test_support::options("mdm_inventory_runtime")?.password("runtime-fixture");
    let mut connection = sqlx::PgConnection::connect_with(&options).await?;
    sqlx::query("BEGIN").execute(&mut connection).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut connection)
        .await?;
    let mut spec = r::TelemetryProfileSpec {
        template: r::TelemetryTemplate {
            resource: Uuid::new_v4().to_string(),
            version: "v1".into(),
            variant: "default".into(),
            platform: r::Platform::MacOS,
            architecture: r::Architecture::Aarch64,
        },
        parameters: Default::default(),
        fields: vec![r::TelemetryFieldReference {
            key: "device.model".into(),
            version: 1,
        }],
        projection: r::TelemetryProjection::Current,
        sample_millis: 5000,
        upload_millis: 10000,
        budget: r::TelemetryBudget {
            points: 4,
            bytes: 65536,
            resources: 1,
            execution_millis: 1000,
            output_bytes: 4096,
        },
        boost: None,
        backfill_seconds: 3600,
    };
    let profile = r::TelemetryProfile::new(spec.clone())?;
    ensure!(
        profile_fields_on(&mut connection, tenant, &profile)
            .await?
            .len()
            == 1
    );
    spec.fields[0].version = 999;
    let missing = r::TelemetryProfile::new(spec)?;
    ensure!(matches!(
        profile_fields_on(&mut connection, tenant, &missing).await,
        Err(Fault::Request(I::Conflict))
    ));
    // A real failed SQL statement leaves the transaction unavailable, not conflicted.
    ensure!(
        sqlx::query("SELECT 1/0")
            .execute(&mut connection)
            .await
            .is_err()
    );
    let failure = profile_fields_on(&mut connection, tenant, &profile)
        .await
        .unwrap_err();
    ensure!(matches!(
        failure,
        Fault::Request(I::Unavailable(_)) | Fault::Sql(_)
    ));
    let projected: rss_mdm_execution_service::transaction::Fault = failure.into();
    ensure!(matches!(
        projected,
        rss_mdm_execution_service::transaction::Fault::Request(
            rss_mdm_execution_service::Error::Unavailable(_)
        ) | rss_mdm_execution_service::transaction::Fault::Sql(_)
    ));
    sqlx::query("ROLLBACK").execute(&mut connection).await?;
    connection.close().await?;
    Ok(())
}
