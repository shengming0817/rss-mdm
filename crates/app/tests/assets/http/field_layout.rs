//! Real HTTP/PG proofs for tenant-shared display metadata, not device membership.
use super::*;
use crate::authorization::{Grant, Permission, Scope};
const PATH: &str = "/api/v1/asset-field-layout";

fn operation(revision: u64, groups: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":{"groups":groups}})
}
async fn grants(subject: &str, operations: &[Permission]) -> Result<()> {
    crate::test_support::identity::set_grants(
        case_tenant(),
        subject,
        operations
            .iter()
            .map(|operation| Grant {
                operation: *operation,
                scope: if operation.device() {
                    Scope::AllDevices
                } else {
                    Scope::Tenant
                },
            })
            .collect(),
    )
    .await
}
async fn publish(fixture: &mut AssetHttp, key: &str, sensitivity: &str) -> Result<()> {
    let change = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{
        "key":key,"version":1,"valueType":{"kind":"string","maxLength":128,"allowEmpty":false},"nullable":false,"manual":false,
        "sources":{"agent.script":100},"platforms":["macos"],"sensitivity":sensitivity,"unit":null,"searchable":true,"itemKey":null
    }}});
    let result = fixture
        .author
        .call(
            &fixture.router,
            Method::PUT,
            &format!("/api/v1/asset-fields/{key}"),
            Some(change),
        )
        .await?;
    ensure!(result.0 == StatusCode::OK, "publish: {result:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.http: shared layout HTTP authorization and persistence"]
async fn shared_layout_round_trip_permissions_and_retired_fields() -> Result<()> {
    let mut fixture = AssetHttp::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let initial = fixture.author.call(&fixture.router, Method::GET, PATH, None).await?;
        ensure!(initial.0 == StatusCode::OK && initial.1["asset"] == json!({"kind":"field_layout","revision":0,"editable":false,"groups":[]}));
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let groups = json!([
            {"id":first,"name":"  采购  ","fields":["custom.layout_public","custom.layout_secret"]},
            {"id":second,"name":"安全","fields":["custom.layout_secret"]}
        ]);
        let write = operation(0, groups.clone());
        let huge = operation(0, json!([{ "id":first,"name":"x".repeat(17000),"fields":["custom.layout_public"] }]));
        ensure!(fixture.author.call(&fixture.router, Method::PUT, PATH, Some(huge)).await?.0 == StatusCode::PAYLOAD_TOO_LARGE);

        ensure!(fixture.author.call(&fixture.router, Method::PUT, PATH, Some(write.clone())).await?.0 == StatusCode::FORBIDDEN);
        grants(&fixture.author_id, &[Permission::InventoryFieldsWrite]).await?;
        publish(&mut fixture, "custom.layout_public", "standard").await?;
        publish(&mut fixture, "custom.layout_secret", "sensitive").await?;
        let saved = fixture.author.call(&fixture.router, Method::PUT, PATH, Some(write.clone())).await?;
        ensure!(saved.0 == StatusCode::OK && saved.1["asset"] == json!({"kind":"field_layout_written","revision":1}), "save: {saved:?}");
        ensure!(fixture.author.call(&fixture.router, Method::PUT, PATH, Some(write.clone())).await? == saved);
        let mut different = write.clone(); different["input"]["groups"][0]["name"] = json!("changed");
        ensure!(fixture.author.call(&fixture.router, Method::PUT, PATH, Some(different)).await?.0 == StatusCode::CONFLICT);
        let managed = fixture.author.call(&fixture.router, Method::GET, PATH, None).await?;
        ensure!(managed.0 == StatusCode::OK && managed.1["asset"]["editable"] == true);
        ensure!(managed.1["asset"]["groups"][0]["fields"] == groups[0]["fields"] && managed.1["asset"]["groups"][0]["name"] == "采购");
        let mut reader = authority::Authority::prepared_browser("admin").await?;
        let reader_id = browser_subject(&reader, &fixture.router).await?;
        grants(&reader_id, &[Permission::InventoryRead]).await?;
        let projected = reader.call(&fixture.router, Method::GET, PATH, None).await?;
        ensure!(projected.0 == StatusCode::OK && projected.1["asset"]["groups"] == json!([{ "id":first,"name":"采购","fields":["custom.layout_public"] }]));
        ensure!(projected.1["asset"]["editable"] == false && !projected.1.to_string().contains("custom.layout_secret"));
        ensure!(reader.call(&fixture.router, Method::PUT, PATH, Some(operation(1, json!([])))).await?.0 == StatusCode::FORBIDDEN);
        grants(&reader_id, &[Permission::InventoryRead, Permission::InventorySensitiveRead]).await?;
        let shared = reader.call(&fixture.router, Method::GET, PATH, None).await?;
        ensure!(shared.1["asset"]["groups"] == managed.1["asset"]["groups"] && shared.1["asset"]["revision"] == 1);
        // Another service composition uses persisted state rather than an in-memory copy.
        let mut restarted = AssetHttp::open().await?;
        let restarted_resources = std::mem::take(&mut restarted.resources);
        restarted_resources.finish(async {
            grants(&restarted.author_id, &[Permission::InventoryFieldsWrite]).await?;
            ensure!(restarted.author.call(&restarted.router, Method::GET, PATH, None).await? == managed);
            Ok(())
        }).await?;
        let persisted = pg(&format!("SELECT document::text FROM mdm_assets.field_layouts WHERE tenant_id='{}'", case_tenant()))?;
        ensure!(pg_tenant(case::peer(), &format!("SET LOCAL ROLE mdm_flow_runtime; SELECT count(*) FROM mdm_assets.field_layouts WHERE tenant_id='{}'", case_tenant()))?.trim() == "0");
        ensure!(pg_tenant(case::peer(), &format!(r#"SET LOCAL ROLE mdm_flow_runtime; INSERT INTO mdm_assets.field_layouts VALUES('{}',1,'{{"groups":[]}}'::jsonb)"#, case_tenant())).is_err());
        ensure!(persisted.contains("custom.layout_secret"));
        // Whole-layout replacement retains sensitive references without granting raw-value access.
        let mut reordered = managed.1["asset"]["groups"].clone();
        reordered.as_array_mut().unwrap().reverse();
        reordered[1]["fields"].as_array_mut().unwrap().reverse();
        let updated = fixture.author.call(&fixture.router, Method::PUT, PATH, Some(operation(1, reordered.clone()))).await?;
        ensure!(updated.0 == StatusCode::OK && updated.1["asset"]["revision"] == 2);
        let ordered = fixture.author.call(&fixture.router, Method::GET, PATH, None).await?;
        ensure!(ordered.1["asset"]["groups"] == reordered);
        // Presentation references never block field retirement or mutate the layout on GET.
        let retire = json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}});
        ensure!(fixture.author.call(&fixture.router, Method::PUT, "/api/v1/asset-fields/custom.layout_secret", Some(retire)).await?.0 == StatusCode::OK);
        let document = pg(&format!("SELECT document::text FROM mdm_assets.field_layouts WHERE tenant_id='{}'", case_tenant()))?;
        let retired = fixture.author.call(&fixture.router, Method::GET, PATH, None).await?;
        ensure!(retired.1["asset"]["revision"] == 2 && retired.1["asset"]["groups"][0]["fields"] == json!([]));
        ensure!(pg(&format!("SELECT document::text FROM mdm_assets.field_layouts WHERE tenant_id='{}'", case_tenant()))? == document);
        ensure!(fixture.author.call(&fixture.router, Method::PUT, PATH, Some(operation(2, reordered))).await?.0 == StatusCode::BAD_REQUEST);
        let valid = json!([{ "id":first,"name":"采购","fields":["custom.layout_public"] }]);
        ensure!(fixture.author.call(&fixture.router, Method::PUT, PATH, Some(operation(2, valid))).await?.0 == StatusCode::OK);
        ensure!(!pg(&format!("SELECT document::text FROM mdm_assets.field_layouts WHERE tenant_id='{}'", case_tenant()))?.contains("custom.layout_secret"));
        // Revocation prevents replay of a previously accepted operation too.
        grants(&fixture.author_id, &[Permission::InventoryRead]).await?;
        ensure!(fixture.author.call(&fixture.router, Method::PUT, PATH, Some(write)).await?.0 == StatusCode::FORBIDDEN);
        grants(&fixture.author_id, &[]).await?;
        ensure!(fixture.author.call(&fixture.router, Method::GET, PATH, None).await?.0 == StatusCode::FORBIDDEN);
        Ok(())
    }).await
}

#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.http: real layout CAS, rollback and uncertain commit recovery"]
async fn layout_cas_receipts_and_audit_are_atomic() -> Result<()> {
    use rss_mdm_audit_integration::RequestAudit;
    use rss_mdm_inventory_service::Error;
    use rss_mdm_inventory_service::assets::{
        Command, FieldDisplayGroup, FieldLayout, FieldLayoutAccess,
    };
    use rss_mdm_inventory_service::operation::Operation;
    use rss_request_context::TenantId;
    let tenant = TenantId::parse(case_tenant())?;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut resources = Resources::default();
    let service = super::storage::independent_assets(runtime.clone(), tenant, &mut resources).await;
    resources.finish(async {
        async fn execute(service: &rss_mdm_inventory_service::assets::AssetService, command: &Command) -> std::result::Result<Value, Error> {
            let audit = RequestAudit::new(case_tenant().into(), "management_write");
            audit.set_principal("layout-operator", crate::test_support::INSTANCE);
            audit.target("asset-field-layout");
            if let Some(id) = command.operation() { audit.operation(id, "management_write"); }
            let result = service.execute(command, &audit, &|| Ok(())).await;
            audit.finalize(None);
            result
        }
        let id = Uuid::new_v4();
        let group = FieldDisplayGroup { id: Uuid::new_v4(), name: "资产".into(), fields: vec![rss_mdm_inventory::FieldKey::parse("custom.asset_tag")?] };
        let command = Command::FieldLayoutWrite { change: Operation { operation_id: id, expected_revision: 0, input: FieldLayout { groups: vec![group.clone()] } } };
        runtime.inject_next_transaction_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck);
        ensure!(matches!(execute(&service, &command).await, Err(Error::CommitUnknown)));
        let recovered = execute(&service, &command).await?;
        ensure!(recovered["asset"] == json!({"kind":"field_layout_written","revision":1}));
        ensure!(execute(&service, &command).await? == recovered);
        ensure!(pg(&format!("SELECT count(*) FROM mdm_assets.operations WHERE tenant_id='{}' AND id='{id}'", case_tenant()))?.trim() == "1");
        let make = |name: &str| Command::FieldLayoutWrite { change: Operation {
            operation_id: Uuid::new_v4(), expected_revision: 1,
            input: FieldLayout { groups: vec![FieldDisplayGroup { name: name.into(), ..group.clone() }] },
        }};
        let a = make("甲"); let b = make("乙");
        let (a, b) = tokio::join!(execute(&service, &a), execute(&service, &b));
        ensure!(a.is_ok() ^ b.is_ok());
        ensure!(matches!(a, Err(Error::Conflict)) ^ matches!(b, Err(Error::Conflict)));
        let before = pg(&format!("SELECT revision||':'||document::text FROM mdm_assets.field_layouts WHERE tenant_id='{}'", case_tenant()))?;
        let business = || -> Result<Vec<String>> {
            let text = pg(&format!("SELECT encode(canonical,'hex') FROM (SELECT canonical FROM mdm_audit.receipts WHERE tenant_id='{0}' UNION ALL SELECT canonical FROM rss_audit.records WHERE tenant_id='{0}') records ORDER BY encode(canonical,'hex')", case_tenant()))?;
            Ok(crate::audit_test_support::decode_hex(&text)?.into_iter().filter(|r| r.source() == "mdm.business").map(|r| r.decoded.event().identity().event_id().as_str().to_owned()).collect())
        };
        let facts = business()?;
        ensure!(!facts.is_empty());
        let failed_id = Uuid::new_v4();
        let failed = Command::FieldLayoutWrite { change: Operation { operation_id: failed_id, expected_revision: 2, input: FieldLayout::default() } };
        // Failure while appending the real Audit record rolls the layout and receipt back.
        pg("CREATE FUNCTION public.reject_layout_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER reject_layout_audit BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_layout_audit();")?;
        let result = execute(&service, &failed).await;
        pg("DROP TRIGGER reject_layout_audit ON rss_audit.records; DROP FUNCTION public.reject_layout_audit();")?;
        ensure!(result.is_err(), "audit failure accepted layout");
        ensure!(pg(&format!("SELECT revision||':'||document::text FROM mdm_assets.field_layouts WHERE tenant_id='{}'", case_tenant()))? == before);
        ensure!(pg(&format!("SELECT count(*) FROM mdm_assets.operations WHERE tenant_id='{}' AND id='{failed_id}'", case_tenant()))?.trim() == "0");
        ensure!(business()? == facts);
        let cleared = execute(&service, &failed).await?;
        ensure!(cleared["asset"]["revision"] == 3);
        ensure!(execute(&service, &command).await? == recovered, "old receipt must survive later layout changes");
        let current = execute(&service, &Command::FieldLayoutRead { access: FieldLayoutAccess::Edit }).await?;
        ensure!(current["asset"]["revision"] == 3 && current["asset"]["groups"] == json!([]));
        let oversize = Command::FieldLayoutWrite { change: Operation { operation_id: Uuid::new_v4(), expected_revision: 3, input: FieldLayout { groups: (0..180).map(|_| FieldDisplayGroup { id: Uuid::new_v4(), name: "x".repeat(40), ..group.clone() }).collect() } } };
        ensure!(matches!(execute(&service, &oversize).await, Err(Error::Malformed)));
        let mut overflow = failed.clone();
        if let Command::FieldLayoutWrite { change } = &mut overflow { change.operation_id = Uuid::new_v4(); change.expected_revision = i64::MAX as u64; }
        ensure!(matches!(execute(&service, &overflow).await, Err(Error::Malformed)));
        Ok(())
    }).await
}
