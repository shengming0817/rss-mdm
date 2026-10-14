use super::*;
use sqlx::Connection;
#[tokio::test]
#[ignore = "MODULE=apple.collection: native protocol and durable state"]
async fn collection_lifecycle() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (_peer, device) = f.ready_local_peer().await?;
    let response = f
        .browser
        .call(
            &f.router,
            Method::POST,
            &format!("/api/v1/devices/{}/collection-runs", case_device()),
            Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
        )
        .await?;
    ensure!(
        response.0 == StatusCode::NOT_FOUND,
        "removed fixed collection endpoint: {response:?}"
    );
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.collection: published template and actual native peer"]
async fn published_native_template_uses_policy_and_direct_collection_progress() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    use crate::test_support::agent_execution::{post, resource, upload};
    use rss_mdm_resource::{
        NativeAdapter, NativeCollectionDefinition, NativeCollectionSpec, NativeMapping,
    };
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &[
            "inventory_read",
            "inventory_collect",
            "enrollment",
            "credentials",
            "operation_read",
            "operation_cancel",
        ],
    )?;
    for operation in [
        Permission::InventoryFieldsWrite,
        Permission::ResourceRead,
        Permission::ResourceWrite,
        Permission::PolicyRead,
        Permission::PolicyWrite,
        Permission::ScopeRead,
        Permission::ScopeWrite,
    ] {
        grants.push(Grant {
            operation,
            scope: Scope::Tenant,
        });
    }
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    let automation = crate::automation::Automation::connect(
        f.app.flow.planning.clone(),
        f.app.flow.assets.clone(),
        f.app.flow.compliance.clone(),
        crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(automation.registration(f.signals.flow()).critical());
    launch.finish();
    let result = async {
    let field = "custom.link_addresses";
    let definition = json!({"key":field,"version":1,"valueType":{"kind":"array","items":{"kind":"string","maxLength":128,"allowEmpty":false},"maxItems":100},"nullable":false,"manual":false,"sources":{"mdm.apple":0},"platforms":["macos"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null});
    let published = f.browser.call(&f.router, Method::PUT, &format!("/api/v1/asset-fields/{field}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":definition}}))).await?;
    ensure!(
        published.0 == StatusCode::OK,
        "list definition: {published:?}"
    );
    let template = NativeCollectionDefinition::new(NativeCollectionSpec {
        scope: rss_mdm_resource::TemplateScope::Device,
        applicability: Default::default(),
        adapter: NativeAdapter::AppleDeviceInformation,
        mappings: [
            (
                "device.model".into(),
                NativeMapping {
                    query: rss_mdm_resource::NativeQuery::Apple("Model".into()),
                mapping: rss_mdm_resource::ValueMapping::identity(""),
                },
            ),
            (
                field.into(),
                NativeMapping {
                    query: rss_mdm_resource::NativeQuery::Apple("EthernetMACs".into()),
                mapping: rss_mdm_resource::ValueMapping::identity(""),
                },
            ),
        ]
        .into(),
        timeout_seconds: 60,
        output_bytes: 16384,
    })?;
    let bytes = template.canonical();
    let id = Uuid::new_v4();
    let digest = rss_mdm_resource::Digest::of(&bytes).bytes();
    resource(
        &mut f.browser,
        &f.router,
        id,
        0,
        json!({"action":"create","kind":"native_collection"}),
    )
    .await?;
    resource(&mut f.browser,&f.router,id,1,json!({"action":"version","version":"v1","kind":"native_collection","variants":(["x86_64", "aarch64"].map(|architecture| json!({"platform":"macos","architecture":architecture,"key":"default","declaration":{"kind":"native_collection","artifact":{"reference":"native-template","length":bytes.len(),"sha256":digest},"definition":template}})))})).await?;
    ensure!(upload(&f.browser, &f.router, id, &bytes).await? == StatusCode::CREATED);
    resource(
        &mut f.browser,
        &f.router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let scope = Uuid::new_v4();
    post(&mut f.browser,&f.router,&format!("/api/v1/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}}})).await?;
    let policy = Uuid::new_v4();
    post(&mut f.browser,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
    let (run, payload) = peer.next("DeviceInformation").await?;
    ensure!(
        payload["Queries"].as_array().unwrap()
            == &vec![
                plist::Value::from("EthernetMACs"),
                plist::Value::from("Model")
            ]
    );
    peer.manage(
        "Acknowledged",
        Some(run),
        Some((
            "QueryResponses",
            plist::Value::Dictionary(protocol::dictionary([
                ("Model", "native-template-model".into()),
                (
                    "EthernetMACs",
                    plist::Value::Array(vec![
                        "aa:bb:cc:dd:ee:01".into(),
                        "aa:bb:cc:dd:ee:02".into(),
                    ]),
                ),
            ])),
        )),
    )
    .await?;
    let result = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/devices/{}/collections/{run}", case_device()),
            None,
        )
        .await?;
    ensure!(
        result.0 == StatusCode::OK && result.1["asset"]["run"]["result"] == "snapshot",
        "run: {result:?}"
    );
    ensure!(
        peer.manage("Idle", None, None).await?.is_empty(),
        "unchanged membership repeated native collection"
    );
    let item_path = format!(
        "/api/v1/devices/{}/collections/{run}/fields/{field}/items",
        case_device()
    );
    let first = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("{item_path}?limit=1"),
            None,
        )
        .await?;
    ensure!(
        first.0 == StatusCode::OK
            && first.1["asset"]["items"][0]["quality"] == "success"
            && first.1["asset"]["nextOffset"] == 1,
        "item quality: {first:?}"
    );
    let refresh_policy = Uuid::new_v4();
    post(&mut f.browser,&f.router,&format!("/api/v1/policies/{refresh_policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
    let (refresh, _) = peer.next("DeviceInformation").await?;
    let mut historical = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
    let parent = Uuid::new_v4();
    crate::test_support::agent_execution::historical_remote_run(&mut historical,case_tenant(),refresh,parent).await?;
    sqlx::query("UPDATE mdm_apple.attempts SET state='not_now',next_attempt=clock_timestamp() WHERE tenant_id=$1::uuid AND id=$2 AND phase='collect'").bind(case_tenant()).bind(refresh).execute(&mut historical).await?;
    ensure!(peer.manage("Idle",None,None).await?.is_empty(), "retired Remote collection was retried");

    ensure!(refresh != run);
    peer.manage(
        "Acknowledged",
        Some(refresh),
        Some((
            "QueryResponses",
            plist::Value::Dictionary(protocol::dictionary([
                ("Model", "refreshed-model".into()),
                (
                    "EthernetMACs",
                    plist::Value::Array(vec![
                        "aa:bb:cc:dd:ee:03".into(),
                        plist::Value::Boolean(true),
                    ]),
                ),
            ])),
        )),
    )
    .await?;
    f.app.execution.recover_remote_fixture(parent).await?;
    let state:String=sqlx::query_scalar("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(refresh).fetch_one(&mut historical).await?;
    ensure!(state == "succeeded", "original Remote native receipt failed to settle: {state}");
    historical.close().await?;
    let invalid = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!(
                "/api/v1/devices/{}/collections/{refresh}/fields/{field}/items",
                case_device()
            ),
            None,
        )
        .await?;
    ensure!(
        invalid.0 == StatusCode::OK
            && invalid.1["asset"]["items"][0]["quality"] == "success"
            && invalid.1["asset"]["items"][1]["quality"] == "invalid",
        "partial row quality: {invalid:?}"
    );
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let list = f
                .browser
                .call(
                    &f.router,
                    Method::GET,
                    &format!("/api/v1/devices/{}/inventory-lists/{field}", case_device()),
                    None,
                )
                .await?;
            if list.0 == StatusCode::OK && list.1["asset"]["total"] == 2 {
                ensure!(
                    list.1["asset"]["items"][0]["value"] == "aa:bb:cc:dd:ee:01",
                    "invalid list replaced trusted snapshot: {list:?}"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
        Ok::<_, anyhow::Error>(())
    }.await;
    let automation_shutdown = crate::test_support::stop_worker(Some(owner)).await;
    drop(device);
    let fixture_shutdown = f.close().await;
    result?;
    automation_shutdown?;
    fixture_shutdown
}

#[tokio::test]
#[ignore = "MODULE=apple.collection: current grant before native dispatch"]
async fn template_revocation_prevents_dispatch() -> Result<()> {
    withdrawn_template(false, "grant").await
}
#[tokio::test]
#[ignore = "MODULE=apple.collection: current grant before native receipt"]
async fn template_revocation_rejects_first_report() -> Result<()> {
    withdrawn_template(true, "grant").await
}
#[tokio::test]
#[ignore = "MODULE=apple.collection: current Policy before native receipt"]
async fn disabled_template_policy_rejects_first_report() -> Result<()> {
    withdrawn_template(true, "policy").await
}
#[tokio::test]
#[ignore = "MODULE=apple.collection: current applicability before native receipt"]
async fn template_access_rights_change_rejects_first_report() -> Result<()> {
    withdrawn_template(true, "rights").await
}

async fn withdrawn_template(dispatched: bool, withdrawal: &str) -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.policy_grants().await?;
    let definition = f.collection_template().await?;
    let owner = f.policy_worker().await?;
    let queued = f.queue_collection(&definition).await;
    crate::test_support::stop_worker(Some(owner)).await?;
    let (policy, run) = queued?;
    if dispatched {
        ensure!(peer.next("DeviceInformation").await?.0 == run);
    }
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    match withdrawal {
        "grant" => {
            crate::test_support::identity::set_grants(
                case_tenant(),
                crate::test_support::case::admin(),
                crate::test_support::identity::device_grants(
                    Some(case_device()),
                    &["inventory_read"],
                )?,
            )
            .await?
        }
        "policy" => {
            f.policy_post(
                &format!("/api/v1/policies/{policy}"),
                1,
                json!({"action":"put","enabled":false,"definition":definition}),
            )
            .await?;
        }
        "rights" => {
            sqlx::query("UPDATE mdm_apple.devices SET access_rights=access_rights & ~16 WHERE tenant_id=$1::uuid AND registration=(SELECT registration FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2)").bind(case_tenant()).bind(run).execute(&mut pg).await?;
        }
        _ => unreachable!(),
    }
    let response = if dispatched {
        peer.manage(
            "Acknowledged",
            Some(run),
            Some((
                "QueryResponses",
                plist::Value::Dictionary(protocol::dictionary([
                    ("Model", "unauthorized-model".into()),
                    ("OSVersion", "99.0".into()),
                ])),
            )),
        )
        .await?
    } else {
        peer.manage("Idle", None, None).await?
    };
    ensure!(response.is_empty(), "withdrawn collection dispatched work");
    let terminal: (bool, bool, String) = sqlx::query_as("SELECT sealed_at IS NOT NULL,batch IS NULL,reason FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut pg).await?;
    ensure!(
        terminal == (true, true, "revoked".into()),
        "withdrawn receipt reached Inventory: {terminal:?}"
    );
    let facts = crate::audit_test_support::read(&mut pg).await?;
    ensure!(
        facts
            .iter()
            .filter(|fact| fact.action() == "collection_finish"
                && fact.operation() == Some(run.to_string().as_str()))
            .count()
            == 1,
        "withdrawal lost exactly-once terminal audit"
    );
    pg.close().await?;
    drop(device);
    f.close().await
}
