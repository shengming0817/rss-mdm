use super::*;
use lifecycle::Peer;
use sqlx::Connection;
impl Fixture {
    pub async fn collection_cycle(&mut self, peer: &Peer) -> Result<()> {
        for (model, version, result) in [
            ("Mac14,7", Some("14.7"), "snapshot"),
            ("Mac14,8", None, "partial"),
        ] {
            let request = Uuid::new_v4();
            let body = json!({"source":"mdm.apple","requestId":request});
            let path = format!(
                "/api/v1/devices/{DEVICE}/collection-runs",
                DEVICE = case_device()
            );
            let reply = self
                .browser
                .call(&self.router, Method::POST, &path, Some(body.clone()))
                .await?;
            ensure!(
                reply.0 == StatusCode::ACCEPTED,
                "collection create: {reply:?}"
            );
            ensure!(
                self.browser
                    .call(&self.router, Method::POST, &path, Some(body))
                    .await?
                    == reply
            );
            let run = Uuid::parse_str(reply.1["runId"].as_str().unwrap())?;
            let (id, payload) = peer.next("DeviceInformation").await?;
            ensure!(
                id == run
                    && payload["Queries"].as_array().unwrap()
                        == &vec![plist::Value::from("Model"), plist::Value::from("OSVersion")]
            );
            let mut values = protocol::dictionary([("Model", model.into())]);
            if let Some(version) = version {
                values.insert("OSVersion".into(), version.into());
            }
            let extra = Some(("QueryResponses", plist::Value::Dictionary(values)));
            ensure!(
                peer.manage("Acknowledged", Some(id), extra.clone())
                    .await?
                    .is_empty()
            );
            ensure!(
                peer.manage("Acknowledged", Some(id), extra)
                    .await?
                    .is_empty()
            );
            let read = self
                .browser
                .call(
                    &self.router,
                    Method::GET,
                    &format!("{path}/{run}?source=mdm.apple"),
                    None,
                )
                .await?;
            ensure!(
                read.0 == StatusCode::OK && read.1["run"]["result"] == result,
                "collection read {read:?}"
            );
            ensure!(
                read.1["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|f| f["status"].is_null()),
                "Apple created SyncML status"
            );
            let mut pg = sqlx::PgConnection::connect_with(&crate::device::test_support::options(
                "postgres",
            )?)
            .await?;
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM rss_device_command.commands WHERE command_id=$1",
            )
            .bind(run.to_string())
            .fetch_one(&mut pg)
            .await?;
            ensure!(count == 0, "DeviceInformation became a device command");
            // Read actual Inventory projection, waiting only for the real worker.
            let mut projected = false;
            for _ in 0..100 {
                let rows:Vec<(String,Option<String>)>=sqlx::query_as("SELECT field,value FROM mdm.inventory WHERE tenant_id=$1::uuid AND source='mdm.apple' ORDER BY field").bind(case_tenant()).fetch_all(&mut pg).await?;
                let delivered: bool = sqlx::query_scalar(
                    "SELECT NOT delivery_pending FROM mdm_access.collection_runs WHERE id=$1::uuid",
                )
                .bind(run.to_string())
                .fetch_one(&mut pg)
                .await?;
                if delivered
                    && rows
                        == vec![
                            (
                                "device.model".into(),
                                Some(serde_json::to_string(&rss_mdm_inventory::Scalar::String(
                                    model.into(),
                                ))?),
                            ),
                            (
                                "device.os.version".into(),
                                Some(serde_json::to_string(&rss_mdm_inventory::Scalar::String(
                                    "14.7".into(),
                                ))?),
                            ),
                        ]
                {
                    projected = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if !projected {
                let read = self
                    .browser
                    .call(
                        &self.router,
                        Method::GET,
                        &format!("{path}/{run}?source=mdm.apple"),
                        None,
                    )
                    .await?;
                let rows:Vec<(String,Option<String>)>=sqlx::query_as("SELECT field,value FROM mdm.inventory WHERE tenant_id=$1::uuid AND source='mdm.apple' ORDER BY field").bind(case_tenant()).fetch_all(&mut pg).await?;
                anyhow::bail!("Inventory did not preserve partial response: {read:?}; {rows:?}")
            }
            pg.close().await?;
            let asset = self
                .browser
                .call(
                    &self.router,
                    Method::GET,
                    &format!("/api/v2/devices/{DEVICE}/inventory", DEVICE = case_device()),
                    None,
                )
                .await?;
            ensure!(
                asset.0 == StatusCode::OK,
                "Apple asset read failed: {asset:?}"
            );
            ensure!(
                asset.1["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"]
                    == model
            );
            ensure!(
                asset.1["asset"]["device"]["fields"]["device.os.version"]["state"]["value"]["value"]
                    == "14.7"
            );
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.collection: native protocol and durable state"]
async fn collection_lifecycle() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.collection_cycle(&peer).await?;
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
    let field = "custom.link_addresses";
    let definition = json!({"key":field,"version":1,"valueType":{"kind":"array","items":{"kind":"string","maxLength":128,"allowEmpty":false},"maxItems":100},"nullable":false,"manual":false,"sources":{"mdm.apple":0},"platforms":["macos"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null});
    let published = f.browser.call(&f.router, Method::PUT, &format!("/api/v2/asset-fields/{field}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":definition}}))).await?;
    ensure!(
        published.0 == StatusCode::OK,
        "list definition: {published:?}"
    );
    let template = NativeCollectionDefinition::new(NativeCollectionSpec {
        adapter: NativeAdapter::AppleDeviceInformation,
        mappings: [
            (
                "device.model".into(),
                NativeMapping {
                    query: "Model".into(),
                    pointer: String::new(),
                    columns: Default::default(),
                },
            ),
            (
                field.into(),
                NativeMapping {
                    query: "EthernetMACs".into(),
                    pointer: String::new(),
                    columns: Default::default(),
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
    resource(&mut f.browser,&f.router,id,1,json!({"action":"version","version":"v1","kind":"native_collection","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"native_collection","artifact":{"reference":"native-template","length":bytes.len(),"sha256":digest},"definition":template}}]})).await?;
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
    post(&mut f.browser,&f.router,&format!("/api/v2/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}}})).await?;
    let policy = Uuid::new_v4();
    post(&mut f.browser,&f.router,&format!("/api/v2/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
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
            &format!("/api/v2/devices/{}/collections/{run}", case_device()),
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
        "/api/v2/devices/{}/collections/{run}/fields/{field}/items",
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
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    post(&mut f.browser,&f.router,"/api/v2/remote-operations",json!({"operationId":Uuid::new_v4(),"resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"targets":{"kind":"devices","devices":[case_device()]},"action":{"kind":"collect_native"},"deadline":now+300})).await?;
    let (refresh, _) = peer.next("DeviceInformation").await?;
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
    let invalid = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!(
                "/api/v2/devices/{}/collections/{refresh}/fields/{field}/items",
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
                    &format!("/api/v2/devices/{}/inventory-lists/{field}", case_device()),
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
    crate::test_support::stop_worker(Some(owner)).await?;
    drop(device);
    f.close().await
}
