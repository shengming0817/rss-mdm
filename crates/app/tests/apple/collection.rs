use super::*;
use sqlx::Connection;

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
    let field = "custom.active_users";
    let definition = json!({"key":field,"version":1,"valueType":{"kind":"array","items":{"kind":"string","maxLength":128,"allowEmpty":false},"maxItems":100},"nullable":false,"manual":false,"sources":{"mdm.apple":0},"platforms":["macos"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null});
    let published = f.browser.call(&f.router, Method::PUT, &format!("/api/v1/asset-fields/{field}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":definition}}))).await?;
    ensure!(
        published.0 == StatusCode::OK,
        "list definition: {published:?}"
    );
    let template = NativeCollectionDefinition::new(NativeCollectionSpec {
        scope: rss_mdm_resource::TemplateScope::Device,
        applicability: rss_mdm_resource::Applicability { minimum_os_version: Some("15.0".into()), ..Default::default() },
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
                    query: rss_mdm_resource::NativeQuery::Apple("ActiveManagedUsers".into()),
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
    let (run, payload) = peer.next_collection().await?;
    ensure!(
        payload["Queries"].as_array().unwrap()
            == &vec![
                plist::Value::from("ActiveManagedUsers"),
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
                    "ActiveManagedUsers",
                    plist::Value::Array(vec![
                        "fixture-user-one".into(),
                        "fixture-user-two".into(),
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
    // A prior run observed macOS 14. The current peer reports 15 in its
    // prerequisite response; historical evidence must not block that refresh.
    let mut prior = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
    let updated = sqlx::query("UPDATE mdm_apple.attempts SET context=jsonb_set(context,'{version}','\"14.0\"'::jsonb) WHERE tenant_id=$1::uuid AND id=$2 AND phase='collect'")
        .bind(case_tenant()).bind(run).execute(&mut prior).await?;
    ensure!(updated.rows_affected() == 1);
    prior.close().await?;
    let current_definition = json!({"scope":scope,"action":{"kind":"native_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":300}});
    let preview = f.browser.call(&f.router, Method::POST, "/api/v1/policies/previews", Some(json!({"definition":current_definition}))).await?;
    ensure!(preview.0 == StatusCode::OK && preview.1["items"][0]["taskAdmission"]["state"] == "channel_unknown", "historical evidence became current preview eligibility: {preview:?}");
    // New evidence below the minimum, or missing its OS version, must not
    // dispatch business queries even when historical context exists.
    for version in [Some("14.0"), None] {
        let (_, unsupported) = f.queue_collection(&current_definition, &peer).await?;
        let (prerequisite, _) = peer.next("DeviceInformation").await?;
        let mut facts = protocol::dictionary([
            ("IsSupervised", true.into()), ("IsAppleSilicon", true.into()),
        ]);
        if let Some(version) = version { facts.insert("OSVersion".into(), version.into()); }
        let reply = peer.manage("Acknowledged", Some(prerequisite), Some(("QueryResponses", facts.into()))).await?;
        let reply = if version.is_some() {
            let (prerequisite, _) = lifecycle::command(&reply, "SecurityInfo")?;
            peer.manage("Acknowledged", Some(prerequisite), Some(("SecurityInfo", protocol::dictionary([
                ("ManagementStatus", protocol::dictionary([
                    ("IsUserEnrollment", false.into()), ("EnrolledViaDEP", false.into()), ("UserApprovedEnrollment", true.into()),
                ]).into()),
            ]).into()))).await?
        } else { reply };
        ensure!(reply.is_empty(), "unsupported current version dispatched business collection");
        let mut check = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let terminal: (bool, bool) = sqlx::query_as("SELECT sealed_at IS NOT NULL,NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE a.tenant_id=c.tenant_id AND a.collection=c.id AND a.phase='collect') FROM mdm_access.collection_runs c WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(unsupported).fetch_one(&mut check).await?;
        ensure!(terminal == (true, true), "version rejection did not seal without dispatch: {terminal:?}");
        check.close().await?;
    }
    let refresh_policy = Uuid::new_v4();
    post(&mut f.browser,&f.router,&format!("/api/v1/policies/{refresh_policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
    let (refresh, _) = peer.next_collection().await?;
    ensure!(refresh != run);
    peer.manage(
        "Acknowledged",
        Some(refresh),
        Some((
            "QueryResponses",
            plist::Value::Dictionary(protocol::dictionary([
                ("Model", "refreshed-model".into()),
                (
                    "ActiveManagedUsers",
                    plist::Value::Array(vec![
                        "fixture-user-three".into(),
                        plist::Value::String("x".repeat(129)),
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
                    list.1["asset"]["items"][0]["value"] == "fixture-user-one",
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
    let queued = f.queue_collection(&definition, &peer).await;
    crate::test_support::stop_worker(Some(owner)).await?;
    let (policy, run) = queued?;
    if dispatched {
        ensure!(peer.next_collection().await?.0 == run);
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

#[tokio::test]
#[ignore = "MODULE=apple.collection: exact user scope dispatch receipt and read isolation"]
async fn user_collection_cannot_cross_device_or_other_user_namespace() -> Result<()> {
    use lifecycle::command;
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.policy_grants().await?;
    let user = Uuid::new_v4();
    let other = Uuid::new_v4();
    peer.user_token(user, 41).await?;
    peer.user_token(other, 42).await?;
    let template = f
        .collection_template_scoped(rss_mdm_resource::TemplateScope::User {
            identity: user.to_string(),
        })
        .await?;
    let worker = f.policy_worker().await?;
    let (_, run) = f.queue_collection(&template, &peer).await?;
    let (prerequisite, _) = peer.next("DeviceInformation").await?;
    let security = peer
        .manage(
            "Acknowledged",
            Some(prerequisite),
            Some((
                "QueryResponses",
                protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsSupervised", true.into()),
                    ("IsAppleSilicon", true.into()),
                ])
                .into(),
            )),
        )
        .await?;
    let (prerequisite, _) = command(&security, "SecurityInfo")?;
    let device_reply = peer
        .manage(
            "Acknowledged",
            Some(prerequisite),
            Some((
                "SecurityInfo",
                protocol::dictionary([(
                    "ManagementStatus",
                    protocol::dictionary([
                        ("IsUserEnrollment", false.into()),
                        ("EnrolledViaDEP", false.into()),
                        ("UserApprovedEnrollment", true.into()),
                    ])
                    .into(),
                )])
                .into(),
            )),
        )
        .await?;
    ensure!(
        device_reply.is_empty(),
        "user payload escaped on device channel"
    );
    ensure!(
        peer.user_manage(other, "Idle", None, None)
            .await?
            .1
            .is_empty()
    );
    let (status, payload) = peer.user_manage(user, "Idle", None, None).await?;
    ensure!(status == StatusCode::OK);
    let (attempt, payload) = command(&payload, "DeviceInformation")?;
    ensure!(attempt == run);
    let mut response = plist::Dictionary::new();
    for query in payload["Queries"].as_array().unwrap() {
        let name = query.as_string().unwrap();
        response.insert(
            name.into(),
            match name {
                "OSVersion" => "15.0".into(),
                "Model" => "user-model".into(),
                _ => anyhow::bail!("unexpected query {name}"),
            },
        );
    }
    let extra = Some(("QueryResponses", plist::Value::Dictionary(response)));
    ensure!(
        peer.user_manage(other, "Acknowledged", Some(run), extra.clone())
            .await?
            .0
            != StatusCode::OK
    );
    ensure!(
        peer.user_manage(user, "Acknowledged", Some(run), extra.clone())
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        peer.user_manage(user, "Acknowledged", Some(run), extra)
            .await?
            .0
            == StatusCode::OK
    );
    let path = format!("/api/v1/devices/{}/collections/{run}", case_device());
    ensure!(f.browser.call(&f.router, Method::GET, &path, None).await?.0 == StatusCode::NOT_FOUND);
    ensure!(
        f.browser
            .call(
                &f.router,
                Method::GET,
                &format!(
                    "{path}?scope=%7B%22kind%22:%22apple_user%22,%22identity%22:%22{other}%22%7D"
                ),
                None
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    let result = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("{path}?scope=%7B%22kind%22:%22apple_user%22,%22identity%22:%22{user}%22%7D"),
            None,
        )
        .await?;
    ensure!(result.0 == StatusCode::OK, "scoped result {result:?}");
    ensure!(
        result.1["asset"]["run"]["fields"][0]["scope"]
            == json!({"kind":"apple_user","identity":user})
    );
    crate::test_support::stop_worker(Some(worker)).await?;
    drop(device);
    f.close().await
}
