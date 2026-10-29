use super::*;
use anyhow::Context;
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
    crate::test_support::identity::seed_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    let automation = crate::test_support::workers::Workers::open(
        f.planning.clone(),
        Some(f.commands.events.clone()),
        crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        automation.scheduler.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(
        std::sync::Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
            crate::planning::test_support::scopes(&f.planning).await,
            automation.scheduler.store.clone(),
        ))
        .registration(f.signals.handle(crate::worker_wake::Work::Scopes))
        .critical(),
    );
    automation.register(&f.signals, |task| {
        launch.stage_deferred_task_with_token(task.critical());
    });
    launch.finish();
    f.router = f.router.clone().merge(f.authority.protect(
        {
 rss_mdm_http_contract::route_module! { struct PublishedNativeTemplateUsesPolicyAndDirectCollectionProgressModule1 for [Browser] { api_v1 at "/api/v1" } }
 PublishedNativeTemplateUsesPolicyAndDirectCollectionProgressModule1 { api_v1: rss_mdm_management_http::policy_events::routes(f.commands.events.clone()) }.assemble()
},
    )?);
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
                mapping: rss_mdm_agent_wire::runtime::ValueMapping::identity(""),
                },
            ),
            (
                field.into(),
                NativeMapping {
                    query: rss_mdm_resource::NativeQuery::Apple("ActiveManagedUsers".into()),
                mapping: rss_mdm_agent_wire::runtime::ValueMapping::identity(""),
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
            && first.1["asset"]["nextCursor"].is_string(),
        "item quality: {first:?}"
    );
    // A prior run observed macOS 14. The current peer reports 15 in its
    // prerequisite response; historical evidence must not block that refresh.
    let mut prior = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut prior).await?;
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
                        "fixture-user-four".into(),
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
                "/api/v1/devices/{}/collections/{refresh}/fields/{field}/items?limit=2",
                case_device()
            ),
            None,
        )
        .await?;
    ensure!(
        invalid.0 == StatusCode::OK
            && invalid.1["asset"]["items"][0]["quality"] == "success"
            && invalid.1["asset"]["items"][1]["quality"] == "invalid"
            && invalid.1["asset"]["items"][0]["value"] == json!({"kind":"string","value":"fixture-user-three"})
            && invalid.1["asset"]["items"][1]["value"].is_null(),
        "partial row quality: {invalid:?}"
    );
    let cursor = invalid.1["asset"]["nextCursor"].as_str().context("collection continuation")?;
    let tail = f.browser.call(&f.router, Method::GET,
        &format!("/api/v1/devices/{}/collections/{refresh}/fields/{field}/items?cursor={cursor}&limit=2", case_device()), None).await?;
    ensure!(tail.0 == StatusCode::OK && tail.1["asset"]["items"][0]["index"] == 2
        && tail.1["asset"]["items"][0]["value"] == json!({"kind":"string","value":"fixture-user-four"})
        && tail.1["asset"]["nextCursor"].is_null(), "diagnostic ordinal: {tail:?}");
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
    // An early event resets the native collection clock only when the real peer starts it.
    let now = f.clock.unix_seconds()?;
    let periodic = Uuid::new_v4();
    post(&mut f.browser,&f.router,&format!("/api/v1/policies/{periodic}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"customEvent":"native-clock","scope":scope,"action":{"kind":"native_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"schedule":{"trigger":{"kind":"interval","anchor":now+120,"seconds":3600},"misfire":{"kind":"coalesce_one"},"notBefore":0,"jitterSeconds":0},"runLifetimeSeconds":300}}}})).await?;
    let batch=post(&mut f.browser,&f.router,&format!("/api/v1/devices/{}/policy-events",case_device()),json!({"operationId":Uuid::new_v4(),"event":"native-clock","source":{"kind":"human"}})).await?;
    let members_path=format!("/api/v1/devices/{}/policy-event-batches/{}/members",case_device(),batch["batchId"].as_str().context("batch")?);
    let action_run=tokio::time::timeout(Duration::from_secs(20),async {loop {
        let(status,members)=f.browser.call(&f.router,Method::GET,&members_path,None).await?;
        ensure!(status==StatusCode::OK,"{members}");
        if members["items"][0]["state"]!="pending" {
            ensure!(members["items"][0]["state"]=="accepted","{members}");
            break Ok::<_,anyhow::Error>(Uuid::parse_str(members["items"][0]["decision"]["operations"][0]["id"].as_str().context("operation")?)?);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }}).await??;
    let (native_run,_) = peer.next_collection().await?;
    peer.manage("Acknowledged",Some(native_run),Some(("QueryResponses",protocol::dictionary([
        ("Model","clock-model".into()),("ActiveManagedUsers",plist::Value::Array(vec![])),
    ]).into()))).await?;
    let runtime=f.commands.runtime.clone();let reader_runtime=runtime.clone();let execution=f.commands.service.clone();
    let correct=runtime.local_tx(f.planning.tenant,crate::identity::deadline(),|tx|Box::pin(async move {
        let run=rss_mdm_execution_service::actions::storage::load_run(tx,action_run).await.map_err(|e|sqlx::Error::Protocol(e.to_string()))?;
        let started=run.state.started_at.ok_or_else(||sqlx::Error::Protocol("native Start missing".into()))?;
        let reader=rss_mdm_policy_postgres::PolicyReader::bind(reader_runtime,tx.tenant_id());
        let plan=rss_mdm_execution_service::actions::storage::load_source(&reader,tx,run.source).await.map_err(|e|sqlx::Error::Protocol(e.to_string()))?;
        let early=Uuid::new_v4();let due=Uuid::new_v4();
        for (at,id) in [(started+120,early),(started+3600,due)] {
            rss_mdm_execution_service::actions::production::accept_for_device(&execution,tx,&plan,&run.target,rss_mdm_execution_service::actions::production::AdmissionTrigger::Scheduled,at,id).await.map_err(|e|sqlx::Error::Protocol(e.to_string()))?;
        }
        let tenant=tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move {let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=ANY($2)").bind(tenant).bind(vec![early,due]).fetch_all(c).await?;Ok(ids==vec![due])})).await
    })).await.fold(Ok,|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")))?;
    ensure!(correct,"native collection must be due one hour after actual Start");
        Ok::<_, anyhow::Error>(())
    }.await;
    let automation_shutdown = crate::test_support::runtime::stop_worker(Some(owner)).await;
    drop(device);
    let fixture_shutdown = f.close().await;
    result?;
    automation_shutdown?;
    fixture_shutdown
}

#[tokio::test]
#[ignore = "MODULE=apple.collection: current grant before native receipt"]
async fn template_revocation_rejects_first_report() -> Result<()> {
    withdrawn_template("grant").await
}
#[tokio::test]
#[ignore = "MODULE=apple.collection: current Policy before native receipt"]
async fn disabled_template_policy_rejects_first_report() -> Result<()> {
    withdrawn_template("policy").await
}
#[tokio::test]
#[ignore = "MODULE=apple.collection: current applicability before native receipt"]
async fn template_access_rights_change_rejects_first_report() -> Result<()> {
    withdrawn_template("rights").await
}

async fn withdrawn_template(withdrawal: &str) -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    crate::test_support::identity::seed_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        Fixture::policy_grants()?,
    )
    .await?;
    let definition = f.collection_template().await?;
    let owner = f.policy_worker().await?;
    let queued = f.queue_collection(&definition, &peer).await;
    crate::test_support::runtime::stop_worker(Some(owner)).await?;
    let (policy, run) = queued?;
    ensure!(peer.next_collection().await?.0 == run);
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    match withdrawal {
        "grant" => {
            crate::test_support::identity::change_grants(
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
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
                .bind(case_tenant())
                .execute(&mut pg)
                .await?;
            sqlx::query("UPDATE mdm_apple.devices SET access_rights=access_rights & ~16 WHERE tenant_id=$1::uuid AND registration=(SELECT registration FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2)").bind(case_tenant()).bind(run).execute(&mut pg).await?;
        }
        _ => unreachable!(),
    }
    let response = peer
        .manage(
            "Acknowledged",
            Some(run),
            Some((
                "QueryResponses",
                plist::Value::Dictionary(protocol::dictionary([
                    ("Model", "accepted-model".into()),
                    ("OSVersion", "14.0".into()),
                ])),
            )),
        )
        .await?;
    ensure!(response.is_empty(), "withdrawn collection dispatched work");
    let terminal: (bool, bool, String) = sqlx::query_as("SELECT sealed_at IS NOT NULL,batch IS NULL,reason FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut pg).await?;
    ensure!(
        terminal
            == if withdrawal == "rights" || withdrawal == "policy" {
                (true, true, "revoked".into())
            } else {
                (true, false, "complete".into())
            },
        "withdrawn receipt reached Inventory: {terminal:?}"
    );
    let facts =
        crate::audit_test_support::read(&mut pg, crate::test_support::case::tenant()).await?;
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
    crate::test_support::identity::seed_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        Fixture::policy_grants()?,
    )
    .await?;
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
    crate::test_support::runtime::stop_worker(Some(worker)).await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.collection: builtin software list, projection and ordinal pages"]
async fn builtin_applications_preserve_optional_identifiers_and_last_trusted_snapshot() -> Result<()>
{
    use rss_mdm_resource::{Artifact, Digest, Id, Platform, blueprints};
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    crate::test_support::identity::seed_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        Fixture::policy_grants()?,
    )
    .await?;
    let blueprint =
        blueprints::get("macos.installed_applications", "1").context("builtin applications")?;
    let blueprints::Definition::NativeCollection { template } = blueprint.definition else {
        anyhow::bail!("native applications blueprint");
    };
    let bytes = template.canonical();
    let resource = Uuid::new_v4();
    crate::test_support::planning_http::seed_native_template(
        &f.planning.runtime,
        f.planning.tenant,
        resource,
        Platform::MacOS,
        template,
    )
    .await?;
    let artifact = Artifact::new(
        Id::new("native-template")?,
        bytes.len() as u64,
        Digest::of(&bytes),
    )?;
    rss_mdm_content_service::fixture::artifact(
        f.commands.content.as_deref().context("native content")?,
        &artifact,
        bytes,
        f.clock.unix_seconds()? + 86400,
    )
    .await?;
    let scope = Uuid::new_v4();
    crate::test_support::agent_execution::seed_scope(
        &f.planning,
        scope,
        json!([{"kind":"device","id":case_device()}]),
    )
    .await?;
    let definition = json!({"scope":scope,"action":{"kind":"native_collection","resource":{
        "id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"
    },"runLifetimeSeconds":300}});
    let owner = f.policy_worker().await?;
    let result = async {
        let field = "device.software.apple.installed_applications";
        let valid = vec![
            protocol::dictionary([
                ("Name", "Anonymous".into()),
                ("Path", "/Applications/Anonymous.app".into()),
            ])
            .into(),
            protocol::dictionary([
                ("Identifier", "com.example.same".into()),
                ("Path", "/Applications/One.app".into()),
            ])
            .into(),
            protocol::dictionary([
                ("Identifier", "com.example.same".into()),
                ("Path", "/Applications/Two.app".into()),
            ])
            .into(),
            plist::Dictionary::new().into(),
            protocol::dictionary([("Identifier", "".into())]).into(),
        ];
        let values = json!([
            {"id":""},
            {"id":"com.example.same","path":"/Applications/One.app"},
            {"id":"com.example.same","path":"/Applications/Two.app"},
            {"name":"Anonymous","path":"/Applications/Anonymous.app"}, {}
        ]);
        let catalog = rss_mdm_inventory::builtin::fields();
        let builtin = catalog
            .iter()
            .find(|f| f.key.as_str() == field)
            .context("applications field")?;
        let rss_mdm_inventory::ValueType::Array { items, .. } = &builtin.value_type else {
            anyhow::bail!("application array");
        };
        let expected = values
            .as_array()
            .unwrap()
            .iter()
            .map(|row| Ok(serde_json::to_value(items.decode_json(row)?)?))
            .collect::<Result<Vec<_>>>()?;
        let invalid = vec![protocol::dictionary([("Identifier", 42.into())]).into()];
        let mut trusted = Vec::new();
        let mut reordered = valid.clone();
        reordered.reverse();
        for (rows, complete, expected_rows) in [
            (valid, true, expected.clone()),
            (reordered, true, expected.clone()),
            (invalid, false, expected),
            (vec![], true, vec![]),
        ] {
            let (_, run) = f.queue_collection(&definition, &peer).await?;
            let (command, _) = peer.next("InstalledApplicationList").await?;
            ensure!(run == command, "response must belong to this collection");
            peer.manage(
                "Acknowledged",
                Some(command),
                Some(("InstalledApplicationList", plist::Value::Array(rows))),
            )
            .await?;
            // Wait for this exact response to be consumed and projected, not just for old rows to exist.
            let view = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let reply = f
                        .browser
                        .call(
                            &f.router,
                            Method::GET,
                            &format!("/api/v1/devices/{}/collections/{run}", case_device()),
                            None,
                        )
                        .await?;
                    ensure!(reply.0 == StatusCode::OK, "collection read: {reply:?}");
                    let view = &reply.1["asset"]["run"];
                    if view["finishedAt"].is_number()
                        && view["deliveryPending"] == false
                        && view["delivery"]["projection"] == "projected"
                    {
                        return Ok::<_, anyhow::Error>(view.clone());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await??;
            ensure!(
                view["complete"] == complete
                    && view["result"] == if complete { "snapshot" } else { "failed" },
                "application coverage: {view}"
            );
            ensure!(
                view["delivery"]["receipt"]["batch_id"] == run.to_string(),
                "wrong receipt: {view}"
            );
            let quality = &view["fields"][0];
            ensure!(
                quality["field"] == field
                    && quality["quality"] == if complete { "success" } else { "failed" },
                "application quality: {view}"
            );
            // A wrong protocol type is rejected before Inventory can classify individual rows.
            ensure!(
                quality["invalidItems"] == 0
                    && quality["itemCount"] == if complete { expected_rows.len() } else { 0 },
                "application diagnostics: {view}"
            );
            let path = format!("/api/v1/devices/{}/inventory-lists/{field}", case_device());
            let mut cursor = None;
            let mut actual = Vec::new();
            loop {
                let url = match &cursor {
                    Some(cursor) => format!("{path}?limit=2&cursor={cursor}"),
                    None => format!("{path}?limit=2"),
                };
                let page = f.browser.call(&f.router, Method::GET, &url, None).await?;
                ensure!(
                    page.0 == StatusCode::OK && page.1["asset"]["total"] == expected_rows.len(),
                    "application page: {page:?}"
                );
                let rows = page.1["asset"]["items"].as_array().context("list rows")?;
                ensure!(
                    rows.len() <= 2 && actual.len() + rows.len() <= expected_rows.len(),
                    "unbounded or repeated page"
                );
                actual.extend_from_slice(rows);
                cursor = page.1["asset"]["nextCursor"].as_str().map(str::to_owned);
                if cursor.is_none() {
                    break;
                }
                ensure!(!rows.is_empty(), "empty continuation page");
            }
            ensure!(
                actual == expected_rows,
                "applications changed order, identity or properties: {actual:?}"
            );
            if complete {
                trusted = actual;
            } else {
                ensure!(
                    actual == trusted,
                    "failed response replaced trusted applications"
                );
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let shutdown = crate::test_support::runtime::stop_worker(Some(owner)).await;
    drop(device);
    let close = f.close().await;
    result?;
    shutdown?;
    close
}

/// A native request waiting for the history clock must not retain the registration row.
/// The old row -> watermark order deadlocked a collection finalizer holding that clock.
#[tokio::test]
#[ignore = "make t2 MODULE=apple.collection"]
async fn native_receipt_waits_for_watermark_before_registration_write() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let mut hold =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("BEGIN").execute(&mut hold).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('lock_timeout','500',true)")
        .bind(case_tenant())
        .execute(&mut hold)
        .await?;
    sqlx::query("SELECT mdm.lock_asset_watermark($1::uuid)")
        .bind(case_tenant())
        .execute(&mut hold)
        .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut hold)
        .await?;
    let client = peer.client.clone();
    let origin = peer.origin.clone();
    let bytes = protocol::xml(protocol::dictionary([
        ("Status", "Idle".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
    ]))?;
    let request = tokio::spawn(async move {
        client
            .put(format!("{origin}/mdm"))
            .header("content-type", "application/xml")
            .body(bytes)
            .send()
            .await
    });
    let result = async {
        let mut observer = sqlx::PgConnection::connect_with(
            &crate::device::test_support::options("postgres")?,
        ).await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%mdm.lock_asset_watermark%')")
                    .bind(pid).fetch_one(&mut observer).await?;
                if waiting { return Ok::<_,anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        // Same-value update still takes the real registration row lock, without manufacturing facts.
        let changed = sqlx::query("UPDATE mdm_access.registrations SET next_command=next_command WHERE tenant_id=$1::uuid AND device=$2 AND state='active'")
            .bind(case_tenant()).bind(case_device()).execute(&mut hold).await?;
        ensure!(changed.rows_affected()==1,"missing registered test device");
        observer.close().await?;
        Ok::<_,anyhow::Error>(())
    }.await;
    sqlx::query("ROLLBACK").execute(&mut hold).await?;
    let response = request.await??;
    let status = response.status();
    drop(response);
    hold.close().await?;
    drop(device);
    f.close().await?;
    result?;
    ensure!(
        status == StatusCode::OK,
        "native request did not resume: {status}"
    );
    Ok(())
}
