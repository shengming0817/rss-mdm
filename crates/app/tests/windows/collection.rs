use crate::authorization::{Grant, Permission, Scope};
use crate::execution::test_support::{Client, case_device, case_tenant, native};
use crate::test_support::agent_execution::{post, resource, upload_for};
use crate::windows::test_support::Host;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_resource::{
    NativeAdapter, NativeCollectionDefinition, NativeCollectionSpec, NativeMapping,
};
use rss_mdm_windows_mdm::{CodecLimits, syncml as s};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[tokio::test]
#[ignore = "MODULE=windows.management: native template over real SyncML mTLS"]
async fn native_template_policy_uses_correlated_get_and_collection_run() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut f = Client::start(host.browser.clone(), host.app.clone()).await?;
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &[
            "inventory_read",
            "inventory_collect",
            "operation_read",
            "operation_cancel",
        ],
    )?;
    for operation in [
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
        host.app.flow.planning.clone(),
        host.app.flow.assets.clone(),
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
    launch.stage_deferred_task_with_token(
        automation
            .registration(host.notifications.signals.flow())
            .critical(),
    );
    launch.stage_deferred_task_with_token(
        host.app
            .execution
            .clone()
            .registration(host.notifications.signals.flow())
            .critical(),
    );
    launch.finish();
    let template = NativeCollectionDefinition::new(NativeCollectionSpec {
        adapter: NativeAdapter::WindowsCsp,
        mappings: [(
            "device.model".into(),
            NativeMapping {
                query: "./DevDetail/DevTyp".into(),
                pointer: String::new(),
                columns: Default::default(),
            },
        )]
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
    resource(&mut f.browser,&f.router,id,1,json!({"action":"version","version":"v1","kind":"native_collection","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"native_collection","artifact":{"reference":"native-template","length":bytes.len(),"sha256":digest},"definition":template}}]})).await?;
    ensure!(
        upload_for(&f.browser, &f.router, id, &bytes, "windows", "x86_64").await?
            == StatusCode::CREATED
    );
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
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    post(&mut f.browser,&f.router,&format!("/api/v2/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","frequency":"every_trigger","schedule":{"trigger":{"kind":"interval","anchor":now-7200,"seconds":3600},"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"coalesce_one"}},"resource":{"id":id,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
    // The existing outbox accepts the action before its native read can be sent.
    use sqlx::Connection;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let pending = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let ready: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND gateway_accepted AND state->>'execution'='not_started')")
                .bind(case_tenant()).fetch_one(&mut pg).await?;
            if ready { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    }).await;
    if pending.is_err() {
        for query in [
            "SELECT to_jsonb(t) FROM mdm_planning.scopes t WHERE tenant_id=$1::uuid",
            "SELECT to_jsonb(t) FROM mdm_policy.policies t WHERE tenant_id=$1::uuid",
            "SELECT to_jsonb(t) FROM mdm_commands.action_runs t WHERE tenant_id=$1::uuid",
            "SELECT to_jsonb(t) FROM mdm_access.report_sources t WHERE tenant_id=$1::uuid",
        ] {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(query)
                .bind(case_tenant())
                .fetch_all(&mut pg)
                .await?;
            eprintln!("native wait {query}: {rows:?}");
        }
    }
    pending??;
    ensure!(
        native::post(&peer.mutual, &peer.url, &peer.message)
            .await?
            .status()
            == StatusCode::OK
    );
    let response = native::post(&peer.mutual, &peer.url, &peer.ack).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "Get admission: {}",
        response.status()
    );
    let wire = s::decode(&response.bytes().await?, &CodecLimits::default())?;
    let gets: Vec<_> = wire
        .commands
        .iter()
        .filter_map(|command| match command {
            s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
            _ => None,
        })
        .collect();
    ensure!(
        gets.iter()
            .filter(|(_, uri)| uri == "./DevDetail/DevTyp")
            .count()
            == 1,
        "template Get missing: {gets:?}"
    );
    let packet = native::report(&peer.message, &gets, "template-workstation", 200);
    ensure!(
        native::post(&peer.mutual, &peer.url, &packet)
            .await?
            .status()
            == StatusCode::OK
    );
    // Exact transport retry cannot create another run or observation.
    ensure!(
        native::post(&peer.mutual, &peer.url, &packet)
            .await?
            .status()
            == StatusCode::OK
    );
    let runs: Vec<Uuid> = sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2")
        .bind(case_tenant()).bind(policy).fetch_all(&mut pg).await?;
    ensure!(runs.len() == 1, "native Policy runs: {runs:?}");
    let result = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v2/devices/{}/collections/{}", case_device(), runs[0]),
            None,
        )
        .await?;
    ensure!(
        result.0 == StatusCode::OK && result.1["asset"]["run"]["result"] == "snapshot",
        "native progress: {result:?}"
    );
    pg.close().await?;
    crate::test_support::stop_worker(Some(owner)).await?;
    host.close().await
}
