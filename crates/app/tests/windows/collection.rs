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
    template_flow(None, 9, Completion::Snapshot).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: template authority before first fragment"]
async fn template_revocation_before_first_fragment_aborts() -> anyhow::Result<()> {
    template_flow(Some(false), 9, Completion::Snapshot).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: template authority between fragments"]
async fn template_revocation_between_fragments_aborts() -> anyhow::Result<()> {
    template_flow(Some(true), 9, Completion::Snapshot).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: last supported collection dispatch message"]
async fn template_dispatch_at_last_supported_message() -> anyhow::Result<()> {
    template_flow(
        None,
        CodecLimits::default().session_messages as u32 - 1,
        Completion::Snapshot,
    )
    .await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: original Remote collection receipt without redelivery"]
async fn historical_remote_template_settles_original_results_without_cache_redelivery()
-> anyhow::Result<()> {
    template_flow(None, 9, Completion::Historical).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: client abort of a real template run"]
async fn template_client_abort_cannot_publish_a_snapshot() -> anyhow::Result<()> {
    template_flow(None, 9, Completion::SessionAbort).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: non-Final report at the message budget"]
async fn template_nonfinal_message_budget_cannot_publish_a_snapshot() -> anyhow::Result<()> {
    template_flow(
        None,
        CodecLimits::default().session_messages as u32 - 1,
        Completion::MessageBudget,
    )
    .await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: dynamic inventory through SyncML and projection"]
async fn dynamic_inventory_reenumerates_and_projects() -> anyhow::Result<()> {
    template_flow(None, 9, Completion::Inventory).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: a missing dynamic child cannot publish an empty list"]
async fn dynamic_inventory_missing_child_is_partial() -> anyhow::Result<()> {
    template_flow(None, 9, Completion::MissingChild).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: confirmed empty replaces only native inventory"]
async fn dynamic_empty_preserves_agent_software() -> anyhow::Result<()> {
    template_flow(None, 9, Completion::EmptyInventory).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: Final budget boundary preserves confirmed partial fields"]
async fn dynamic_final_budget_preserves_partial_inventory() -> anyhow::Result<()> {
    template_flow(
        None,
        CodecLimits::default().session_messages as u32 - 1,
        Completion::FinalInventoryBudget,
    )
    .await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: dynamic leaf MoreData uses exact persisted ownership"]
async fn dynamic_leaf_more_data_completes() -> anyhow::Result<()> {
    template_flow(None, 9, Completion::FragmentInventory).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: dynamic leaf replay and continuation recheck grants"]
async fn dynamic_leaf_replay_and_continuation_revalidate_grants() -> anyhow::Result<()> {
    template_flow(None, 9, Completion::RevokedInventory).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: expired template cannot continue a large object"]
async fn expired_template_rejects_more_data() -> anyhow::Result<()> {
    template_flow(None, 9, Completion::Expired).await
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Expired,
    Snapshot,
    Inventory,
    MissingChild,
    EmptyInventory,
    FinalInventoryBudget,
    FragmentInventory,
    RevokedInventory,
    Historical,
    SessionAbort,
    MessageBudget,
}
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and durable recovery assertions shared by T2 scenarios"
)]
async fn template_flow(
    revoke_after_first: Option<bool>,
    request_message: u32,
    completion: Completion,
) -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let agent_source = if matches!(
        completion,
        Completion::Inventory
            | Completion::MissingChild
            | Completion::EmptyInventory
            | Completion::FinalInventoryBudget
            | Completion::FragmentInventory
            | Completion::RevokedInventory
    ) {
        Some(crate::test_support::inventory::seed_source(
            case_device(),
            "agent",
            "agent.builtin",
            "Agent model",
        )?)
    } else {
        None
    };
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
        Permission::InventorySensitiveRead,
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
        host.app.flow.compliance.clone(),
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
            .registration(host.notifications.signals.execution())
            .critical(),
    );
    launch.finish();
    let mut owner = Some(owner);
    let template = NativeCollectionDefinition::new(NativeCollectionSpec {
        scope: rss_mdm_resource::TemplateScope::Device,
        applicability: rss_mdm_resource::Applicability {
            minimum_build: Some(22000),
            enrollments: ["primary".into()].into(),
            ..Default::default()
        },
        adapter: NativeAdapter::WindowsRead,
        mappings: [(
            "device.model".into(),
            NativeMapping {
                query: rss_mdm_resource::NativeQuery::Windows(
                    rss_mdm_resource::WindowsRead::Scalar {
                        uri: "./DevDetail/DevTyp".into(),
                    },
                ),
                mapping: rss_mdm_resource::ValueMapping {
                    pointer: "".into(),
                    conversion: rss_mdm_resource::Conversion::Enum {
                        values: [(
                            "template-workstation".into(),
                            json!("canonical-workstation"),
                        )]
                        .into(),
                    },
                    columns: Default::default(),
                },
            },
        )]
        .into(),
        timeout_seconds: 120,
        output_bytes: 16384,
    })?;
    let template = if matches!(
        completion,
        Completion::Inventory
            | Completion::MissingChild
            | Completion::EmptyInventory
            | Completion::FinalInventoryBudget
            | Completion::FragmentInventory
            | Completion::RevokedInventory
    ) {
        let mut spec = template.spec().clone();
        let builtin = rss_mdm_resource::blueprints::get("windows.software.win32", "2").unwrap();
        let rss_mdm_resource::blueprints::Definition::NativeCollection { template } =
            builtin.definition
        else {
            panic!("Windows software blueprint must be a native collection")
        };
        spec.mappings.extend(template.spec().mappings.clone());
        NativeCollectionDefinition::new(spec)?
    } else {
        template
    };
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
    resource(&mut f.browser,&f.router,id,1,json!({"action":"version","version":"v1","kind":"native_collection","variants":(["x86_64", "aarch64"].map(|architecture| json!({"platform":"windows","architecture":architecture,"key":"default","declaration":{"kind":"native_collection","artifact":{"reference":"native-template","length":bytes.len(),"sha256":digest},"definition":template}})))})).await?;
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
    post(&mut f.browser,&f.router,&format!("/api/v1/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}}})).await?;
    let policy = Uuid::new_v4();
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    post(&mut f.browser,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","frequency":"every_trigger","schedule":{"trigger":{"kind":"interval","anchor":now-7200,"seconds":3600},"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"coalesce_one"}},"resource":{"id":id,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
    let directory = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/policies?action=native_collection&resource={id}"),
            None,
        )
        .await?;
    ensure!(directory.0 == StatusCode::OK, "{directory:?}");
    ensure!(
        directory.1["items"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["id"] == policy.to_string())),
        "native collection missing from directory: {directory:?}"
    );
    let invalid = f
        .browser
        .call(
            &f.router,
            Method::GET,
            "/api/v1/policies?action=plugin",
            None,
        )
        .await?;
    ensure!(invalid.0 == StatusCode::BAD_REQUEST, "{invalid:?}");
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
    let capabilities = s::decode(&response.bytes().await?, &CodecLimits::default())?;
    let gets: Vec<_> = capabilities
        .commands
        .iter()
        .filter_map(|c| {
            if let s::Command::Get { id, items, .. } = c {
                Some((*id, items[0].target.clone().unwrap()))
            } else {
                None
            }
        })
        .collect();
    let mut report = native::report(&peer.message, &gets, "10.0.22621.0", 200);
    for command in &mut report.commands {
        match command {
            s::Command::Status(status) => status.message_ref = capabilities.header.message_id,
            s::Command::Results(result) => {
                result.message_ref = Some(capabilities.header.message_id)
            }
            _ => {}
        }
    }
    for command in &mut report.commands {
        if let s::Command::Results(result) = command {
            for item in &mut result.items {
                if item.source.as_deref() == Some("./Vendor/MSFT/DeviceStatus/OS/Edition") {
                    item.data = Some(rss_mdm_windows_mdm::Secret("48".into()));
                }
            }
        }
    }
    report.final_message = false;
    let mut delivery_request = report.clone();
    let mut ready = native::post(&peer.mutual, &peer.url, &report).await?;
    ensure!(ready.status() == StatusCode::OK);
    // Applicability requires authenticated native capability facts before admission.
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
    // Complete capability evidence may precede the package Final by many messages.
    for message_id in 4..=request_message {
        let mut end = report.clone();
        end.header.message_id = message_id;
        end.commands = vec![s::Command::Status(s::Status {
            id: 1,
            message_ref: message_id - 1,
            command_ref: 0,
            command: s::CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        })];
        end.final_message = message_id == request_message;
        delivery_request = end.clone();
        ready = native::post(&peer.mutual, &peer.url, &end).await?;
        ensure!(
            ready.status() == StatusCode::OK,
            "late dispatch at {message_id}"
        );
    }
    ensure!(ready.status() == StatusCode::OK);
    let wire = s::decode(&ready.bytes().await?, &CodecLimits::default())?;
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
    if matches!(
        completion,
        Completion::Inventory
            | Completion::MissingChild
            | Completion::EmptyInventory
            | Completion::FinalInventoryBudget
            | Completion::FragmentInventory
            | Completion::RevokedInventory
    ) {
        dynamic_result(
            &host,
            &mut f,
            &peer,
            &mut pg,
            policy,
            wire,
            (completion, agent_source.unwrap()),
        )
        .await?;
        crate::test_support::stop_worker(owner.take()).await?;
        host.close().await?;
        return Ok(());
    }
    if request_message == CodecLimits::default().session_messages as u32 - 1
        && completion == Completion::Snapshot
    {
        let stored:i64=sqlx::query_scalar("SELECT w.request_message FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id=$1::uuid AND r.evidence ? 'nativeTemplate'").bind(case_tenant()).fetch_one(&mut pg).await?;
        ensure!(
            stored == i64::from(request_message),
            "last supported request was not persisted"
        );
        crate::test_support::stop_worker(owner.take()).await?;
        host.close().await?;
        return Ok(());
    }
    let remote = if completion == Completion::Historical {
        let run:Uuid=sqlx::query_scalar("SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND policy_version IN(SELECT id FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND policy=$2)").bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
        let parent = Uuid::new_v4();
        // Stop the precise Policy producer before restoring predecessor ownership.
        crate::test_support::stop_worker(owner.take()).await?;
        crate::test_support::agent_execution::historical_remote_run(
            &mut pg,
            case_tenant(),
            run,
            parent,
        )
        .await?;
        let replay = native::post(&peer.mutual, &peer.url, &delivery_request).await?;
        ensure!(
            !replay.status().is_success(),
            "retired Remote cached Get was redelivered"
        );
        Some((run, parent))
    } else {
        None
    };
    let mut packet = native::report(&peer.message, &gets, "template-workstation", 200);
    packet.header.message_id = wire.header.message_id + 1;
    packet.final_message = false;
    for command in &mut packet.commands {
        match command {
            s::Command::Status(status) => status.message_ref = wire.header.message_id,
            s::Command::Results(result) => result.message_ref = Some(wire.header.message_id),
            _ => {}
        }
    }
    if matches!(
        completion,
        Completion::SessionAbort | Completion::MessageBudget
    ) {
        // fetch_one proves an actual dispatched, unsealed template run in this session.
        let run: Uuid = sqlx::query_scalar("SELECT r.id FROM mdm_access.collection_runs r JOIN mdm_windows.collections w USING(tenant_id,id) JOIN mdm_commands.action_runs a USING(tenant_id,id) JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(a.tenant_id,a.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND w.registration=$3 AND w.session_id=$4 AND w.request_message=$5 AND r.sealed_at IS NULL AND r.evidence ? 'nativeTemplate'")
            .bind(case_tenant()).bind(policy).bind(peer.intent.registration)
            .bind(wire.header.session_id.to_string()).bind(i64::from(request_message))
            .fetch_one(&mut pg).await?;
        crate::test_support::stop_worker(owner.take()).await?;
        terminated_template_result(&peer, &mut pg, packet, run, completion).await?;
        pg.close().await?;
        host.close().await?;
        return Ok(());
    }
    if revoke_after_first.is_some() || completion == Completion::Expired {
        let run:Uuid=sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2").bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
        if completion == Completion::Expired {
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
                .bind(case_tenant())
                .execute(&mut pg)
                .await?;
            sqlx::query("UPDATE mdm_access.collection_runs SET deadline=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(run).execute(&mut pg).await?;
        }
        denied_template_result(&peer, &mut pg, packet, run, revoke_after_first).await?;
        crate::test_support::stop_worker(owner.take()).await?;
        host.close().await?;
        return Ok(());
    }
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
    let runs: Vec<Uuid> = if let Some((run, _)) = remote {
        vec![run]
    } else {
        sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2").bind(case_tenant()).bind(policy).fetch_all(&mut pg).await?
    };
    ensure!(runs.len() == 1, "native Policy runs: {runs:?}");
    let pending:bool=sqlx::query_scalar("SELECT sealed_at IS NULL FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    ensure!(pending, "non-Final template results sealed early");
    crate::test_support::stop_worker(owner.take()).await?;
    let browser = f.browser.clone();
    drop(f);
    host = host.restart().await?;
    f = Client::with_browser(host.browser.clone(), host.app.clone(), browser);
    let mut end = packet.clone();
    end.header.message_id += 1;
    end.commands = vec![s::Command::Status(s::Status {
        id: 1,
        message_ref: packet.header.message_id,
        command_ref: 0,
        command: s::CommandName::SyncHdr,
        target_refs: vec![],
        source_refs: vec![],
        code: 200,
        items: vec![],
        challenge: None,
        credential: None,
    })];
    end.final_message = true;
    ensure!(native::post(&peer.mutual, &peer.url, &end).await?.status() == StatusCode::OK);
    let result = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/devices/{}/collections/{}", case_device(), runs[0]),
            None,
        )
        .await?;
    ensure!(
        result.0 == StatusCode::OK && result.1["asset"]["run"]["result"] == "snapshot",
        "native progress: {result:?}"
    );
    let progress: String = sqlx::query_scalar(
        "SELECT attempts FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(runs[0])
    .fetch_one(&mut pg)
    .await?;
    let progress: serde_json::Value = serde_json::from_str(&progress)?;
    ensure!(
        progress["fields"]["device.model"]["value"]
            == json!({"kind":"value","value":{"kind":"string","value":"canonical-workstation"}}),
        "enum mapping did not reach durable collection: {progress}"
    );
    // Restore the durable pre-settlement state while retaining the already sealed response.
    // Recovery happens after its original execution timeout, as after worker downtime.
    sqlx::query("UPDATE mdm_commands.action_runs SET state=jsonb_set(jsonb_set(state,'{execution}','\"running\"'),'{startedAt}',to_jsonb($3::bigint)) WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).bind(now-120).execute(&mut pg).await?;
    if let Some((_, parent)) = remote {
        host.app.execution.recover_remote_fixture(parent).await?;
    } else {
        host.app.execution.recover_action_fixture(policy).await?;
    }
    let state:String=sqlx::query_scalar("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    ensure!(
        state == "succeeded",
        "sealed success was lost after downtime: {state}"
    );
    if remote.is_some() {
        let attempts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(case_tenant())
        .bind(runs[0])
        .fetch_one(&mut pg)
        .await?;
        ensure!(attempts == 1);
        pg.close().await?;
        host.close().await?;
        return Ok(());
    }
    // Shift the completed occurrence to the previous interval; the current one is due.
    sqlx::query("UPDATE mdm_commands.action_runs SET occurrence='timer:'||($3::bigint)::text||':'||registration::text,created_at=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).bind(now-3600).execute(&mut pg).await?;
    host.app.execution.recover_action_fixture(policy).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2")
        .bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
    ensure!(count == 2, "completed run blocked the next occurrence");
    // History is retained, but it cannot occupy the entire check-in recovery page.
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,source_objects) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'blocked-history:'||n,created_at-1000,available_at,deadline,jsonb_set(jsonb_set(state,'{execution}',to_jsonb(CASE WHEN n<=65 THEN 'unknown' ELSE 'not_started' END::text)),'{cancellation}',to_jsonb(CASE WHEN n<=65 THEN 'none' ELSE 'confirmed' END::text)),gateway_accepted,dispatch_fingerprint,source_objects FROM mdm_commands.action_runs CROSS JOIN generate_series(1,130) n WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).execute(&mut pg).await?;
    let next:Uuid=sqlx::query_scalar("UPDATE mdm_commands.action_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id<>$2 AND occurrence NOT LIKE 'blocked-history:%' RETURNING id")
        .bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    host.app
        .execution
        .settle_native_fixture(case_device())
        .await?;
    let initialized:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2)")
        .bind(case_tenant()).bind(next).fetch_one(&mut pg).await?;
    ensure!(
        initialized,
        "historical Unknown/cancelled runs starved native check-in recovery"
    );
    let unknown:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND occurrence LIKE 'blocked-history:%' AND state->>'execution'='unknown'")
        .bind(case_tenant()).fetch_one(&mut pg).await?;
    ensure!(unknown == 65, "unknown history was retried or rewritten");
    // Preserve historical terminal evidence when retiring the same real registration.
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,source_objects) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'confirmed-history',created_at,available_at,deadline,jsonb_set(jsonb_set(state,'{execution}','\"unknown\"'),'{cancellation}','\"confirmed\"'),gateway_accepted,dispatch_fingerprint,source_objects FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(runs[0]).execute(&mut pg).await?;
    let history: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_array(id,state) ORDER BY id) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND (state->>'execution' IN('succeeded','failed') OR state->>'cancellation'='confirmed')").bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    let mut notification = peer.message.clone();
    notification.header.session_id = 3000;
    notification.header.message_id = 1;
    notification.header.credential = None;
    notification.commands = vec![s::Command::Alert {
        id: 2,
        alert: s::Alert::UnenrollmentRequested,
    }];
    ensure!(
        native::post(&peer.mutual, &peer.url, &notification)
            .await?
            .status()
            == StatusCode::OK
    );
    let preserved: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_array(id,state) ORDER BY id) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND id IN(SELECT (value->>0)::uuid FROM jsonb_array_elements($3::jsonb))").bind(case_tenant()).bind(peer.intent.registration).bind(&history).fetch_one(&mut pg).await?;
    ensure!(
        preserved == history,
        "registration retirement rewrote historical terminal evidence"
    );
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND state->>'execution' IN('not_started','running','waiting_reboot','unknown') AND state->>'cancellation'='none'").bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    ensure!(live == 0, "retirement paging missed pending actions");
    pg.close().await?;
    host.close().await
}

async fn denied_template_result(
    peer: &crate::windows::test_support::Peer,
    pg: &mut sqlx::PgConnection,
    mut packet: s::Message,
    run: Uuid,
    after_first: Option<bool>,
) -> anyhow::Result<()> {
    for command in &mut packet.commands {
        if let s::Command::Results(result) = command {
            result.items[0].data = Some(rss_mdm_windows_mdm::Secret("template".into()));
            result.items[0].more_data = true;
            result.items[0].meta = Some(s::Meta {
                format: Some("chr".into()),
                size: Some("template-workstation".len() as u32),
                ..Default::default()
            });
        }
    }
    let revoke = || {
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            vec![],
        )
    };
    if after_first == Some(false) {
        revoke().await?;
    }
    let mut response = native::post(&peer.mutual, &peer.url, &packet).await?;
    ensure!(response.status() == StatusCode::OK);
    if after_first == Some(true) {
        let ack = s::decode(&response.bytes().await?, &CodecLimits::default())?;
        ensure!(
            ack.commands
                .iter()
                .any(|c| matches!(c,s::Command::Status(status) if status.code==213))
        );
        revoke().await?;
        packet.header.message_id += 1;
        for command in &mut packet.commands {
            if let s::Command::Results(result) = command {
                result.items[0].data = Some(rss_mdm_windows_mdm::Secret("-workstation".into()));
                result.items[0].more_data = false;
                result.items[0].meta = None;
            }
        }
        packet.final_message = true;
        response = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(response.status() == StatusCode::OK);
    }
    let aborted = s::decode(&response.bytes().await?, &CodecLimits::default())?;
    ensure!(aborted.commands.iter().any(|c| matches!(
        c,
        s::Command::Alert {
            alert: s::Alert::SessionAbort,
            ..
        }
    )));
    ensure!(!aborted.commands.iter().any(
        |c| matches!(c,s::Command::Status(status) if status.code==213)
            || matches!(c, s::Command::Get { .. })
    ));
    let failed:bool=sqlx::query_scalar("SELECT result='failed' AND reason='aborted' AND batch IS NULL AND NOT delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut *pg).await?;
    ensure!(failed, "revoked template published a result");
    Ok(())
}

async fn terminated_template_result(
    peer: &crate::windows::test_support::Peer,
    pg: &mut sqlx::PgConnection,
    mut packet: s::Message,
    run: Uuid,
    completion: Completion,
) -> anyhow::Result<()> {
    ensure!(
        packet
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Results(_)))
    );
    let reason = if completion == Completion::SessionAbort {
        packet.final_message = true;
        packet.commands.push(s::Command::Alert {
            id: packet.commands.iter().map(s::Command::id).max().unwrap() + 1,
            alert: s::Alert::SessionAbort,
        });
        "aborted"
    } else {
        ensure!(packet.header.message_id as usize == CodecLimits::default().session_messages);
        ensure!(!packet.final_message);
        "message_budget"
    };
    let response = native::post(&peer.mutual, &peer.url, &packet).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "termination response {}",
        response.status()
    );
    let response = s::decode(&response.bytes().await?, &CodecLimits::default())?;
    ensure!(!response.final_message);
    let terminal: (bool, String, String, bool, bool) = sqlx::query_as("SELECT sealed_at IS NOT NULL,result,reason,batch IS NULL,delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(run).fetch_one(pg).await?;
    ensure!(
        terminal == (true, "failed".into(), reason.into(), true, false),
        "termination published collection evidence for {run}: {terminal:?}"
    );
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and durable projection assertions shared by dynamic T2 scenarios"
)]
async fn dynamic_result(
    host: &Host,
    f: &mut Client,
    peer: &crate::windows::test_support::Peer,
    pg: &mut sqlx::PgConnection,
    policy: Uuid,
    mut wire: s::Message,
    scenario: (Completion, (Uuid, Uuid)),
) -> anyhow::Result<()> {
    use anyhow::Context;
    let (completion, (agent, epoch)) = scenario;
    let run:Uuid=sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2").bind(case_tenant()).bind(policy).fetch_one(&mut *pg).await.context("dynamic action run")?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut *pg)
        .await?;
    let saved = crate::collection::store::load_on(pg, case_tenant(), run)
        .await
        .context("dynamic collection run")?;
    let key = rss_mdm_inventory::FieldKey::parse("device.software.windows.win32")?;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/windows-collection/software.win32.json"
    ))?;
    let old = saved
        .attempts
        .definition()
        .field(key)?
        .value_type
        .decode_json(&fixture[key.as_str()])?;
    seed_prior_list(pg, &saved.scope, saved.attempts.definition(), key, &old).await?;
    let agent_scope = crate::device::scope(saved.scope.tenant(), agent, "agent.builtin", epoch)?;
    let agent_key = rss_mdm_inventory::FieldKey::parse("device.software.installations")?;
    let field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key == agent_key)
        .unwrap();
    let agent_value=field.value_type.decode_json(&json!([{"id":"agent-app","name":"Agent application","version":"9","publisher":"Vendor","scope":"device","native_id":"agent-app","owner":"","origin":"agent","location":"","installation_state":"installed"}]))?;
    let definition = rss_mdm_inventory::CollectionDefinition::new(
        rss_mdm_inventory::CollectionScope::Device,
        "inventory",
        "prior-software",
        rss_mdm_inventory::Source::AgentBuiltin,
        vec![field],
    )?;
    rss_mdm_inventory_postgres::register_collection_in(pg, saved.scope.tenant(), &definition)
        .await?;
    seed_prior_list(pg, &agent_scope, &definition, agent_key, &agent_value).await?;
    let mut enumerations = 0;
    for _ in 0..6 {
        let gets: Vec<_> = wire
            .commands
            .iter()
            .filter_map(|c| match c {
                s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
                _ => None,
            })
            .collect();
        if gets.is_empty() {
            break;
        }
        let fragment = completion == Completion::FragmentInventory
            && gets.iter().any(|(_, uri)| uri.ends_with("/Name"));
        let mut packet = native::report(&peer.message, &gets, "", 200);
        packet.header.message_id = wire.header.message_id + 1;
        packet.final_message = true;
        for c in &mut packet.commands {
            match c {
                s::Command::Status(v) => {
                    v.message_ref = wire.header.message_id;
                    if completion == Completion::MissingChild
                        && gets
                            .iter()
                            .any(|(id, uri)| *id == v.command_ref && uri.ends_with("/Version"))
                    {
                        v.code = 404;
                    }
                }
                s::Command::Results(v) => {
                    v.message_ref = Some(wire.header.message_id);
                    for item in &mut v.items {
                        let uri = item.source.as_deref().unwrap();
                        let value = if uri.ends_with("/Win32InstalledProgram") {
                            enumerations += 1;
                            if completion == Completion::EmptyInventory {
                                ""
                            } else {
                                "program"
                            }
                        } else if uri.ends_with("/Name") {
                            "Example"
                        } else if uri.ends_with("/Publisher") {
                            "Vendor"
                        } else if uri.ends_with("/Version") {
                            "1.2"
                        } else if uri.ends_with("/Source") {
                            "Registry"
                        } else if uri.ends_with("/RegKey") {
                            "HKLM\\Software\\Example"
                        } else {
                            "template-workstation"
                        };
                        item.data = Some(rss_mdm_windows_mdm::Secret(value.into()));
                    }
                }
                _ => (),
            }
        }
        packet.commands.retain(|c|!matches!(c,s::Command::Results(v) if completion==Completion::MissingChild && v.items.iter().any(|i|i.source.as_deref().is_some_and(|u|u.ends_with("/Version")))));
        let mut tail = None;
        if fragment {
            packet.final_message = false;
            for c in &mut packet.commands {
                if let s::Command::Results(v) = c
                    && v.items[0]
                        .source
                        .as_deref()
                        .is_some_and(|u| u.ends_with("/Name"))
                {
                    let mut result = v.clone();
                    result.items[0].data = Some(rss_mdm_windows_mdm::Secret("ple".into()));
                    tail = Some(s::Command::Results(result));
                    v.items[0].data = Some(rss_mdm_windows_mdm::Secret("Exam".into()));
                    v.items[0].more_data = true;
                    v.items[0].meta = Some(s::Meta {
                        format: Some("chr".into()),
                        size: Some(7),
                        ..Default::default()
                    });
                }
            }
        }
        // MoreData starts the sole open object; later unrelated results would interrupt it.
        packet.commands.sort_by_key(
            |c| matches!(c, s::Command::Results(v) if v.items.iter().any(|i| i.more_data)),
        );
        let response = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "dynamic response: {}",
            response.status()
        );
        let bytes = response.bytes().await?;
        let next = s::decode(&bytes, &CodecLimits::default())?;
        let leaf_gets: Vec<_> = next
            .commands
            .iter()
            .filter_map(|c| match c {
                s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
                _ => None,
            })
            .collect();
        if completion == Completion::RevokedInventory
            && leaf_gets.iter().any(|(_, u)| u.ends_with("/Name"))
        {
            crate::test_support::identity::set_grants(
                case_tenant(),
                crate::test_support::case::admin(),
                vec![],
            )
            .await?;
            let replay = native::post(&peer.mutual, &peer.url, &packet).await?;
            ensure!(
                !replay.status().is_success(),
                "revoked dynamic cached leaf was redelivered"
            );
            let mut denied = native::report(&peer.message, &leaf_gets, "Exam", 200);
            denied.header.message_id = next.header.message_id + 1;
            denied.final_message = false;
            for c in &mut denied.commands {
                match c {
                    s::Command::Status(v) => v.message_ref = next.header.message_id,
                    s::Command::Results(v) => {
                        v.message_ref = Some(next.header.message_id);
                        if v.items[0]
                            .source
                            .as_deref()
                            .is_some_and(|u| u.ends_with("/Name"))
                        {
                            v.items[0].more_data = true;
                            v.items[0].meta = Some(s::Meta {
                                format: Some("chr".into()),
                                size: Some(7),
                                ..Default::default()
                            });
                        }
                    }
                    _ => (),
                }
            }
            denied.commands.sort_by_key(
                |c| matches!(c, s::Command::Results(v) if v.items.iter().any(|i| i.more_data)),
            );
            let response = native::post(&peer.mutual, &peer.url, &denied).await?;
            ensure!(response.status() == StatusCode::OK);
            let response = s::decode(&response.bytes().await?, &CodecLimits::default())?;
            ensure!(response.commands.iter().any(|c| matches!(
                c,
                s::Command::Alert {
                    alert: s::Alert::SessionAbort,
                    ..
                }
            )));
            let failed:bool=sqlx::query_scalar("SELECT result='failed' AND batch IS NULL FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut *pg).await.context("dynamic sealed result")?;
            ensure!(failed);
            return Ok(());
        }
        let replay = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(replay.status() == StatusCode::OK);
        ensure!(replay.bytes().await? == bytes);
        wire = next;
        if let Some(tail) = tail {
            ensure!(
                wire.commands
                    .iter()
                    .any(|c| matches!(c,s::Command::Status(v) if v.code==213))
            );
            packet.header.message_id += 1;
            packet.commands = vec![
                s::Command::Status(s::Status {
                    id: 1,
                    message_ref: wire.header.message_id,
                    command_ref: 0,
                    command: s::CommandName::SyncHdr,
                    target_refs: vec![],
                    source_refs: vec![],
                    code: 200,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }),
                tail,
            ];
            packet.final_message = true;
            let response = native::post(&peer.mutual, &peer.url, &packet).await?;
            ensure!(response.status() == StatusCode::OK);
            wire = s::decode(&response.bytes().await?, &CodecLimits::default())?;
        }
    }
    let result:(String,String)=sqlx::query_as("SELECT result,attempts FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NOT NULL").bind(case_tenant()).bind(run).fetch_one(&mut *pg).await.context("dynamic sealed result")?;
    let attempts: serde_json::Value = serde_json::from_str(&result.1)?;
    if matches!(
        completion,
        Completion::MissingChild | Completion::FinalInventoryBudget
    ) {
        ensure!(result.0 == "partial", "{result:?}");
        ensure!(
            attempts["fields"]["device.software.windows.win32"]["value"].is_null(),
            "{attempts}"
        );
    } else {
        ensure!(
            result.0 == "snapshot" && enumerations == 2,
            "{result:?}, enumerations={enumerations}"
        );
        if matches!(
            completion,
            Completion::Inventory | Completion::FragmentInventory
        ) {
            let row = &attempts["fields"]["device.software.windows.win32"]["value"]["value"]["value"]
                [0]["value"];
            ensure!(
                row["name"]["value"] == "Example" && row["version"]["value"] == "1.2",
                "{attempts}"
            );
        } else {
            ensure!(
                attempts["fields"]["device.software.windows.win32"]["value"]["value"]["value"]
                    == json!([]),
                "{attempts}"
            );
        }
        tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                let pending:bool=sqlx::query_scalar("SELECT delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut *pg).await?;
                if !pending {break;}
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_,anyhow::Error>(())
        }).await??;
        let page=tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                let page=f.browser.call(&f.router,Method::GET,&format!("/api/v1/devices/{}/inventory-lists/device.software.windows.win32?limit=100",case_device()),None).await?;
                if page.0==StatusCode::OK && page.1["asset"]["total"]==if completion==Completion::EmptyInventory {0} else {1} {break Ok::<_,anyhow::Error>(page);}
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await??;
        if matches!(
            completion,
            Completion::Inventory | Completion::FragmentInventory
        ) {
            ensure!(page.1.to_string().contains("Example"), "{page:?}");
        }
    }
    let sealed = crate::collection::store::load_on(pg, case_tenant(), run).await?;
    crate::inventory_runtime::test_support::wait_ready_projection(&host.runtime, &sealed).await?;
    let value:serde_json::Value=sqlx::query_scalar("SELECT value::jsonb FROM mdm.inventory WHERE tenant_id=$1::uuid AND scope=$2 AND field=$3 ORDER BY collection_sequence DESC LIMIT 1").bind(case_tenant()).bind(saved.scope.encode()?).bind(key.as_str()).fetch_one(&mut *pg).await?;
    if matches!(
        completion,
        Completion::MissingChild | Completion::FinalInventoryBudget
    ) {
        ensure!(value == serde_json::to_value(&old)?);
    }
    if completion == Completion::EmptyInventory {
        ensure!(value == json!({"kind":"array","value":[]}));
    }
    let retained: serde_json::Value = sqlx::query_scalar(
        "SELECT value::jsonb FROM mdm.inventory WHERE tenant_id=$1::uuid AND scope=$2 AND field=$3",
    )
    .bind(case_tenant())
    .bind(agent_scope.encode()?)
    .bind(agent_key.as_str())
    .fetch_one(&mut *pg)
    .await?;
    ensure!(
        retained == serde_json::to_value(&agent_value)?,
        "native collection modified Agent software"
    );
    Ok(())
}

async fn seed_prior_list(
    pg: &mut sqlx::PgConnection,
    scope: &rss_observation::Scope,
    definition: &rss_mdm_inventory::CollectionDefinition,
    key: rss_mdm_inventory::FieldKey,
    value: &rss_mdm_inventory::Scalar,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES($1::uuid,'mdm.observation.v1','inventory-v6',$2,$3,$4,$5,'prior-list',1,2,'known',$5,'prior-list',1,2,$6::uuid,$7,$8::uuid,0)")
        .bind(scope.tenant().to_string()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(key.as_str()).bind(serde_json::to_string(value)?).bind(scope.registration().as_str()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).execute(pg).await?;
    Ok(())
}
