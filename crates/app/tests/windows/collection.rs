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
use sqlx::Connection;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[tokio::test]
#[ignore = "MODULE=windows.management: native template over real SyncML mTLS"]
async fn native_template_policy_uses_correlated_get_and_collection_run() -> anyhow::Result<()> {
    template_flow(Completion::Snapshot).await
}

#[tokio::test]
#[ignore = "MODULE=windows.management: client abort of a real template run"]
async fn template_client_abort_cannot_publish_a_snapshot() -> anyhow::Result<()> {
    template_flow(Completion::SessionAbort).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: dynamic inventory through SyncML and projection"]
async fn dynamic_inventory_reenumerates_and_projects() -> anyhow::Result<()> {
    template_flow(Completion::Inventory).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: a missing dynamic child cannot publish an empty list"]
async fn dynamic_inventory_missing_child_is_partial() -> anyhow::Result<()> {
    template_flow(Completion::MissingChild).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: confirmed empty replaces only native inventory"]
async fn dynamic_empty_preserves_agent_software() -> anyhow::Result<()> {
    template_flow(Completion::EmptyInventory).await
}

#[tokio::test]
#[ignore = "MODULE=windows.management: expired template cannot continue a large object"]
async fn expired_template_rejects_more_data() -> anyhow::Result<()> {
    template_flow(Completion::Expired).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: 214 template receipt stops all producers without publishing partial evidence"]
async fn template_214_closes_session_preserving_unsealed_run() -> anyhow::Result<()> {
    template_flow(Completion::Stopped).await
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Stopped,
    Expired,
    Snapshot,
    Inventory,
    MissingChild,
    EmptyInventory,
    SessionAbort,
}
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and durable recovery assertions shared by T2 scenarios"
)]
async fn template_flow(completion: Completion) -> anyhow::Result<()> {
    let request_message = 4;
    let mut host = Host::open().await?;
    host.listen().await?;
    let mut peer = host.peer().await?;
    // Native Windows sends both the client-initiated session and LoginStatus alerts.
    peer.message.commands.insert(
        1,
        s::Command::Alert {
            id: 4,
            alert: s::Alert::LoginStatus {
                status: s::LoginStatus::Others,
                explicit_format: false,
            },
        },
    );
    let agent_source = if matches!(
        completion,
        Completion::Inventory | Completion::MissingChild | Completion::EmptyInventory
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
    let mut f = Client::start(
        host.browser.clone(),
        &host.commands,
        &host.authority.identity,
        host.authority.audit.clone(),
        host.clock.clone(),
    )
    .await?;
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
    crate::test_support::identity::seed_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    let automation = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect_planning(
            host.planning.clone(),
            crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
        )
        .await?,
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.work.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(
        Arc::new(rss_mdm_inventory_service::assets::runtime::QueryWork::new(
            host.assets.clone(),
            automation.work.scheduler(),
        ))
        .registration(
            host.notifications
                .signals
                .handle(crate::worker_wake::Work::AssetQueries),
        )
        .critical(),
    );
    launch.stage_deferred_task_with_token(
        Arc::new(
            rss_mdm_inventory_service::compliance::runtime::ComplianceWork::new(
                host.compliance.clone(),
                automation.work.scheduler(),
            ),
        )
        .registration(
            host.notifications
                .signals
                .handle(crate::worker_wake::Work::Compliance),
        )
        .critical(),
    );

    launch.stage_deferred_task_with_token(
        automation
            .registration(host.notifications.signals.flow())
            .critical(),
    );
    launch.stage_deferred_task_with_token(
        host.commands
            .service
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
                mapping: rss_mdm_agent_wire::runtime::ValueMapping {
                    pointer: "".into(),
                    conversion: rss_mdm_agent_wire::runtime::Conversion::Enum {
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
        Completion::Inventory | Completion::MissingChild | Completion::EmptyInventory
    ) {
        let mut spec = template.spec().clone();
        let builtin = rss_mdm_resource::blueprints::get("windows.software.win32", "1").unwrap();
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
    let scope = Uuid::new_v4();
    if completion == Completion::Snapshot {
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
        post(&mut f.browser,&f.router,&format!("/api/v1/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}}})).await?;
    } else {
        crate::test_support::planning_http::seed_native_template(
            &host.planning.runtime,
            host.planning.tenant,
            id,
            rss_mdm_resource::Platform::Windows,
            template,
        )
        .await?;
        let artifact = rss_mdm_resource::Artifact::new(
            rss_mdm_resource::Id::new("native-template")?,
            bytes.len() as u64,
            rss_mdm_resource::Digest::of(&bytes),
        )?;
        rss_mdm_content_service::fixture::artifact(
            host.commands
                .content
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("native content"))?,
            &artifact,
            bytes.clone(),
            crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400,
        )
        .await?;
        crate::test_support::agent_execution::seed_scope(
            &host.planning,
            scope,
            json!([{"kind":"device","id":case_device()}]),
        )
        .await?;
    }
    let policy = Uuid::new_v4();
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let period = if completion == Completion::Snapshot {
        60
    } else {
        3600
    };
    post(&mut f.browser,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","frequency":"every_trigger","schedule":{"trigger":{"kind":"interval","anchor":now,"seconds":period},"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"coalesce_one"}},"resource":{"id":id,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
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
    let mut ready = native::post(&peer.mutual, &peer.url, &report).await?;
    ensure!(ready.status() == StatusCode::OK);
    // Applicability requires authenticated native capability facts before admission.
    // Both outbox acceptance and the worker-created CollectionRun precede protocol delivery.
    use sqlx::Connection;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut pg)
        .await?;
    let pending = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let ready: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_access.collection_runs c ON(c.tenant_id,c.id)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.gateway_accepted AND c.sealed_at IS NULL)")
                .bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
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
        Completion::Inventory | Completion::MissingChild | Completion::EmptyInventory
    ) {
        // The request must settle its own result without assistance from recovery.
        crate::test_support::runtime::stop_worker(owner.take()).await?;
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
        crate::test_support::runtime::stop_worker(owner.take()).await?;
        host.close().await?;
        return Ok(());
    }
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
    if completion == Completion::Stopped {
        for command in &mut packet.commands {
            if let s::Command::Status(status) = command
                && status.command_ref != 0
            {
                status.code = 214;
            }
        }
        // Leave this field unanswered so the same frozen run must resume next session.
        packet
            .commands
            .retain(|c| !matches!(c, s::Command::Results(_)));
        let response = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(response.status() == StatusCode::OK);
        let bytes = response.bytes().await?;
        let reply = s::decode(&bytes, &CodecLimits::default())?;
        ensure!(
            reply.final_message
                && reply
                    .commands
                    .iter()
                    .all(|c| matches!(c, s::Command::Status(_)))
        );
        ensure!(
            native::post(&peer.mutual, &peer.url, &packet)
                .await?
                .bytes()
                .await?
                == bytes
        );
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs r JOIN mdm_windows.collections w USING(tenant_id,id) WHERE r.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3 AND w.kind='template' AND r.sealed_at IS NULL)")
            .bind(case_tenant()).bind(peer.intent.registration).bind(packet.header.session_id.to_string()).fetch_one(&mut pg).await?;
        ensure!(pending, "214 falsely completed a non-Final collection");
        crate::test_support::runtime::stop_worker(owner.take()).await?;
        let run: Uuid = sqlx::query_scalar("SELECT r.id FROM mdm_access.collection_runs r JOIN mdm_windows.collections w USING(tenant_id,id) WHERE r.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3 AND w.kind='template' AND r.sealed_at IS NULL")
            .bind(case_tenant()).bind(peer.intent.registration).bind(packet.header.session_id.to_string()).fetch_one(&mut pg).await?;
        let resumed = native::begin(
            &peer.mutual,
            &peer.url,
            &peer.message,
            &peer.ack,
            3032,
            None,
        )
        .await?;
        let capabilities = native::report(&resumed.first, &resumed.gets, "10.0.26100.0", 200);
        let response = native::post(&peer.mutual, &peer.url, &capabilities).await?;
        ensure!(response.status() == StatusCode::OK);
        let next = s::decode(&response.bytes().await?, &CodecLimits::default())?;
        let gets: Vec<_> = next
            .commands
            .iter()
            .filter_map(|c| match c {
                s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
                _ => None,
            })
            .collect();
        ensure!(gets.iter().any(|(_, uri)| uri == "./DevDetail/DevTyp"));
        let bindings: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(case_tenant())
        .bind(run)
        .fetch_one(&mut pg)
        .await?;
        ensure!(
            bindings == 2,
            "recovery replaced the original session binding"
        );
        let prior: Vec<u8> = sqlx::query_scalar("SELECT template_state FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2 AND session_id='3032'")
            .bind(case_tenant()).bind(run).fetch_one(&mut pg).await?;
        ensure!(
            native::post(&peer.mutual, &peer.url, &packet)
                .await?
                .bytes()
                .await?
                == bytes
        );
        let after: Vec<u8> = sqlx::query_scalar("SELECT template_state FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2 AND session_id='3032'")
            .bind(case_tenant()).bind(run).fetch_one(&mut pg).await?;
        ensure!(prior == after, "old replay mutated resumed state");
        let mut done = native::report(&resumed.first, &gets, "template-workstation", 200);
        done.header.message_id = next.header.message_id + 1;
        for c in &mut done.commands {
            match c {
                s::Command::Status(v) => v.message_ref = next.header.message_id,
                s::Command::Results(v) => v.message_ref = Some(next.header.message_id),
                _ => (),
            }
        }
        ensure!(native::post(&peer.mutual, &peer.url, &done).await?.status() == StatusCode::OK);
        let sealed: bool = sqlx::query_scalar("SELECT sealed_at IS NOT NULL FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(run).fetch_one(&mut pg).await?;
        ensure!(sealed, "resumed run failed to complete");
        pg.close().await?;
        return host.close().await;
    }
    if matches!(completion, Completion::SessionAbort) {
        // fetch_one proves an actual dispatched, unsealed template run in this session.
        let run: Uuid = sqlx::query_scalar("SELECT r.id FROM mdm_access.collection_runs r JOIN mdm_windows.collections w USING(tenant_id,id) JOIN mdm_commands.action_runs a USING(tenant_id,id) JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(a.tenant_id,a.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND w.registration=$3 AND w.session_id=$4 AND w.request_message=$5 AND r.sealed_at IS NULL AND r.evidence ? 'nativeTemplate'")
            .bind(case_tenant()).bind(policy).bind(peer.intent.registration)
            .bind(wire.header.session_id.to_string()).bind(i64::from(request_message))
            .fetch_one(&mut pg).await?;
        crate::test_support::runtime::stop_worker(owner.take()).await?;
        terminated_template_result(&peer, &mut pg, packet, run).await?;
        pg.close().await?;
        host.close().await?;
        return Ok(());
    }
    if completion == Completion::Expired {
        let run:Uuid=sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2").bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
        if completion == Completion::Expired {
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
                .bind(case_tenant())
                .execute(&mut pg)
                .await?;
            let changed = sqlx::query("UPDATE mdm_access.collection_runs SET deadline=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(run).execute(&mut pg).await?;
            ensure!(changed.rows_affected() == 1);
        }
        denied_template_result(&peer, &mut pg, packet, run).await?;
        crate::test_support::runtime::stop_worker(owner.take()).await?;
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
    let runs: Vec<Uuid> = sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2").bind(case_tenant()).bind(policy).fetch_all(&mut pg).await?;
    ensure!(runs.len() == 1, "native Policy runs: {runs:?}");
    let pending:bool=sqlx::query_scalar("SELECT sealed_at IS NULL FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    ensure!(pending, "non-Final template results sealed early");
    crate::test_support::runtime::stop_worker(owner.take()).await?;
    let browser = f.browser.clone();
    drop(f);
    host = host.restart().await?;
    f = Client::with_browser(
        host.browser.clone(),
        &host.commands,
        &host.authority.identity,
        host.authority.audit.clone(),
        host.clock.clone(),
        browser,
    );
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
    // Reconcile the committed success again after restart. Rewinding only the run
    // while retaining its terminal webhook creates an impossible partial commit.
    host.commands
        .service
        .recover_native_run_fixture(runs[0])
        .await?;
    let state:String=sqlx::query_scalar("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    ensure!(
        state == "succeeded",
        "committed success was lost during repeated recovery: {state}"
    );
    // Resume the background driver after the explicit recovery assertion, before
    // checking recurrence of the same policy.
    let mut resumed = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = resumed.startup()?.commit();
    launch.stage_deferred_task_with_token(
        host.commands
            .service
            .clone()
            .registration(host.notifications.signals.execution())
            .critical(),
    );
    launch.finish();
    owner = Some(resumed);
    // Wait for the second real period of the SAME immutable Policy version.
    // No rerun, version edit, synthetic occurrence or precreated next run is involved.
    tokio::time::timeout(std::time::Duration::from_secs(95), async {
        loop {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2")
                .bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
            if count == 2 { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.map_err(|_| anyhow::anyhow!("completed run blocked the next occurrence"))??;
    // History is retained, but it cannot occupy the entire check-in recovery page.
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,source_objects,origin) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'blocked-history:'||n,created_at-1000,available_at,deadline,jsonb_set(jsonb_set(state,'{execution}',to_jsonb(CASE WHEN n<=65 THEN 'unknown' ELSE 'not_started' END::text)),'{cancellation}',to_jsonb(CASE WHEN n<=65 THEN 'none' ELSE 'confirmed' END::text)),gateway_accepted,dispatch_fingerprint,source_objects,origin FROM mdm_commands.action_runs CROSS JOIN generate_series(1,130) n WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).execute(&mut pg).await?;
    let next:Uuid=sqlx::query_scalar("SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id<>$2 AND occurrence NOT LIKE 'blocked-history:%'")
        .bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let initialized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2)")
                .bind(case_tenant()).bind(next).fetch_one(&mut pg).await?;
            if initialized { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.map_err(|_| anyhow::anyhow!("historical Unknown/cancelled runs starved native recovery"))??;
    let unknown:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND occurrence LIKE 'blocked-history:%' AND state->>'execution'='unknown'")
        .bind(case_tenant()).fetch_one(&mut pg).await?;
    ensure!(unknown == 65, "unknown history was retried or rewritten");
    native_unknown_barrier(&host, &mut pg, policy, runs[0]).await?;
    // Preserve historical terminal evidence when retiring the same real registration.
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,source_objects,origin) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'confirmed-history',created_at,available_at,deadline,jsonb_set(jsonb_set(state,'{execution}','\"unknown\"'),'{cancellation}','\"confirmed\"'),gateway_accepted,dispatch_fingerprint,source_objects,origin FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(runs[0]).execute(&mut pg).await?;
    let history: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_array(id,state) ORDER BY id) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND (state->>'execution' IN('succeeded','failed') OR state->>'cancellation'='confirmed')").bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    let mut notification = peer.message.clone();
    notification.header.session_id = 3000;
    notification.header.message_id = 1;
    notification.header.credential = None;
    notification.commands = vec![s::Command::Alert {
        id: 2,
        alert: s::Alert::UnenrollmentRequested,
    }];
    crate::test_support::runtime::stop_worker(owner.take()).await?;
    authenticate_during_recovery(&host, &peer, &mut pg, next).await?;
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

async fn native_unknown_barrier(
    host: &Host,
    pg: &mut sqlx::PgConnection,
    policy: Uuid,
    original: Uuid,
) -> anyhow::Result<()> {
    let (version, device, generation, deadline): (Uuid, String, i64, i64) = sqlx::query_as(
        "SELECT policy_version,device,generation,deadline FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
    ).bind(case_tenant()).bind(original).fetch_one(&mut *pg).await?;
    // A replacement registration still sees Unknown history, but does not see
    // the current registration's ordinary pending run.
    let target = rss_mdm_execution_service::Target {
        device,
        registration: Uuid::new_v4(),
        generation,
    };
    ensure!(pending_at(host, policy, version, target.clone(), deadline - 1).await?);
    ensure!(!pending_at(host, policy, version, target.clone(), deadline + 1).await?);
    sqlx::query("UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{cancellation}','\"confirmed\"') WHERE tenant_id=$1::uuid AND occurrence LIKE 'blocked-history:%' AND state->>'execution'='unknown'")
        .bind(case_tenant()).execute(&mut *pg).await?;
    ensure!(!pending_at(host, policy, version, target, deadline - 1).await?);
    // Restore the fault fixture so the original retirement paging assertions
    // continue to cover all 65 unconfirmed Unknown runs.
    sqlx::query("UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{cancellation}','\"none\"') WHERE tenant_id=$1::uuid AND occurrence LIKE 'blocked-history:%' AND state->>'execution'='unknown'")
        .bind(case_tenant()).execute(&mut *pg).await?;
    Ok(())
}
async fn pending_at(
    host: &Host,
    policy: Uuid,
    version: Uuid,
    target: rss_mdm_execution_service::Target,
    now: i64,
) -> anyhow::Result<bool> {
    host.commands
        .runtime
        .local_tx(
            rss_request_context::TenantId::parse(case_tenant())?,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(15),
            ),
            move |tx| {
                Box::pin(async move {
                    rss_mdm_execution_service::actions::production::policy_pending_in(
                        tx, policy, version, &target, now, false,
                    )
                    .await
                    .map(|value| value.0)
                    .map_err(|e| {
                        rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(
                            e.to_string(),
                        ))
                    })
                })
            },
        )
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("pending probe rollback unconfirmed")),
            |_| Err(anyhow::anyhow!("pending probe commit unconfirmed")),
            |e| Err(anyhow::anyhow!(e)),
        )
}

/// Hold the real pending run so its recovery transaction retains the channel fence.
/// Authentication must finish while the real writer still holds this device's fence.
async fn authenticate_during_recovery(
    host: &Host,
    peer: &crate::windows::test_support::Peer,
    observer: &mut sqlx::PgConnection,
    row: Uuid,
) -> anyhow::Result<()> {
    use sqlx::Connection;
    // UUID ordering may select synthetic historical rows whose dispatch identity
    // belongs to the original run. Recover only the actual newly admitted run.
    let actual: Uuid = sqlx::query_scalar("SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND id=$3 AND state->>'cancellation'='none'")
        .bind(case_tenant()).bind(peer.intent.registration).bind(row).fetch_one(&mut *observer).await?;
    ensure!(actual == row);
    let mut connection =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut held = connection.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    sqlx::query(
        "SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE",
    )
    .bind(case_tenant())
    .bind(row)
    .fetch_one(&mut *held)
    .await?;
    let authentication = async {
        let result = async {
            let worker = blocked_recovery(observer, blocker).await?;
            let key = serde_json::to_string(&(case_tenant(), case_device(), rss_mdm_inventory::Channel::Mdm))?;
            let locked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND granted AND classid::bigint=((hashtextextended($2,2348)>>32)&4294967295) AND objid::bigint=(hashtextextended($2,2348)&4294967295) AND objsubid=1)")
                .bind(worker).bind(key).fetch_one(&mut *observer).await?;
            ensure!(locked, "recovery did not hold this device's channel fence");
            let leaf = host.windows.as_ref().channel.ca.verify(
                &[tokio_rustls::rustls::pki_types::CertificateDer::from(peer.certificate.as_slice())],
                crate::windows::test_support::now(),
            )?;
            let credential = crate::device::ChannelMount::new(
                rss_request_context::TenantId::parse(case_tenant())?,
                rss_mdm_inventory::ReportSource::MdmWindows,
                rss_mdm_registration_service::Purpose::Primary,
            ).credential(leaf.fingerprint())?;
            let principal = host.devices.management_principal(&credential).await?;
            ensure!(principal.registration() == peer.intent.registration && principal.device() == case_device(),
                "authentication returned another registration while recovery held the channel");
            // The holder is still blocked by our row transaction: the read did not
            // succeed merely because recovery happened to release its channel lock.
            let still_blocked: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
                .bind(blocker).bind(worker).fetch_one(&mut *observer).await?;
            ensure!(still_blocked, "recovery escaped the authentication rendezvous");
            Ok::<_, anyhow::Error>(())
        }.await;
        // Release the writer even when the old-code authentication counterexample fails.
        held.rollback().await?;
        result
    };
    let (recovered, authenticated) = tokio::join!(
        host.commands.service.recover_native_run_fixture(row),
        authentication
    );
    let closed = connection.close().await;
    recovered?;
    authenticated?;
    closed?;
    Ok(())
}

async fn blocked_recovery(observer: &mut sqlx::PgConnection, blocker: i32) -> anyhow::Result<i32> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_command_runtime' AND query LIKE '%FROM mdm_commands.action_runs%FOR UPDATE' AND $1=ANY(pg_blocking_pids(pid)) ORDER BY pid LIMIT 1")
                .bind(blocker).fetch_optional(&mut *observer).await?;
            if let Some(pid) = pid { return Ok::<_, anyhow::Error>(pid); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| anyhow::anyhow!("recovery never reached the action row held by {blocker}"))?
}

async fn denied_template_result(
    peer: &crate::windows::test_support::Peer,
    pg: &mut sqlx::PgConnection,
    mut packet: s::Message,
    run: Uuid,
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
    let response = native::post(&peer.mutual, &peer.url, &packet).await?;
    ensure!(response.status() == StatusCode::OK);
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
    ensure!(failed, "expired template published a result");
    Ok(())
}

async fn terminated_template_result(
    peer: &crate::windows::test_support::Peer,
    pg: &mut sqlx::PgConnection,
    mut packet: s::Message,
    run: Uuid,
) -> anyhow::Result<()> {
    ensure!(
        packet
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Results(_)))
    );
    packet.final_message = true;
    packet.commands.push(s::Command::Alert {
        id: packet.commands.iter().map(s::Command::id).max().unwrap() + 1,
        alert: s::Alert::SessionAbort,
    });
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
        terminal == (true, "failed".into(), "aborted".into(), true, false),
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
        "inventory",
        "prior-software",
        rss_mdm_inventory::Source::AgentBuiltin,
        {
            let scope = rss_mdm_inventory::CollectionScope::Device;
            let fields: Vec<rss_mdm_inventory::FieldDefinition> = vec![field];
            fields
                .into_iter()
                .map(|definition| rss_mdm_inventory::CollectionField {
                    definition,
                    scope: scope.clone(),
                })
                .collect()
        },
    )?;
    rss_mdm_inventory_postgres::register_collection_in(pg, saved.scope.tenant(), &definition)
        .await?;
    seed_prior_list(pg, &agent_scope, &definition, agent_key, &agent_value).await?;
    let mut enumerations = 0;
    let mut final_packet = None;
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
        let fragment = completion == Completion::Inventory
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
        final_packet = Some(packet.clone());
        let response = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "dynamic response: {}",
            response.status()
        );
        let bytes = response.bytes().await?;
        let next = s::decode(&bytes, &CodecLimits::default())?;
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
            final_packet = Some(packet.clone());
            let response = native::post(&peer.mutual, &peer.url, &packet).await?;
            ensure!(response.status() == StatusCode::OK);
            wire = s::decode(&response.bytes().await?, &CodecLimits::default())?;
        }
    }
    let result:(String,String)=sqlx::query_as("SELECT result,attempts FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NOT NULL").bind(case_tenant()).bind(run).fetch_one(&mut *pg).await.context("dynamic sealed result")?;
    let action: (String, String) = sqlx::query_as("SELECT state->>'execution',result->>'collectionRun' FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(run).fetch_one(&mut *pg).await?;
    ensure!(
        action == ("succeeded".into(), run.to_string()),
        "final multi-stage receipt did not atomically settle its ActionRun: {action:?}"
    );
    let packet = final_packet
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing final packet"))?;
    ensure!(
        native::post(&peer.mutual, &peer.url, packet)
            .await?
            .status()
            == StatusCode::OK
    );
    let before: serde_json::Value = sqlx::query_scalar("SELECT jsonb_build_array(state,result) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(run).fetch_one(&mut *pg).await?;
    let attempts: serde_json::Value = serde_json::from_str(&result.1)?;
    if matches!(completion, Completion::MissingChild) {
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
        if matches!(completion, Completion::Inventory) {
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
        if matches!(completion, Completion::Inventory) {
            let rows = page.1["asset"]["items"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("missing inventory rows: {page:?}"))?;
            ensure!(
                rows.len() == 1
                    && rows[0]["value"]["name"]["value"] == "Example"
                    && rows[0]["value"]["version"]["value"] == "1.2",
                "{page:?}"
            );
        }
    }
    if completion == Completion::MissingChild {
        ensure!(
            attempts["fields"]["device.model"]["quality"] == "success",
            "partial report lost its confirmed scalar: {attempts}"
        );
    }
    let sealed = crate::collection::store::load_on(pg, case_tenant(), run).await?;
    crate::inventory_runtime::test_support::wait_ready_projection(&host.runtime, &sealed).await?;
    let value = prior_list_value(pg, &saved.scope, key).await?;
    if matches!(completion, Completion::MissingChild) {
        ensure!(value == serde_json::to_value(&old)?);
    }
    if completion == Completion::EmptyInventory {
        ensure!(value == json!({"kind":"array","value":[]}));
    }
    let retained = prior_list_value(pg, &agent_scope, agent_key).await?;
    ensure!(
        retained == serde_json::to_value(&agent_value)?,
        "native collection modified Agent software"
    );
    crate::test_support::identity::change_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        vec![],
    )
    .await?;
    let mut recovery = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = recovery.startup()?.commit();
    launch.stage_deferred_task_with_token(
        host.commands
            .service
            .clone()
            .registration(host.notifications.signals.execution())
            .critical(),
    );
    launch.finish();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let converged: bool = sqlx::query_scalar("SELECT result='converged' FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='mdm.commands.v1' AND entity='native-run:'||$2::text")
                .bind(case_tenant()).bind(run).fetch_one(&mut *pg).await?;
            if converged { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await??;
    crate::test_support::runtime::stop_worker(Some(recovery)).await?;
    let after: serde_json::Value = sqlx::query_scalar("SELECT jsonb_build_array(state,result) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(run).fetch_one(&mut *pg).await?;
    ensure!(
        before == after,
        "revocation changed a synchronously sealed result"
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
    use sha2::{Digest, Sha256};
    let field = definition.field(key)?;
    let value = field.canonical_value(value.clone())?;
    let rss_mdm_inventory::Scalar::Array(items) = &value else {
        anyhow::bail!("prior list fixture requires an array");
    };
    let bytes = serde_json::to_vec(&value)?;
    let definition_bytes = serde_json::to_vec(field)?;
    let definition_digest = format!("{:x}", Sha256::digest(&definition_bytes));
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let version = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(1, &definition_digest, &digest))?)
    );
    let mut tx = pg.begin().await?;
    sqlx::query("INSERT INTO mdm.array_versions(tenant_id,version,format,field,definition_digest,item_count,canonical_bytes,digest,definition) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
        .bind(scope.tenant().to_string()).bind(&version).bind(key.as_str()).bind(&definition_digest).bind(items.len() as i64).bind(bytes.len() as i64).bind(digest).bind(definition_bytes).execute(&mut *tx).await?;
    let mut prefix = 0i64;
    for (ordinal, item) in items.iter().enumerate() {
        let payload = serde_json::to_vec(item)?;
        prefix += payload.len() as i64 + i64::from(ordinal > 0);
        sqlx::query("INSERT INTO mdm.array_items(tenant_id,version,ordinal,payload,digest,prefix_bytes) VALUES($1::uuid,$2,$3,$4,sha256($4),$5) ON CONFLICT DO NOTHING")
            .bind(scope.tenant().to_string()).bind(&version).bind(ordinal as i64).bind(payload).bind(prefix).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value_version,batch_id,observed_at,received_at,state,last_known_version,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),$1::uuid,'mdm.observation.v1','inventory-projection-v1',$2,$3,$4,$5,'prior-list',1,2,'known',$5,'prior-list',1,2,$6::uuid,$7,$8::uuid,0)")
        .bind(scope.tenant().to_string()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(key.as_str()).bind(version).bind(scope.registration().as_str()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn prior_list_value(
    pg: &mut sqlx::PgConnection,
    scope: &rss_observation::Scope,
    key: rss_mdm_inventory::FieldKey,
) -> anyhow::Result<serde_json::Value> {
    let fields = rss_mdm_inventory_postgres::read_in(
        pg,
        scope.tenant(),
        std::slice::from_ref(scope),
        &[key],
    )
    .await?;
    let fact = fields
        .arrays
        .into_iter()
        .find(|f| f.field == key)
        .ok_or_else(|| anyhow::anyhow!("missing projected list"))?;
    let rss_mdm_inventory::ArrayState::Known(value) = fact.fact.state else {
        anyhow::bail!("projected list is not known")
    };
    let mut items = Vec::new();
    let mut next = 0;
    loop {
        let page = rss_mdm_inventory_postgres::arrays::page(
            pg,
            scope.tenant(),
            &value.version,
            next,
            1000,
            16 * 1024 * 1024,
        )
        .await?;
        items.extend(page.items);
        match page.next {
            Some(n) => next = n,
            None => break,
        }
    }
    Ok(serde_json::to_value(rss_mdm_inventory::Scalar::Array(
        items,
    ))?)
}
