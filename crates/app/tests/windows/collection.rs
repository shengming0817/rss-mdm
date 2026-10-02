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
    template_flow(None, 9).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: template authority before first fragment"]
async fn template_revocation_before_first_fragment_aborts() -> anyhow::Result<()> {
    template_flow(Some(false), 9).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: template authority between fragments"]
async fn template_revocation_between_fragments_aborts() -> anyhow::Result<()> {
    template_flow(Some(true), 9).await
}
#[tokio::test]
#[ignore = "MODULE=windows.management: last supported collection dispatch message"]
async fn template_dispatch_at_last_supported_message() -> anyhow::Result<()> {
    template_flow(None, CodecLimits::default().session_messages as u32 - 1).await
}
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and durable recovery assertions shared by T2 scenarios"
)]
async fn template_flow(
    revoke_after_first: Option<bool>,
    request_message: u32,
) -> anyhow::Result<()> {
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
        timeout_seconds: 120,
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
    post(&mut f.browser,&f.router,&format!("/api/v3/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"native_collection","frequency":"every_trigger","schedule":{"trigger":{"kind":"interval","anchor":now-7200,"seconds":3600},"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"coalesce_one"}},"resource":{"id":id,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
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
    if request_message == CodecLimits::default().session_messages as u32 - 1 {
        let stored:i64=sqlx::query_scalar("SELECT w.request_message FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id=$1::uuid AND r.evidence ? 'nativeTemplate'").bind(case_tenant()).fetch_one(&mut pg).await?;
        ensure!(
            stored == i64::from(request_message),
            "last supported request was not persisted"
        );
        crate::test_support::stop_worker(Some(owner)).await?;
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
    if let Some(after_first) = revoke_after_first {
        let run:Uuid=sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2").bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
        revoked_template_result(&peer, &mut pg, packet, run, after_first).await?;
        crate::test_support::stop_worker(Some(owner)).await?;
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
    let runs: Vec<Uuid> = sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2")
        .bind(case_tenant()).bind(policy).fetch_all(&mut pg).await?;
    ensure!(runs.len() == 1, "native Policy runs: {runs:?}");
    let pending:bool=sqlx::query_scalar("SELECT sealed_at IS NULL FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    ensure!(pending, "non-Final template results sealed early");
    crate::test_support::stop_worker(Some(owner)).await?;
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
            &format!("/api/v2/devices/{}/collections/{}", case_device(), runs[0]),
            None,
        )
        .await?;
    ensure!(
        result.0 == StatusCode::OK && result.1["asset"]["run"]["result"] == "snapshot",
        "native progress: {result:?}"
    );
    // Restore the durable pre-settlement state while retaining the already sealed response.
    // Recovery happens after its original execution timeout, as after worker downtime.
    sqlx::query("UPDATE mdm_commands.action_runs SET state=jsonb_set(jsonb_set(state,'{execution}','\"running\"'),'{startedAt}',to_jsonb($3::bigint)) WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).bind(now-120).execute(&mut pg).await?;
    host.app.execution.recover_action_fixture(policy).await?;
    let state:String=sqlx::query_scalar("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).fetch_one(&mut pg).await?;
    ensure!(
        state == "succeeded",
        "sealed success was lost after downtime: {state}"
    );
    // Shift the completed occurrence to the previous interval; the current one is due.
    sqlx::query("UPDATE mdm_commands.action_runs SET occurrence='timer:'||($3::bigint)::text||':'||registration::text,created_at=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(runs[0]).bind(now-3600).execute(&mut pg).await?;
    host.app.execution.recover_action_fixture(policy).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2")
        .bind(case_tenant()).bind(policy).fetch_one(&mut pg).await?;
    ensure!(count == 2, "completed run blocked the next occurrence");
    // History is retained, but it cannot occupy the entire check-in recovery page.
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'blocked-history:'||n,created_at-1000,available_at,deadline,jsonb_set(jsonb_set(state,'{execution}',to_jsonb(CASE WHEN n<=65 THEN 'unknown' ELSE 'not_started' END::text)),'{cancellation}',to_jsonb(CASE WHEN n<=65 THEN 'none' ELSE 'confirmed' END::text)),gateway_accepted,dispatch_fingerprint FROM mdm_commands.action_runs CROSS JOIN generate_series(1,130) n WHERE tenant_id=$1::uuid AND id=$2")
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
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'confirmed-history',created_at,available_at,deadline,jsonb_set(jsonb_set(state,'{execution}','\"unknown\"'),'{cancellation}','\"confirmed\"'),gateway_accepted,dispatch_fingerprint FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(runs[0]).execute(&mut pg).await?;
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

async fn revoked_template_result(
    peer: &crate::windows::test_support::Peer,
    pg: &mut sqlx::PgConnection,
    mut packet: s::Message,
    run: Uuid,
    after_first: bool,
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
    if !after_first {
        revoke().await?;
    }
    let mut response = native::post(&peer.mutual, &peer.url, &packet).await?;
    ensure!(response.status() == StatusCode::OK);
    if after_first {
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
