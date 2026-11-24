use super::super::*;
use rss_mdm_authorization_service::{Permission as P, context::AuthorizedPrincipal};
use rss_mdm_policy_service::{events::Events, worker::PolicyWork};
use rss_reconcile::{DurableStore, ReconcileStep};
use std::time::Duration;
use tower::ServiceExt;

async fn members(
    h: &Harness,
    events: &Arc<Events>,
    proof: &Arc<AuthorizedPrincipal>,
    device: rss_mdm_agent_wire::DeviceId,
    batch: Uuid,
) -> Result<(u16, Value)> {
    let routes = rss_mdm_management_http::policy_events::routes(events.clone())
        .layer(axum::Extension(h.c.read_auth(proof.clone())))
        .layer(axum::Extension(h.c.request(proof)?))
        .into_axum();
    let app = axum::Router::new().nest("/api/v1/tenants/{tenant}", routes);
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(format!(
                    "/api/v1/tenants/{}/devices/{device}/policy-event-batches/{batch}/members",
                    h.c.tenant
                ))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&body)?))
}

async fn advance(h: &Harness, worker: &PolicyWork, batch: Uuid) -> Result<()> {
    let timer = rss_mdm_policy_service::clock::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
    let scope = rss_reconcile::Scope::new(h.c.tenant, "mdm.policy-events")?;
    let target = format!("event:{batch}");
    let mut applied = false;
    for claim in worker
        .claim_due(&scope, 16, 64, Duration::from_secs(30), &control)
        .await?
        .claims
    {
        if claim.target().entity() == target {
            let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
                anyhow::bail!("event observation deferred")
            };
            assert!(matches!(
                worker.apply(&claim, diff, &control).await?,
                ReconcileStep::Ready(())
            ));
            applied = true;
        }
        worker.release(&claim, &control).await?;
    }
    anyhow::ensure!(applied, "missing durable event job for {batch}");
    Ok(())
}

#[tokio::test]
#[ignore = "T2: authenticated Policy event replay and owner-decided Script/Native Collection progress through member HTTP"]
async fn original_parent_receipt_and_member_progress() -> Result<()> {
    let h = Harness::open().await?;
    let owner = planning::owner(&h.c, "mdm_policy_runtime").await?;
    let resources = &h.a.resources;
    let app = crate::assembly::policy::application(
        &resources.background,
        &owner,
        h.c.execution(),
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        resources.protection.clone(),
        None,
    )
    .await?;
    let events = crate::assembly::policy::events(
        h.c.execution(),
        app.clone(),
        Arc::new(crate::assembly::policy::EventInputs {
            source: resources.source.clone(),
            protection: resources.protection.clone(),
            instance: resources.config.identity.instance_id.clone(),
        }),
        h.a.software.materials.clone(),
        h.a.registration.materials.clone(),
        Vec::new(),
    )
    .await?;
    let worker = PolicyWork::new(
        h.c.database.archive_pool(),
        h.c.execution().storage(),
        app,
        events.clone(),
        resources.storage.reconcile.clone(),
    );
    let device = *h.p.device();
    let (child, _) = h.policy("event-child").await?;
    let (_, version) = h.policy("event-parent").await?;
    let parent = h.run(version, "event-parent", now() + 300).await?;
    let offer = h.claim().await?;
    assert_eq!(offer.payload.task_id(), parent);
    h.event(&offer, w::TaskEvent::Received).await?;
    h.event(&offer, w::TaskEvent::Start).await?;
    let mut setup = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_policy.policies SET definition=jsonb_set(definition,'{customEvent}',to_jsonb('child-event'::text)) WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string()).bind(child).execute(&mut *setup).await?;
    setup.commit().await?;
    let input = w::PolicyEventRequest {
        operation_id: Uuid::new_v4(),
        event: w::PolicyEventName::parse("child-event")?,
        source: w::PolicyEventSource::Policy { run_id: parent },
        execution_context: Some(context()),
    };
    let accepted = events.invoke_agent(&h.p, &input, &request(&h.c)).await?;
    assert_eq!(accepted.members, 1);
    let at = now();
    h.event(
        &offer,
        w::TaskEvent::Result(w::TaskResult::new(
            Some(0),
            w::OutputQuality::Complete,
            json!({"ok":true}),
            w::TaskDiagnostics::new(String::new(), String::new(), 1, at, None)?,
            at,
        )?),
    )
    .await?;
    assert_eq!(
        events
            .invoke_agent(&h.p, &input, &request(&h.c))
            .await?
            .batch_id,
        accepted.batch_id
    );
    let fresh = w::PolicyEventRequest {
        operation_id: Uuid::new_v4(),
        ..input.clone()
    };
    assert!(matches!(
        events.invoke_agent(&h.p, &fresh, &request(&h.c)).await,
        Err(rss_mdm_policy_service::Error::Forbidden)
    ));
    advance(&h, &worker, accepted.batch_id).await?;
    let account =
        h.c.account(&[
            P::PolicyRead,
            P::OperationRead,
            P::InventoryRead,
            P::InventoryCollect,
        ])
        .await?;
    let proof = Arc::new(h.c.authenticate(&account).await?);
    let (status, page) = members(&h, &events, &proof, device, accepted.batch_id).await?;
    assert_eq!(status, 200, "{page}");
    let row = &page["items"][0];
    assert_eq!(row["decision"]["state"], "accepted", "{row}");
    assert_eq!(row["operations"][0]["reference"]["id"], row["id"]);
    assert_eq!(row["operations"][0]["state"]["execution"], "not_started");
    let id = serde_json::from_value(row["id"].clone())?;
    let mut unknown: rss_mdm_task_state::RunState = serde_json::from_value(h.state(id).await?)?;
    let attempt = Uuid::new_v4();
    unknown.claim(attempt, at)?;
    unknown.received(attempt, at)?;
    unknown.start(attempt, at)?;
    unknown.expire(unknown.deadline);
    unknown.cancel();
    let mut setup = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_script.runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(id)
        .bind(json!(unknown))
        .execute(&mut *setup)
        .await?;
    setup.commit().await?;
    let (status, page) = members(&h, &events, &proof, device, accepted.batch_id).await?;
    assert_eq!(status, 200);
    assert_eq!(page["items"][0]["operations"][0]["state"], json!(unknown));
    let (native_policy, _, object) = super::super::retirement::native(&h, None).await?;
    let native_device = object.members[0].device;
    let scope = planning::published(&h.c, &object).await?.scope;
    let mut setup = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_windows.capabilities(tenant_id,device,protocol_epoch,os_version,edition,session,observed_at)
        SELECT tenant_id,id,epoch,'10.0.22631.0',4,1,extract(epoch from clock_timestamp())::bigint FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string()).bind(native_device.into_uuid()).execute(&mut *setup).await?;
    sqlx::query("UPDATE mdm_policy.policies SET definition=definition || jsonb_build_object('scope',$3::uuid,'customEvent','native-event') WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string()).bind(native_policy).bind(scope).execute(&mut *setup).await?;
    setup.commit().await?;
    let input = w::PolicyEventRequest {
        operation_id: Uuid::new_v4(),
        event: w::PolicyEventName::parse("native-event")?,
        source: w::PolicyEventSource::Human,
        execution_context: None,
    };
    let batch = events
        .invoke_management(&proof, &native_device, &input, &h.c.request(&proof)?)
        .await?;
    assert_eq!(batch.members, 1);
    advance(&h, &worker, batch.batch_id).await?;
    let (status, page) = members(&h, &events, &proof, native_device, batch.batch_id).await?;
    assert_eq!(status, 200, "{page}");
    let row = &page["items"][0];
    assert_eq!(row["decision"]["state"], "accepted", "{row}");
    assert_eq!(
        row["operations"][0]["reference"],
        json!({"kind":"run","id":row["id"]})
    );
    assert_eq!(row["operations"][0]["state"]["delivery"], "queued");
    assert_eq!(
        members(&h, &events, &proof, device, batch.batch_id)
            .await?
            .0,
        404
    );
    let mut invalid = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_access.devices SET epoch=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(device.into_uuid())
        .bind(Uuid::new_v4())
        .execute(&mut *invalid)
        .await?;
    invalid.commit().await?;
    assert!(matches!(
        events.invoke_agent(&h.p, &fresh, &request(&h.c)).await,
        Err(rss_mdm_policy_service::Error::Unauthorized)
    ));
    owner.runtime.close().await;
    h.close().await
}
