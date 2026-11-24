//! WNS rechecks business demand and settles only the selected channel.
use super::*;
use rss_mdm_agent_wire::DeviceId;
use rss_mdm_windows_channel::{
    participants::{Pending, WakeDemand},
    push,
};
use rss_transactional_messaging::fence::ExecutionBinding;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;
struct FailFirstPage {
    owner: crate::assembly::windows_business::WindowsBusiness,
    first: AtomicBool,
    blocked: std::sync::OnceLock<DeviceId>,
    reached_claim: tokio_util::sync::CancellationToken,
    resume_claim: tokio_util::sync::CancellationToken,
}
impl WakeDemand for FailFirstPage {
    fn candidates<'a>(
        &'a self,
        connection: &'a mut sqlx::PgConnection,
        after: Option<(Uuid, Uuid)>,
    ) -> Pending<'a, Vec<rss_mdm_windows_channel::participants::WakeCandidate>> {
        if self.first.swap(false, Ordering::AcqRel) {
            return Box::pin(async {
                Err(rss_mdm_windows_channel::Error::Unavailable(
                    rss_mdm_windows_channel::Failure::Database,
                ))
            });
        }
        self.owner.candidates(connection, after)
    }
    fn pending<'a>(
        &'a self,
        binding: ExecutionBinding,
        tx: &'a mut sqlx::PgConnection,
        device: &'a DeviceId,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            if self.blocked.get() == Some(device) {
                self.reached_claim.cancel();
                self.resume_claim.cancelled().await;
            }
            self.owner.pending(binding, tx, device).await
        })
    }
}
async fn selected_configuration(
    c: &Context,
    key: &rss_mdm_native_protection::Protector,
    sid: &str,
) -> Result<[u8; 32]> {
    let t = c.tenant.to_string();
    let mut tx = command::seed_transaction(c).await?;
    let expected_revision: i64 = sqlx::query_scalar(
        "SELECT coalesce((SELECT revision FROM mdm_wns.heads WHERE tenant_id=$1::uuid),0)",
    )
    .bind(&t)
    .fetch_one(&mut *tx)
    .await?;
    let material = rss_mdm_windows_channel::wns_materials::prepare(
        &mut tx,
        &t,
        Uuid::new_v4(),
        "wake-worker",
        &rss_mdm_windows_channel::wns_materials::Request {
            expected_revision,
            package_family_name: "Rss.Test_0123456789abc".into(),
            sid: sid.to_owned().into(),
            client_secret: format!("test-secret-{expected_revision}").into(),
        },
        key,
    )
    .await?;
    let config:Vec<u8>=sqlx::query_scalar("UPDATE mdm_wns.versions SET qualified_at=1,selected=true WHERE tenant_id=$1::uuid AND revision=$2 RETURNING configuration")
        .bind(&t).bind(material.revision).fetch_one(&mut *tx).await?;
    let config: [u8; 32] = config.try_into().unwrap();
    sqlx::query("UPDATE mdm_wns.heads SET desired_revision=$2 WHERE tenant_id=$1::uuid")
        .bind(&t)
        .bind(material.revision)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(config)
}
async fn channel(
    c: &Context,
    device: DeviceId,
    key: &rss_mdm_native_protection::Protector,
    config: [u8; 32],
    uri: &[u8],
) -> Result<()> {
    let t = c.tenant.to_string();
    let mut tx = command::seed_transaction(c).await?;
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(device, config))?,
        "windows.push.channel",
        1,
    )?
    .derive();
    sqlx::query("INSERT INTO mdm_windows.push_channels(tenant_id,device,revision,configuration,uri,digest,attempt_until) VALUES($1::uuid,$2,1,$3,$4,$5,clock_timestamp()+interval '1 hour')")
        .bind(&t).bind(device.into_uuid()).bind(config.as_slice()).bind(key.seal_bytes(uri,&aad)?).bind(key.mac(uri,&aad)?.to_vec()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: WNS retries a failed business page, delivers to a TLS provider and retires its invalid channel"]
async fn failed_page_recovers_without_hint_and_invalid_channel_leaves_discovery() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let other = Context::open("shared", &[]).await?;
    let (c, other) = if c.tenant.to_string() < other.tenant.to_string() {
        (c, other)
    } else {
        (other, c)
    };
    let n = identity::seed(&c, "windows").await?;
    let sibling = identity::seed(&c, "windows").await?;
    let peer = identity::seed(&other, "windows").await?;
    let _peer_windows = windows(&other, &peer).await?;
    let w = windows(&c, &n).await?;
    let listener = crate::provider_http_t2_support::Listener::open(&n.directory).await?;
    let port = listener.address()?.port();
    let h = host_with_provider(
        &c,
        &n,
        w,
        Some((port, reqwest::Certificate::from_der(&n.root)?)),
    )
    .await?;
    let a = &h.assembly;
    let key = &a.resources.protection;
    let t = c.tenant.to_string();
    let config = selected_configuration(&c, key, "ms-app://rss-test").await?;
    channel(
        &c,
        n.device,
        key,
        config,
        b"https://fixture.notify.windows.com/held",
    )
    .await?;
    // Verify the capability under the actual database logins, including the shared command writer.
    for (role, trusted) in [
        ("mdm_access", false),
        ("mdm_command_runtime", false),
        ("mdm_wns_runtime", true),
    ] {
        let db = c.inputs.pool(&c.profile, role).await?;
        let (execute,write,trigger):(bool,bool,bool)=sqlx::query_as("SELECT
          has_function_privilege(current_user,p.oid,'EXECUTE'),
          has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE'),
          EXISTS(SELECT FROM pg_trigger tr WHERE tr.tgrelid=(SELECT ch.oid FROM pg_class ch JOIN pg_namespace ns ON ns.oid=ch.relnamespace WHERE ns.nspname='mdm_windows' AND ch.relname='push_channels') AND NOT tr.tgisinternal AND tr.tgfoid IN(SELECT f.oid FROM pg_proc f WHERE f.pronamespace=n.oid))
          FROM pg_namespace n JOIN pg_proc p ON p.pronamespace=n.oid AND p.proname='settle_throttle'
          JOIN pg_class c ON c.relnamespace=n.oid AND c.relname='provider_throttles' WHERE n.nspname='mdm_wns'")
            .fetch_one(&db).await?;
        assert_eq!((execute, write, trigger), (trusted, false, false), "{role}");
        db.close().await;
    }
    let pool = c.database.archive_pool();
    let discovered = || {
        sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM mdm_windows.push_work_page(NULL,NULL) WHERE tenant_id=$1::uuid)")
        .bind(&t).fetch_one(&pool)
    };
    assert!(!discovered().await?, "channel with no pending command");
    let command_id = Uuid::new_v4();
    identity_cases::seed_group(
        &c,
        &n,
        key,
        &identity_cases::request(false, false)?,
        &[command_id],
    )
    .await?;
    assert!(discovered().await?);
    let mut terminal = command::seed_transaction(&c).await?;
    sqlx::query("UPDATE rss_device_command.commands SET status='superseded',terminal_at=queued_at,version=version+1 WHERE tenant_id=$1::uuid AND command_id=$2")
        .bind(&t).bind(command_id.to_string()).execute(&mut *terminal).await?;
    let stale: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM mdm_windows.push_work_page(NULL,NULL) WHERE tenant_id=$1::uuid)",
    )
    .bind(&t)
    .fetch_one(&mut *terminal)
    .await?;
    assert!(
        !stale,
        "a terminal command with an active channel is no longer WNS work"
    );
    terminal.rollback().await?;
    let mut revoked = command::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_wns.versions SET revoked=true WHERE tenant_id=$1::uuid AND selected")
        .bind(&t)
        .execute(&mut *revoked)
        .await?;
    let stale: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM mdm_windows.push_work_page(NULL,NULL) WHERE tenant_id=$1::uuid)",
    )
    .bind(&t)
    .fetch_one(&mut *revoked)
    .await?;
    assert!(
        !stale,
        "revoked materials remove the channel from discovery"
    );
    revoked.rollback().await?;
    channel(
        &c,
        sibling.device,
        key,
        config,
        b"https://fixture.notify.windows.com/live",
    )
    .await?;
    let peer_config = selected_configuration(&other, key, "ms-app://rss-test").await?;
    channel(
        &other,
        peer.device,
        key,
        peer_config,
        b"https://fixture.notify.windows.com/live",
    )
    .await?;
    for (ctx, native) in [(&c, &sibling), (&other, &peer)] {
        identity_cases::seed_group(
            ctx,
            native,
            key,
            &identity_cases::request(false, false)?,
            &[Uuid::new_v4()],
        )
        .await?;
    }
    let owner = Arc::new(FailFirstPage {
        owner: crate::assembly::windows_business::WindowsBusiness(
            a.service.clone(),
            a.configuration.clone(),
            a.collections.clone(),
            a.software.service.clone(),
            a.registration.native.clone(),
        ),
        first: AtomicBool::new(true),
        blocked: Default::default(),
        reached_claim: Default::default(),
        resume_claim: Default::default(),
    });
    let held = Arc::new(tokio::sync::Notify::new());
    let release = tokio_util::sync::CancellationToken::new();
    let held_route = {
        let (held, release) = (held.clone(), release.clone());
        axum::routing::post(move || {
            let (held, release) = (held.clone(), release.clone());
            async move {
                held.notify_one();
                release.cancelled().await;
                axum::http::StatusCode::GONE
            }
        })
    };
    let router=axum::Router::new().route("/accesstoken.srf",axum::routing::post(||async{
        axum::Json(serde_json::json!({"token_type":"bearer","access_token":"test-token","expires_in":600}))
    })).route("/live",axum::routing::post(|headers:axum::http::HeaderMap|async move {
        assert_eq!(headers["authorization"],"Bearer test-token");
        axum::http::StatusCode::GONE
    }));
    let reached_claim = owner.reached_claim.clone();
    let router = router.route(
        "/throttled",
        axum::routing::post(move || async move {
            reached_claim.cancelled().await;
            (
                axum::http::StatusCode::NOT_ACCEPTABLE,
                [("retry-after", "120")],
            )
        }),
    );
    let server =
        tokio::spawn(axum::serve(listener, router.route("/held", held_route)).into_future());
    let hint = Arc::new(tokio::sync::Notify::new());
    let register = || -> Result<rss_runtime::ShutdownStack> {
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = stack.startup()?.commit();
        launch.stage_task_with_token(
            push::registration(
                h.state.clone(),
                owner.clone(),
                h.receipts.audit.clone(),
                rss_mdm_work_page::external::Limits::new(8.try_into()?, 7.try_into()?).unwrap(),
                hint.clone(),
            )
            .critical(),
        );
        launch.finish();
        Ok(stack)
    };
    let mut stack = Some(register()?);
    let result=tokio::time::timeout(Duration::from_secs(20),async {
        held.notified().await;
        loop {
            let finished:bool=sqlx::query_scalar("SELECT outcome IS NOT DISTINCT FROM 'unregistered' FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2")
                .bind(other.tenant.to_string()).bind(peer.device.into_uuid()).fetch_one(&other.operator).await?;
            if finished && sqlx::query_scalar::<_,bool>("SELECT outcome IS NOT DISTINCT FROM 'unregistered' AND settled_id IS NOT NULL FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2").bind(&t).bind(sibling.device.into_uuid()).fetch_one(&c.operator).await? { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let states:(i64,i64)=sqlx::query_as("SELECT count(*) FILTER (WHERE lease_id IS NOT NULL),count(settled_id) FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid")
            .bind(&t).fetch_one(&c.operator).await?;
        assert_eq!(states,(1,1), "A2 and B settle while A1 still owns its lease");
        let lease:Uuid=sqlx::query_scalar("SELECT lease_id FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2").bind(&t).bind(n.device.into_uuid()).fetch_one(&c.operator).await?;
        let drain=stack.take().unwrap().shutdown();
        assert_eq!(selected_configuration(&c,key,"ms-app://rss-test").await?,config);
        let limited=crate::planning_t2_support::endpoint(&c).await?.members[0].device;
        channel(&c,limited,key,config,b"https://fixture.notify.windows.com/throttled").await?;
        identity_cases::seed_device_group(&c,limited,key,&identity_cases::request(false,false)?,&[Uuid::new_v4()]).await?;
        hint.notify_one();
        release.cancel();
        assert!(drain.join().await?.is_clean());
        let row:(String,i32,Uuid,i64)=sqlx::query_as("SELECT outcome,status,settled_id,material_revision FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2").bind(&t).bind(n.device.into_uuid()).fetch_one(&c.operator).await?;
        assert_eq!(row,("unregistered".into(),410,lease,1));
        let pending:bool=sqlx::query_scalar("SELECT lease_id IS NULL AND settled_id IS NULL FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2").bind(&t).bind(limited.into_uuid()).fetch_one(&c.operator).await?;
        assert!(pending);
        let blocked=crate::planning_t2_support::endpoint(&other).await?.members[0].device;
        channel(&other,blocked,key,peer_config,b"https://fixture.notify.windows.com/live").await?;
        identity_cases::seed_device_group(&other,blocked,key,&identity_cases::request(false,false)?,&[Uuid::new_v4()]).await?;
        owner.blocked.set(blocked).unwrap();
        stack=Some(register()?);
        hint.notify_one();
        loop {
            let throttled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2 AND status=406 AND outcome='retryable' AND next_push>clock_timestamp()+interval '110 seconds')").bind(&t).bind(limited.into_uuid()).fetch_one(&c.operator).await?;
            if throttled {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_windows.push_work_page(NULL,NULL) WHERE tenant_id=$1::uuid AND device=$2)").bind(other.tenant.to_string()).bind(blocked.into_uuid()).fetch_one(&pool).await?;
        assert!(!allowed,"406 applies to the same OAuth identity across tenants");
        // Make the original provider deadline due. The same durable work becomes eligible again.
        sqlx::query("UPDATE mdm_wns.provider_throttles SET retry_at=clock_timestamp()+interval '1 second' WHERE tenant_id=$1::uuid").bind(&t).execute(&c.operator).await?;
        let mut held_material=command::seed_transaction(&other).await?;
        let holder:i32=sqlx::query_scalar("SELECT pg_backend_pid() FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND selected FOR UPDATE")
            .bind(other.tenant.to_string()).fetch_one(&mut *held_material).await?;
        owner.resume_claim.cancel();
        other.wait_blocked(holder).await?;
        // The claim snapshot observed a cooldown, which expires before the query can return.
        loop {
            let expired:bool=sqlx::query_scalar("SELECT retry_at<=clock_timestamp() FROM mdm_wns.provider_throttles WHERE tenant_id=$1::uuid")
                .bind(&t).fetch_one(&c.operator).await?;
            if expired {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        held_material.rollback().await?;
        loop {
            if sqlx::query_scalar::<_,bool>("SELECT settled_id IS NOT NULL AND status=410 FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2").bind(other.tenant.to_string()).bind(blocked.into_uuid()).fetch_one(&c.operator).await? {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!owner.first.load(Ordering::Acquire));
        Ok::<_,anyhow::Error>(())
    }).await;
    release.cancel();
    owner.resume_claim.cancel();
    if let Some(stack) = stack {
        assert!(stack.shutdown().join().await?.is_clean());
    }
    server.abort();
    let _stopped = server.await;
    h.close().await?;
    c.close().await;
    other.close().await;
    result?
}

#[path = "wake_capacity.rs"]
mod capacity;
