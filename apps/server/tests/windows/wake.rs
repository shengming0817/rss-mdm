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
}
impl WakeDemand for FailFirstPage {
    fn candidates<'a>(
        &'a self,
        store: &'a rss_mdm_windows_channel::Store,
        after: Option<(Uuid, Uuid)>,
    ) -> Pending<'a, Vec<(Uuid, Uuid)>> {
        if self.first.swap(false, Ordering::AcqRel) {
            return Box::pin(async {
                Err(rss_mdm_windows_channel::Error::Unavailable(
                    rss_mdm_windows_channel::Failure::Database,
                ))
            });
        }
        self.owner.candidates(store, after)
    }
    fn pending<'a>(
        &'a self,
        binding: ExecutionBinding,
        tx: &'a mut sqlx::PgConnection,
        device: &'a DeviceId,
    ) -> Pending<'a, bool> {
        self.owner.pending(binding, tx, device)
    }
}
#[tokio::test]
#[ignore = "T2: WNS retries a failed business page, delivers to a TLS provider and retires its invalid channel"]
async fn failed_page_recovers_without_hint_and_invalid_channel_leaves_discovery() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "windows").await?;
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
    let mut tx = command::seed_transaction(&c).await?;
    let material = rss_mdm_windows_channel::wns_materials::prepare(
        &mut tx,
        &t,
        Uuid::new_v4(),
        "wake-worker",
        &rss_mdm_windows_channel::wns_materials::Request {
            expected_revision: 0,
            package_family_name: "Rss.Test_0123456789abc".into(),
            sid: "ms-app://rss-test".to_owned().into(),
            client_secret: "test-secret".to_owned().into(),
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
    let uri = b"https://fixture.notify.windows.com/live";
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(n.device, config))?,
        "windows.push.channel",
        1,
    )?
    .derive();
    sqlx::query("INSERT INTO mdm_windows.push_channels(tenant_id,device,revision,configuration,uri,digest,attempt_until) VALUES($1::uuid,$2,1,$3,$4,$5,clock_timestamp()+interval '1 hour')")
        .bind(&t).bind(n.device.into_uuid()).bind(config.as_slice()).bind(key.seal_bytes(uri,&aad)?).bind(key.mac(uri,&aad)?.to_vec()).execute(&mut *tx).await?;
    tx.commit().await?;
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
    let owner = Arc::new(FailFirstPage {
        owner: crate::assembly::windows_business::WindowsBusiness(
            a.service.clone(),
            a.configuration.clone(),
            a.collections.clone(),
            a.software.service.clone(),
            a.registration.native.clone(),
        ),
        first: AtomicBool::new(true),
    });
    let router=axum::Router::new().route("/accesstoken.srf",axum::routing::post(||async{
        axum::Json(serde_json::json!({"token_type":"bearer","access_token":"test-token","expires_in":600}))
    })).route("/live",axum::routing::post(|headers:axum::http::HeaderMap|async move {
        assert_eq!(headers["authorization"],"Bearer test-token");
        axum::http::StatusCode::GONE
    }));
    let server = tokio::spawn(axum::serve(listener, router).into_future());
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(
        push::registration(
            h.state.clone(),
            owner.clone(),
            Arc::new(tokio::sync::Notify::new()),
        )
        .critical(),
    );
    launch.finish();
    let result=tokio::time::timeout(Duration::from_secs(20),async {
        while discovered().await? {tokio::time::sleep(Duration::from_millis(20)).await;}
        let row:(String,i32,bool)=sqlx::query_as("SELECT outcome,status,settled_id IS NOT NULL FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND device=$2")
            .bind(&t).bind(n.device.into_uuid()).fetch_one(&c.operator).await?;
        assert_eq!(row,("unregistered".into(),410,true));
        assert!(!owner.first.load(Ordering::Acquire));
        Ok::<_,anyhow::Error>(())
    }).await;
    assert!(stack.shutdown().join().await?.is_clean());
    server.abort();
    let _stopped = server.await;
    h.close().await?;
    c.close().await;
    result?
}
