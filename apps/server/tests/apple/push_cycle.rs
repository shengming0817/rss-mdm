//! Real durable lease → HTTP/2 send → persisted result, without command evidence.
use super::*;
use crate::apple::push;
use sqlx::{Connection, PgConnection};
async fn due(pg: &mut PgConnection) -> Result<()> {
    sqlx::query("UPDATE mdm_apple.channels SET next_push=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2)")
        .bind(case_tenant()).bind(case_device())
        .execute(pg)
        .await?;
    Ok(())
}
async fn state(pg: &mut PgConnection) -> Result<serde_json::Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('state',state,'token',material IS NOT NULL,'magic',material IS NOT NULL,'lease',push_lease_until IS NOT NULL,'status',push_status,'outcome',push_outcome,'failures',push_failures,'delay',extract(epoch FROM next_push-clock_timestamp())::double precision) FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND state<>'retired'").bind(case_tenant()).bind(case_device()).fetch_one(pg).await?)
}
impl Fixture {
    pub async fn push_cycle(&mut self, peer: &lifecycle::Peer) -> Result<()> {
        self.native_context().await?;
        crate::test_support::identity::change_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            Fixture::native_grants(&["device_control"])?,
        )
        .await?;
        let operation = self.create_restart().await?;
        let mut pg =
            PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(case_tenant())
            .execute(&mut pg)
            .await?;
        let participant =
            push::test_support::Participant::start(vec![429, 429, 400, 200, 410], vec![42; 32])
                .await?;
        for (status, failures, minimum) in [(429, 1, 25.0), (429, 2, 55.0), (400, 0, 25.0)] {
            due(&mut pg).await?;
            rss_mdm_apple_channel::push::wake(&participant.push, &self.commands.service).await?;
            let receipt = state(&mut pg).await?;
            ensure!(
                receipt["status"] == status
                    && receipt["failures"] == failures
                    && receipt["lease"] == false
                    && receipt["state"] == "active"
                    && receipt["token"] == true,
                "APNs durable receipt {receipt}"
            );
            ensure!(
                receipt["delay"].as_f64().unwrap() >= minimum,
                "APNs retry is not delayed {receipt}"
            );
            ensure!(self.operation(operation).await?["commandStatus"] == "published");
        }
        due(&mut pg).await?;
        rss_mdm_apple_channel::push::wake(&participant.push, &self.commands.service).await?;
        ensure!(
            state(&mut pg).await?["status"] == 400,
            "permanent rejection was retried without recovery"
        );
        ensure!(
            self.commands
                .service
                .apple_wake(&participant.push.configuration)
                .await?
                .is_none()
        );
        // A genuinely reissued certificate reopens only the old certificate's pause.
        let rotated = push::test_support::Participant::start_with_rotation(
            vec![400, 200],
            vec![42; 32],
            true,
        )
        .await?;
        ensure!(rotated.push.configuration != participant.push.configuration);
        rss_mdm_apple_channel::push::wake(&rotated.push, &self.commands.service).await?;
        ensure!(state(&mut pg).await?["outcome"] == "rejected");
        ensure!(
            self.commands
                .service
                .apple_wake(&rotated.push.configuration)
                .await?
                .is_none()
        );
        // TokenUpdate is the explicit recovery transition for a paused token.
        peer.token().await?;
        rss_mdm_apple_channel::push::wake(&rotated.push, &self.commands.service).await?;
        ensure!(state(&mut pg).await?["outcome"] == "accepted");
        rotated.close().await?;
        due(&mut pg).await?;
        rss_mdm_apple_channel::push::wake(&participant.push, &self.commands.service).await?;
        ensure!(state(&mut pg).await?["outcome"] == "accepted");
        ensure!(self.operation(operation).await?["commandStatus"] == "published");
        due(&mut pg).await?;
        rss_mdm_apple_channel::push::wake(&participant.push, &self.commands.service).await?;
        let unregistered = state(&mut pg).await?;
        ensure!(
            unregistered["state"] == "pending_token"
                && unregistered["token"] == false
                && unregistered["magic"] == false
                && unregistered["lease"] == false
        );
        let denied = peer
            .send(
                "/mdm",
                protocol::dictionary([
                    ("Status", "Idle".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]),
            )
            .await?;
        ensure!(denied.0 == StatusCode::UNAUTHORIZED);
        participant.close().await?;
        peer.token().await?;
        let unavailable = push::test_support::Participant::unavailable_push().await?;
        rss_mdm_apple_channel::push::wake(&unavailable, &self.commands.service).await?;
        let failed = state(&mut pg).await?;
        ensure!(
            failed["status"].is_null()
                && failed["outcome"] == "retryable"
                && failed["lease"] == false
                && failed["failures"] == 1
        );
        ensure!(self.operation(operation).await?["commandStatus"] == "published");
        due(&mut pg).await?;
        let recovered = push::test_support::Participant::start(vec![200], vec![42; 32]).await?;
        rss_mdm_apple_channel::push::wake(&recovered.push, &self.commands.service).await?;
        ensure!(state(&mut pg).await?["failures"] == 0);
        recovered.close().await?;
        pg.close().await?;
        let operation_state = self.operation(operation).await?;
        let cancelled=self.browser.call(&self.router,Method::POST,&format!("/api/v1/devices/{DEVICE}/operations/{operation}/cancel", DEVICE = case_device()),Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":operation_state["revision"]}))).await?;
        ensure!(cancelled.0 == StatusCode::OK);
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.push: native protocol and durable state"]
async fn durable_push_leases_receipts_and_health() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.push_cycle(&peer).await?;
    drop(device);
    f.close().await
}

/// APNs candidate claims must not retain a channel row while waiting for publication clocks.
#[tokio::test]
#[ignore = "MODULE=apple.push: native wake and receipt lock ordering"]
async fn push_candidates_wait_for_watermark_before_channel_rows() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (_peer, device) = f.ready_local_peer().await?;
    f.native_context().await?;
    crate::test_support::identity::change_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        Fixture::native_grants(&["device_control"])?,
    )
    .await?;
    f.create_restart().await?;
    let mut hold =
        PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut hold)
        .await?;
    due(&mut hold).await?;
    let result = async {
        let mut previous = None;
        for phase in ["claim", "settle"] {
            sqlx::query("BEGIN").execute(&mut hold).await?;
            sqlx::query("SELECT mdm.lock_asset_watermark($1::uuid)")
                .bind(case_tenant()).execute(&mut hold).await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut hold).await?;
            let service = f.commands.service.clone();
            let configuration = f.apple.as_ref().channel.push_fixture().configuration;
            let current = previous.take();
            let work = tokio::spawn(async move {
                if let Some(wake) = current {
                    service.apple_pushed(&wake, Some(200), rss_mdm_execution_service::channels::PushOutcome::Accepted).await?;
                    Ok(None)
                } else {
                    service.apple_wake(&configuration).await
                }
            });
            let check = async {
                let mut observer = PgConnection::connect_with(
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
                let rows = sqlx::query("SELECT registration FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND state='active' FOR UPDATE NOWAIT")
                    .bind(case_tenant()).bind(case_device()).fetch_all(&mut hold).await?;
                ensure!(rows.len()==1,"missing native test channel during {phase}");
                observer.close().await?;
                Ok::<_,anyhow::Error>(())
            }.await;
            sqlx::query("ROLLBACK").execute(&mut hold).await?;
            let resumed = work.await?;
            check?;
            previous = resumed?;
            ensure!(phase!="claim" || previous.is_some(), "missing durable wake for settlement proof");
        }
        Ok(())
    }.await;
    hold.close().await?;
    drop(device);
    f.close().await?;
    result
}

#[tokio::test]
#[ignore = "MODULE=apple.push: isolated deadline query permission fault"]
async fn deadline_query_failure_is_not_healthy_idle() -> Result<()> {
    use sqlx::Executor;
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let mut resources = std::mem::take(&mut authority.resources);
    let config = crate::test_support::identity::config(case_tenant())?;
    let sessions = Arc::new(
        rss_mdm_authorization_service::session::SessionAuthority::new(
            authority.identity.authority.clone(),
            authority.identity.tenant,
        ),
    );
    let (execution, _, _) = crate::test_support::command::command_service(
        authority.audit.clone(),
        sessions,
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    resources.resource(rss_mdm_execution_service::Resource(execution.clone()));
    let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
    let apple_config = serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
    let apple = Apple::load(
        config.native_protector()?,
        apple_config,
        fixture_materials(&root)?,
        crate::clock::SystemClock.unix_seconds()?,
        (&config.product_origin, authority.identity.tenant),
        crate::device_pki::providers(&config.device_pki)?,
    )?;
    let access = rss_mdm_apple_channel::Store::from_pool(
        authority.pool.clone(),
        authority.registration.clone(),
        authority.authorization.clone(),
    );
    resources
        .finish(async {
            let mut pg =
                PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                    .await?;
            pg.execute("REVOKE EXECUTE ON FUNCTION pg_catalog.ceil(numeric) FROM PUBLIC")
                .await?;
            let result = rss_mdm_apple_channel::push::cycle(
                &apple.channel,
                &execution,
                &access,
                &authority.audit,
                case_tenant(),
            )
            .await;
            pg.execute("GRANT EXECUTE ON FUNCTION pg_catalog.ceil(numeric) TO PUBLIC")
                .await?;
            let restored = rss_mdm_apple_channel::push::cycle(
                &apple.channel,
                &execution,
                &access,
                &authority.audit,
                case_tenant(),
            )
            .await;
            ensure!(
                matches!(
                    result,
                    Err(rss_mdm_apple_channel::Error::Unavailable(
                        rss_mdm_apple_channel::Failure::Database
                    ))
                ),
                "deadline query failure became healthy idle"
            );
            ensure!(matches!(restored, Ok((0, push::WakeHealth::Idle, None))));
            pg.close().await?;
            Ok(())
        })
        .await
}
