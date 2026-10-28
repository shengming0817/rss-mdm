//! A blocked TLS response races with a real persisted route rebind/retirement.
use crate::windows::test_support::{Host, case_tenant, root};
use anyhow::{Result, ensure};
use rss_mdm_native_protection::ProtectionContext;
use sqlx::Row;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(super) async fn late_receipts(
    host: &Host,
    pool: &sqlx::PgPool,
    registration: Uuid,
) -> Result<()> {
    let root = root()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let mut tls = crate::test_support::tls::server(&root, "windows-tls.pk8", None)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let (requests, mut observed) = tokio::sync::mpsc::channel(1);
    let server = tokio::spawn(async move {
        let (io, _) = listener.accept().await?;
        let mut connection = h2::server::handshake(acceptor.accept(io).await?).await?;
        let mut handlers = tokio::task::JoinSet::new();
        for (token, status) in [
            (true, 200),
            (false, 404),
            (false, 200),
            (false, 410),
            (false, 200),
        ] {
            let (request, mut response) = connection
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("closed TLS peer"))??;
            let requests = requests.clone();
            handlers.spawn(async move {
                let mut body = request.into_body();
                while let Some(bytes) = body.data().await {
                    let bytes = bytes?;
                    body.flow_control().release_capacity(bytes.len())?;
                }
                if !token {
                    let (resume, ready) = tokio::sync::oneshot::channel();
                    requests.send(resume).await?;
                    ready.await?;
                }
                let mut response = response.send_response(
                    axum::http::Response::builder().status(status).body(())?,
                    false,
                )?;
                response.send_data(
                    axum::body::Bytes::from_static(if token {
                        br#"{"access_token":"fixture-token","expires_in":3600}"#
                    } else {
                        b""
                    }),
                    true,
                )?;
                Ok::<(), anyhow::Error>(())
            });
        }
        tokio::select! { ()=stopped.cancelled()=>{}, next=connection.accept()=>ensure!(next.is_none(),"unexpected request"), }
        while let Some(result) = handlers.join_next().await {
            result??;
        }
        Ok::<(), anyhow::Error>(())
    });
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root.join("ca.crt"),
        )?)?)
        .build()?;
    let mut windows = crate::windows::test_support::windows()?;
    let configuration = host.windows.channel.push.as_ref().unwrap().configuration;
    let mut push = rss_mdm_windows_channel::push::Push::fixture(
        "fixture.pfn".into(),
        "fixture-sid".into(),
        "fixture-secret".into(),
        client,
        &origin,
        crate::windows::test_support::monotonic(),
    )?;
    push.configuration = configuration;
    Arc::get_mut(&mut windows.channel).unwrap().push = Some(push);
    let generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(registration)
    .fetch_one(pool)
    .await?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let original = "https://db5.notify.windows.com/changed";
    for (index, (new_uri, retire, invalid)) in [
        (false, false, true),
        (false, false, false),
        (true, false, false),
        (false, true, false),
    ]
    .into_iter()
    .enumerate()
    {
        let aad = ProtectionContext::new(
            tenant,
            &serde_json::to_string(&(registration, generation, configuration))?,
            "windows.push.channel",
            1,
        )?
        .derive();
        let sealed = host
            .commands
            .protection
            .seal_bytes(original.as_bytes(), &aad)?;
        let digest = host.commands.protection.mac(original.as_bytes(), &aad)?;
        sqlx::query("UPDATE mdm_windows.push_channels SET configuration=$3,uri=$4,digest=$5,revision=revision+1,outcome=NULL,status=NULL,lease_id=NULL,lease_until=NULL,settled_id=NULL,next_push=clock_timestamp(),attempt_until=clock_timestamp()+interval '1 day' WHERE tenant_id=$1::uuid AND registration=$2")
            .bind(case_tenant()).bind(registration).bind(configuration.as_slice()).bind(sealed).bind(digest.as_slice()).execute(pool).await?;
        let scan = rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &host.commands.service,
            &host.commands.protection,
            &host.windows_state.access,
            &host.authority.audit,
            case_tenant(),
        );
        let change = async {
            let resume = tokio::time::timeout(Duration::from_secs(10), observed.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing request"))?;
            let mut tx = pool.begin().await?;
            if retire {
                sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(registration).execute(&mut *tx).await?;
                rss_mdm_windows_channel::retire_in(&mut tx, case_tenant(), registration).await?;
            } else {
                let next = [index as u8 + 70; 32];
                let value = if new_uri {
                    "https://db5.notify.windows.com/replacement"
                } else {
                    original
                };
                let aad = ProtectionContext::new(
                    tenant,
                    &serde_json::to_string(&(registration, generation, next))?,
                    "windows.push.channel",
                    1,
                )?
                .derive();
                let sealed = host
                    .commands
                    .protection
                    .seal_bytes(value.as_bytes(), &aad)?;
                let digest = host.commands.protection.mac(value.as_bytes(), &aad)?;
                sqlx::query("UPDATE mdm_windows.push_channels SET configuration=$3,uri=$4,digest=$5,revision=revision+1 WHERE tenant_id=$1::uuid AND registration=$2")
                    .bind(case_tenant()).bind(registration).bind(next.as_slice()).bind(sealed).bind(digest.as_slice()).execute(&mut *tx).await?;
            }
            tx.commit().await?;
            resume
                .send(())
                .map_err(|_| anyhow::anyhow!("sender ended"))?;
            Ok::<(), anyhow::Error>(())
        };
        let (scan, changed) = tokio::join!(scan, change);
        changed?;
        ensure!(scan?.sent == 1);
        let row = sqlx::query("SELECT outcome,lease_id FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(registration).fetch_one(pool).await?;
        ensure!(
            row.try_get::<Option<String>, _>("outcome")?.as_deref()
                == invalid.then_some("unregistered")
        );
        if invalid || retire {
            ensure!(row.try_get::<Option<Uuid>, _>("lease_id")?.is_none());
        }
        if retire {
            let scan = rss_mdm_windows_channel::push::wake_once(
                &windows.channel,
                &host.commands.service,
                &host.commands.protection,
                &host.windows_state.access,
                &host.authority.audit,
                case_tenant(),
            )
            .await?;
            ensure!(scan.sent == 0 && scan.transactions == 0);
        }
    }
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    Ok(())
}
