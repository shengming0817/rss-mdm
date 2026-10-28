//! A real TLS participant checks OAuth, raw wake headers and token refresh independently.
use crate::windows::test_support::root;
use anyhow::{Result, ensure};
use std::{sync::Arc, time::Duration};

#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn native_push_routes_preserve_deadlines_and_rejections_until_uri_changes() -> Result<()> {
    use crate::{
        execution::test_support::native,
        windows::test_support::{Host, case_tenant},
    };
    use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
    use sqlx::Row;
    let mut host = Host::with_push().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let registration = peer.intent.registration;
    let pool =
        sqlx::PgPool::connect_with(crate::device::test_support::options("postgres")?).await?;
    scale::idle_costs(&host, &pool, registration).await?;
    let lease = uuid::Uuid::new_v4();
    for (round, pfn, uri, revision) in [
        (0, "wrong.pfn", "https://db5.notify.windows.com/wake", 0),
        (1, "fixture.pfn", "https://db5.notify.windows.com/wake", 1),
        (2, "fixture.pfn", "https://db5.notify.windows.com/wake", 1),
        (
            3,
            "fixture.pfn",
            "https://db5.notify.windows.com/changed",
            2,
        ),
    ] {
        let mut first = peer.message.clone();
        first.header.session_id = 1600 + round;
        ensure!(
            native::post(&peer.mutual, &peer.url, &first)
                .await?
                .status()
                .is_success()
        );
        let mut ack = peer.ack.clone();
        ack.header.session_id = first.header.session_id;
        if let s::Command::Status(status) = &mut ack.commands[0] {
            use base64::Engine;
            status.challenge.as_mut().unwrap().nonce = Some(Secret(
                base64::engine::general_purpose::STANDARD.encode([round as u8 + 30; 16]),
            ));
        }

        let response = native::post(&peer.mutual, &peer.url, &ack).await?;
        ensure!(response.status().is_success());
        let response = s::decode(&response.bytes().await?, &CodecLimits::default())?;
        let (push_id, items) = response
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Get { id, items, .. }
                    if items
                        .iter()
                        .any(|i| i.target.as_ref().is_some_and(|u| u.ends_with("/Push/PFN"))) =>
                {
                    Some((*id, items.clone()))
                }
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("missing native WNS query"))?;
        let gets = response
            .commands
            .iter()
            .filter_map(|c| match c {
                s::Command::Get { id, items, .. } if *id != push_id => {
                    Some((*id, items[0].target.clone().unwrap()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut packet = native::report(&first, &gets, "10.0.26100.0", 200);
        let id = packet.commands.iter().map(s::Command::id).max().unwrap() + 1;
        packet.commands.push(s::Command::Status(s::Status {
            id,
            message_ref: response.header.message_id,
            command_ref: push_id,
            command: s::CommandName::Get,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        }));
        packet.commands.push(s::Command::Results(s::Results {
            id: id + 1,
            message_ref: Some(response.header.message_id),
            command_ref: Some(push_id),
            command: Some(s::CommandName::Get),
            meta: None,
            items: items
                .into_iter()
                .map(|i| {
                    let source = i.target.unwrap();
                    let value = if source.ends_with("/PFN") { pfn } else { uri };
                    s::Item {
                        source: Some(source),
                        target: None,
                        meta: None,
                        data: Some(Secret(value.into())),
                        more_data: false,
                    }
                })
                .collect(),
        }));
        // Reply Status order follows the actual server request, including Push
        // before the inventory Gets. Client CmdIDs stay unique and sequential.
        let order = response
            .commands
            .iter()
            .enumerate()
            .map(|(index, command)| (command.id(), index))
            .collect::<std::collections::BTreeMap<_, _>>();
        packet.commands[1..].sort_by_key(|command| match command {
            s::Command::Status(value) => order[&value.command_ref],
            s::Command::Results(value) => order[&value.command_ref.unwrap()],
            _ => unreachable!(),
        });
        for (index, command) in packet.commands.iter_mut().enumerate() {
            match command {
                s::Command::Status(value) => value.id = index as u32 + 1,
                s::Command::Results(value) => value.id = index as u32 + 1,
                _ => unreachable!(),
            }
        }
        let result = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(
            result.status().is_success(),
            "WNS route report {}",
            result.status()
        );
        let original = result.bytes().await?;
        ensure!(
            native::post(&peer.mutual, &peer.url, &packet)
                .await?
                .bytes()
                .await?
                == original
        );
        let row=sqlx::query("SELECT revision,uri,lease_id,outcome,attempt_until>clock_timestamp()+interval '29 days' AS fresh FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2")
            .bind(case_tenant()).bind(registration).fetch_optional(&pool).await?;
        if revision == 0 {
            ensure!(row.is_none());
            continue;
        }
        let row = row.unwrap();
        ensure!(row.try_get::<i64, _>("revision")? == revision);
        ensure!(row.try_get::<bool, _>("fresh")? == (round != 2));
        ensure!(
            !row.try_get::<Vec<u8>, _>("uri")?
                .windows(uri.len())
                .any(|v| v == uri.as_bytes())
        );
        if round == 2 {
            ensure!(row.try_get::<Option<uuid::Uuid>, _>("lease_id")? == Some(lease));
            ensure!(row.try_get::<Option<String>, _>("outcome")?.as_deref() == Some("rejected"));
        }
        if round == 3 {
            ensure!(row.try_get::<Option<uuid::Uuid>, _>("lease_id")?.is_none());
        }
        if round == 1 {
            sqlx::query("UPDATE mdm_windows.push_channels SET attempt_until=clock_timestamp()+interval '1 hour',lease_id=$3,lease_until=clock_timestamp()+interval '30 seconds',outcome='rejected' WHERE tenant_id=$1::uuid AND registration=$2")
                .bind(case_tenant()).bind(registration).bind(lease).execute(&pool).await?;
        }
    }
    // Use the production claim/settle loop with the App authority bridge and a real TLS WNS peer.
    let (retry_date,retry_at): (String,f64) = sqlx::query_as("WITH due AS (SELECT date_trunc('second',clock_timestamp()+interval '1 hour') AS at) SELECT to_char(at AT TIME ZONE 'UTC','Dy, DD Mon YYYY HH24:MI:SS \"GMT\"'),extract(epoch FROM at)::double precision FROM due").fetch_one(&pool).await?;
    let (origin, transport, server, stop) = worker_transport(retry_date).await?;
    let mut windows = crate::windows::test_support::windows()?;
    let channel = Arc::get_mut(&mut windows.channel).unwrap();
    channel.push = Some(rss_mdm_windows_channel::push::Push::fixture(
        "fixture.pfn".into(),
        "fixture-sid".into(),
        "fixture-secret".into(),
        transport,
        &origin,
        crate::windows::test_support::monotonic(),
    )?);
    channel.push.as_mut().unwrap().configuration =
        host.windows.channel.push.as_ref().unwrap().configuration;
    let database = host.windows_state.access.clone();
    let eligibility = host.commands.service.clone();
    ensure!(
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant()
        )
        .await?
        .sent
            == 0,
        "no work must not wake a device"
    );
    let mut command = crate::execution::test_support::Client::start(
        host.browser.clone(),
        &host.commands,
        &host.authority.identity,
        host.authority.audit.clone(),
        host.clock.clone(),
    )
    .await?;
    command.accept_authorized().await?;
    command.publish_operation(command.operation).await?;
    scale::pending_costs(&host, &pool, command.operation).await?;
    let before: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await?;
    // Discovery rejects expired, fenced and already leased routes before a write transaction.
    for (change, restore) in [
        (
            "attempt_until=clock_timestamp()",
            "attempt_until=clock_timestamp()+interval '1 day'",
        ),
        ("generation=generation+1", "generation=generation-1"),
        (
            "lease_id=gen_random_uuid(),lease_until=clock_timestamp()+interval '30 seconds'",
            "lease_id=NULL,lease_until=NULL",
        ),
    ] {
        sqlx::query(&format!("UPDATE mdm_windows.push_channels SET {change} WHERE tenant_id=$1::uuid AND registration=$2"))
            .bind(case_tenant()).bind(registration).execute(&pool).await?;
        let scan = rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant(),
        )
        .await?;
        ensure!(scan.sent == 0 && scan.candidates == 67);
        sqlx::query(&format!("UPDATE mdm_windows.push_channels SET {restore} WHERE tenant_id=$1::uuid AND registration=$2"))
            .bind(case_tenant()).bind(registration).execute(&pool).await?;
    }
    // Both workers discover the same pending command; the durable lease permits one send.
    let (first, second) = tokio::join!(
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant()
        ),
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant()
        ),
    );
    let first = first?;
    let second = second?;
    ensure!(first.sent + second.sent == 1 && first.candidates == 67 && second.candidates == 67);
    // Retained unavailable registrations no longer participate after retirement.
    sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND device LIKE 'wns-idle:%'").bind(case_tenant()).execute(&pool).await?;
    let row = sqlx::query("SELECT outcome,status,failures,lease_id,settled_id,next_push>=to_timestamp($3+300) AS delayed FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(registration).bind(before as f64).fetch_one(&pool).await?;
    ensure!(
        row.try_get::<String, _>("outcome")? == "retryable"
            && row.try_get::<i32, _>("status")? == 406
            && row.try_get::<i32, _>("failures")? == 1
            && row.try_get::<Option<uuid::Uuid>, _>("lease_id")?.is_none()
            && row
                .try_get::<Option<uuid::Uuid>, _>("settled_id")?
                .is_some()
            && row.try_get::<bool, _>("delayed")?
    );
    let command_view = command
        .call(
            axum::http::Method::GET,
            &format!("/{}", command.operation),
            None,
        )
        .await?;
    ensure!(
        command_view.1["commandStatus"] == "published",
        "WNS acceptance became delivery: {}",
        command_view.1
    );
    ensure!(
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant()
        )
        .await?
        .sent
            == 0
    );
    // Expire only the persisted due time; the same URI/revision must recover without re-enrollment.
    sqlx::query("UPDATE mdm_windows.push_channels SET next_push=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(registration).execute(&pool).await?;
    ensure!(
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant()
        )
        .await?
        .sent
            > 0
    );
    let row = sqlx::query("SELECT outcome,status,failures,next_push>=to_timestamp($3) AS delayed FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(registration).bind(retry_at).fetch_one(&pool).await?;
    ensure!(
        row.try_get::<String, _>("outcome")? == "retryable"
            && row.try_get::<i32, _>("status")? == 503
            && row.try_get::<i32, _>("failures")? == 2
            && row.try_get::<bool, _>("delayed")?
    );
    ensure!(
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant()
        )
        .await?
        .sent
            == 0
    );
    sqlx::query("UPDATE mdm_windows.push_channels SET next_push=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(registration).execute(&pool).await?;
    ensure!(
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.commands.protection,
            &database,
            &host.authority.audit,
            case_tenant()
        )
        .await?
        .sent
            > 0
    );
    let row = sqlx::query("SELECT outcome,status,failures,revision,next_push>clock_timestamp() AS delayed FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(registration).fetch_one(&pool).await?;
    ensure!(
        row.try_get::<String, _>("outcome")? == "accepted"
            && row.try_get::<i32, _>("status")? == 200
            && row.try_get::<i32, _>("failures")? == 0
            && row.try_get::<i64, _>("revision")? == 2
            && row.try_get::<bool, _>("delayed")?
    );
    ensure!(
        command
            .call(
                axum::http::Method::GET,
                &format!("/{}", command.operation),
                None
            )
            .await?
            .1["commandStatus"]
            == "published"
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    lifecycle::late_receipts(&host, &pool, registration).await?;
    pool.close().await;
    host.close().await
}

async fn worker_transport(
    retry_date: String,
) -> Result<(
    String,
    reqwest::Client,
    tokio::task::JoinHandle<Result<()>>,
    tokio_util::sync::CancellationToken,
)> {
    let root = root()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let mut tls = crate::test_support::tls::server(&root, "windows-tls.pk8", None)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server = tokio::spawn(async move {
        let (io, _) = listener.accept().await?;
        let mut connection = h2::server::handshake(acceptor.accept(io).await?).await?;
        let mut handlers = tokio::task::JoinSet::new();
        for (token, status, retry_after) in [
            (true, 200, None),
            (false, 406, Some("300".to_owned())),
            (false, 503, Some(retry_date)),
            (false, 200, None),
        ] {
            let (request, mut send) = connection
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("WNS connection closed"))??;
            ensure!(request.method() == "POST");
            ensure!(
                request.uri().path()
                    == if token {
                        "/accesstoken.srf"
                    } else {
                        "/changed"
                    }
            );
            if !token {
                ensure!(
                    request.headers()["authorization"] == "Bearer fixture-token"
                        && request.headers()["x-wns-type"] == "wns/raw"
                );
            }
            handlers.spawn(async move {
                let mut body = request.into_body();
                while let Some(chunk) = body.data().await { let chunk = chunk?; body.flow_control().release_capacity(chunk.len())?; if !token { ensure!(chunk.is_empty()); } }
                let mut response = axum::http::Response::builder().status(status).header("x-wns-status", "received");
                if let Some(wait) = retry_after { response = response.header("retry-after",wait); }
                let response = response.body(())?;
                let mut response = send.send_response(response,false)?;
                response.send_data(axum::body::Bytes::from_static(if token {br#"{"token_type":"bearer","access_token":"fixture-token","expires_in":3600}"#} else {b""}),true)?;
                Ok::<(),anyhow::Error>(())
            });
        }
        tokio::select! { ()=stopped.cancelled()=>{}, next=connection.accept()=>ensure!(next.is_none(),"unexpected wake") }
        while let Some(result) = handlers.join_next().await {
            result??;
        }
        Ok(())
    });
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http2_prior_knowledge()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root.join("ca.crt"),
        )?)?)
        .build()?;
    Ok((origin, client, server, stop))
}

#[tokio::test]
#[ignore = "MODULE=windows.management: WNS credential rotation preserves application channel binding and rejects stale or cross-tenant replay"]
async fn durable_wns_rotation_keeps_channel_identity_and_original_operation() -> Result<()> {
    use crate::windows::test_support::case_tenant;
    use rss_mdm_windows_channel::wns_materials as material;
    use sqlx::Connection;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_owner")?)
            .await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let key = rss_mdm_native_protection::Protector::new(&[31; 32])?;
    let next =
        rss_mdm_native_protection::Protector::with_fingerprint(&[32; 32], &[&[31; 32]], &[31; 32])?;
    let first_id = uuid::Uuid::new_v4();
    let request = material::Request {
        expected_revision: 0,
        package_family_name: "fixture.pfn".into(),
        sid: "fixture-sid".to_owned().into(),
        client_secret: "original-secret".to_owned().into(),
    };
    let first = material::prepare(
        &mut tx,
        case_tenant(),
        first_id,
        "first-administrator",
        &request,
        &key,
    )
    .await?;
    ensure!(first.revision == 1 && first.qualified_at.is_none() && !first.selected);
    ensure!(
        material::load(
            &mut tx,
            case_tenant(),
            1,
            &key,
            crate::test_support::runtime::monotonic(),
            true
        )
        .await
        .is_err()
    );
    ensure!(
        material::prepare(
            &mut tx,
            case_tenant(),
            first_id,
            "different-administrator",
            &request,
            &key
        )
        .await
        .is_err()
    );
    material::qualify(
        &mut tx,
        case_tenant(),
        1,
        crate::windows::test_support::now(),
    )
    .await?;
    let before = material::load(
        &mut tx,
        case_tenant(),
        1,
        &key,
        crate::test_support::runtime::monotonic(),
        true,
    )
    .await?;
    let id = uuid::Uuid::new_v4();
    let mut replacement = material::Request {
        expected_revision: 1,
        package_family_name: "fixture.pfn".into(),
        sid: "fixture-sid".to_owned().into(),
        client_secret: "replacement-secret".to_owned().into(),
    };
    let second = material::prepare(
        &mut tx,
        case_tenant(),
        id,
        "first-administrator",
        &replacement,
        &key,
    )
    .await?;
    ensure!(second.revision == 2);
    ensure!(
        material::prepare(
            &mut tx,
            case_tenant(),
            id,
            "first-administrator",
            &replacement,
            &key
        )
        .await?
        .revision
            == 2
    );
    replacement.client_secret = "changed-replay".to_owned().into();
    ensure!(
        material::prepare(
            &mut tx,
            case_tenant(),
            id,
            "first-administrator",
            &replacement,
            &key
        )
        .await
        .is_err()
    );
    ensure!(material::rewrap(&mut tx, case_tenant(), &next).await? == 2);
    ensure!(material::rewrap(&mut tx, case_tenant(), &next).await? == 0);
    material::qualify(
        &mut tx,
        case_tenant(),
        2,
        crate::windows::test_support::now(),
    )
    .await?;
    let after = material::load(
        &mut tx,
        case_tenant(),
        2,
        &next,
        crate::test_support::runtime::monotonic(),
        true,
    )
    .await?;
    ensure!(before.configuration == after.configuration && before.pfn == after.pfn);
    let other = uuid::Uuid::new_v4().to_string();
    ensure!(
        material::load(
            &mut tx,
            &other,
            2,
            &next,
            crate::test_support::runtime::monotonic(),
            true
        )
        .await
        .is_err()
    );
    let revoke_id = uuid::Uuid::new_v4();
    let input = material::RevokeRequest {
        expected_revision: 2,
        material_revision: 2,
    };
    ensure!(
        material::revoke(
            &mut tx,
            case_tenant(),
            revoke_id,
            "first-administrator",
            &input,
            &next
        )
        .await?
        .revision
            == 3
    );
    ensure!(
        material::revoke(
            &mut tx,
            case_tenant(),
            revoke_id,
            "first-administrator",
            &input,
            &next
        )
        .await?
        .revision
            == 3
    );
    ensure!(
        material::directory(&mut tx, case_tenant(), None)
            .await?
            .revision
            == 3
    );
    ensure!(
        material::load(
            &mut tx,
            case_tenant(),
            2,
            &next,
            crate::test_support::runtime::monotonic(),
            true
        )
        .await
        .is_err()
    );
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=windows.management: runtime cannot forge WNS qualification"]
async fn runtime_role_cannot_insert_provider_success() -> Result<()> {
    use sqlx::Connection;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?)
            .await?;
    let mut tx = c.begin().await?;
    let tenant = uuid::Uuid::new_v4();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_wns.heads VALUES($1,0,NULL)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    let error = sqlx::query("INSERT INTO mdm_wns.versions(tenant_id,revision,operation_id,actor,fingerprint_key,fingerprint,pfn,sid_digest,configuration,material,qualified_at,selected) VALUES($1,1,$2,'fake','fake',decode(repeat('00',32),'hex'),'fake',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),decode('00','hex'),1,true)")
        .bind(tenant).bind(uuid::Uuid::new_v4()).execute(&mut *tx).await.unwrap_err();
    ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"));
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}

#[path = "wns_scale.rs"]
mod scale;

#[path = "wns_lifecycle.rs"]
mod lifecycle;
