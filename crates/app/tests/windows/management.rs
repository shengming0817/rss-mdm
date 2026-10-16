use crate::device::test_support::options;
use crate::windows::test_support::*;
use anyhow::ensure;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::syncml::{self, Command, CommandName};
use rss_mdm_windows_mdm::{CodecLimits, Secret};
use uuid::Uuid;
#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn session_replay_nonce_collection_and_revoke() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let Peer {
        proof,
        intent,
        secrets,
        mutual,
        url,
        message,
        ..
    } = host.peer().await?;
    let app = &host.app;
    let reader = rss_mdm_inventory_postgres::InventoryReader::connect(options("mdm_api")?).await?;
    let wire = syncml::encode(&message, &CodecLimits::default())?;
    let post = |bytes: Vec<u8>| {
        mutual
            .post(&url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(bytes)
    };
    #[cfg(feature = "integration")]
    {
        app.execution
            .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
        ensure!(post(wire.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE);
        app.execution.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        ensure!(post(wire.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE);
    }
    let first = post(wire.clone()).send().await?;
    ensure!(first.status() == StatusCode::OK);
    let first = first.bytes().await?;
    let response = syncml::decode(&first, &CodecLimits::default())?;
    ensure!(
        response.header.credential.as_ref().unwrap().data.0
            == rss_mdm_windows_channel::test_support::digest(
                "RSS-MDM",
                &secrets.server_password,
                &secrets.server_nonce
            )
    );
    ensure!(post(wire.clone()).send().await?.bytes().await? == first);
    let mut wrong = message.clone();
    wrong.header.source = "another-device".into();
    ensure!(
        post(syncml::encode(&wrong, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    let mut changed = message.clone();
    changed.header.meta = Some(syncml::Meta {
        max_message_size: Some(65536),
        ..Default::default()
    });
    ensure!(
        post(syncml::encode(&changed, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    ensure!(
        post(wire.clone())
            .header("x-ssl-client-cert", "forged")
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED
    );
    let next_nonce = [7u8; 16];
    let followup = syncml::Message {
        header: syncml::Header {
            message_id: 2,
            credential: None,
            ..message.header.clone()
        },
        commands: vec![Command::Status(syncml::Status {
            credential: None,
            id: 1,
            message_ref: 1,
            command_ref: 0,
            command: CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 212,
            items: vec![],
            challenge: Some(syncml::Challenge {
                media_type: "syncml:auth-md5".into(),
                nonce: Some(Secret(STANDARD.encode(next_nonce))),
            }),
        })],
        final_message: true,
    };
    let followup = syncml::encode(&followup, &CodecLimits::default())?;
    let finished = post(followup.clone()).send().await?;
    ensure!(finished.status() == StatusCode::OK);
    let finished = finished.bytes().await?;
    ensure!(
        syncml::decode(&finished, &CodecLimits::default())?
            .header
            .credential
            .unwrap()
            .data
            .0
            == rss_mdm_windows_channel::test_support::digest(
                "RSS-MDM",
                &secrets.server_password,
                &secrets.server_nonce
            )
    );
    ensure!(post(followup.clone()).send().await?.bytes().await? == finished);
    let get_request = syncml::decode(&finished, &CodecLimits::default())?;
    let gets: Vec<_> = get_request
        .commands
        .iter()
        .filter_map(|c| match c {
            Command::Get { id, items, .. }
                if !items[0]
                    .target
                    .as_deref()
                    .unwrap()
                    .starts_with("./Device/Vendor/MSFT/RootCATrustedCertificates/") =>
            {
                Some((*id, items[0].target.clone().unwrap()))
            }
            _ => None,
        })
        .collect();
    ensure!(
        !gets.iter().any(|(_, uri)| uri == "./DevInfo/Mod"),
        "unconfigured session started fixed inventory collection"
    );
    let scope = app
        .devices
        .current_scope(
            &proof,
            crate::test_support::case::name("tls-device"),
            crate::device::coordinates::Coordinates {
                source: rss_mdm_inventory::ReportSource::MdmWindows,
            },
        )
        .await?;
    ensure!(
        reader
            .read(scope.tenant(), std::slice::from_ref(&scope))
            .await?
            .is_empty()
    );
    // The 212 NextNonce is persisted for the next session, while current-session
    // responses and retransmissions continue using the old digest.
    let mut next_session = message.clone();
    next_session.header.session_id += 1;
    let next_response = post(syncml::encode(&next_session, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(next_response.status() == StatusCode::OK);
    let next_response = syncml::decode(&next_response.bytes().await?, &CodecLimits::default())?;
    ensure!(
        next_response.header.credential.unwrap().data.0
            == rss_mdm_windows_channel::test_support::digest(
                "RSS-MDM",
                &secrets.server_password,
                &next_nonce
            )
    );
    // A newer session supersedes the prior unfinished session. Its stored response remains replayable,
    // but a delayed 212 from that older session cannot overwrite the latest next nonce.
    let old_initial = syncml::encode(&next_session, &CodecLimits::default())?;
    let old_response = post(old_initial.clone()).send().await?.bytes().await?;
    let mut newer_session = next_session.clone();
    newer_session.header.session_id += 1;
    ensure!(
        post(syncml::encode(&newer_session, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    ensure!(post(old_initial).send().await?.bytes().await? == old_response);
    let mut older_ack = syncml::decode(&followup, &CodecLimits::default())?;
    older_ack.header.session_id = next_session.header.session_id;
    ensure!(
        post(syncml::encode(&older_ack, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    older_ack.header.session_id = newer_session.header.session_id;
    let Command::Status(s) = &mut older_ack.commands[0] else {
        panic!()
    };
    s.challenge.as_mut().unwrap().nonce = Some(Secret(STANDARD.encode([9u8; 32])));
    ensure!(
        post(syncml::encode(&older_ack, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    let mut unsent = newer_session.clone();
    unsent.header.session_id += 1;
    unsent.commands.insert(0, older_ack.commands[0].clone());
    for (index, command) in unsent.commands.iter_mut().enumerate() {
        match command {
            Command::Status(s) => s.id = index as u32 + 1,
            Command::Alert { id, .. } | Command::DevInfo { id, .. } => *id = index as u32 + 1,
            _ => unreachable!(),
        }
    }
    ensure!(
        post(syncml::encode(&unsent, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    newer_session.header.session_id += 2;
    let current = post(syncml::encode(&newer_session, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(current.status() == StatusCode::OK);
    let current = syncml::decode(&current.bytes().await?, &CodecLimits::default())?;
    ensure!(
        current.header.credential.unwrap().data.0
            == rss_mdm_windows_channel::test_support::digest(
                "RSS-MDM",
                &secrets.server_password,
                &[9u8; 32]
            )
    );

    // Existing TLS keepalive connections do not cache the active mapping.
    app.devices
        .revoke(
            &proof,
            crate::test_support::case::name("tls-device"),
            intent.registration,
            Uuid::new_v4(),
        )
        .await?;
    ensure!(post(followup).send().await?.status() == StatusCode::UNAUTHORIZED);
    reader.close().await;
    host.close().await?;
    Ok(())
}

#[cfg(feature = "integration")]
#[path = "collection.rs"]
mod collection;

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn native_notifications_are_acked_and_replayed_without_finishing_pending_queries()
-> anyhow::Result<()> {
    use crate::execution::test_support::native;
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let exchange = native::begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1900,
        None,
    )
    .await?;
    use sqlx::Connection;
    let mut pg = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    let pending_query = "SELECT version_status IS NULL AND edition_status IS NULL FROM mdm_commands.capability_queries WHERE tenant_id=$1::uuid AND registration=$2 AND session=1900";
    ensure!(
        sqlx::query_scalar::<_, bool>(pending_query)
            .bind(case_tenant())
            .bind(peer.intent.registration)
            .fetch_one(&mut pg)
            .await?
    );
    let mut message = syncml::Message {
        header: syncml::Header {
            message_id: 3,
            credential: None,
            ..exchange.first.header.clone()
        },
        commands: vec![
            Command::Status(syncml::Status {
                id: 1,
                message_ref: exchange.response.header.message_id,
                command_ref: 0,
                command: CommandName::SyncHdr,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
            Command::Alert {
                id: 2,
                alert: syncml::Alert::Generic {
                    items: vec![syncml::Item {
                        source: Some("./Vendor/MSFT/HealthAttestation/VerifyHealth".into()),
                        target: None,
                        meta: Some(syncml::Meta {
                            media_type: Some("com.microsoft.mdm:HealthAttestation.Result".into()),
                            format: Some("int".into()),
                            ..Default::default()
                        }),
                        data: Some(Secret("3".into())),
                        more_data: false,
                    }],
                },
            },
        ],
        final_message: false,
    };
    let response = native::post(&peer.mutual, &peer.url, &message).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "native notification {}",
        response.status()
    );
    let original = response.bytes().await?;
    ensure!(
        native::post(&peer.mutual, &peer.url, &message)
            .await?
            .bytes()
            .await?
            == original
    );
    let reply = syncml::decode(&original, &CodecLimits::default())?;
    ensure!(!reply.final_message);
    ensure!(reply.commands.iter().any(|c|matches!(c,Command::Status(status) if status.command==CommandName::Alert && status.command_ref==2 && status.code==200)));
    ensure!(
        sqlx::query_scalar::<_, bool>(pending_query)
            .bind(case_tenant())
            .bind(peer.intent.registration)
            .fetch_one(&mut pg)
            .await?,
        "Alert completed an unanswered capability query"
    );
    let records: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical FROM mdm_audit.receipts WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_all(&mut pg)
            .await?;
    let notifications = records
        .iter()
        .filter_map(|record| {
            let decoded = rss_audit_core::decode_untrusted(record).ok()?;
            let payload: serde_json::Value =
                serde_json::from_slice(decoded.event().context().payload().as_bytes()).ok()?;
            (payload["details"]["nativeCode"] == 1226).then_some(payload)
        })
        .collect::<Vec<_>>();
    ensure!(
        notifications.len() == 1
            && notifications[0]["details"]["nativeItems"][0]["nativeType"]
                == "com.microsoft.mdm:HealthAttestation.Result"
            && notifications[0]["details"]["nativeItems"][0]["source"]
                == "./Vendor/MSFT/HealthAttestation/VerifyHealth",
        "native notification metadata was lost or replayed twice"
    );
    // The notification carries no values for the still-outstanding Get operations.
    let gets = exchange.gets.clone();
    message = native::report(&exchange.first, &gets, "10.0.26100.0", 200);
    message.header.message_id = 4;
    if let Command::Status(status) = &mut message.commands[0] {
        status.message_ref = reply.header.message_id;
    }
    let result = native::post(&peer.mutual, &peer.url, &message).await?;
    ensure!(
        result.status() == StatusCode::OK,
        "pending native reads lost after alert {}",
        result.status()
    );
    let observed: (String, i32, i64) = sqlx::query_as("SELECT os_version,edition,session FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    ensure!(observed == ("10.0.26100.0".into(), 48, 1900));
    pg.close().await?;
    host.close().await
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn damaged_committed_transcript_fails_closed_without_rewriting_evidence() -> anyhow::Result<()>
{
    use crate::execution::test_support::native;
    use sqlx::Connection;
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let exchange = native::begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1901,
        None,
    )
    .await?;
    let mut pg = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    let changed = sqlx::query("UPDATE mdm_access.management_messages SET request=set_byte(request,0,get_byte(request,0)#1) WHERE tenant_id=$1::uuid AND registration=$2 AND session_id='1901' AND message_id=1")
        .bind(case_tenant()).bind(peer.intent.registration).execute(&mut pg).await?;
    ensure!(changed.rows_affected() == 1);
    let damaged:Vec<u8>=sqlx::query_scalar("SELECT request FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2 AND session_id='1901' AND message_id=1")
        .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    let next = native::report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
    ensure!(
        native::post(&peer.mutual, &peer.url, &next).await?.status()
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let retained:Vec<u8>=sqlx::query_scalar("SELECT request FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2 AND session_id='1901' AND message_id=1")
        .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2 AND session_id='1901'")
        .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    ensure!(
        retained == damaged && count == 2,
        "damaged history was rewritten or advanced"
    );
    host.close().await
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn native_unenrollment_notification_retires_only_its_authenticated_registration()
-> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = crate::execution::test_support::native::begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1299,
        None,
    )
    .await?;
    ensure!(
        crate::execution::test_support::native::post(
            &peer.mutual,
            &peer.url,
            &crate::execution::test_support::native::report(
                &warm.first,
                &warm.gets,
                "10.0.26100.0",
                200
            )
        )
        .await?
        .status()
            == StatusCode::OK
    );
    let mut work =
        crate::execution::test_support::Client::start(host.browser.clone(), host.app.clone())
            .await?;
    work.accept_approved().await?;
    work.publish_operation(work.operation).await?;
    let pool = sqlx::PgPool::connect_with(options("postgres")?).await?;
    let second_device = crate::test_support::case::name("unaffected-native-device");
    let second = host.peer_for(second_device).await?;
    let second_exchange = crate::execution::test_support::native::begin(
        &second.mutual,
        &second.url,
        &second.message,
        &second.ack,
        1298,
        None,
    )
    .await?;
    ensure!(!second_exchange.gets.is_empty());
    let second_snapshot = "SELECT jsonb_build_object('registration',to_jsonb(r),'credentials',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM mdm_access.credentials c WHERE c.tenant_id=r.tenant_id AND c.registration=r.id),'pending',(SELECT jsonb_agg(to_jsonb(q) ORDER BY q.session) FROM mdm_commands.capability_queries q WHERE q.tenant_id=r.tenant_id AND q.registration=r.id)) FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.id=$2";
    let second_before: serde_json::Value = sqlx::query_scalar(second_snapshot)
        .bind(case_tenant())
        .bind(second.intent.registration)
        .fetch_one(&pool)
        .await?;
    ensure!(
        second_before["registration"]["state"] == "active"
            && second_before["credentials"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
            && second_before["pending"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
    );
    let mut notification = peer.message.clone();
    notification.header.session_id = 1300;
    notification.header.credential = None;
    notification.commands = vec![Command::Alert {
        id: 2,
        alert: syncml::Alert::UnenrollmentRequested,
    }];
    let mut other = notification.clone();
    other.header.source = "other-native-device".into();
    let post = |message: syncml::Message| {
        peer.mutual
            .post(&peer.url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(syncml::encode(&message, &CodecLimits::default()).unwrap())
            .send()
    };
    ensure!(post(other).await?.status() == StatusCode::FORBIDDEN);
    host.app
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::BeforeCommitPending);
    ensure!(post(notification.clone()).await?.status() == StatusCode::SERVICE_UNAVAILABLE);
    let intact: bool = sqlx::query_scalar("SELECT r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.credentials c WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND c.state='active') AND NOT EXISTS(SELECT 1 FROM mdm_windows.unenrollment_receipts u WHERE u.tenant_id=r.tenant_id AND u.registration=r.id) FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.id=$2").bind(case_tenant()).bind(peer.intent.registration).fetch_one(&pool).await?;
    ensure!(intact, "retirement or receipt escaped rollback");
    let state = work
        .call(
            axum::http::Method::GET,
            &format!("/{}", work.operation),
            None,
        )
        .await?;
    ensure!(
        state.1["commandStatus"] == "published",
        "retirement reducer escaped rollback: {}",
        state.1
    );
    let (response, duplicate) =
        tokio::join!(post(notification.clone()), post(notification.clone()));
    let response = response?;
    let duplicate = duplicate?;
    ensure!(
        response.status() == StatusCode::OK,
        "native disconnection: {}",
        response.status()
    );
    let original = response.bytes().await?;
    ensure!(duplicate.status() == StatusCode::OK);
    ensure!(duplicate.bytes().await? == original);
    let state = work
        .call(
            axum::http::Method::GET,
            &format!("/{}", work.operation),
            None,
        )
        .await?;
    ensure!(
        state.1["commandStatus"] == "cancelled",
        "pending command survived retirement: {}",
        state.1
    );

    // Retired response recovery survives temporary transcript pruning.
    let pool = sqlx::PgPool::connect_with(options("postgres")?).await?;
    sqlx::query(
        "DELETE FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2",
    )
    .bind(case_tenant())
    .bind(peer.intent.registration)
    .execute(&pool)
    .await?;
    sqlx::query(
        "DELETE FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2",
    )
    .bind(case_tenant())
    .bind(peer.intent.registration)
    .execute(&pool)
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_windows.unenrollment_receipts WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(peer.intent.registration).fetch_one(&pool).await?;
    ensure!(count == 1);
    let second_after: serde_json::Value = sqlx::query_scalar(second_snapshot)
        .bind(case_tenant())
        .bind(second.intent.registration)
        .fetch_one(&pool)
        .await?;
    ensure!(
        second_after == second_before,
        "retirement modified another registration's credentials or pending native reads"
    );
    pool.close().await;
    let response = syncml::decode(&original, &CodecLimits::default())?;
    ensure!(
        response
            .commands
            .iter()
            .all(|c| matches!(c, Command::Status(_))),
        "new work after disconnection"
    );
    let replay = post(notification.clone()).await?;
    ensure!(replay.status() == StatusCode::OK);
    ensure!(replay.bytes().await? == original);
    notification.header.session_id += 1;
    ensure!(post(notification).await?.status() == StatusCode::CONFLICT);
    ensure!(post(peer.message.clone()).await?.status() == StatusCode::UNAUTHORIZED);
    host.close().await?;
    Ok(())
}

#[cfg(feature = "integration")]
#[path = "wns.rs"]
mod wns;

// Real CSP replies are the installation proof; an Add ACK alone is insufficient.
#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn native_trust_requires_exact_csp_readback_before_confirmation() -> anyhow::Result<()> {
    use crate::execution::test_support::native;
    use sqlx::Connection;
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut observer = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    for (index, session) in [201, 202, 203, 204].into_iter().enumerate() {
        let opened = native::begin(
            &peer.mutual,
            &peer.url,
            &peer.message,
            &peer.ack,
            session,
            None,
        )
        .await?;
        let mut report = native::report(&opened.first, &opened.gets, "10.0.19045.0", 200);
        let business = report.commands.split_off(1);
        let mut store = std::collections::BTreeMap::new();
        for command in &opened.response.commands {
            if let Command::Add { id, items, .. } = command {
                for item in items {
                    if let Some(uri) = item.target.as_ref().filter(|u| {
                        u.starts_with("./Device/Vendor/MSFT/RootCATrustedCertificates/")
                    }) {
                        store.insert(uri.clone(), item.data.as_ref().unwrap().0.clone());
                        report.commands.push(Command::Status(syncml::Status {
                            id: report.commands.len() as u32 + 1,
                            message_ref: opened.response.header.message_id,
                            command_ref: *id,
                            command: CommandName::Add,
                            code: 200,
                            target_refs: vec![],
                            source_refs: vec![],
                            items: vec![],
                            challenge: None,
                            credential: None,
                        }));
                    }
                }
            }
        }
        ensure!(
            !store.is_empty(),
            "trust test did not receive any certificate Add"
        );
        if index > 0 {
            for command in &opened.response.commands {
                if let Command::Get { id, items, .. } = command {
                    for item in items {
                        if let Some(uri) = item.target.as_ref().filter(|u| store.contains_key(*u)) {
                            report.commands.push(Command::Status(syncml::Status {
                                id: report.commands.len() as u32 + 1,
                                message_ref: opened.response.header.message_id,
                                command_ref: *id,
                                command: CommandName::Get,
                                code: 200,
                                target_refs: vec![],
                                source_refs: vec![],
                                items: vec![],
                                challenge: None,
                                credential: None,
                            }));
                            report.commands.push(Command::Results(syncml::Results {
                                id: report.commands.len() as u32 + 1,
                                message_ref: Some(opened.response.header.message_id),
                                command_ref: Some(*id),
                                command: Some(CommandName::Get),
                                meta: None,
                                items: vec![syncml::Item {
                                    source: Some(uri.clone()),
                                    target: None,
                                    more_data: false,
                                    meta: None,
                                    data: Some(Secret(if index == 1 {
                                        "AA==".into()
                                    } else {
                                        store[uri].clone()
                                    })),
                                }],
                            }));
                        }
                    }
                }
            }
        }
        // Preserve the server's command order and unique reply CmdIDs.
        let offset = report.commands.len() as u32 - 1;
        for mut command in business {
            match &mut command {
                Command::Status(s) => s.id += offset,
                Command::Results(r) => r.id += offset,
                _ => anyhow::bail!("unexpected business fixture reply"),
            }
            report.commands.push(command);
        }
        let response = native::post(&peer.mutual, &peer.url, &report).await?;
        ensure!(response.status() == StatusCode::OK);
        let count:i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_pki.installations WHERE tenant_id=$1::uuid AND purpose='windows' AND registration=$2")
            .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut observer).await?;
        if index <= 1 {
            ensure!(count == 0, "Add ACK or wrong CSP readback confirmed trust");
        } else if count == 1 {
            observer.close().await?;
            return host.close().await;
        }
    }
    anyhow::bail!("exact native Root/CA readback did not confirm installed trust")
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=windows.management: issuance is not first authentication"]
async fn admission_pause_blocks_first_authentication_but_preserves_authenticated_sessions()
-> anyhow::Result<()> {
    use sqlx::Connection;
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut pg = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    let registration = peer.intent.registration;
    let initial: (String,bool) = sqlx::query_as("SELECT state, first_authenticated_at IS NOT NULL FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(registration).fetch_one(&mut pg).await?;
    ensure!(initial == ("active".into(), false));
    sqlx::query("INSERT INTO mdm_access.registration_admission(tenant_id,channel,revision,paused) VALUES($1::uuid,'windows_mdm',1,true)")
        .bind(case_tenant()).execute(&mut pg).await?;
    let wire = syncml::encode(&peer.message, &CodecLimits::default())?;
    let post = || {
        peer.mutual
            .post(&peer.url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(wire.clone())
    };
    ensure!(post().send().await?.status() == StatusCode::CONFLICT);
    let authenticated:bool=sqlx::query_scalar("SELECT first_authenticated_at IS NOT NULL FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(registration).fetch_one(&mut pg).await?;
    ensure!(!authenticated);
    sqlx::query("UPDATE mdm_access.registration_admission SET paused=false,revision=2 WHERE tenant_id=$1::uuid AND channel='windows_mdm'").bind(case_tenant()).execute(&mut pg).await?;
    let first = post().send().await?;
    ensure!(first.status() == StatusCode::OK);
    let bytes = first.bytes().await?;
    let authenticated = peer
        .mutual
        .post(&peer.url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(syncml::encode(&peer.ack, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(authenticated.status() == StatusCode::OK);

    let capability_reply = syncml::decode(&authenticated.bytes().await?, &CodecLimits::default())?;
    sqlx::query("UPDATE mdm_access.registration_admission SET paused=true,revision=3 WHERE tenant_id=$1::uuid AND channel='windows_mdm'").bind(case_tenant()).execute(&mut pg).await?;
    let replay = post().send().await?;
    ensure!(replay.status() == StatusCode::OK && replay.bytes().await? == bytes);
    let gets = capability_reply
        .commands
        .iter()
        .filter_map(|c| match c {
            Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(!gets.is_empty());
    let message =
        crate::execution::test_support::native::report(&peer.message, &gets, "10.0.26100.0", 200);
    let response =
        crate::execution::test_support::native::post(&peer.mutual, &peer.url, &message).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "pause rejected an existing registration's new message"
    );
    let progressed: bool = sqlx::query_scalar("SELECT last_message=$4 FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2 AND session_id=$3")
        .bind(case_tenant()).bind(registration).bind(message.header.session_id.to_string()).bind(i32::try_from(message.header.message_id)?).fetch_one(&mut pg).await?;
    ensure!(progressed);
    host.close().await?;
    Ok(())
}
