use crate::device::test_support::options;
use crate::windows::test_support::*;
use crate::windows::*;
use anyhow::ensure;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::syncml::{self, Command, CommandName};
use rss_mdm_windows_mdm::{CodecLimits, Secret};
use std::time::Duration;
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
    let store = &host.store;
    let runtime = &host.runtime;
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
            Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
            _ => None,
        })
        .collect();
    ensure!(gets.len() == 4 && gets[0].1 == "./DevInfo/Mod" && gets[1].1 == "./DevDetail/SwV");
    let packet = |message_id, previous, index: usize, value: &str| syncml::Message {
        header: syncml::Header {
            message_id,
            credential: None,
            ..message.header.clone()
        },
        commands: vec![
            Command::Status(syncml::Status {
                id: 1,
                message_ref: previous,
                command_ref: 0,
                command: CommandName::SyncHdr,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
            Command::Status(syncml::Status {
                id: 2,
                message_ref: 2,
                command_ref: gets[index].0,
                command: CommandName::Get,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
            Command::Results(syncml::Results {
                id: 3,
                message_ref: Some(2),
                command_ref: Some(gets[index].0),
                command: Some(CommandName::Get),
                meta: None,
                items: vec![syncml::Item {
                    more_data: false,
                    source: Some(gets[index].1.clone()),
                    target: None,
                    meta: None,
                    data: Some(Secret(value.into())),
                }],
            }),
        ],
        final_message: true,
    };

    let model = syncml::encode(&packet(3, 2, 0, "Model-TLS"), &CodecLimits::default())?;
    let first_fragment = post(model.clone()).send().await?;
    ensure!(first_fragment.status() == StatusCode::OK);
    let first_fragment = first_fragment.bytes().await?;
    ensure!(post(model.clone()).send().await?.bytes().await? == first_fragment);

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
    let pending = crate::collection::store::collection(&store.inventory(), &scope, None)
        .await?
        .unwrap();
    ensure!(pending.result == crate::collection::RunResult::Pending && pending.batch().is_none());
    ensure!(
        reader
            .read(scope.tenant(), std::slice::from_ref(&scope))
            .await?
            .is_empty(),
        "fragment projected before complete collection"
    );
    let mut conflicting = packet(4, 3, 0, "changed");
    ensure!(
        post(syncml::encode(&conflicting, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    conflicting = packet(4, 3, 1, "10.0.26100");
    let final_fragment = syncml::encode(&conflicting, &CodecLimits::default())?;
    #[cfg(feature = "integration")]
    {
        app.execution.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        ensure!(
            post(final_fragment.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let replay = post(final_fragment.clone()).send().await?;
    ensure!(replay.status() == StatusCode::OK);
    let replay = syncml::decode(&replay.bytes().await?, &CodecLimits::default())?;
    ensure!(
        replay
            .commands
            .iter()
            .any(|c| matches!(c, Command::Status(s) if s.command == CommandName::Results))
    );
    let sealed = crate::collection::store::collection(&store.inventory(), &scope, None)
        .await?
        .unwrap();
    ensure!(sealed.id == pending.id && sealed.result == crate::collection::RunResult::Snapshot);
    let bytes = sealed.batch().unwrap().encode().to_vec();
    ensure!(post(final_fragment).send().await?.status() == StatusCode::OK);
    ensure!(
        crate::collection::store::collection(&store.inventory(), &scope, None)
            .await?
            .unwrap()
            .batch()
            .unwrap()
            .encode()
            == bytes
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if runtime.inspect(&sealed).await?.projection
                == crate::inventory_runtime::ProjectionStatus::Projected
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    let fields = reader
        .read(scope.tenant(), std::slice::from_ref(&scope))
        .await?;
    ensure!(
        fields.len() == 2
            && fields[0].fact.state
                == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String(
                    "Model-TLS".into()
                ))
            && fields[1].fact.state
                == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String(
                    "10.0.26100".into()
                ))
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
    use sqlx::Connection;
    let mut pg = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
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
async fn abort_and_nonfinal_message_budget_cannot_publish_a_collection_snapshot()
-> anyhow::Result<()> {
    use crate::execution::test_support::native;
    use sqlx::Connection;
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut pg = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    for (session, abort) in [(1902, true), (1903, false)] {
        let exchange = native::begin(
            &peer.mutual,
            &peer.url,
            &peer.message,
            &peer.ack,
            session,
            None,
        )
        .await?;
        let mut complete = native::report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
        if abort {
            let id = complete.commands.iter().map(Command::id).max().unwrap() + 1;
            complete.commands.push(Command::Alert {
                id,
                alert: syncml::Alert::SessionAbort,
            });
        } else {
            for message_id in 3..CodecLimits::default().session_messages as u32 {
                let mut packet = complete.clone();
                packet.commands.truncate(1);
                packet.header.message_id = message_id;
                packet.final_message = false;
                if let Command::Status(status) = &mut packet.commands[0] {
                    status.message_ref = message_id - 1;
                }
                let response = native::post(&peer.mutual, &peer.url, &packet).await?;
                ensure!(
                    response.status() == StatusCode::OK,
                    "partial packet {message_id}: {}",
                    response.status()
                );
            }
            complete.header.message_id = CodecLimits::default().session_messages as u32;
            complete.final_message = false;
            if let Command::Status(status) = &mut complete.commands[0] {
                status.message_ref = complete.header.message_id - 1;
            }
        }
        let response = native::post(&peer.mutual, &peer.url, &complete).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "termination response {}",
            response.status()
        );
        let response = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
        ensure!(!response.final_message);
        let rows:Vec<(String,String,Option<Vec<u8>>,bool)> = sqlx::query_as("SELECT r.result,r.reason,r.batch,r.delivery_pending FROM mdm_access.collection_runs r JOIN mdm_windows.collections w ON(w.tenant_id,w.id)=(r.tenant_id,r.id) WHERE w.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3")
            .bind(case_tenant()).bind(peer.intent.registration).bind(session.to_string()).fetch_all(&mut pg).await?;
        ensure!(
            !rows.is_empty()
                && rows
                    .iter()
                    .all(|(result, reason, batch, pending)| result == "failed"
                        && reason == if abort { "aborted" } else { "message_budget" }
                        && batch.is_none()
                        && !pending),
            "termination published successful collection evidence: {rows:?}"
        );
    }
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
    // Retired response recovery survives temporary transcript pruning.
    let pool = sqlx::PgPool::connect_with(options("postgres")?).await?;
    sqlx::query(
        "DELETE FROM mdm_windows.management_sessions WHERE tenant_id=$1::uuid AND registration=$2",
    )
    .bind(case_tenant())
    .bind(peer.intent.registration)
    .execute(&pool)
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_windows.unenrollment_receipts WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(peer.intent.registration).fetch_one(&pool).await?;
    ensure!(count == 1);
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
