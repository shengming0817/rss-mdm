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

#[path = "collection.rs"]
mod collection;
