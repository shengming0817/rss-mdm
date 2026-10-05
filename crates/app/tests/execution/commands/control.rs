//! Native effect uncertainty, strict confirmation and historical delivery fences.
use crate::execution::test_support::{
    native::{begin, post, report},
    *,
};
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_windows_mdm::{CodecLimits, syncml as s};
use serde_json::json;
use sqlx::Connection;

#[tokio::test]
#[ignore = "MODULE=execution.commands.windows: real TLS/SyncML and historical recovery"]
async fn fixed_controls_preserve_uncertainty_and_retire_old_authority() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1200,
        None,
    )
    .await?;
    ensure!(
        post(
            &peer.mutual,
            &peer.url,
            &report(&warm.first, &warm.gets, "10.0.26100.0", 200)
        )
        .await?
        .status()
            == StatusCode::OK
    );
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        crate::test_support::identity::device_grants(
            None,
            &[
                "inventory_read",
                "operation_read",
                "operation_cancel",
                "device_control",
                "device_wipe",
            ],
        )?,
    )
    .await?;
    let device = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/devices/{}", case_device()),
            None,
        )
        .await?;
    ensure!(
        device.0 == StatusCode::OK,
        "registration detail: {device:?}"
    );
    let registration = &device.1["primaryMdmRegistration"];
    let confirmation = json!({"confirmed":true,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"]});
    for action in [
        json!({"kind":"lock","confirmed":true,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"],"pin":"123456"}),
        json!({"kind":"wipe","confirmed":false,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"]}),
        json!({"kind":"wipe","confirmed":true,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"].as_i64().unwrap()+1}),
    ] {
        let id = Uuid::new_v4();
        let response=client.call(Method::POST,"",Some(json!({"operationId":id,"deadline":host.app.clock.unix_seconds()?+300,"action":action}))).await?;
        ensure!(
            !response.0.is_success(),
            "unsupported/invalid control accepted: {response:?}"
        );
        ensure!(
            client.call(Method::GET, &format!("/{id}"), None).await?.0 == StatusCode::NOT_FOUND
        );
    }
    let mut ids = Vec::new();
    for kind in ["restart", "wipe"] {
        let id = Uuid::new_v4();
        let mut action = if kind == "restart" {
            json!({})
        } else {
            confirmation.clone()
        };
        action["kind"] = json!(kind);
        let body =
            json!({"operationId":id,"deadline":host.app.clock.unix_seconds()?+300,"action":action});
        let accepted = client.call(Method::POST, "", Some(body.clone())).await?;
        ensure!(accepted.0 == StatusCode::ACCEPTED, "{kind}: {accepted:?}");
        ensure!(client.call(Method::POST, "", Some(body)).await? == accepted);
        if kind == "wipe" {
            let wrong = client
                .call(
                    Method::POST,
                    &format!("/{id}/approve"),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1})),
                )
                .await?;
            ensure!(
                wrong.0 == StatusCode::CONFLICT,
                "dangerous reapproval without confirmation: {wrong:?}"
            );
            let approved=client.call(Method::POST,&format!("/{id}/approve"),Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1,"confirmation":confirmation}))).await?;
            ensure!(
                approved.0 == StatusCode::OK,
                "wipe reapproval: {approved:?}"
            );
        }
        client.publish_operation(id).await?;
        ids.push(id);
    }
    let exchange = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1201,
        None,
    )
    .await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut response = exchange.response.clone();
    let mut seen = std::collections::BTreeSet::new();
    let mut cached_delivery_requests = Vec::new();
    for _ in 0..6 {
        let gets = response
            .commands
            .iter()
            .filter_map(|c| match c {
                s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut packet = report(&exchange.first, &gets, "10.0.26100.0", 200);
        packet.header.message_id = response.header.message_id + 1;
        for c in &mut packet.commands {
            match c {
                s::Command::Status(v) => v.message_ref = response.header.message_id,
                s::Command::Results(v) => v.message_ref = Some(response.header.message_id),
                _ => {}
            }
        }
        for c in &response.commands {
            if let s::Command::Exec { items, .. } = c {
                let uri = items[0].target.clone().unwrap();
                ensure!(
                    [
                        "./Device/Vendor/MSFT/Reboot/RebootNow",
                        "./Device/Vendor/MSFT/RemoteWipe/doWipe"
                    ]
                    .contains(&uri.as_str()),
                    "arbitrary native command {uri}"
                );
                seen.insert(uri.clone());
                packet.commands.push(s::Command::Status(s::Status {
                    id: 100 + seen.len() as u32,
                    message_ref: response.header.message_id,
                    command_ref: c.id(),
                    command: s::CommandName::Exec,
                    target_refs: vec![uri],
                    source_refs: vec![],
                    code: 200,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }));
            }
        }
        let reply = post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(reply.status() == StatusCode::OK);
        response = s::decode(&reply.bytes().await?, &CodecLimits::default())?;
        if response
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Exec { .. }))
        {
            cached_delivery_requests.push(packet);
            for c in &response.commands {
                if let s::Command::Exec { items, .. } = c {
                    let index =
                        usize::from(items[0].target.as_deref().unwrap().ends_with("/doWipe"));
                    let id = ids[index];
                    // This attempt has reached the peer, but its original ACK has not arrived.
                    sqlx::query("UPDATE mdm_commands.operations SET approval=(approval-'action'-'confirmation')||'{\"kind\":\"user\"}'::jsonb WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).execute(&mut pg).await?;
                    client.publish_operation(id).await?;
                    ensure!(
                        client.call(Method::GET, &format!("/{id}"), None).await?.1["commandStatus"]
                            == "published"
                    );
                }
            }
        }
        if seen.len() == 2 {
            break;
        }
    }
    ensure!(seen.len() == 2, "fixed native controls missing: {seen:?}");
    for id in &ids {
        let read = client.call(Method::GET, &format!("/{id}"), None).await?;
        ensure!(
            read.1["commandStatus"] == "received"
                && read.1["observation"]["effect"] == "unverifiable",
            "ACK claimed effect: {read:?}"
        );
        client.publish_operation(*id).await?;
        ensure!(
            client
                .call(
                    Method::POST,
                    &format!("/{id}/approve"),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":read.1["revision"]}))
                )
                .await?
                .0
                == StatusCode::CONFLICT
        );
        ensure!(
            client.call(Method::GET, &format!("/{id}"), None).await?.1["commandStatus"]
                == "received"
        );
    }
    ensure!(!cached_delivery_requests.is_empty());
    for packet in cached_delivery_requests {
        let replay = post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(
            !replay.status().is_success(),
            "retired authority replayed cached native delivery"
        );
    }
    let pending = Uuid::new_v4();
    ensure!(client.call(Method::POST,"",Some(json!({"operationId":pending,"deadline":host.app.clock.unix_seconds()?+300,"action":{"kind":"restart"}}))).await?.0==StatusCode::ACCEPTED);
    sqlx::query("UPDATE mdm_commands.operations SET approval=(approval-'action'-'confirmation')||'{\"kind\":\"user\"}'::jsonb WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(pending).execute(&mut pg).await?;
    client.publish_operation(pending).await?;
    ensure!(
        client
            .call(Method::GET, &format!("/{pending}"), None)
            .await?
            .1["commandStatus"]
            == "cancelled"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2",
    )
    .bind(case_tenant())
    .bind(pending)
    .fetch_one(&mut pg)
    .await?;
    ensure!(count == 0, "retired pending task acquired an attempt");
    pg.close().await?;
    host.close().await?;
    Ok(())
}
