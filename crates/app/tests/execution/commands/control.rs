//! Native effect uncertainty, strict confirmation.
use crate::execution::test_support::{
    native::{begin, post, report},
    *,
};
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_windows_mdm::{CodecLimits, syncml as s};
use serde_json::json;

#[tokio::test]
#[ignore = "MODULE=execution.commands.windows: real TLS/SyncML control receipts"]
async fn fixed_controls_preserve_uncertainty() -> anyhow::Result<()> {
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
    for (index, action) in [
        json!({"kind":"restart","fields":{}}),
        json!({"kind":"lock","confirmed":true,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"],"pin":"123456"}),
        json!({"kind":"wipe","confirmed":false,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"]}),
        json!({"kind":"wipe","confirmed":true,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"].as_i64().unwrap()+1}),
    ].into_iter().enumerate() {
        let id = Uuid::new_v4();
        let response=client.call(Method::POST,"",Some(json!({"operationId":id,"deadline":host.app.clock.unix_seconds()?+300,"action":action}))).await?;
        let expected = [
            (StatusCode::BAD_REQUEST, "malformed_request"),
            (StatusCode::NOT_IMPLEMENTED, "action_not_supported"),
            (StatusCode::BAD_REQUEST, "malformed_request"),
            (StatusCode::CONFLICT, "operation_conflict"),
        ][index];
        ensure!(response.0 == expected.0 && response.1["code"] == expected.1,
            "wrong control rejection: {response:?}");
        ensure!(
            client.call(Method::GET, &format!("/{id}"), None).await?.0 == StatusCode::NOT_FOUND
        );
    }
    let mut ids = Vec::new();
    let mut approved_request = None;
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
            let body = json!({"requestId":Uuid::new_v4(),"expectedRevision":1,"confirmation":confirmation});
            let approved = client
                .call(Method::POST, &format!("/{id}/approve"), Some(body.clone()))
                .await?;
            ensure!(
                approved.0 == StatusCode::OK,
                "wipe reapproval: {approved:?}"
            );
            approved_request = Some((body, approved));
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
    let mut response = exchange.response.clone();
    let mut seen = std::collections::BTreeSet::new();
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
        let request_id = Uuid::new_v4();
        let mut approval = json!({"requestId":request_id,"expectedRevision":read.1["revision"]});
        if *id == ids[1] {
            approval["confirmation"] = confirmation.clone();
        }
        let stored = || {
            crate::test_support::pg(&format!(
                "SELECT jsonb_build_array(revision,approval) FROM mdm_commands.operations WHERE tenant_id='{}' AND id='{id}'",
                case_tenant()
            ))
        };
        let before = stored()?;
        if *id == ids[1] {
            let (body, response) = approved_request.as_ref().unwrap();
            ensure!(
                client
                    .call(Method::POST, &format!("/{id}/approve"), Some(body.clone()))
                    .await?
                    == *response
            );
            ensure!(
                stored()? == before,
                "receipt replay changed authority/revision"
            );
        }
        let denied = client
            .call(Method::POST, &format!("/{id}/approve"), Some(approval))
            .await?;
        ensure!(
            denied.0 == StatusCode::CONFLICT,
            "received command reapproval: {denied:?}"
        );
        ensure!(
            stored()? == before,
            "received command reapproval changed revision/authority"
        );
        let after = client.call(Method::GET, &format!("/{id}"), None).await?;
        ensure!(
            after.0 == StatusCode::OK
                && after.1["revision"] == read.1["revision"]
                && after.1["commandStatus"] == "received"
                && after.1["observation"]["effect"] == "unverifiable",
            "received command reapproval changed state: {after:?}"
        );
        ensure!(crate::test_support::pg(&format!(
            "SELECT count(*) FROM mdm_commands.requests WHERE tenant_id='{}' AND id='{request_id}'", case_tenant()))?.trim() == "0",
            "rejected reapproval persisted a success receipt");
        ensure!(
            crate::test_support::audit_count(|r| r.source() == "mdm.business"
                && r.operation() == Some(request_id.to_string().as_str())
                && r.result() == "success")?
                == 0,
            "rejected reapproval appended a success business fact"
        );
    }
    host.close().await?;
    Ok(())
}
