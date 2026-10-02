#![allow(
    clippy::cognitive_complexity,
    reason = "real protocol ordering, revocation and recovery assertions"
)]
use crate::execution::test_support::native::{self, begin, post, report};
use crate::execution::test_support::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_execution_service::*;
use rss_mdm_windows_mdm::{Secret, syncml as s};
use serde_json::{Value, json};
use sqlx::Connection;

fn task_packet(
    exchange: &native::ReadExchange,
    message: u32,
    status: Option<u16>,
    value: Option<&str>,
) -> s::Message {
    let (id, uri) = exchange
        .gets
        .iter()
        .rev()
        .find(|(_, uri)| uri == "./DevInfo/Mod")
        .unwrap();
    let mut packet = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
    packet.header.message_id = message;
    packet.commands.truncate(1);
    if let s::Command::Status(header) = &mut packet.commands[0] {
        header.message_ref = message - 1;
    }
    if let Some(code) = status {
        packet.commands.push(s::Command::Status(s::Status {
            id: 2,
            message_ref: 2,
            command_ref: *id,
            command: s::CommandName::Get,
            target_refs: vec![uri.clone()],
            source_refs: vec![],
            code,
            items: vec![],
            challenge: None,
            credential: None,
        }));
    }
    if let Some(value) = value {
        packet.commands.push(s::Command::Results(s::Results {
            id: 3,
            message_ref: Some(2),
            command_ref: Some(*id),
            command: Some(s::CommandName::Get),
            meta: None,
            items: vec![s::Item {
                source: Some(uri.clone()),
                target: None,
                meta: None,
                data: Some(Secret(value.into())),
            }],
        }));
    }
    packet
}
async fn operation(client: &mut Client) -> anyhow::Result<Value> {
    let (status, body) = client
        .call(Method::GET, &format!("/{}", client.operation), None)
        .await?;
    ensure!(status == StatusCode::OK, "native read: {status} {body}");
    Ok(body)
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn native_partial_receipts_late_results_read_recovery_and_generation_fences()
-> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 990, None).await?;
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
    client.accept_approved().await?;
    client.publish_operation(client.operation).await?;
    let exchange = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        991,
        Some("./DevInfo/Mod"),
    )
    .await?;
    let native_id = exchange
        .gets
        .iter()
        .rev()
        .find(|(_, uri)| uri == "./DevInfo/Mod")
        .unwrap()
        .0;
    let mut first = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
    for command in &mut first.commands {
        if let s::Command::Status(status) = command
            && status.command_ref == native_id
        {
            status.code = 101;
        }
    }
    first
        .commands
        .retain(|c| !matches!(c, s::Command::Results(r) if r.command_ref == Some(native_id)));
    ensure!(post(&peer.mutual, &peer.url, &first).await?.status() == StatusCode::OK);
    ensure!(
        operation(&mut client).await?["commandStatus"] == "published",
        "101 became completion"
    );
    for (message, status) in [(4, 202), (5, 206)] {
        ensure!(
            post(
                &peer.mutual,
                &peer.url,
                &task_packet(&exchange, message, Some(status), None)
            )
            .await?
            .status()
                == StatusCode::OK
        );
        ensure!(
            operation(&mut client).await?["commandStatus"] == "published",
            "{status} became completion"
        );
    }
    ensure!(
        post(
            &peer.mutual,
            &peer.url,
            &task_packet(&exchange, 6, Some(213), None)
        )
        .await?
        .status()
            == StatusCode::OK
    );
    let partial = operation(&mut client).await?;
    ensure!(
        partial["commandStatus"] == "published"
            && partial["observation"]["receipts"][0]["status"] == 213
            && partial["observation"]["receipts"][0]["accepted"].is_null(),
        "buffered status became a terminal receipt: {partial}"
    );
    ensure!(
        post(
            &peer.mutual,
            &peer.url,
            &task_packet(&exchange, 7, Some(200), None)
        )
        .await?
        .status()
            == StatusCode::OK
    );
    let acked = operation(&mut client).await?;
    ensure!(
        acked["commandStatus"] == "received"
            && acked["observation"]["effect"] == "waiting"
            && acked["observation"]["receipts"][0]["value"].is_null(),
        "ACK became native state: {acked}"
    );
    client.set_authorized(false).await?;
    let late_packet = task_packet(&exchange, 8, None, Some("late-model"));
    ensure!(post(&peer.mutual, &peer.url, &late_packet).await?.status() == StatusCode::OK);
    let late = operation(&mut client).await?;
    let receipt = &late["observation"]["receipts"][0];
    ensure!(
        late["commandStatus"] == "received"
            && receipt["accepted"] == true
            && receipt["resultAccepted"] == false
            && receipt["value"] == "late-model",
        "late Results inherited earlier ACK authority: {late}"
    );
    client.set_authorized(true).await?;
    let approved = client
        .call(
            Method::POST,
            &format!("/{}/approve", client.operation),
            Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":late["revision"]})),
        )
        .await?;
    ensure!(
        approved.0 == StatusCode::OK,
        "renewed native approval: {approved:?}"
    );
    let recovery = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        992,
        Some("./DevInfo/Mod"),
    )
    .await?;
    let recovery_id = recovery
        .gets
        .iter()
        .rev()
        .find(|(_, uri)| uri == "./DevInfo/Mod")
        .unwrap()
        .0;
    let mut results_first = report(&recovery.first, &recovery.gets, "10.0.26100.0", 200);
    results_first
        .commands
        .retain(|c| !matches!(c,s::Command::Status(s) if s.command_ref == recovery_id));
    ensure!(
        post(&peer.mutual, &peer.url, &results_first)
            .await?
            .status()
            == StatusCode::OK
    );
    let waiting = operation(&mut client).await?;
    ensure!(
        waiting["commandStatus"] == "received",
        "Results without Status completed the request: {waiting}"
    );
    let current = waiting["observation"]["receipts"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    ensure!(
        current["ordinal"] == 2
            && current["accepted"].is_null()
            && current["resultAccepted"] == true
    );
    ensure!(post(&peer.mutual, &peer.url, &late_packet).await?.status() == StatusCode::OK);
    ensure!(
        operation(&mut client).await? == waiting,
        "old session replay replaced the current query"
    );
    let completed = task_packet(&recovery, 4, Some(200), None);
    #[cfg(feature = "integration")]
    {
        client.app.execution.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        ensure!(
            post(&peer.mutual, &peer.url, &completed).await?.status()
                == StatusCode::SERVICE_UNAVAILABLE
        );
    }
    ensure!(post(&peer.mutual, &peer.url, &completed).await?.status() == StatusCode::OK);
    let read = operation(&mut client).await?;
    ensure!(
        read["commandStatus"] == "applied" && read["observation"]["effect"] == "waiting",
        "complete native query missing: {read}"
    );
    ensure!(read["observation"]["receipts"].as_array().unwrap().len() == 2);
    ensure!(
        post(&peer.mutual, &peer.url, &recovery.ack).await?.status() == StatusCode::FORBIDDEN,
        "completed query request was replayed"
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let persisted: Vec<Vec<u8>> = sqlx::query_scalar("SELECT request FROM mdm_commands.attempts WHERE tenant_id=$1::uuid UNION ALL SELECT request FROM mdm_commands.capability_queries WHERE tenant_id=$1::uuid UNION ALL SELECT response FROM mdm_access.management_messages WHERE tenant_id=$1::uuid UNION ALL SELECT correlation::bytea FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid UNION ALL SELECT request FROM mdm_windows.collections WHERE tenant_id=$1::uuid").bind(case_tenant()).fetch_all(&mut pg).await?;
    ensure!(!persisted.is_empty());
    for stored in persisted {
        ensure!(
            s::decode(&stored, &rss_mdm_windows_mdm::CodecLimits::default()).is_err(),
            "durable native wire remained plaintext"
        );
    }
    let native_values: Vec<Vec<u8>> = sqlx::query_scalar("SELECT value FROM mdm_commands.attempt_items WHERE tenant_id=$1::uuid AND value IS NOT NULL").bind(case_tenant()).fetch_all(&mut pg).await?;
    ensure!(!native_values.is_empty());
    for stored in native_values {
        ensure!(
            !stored
                .windows(b"late-model".len())
                .any(|v| v == b"late-model"),
            "native result remained plaintext"
        );
    }
    sqlx::query("UPDATE mdm_access.management_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND session_id IN('990','991','992')").bind(case_tenant()).execute(&mut pg).await?;
    ensure!(
        rss_mdm_windows_channel::retention::prune_management(
            &client.app.access.windows_store(),
            &client.app.audit_store,
            case_tenant()
        )
        .await?
            >= 1
    );
    ensure!(
        operation(&mut client).await? == read,
        "session GC removed durable native evidence"
    );
    host.replace(&peer).await?;
    client.operation = Uuid::new_v4();
    client.accept_approved().await?;
    let current = operation(&mut client).await?;
    ensure!(post(&peer.mutual, &peer.url, &completed).await?.status() == StatusCode::UNAUTHORIZED);
    ensure!(
        operation(&mut client).await? == current,
        "old certificate changed the new registration operation"
    );
    let generation:i64=sqlx::query_scalar("SELECT registration_generation FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(client.operation).fetch_one(&mut pg).await?;
    ensure!(generation == 2);
    pg.close().await?;
    host.close().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn console_mixed_kind_cursor_and_device_visibility() -> anyhow::Result<()> {
    use crate::test_support::{agent_execution as agent, identity};
    let mut fixture = agent::Fixture::new().await?;
    fixture.register().await?;
    let (resource, _, _) = fixture.resource().await?;
    fixture
        .scope(
            agent::case_task_scope(),
            json!([{"kind":"device","id":agent::case_device_id()}]),
        )
        .await?;
    let worker = agent::worker(&fixture.base).await?;
    agent::publish(&mut fixture.author, &fixture.router, resource).await?;
    let task = agent::claim(&fixture.router).await?;
    agent::complete(&fixture.router, &task).await?;
    let id = Uuid::parse_str(task["payload"]["taskId"].as_str().unwrap())?;
    crate::test_support::stop_worker(worker).await?;
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let _peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    // IDs belong to their original owners; equal IDs must not lose either kind.
    client.operation = id;
    client.accept_approved().await?;
    client.publish_operation(id).await?;
    let mut grants = fixture.grants.clone();
    grants.extend(identity::device_grants(None, &["operation_read"])?);
    identity::set_grants(case_tenant(), &fixture.author_id, grants).await?;
    for descending in [false, true] {
        let mut path = format!("/api/v3/operations?limit=1&descending={descending}");
        let mut kinds = Vec::new();
        loop {
            let (status, page) = fixture
                .author
                .call(&fixture.router, Method::GET, &path, None)
                .await?;
            ensure!(status == StatusCode::OK, "mixed directory: {status} {page}");
            ensure!(
                page["statistics"]["total"] == 2
                    && page["statistics"]["commands"] == 1
                    && page["statistics"]["actionRuns"] == 1,
                "mixed statistics: {page}"
            );
            let item = &page["items"][0];
            ensure!(item["id"] == id.to_string(), "mixed ID: {item}");
            let kind = item["kind"].as_str().unwrap();
            kinds.push(kind.to_owned());
            if kind == "command" {
                ensure!(
                    item["evidence"]["commandStatus"] == "published"
                        && item["evidence"]["observation"]["effect"] == "waiting",
                    "receipt became effect: {item}"
                );
                ensure!(item["evidence"]["observation"].get("value").is_none());
                ensure!(
                    item["detailUrl"]
                        == format!("/api/v3/devices/{}/operations/{id}", case_device())
                );
            } else {
                ensure!(item["evidence"]["result"].get("output").is_none());
                ensure!(
                    item["evidence"]["result"]["diagnostics"]
                        .get("stdout")
                        .is_none()
                );
            }
            let Some(cursor) = page["nextCursor"].as_object() else {
                break;
            };
            path = format!(
                "/api/v3/operations?limit=1&descending={descending}&after={}&afterKind={}",
                cursor["id"].as_str().unwrap(),
                cursor["kind"].as_str().unwrap()
            );
            ensure!(kinds.len() <= 2, "cursor repeated: {kinds:?}");
        }
        let expected = if descending {
            vec!["command", "action_run"]
        } else {
            vec!["action_run", "command"]
        };
        ensure!(kinds == expected, "mixed cursor lost an owner: {kinds:?}");
    }
    identity::set_grants(case_tenant(), &fixture.author_id, fixture.grants.clone()).await?;
    let (status, page) = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v3/operations?limit=1",
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK
            && page["statistics"]["total"] == 1
            && page["statistics"]["commands"] == 0
            && page["items"][0]["kind"] == "action_run"
            && page["nextCursor"].is_null(),
        "hidden command affected count or cursor: {page}"
    );
    let hidden = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("/api/v3/operations?device={}", case_device()),
            None,
        )
        .await?;
    ensure!(
        hidden.0 == StatusCode::OK
            && hidden.1["statistics"]["total"] == 0
            && hidden.1["items"] == json!([])
    );
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn native_status_requires_the_reported_command_semantics() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 700, None).await?;
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
    for (index, code) in [201, 204, 214, 215, 217, 218, 516].into_iter().enumerate() {
        client.operation = Uuid::new_v4();
        client.accept_approved().await?;
        client.publish_operation(client.operation).await?;
        let exchange = begin(
            &peer.mutual,
            &peer.url,
            &peer.message,
            &peer.ack,
            701 + index as u32,
            Some("./DevInfo/Mod"),
        )
        .await?;
        let native_id = exchange.gets.last().unwrap().0;
        let mut packet = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
        for command in &mut packet.commands {
            if let s::Command::Status(status) = command
                && status.command_ref == native_id
            {
                status.code = code;
            }
        }
        if code != 214 {
            packet.commands.retain(|command| !matches!(command,s::Command::Results(r) if r.command_ref == Some(native_id)));
        }
        ensure!(
            post(&peer.mutual, &peer.url, &packet).await?.status() == StatusCode::OK,
            "code {code}"
        );
        let actual = operation(&mut client).await?;
        let expected = match code {
            204 | 214 => "applied",
            215 => "rejected",
            _ => "published",
        };
        ensure!(actual["commandStatus"] == expected, "code {code}: {actual}");
        ensure!(actual["observation"]["effect"] == "waiting");
        if code == 204 {
            ensure!(actual["observation"]["receipts"][0]["value"].is_null());
        }
        if expected == "published" {
            let cancelled = client
                .call(
                    Method::POST,
                    &format!("/{}/cancel", client.operation),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":actual["revision"]})),
                )
                .await?;
            ensure!(
                cancelled.0 == StatusCode::OK,
                "cancel unresolved receipt: {cancelled:?}"
            );
        }
    }
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn atomic_rollback_replaces_tentative_child_success_with_fresh_authority()
-> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 800, None).await?;
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
    let rule = Uuid::new_v4();
    let mut revision = 0;
    for (index, revoke) in [false, true].into_iter().enumerate() {
        let grants = |enabled: bool| {
            let mut operations = vec!["operation_read", "operation_cancel"];
            if enabled {
                operations.push("configuration_write");
            }
            operations
                .into_iter()
                .map(|operation| json!({"operation":operation,"scope":{"kind":"all_devices"}}))
                .collect::<Vec<_>>()
        };
        let update = |enabled: bool, revision: u64| json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants(enabled)}});
        let authorized = client
            .browser
            .call(
                &client.router,
                Method::PUT,
                &format!("/api/v1/authorization/rules/{rule}"),
                Some(update(true, revision)),
            )
            .await?;
        ensure!(
            authorized.0 == StatusCode::OK,
            "atomic grants: {authorized:?}"
        );
        revision += 1;
        client.operation = Uuid::new_v4();
        let nodes = [
            "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana",
            "./Device/Vendor/MSFT/Policy/Config/Privacy/LetAppsAccessCamera",
        ];
        let operations:Vec<_> = nodes.iter().map(|node|json!({"kind":"node","node":node,"instance":[],"operation":"replace","value":{"type":"integer","value":"1"}})).collect();
        let accepted = client.call(Method::POST,"",Some(json!({"operationId":client.operation,"inputVersion":"1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"atomic","operations":operations}}},"deadline":client.app.clock.unix_seconds()?+300}))).await?;
        ensure!(
            accepted.0 == StatusCode::ACCEPTED,
            "atomic create: {accepted:?}"
        );
        ensure!(
            client
                .call(
                    Method::POST,
                    &format!("/{}/approve", client.operation),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
                )
                .await?
                .0
                == StatusCode::OK
        );
        client.publish_operation(client.operation).await?;
        let exchange = begin(
            &peer.mutual,
            &peer.url,
            &peer.message,
            &peer.ack,
            801 + index as u32,
            None,
        )
        .await?;
        let (parent, children) = exchange
            .response
            .commands
            .iter()
            .find_map(|command| match command {
                s::Command::Atomic { id, commands } => Some((*id, commands)),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("atomic group missing"))?;
        let ids: Vec<_> = children.iter().map(s::Command::id).collect();
        ensure!(ids.len() == 2);
        let push_status =
            |packet: &mut s::Message, command_ref: u32, command: s::CommandName, code: u16| {
                packet.commands.push(s::Command::Status(s::Status {
                    id: packet.commands.len() as u32 + 1,
                    message_ref: 2,
                    command_ref,
                    command,
                    target_refs: vec![],
                    source_refs: vec![],
                    code,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }));
            };
        let mut initial = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
        for id in &ids {
            push_status(&mut initial, *id, s::CommandName::Replace, 200);
        }
        ensure!(post(&peer.mutual, &peer.url, &initial).await?.status() == StatusCode::OK);
        ensure!(
            operation(&mut client).await?["commandStatus"] == "published",
            "Atomic children completed before their parent"
        );
        if revoke {
            let revoked = client
                .browser
                .call(
                    &client.router,
                    Method::PUT,
                    &format!("/api/v1/authorization/rules/{rule}"),
                    Some(update(false, revision)),
                )
                .await?;
            ensure!(revoked.0 == StatusCode::OK);
            revision += 1;
        }
        let mut rollback = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
        rollback.header.message_id = 4;
        rollback.commands.truncate(1);
        if let s::Command::Status(header) = &mut rollback.commands[0] {
            header.message_ref = 3;
        }
        push_status(&mut rollback, parent, s::CommandName::Atomic, 507);
        for id in &ids {
            push_status(&mut rollback, *id, s::CommandName::Replace, 216);
        }
        ensure!(post(&peer.mutual, &peer.url, &rollback).await?.status() == StatusCode::OK);
        let actual = operation(&mut client).await?;
        ensure!(
            actual["commandStatus"] == if revoke { "published" } else { "rejected" },
            "Atomic rollback: {actual}"
        );
        for receipt in actual["observation"]["receipts"].as_array().unwrap() {
            ensure!(
                receipt["accepted"] == !revoke,
                "rollback inherited earlier authority: {actual}"
            );
        }
        ensure!(actual["observation"]["effect"] == "waiting");
        if revoke {
            let cancelled = client
                .call(
                    Method::POST,
                    &format!("/{}/cancel", client.operation),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":actual["revision"]})),
                )
                .await?;
            ensure!(cancelled.0 == StatusCode::OK);
        }
    }
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn update_security_and_control_share_native_dispatch_but_not_effect_success()
-> anyhow::Result<()> {
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
    let grants = crate::test_support::identity::device_grants(
        None,
        &[
            "operation_read",
            "operation_cancel",
            "device_update",
            "security_operate",
            "device_control",
        ],
    )?;
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    let requests = [
        (
            "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate",
            "replace",
            json!({"type":"integer","value":"1"}),
        ),
        (
            "./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring",
            "replace",
            json!({"type":"integer","value":"1"}),
        ),
        ("./Device/Vendor/MSFT/Reboot/RebootNow", "exec", Value::Null),
    ];
    let mut ids = Vec::new();
    for (uri, verb, value) in &requests {
        let id = Uuid::new_v4();
        let body = json!({"operationId":id,"inputVersion":"family-v1","target":{"kind":"device"},"deadline":client.app.clock.unix_seconds()?+300,"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":uri,"instance":[],"operation":verb,"value":value}}}});
        let accepted = client.call(Method::POST, "", Some(body)).await?;
        ensure!(
            accepted.0 == StatusCode::ACCEPTED,
            "family {uri}: {accepted:?}"
        );
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
    let mut readbacks = std::collections::BTreeSet::new();
    // The existing exchange deliberately dispatches one operation per response.
    // Follow its bounded sequence rather than weakening protocol scheduling.
    for _ in 0..6 {
        let gets = response
            .commands
            .iter()
            .filter_map(|c| {
                if let s::Command::Get { id, items, .. } = c {
                    Some((*id, items[0].target.clone().unwrap()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut packet = report(&exchange.first, &gets, "10.0.26100.0", 200);
        packet.header.message_id = response.header.message_id + 1;
        for command in &mut packet.commands {
            match command {
                s::Command::Status(status) => status.message_ref = response.header.message_id,
                s::Command::Results(result) => {
                    result.message_ref = Some(response.header.message_id);
                    for item in &mut result.items {
                        if requests[..2]
                            .iter()
                            .any(|(uri, _, _)| item.source.as_deref() == Some(*uri))
                        {
                            readbacks.insert(item.source.clone().unwrap());
                            item.data = Some(Secret("1".into()));
                        }
                    }
                }
                _ => {}
            }
        }
        let mut mutations = 0;
        for command in &response.commands {
            let (kind, items) = match command {
                s::Command::Replace { items, .. } => (s::CommandName::Replace, items),
                s::Command::Exec { items, .. } => (s::CommandName::Exec, items),
                _ => continue,
            };
            seen.insert(items[0].target.clone().unwrap());
            mutations += 1;
            packet.commands.push(s::Command::Status(s::Status {
                id: 100 + mutations,
                message_ref: response.header.message_id,
                command_ref: command.id(),
                command: kind,
                target_refs: vec![items[0].target.clone().unwrap()],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }));
        }
        let reply = post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(reply.status() == StatusCode::OK);
        response = s::decode(
            &reply.bytes().await?,
            &rss_mdm_windows_mdm::CodecLimits::default(),
        )?;
        if seen.len() == 3 && readbacks.len() == 2 {
            break;
        }
    }
    ensure!(
        seen == requests
            .iter()
            .map(|(uri, _, _)| (*uri).to_owned())
            .collect(),
        "native families missing: {seen:?}"
    );
    ensure!(
        readbacks.len() == 2,
        "readback did not cover the queryable mutations: {readbacks:?}"
    );
    for (i, id) in ids.iter().enumerate() {
        let read = client.call(Method::GET, &format!("/{id}"), None).await?;
        ensure!(read.0 == StatusCode::OK);
        if i < 2 {
            ensure!(
                read.1["commandStatus"] == "applied"
                    && read.1["observation"]["effect"] == "verified",
                "family effect {read:?}"
            );
        } else {
            ensure!(
                read.1["commandStatus"] == "received"
                    && read.1["observation"]["effect"] == "unverifiable",
                "reboot ACK became effect: {read:?}"
            );
        }
        if i == 1 {
            ensure!(
                read.1["observation"]["receipts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| r["value"].is_null()),
                "sensitive native values escaped redaction"
            );
        }
    }
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn native_tree_that_cannot_fit_header_fails_without_poisoning_checkin() -> anyhow::Result<()>
{
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 890, None).await?;
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
    client.set_authorized(true).await?;
    let nodes=(0..255).map(|_|json!({"kind":"node","node":"./DevInfo/Mod","instance":[],"operation":"get","value":null})).collect::<Vec<_>>();
    let body = json!({"operationId":client.operation,"inputVersion":"1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"sequence","operations":nodes}}},"deadline":client.app.clock.unix_seconds()?+300});
    let accepted = client.call(Method::POST, "", Some(body)).await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "boundary tree acceptance: {accepted:?}"
    );
    client.publish_operation(client.operation).await?;
    let exchange = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 891, None).await?;
    ensure!(
        !exchange
            .first
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Sequence { .. })),
        "oversized group escaped admission"
    );
    let actual = operation(&mut client).await?;
    ensure!(
        actual["commandStatus"] == "cancelled"
            && actual["dispatchFailure"]["reason"] == "native_response_budget_exceeded",
        "oversized tree poisoned management instead of failing: {actual}"
    );
    ensure!(
        post(
            &peer.mutual,
            &peer.url,
            &report(&exchange.first, &exchange.gets, "10.0.26100.0", 200)
        )
        .await?
        .status()
            == StatusCode::OK
    );
    host.close().await?;
    Ok(())
}
