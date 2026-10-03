#![allow(
    clippy::cognitive_complexity,
    reason = "real protocol ordering, revocation and recovery assertions"
)]
use crate::execution::test_support::native::{self, begin, post, report};
use crate::execution::test_support::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
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
                more_data: false,
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
    let persisted: Vec<Vec<u8>> = sqlx::query_scalar("SELECT request FROM mdm_commands.attempts WHERE tenant_id=$1::uuid UNION ALL SELECT request FROM mdm_commands.capability_queries WHERE tenant_id=$1::uuid UNION ALL SELECT response FROM mdm_access.management_messages WHERE tenant_id=$1::uuid UNION ALL SELECT request FROM mdm_access.management_messages WHERE tenant_id=$1::uuid UNION ALL SELECT request FROM mdm_windows.collections WHERE tenant_id=$1::uuid").bind(case_tenant()).fetch_all(&mut pg).await?;
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
            let detail_path = item["detailUrl"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing execution detail URL"))?;
            let detail = fixture
                .author
                .call(&fixture.router, Method::GET, detail_path, None)
                .await?;
            ensure!(
                detail.0 == StatusCode::OK,
                "unusable execution detail URL {detail_path}: {:?}",
                detail
            );
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

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn native_response_package_waits_for_final_and_outlives_eight_messages() -> anyhow::Result<()>
{
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 980, None).await?;
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
        981,
        Some("./DevInfo/Mod"),
    )
    .await?;
    let mut packet = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
    packet.final_message = false;
    for message in 3..=14 {
        packet.header.message_id = message;
        let response = post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "native package message {message}: {}",
            response.status()
        );
        let bytes = response.bytes().await?;
        let response = s::decode(&bytes, &rss_mdm_windows_mdm::CodecLimits::default())?;
        if message == 14 {
            ensure!(response.final_message);
            break;
        }
        ensure!(
            !response.final_message
                && matches!(&response.commands[0], s::Command::Status(v) if v.command == s::CommandName::SyncHdr)
                && response.commands.iter().all(|c| matches!(
                    c,
                    s::Command::Status(_)
                        | s::Command::Alert {
                            alert: s::Alert::MoreMessages,
                            ..
                        }
                )),
            "interim package response contained new work: {response:?}"
        );
        let alert = response
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Alert {
                    id,
                    alert: s::Alert::MoreMessages,
                } => Some(*id),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("missing MoreMessages control"))?;
        ensure!(String::from_utf8_lossy(&bytes).contains("1222"));
        ensure!(
            operation(&mut client).await?["commandStatus"] == "published",
            "incomplete native package settled execution"
        );
        ensure!(
            post(&peer.mutual, &peer.url, &packet)
                .await?
                .bytes()
                .await?
                == bytes,
            "interim replay changed response"
        );
        packet.commands = vec![
            s::Command::Status(s::Status {
                id: 1,
                message_ref: message,
                command_ref: 0,
                command: s::CommandName::SyncHdr,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
            s::Command::Status(s::Status {
                id: 2,
                message_ref: message,
                command_ref: alert,
                command: s::CommandName::Alert,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
        ];
        packet.final_message = message == 13;
    }
    ensure!(operation(&mut client).await?["commandStatus"] == "applied");
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn native_large_results_reassemble_once_and_size_errors_keep_result_unknown()
-> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 970, None).await?;
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
    let data = "native-object-".repeat(6000);
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    for (session, wrong_size, cancel) in
        [(971, false, false), (972, true, false), (973, false, true)]
    {
        client.operation = Uuid::new_v4();
        client.accept_approved().await?;
        client.publish_operation(client.operation).await?;
        let exchange = begin(
            &peer.mutual,
            &peer.url,
            &peer.message,
            &peer.ack,
            session,
            Some("./DevInfo/Mod"),
        )
        .await?;
        let native = exchange.gets.last().unwrap().0;
        let mut first = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
        first.final_message = false;
        for command in &mut first.commands {
            if let s::Command::Results(result) = command
                && result.command_ref == Some(native)
            {
                result.items[0].data = Some(Secret(data[..30001].into()));
                result.items[0].more_data = true;
                result.items[0].meta = Some(s::Meta {
                    format: Some("chr".into()),
                    size: Some(data.len() as u32 + u32::from(wrong_size)),
                    ..s::Meta::default()
                });
            }
        }
        let mut blocker =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let mut observer =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let registration: Uuid = sqlx::query_scalar(
            "SELECT registration FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(case_tenant())
        .bind(client.operation)
        .fetch_one(&mut observer)
        .await?;
        let count_management = |records: Vec<crate::audit_test_support::Record>| {
            records
                .iter()
                .filter(|r| {
                    r.source() == "mdm.request"
                        && r.action() == "windows_management"
                        && r.target() == case_device()
                })
                .fold((0, 0), |(success, replay), r| {
                    (
                        success + usize::from(r.result() == "success"),
                        replay + usize::from(r.result() == "replay"),
                    )
                })
        };
        let audit_before = count_management(crate::audit_test_support::read(&mut observer).await?);
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut blocker)
            .await?;
        sqlx::query("BEGIN").execute(&mut blocker).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2351))")
            .bind(format!("{}:{registration}", case_tenant()))
            .execute(&mut blocker)
            .await?;
        let barrier = tokio::sync::Barrier::new(3);
        let request = || async {
            barrier.wait().await;
            post(&peer.mutual, &peer.url, &first).await
        };
        let release = async {
            barrier.wait().await;
            let overlap = tokio::time::timeout(Duration::from_secs(6),async {
                loop {
                    let blocked:i64 = sqlx::query_scalar("WITH RECURSIVE waiting(pid) AS (SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))) SELECT count(*) FROM waiting")
                        .bind(pid).fetch_one(&mut observer).await?;
                    if blocked>=2 { break Ok::<_,sqlx::Error>(()); }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await;
            sqlx::query("ROLLBACK").execute(&mut blocker).await?;
            overlap??;
            Ok::<_, anyhow::Error>(())
        };
        let (left, right, overlap) = tokio::join!(request(), request(), release);
        overlap?;
        let left = left?;
        let right = right?;
        ensure!(
            left.status() == StatusCode::OK && right.status() == StatusCode::OK,
            "competing fragment request failed"
        );
        let bytes = left.bytes().await?;
        ensure!(
            right.bytes().await? == bytes,
            "first-write competition changed response"
        );
        let persisted:i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2 AND session_id=$3 AND message_id=3")
            .bind(case_tenant()).bind(registration).bind(session.to_string()).fetch_one(&mut observer).await?;
        let attempts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2",
        )
        .bind(case_tenant())
        .bind(client.operation)
        .fetch_one(&mut observer)
        .await?;
        ensure!(
            persisted == 1 && attempts == 1,
            "competing fragment duplicated transcript or logical attempt"
        );
        let audit_after = count_management(crate::audit_test_support::read(&mut observer).await?);
        ensure!(
            audit_after == (audit_before.0 + 1, audit_before.1 + 1),
            "competing fragment audit facts: before={audit_before:?}, after={audit_after:?}"
        );
        drop(blocker);
        drop(observer);
        let ack = s::decode(&bytes, &rss_mdm_windows_mdm::CodecLimits::default())?;
        ensure!(!ack.final_message && ack.commands.iter().any(|c|matches!(c,s::Command::Status(s) if s.command==s::CommandName::Results && s.code==213)));
        ensure!(
            post(&peer.mutual, &peer.url, &first).await?.bytes().await? == bytes,
            "fragment replay changed response"
        );
        let operation_id = client.operation;
        let browser = client.browser.clone();
        drop(client);
        host = host.restart().await?;
        client = Client::with_browser(host.browser.clone(), host.app.clone(), browser);
        client.operation = operation_id;
        let buffered = operation(&mut client).await?;
        ensure!(
            buffered["commandStatus"] == "published"
                && buffered["observation"]["receipts"][0]["value"].is_null()
                && buffered["observation"]["receipts"][0]["resultAccepted"].is_null(),
            "partial object became a result: {buffered}"
        );
        if cancel {
            let cancelled = client
                .call(
                    Method::POST,
                    &format!("/{}/cancel", client.operation),
                    Some(
                        json!({"requestId":Uuid::new_v4(),"expectedRevision":buffered["revision"]}),
                    ),
                )
                .await?;
            ensure!(
                cancelled.0 == StatusCode::OK,
                "cancel chunked result: {cancelled:?}"
            );
        }
        let alert = ack
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Alert { id, .. } => Some(*id),
                _ => None,
            })
            .unwrap();
        let mut last = task_packet(&exchange, 4, None, Some(&data[30001..]));
        last.commands.insert(
            1,
            s::Command::Status(s::Status {
                id: 2,
                message_ref: 3,
                command_ref: alert,
                command: s::CommandName::Alert,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }),
        );
        let response = post(&peer.mutual, &peer.url, &last).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "last large result: {}",
            response.status()
        );
        let response = s::decode(
            &response.bytes().await?,
            &rss_mdm_windows_mdm::CodecLimits::default(),
        )?;
        let value = operation(&mut client).await?;
        ensure!(
            post(&peer.mutual, &peer.url, &first).await?.bytes().await? == bytes,
            "past fragment replay changed response after completion"
        );
        if cancel {
            ensure!(
                !response.final_message
                    && response.commands.iter().any(|c| matches!(
                        c,
                        s::Command::Alert {
                            alert: s::Alert::SessionAbort,
                            ..
                        }
                    ))
            );
            ensure!(
                value["commandStatus"] == "cancelled"
                    && value["observation"]["receipts"][0]["value"].is_null(),
                "cancelled continuation advanced operation: {value}"
            );
        } else if wrong_size {
            ensure!(
                !response.final_message
                    && response
                        .commands
                        .iter()
                        .any(|c| matches!(c,s::Command::Status(s) if s.code==424))
            );
            ensure!(
                value["commandStatus"] != "applied"
                    && value["observation"]["receipts"][0]["value"].is_null()
            );
            let cancelled = client
                .call(
                    Method::POST,
                    &format!("/{}/cancel", client.operation),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":value["revision"]})),
                )
                .await?;
            ensure!(cancelled.0 == StatusCode::OK);
        } else {
            ensure!(
                value["commandStatus"] == "applied"
                    && value["observation"]["receipts"][0]["value"] == data
                    && value["observation"]["receipts"][0]["resultAccepted"] == true
            );
        }
    }
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn native_outgoing_chunks_wait_for_buffer_receipts_and_never_accept_early_success()
-> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 980, None).await?;
    ensure!(
        post(
            &peer.mutual,
            &peer.url,
            &report(&warm.first, &warm.gets, "10.0.22621.521", 200)
        )
        .await?
        .status()
            == StatusCode::OK
    );
    let data = format!(
        "<AssessmentsRoot><Assessments><Assessment><TestName>{}</TestName><TestUri>https://example.test</TestUri></Assessment></Assessments></AssessmentsRoot>",
        "chunk-value-".repeat(1200)
    );
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    for (session, early) in [(981, false), (982, true)] {
        client.operation = Uuid::new_v4();
        let grants: Vec<_> = ["configuration_write", "operation_read", "operation_cancel"]
            .iter()
            .map(|p| json!({"operation":p,"scope":{"kind":"device","id":case_device()}}))
            .collect();
        let grant=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
        ensure!(grant.0 == StatusCode::OK, "outgoing grant: {grant:?}");
        let create=client.call(Method::POST,"",Some(json!({"operationId":client.operation,"inputVersion":"1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Vendor/MSFT/SecureAssessment/Assessments","instance":[],"operation":"replace","value":{"type":"text","value":data}}}},"deadline":client.app.clock.unix_seconds()?+300}))).await?;
        ensure!(
            create.0 == StatusCode::ACCEPTED,
            "outgoing create: {create:?}"
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
        let mut initial = peer.message.clone();
        initial
            .header
            .meta
            .get_or_insert_with(s::Meta::default)
            .max_message_size = Some(4096);
        let exchange = begin(&peer.mutual, &peer.url, &initial, &peer.ack, session, None).await?;
        let mut sent = exchange.response.clone();
        let dispatched = operation(&mut client).await?;
        ensure!(
            sent.commands
                .iter()
                .any(|c| matches!(c, s::Command::Replace { .. })),
            "outgoing operation not emitted: {dispatched}"
        );
        let mut joined = String::new();
        let mut frames = 0;
        loop {
            ensure!(s::encode(&sent, &rss_mdm_windows_mdm::CodecLimits::default())?.len() <= 4096);
            let (id, item) = sent
                .commands
                .iter()
                .find_map(|c| match c {
                    s::Command::Replace { id, items, .. } => Some((*id, &items[0])),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("missing outgoing chunk"))?;
            frames += 1;
            ensure!(frames <= 16);
            ensure!(
                item.meta.as_ref().and_then(|m| m.size)
                    == (frames == 1).then_some(data.len() as u32)
            );
            joined.push_str(&item.data.as_ref().unwrap().0);
            let more = item.more_data;
            if more {
                ensure!(!sent.final_message);
            }
            let before = operation(&mut client).await?;
            let ranges = before["observation"]["receipts"][0]["frames"]
                .as_array()
                .unwrap();
            ensure!(
                ranges.len() == frames && ranges.last().unwrap()["endByte"] == joined.len(),
                "missing persisted native range: {before}"
            );
            ensure!(
                before["commandStatus"] == "published",
                "fragment became complete: {before}"
            );
            let mut packet = report(&exchange.first, &exchange.gets, "10.0.22621.521", 200);
            packet.header.message_id = sent.header.message_id + 1;
            if frames > 1 {
                packet.commands.truncate(1);
            }
            if let s::Command::Status(header) = &mut packet.commands[0] {
                header.message_ref = sent.header.message_id;
            }
            packet.final_message = !more || early;
            packet.commands.push(s::Command::Status(s::Status {
                id: packet.commands.iter().map(s::Command::id).max().unwrap() + 1,
                message_ref: sent.header.message_id,
                command_ref: id,
                command: s::CommandName::Replace,
                target_refs: vec![item.target.clone().unwrap()],
                source_refs: vec![],
                code: if more && !early { 213 } else { 200 },
                items: vec![],
                challenge: None,
                credential: None,
            }));
            let notification = packet.commands.iter().map(s::Command::id).max().unwrap() + 1;
            packet.commands.push(s::Command::Alert {
                id: notification,
                alert: s::Alert::Generic {
                    items: vec![s::Item {
                        source: Some("./Vendor/MSFT/HealthAttestation/VerifyHealth".into()),
                        target: None,
                        meta: Some(s::Meta {
                            format: Some("int".into()),
                            media_type: Some("com.microsoft.mdm:HealthAttestation.Result".into()),
                            ..Default::default()
                        }),
                        data: Some(Secret("3".into())),
                        more_data: false,
                    }],
                },
            });
            let response = post(&peer.mutual, &peer.url, &packet).await?;
            ensure!(
                response.status() == StatusCode::OK,
                "outgoing response {}",
                response.status()
            );
            let bytes = response.bytes().await?;
            ensure!(
                post(&peer.mutual, &peer.url, &packet)
                    .await?
                    .bytes()
                    .await?
                    == bytes,
                "chunk replay changed response"
            );
            sent = s::decode(&bytes, &rss_mdm_windows_mdm::CodecLimits::default())?;
            ensure!(sent.commands.iter().any(|c|matches!(c,s::Command::Status(status) if status.command==s::CommandName::Alert && status.command_ref==notification && status.code==200)),"notification ACK was lost during outgoing transfer");
            if frames == 1 && !early {
                let operation_id = client.operation;
                let browser = client.browser.clone();
                drop(client);
                host = host.restart().await?;
                client = Client::with_browser(host.browser.clone(), host.app.clone(), browser);
                client.operation = operation_id;
                ensure!(
                    post(&peer.mutual, &peer.url, &packet)
                        .await?
                        .bytes()
                        .await?
                        == bytes,
                    "outgoing frame replay changed after service reconstruction"
                );
            }
            let after = operation(&mut client).await?;
            if early {
                ensure!(
                    after["commandStatus"] == "published",
                    "early success completed object: {after}"
                );
                ensure!(sent.commands.iter().any(|c| matches!(
                    c,
                    s::Command::Alert {
                        alert: s::Alert::SessionAbort,
                        ..
                    }
                )));
                ensure!(
                    sent.commands
                        .iter()
                        .all(|c| !matches!(c, s::Command::Replace { .. } | s::Command::Get { .. }))
                );
                break;
            }
            if !more {
                ensure!(frames >= 3 && joined == data);
                ensure!(
                    after["commandStatus"] == "received",
                    "full receipt not separated from effect: {after}"
                );
                break;
            }
            ensure!(
                sent.commands
                    .iter()
                    .all(|c| !matches!(c, s::Command::Get { .. })),
                "unrelated new work during transfer"
            );
        }
        let value = operation(&mut client).await?;
        ensure!(
            client
                .call(
                    Method::POST,
                    &format!("/{}/cancel", client.operation),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":value["revision"]}))
                )
                .await?
                .0
                == StatusCode::OK
        );
    }
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn management_address_effect_requires_a_new_session_on_the_actual_tls_endpoint()
-> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::with_management_addresses().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let alternate = format!(
        "{}/ManagementServer/MDM.svc",
        host.app.windows()?.channel.additional_management_origins[0]
    );
    let warm = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1800,
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
    let grants: Vec<_> = ["enrollment", "operation_read", "operation_cancel"]
        .into_iter()
        .map(|p| json!({"operation":p,"scope":{"kind":"device","id":case_device()}}))
        .collect();
    let grant=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
    ensure!(grant.0 == StatusCode::OK);
    let node = "./Device/Vendor/MSFT/DMClient/Provider/*/ManagementServerAddressList";
    let uri = "./Device/Vendor/MSFT/DMClient/Provider/RSS-MDM/ManagementServerAddressList";
    let create=client.call(Method::POST,"",Some(json!({"operationId":client.operation,"inputVersion":"1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":node,"instance":["RSS-MDM"],"operation":"replace","value":{"type":"text","value":alternate}}}},"deadline":client.app.clock.unix_seconds()?+300}))).await?;
    ensure!(
        create.0 == StatusCode::ACCEPTED,
        "address create {create:?}"
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
        1801,
        None,
    )
    .await?;
    let id = exchange
        .response
        .commands
        .iter()
        .find_map(|c| match c {
            s::Command::Replace { id, items, .. }
                if items.iter().any(|i| i.target.as_deref() == Some(uri)) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("missing address change"))?;
    let mut ack = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
    ack.commands.push(s::Command::Status(s::Status {
        id: 100,
        message_ref: exchange.response.header.message_id,
        command_ref: id,
        command: s::CommandName::Replace,
        target_refs: vec![uri.into()],
        source_refs: vec![],
        code: 200,
        items: vec![],
        challenge: None,
        credential: None,
    }));
    ensure!(post(&peer.mutual, &peer.url, &ack).await?.status() == StatusCode::OK);
    ensure!(operation(&mut client).await?["commandStatus"] != "applied");
    let mut next = peer.message.clone();
    next.header.target = alternate.clone();
    next.header.session_id = 1802;
    ensure!(
        post(&peer.mutual, &peer.url, &next).await?.status() == StatusCode::FORBIDDEN,
        "claimed target was accepted on old endpoint"
    );
    ensure!(
        crate::windows::test_support::absolute_form_post(&host, &peer, &alternate, &next).await?
            == 400,
        "absolute-form authority mismatch was accepted"
    );
    let mut peer_ack = peer.ack.clone();
    peer_ack.header.target = alternate.clone();
    let observed = begin(&peer.mutual, &alternate, &next, &peer_ack, 1802, Some(uri)).await?;
    let mut packet = report(&observed.first, &observed.gets, "10.0.26100.0", 200);
    for command in &mut packet.commands {
        if let s::Command::Results(result) = command {
            for item in &mut result.items {
                if item.source.as_deref() == Some(uri) {
                    item.data = Some(Secret(alternate.clone()));
                }
            }
        }
    }
    ensure!(post(&peer.mutual, &alternate, &packet).await?.status() == StatusCode::OK);
    let result = operation(&mut client).await?;
    ensure!(result["commandStatus"] == "applied", "{result}");
    host.close().await
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn dmacc_prepare_proves_provider_before_any_account_operation() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1700,
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
    for (session, provider) in [(1701, "other-provider"), (1702, "RSS-MDM")] {
        let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
        let grants: Vec<_> = ["enrollment", "operation_read", "operation_cancel"]
            .into_iter()
            .map(|p| json!({"operation":p,"scope":{"kind":"device","id":case_device()}}))
            .collect();
        let grant=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
        ensure!(grant.0 == StatusCode::OK, "DMAcc grant {grant:?}");
        let create=client.call(Method::POST,"",Some(json!({"operationId":client.operation,"inputVersion":"1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./SyncML/DMAcc/*/Name","instance":["native-account"],"operation":"get","value":null}}},"deadline":client.app.clock.unix_seconds()?+300}))).await?;
        ensure!(create.0 == StatusCode::ACCEPTED, "DMAcc create {create:?}");
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
            session,
            Some("./SyncML/DMAcc/native-account/ServerID"),
        )
        .await?;
        ensure!(!exchange.gets.iter().any(|(_, uri)| uri.ends_with("/Name")));
        let mut packet = report(&exchange.first, &exchange.gets, "10.0.26100.0", 200);
        for command in &mut packet.commands {
            if let s::Command::Results(result) = command {
                for item in &mut result.items {
                    if item.source.as_deref() == Some("./SyncML/DMAcc/native-account/ServerID") {
                        item.data = Some(rss_mdm_windows_mdm::Secret(provider.into()));
                    }
                }
            }
        }
        let response = post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(response.status() == StatusCode::OK);
        let wire = response.bytes().await?;
        ensure!(
            post(&peer.mutual, &peer.url, &packet)
                .await?
                .bytes()
                .await?
                == wire
        );
        let response = s::decode(&wire, &rss_mdm_windows_mdm::CodecLimits::default())?;
        let name=response.commands.iter().any(|c|matches!(c,s::Command::Get{items,..} if items.iter().any(|i|i.target.as_deref()==Some("./SyncML/DMAcc/native-account/Name"))));
        ensure!(name == (provider == "RSS-MDM"));
        let read = client
            .call(Method::GET, &format!("/{}", client.operation), None)
            .await?;
        if provider != "RSS-MDM" {
            ensure!(
                read.1["dispatchFailure"]["reason"] == "enrollment_account_scope",
                "{read:?}"
            );
        } else {
            ensure!(read.1["commandStatus"] != "applied");
        }
        if provider == "RSS-MDM" {
            client
                .call(
                    Method::POST,
                    &format!("/{}/cancel", client.operation),
                    Some(json!({"requestId":Uuid::new_v4()})),
                )
                .await?;
        }
    }
    host.close().await
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn full_user_context_is_exact_and_login_availability_is_session_local() -> anyhow::Result<()>
{
    use rss_mdm_registration_service::enrollment::WindowsProfile;
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer_profile(WindowsProfile::Full).await?;
    let user = peer.intent.registration.to_string();
    let credential = host.app.windows()?.channel.ca.verify(
        &[host
            .app
            .windows()?
            .channel
            .ca
            .sign(&host.app.windows()?.channel.ca.restore_intent(
                &peer.intent.tbs,
                &rss_mdm_certificate::windows::Csr::verify(&peer.intent.csr)?,
                peer.intent.registration,
            )?)?
            .into()],
        crate::windows::test_support::now(),
    )?;
    let principal = host
        .app
        .devices
        .management_principal(
            &crate::device::ChannelMount::new(
                host.app.identity.tenant,
                rss_mdm_inventory::ReportSource::MdmWindows,
                rss_mdm_registration_service::Purpose::Primary,
            )
            .credential(credential.fingerprint()),
        )
        .await?;
    ensure!(principal.user_context() == Some(peer.intent.registration));
    let config: rss_mdm_execution_service::configuration::Configuration = serde_json::from_value(
        json!({"target":{"kind":"user","userId":user},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./User/Vendor/MSFT/Policy/Config/Experience/AllowThirdPartySuggestionsInWindowsSpotlight","instance":[],"operation":"replace","value":{"type":"integer","value":"1"}}}},"remove":null}),
    )?;
    config.validate()?;
    let key = rss_mdm_native_protection::Protector::new(&[33; 32])?;
    let owner = rss_mdm_execution_service::configuration::Owner::Remote {
        operation: Uuid::new_v4(),
    };
    let protected = rss_mdm_execution_service::configuration::Protected::seal(
        &key,
        principal.tenant(),
        owner,
        &config,
    )?;
    ensure!(protected.open(&key, principal.tenant(), owner)?.target == config.target);

    let mut initial = peer.message.clone();
    initial.commands[0] = s::Command::Alert {
        id: initial.commands[0].id(),
        alert: s::Alert::LoginStatus {
            status: s::LoginStatus::User,
            explicit_format: false,
        },
    };
    let warm = begin(&peer.mutual, &peer.url, &initial, &peer.ack, 2100, None).await?;
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
    let uri =
        "./User/Vendor/MSFT/Policy/Config/Experience/AllowThirdPartySuggestionsInWindowsSpotlight";
    let request = |id, user: &str| json!({"operationId":id,"inputVersion":"user-context-v1","target":{"kind":"user","userId":user},"deadline":crate::windows::test_support::now()+300,"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":uri,"instance":[],"operation":"get","value":null}}}});
    let wrong = client
        .call(
            Method::POST,
            "",
            Some(request(Uuid::new_v4(), &Uuid::new_v4().to_string())),
        )
        .await?;
    ensure!(
        wrong.0 == StatusCode::FORBIDDEN,
        "wrong user admitted: {wrong:?}"
    );
    let id = client.operation;
    let accepted = client
        .call(Method::POST, "", Some(request(id, &user)))
        .await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "Full user admission: {accepted:?}"
    );
    client.publish_operation(id).await?;
    // A fresh device session lacks LoginStatus.User, even after an earlier user session.
    let absent = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        2101,
        None,
    )
    .await?;
    ensure!(!absent.gets.iter().any(|(_, u)| u == uri));
    let available = begin(
        &peer.mutual,
        &peer.url,
        &initial,
        &peer.ack,
        2102,
        Some(uri),
    )
    .await?;
    ensure!(available.gets.iter().any(|(_, u)| u == uri));
    let mut packet = report(&available.first, &available.gets, "10.0.26100.0", 200);
    for command in &mut packet.commands {
        if let s::Command::Results(result) = command {
            for item in &mut result.items {
                if item.source.as_deref() == Some(uri) {
                    item.data = Some(Secret("1".into()));
                }
            }
        }
    }
    ensure!(post(&peer.mutual, &peer.url, &packet).await?.status() == StatusCode::OK);
    let row = operation(&mut client).await?;
    ensure!(row["target"]["userId"] == user, "{row}");
    host.close().await
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn device_profile_never_grants_an_enrolled_user_scope() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        2199,
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
    client.set_authorized(true).await?;
    let body = json!({"operationId":client.operation,"inputVersion":"device-profile-v1","target":{"kind":"user","userId":peer.intent.registration},"deadline":crate::windows::test_support::now()+300,"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./User/Vendor/MSFT/Policy/Config/Experience/AllowThirdPartySuggestionsInWindowsSpotlight","instance":[],"operation":"get","value":null}}}});
    ensure!(client.call(Method::POST, "", Some(body)).await?.0 == StatusCode::FORBIDDEN);
    client.accept_approved().await?;
    client.publish_operation(client.operation).await?;
    let device = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        2200,
        Some("./DevInfo/Mod"),
    )
    .await?;
    ensure!(device.gets.iter().any(|(_, u)| u == "./DevInfo/Mod"));
    host.close().await
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn unsupported_config_refresh_does_not_abort_other_management_tasks() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let warm = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1910,
        None,
    )
    .await?;
    ensure!(
        post(
            &peer.mutual,
            &peer.url,
            &report(&warm.first, &warm.gets, "10.0.22631.1", 200)
        )
        .await?
        .status()
            == StatusCode::OK
    );
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    client.accept_approved().await?;
    client.publish_operation(client.operation).await?;
    // Reject the earlier candidate before the one valid command this response may dispatch.
    let unsupported = Uuid::from_u128(client.operation.as_u128() - 1);
    let input = json!({"operationId":unsupported,"inputVersion":"1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/DMClient/Provider/*/ConfigRefresh/Enabled","instance":[host.app.windows()?.channel.provider_id],"operation":"get","value":null}}},"deadline":host.app.clock.unix_seconds()?+300});
    ensure!(client.call(Method::POST, "", Some(input)).await?.0 == StatusCode::ACCEPTED);
    ensure!(
        client
            .call(
                Method::POST,
                &format!("/{unsupported}/approve"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    client.publish_operation(unsupported).await?;
    let exchange = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1911,
        Some("./DevInfo/Mod"),
    )
    .await?;
    ensure!(
        exchange
            .gets
            .iter()
            .all(|(_, uri)| !uri.contains("ConfigRefresh")),
        "unsupported task sent"
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let failure: Option<Value> = sqlx::query_scalar(
        "SELECT dispatch_failure FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(unsupported)
    .fetch_one(&mut pg)
    .await?;
    let admission: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('gatewayAccepted',o.gateway_accepted,'commandStatus',d.status,'authority',o.approval->>'kind','osVersion',c.os_version,'edition',c.edition) FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text LEFT JOIN mdm_commands.capabilities c ON c.tenant_id=o.tenant_id AND c.registration=o.registration AND c.generation=o.registration_generation WHERE o.tenant_id=$1::uuid AND o.id=$2",
    ).bind(case_tenant()).bind(unsupported).fetch_one(&mut pg).await?;
    ensure!(
        failure
            .as_ref()
            .is_some_and(|value| value["phase"] == "prepare"),
        "per-operation rejection absent: {failure:?}; admission={admission}"
    );
    let attempts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2",
    )
    .bind(case_tenant())
    .bind(client.operation)
    .fetch_one(&mut pg)
    .await?;
    ensure!(attempts > 0, "eligible ordinary task was blocked");
    pg.close().await?;
    host.close().await?;
    Ok(())
}
