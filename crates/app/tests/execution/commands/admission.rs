#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::execution::test_support::*;
use crate::execution::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::Connection;
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.admission"]
async fn authorized_idempotent_atomic_admission() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    client.admission_transactions().await?;
    host.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.admission"]
async fn minimum_role_scope_and_storage_admission() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    client.accept_approved().await?;
    client.admission_and_scope().await?;
    host.close().await?;
    Ok(())
}
impl Client {
    async fn admission_transactions(&mut self) -> anyhow::Result<()> {
        self.set_authorized(true).await?;
        let old_id = Uuid::new_v4();
        let old = json!({"operationId":old_id,"field":"model","expectedValue":"old-wire","deadline":self.app.clock.unix_seconds()?+300});
        let denied = self.call(Method::POST, "", Some(old)).await?;
        ensure!(denied.0 == StatusCode::BAD_REQUEST && denied.1["code"] == "malformed_request");
        let mut check =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let effects:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid),(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$1),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$2)").bind(old_id.to_string()).bind(format!("dispatch.{old_id}")).fetch_one(&mut check).await?;
        let audits = crate::audit_test_support::read(&mut check)
            .await?
            .iter()
            .filter(|r| {
                r.source() == "mdm.business"
                    && r.operation() == Some(old_id.to_string().as_str())
                    && r.result() == "success"
            })
            .count() as i64;
        let effects = (effects.0, effects.1, effects.2, audits);
        ensure!(effects == (0, 0, 0, 0));
        check.close().await?;
        let request = json!({"operationId":self.operation,"task":{"kind":"state_verify","field":"model","expectedValue":"Final-Model"},"deadline":self.app.clock.unix_seconds()?+300});
        let mut malformed = request.clone();
        malformed["unexpected"] = true.into();
        let rejected = self.call(Method::POST, "", Some(malformed)).await?;
        ensure!(
            rejected.0 == StatusCode::BAD_REQUEST && rejected.1["code"] == "malformed_request",
            "JSON contract: {rejected:?}"
        );
        // The complete transaction committed, but its ACK is withheld by the provider.
        #[cfg(feature = "integration")]
        {
            self.app.execution.inject_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            ensure!(
                self.call(Method::POST, "", Some(request.clone())).await?.0
                    == StatusCode::SERVICE_UNAVAILABLE
            );
        }
        let accepted = self.call(Method::POST, "", Some(request.clone())).await?;
        ensure!(
            accepted.0 == StatusCode::ACCEPTED,
            "acceptance {:?}",
            accepted
        );
        for _ in 0..100 {
            if self.app.timeline.catch_up().await? == 0 {
                break;
            }
        }
        let path = format!(
            "/api/v3/devices/{}/timeline?operationId={}",
            case_device(),
            self.operation
        );
        let (status, timeline) = self
            .browser
            .call(&self.router, Method::GET, &path, None)
            .await?;
        ensure!(status == StatusCode::OK);
        ensure!(
            timeline["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["source"] == "mdm.business"
                    && v["action"] == "command_accept"
                    && v["phase"] == "accepted"
                    && v["effect"] == "unknown"
                    && v["operationId"] == self.operation.to_string())
        );
        let replay = self.call(Method::POST, "", Some(request.clone())).await?;
        ensure!(replay == accepted);
        let mut conflict = request.clone();
        conflict["task"]["expectedValue"] = "other".into();
        ensure!(self.call(Method::POST, "", Some(conflict)).await?.0 == StatusCode::CONFLICT);
        #[cfg(feature = "integration")]
        self.atomic_failure(&request).await?;
        self.set_authorized(false).await?;
        let blocked = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(blocked.0 == StatusCode::OK && blocked.1["authorization"] == "blocked");
        ensure!(
            self.call(Method::POST, "", Some(request.clone())).await?.0 == StatusCode::FORBIDDEN
        );
        self.set_authorized(true).await?;
        let approval = json!({"requestId":Uuid::new_v4(),"expectedRevision":1});
        let approved = self
            .call(
                Method::POST,
                &format!("/{}/approve", self.operation),
                Some(approval.clone()),
            )
            .await?;
        ensure!(approved.0 == StatusCode::OK && approved.1["revision"] == 2);
        ensure!(
            self.call(
                Method::POST,
                &format!("/{}/approve", self.operation),
                Some(approval)
            )
            .await?
                == approved
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let concurrent = Uuid::new_v4();
        let mut body = request.clone();
        body["operationId"] = concurrent.to_string().into();
        let (mut one, mut two) = (self.browser.clone(), self.browser.clone());
        let path = format!(
            "/api/v2/devices/{DEVICE}/operations",
            DEVICE = case_device()
        );
        let (a, b) = tokio::join!(
            one.call(&self.router, Method::POST, &path, Some(body.clone())),
            two.call(&self.router, Method::POST, &path, Some(body))
        );
        let (a, b) = (a?, b?);
        ensure!(
            a == b && a.0 == StatusCode::ACCEPTED,
            "concurrent replay diverged"
        );
        ensure!(
            self.call(
                Method::POST,
                &format!("/{concurrent}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0 == StatusCode::OK
        );

        for different in [false, true] {
            let id = Uuid::new_v4();
            let mut first = request.clone();
            first["operationId"] = id.to_string().into();
            let mut second = first.clone();
            if different {
                second["task"]["expectedValue"] = "different-target".into();
            }
            let (a, b) = tokio::join!(
                one.call(&self.router, Method::POST, &path, Some(first)),
                two.call(&self.router, Method::POST, &path, Some(second))
            );
            let (a, b) = (a?, b?);
            if different {
                ensure!(
                    (a.0 == StatusCode::ACCEPTED && b.0 == StatusCode::CONFLICT)
                        || (b.0 == StatusCode::ACCEPTED && a.0 == StatusCode::CONFLICT)
                );
            } else {
                ensure!(a == b && a.0 == StatusCode::ACCEPTED);
            }
            let facts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid),(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$1),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$2)").bind(id.to_string()).bind(format!("dispatch.{id}")).fetch_one(&mut pg).await?;
            let audits = crate::audit_test_support::read(&mut pg)
                .await?
                .iter()
                .filter(|r| {
                    r.source() == "mdm.business"
                        && r.operation() == Some(id.to_string().as_str())
                        && r.result() == "success"
                        && r.action() == "command_accept"
                })
                .count() as i64;
            let facts = (facts.0, facts.1, facts.2, audits);
            ensure!(
                facts == (1, 1, 1, 1),
                "concurrent request duplicated facts {facts:?}"
            );
            ensure!(
                self.call(
                    Method::POST,
                    &format!("/{id}/cancel"),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
                )
                .await?
                .0 == StatusCode::OK
            );
        }

        pg.close().await?;
        Ok(())
    }
    async fn admission_and_scope(&mut self) -> anyhow::Result<()> {
        let other = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!(
                    "/api/v2/devices/another-device/operations/{}",
                    self.operation
                ),
                None,
            )
            .await?;
        ensure!(other.0 == StatusCode::FORBIDDEN);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        for relation in [
            "mdm_planning.firewall_resources",
            "mdm_policy.requests",
            "mdm_group.groups",
        ] {
            let permitted: bool =
                sqlx::query_scalar("SELECT has_table_privilege('mdm_command_runtime',$1,'SELECT')")
                    .bind(relation)
                    .fetch_one(&mut pg)
                    .await?;
            ensure!(
                !permitted,
                "command role reads private owner relation {relation}"
            );
        }
        // Formal migration 0021 grants these reads for software rollout admission.
        for relation in ["mdm_planning.scopes", "mdm_planning.scope_results"] {
            let permitted: bool =
                sqlx::query_scalar("SELECT has_table_privilege('mdm_command_runtime',$1,'SELECT')")
                    .bind(relation)
                    .fetch_one(&mut pg)
                    .await?;
            ensure!(permitted, "missing rollout admission input {relation}");
        }
        for (damage, restore) in [
            (
                "GRANT SELECT ON mdm_group.groups TO mdm_command_runtime",
                "REVOKE SELECT ON mdm_group.groups FROM mdm_command_runtime",
            ),
            (
                "ALTER FUNCTION mdm_planning.scope_admission(uuid,text) SECURITY INVOKER",
                "ALTER FUNCTION mdm_planning.scope_admission(uuid,text) SECURITY DEFINER",
            ),
            (
                "ALTER ROLE mdm_owner BYPASSRLS",
                "ALTER ROLE mdm_owner NOBYPASSRLS",
            ),
            (
                "CREATE POLICY widened ON mdm_access.registrations USING(true)",
                "DROP POLICY widened ON mdm_access.registrations",
            ),
            (
                "ALTER TABLE mdm_access.collection_runs DISABLE ROW LEVEL SECURITY",
                "ALTER TABLE mdm_access.collection_runs ENABLE ROW LEVEL SECURITY",
            ),
            (
                "CREATE FUNCTION rss_device_command.unexpected() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'SELECT';",
                "DROP FUNCTION rss_device_command.unexpected()",
            ),
            (
                "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY INVOKER",
                "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY DEFINER",
            ),
            (
                "GRANT EXECUTE ON FUNCTION rss_device_command.lock_authority(uuid,uuid) TO PUBLIC",
                "REVOKE EXECUTE ON FUNCTION rss_device_command.lock_authority(uuid,uuid) FROM PUBLIC",
            ),
            (
                "GRANT UPDATE(fingerprint) ON mdm_commands.requests TO mdm_command_runtime",
                "REVOKE UPDATE(fingerprint) ON mdm_commands.requests FROM mdm_command_runtime",
            ),
            (
                "CREATE POLICY widened ON mdm_commands.operations USING(true)",
                "DROP POLICY widened ON mdm_commands.operations",
            ),
            (
                "ALTER TABLE mdm_commands.operations ADD CONSTRAINT unexpected_command_check CHECK(revision<100000)",
                "ALTER TABLE mdm_commands.operations DROP CONSTRAINT unexpected_command_check",
            ),
        ] {
            sqlx::raw_sql(damage).execute(&mut pg).await?;
            let response = self
                .call(Method::GET, &format!("/{}", self.operation), None)
                .await?;
            sqlx::raw_sql(restore).execute(&mut pg).await?;
            ensure!(
                response.0 == StatusCode::SERVICE_UNAVAILABLE,
                "command admission accepted drift {:?}",
                response
            );
            ensure!(
                self.call(Method::GET, &format!("/{}", self.operation), None)
                    .await?
                    .0
                    == StatusCode::OK
            );
        }
        sqlx::query("UPDATE rss_device_command.commands SET command_id=$2 WHERE command_id=$1")
            .bind(self.operation.to_string())
            .bind(Uuid::nil().to_string())
            .execute(&mut pg)
            .await?;
        let missing = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        sqlx::query("UPDATE rss_device_command.commands SET command_id=$2 WHERE command_id=$1")
            .bind(Uuid::nil().to_string())
            .bind(self.operation.to_string())
            .execute(&mut pg)
            .await?;
        ensure!(
            missing.0 == StatusCode::SERVICE_UNAVAILABLE
                && missing.1["code"] == "service_unavailable",
            "missing command misclassified {missing:?}"
        );
        let poison = self
            .app
            .execution
            .accept_dispatch(Uuid::new_v4(), vec![0; 32])
            .await;
        ensure!(matches!(
            poison,
            Err(rss_mdm_flow_service::Error::Unavailable(
                rss_mdm_flow_service::Failure::CommandInvariant
            ))
        ));
        pg.close().await?;
        Ok(())
    }
    #[cfg(feature = "integration")]
    async fn atomic_failure(&mut self, request: &Value) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        // The provider loses the commit future after all business SQL has run.
        self.app
            .execution
            .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
        let mut next = request.clone();
        let id = Uuid::new_v4();
        next["operationId"] = id.to_string().into();
        let result = self.call(Method::POST, "", Some(next)).await?;
        ensure!(result.0 == StatusCode::SERVICE_UNAVAILABLE);
        let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid)+(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$2)+(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$3)").bind(id.to_string()).bind(id.to_string()).bind(format!("dispatch.{id}")).fetch_one(&mut pg).await?;
        let count = count
            + crate::audit_test_support::read(&mut pg)
                .await?
                .iter()
                .filter(|r| {
                    r.source() == "mdm.business"
                        && r.operation() == Some(id.to_string().as_str())
                        && r.action() == "command_accept"
                })
                .count() as i64;
        ensure!(
            count == 0,
            "abandoned commit partially persisted command/outbox"
        );
        pg.close().await?;
        Ok(())
    }
}

// Request IDs, native operations and action runs are independent identity spaces.
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.admission"]
async fn cancellation_request_identity_does_not_claim_another_device() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    let (other, other_operation) = client.timeline_pair().await?;
    let cancelled = client
        .call(
            Method::POST,
            &format!("/{}/cancel", client.operation),
            Some(json!({"requestId":other_operation,"expectedRevision":1})),
        )
        .await?;
    ensure!(cancelled.0 == StatusCode::OK, "cancel: {cancelled:?}");
    client.drain_timeline().await?;
    let path = format!(
        "/api/v3/devices/{other}/timeline?action=command_cancel&operationId={other_operation}"
    );
    let (status, page) = client
        .browser
        .call(&client.router, Method::GET, &path, None)
        .await?;
    ensure!(
        status == StatusCode::OK && page["items"].as_array().unwrap().is_empty(),
        "request UUID claimed other device: {page}"
    );
    let path = format!(
        "/api/v3/devices/{}/timeline?action=command_cancel&operationId={}",
        case_device(),
        client.operation
    );
    let (_, page) = client
        .browser
        .call(&client.router, Method::GET, &path, None)
        .await?;
    ensure!(
        !page["items"].as_array().unwrap().is_empty(),
        "fact must remain searchable by actual operation: {page}"
    );
    host.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.admission"]
async fn child_dispatch_keeps_its_device_and_parent_search_link() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    let (other, child) = client.timeline_pair().await?;
    let parent = Uuid::new_v4();
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    // Persist the two-target owner relation; the child UUID deliberately equals B's native operation.
    sqlx::query("INSERT INTO mdm_planning.remote_operations(tenant_id,id,resource,resource_version,frozen,snapshot,created_at,deadline,author) VALUES($1::uuid,$2,'fixture','1','{}','{}',1,10000000000,'{}')")
        .bind(case_tenant()).bind(parent).execute(&mut pg).await?;
    sqlx::query("INSERT INTO mdm_planning.remote_operation_targets(tenant_id,operation,device,status,diagnosis) VALUES($1::uuid,$2,$3,'blocked','fixture'),($1::uuid,$2,$4,'blocked','fixture')")
        .bind(case_tenant()).bind(parent).bind(case_device()).bind(&other).execute(&mut pg).await?;
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,source_kind,remote_operation,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint) SELECT tenant_id,$2,'remote_operation',$3,device,registration,registration_generation,'fixture',1,1,10000000000,'{}',decode(repeat('00',32),'hex') FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$4")
        .bind(case_tenant()).bind(child).bind(parent).bind(client.operation).execute(&mut pg).await?;
    pg.close().await?;
    client
        .app
        .execution
        .accept_action_dispatch(child, vec![0; 32])
        .await?;
    client.drain_timeline().await?;
    let path =
        format!("/api/v3/devices/{other}/timeline?action=command_dispatch&operationId={child}");
    let (_, page) = client
        .browser
        .call(&client.router, Method::GET, &path, None)
        .await?;
    ensure!(
        page["items"].as_array().unwrap().is_empty(),
        "child fact leaked to sibling/native UUID: {page}"
    );
    let path = format!(
        "/api/v3/devices/{}/timeline?action=command_dispatch&operationId={parent}",
        case_device()
    );
    let (_, page) = client
        .browser
        .call(&client.router, Method::GET, &path, None)
        .await?;
    ensure!(
        page["items"].as_array().unwrap().len() == 1,
        "parent search link lost: {page}"
    );
    host.close().await?;
    Ok(())
}
impl Client {
    async fn timeline_pair(&mut self) -> anyhow::Result<(String, Uuid)> {
        let other = crate::test_support::case::name("timeline-other").to_owned();
        let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
        let credential =
            crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 94);
        crate::device::test_support::bind(&self.app.devices, &proof, &credential, &other, 0)
            .await?;
        let subject = crate::test_support::browser_subject(&self.browser, &self.router).await?;
        let mut grants = crate::test_support::identity::device_grants(
            None,
            &["state_verify", "operation_read", "operation_cancel"],
        )?;
        grants.push(crate::authorization::Grant {
            operation: crate::authorization::Permission::AuthorizationRead,
            scope: crate::authorization::Scope::Tenant,
        });
        crate::test_support::identity::set_grants(case_tenant(), &subject, grants).await?;
        let request = |id| json!({"operationId":id,"task":{"kind":"state_verify","field":"model","expectedValue":"Final-Model"},"deadline":self.app.clock.unix_seconds().unwrap()+300});
        let id = Uuid::new_v4();
        let mut other_browser = crate::test_support::Browser::default();
        let login = other_browser.call(&self.router,Method::POST,&format!("/api/v2/tenants/{}/login",case_tenant()),Some(json!({"login":crate::test_support::case::login("other"),"password":crate::test_support::identity::PASSWORD}))).await?;
        ensure!(login.0 == StatusCode::OK, "other login: {login:?}");
        let other_subject =
            crate::test_support::browser_subject(&other_browser, &self.router).await?;
        crate::test_support::identity::set_grants(
            case_tenant(),
            &other_subject,
            crate::test_support::identity::device_grants(Some(&other), &["state_verify"])?,
        )
        .await?;
        ensure!(
            other_browser
                .call(
                    &self.router,
                    Method::POST,
                    &format!("/api/v2/devices/{other}/operations"),
                    Some(request(id))
                )
                .await?
                .0
                == StatusCode::ACCEPTED
        );
        ensure!(
            self.call(Method::POST, "", Some(request(self.operation)))
                .await?
                .0
                == StatusCode::ACCEPTED
        );
        Ok((other, id))
    }
    async fn drain_timeline(&self) -> anyhow::Result<()> {
        for _ in 0..100 {
            if self.app.timeline.catch_up().await? == 0 {
                return Ok(());
            }
        }
        anyhow::bail!("fixture projection did not drain")
    }
}
