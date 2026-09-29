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
    let (host, mut client) = ordinary().await?;
    client.admission_transactions().await?;
    host.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.admission"]
async fn minimum_role_scope_and_storage_admission() -> anyhow::Result<()> {
    let (host, mut client) = ordinary().await?;
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
