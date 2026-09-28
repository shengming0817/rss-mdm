use crate::execution::test_support::*;
use crate::execution::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use sqlx::Connection;
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.dispatch"]
async fn outbox_gateway_ack_and_process_recovery() -> anyhow::Result<()> {
    let (host, mut client) = ordinary().await?;
    client.accept_approved().await?;
    client.dispatch_receipts().await?;
    host.close().await?;
    Ok(())
}
impl Client {
    async fn dispatch_receipts(&mut self) -> anyhow::Result<()> {
        let audit = RequestAudit::new(TENANT.into(), "management_read");
        #[cfg(feature = "integration")]
        self.retry_gateway().await?;
        #[cfg(feature = "integration")]
        self.crash_relay().await?;
        self.app.execution.relay_once().await?;
        // Drive the public bounded recovery seam without a competing fault consumer.
        let s = self.app.execution.clone();
        let id = self.operation;
        crate::transaction::run(
            &s.audit_store,
            &s.runtime,
            s.tenant,
            &audit,
            (s.as_ref(), id),
            |ctx, tx| {
                Box::pin(async move {
                    let op = storage::load(tx, ctx.1).await?;
                    let _page = ctx
                        .0
                        .store
                        .recover(tx, op.scope, dc::BatchLimit::new(64).unwrap(), None)
                        .await?;
                    Ok(())
                })
            },
            crate::transaction::TransactionOwner::Execution,
        )
        .await?;
        audit.finalize(None);
        let read = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            read.0 == StatusCode::OK
                && read.1["task"]["field"] == "model"
                && read.1["task"]["expectedValue"] == "Final-Model"
                && read.1["commandStatus"] == "published"
                && read.1["observation"]["result"] == "unknown",
            "published is not observed {:?}",
            read
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let counts: (i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid),(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$2),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$3)").bind(self.operation.to_string()).bind(self.operation.to_string()).bind(format!("dispatch.{}",self.operation)).fetch_one(&mut pg).await?;
        ensure!(counts == (1, 1, 1));
        let records = crate::audit_test_support::read(&mut pg).await?;
        let successes: Vec<(String, i64)> = ["command_accept", "command_dispatch"]
            .into_iter()
            .map(|action| {
                (
                    action.to_owned(),
                    records
                        .iter()
                        .filter(|r| {
                            r.source() == "mdm.business"
                                && r.operation() == Some(self.operation.to_string().as_str())
                                && r.result() == "success"
                                && r.action() == action
                        })
                        .count() as i64,
                )
            })
            .collect();
        ensure!(
            successes == vec![("command_accept".into(), 1), ("command_dispatch".into(), 1)],
            "replay duplicated success audits {:?}",
            successes
        );

        pg.close().await?;
        Ok(())
    }
    #[cfg(feature = "integration")]
    async fn retry_gateway(&self) -> anyhow::Result<()> {
        use rss_transactional_messaging::outbox::OutboxRelayStore;
        use rss_transactional_messaging_postgres::PgTransactionFault;
        let service = &self.app.execution;
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let mut fingerprint = None;
        for (index, fault) in [
            PgTransactionFault::CommitPending,
            PgTransactionFault::CommitUnknownAfterAck,
        ]
        .into_iter()
        .enumerate()
        {
            let claims = service
                .outbox
                .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
                .await?;
            ensure!(claims.len() == 1);
            for claim in claims {
                let message = PgOutboxStore::<()>::message(&claim);
                ensure!(message.message_id().as_str() == format!("dispatch.{}", self.operation));
                let digest = message.fingerprint().as_bytes().to_vec();
                if let Some(previous) = &fingerprint {
                    ensure!(previous == &digest);
                } else {
                    fingerprint = Some(digest.clone());
                }
                service.inject_fault(fault);
                ensure!(matches!(
                    service.relay_claim(claim).await,
                    Err(Error::CommitUnknown)
                ));
                let row:(String,i32,Vec<u8>)=sqlx::query_as("SELECT status,retry_count,fingerprint FROM rss_transactional_messaging.outbox WHERE message_id=$1").bind(format!("dispatch.{}",self.operation)).fetch_one(&mut pg).await?;
                ensure!(
                    row == ("pending".into(), index as i32 + 1, digest),
                    "unknown gateway acceptance was published or identity changed"
                );
                let accepted: bool = sqlx::query_scalar(
                    "SELECT gateway_accepted FROM mdm_commands.operations WHERE id=$1::uuid",
                )
                .bind(self.operation.to_string())
                .fetch_one(&mut pg)
                .await?;
                let successes = crate::audit_test_support::read(&mut pg)
                    .await?
                    .iter()
                    .filter(|r| {
                        r.source() == "mdm.business"
                            && r.operation() == Some(self.operation.to_string().as_str())
                            && r.action() == "command_dispatch"
                            && r.result() == "success"
                    })
                    .count() as i64;
                ensure!(accepted == (index == 1) && successes == index as i64);
            }
            // Respect the provider's durable Retry schedule, without rewriting its clock/state.
            tokio::time::sleep(Duration::from_millis((1u64 << index) * 1000 + 100)).await;
        }
        pg.close().await?;
        Ok(())
    }
    #[cfg(feature = "integration")]
    async fn crash_relay(&self) -> anyhow::Result<()> {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            std::process::Command::new(std::env::current_exe()?)
                .args([
                    "execution::test_support::relay_crash_child",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?,
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                ensure!(child.0.try_wait()?.is_none(),"relay child exited before durable acceptance");
                let accepted:bool=sqlx::query_scalar("SELECT gateway_accepted FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(TENANT).bind(self.operation.to_string()).fetch_one(&mut pg).await?;
                if accepted {return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await??;
        child.0.kill()?;
        child.0.wait()?;
        // The dead process's opaque claim is never reconstructed. Wait for durable expiry,
        // then the production relay claims and replays the exact gateway acceptance.
        tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                self.app.execution.relay_once().await?;
                let published:bool=sqlx::query_scalar("SELECT status='published' FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2").bind(TENANT).bind(format!("dispatch.{}",self.operation)).fetch_one(&mut pg).await?;
                if published {return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        pg.close().await?;
        Ok(())
    }
}
