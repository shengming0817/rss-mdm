//! Faults target this profile's actual registered Software projection.
use super::*;
use crate::assembly::task_relay::{Owner, lanes::SOFTWARE};
use rss_mdm_recovery_observation::Phase;
use rss_reconcile::ErrorKind;
use rss_transactional_messaging_postgres::PgTransactionFault;

use crate::assembly::task_relay::projection::Projection;

#[derive(Debug, PartialEq, Eq)]
struct State {
    accepted: bool,
    status: String,
    receipt: Option<String>,
    fingerprint: Vec<u8>,
    audit_count: i64,
}
struct Dispatch<'a> {
    c: &'a Context,
    a: &'a Fixture,
    id: Uuid,
    original: String,
    lane: Arc<Projection>,
}
impl Dispatch<'_> {
    async fn state(&self) -> Result<State> {
        let Self {
            c, original, id, ..
        } = self;
        let (accepted,status,disposition,fingerprint) = sqlx::query_as("SELECT r.gateway_accepted,o.status,i.disposition,o.fingerprint FROM mdm_software_deployment.action_runs r JOIN rss_transactional_messaging.outbox o ON o.tenant_id=r.tenant_id AND o.message_id=$2 AND o.fingerprint=r.dispatch_fingerprint LEFT JOIN rss_transactional_messaging.inbox i ON i.tenant_id=o.tenant_id AND i.message_id=o.message_id AND i.fingerprint=o.fingerprint AND i.consumer_group=$3 WHERE r.tenant_id=$1::uuid AND r.id=$4 AND o.domain=$5")
            .bind(c.tenant.to_string()).bind(original).bind(SOFTWARE.role).bind(id).bind(SOFTWARE.domain).fetch_one(&c.operator).await?;
        Ok(State {
            accepted,
            status,
            receipt: disposition,
            fingerprint,
            audit_count: c.audit_count("mdm.business", &id.to_string()).await?,
        })
    }
    fn register(&self) -> Result<rss_runtime::ShutdownStack> {
        command::register_relay(
            self.c,
            Owner::Software(self.a.software.service.clone()),
            self.lane.clone(),
        )
    }
    async fn transient(&self, initial: &State) -> Result<()> {
        let Self { c, original, .. } = self;
        let service = &self.a.software.service;
        // Reject only this source row until the provider has settled an acknowledged rollback as Retry.
        self.install_transient().await?;
        let stack = self.register()?;
        command::wait_relay(async || {
            Ok(service.health().relay == Some(Phase::Failed(ErrorKind::Transient)))
        })
        .await?;
        assert!(stack.shutdown().join().await?.is_clean());
        let retry:(i32,bool,bool) = sqlx::query_as("SELECT retry_count,retry_after>clock_timestamp(),retry_after<=automatic_retry_deadline FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2 AND status='pending'")
        .bind(c.tenant.to_string()).bind(original).fetch_one(&c.operator).await?;
        assert_eq!(retry, (1, true, true));
        assert_eq!(&self.state().await?, initial);
        sqlx::raw_sql("DROP TRIGGER t2_transient_dispatch ON mdm_software_deployment.action_runs; DROP FUNCTION public.t2_transient_dispatch()").execute(&c.operator).await?;
        Ok(())
    }
    async fn install_transient(&self) -> Result<()> {
        let Self { c, id, .. } = self;
        let trigger = format!(
            "CREATE FUNCTION public.t2_transient_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'busy' USING ERRCODE='40001'; END $$; CREATE TRIGGER t2_transient_dispatch BEFORE UPDATE OF gateway_accepted ON mdm_software_deployment.action_runs FOR EACH ROW WHEN (NEW.id='{id}'::uuid) EXECUTE FUNCTION public.t2_transient_dispatch()"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(trigger))
            .execute(&c.operator)
            .await?;
        Ok(())
    }
    async fn uncommitted(&self, initial: &State) -> Result<()> {
        let Self {
            c,
            id,
            lane,
            original,
            ..
        } = self;
        let service = &self.a.software.service;
        let scope = service.relay_scope(c.execution()).unwrap();
        command::check_uncommitted_command(
            c,
            |fault| Ok(lane.inject(fault)?),
            &format!("action:{id}:dispatch"),
            async |expected| {
                let expected =
                    if expected == rss_mdm_audit_integration::WriteOutcome::RollbackFailed {
                        ErrorKind::RollbackFailed
                    } else {
                        ErrorKind::CommitUnknown
                    };
                let stack = self.register()?;
                command::wait_relay(async || {
                    Ok(service.health().relay == Some(Phase::Failed(expected)))
                })
                .await?;
                assert!(stack.shutdown().join().await?.is_clean());
                let message = scope.check().unwrap().message().clone();
                assert_eq!(message.id.as_str(), original.as_str());
                assert_eq!(
                    message.fingerprint.unwrap().as_bytes().as_slice(),
                    initial.fingerprint
                );
                let observed = self.state().await?;
                assert_eq!(
                    observed,
                    State {
                        accepted: false,
                        status: "publishing".into(),
                        receipt: None,
                        fingerprint: initial.fingerprint.clone(),
                        audit_count: initial.audit_count
                    }
                );
                Ok(())
            },
        )
        .await?;
        Ok(())
    }
    async fn committed(&self, initial: State) -> Result<()> {
        let Self { c, lane, .. } = self;
        let service = &self.a.software.service;
        let scope = service.relay_scope(c.execution()).unwrap();
        sqlx::query(
            "REVOKE SELECT ON rss_transactional_messaging.outbox FROM mdm_dispatch_software",
        )
        .execute(&c.operator)
        .await?;
        lane.inject(PgTransactionFault::CommitUnknownAfterAck)?;
        let stack = self.register()?;
        command::wait_relay(async || {
            Ok(self.state().await?.status == "published"
                && service.health().relay == Some(Phase::Failed(ErrorKind::CommitUnknown)))
        })
        .await?;
        assert_eq!(
            scope
                .check()
                .unwrap()
                .message()
                .fingerprint
                .unwrap()
                .as_bytes()
                .as_slice(),
            initial.fingerprint
        );
        sqlx::query("GRANT SELECT ON rss_transactional_messaging.outbox TO mdm_dispatch_software")
            .execute(&c.operator)
            .await?;
        command::wait_relay(async || {
            Ok(self.state().await?.status == "published" && scope.check().is_none())
        })
        .await?;
        assert!(stack.shutdown().join().await?.is_clean());
        let committed = State {
            accepted: true,
            status: "published".into(),
            receipt: Some("succeeded".into()),
            fingerprint: initial.fingerprint,
            audit_count: initial.audit_count + 1,
        };
        assert_eq!(self.state().await?, committed);
        assert_eq!(
            lane.poll(c.execution(), vec![()], Some(&scope))
                .await
                .map_err(rss_reconcile::Error::new)?
                .advanced,
            0
        );
        assert_eq!(self.state().await?, committed);
        Ok(())
    }
}
pub(super) async fn check_dispatch(c: &Context, a: &Fixture, id: Uuid) -> Result<()> {
    let run = Dispatch {
        c,
        a,
        id,
        original: format!("action.{id}"),
        lane: a.resources.projection(c, SOFTWARE).await?,
    };
    let initial = run.state().await?;
    assert!(!initial.accepted && initial.receipt.is_none());
    run.transient(&initial).await?;
    run.uncommitted(&initial).await?;
    run.committed(initial).await?;
    run.lane.runtime.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: the original Software lease recovers a lost rollback acknowledgement with one dispatch fact"]
async fn original_recovers_after_rollback_failed() -> Result<()> {
    let c = Context::open("software_rollback_recovery", &[]).await?;
    let (agent, _, scope_id, _, _) = endpoints(&c).await?;
    let package = software(&c, "rollback").await?;
    let (policy_id, _) = policy(
        &c,
        &package,
        scope_id,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![stage(scope_id)],
    )
    .await?;
    let a = open(&c).await?;
    let id = Uuid::new_v4();
    assert!(accepted(&accept(&c, &a, policy_id, &agent, id).await?));
    let run = Dispatch {
        c: &c,
        a: &a,
        id,
        original: format!("action.{id}"),
        lane: a.resources.projection(&c, SOFTWARE).await?,
    };
    let initial = run.state().await?;
    run.install_transient().await?;
    let scope = a.software.service.relay_scope(c.execution()).unwrap();
    run.lane
        .inject(PgTransactionFault::RollbackFailedAfterAck)?;
    let stack = run.register()?;
    command::wait_relay(async || {
        Ok(a.software.service.health().relay == Some(Phase::Failed(ErrorKind::RollbackFailed)))
    })
    .await?;
    let message = scope.check().unwrap().message().clone();
    assert_eq!(message.id.as_str(), run.original);
    assert_eq!(
        message.fingerprint.unwrap().as_bytes().as_slice(),
        initial.fingerprint
    );
    assert_eq!(
        run.state().await?,
        State {
            status: "publishing".into(),
            accepted: false,
            receipt: None,
            fingerprint: initial.fingerprint.clone(),
            audit_count: initial.audit_count
        }
    );
    sqlx::raw_sql("DROP TRIGGER t2_transient_dispatch ON mdm_software_deployment.action_runs; DROP FUNCTION public.t2_transient_dispatch()").execute(&c.operator).await?;
    command::wait_relay(async || {
        Ok(run.state().await?.status == "published" && scope.check().is_none())
    })
    .await?;
    assert!(stack.shutdown().join().await?.is_clean());
    assert_eq!(
        run.state().await?,
        State {
            accepted: true,
            status: "published".into(),
            receipt: Some("succeeded".into()),
            fingerprint: initial.fingerprint,
            audit_count: initial.audit_count + 1
        }
    );
    run.lane.runtime.close().await;
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}
