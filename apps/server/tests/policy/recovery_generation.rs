use super::*;
use rss_device_command::{BatchLimit, Coordinate, Scope, Store};
use rss_transactional_messaging::policy::OperationDeadline;

// The caller must be the policy login used by the production configuration worker.
pub(super) async fn verify(
    c: &Context,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    device: rss_mdm_agent_wire::DeviceId,
) -> Result<()> {
    let tenant = c.tenant;
    let (cmd, id, generation, epoch):(Uuid,Uuid,i64,i64)=sqlx::query_as("SELECT a.command_device,o.id,a.generation,a.epoch FROM mdm_access.command_authorities a JOIN mdm_planning.configuration_operations o USING(tenant_id,device) JOIN rss_device_command.commands c ON (c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE a.tenant_id=$1::uuid AND a.device=$2 AND c.terminal_at IS NULL ORDER BY o.id LIMIT 1")
        .bind(tenant.to_string()).bind(device.into_uuid()).fetch_one(&c.operator).await?;
    let state = || {
        sqlx::query_as::<_,(i64,i64,String,i64,i64)>("SELECT a.generation,a.authority_epoch,c.status,c.version,o.observed_command_version FROM rss_device_command.authorities a JOIN rss_device_command.commands c USING(tenant_id,device_id) JOIN mdm_planning.configuration_operations o ON (o.tenant_id,o.id::text)=(c.tenant_id,c.command_id) WHERE a.tenant_id=$1::uuid AND a.device_id=$2 AND o.id=$3")
        .bind(tenant.to_string()).bind(cmd).bind(id).fetch_one(&c.operator)
    };
    let original = state().await?;
    let scope = Scope::new(
        tenant,
        rss_device_command::DeviceId::parse(&cmd.to_string())?,
    );
    for commit in [false, true] {
        let caller = runtime.clone();
        let (completed, signal) = tokio::sync::oneshot::channel();
        let attempt=runtime.local_tx(c.execution(),OperationDeadline::from_remaining(Duration::from_secs(15)),move |tx|Box::pin(async move{
            let role:String=tx.with_connection(|c|Box::pin(async move{sqlx::query_scalar("SELECT session_user::text").fetch_one(c).await})).await?;
            assert_eq!(role,"mdm_policy_runtime");
            let (_,store)=crate::assembly::host_storage::bind_command_in(caller,tx,rss_device_command_postgres::CommandClock::Postgres,BatchLimit::new(1).expect("one per page"),rss_transactional_messaging::message::MessagingDomain::parse("mdm.policy.configuration.v1").expect("installed Policy domain")).await?;
            store.advance(tx,scope,Coordinate::new(generation,epoch).expect("current"),Coordinate::new(generation+1,epoch+1).expect("successor")).await?;
            let observed=tx.with_connection(move |c|Box::pin(async move{sqlx::query_scalar::<_,i64>("UPDATE mdm_planning.configuration_operations o SET observed_command_version=c.version FROM rss_device_command.commands c WHERE (c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) AND o.tenant_id=$1::uuid AND o.id=$2 RETURNING o.observed_command_version").bind(tenant.to_string()).bind(id).fetch_one(c).await})).await?;
            let _=completed.send(observed);
            if !commit { return Err(sqlx::Error::Protocol("rollback policy generation".into()).into()); }
            Ok(())
        })).await;
        let committed = attempt.fold(|()| Ok(true), Err, |_| Ok(false), Err, Err, Err)?;
        assert_eq!(committed, commit);
        let observed = signal.await?;
        assert_eq!(observed, original.3 + 1);
        let expected = if commit {
            (
                generation + 1,
                epoch + 1,
                "superseded".into(),
                observed,
                observed,
            )
        } else {
            original.clone()
        };
        assert_eq!(state().await?, expected);
    }
    Ok(())
}
