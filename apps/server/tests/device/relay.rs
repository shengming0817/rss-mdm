use super::*;
use crate::assembly::task_relay::{Owner, lanes::DEVICE};
use rss_mdm_audit_integration::{AuditIntent, operation::OperationOwner};
use rss_mdm_authorization_service::Permission;
use rss_mdm_device_service::control::device_control::{Action, Input};
use rss_mdm_recovery_observation::Phase;
use rss_reconcile::ErrorKind;

#[tokio::test]
#[ignore = "T2: registered Device relay resolves lost commit acknowledgement and preserves pre-ingress expiry identity"]
async fn device_relay_recovers_its_original() -> Result<()> {
    let c = Context::open("command_projection_outage", &[]).await?;
    let device = windows_control_device(&c).await?;
    let principal = c
        .authenticate(&c.account(&[Permission::DeviceWipe]).await?)
        .await?;
    let a = Fixture::open(&c).await?;
    let submit = async |id: Uuid| -> Result<()> {
        let audit = c.request(&principal)?;
        audit.owned_operation(
            OperationOwner::DeviceControl,
            id,
            "command_accept",
            AuditIntent::Management,
        );
        audit.target_device(&device);
        a.service
            .create_control(
                &principal,
                &device,
                &Input {
                    operation_id: id,
                    deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
                    action: Action::Wipe { confirmed: true },
                },
                &audit,
            )
            .await?;
        audit.finalize(None);
        Ok(())
    };
    let first = Uuid::new_v4();
    submit(first).await?;
    let lane = a.resources.projection(&c, DEVICE).await?;
    let binding = c.execution();
    let scope = a.service.relay_scope(binding).unwrap();
    sqlx::query("REVOKE SELECT ON rss_transactional_messaging.outbox FROM mdm_dispatch_device")
        .execute(&c.operator)
        .await?;
    lane.inject(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck)?;
    let stack = command::register_relay(&c, Owner::Device(a.service.clone()), lane.clone())?;
    command::wait_relay(async || {
        Ok(a.service.health().relay == Some(Phase::Failed(ErrorKind::CommitUnknown)))
    })
    .await?;
    let original = scope.check().unwrap().message().clone();
    assert_eq!(original.id.as_str(), format!("dispatch.{first}"));
    let evidence:(String,Vec<u8>,String,bool) = sqlx::query_as("SELECT o.status,o.fingerprint,i.disposition,b.gateway_accepted FROM rss_transactional_messaging.outbox o JOIN rss_transactional_messaging.inbox i USING(tenant_id,message_id,fingerprint) JOIN mdm_devices.control_operations b ON b.tenant_id=o.tenant_id AND b.dispatch_fingerprint=o.fingerprint WHERE o.tenant_id=$1::uuid AND o.domain=$2 AND o.message_id=$3 AND i.consumer_group=$4 AND b.id=$5")
        .bind(c.tenant.to_string()).bind(DEVICE.domain).bind(original.id.as_str()).bind(DEVICE.role).bind(first).fetch_one(&c.operator).await?;
    assert_eq!(
        evidence,
        (
            "published".into(),
            original.fingerprint.unwrap().as_bytes().to_vec(),
            "succeeded".into(),
            true
        )
    );
    let facts = c.audit_count("mdm.business", &first.to_string()).await?;
    assert_eq!(facts, 2);
    lane.verify_terminal(binding, &scope).await;
    assert!(scope.check().is_some());
    sqlx::query("GRANT SELECT ON rss_transactional_messaging.outbox TO mdm_dispatch_device")
        .execute(&c.operator)
        .await?;
    command::wait_relay(async || Ok(scope.check().is_none())).await?;
    assert!(stack.shutdown().join().await?.is_clean());
    assert_eq!(
        c.audit_count("mdm.business", &first.to_string()).await?,
        facts
    );
    let expired = Uuid::new_v4();
    submit(expired).await?;
    failed_expiry_keeps_original(&c, &a, &lane, expired).await?;
    // A valid original source without its native command cannot produce a dispatch audit.
    let missing = Uuid::new_v4();
    submit(missing).await?;
    let mut tx = command::seed_transaction(&c).await?;
    let removed = sqlx::query(
        "DELETE FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(missing.to_string())
    .execute(&mut *tx)
    .await?;
    assert_eq!(removed.rows_affected(), 1);
    tx.commit().await?;
    let before = c.audit_count("mdm.business", &missing.to_string()).await?;
    let stack = command::register_relay(&c, Owner::Device(a.service.clone()), lane.clone())?;
    command::wait_relay(async || Ok(sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_devices.control_operations r JOIN rss_transactional_messaging.outbox o ON o.tenant_id=r.tenant_id AND o.fingerprint=r.dispatch_fingerprint JOIN rss_transactional_messaging.inbox i ON i.tenant_id=o.tenant_id AND i.message_id=o.message_id AND i.fingerprint=o.fingerprint WHERE r.tenant_id=$1::uuid AND r.id=$2 AND o.domain=$3 AND i.consumer_group=$4 AND NOT r.gateway_accepted AND o.status='dead_letter' AND i.disposition='rejected_permanent')").bind(c.tenant.to_string()).bind(missing).bind(DEVICE.domain).bind(DEVICE.role).fetch_one(&c.operator).await?)).await?;
    assert!(stack.shutdown().join().await?.is_clean());
    assert_eq!(
        c.audit_count("mdm.business", &missing.to_string()).await?,
        before
    );
    lane.runtime.close().await;
    a.close().await?;
    c.close().await;
    Ok(())
}
async fn failed_expiry_keeps_original(
    c: &Context,
    a: &Fixture,
    lane: &crate::assembly::task_relay::projection::Projection,
    id: Uuid,
) -> Result<()> {
    use rss_reconcile::Error as ReconcileError;
    let binding = c.execution();
    let message_id = format!("dispatch.{id}");
    let expected = expire_original(c, &message_id).await?;
    sqlx::raw_sql("REVOKE SELECT ON rss_transactional_messaging.outbox FROM mdm_dispatch_device;
        REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) FROM mdm_dispatch_device;").execute(&c.operator).await?;
    let scope = a.service.relay_scope(binding).unwrap();
    assert_eq!(
        lane.poll(binding, vec![()], Some(&scope))
            .await
            .map_err(ReconcileError::new)?
            .advanced,
        0
    );
    let check = || {
        scope
            .check()
            .expect("claimed message remains observable")
            .message()
            .clone()
    };
    assert_eq!(check().id.as_str(), message_id);
    assert_eq!(check().fingerprint, None);
    lane.verify_terminal(binding, &scope).await;
    assert_eq!(check().fingerprint, None);

    sqlx::raw_sql("GRANT SELECT ON rss_transactional_messaging.outbox TO mdm_dispatch_device;
        GRANT EXECUTE ON FUNCTION rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO mdm_dispatch_device;").execute(&c.operator).await?;
    lane.verify_terminal(binding, &scope).await;
    assert_eq!(check().fingerprint.unwrap().as_bytes().as_slice(), expected);
    await_expiry(c, &scope, lane).await?;
    assert_quarantined(c, a, lane, id, &message_id, &expected).await
}

async fn assert_quarantined(
    c: &Context,
    a: &Fixture,
    lane: &crate::assembly::task_relay::projection::Projection,
    id: Uuid,
    message_id: &str,
    expected: &[u8],
) -> Result<()> {
    use rss_mdm_recovery_observation::Phase;
    use rss_reconcile::ErrorKind;
    let binding = c.execution();
    let scope = a.service.relay_scope(binding).unwrap();
    let evidence:(String,Vec<u8>,bool)=sqlx::query_as("SELECT o.status,o.fingerprint,r.gateway_accepted FROM rss_transactional_messaging.outbox o JOIN mdm_devices.control_operations r ON (r.tenant_id,r.dispatch_fingerprint)=(o.tenant_id,o.fingerprint) WHERE o.tenant_id=$1::uuid AND o.message_id=$2 AND r.id=$3").bind(c.tenant.to_string()).bind(message_id).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(evidence.0, "dead_letter");
    assert_eq!(evidence.1, expected);
    assert!(!evidence.2);
    lane.verify_terminal(binding, &scope).await;
    assert!(scope.check().is_none());
    assert_eq!(
        a.service.health().relay,
        Some(Phase::Failed(ErrorKind::Permanent))
    );
    Ok(())
}

async fn expire_original(c: &Context, message_id: &str) -> Result<Vec<u8>> {
    let mut tx = command::seed_transaction(c).await?;
    let fingerprint: Vec<u8>=sqlx::query_scalar("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND message_id=$2 RETURNING fingerprint")
        .bind(c.tenant.to_string()).bind(message_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(fingerprint)
}
async fn await_expiry(
    c: &Context,
    scope: &rss_mdm_recovery_observation::RelayScope<'_>,
    lane: &crate::assembly::task_relay::projection::Projection,
) -> Result<()> {
    let binding = c.execution();
    tokio::time::timeout(std::time::Duration::from_secs(50), async {
        while lane
            .poll(binding, vec![()], Some(scope))
            .await
            .map_err(rss_reconcile::Error::new)?
            .advanced
            == 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
