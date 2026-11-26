use super::*;
use rss_mdm_agent_wire::DeviceId;

async fn state(h: &Harness, device: DeviceId) -> Result<Vec<(String, i64, i64)>> {
    Ok(sqlx::query_as("SELECT c.status,c.version,o.observed_command_version FROM mdm_devices.control_operations o JOIN rss_device_command.commands c ON (c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 ORDER BY o.id")
        .bind(h.c.tenant.to_string()).bind(device.into_uuid()).fetch_all(&h.c.operator).await?)
}

async fn interrupt(h: &Harness, device: DeviceId, commit_competitor: bool) -> Result<()> {
    on_claim(h, rss_mdm_device_service::control::recovery_scope(h.c.tenant),&device, async |claim,control,token| {
    let ReconcileStep::Ready(diff) = h.a.service.observe(claim, control).await? else {
        anyhow::bail!("deferred observation")
    };
    let mut competing = command::seed_transaction(&h.c).await?;
    let pid: i32 = sqlx::query_scalar("UPDATE rss_device_command.commands SET status='cancelled',terminal_at=queued_at+1,version=version+1 WHERE tenant_id=$1::uuid AND command_id=$2 RETURNING pg_backend_pid()")
        .bind(h.c.tenant.to_string()).bind(Uuid::from_u128(2).to_string()).fetch_one(&mut *competing).await?;
    {
        let mut apply = Box::pin(control.run(h.a.service.apply(claim, diff, control)));
        tokio::select! {
            result = &mut apply => anyhow::bail!("page settled before competing save: {result:?}"),
            blocked = crate::authority_t2_support::wait_for_blocked_attempt(&h.c.operator, pid, "rss_device_command.save_page") => { blocked?; }
        }
        if commit_competitor {
            competing.commit().await?;
            assert_eq!(
                apply.await.unwrap_err().kind(),
                rss_reconcile::ErrorKind::Fenced
            );
        } else {
            token.cancel();
            assert_eq!(
                apply.await.unwrap_err().kind(),
                rss_reconcile::ErrorKind::Cancelled
            );
            competing.rollback().await?;
        }
    }
    Ok(())
    }).await
}

#[tokio::test]
#[ignore = "T2: cancelled and CAS-conflicted pages retain the owner checkpoint and settle the same operations on retry"]
async fn interrupted_page_retries_original_commands() -> Result<()> {
    with_harness(async |h| {
    let device = super::super::retirement::native_controls(h, 3)
        .await?
        .device;
    let mut tx = command::seed_transaction(&h.c).await?;
    let previous = Uuid::nil().to_string();
    sqlx::query("UPDATE rss_device_command.commands SET deadline=queued_at+1 WHERE tenant_id=$1::uuid AND command_id=ANY($2)")
        .bind(h.c.tenant.to_string()).bind([Uuid::from_u128(1).to_string(),Uuid::from_u128(2).to_string()].as_slice()).execute(&mut *tx).await?;
    sqlx::query("UPDATE mdm_devices.control_recovery SET authority_epoch=1,recovery_after=$3 WHERE tenant_id=$1::uuid AND device=$2")
        .bind(h.c.tenant.to_string()).bind(device.into_uuid()).bind(&previous).execute(&mut *tx).await?;
    tx.commit().await?;
    let original = state(h, device).await?;
    assert_eq!(original, vec![("queued".to_owned(), 1, 1); 3]);
    for commit_competitor in [false, true] {
        interrupt(h, device, commit_competitor).await?;
        let mut expected = original.clone();
        if commit_competitor {
            expected[1] = ("cancelled".into(), 2, 1);
        }
        assert_eq!(state(h, device).await?, expected);
        let cursor: String = sqlx::query_scalar("SELECT recovery_after FROM mdm_devices.control_recovery WHERE tenant_id=$1::uuid AND device=$2")
            .bind(h.c.tenant.to_string()).bind(device.into_uuid()).fetch_one(&h.c.operator).await?;
        assert_eq!(cursor, previous);
        for n in 1..=3 {
            assert!(command::recovery_fact(&h.c, Uuid::from_u128(n), 2).await?.is_none());
        }
    }
    // Loss of registration cancels the third, still-live command inside the settling transaction.
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_access.devices SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(device.into_uuid())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let (settled,sql) = sql::measure(control_page(h, &device)).await;
    settled?;
    assert_eq!(sql.eligibility_after_save,1,"recheck the originally live command after its registration is revoked");
    let final_page = state(h, device).await?;
    assert_eq!(
        final_page,
        vec![
            ("timed_out".into(), 2, 2),
            ("cancelled".into(), 2, 2),
            ("cancelled".into(), 2, 2)
        ]
    );
    for (index, (status, version, _)) in final_page.into_iter().enumerate() {
        let audit = command::recovery_fact(&h.c, Uuid::from_u128(index as u128 + 1), version)
            .await?
            .expect("committed recovery fact");
        assert_eq!(audit["details"]["version"], version);
        assert_eq!(audit["details"]["after"], status);
    }
    Ok(())
    }).await
}
