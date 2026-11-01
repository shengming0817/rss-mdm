use super::*;
use recovery::storage as vault;
#[tokio::test]
#[ignore = "T2: original candidate and receipt cannot promote a later credential version"]
async fn original_receipt_is_bound_to_candidate_and_version() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let protection = protection(&c, "old")?;
    let keys = &protection.keys;
    let (first, _operation) = native_candidate(&c, keys).await?;
    let receipts = recovery::native_receipts::NativeReceipts::new(protection.clone());
    let verification = Uuid::new_v4();
    let report = plist::Dictionary::from_iter([("PasswordVerified", plist::Value::Boolean(true))]);
    let mut tx = seed(&c).await?;
    assert!(matches!(
        vault::verify_in(&mut tx, &first, Uuid::new_v4()).await,
        Err(recovery::Error::Conflict)
    ));
    vault::link_native_in(
        &mut tx,
        first.tenant,
        verification,
        &first.binding,
        &vault::NativeAction {
            reconciles: None,
            action: "verify_recovery_lock".into(),
            coordinates: Some(first.clone()),
            recipient: String::new(),
        },
    )
    .await?;
    receipts
        .receive_in(
            &mut tx,
            first.tenant,
            verification,
            &first.binding.device,
            first.binding.registration,
            first.binding.generation + 1,
            &report,
            recovery::native_receipts::ReceiptStatus::Acknowledged,
        )
        .await?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT current_version FROM mdm_recovery.entries WHERE tenant_id=$1 AND id=$2",
    )
    .bind(first.tenant)
    .bind(first.material)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(current, None);
    receipts
        .receive_in(
            &mut tx,
            first.tenant,
            verification,
            &first.binding.device,
            first.binding.registration,
            first.binding.generation,
            &report,
            recovery::native_receipts::ReceiptStatus::Acknowledged,
        )
        .await?;
    let later = Uuid::new_v4();
    let second = vault::reserve_in(&mut tx, first.tenant, &first.binding, later, 1).await?;
    vault::ingest_in(&mut tx, &keys, &second, later, b"New-owner-Password!43").await?;
    assert!(matches!(
        receipts
            .receive_in(
                &mut tx,
                first.tenant,
                verification,
                &first.binding.device,
                first.binding.registration,
                first.binding.generation,
                &report,
                recovery::native_receipts::ReceiptStatus::Acknowledged
            )
            .await,
        Err(recovery::Error::Conflict)
    ));
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT current_version FROM mdm_recovery.entries WHERE tenant_id=$1 AND id=$2",
    )
    .bind(first.tenant)
    .bind(first.material)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(current, Some(1));
    vault::verify_in(&mut tx, &second, later).await?;
    tx.commit().await?;
    let mut tx = seed(&c).await?;
    assert_eq!(
        vault::secret_in(&mut tx, &keys, &second).await?.expose(),
        b"New-owner-Password!43"
    );
    let current: i64 = sqlx::query_scalar(
        "SELECT current_version FROM mdm_recovery.entries WHERE tenant_id=$1 AND id=$2",
    )
    .bind(first.tenant)
    .bind(first.material)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(current, 2);
    assert!(matches!(
        vault::cleared_in(&mut tx, &first).await,
        Err(recovery::Error::Conflict)
    ));
    tx.rollback().await?;
    c.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: concurrent maintenance rewraps persisted bytes atomically with audit"]
async fn maintenance_rewrap_is_atomic_and_concurrent() -> Result<()> {
    let c = Context::open("recovery_maintenance", &[]).await?;
    let (coordinate, _) = candidate(&c, &keys("old")?).await?;
    let p = protection(&c, "new")?;
    let owner = Owners::open(&c, "recovery_maintenance", p.clone()).await?;
    let trigger = format!("t2_rewrap_{}", Uuid::new_v4().simple());
    let install = format!(
        "CREATE FUNCTION public.{trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{}'::uuid THEN RAISE EXCEPTION 'test audit unavailable'; END IF; RETURN NEW; END; $$; CREATE TRIGGER {trigger} BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.{trigger}()",
        c.tenant
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(install))
        .execute(&c.operator)
        .await?;
    let rejected = owner.maintenance.run_once().await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {trigger} ON rss_audit.records; DROP FUNCTION public.{trigger}()"
    )))
    .execute(&c.operator)
    .await?;
    assert!(rejected.is_err());
    let unchanged: String = sqlx::query_scalar(
        "SELECT key_id FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=$3",
    )
    .bind(coordinate.tenant)
    .bind(coordinate.material)
    .bind(coordinate.version)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(unchanged, "old");
    let (a, b) = tokio::join!(owner.maintenance.run_once(), owner.maintenance.run_once());
    a?;
    b?;
    let mut tx = seed(&c).await?;
    let (key,sealed):(String,Vec<u8>)=sqlx::query_as("SELECT key_id,sealed FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=$3").bind(coordinate.tenant).bind(coordinate.material).bind(coordinate.version).fetch_one(&mut *tx).await?;
    assert_eq!(key, "new");
    assert_eq!(
        p.keys.open(&key, &coordinate, &sealed)?.expose(),
        b"Owner-test-Password!42"
    );
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT canonical FROM rss_audit.records WHERE tenant_id=$1 AND source_id='mdm.business'",
    )
    .bind(coordinate.tenant)
    .fetch_all(&mut *tx)
    .await?;
    let mut count = 0;
    for row in &rows {
        let decoded = rss_audit_core::decode_untrusted(row)?;
        if decoded
            .event()
            .context()
            .coordinates()
            .operation_id()
            .is_some_and(|id| id.as_str().starts_with("recovery:maintenance:"))
        {
            count += 1;
        }
    }
    assert_eq!(count, 1);
    tx.rollback().await?;
    owner.close().await;
    c.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: unresolved credential fence blocks expiry and cleanup resumes after settlement"]
async fn expiry_preserves_unresolved_material_then_resumes() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let p = protection(&c, "old")?;
    let (coordinate, operation) = native_candidate(&c, &p.keys).await?;
    let owner = Owners::open(&c, "shared", p).await?;
    let attempt = input_copy(&c, &coordinate, operation).await?;
    let mut tx = seed(&c).await?;
    vault::verify_in(&mut tx, &coordinate, operation).await?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='revoked',invalidated_at=$3 WHERE tenant_id=$1 AND entry=$2").bind(coordinate.tenant).bind(coordinate.material).bind(now()-7_776_001).execute(&mut *tx).await?;
    tx.commit().await?;
    owner.maintenance.run_once().await?;
    let mut tx = seed(&c).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT sealed IS NOT NULL FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2",
    )
    .bind(coordinate.tenant)
    .bind(coordinate.material)
    .fetch_one(&mut *tx)
    .await?;
    assert!(exists);
    let purged: bool = sqlx::query_scalar(
        "SELECT inputs_purged FROM mdm_recovery.native_actions WHERE tenant_id=$1 AND operation=$2",
    )
    .bind(coordinate.tenant)
    .bind(operation)
    .fetch_one(&mut *tx)
    .await?;
    assert!(!purged);
    sqlx::query("UPDATE rss_device_command.commands SET status='applied',received_at=$3,terminal_at=$3,version=version+1 WHERE tenant_id=$1 AND command_id=$2").bind(coordinate.tenant).bind(operation.to_string()).bind(now()*1_000_000).execute(&mut *tx).await?;
    tx.commit().await?;
    owner.maintenance.run_once().await?;
    let row: (Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT sealed,key_id FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2",
    )
    .bind(coordinate.tenant)
    .bind(coordinate.material)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(row, (None, None));
    let mut tx = seed(&c).await?;
    let key = material::protection(&c)?;
    let op = recovery::native::storage::load_on(&mut tx, c.tenant, &key, operation).await?;
    let recovery::native::Task::Macos {
        request: rss_mdm_apple_mdm::native::request::Request::Command { command },
    } = op.request.task
    else {
        anyhow::bail!("expected command")
    };
    assert!(!command.fields.0.contains_key("NewPassword"));
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT request FROM mdm_apple.attempts WHERE tenant_id=$1 AND id=$2")
            .bind(coordinate.tenant)
            .bind(attempt)
            .fetch_one(&mut *tx)
            .await?;
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(coordinate.binding.registration, 1i64, attempt))?,
        "apple.attempt.request",
        1,
    )?
    .derive();
    let plain = key.open_bytes(&bytes, &aad)?;
    assert!(!String::from_utf8_lossy(plain.expose()).contains("Owner-test-Password!42"));
    tx.rollback().await?;
    owner.close().await;
    c.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: disclosure releases no plaintext when audit or transaction settlement fails"]
async fn sensitive_disclosure_requires_confirmed_audit_commit() -> Result<()> {
    use rss_transactional_messaging_postgres::PgTransactionFault;
    let c = Context::open("recovery_audit", &[]).await?;
    let p = protection(&c, "old")?;
    let (coordinate, _) = candidate(&c, &p.keys).await?;
    let owner = Owners::open(&c, "recovery_audit", p.clone()).await?;
    let account = c
        .account(&[rss_mdm_authorization_service::Permission::Credentials])
        .await?;
    let proof = c.authenticate(&account).await?;
    let service = recovery::Credentials::new(
        c.database.archive_pool(),
        c.audit.clone(),
        p.keys.clone(),
        None,
        owner.access.clone(),
    );
    let audit = c.request(&proof)?;
    let result = service
        .disclose(
            &proof,
            &coordinate.binding.device,
            coordinate.material,
            coordinate.version,
            &audit,
        )
        .await?;
    assert_eq!(result.secret.as_str(), "Owner-test-Password!42");
    assert_eq!(
        c.audit_count(
            "mdm.business",
            &format!("recovery:read:{}", audit.request_id())
        )
        .await?,
        1
    );
    c.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        service
            .disclose(
                &proof,
                &coordinate.binding.device,
                coordinate.material,
                coordinate.version,
                &c.request(&proof)?
            )
            .await,
        Err(recovery::Error::CommitUnknown)
    ));
    c.disable_audit().await?;
    let denied = service
        .disclose(
            &proof,
            &coordinate.binding.device,
            coordinate.material,
            coordinate.version,
            &c.request(&proof)?,
        )
        .await;
    sqlx::raw_sql("GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_access").execute(&c.operator).await?;
    assert!(matches!(
        denied,
        Err(recovery::Error::Audit) | Err(recovery::Error::Storage)
    ));
    owner.close().await;
    c.close().await;
    Ok(())
}
