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
        vault::verify_in(
            rss_mdm_recovery_credentials::Custody::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                None
            ),
            &mut tx,
            &first,
            Uuid::new_v4()
        )
        .await,
        Err(recovery::Error::Conflict)
    ));
    vault::link_native_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
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
    let second = vault::reserve_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        first.tenant,
        &first.binding,
        later,
        1,
    )
    .await?;
    vault::ingest_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        keys,
        &second,
        later,
        b"New-owner-Password!43",
    )
    .await?;
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
    vault::verify_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        &second,
        later,
    )
    .await?;
    tx.commit().await?;
    let mut tx = seed(&c).await?;
    assert_eq!(
        vault::secret_in(
            rss_mdm_recovery_credentials::Custody::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                None
            ),
            &mut tx,
            keys,
            &second
        )
        .await?
        .expose(),
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
        vault::cleared_in(
            rss_mdm_recovery_credentials::Custody::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                None
            ),
            &mut tx,
            &first
        )
        .await,
        Err(recovery::Error::Conflict)
    ));
    tx.rollback().await?;
    filevault_receipt(&c, &protection, &first.binding).await?;
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
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1 AND source_id='mdm.business'",
    )
    .bind(coordinate.tenant)
    .fetch_one(&mut *tx)
    .await?;
    // This private tenant has no other business writes: only the successful rewrap audits.
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
    vault::verify_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        &coordinate,
        operation,
    )
    .await?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='revoked',invalidated_at=$3 WHERE tenant_id=$1 AND entry=$2").bind(coordinate.tenant).bind(coordinate.material).bind(now()-7_776_001).execute(&mut *tx).await?;
    tx.commit().await?;
    input_secrets(&c, &coordinate, operation, attempt, true).await?;
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
    input_secrets(&c, &coordinate, operation, attempt, true).await?;
    // Published -> Received -> Applied advances the component version twice.
    sqlx::query("UPDATE rss_device_command.commands SET status='applied',received_at=$3,terminal_at=$3,version=version+2 WHERE tenant_id=$1 AND command_id=$2").bind(coordinate.tenant).bind(operation.to_string()).bind(now()*1_000_000).execute(&mut *tx).await?;
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
    input_secrets(&c, &coordinate, operation, attempt, false).await?;
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
        rss_mdm_install_support::StorageProfile::Mdm,
        c.database.archive_pool(),
        c.audit.clone(),
        p.keys.clone(),
        None,
        Some(Arc::new(
            super::super::recovery_eligibility::AccessEligibility {
                admission: Some(owner.access.clone()),
            },
        )),
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
    let fact = rss_mdm_audit_integration::Fact::business(
        &audit,
        &format!("recovery:read:{}", audit.request_id()),
        200,
        "success",
        None,
    )?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1 AND source_id='mdm.business' AND event_id=$2",
    )
    .bind(coordinate.tenant)
    .bind(fact.identity().event_id().as_str())
    .fetch_one(&c.operator).await?;
    assert_eq!(count, 1);
    audit.finalize(None);
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

async fn input_secrets(
    c: &Context,
    coordinate: &recovery::Coordinates,
    operation: Uuid,
    attempt: Uuid,
    retained: bool,
) -> Result<()> {
    let mut tx = seed(c).await?;
    let key = material::protection(c)?;
    let op = recovery::native::storage::load_on(&mut tx, c.tenant, &key, operation).await?;
    let recovery::native::Task::Macos {
        request: rss_mdm_apple_mdm::native::request::Request::Command { command },
    } = op.request.task
    else {
        anyhow::bail!("expected command")
    };
    assert_eq!(
        serde_json::to_value(command.fields.0.get("NewPassword"))?,
        if retained {
            serde_json::json!({"type":"string","value":"Owner-test-Password!42"})
        } else {
            serde_json::Value::Null
        }
    );
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
    assert_eq!(
        String::from_utf8_lossy(plain.expose()).contains("Owner-test-Password!42"),
        retained
    );
    tx.rollback().await?;
    Ok(())
}

// A reconcile receipt belongs to its own operation even when its CMS deduplicates an older candidate.
async fn filevault_receipt(
    c: &Context,
    protection: &Arc<recovery::Protection>,
    source: &recovery::Binding,
) -> Result<()> {
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let mut tx = seed(c).await?;
    let binding = filevault_binding(&mut tx, tenant, source).await?;
    let original = Uuid::new_v4();
    let existing_op = Uuid::new_v4();
    let reconcile = Uuid::new_v4();
    let secret = b"ABCD-EFGH-IJKL-MNOP-QRST-UVWX";
    let existing = vault::reserve_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        tenant,
        &binding,
        existing_op,
        0,
    )
    .await?;
    vault::ingest_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        &protection.keys,
        &existing,
        existing_op,
        secret,
    )
    .await?;
    vault::settled_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        &existing,
        existing_op,
    )
    .await?;
    let pending = vault::reserve_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        tenant,
        &binding,
        original,
        1,
    )
    .await?;
    for operation in [original, reconcile] {
        vault::link_native_in(
            rss_mdm_recovery_credentials::Custody::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                None,
            ),
            &mut tx,
            tenant,
            operation,
            &binding,
            &vault::NativeAction {
                action: "collect_filevault".into(),
                coordinates: Some(pending.clone()),
                recipient: protection.active_recipient().id().into(),
                reconciles: None,
            },
        )
        .await?;
    }
    let report = filevault_report(protection, secret)?;
    let receipts = recovery::native_receipts::NativeReceipts::new(protection.clone());
    receipts
        .receive_in(
            &mut tx,
            tenant,
            reconcile,
            &binding.device,
            binding.registration,
            binding.generation,
            &report,
            recovery::native_receipts::ReceiptStatus::Acknowledged,
        )
        .await?;
    assert_native_coordinates(&mut tx, tenant, reconcile, &binding, &existing).await?;
    assert_native_coordinates(&mut tx, tenant, original, &binding, &pending).await?;
    assert_eq!(
        vault::secret_in(
            rss_mdm_recovery_credentials::Custody::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                None
            ),
            &mut tx,
            &protection.keys,
            &existing
        )
        .await?
        .expose(),
        secret
    );
    tx.commit().await?;
    Ok(())
}

fn filevault_report(protection: &recovery::Protection, secret: &[u8]) -> Result<plist::Dictionary> {
    use openssl::{
        cms::{CMSOptions, CmsContentInfo},
        stack::Stack,
        symm::Cipher,
        x509::X509,
    };
    let mut recipients = Stack::new()?;
    recipients.push(X509::from_der(
        &protection.active_recipient().certificate_der()?,
    )?)?;
    let cms = CmsContentInfo::encrypt(
        &recipients,
        secret,
        Cipher::aes_256_cbc(),
        CMSOptions::BINARY,
    )?
    .to_der()?;
    let report = plist::Dictionary::from_iter([(
        "SecurityInfo",
        plist::Value::Dictionary(plist::Dictionary::from_iter([(
            "FDE_PersonalRecoveryKeyCMS",
            plist::Value::Data(cms),
        )])),
    )]);
    Ok(report)
}

async fn assert_native_coordinates(
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    operation: Uuid,
    binding: &recovery::Binding,
    expected: &recovery::Coordinates,
) -> Result<()> {
    let action = vault::native_action_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        c,
        tenant,
        operation,
        &binding.device,
        binding.registration,
        binding.generation,
    )
    .await?
    .unwrap();
    assert_eq!(
        serde_json::to_value(action.coordinates)?,
        serde_json::to_value(Some(expected))?
    );
    Ok(())
}

async fn filevault_binding(
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    source: &recovery::Binding,
) -> Result<recovery::Binding> {
    let custody = Uuid::new_v4();
    let binding = recovery::Binding {
        subject: recovery::Subject::Filevault { custody, epoch: 1 },
        ..source.clone()
    };
    sqlx::query("INSERT INTO mdm_recovery.filevault_custodies(tenant_id,id,origin_device,origin_registration,origin_generation) VALUES($1,$2,$3,$4,$5)")
        .bind(tenant).bind(custody).bind(&binding.device).bind(binding.registration).bind(binding.generation).execute(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_recovery.filevault_sources(tenant_id,registration,generation,custody,epoch) VALUES($1,$2,$3,$4,1)")
        .bind(tenant).bind(binding.registration).bind(binding.generation).bind(custody).execute(&mut *c).await?;
    Ok(binding)
}
