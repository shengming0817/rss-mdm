//! Real owner transactions, isolated tenant rows, and the existing product-role runtime.
use crate::authority_t2_support::Context;
use crate::device_material_support as support;
use anyhow::Result;
use rss_mdm_agent_wire::task_trust::KeyState;
use rss_mdm_authorization_service::Permission;
use rss_mdm_task_trust::{Error, service::Change};
use uuid::Uuid;

#[tokio::test]
#[ignore = "T2: current registration generation and trust activation SQL"]
async fn activation_requires_current_generation_ack() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let protection = support::protection(&c)?;
    let service = support::service(&c, protection.clone())?;
    let trust =
        support::seed_trust(&c, &protection, &[KeyState::Active, KeyState::Prepared]).await?;
    let (registration, _, _) = support::seed_registration(&c).await?;
    support::seed_ack(&c, &trust, registration, 1).await?;
    let account = c
        .account(&[
            Permission::RegistrationConfigurationWrite,
            Permission::RegistrationConfigurationRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let operation = Uuid::new_v4();
    let key = trust
        .keys
        .iter()
        .find(|v| v.state == KeyState::Prepared)
        .unwrap()
        .id
        .clone();
    let change = Change::Activate {
        expected_revision: 1,
        key_id: key.clone(),
    };
    assert!(matches!(
        service
            .change_task_trust(&proof, &c.request(&proof)?, operation, &change)
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        service.task_trust(&proof, &c.request(&proof)?).await?,
        trust
    );
    assert_eq!(
        c.audit_count("mdm.business", &operation.to_string())
            .await?,
        0
    );
    support::seed_ack(&c, &trust, registration, 2).await?;
    let result = service
        .change_task_trust(&proof, &c.request(&proof)?, operation, &change)
        .await?;
    assert_eq!(result.revision, 2);
    assert!(
        result
            .keys
            .iter()
            .any(|v| v.id == key && v.state == KeyState::Active)
    );
    assert!(
        result
            .keys
            .iter()
            .any(|v| v.id != key && v.state == KeyState::VerifyOnly)
    );
    // Original CAS does not authorize a second operation.
    assert!(matches!(
        service
            .change_task_trust(&proof, &c.request(&proof)?, Uuid::new_v4(), &change)
            .await,
        Err(Error::Conflict)
    ));
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: original trust receipt, protected request identity and atomic Audit"]
async fn operation_replay_keeps_original_key_version_and_fact() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let service = support::service(&c, support::protection(&c)?)?;
    let account = c
        .account(&[
            Permission::RegistrationConfigurationWrite,
            Permission::RegistrationConfigurationRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let operation = Uuid::new_v4();
    let change = Change::Prepare {
        expected_revision: 0,
    };
    let first = service
        .change_task_trust(&proof, &c.request(&proof)?, operation, &change)
        .await?;
    let replay = service
        .change_task_trust(&proof, &c.request(&proof)?, operation, &change)
        .await?;
    assert_eq!(first, replay);
    assert_eq!(
        service
            .task_trust_operation(&proof, &c.request(&proof)?, operation)
            .await?,
        first
    );
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_task_signing.versions WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_task_signing.keys WHERE tenant_id=$1::uuid)")
        .bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(counts, (1, 1));
    assert_eq!(
        c.audit_count("mdm.business", &operation.to_string())
            .await?,
        1
    );
    assert!(matches!(
        service
            .change_task_trust(
                &proof,
                &c.request(&proof)?,
                operation,
                &Change::Prepare {
                    expected_revision: 1
                }
            )
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        service.task_trust(&proof, &c.request(&proof)?).await?,
        first
    );
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: real protected key, certificate principal, durable ACK and signing seam"]
async fn issuance_binds_current_principal_and_real_signed_bytes() -> Result<()> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rss_mdm_agent_wire::runtime as w;
    let c = Context::open("shared", &[]).await?;
    let protection = support::protection(&c)?;
    let trust = support::seed_trust(&c, &protection, &[KeyState::Active]).await?;
    let (registration, grant, device) = support::seed_registration(&c).await?;
    let principal = support::authenticated_agent(
        &c,
        registration,
        grant,
        &device,
        vec![rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1],
    )
    .await?;
    let mut tx = c.database.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let loaded = rss_mdm_task_trust::trust::load(&mut tx, c.tenant, 1, &protection).await?;
    tx.commit().await?;
    let signing = rss_mdm_task_trust::Signing::new(c.tenant, Some(loaded))?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let payload = w::TaskPayload::Unmanage(Box::new(w::UnmanageTaskSpec {
        wire_version: 1,
        tenant_id: Uuid::parse_str(&c.tenant.to_string())?,
        device_id: device,
        registration_id: registration,
        generation: 2,
        retirement_id: Uuid::new_v4(),
        task_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        permit: w::TaskPermit::Offer,
        expires_at: now + 60,
        deadline: now + 300,
        platform: w::TaskPlatform::Windows,
        architecture: w::TaskArchitecture::X86_64,
        authorization: w::TaskAuthorization::Policy {
            policy_id: Uuid::new_v4(),
            policy_version: Uuid::new_v4(),
        },
    }));
    // A current certificate alone does not prove installation of the signing key.
    let mut tx = c.database.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(matches!(
        signing
            .sign_task_on(&mut tx, &principal, payload.clone())
            .await,
        Err(Error::Forbidden)
    ));
    tx.rollback().await?;
    let service = support::service(&c, protection)?;
    let ack = rss_mdm_agent_wire::task_trust::Acknowledgement {
        operation: Uuid::new_v4(),
        registration,
        generation: 2,
        revision: 1,
        digest: trust.installation_digest()?,
        version: 1,
    };
    let audit = rss_mdm_audit_integration::RequestAudit::new(
        c.tenant.to_string(),
        "task-trust",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_device(registration);
    service
        .acknowledge_task_trust(&principal, &audit, &ack)
        .await?;
    let mut tx = c.database.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let mut wrong = payload.clone();
    if let w::TaskPayload::Unmanage(v) = &mut wrong {
        v.generation += 1;
    }
    assert!(matches!(
        signing.sign_task_on(&mut tx, &principal, wrong).await,
        Err(Error::Forbidden)
    ));
    let signed = signing
        .sign_task_on(&mut tx, &principal, payload.clone())
        .await?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        URL_SAFE_NO_PAD.decode(&trust.keys[0].public_key)?,
    )
    .verify(
        &payload.signing_bytes(&signed.key_id)?,
        &URL_SAFE_NO_PAD.decode(&signed.signature)?,
    )
    .map_err(|_| anyhow::anyhow!("real signature verification"))?;
    tx.commit().await?;
    let mut update = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *update)
        .await?;
    sqlx::query(
        "UPDATE mdm_access.registrations SET generation=3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(registration)
    .execute(&mut *update)
    .await?;
    update.commit().await?;
    let mut tx = c.database.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(matches!(
        signing.sign_task_on(&mut tx, &principal, payload).await,
        Err(Error::Unauthorized)
    ));
    tx.rollback().await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: retirement borrows the real pending signature query in its source transaction"]
async fn retirement_retains_key_until_original_signature_expires() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let protection = support::protection(&c)?;
    let trust =
        support::seed_trust(&c, &protection, &[KeyState::Active, KeyState::VerifyOnly]).await?;
    let key = trust
        .keys
        .iter()
        .find(|v| v.state == KeyState::VerifyOnly)
        .unwrap()
        .id
        .clone();
    let service = support::service(&c, protection.clone())?;
    let account = c
        .account(&[
            Permission::RegistrationConfigurationWrite,
            Permission::RegistrationConfigurationRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let run = Uuid::new_v4();
    let (registration, _, device) = support::seed_registration(&c).await?;
    support::seed_ack(&c, &trust, registration, 2).await?;
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rss_mdm_agent_wire::runtime as w;
    let sealed: Vec<u8> = sqlx::query_scalar(
        "SELECT private_key FROM mdm_task_signing.keys WHERE tenant_id=$1::uuid AND key_id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(&key)
    .fetch_one(&c.operator)
    .await?;
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &key,
        "task-signing.private-key",
        1,
    )?
    .derive();
    let private = protection.open_bytes(&sealed, &aad)?;
    let signer = ring::signature::Ed25519KeyPair::from_pkcs8(private.expose())
        .map_err(|_| anyhow::anyhow!("seed key"))?;
    let payload = w::TaskPayload::Unmanage(Box::new(w::UnmanageTaskSpec {
        wire_version: 1,
        tenant_id: Uuid::parse_str(&c.tenant.to_string())?,
        device_id: device.clone(),
        registration_id: registration,
        generation: 2,
        retirement_id: Uuid::new_v4(),
        task_id: run,
        attempt_id: attempt,
        permit: w::TaskPermit::Offer,
        expires_at: now + 5,
        deadline: now + 5,
        platform: w::TaskPlatform::Windows,
        architecture: w::TaskArchitecture::X86_64,
        authorization: w::TaskAuthorization::Policy {
            policy_id: policy,
            policy_version: version,
        },
    }));
    let signature = URL_SAFE_NO_PAD.encode(signer.sign(&payload.signing_bytes(&key)?).as_ref());
    let offer = w::SignedTask {
        payload,
        key_id: key.clone(),
        signature,
    };
    let mut tx = c.operator.begin().await?;
    sqlx::query("INSERT INTO mdm_agent.task_attempts(tenant_id,id,run,registration,claimed_at,deadline,offer) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
        .bind(c.tenant.to_string()).bind(attempt).bind(run).bind(registration).bind(now).bind(now+5).bind(serde_json::to_value(&offer)?).execute(&mut *tx).await?;
    tx.commit().await?;
    let operation = Uuid::new_v4();
    let change = Change::Retire {
        expected_revision: 1,
        key_id: key.clone(),
    };
    assert!(matches!(
        service
            .change_task_trust(&proof, &c.request(&proof)?, operation, &change)
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        service.task_trust(&proof, &c.request(&proof)?).await?,
        trust
    );
    // Let the original signature expire without rewriting its durable evidence.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let result = service
        .change_task_trust(&proof, &c.request(&proof)?, operation, &change)
        .await?;
    assert!(!result.keys.iter().any(|v| v.id == key));
    assert_eq!(result.revision, 2);
    c.close().await;
    Ok(())
}
