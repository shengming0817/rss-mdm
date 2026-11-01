//! Public-owner installation and actual Enrollment delivery, without the MDM application.
mod admission;
mod audit_boundaries;
mod context;
mod installation;
mod isolation;
mod material;
mod observation;
mod registration_owner;
mod scope_seed;
mod shared_state;
mod storage_reads;
use anyhow::Result;
use context::{Context, Inputs};
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_registration_service as registration;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
const DA: StorageProfile = StorageProfile::Da;
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
struct Capacity;
impl registration::participants::capacity::DeviceCapacity for Capacity {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = std::result::Result<bool, registration::participants::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let tenant = tx.tenant_id();
            let device = device.to_owned();
            Ok(tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        registration::enrollment::tasks::storage::active_count_on(
                            DA, c, tenant, &device, now,
                        )
                        .await
                    })
                })
                .await?
                < 128)
        })
    }
}
fn execution_context() -> w::SoftwareExecutionContext {
    w::SoftwareExecutionContext {
        revision: 1,
        msix_sideload: false,
        msix_unsigned: false,
        os_version: [10, 0, 26100, 0],
        system_broker: true,
        user_helper: false,
        interactive_user: None,
        source_credentials: vec![],
    }
}
async fn accepted(c: &Context, p: &registration::DevicePrincipal) -> Result<Uuid> {
    use rss_mdm_inventory_service::objects::{DeviceObject, ObjectRef};
    use sha2::{Digest, Sha256};
    let object = DeviceObject {
        object: ObjectRef::Endpoint(p.device().into()),
        association_version: None,
        verified: true,
        members: vec![registration::device::endpoints::PrimaryRegistration {
            device: p.device().into(),
            channel: rss_mdm_inventory::Channel::Agent,
            registration_id: p.registration(),
            generation: p.generation(),
        }],
    };
    let scope = scope_seed::published(c, &object).await?;
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let run = Uuid::new_v4();
    let at = now();
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: rss_mdm_authorization_service::User {
            instance_id: c.inputs.installation.instance_id.clone(),
            tenant_id: c.tenant.to_string(),
            principal_id: Uuid::new_v4().to_string(),
        },
    };
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":scope.scope,"action":{"kind":"request_mdm_enrollment","organization":c.tenant.to_string(),"runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}}}),
    )?;
    definition.validate()?;
    let rss_mdm_policy::Action::RequestMdmEnrollment { schedule, .. } = &definition.action else {
        unreachable!()
    };
    let entries = registration::enrollment::task::Entries {
        windows: Some("https://mdm.example.test".into()),
        macos: None,
    };
    entries.validate()?;
    let frozen = serde_json::to_value(
        registration::enrollment::tasks::policy::Published::Enrollment {
            action: Box::new(registration::enrollment::task::FrozenEnrollment {
                organization: Uuid::parse_str(&c.tenant.to_string())?,
                schedule: schedule.clone(),
                run_lifetime_seconds: 300,
                entries,
                actor: actor.clone(),
            }),
        },
    )?;
    let mut tx = c.seed().await?;
    sqlx::query("INSERT INTO rss_da.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(actor)?).bind(at).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.policy_versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'request_mdm_enrollment',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.enrollment_runs(tenant_id,id,policy_version,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint) VALUES($1::uuid,$2,$3,'\"policy\"',$4,$5,$6,$7,'once',$8,$8,$9,$10,true,$11)").bind(c.tenant.to_string()).bind(run).bind(version).bind(json!([object])).bind(p.device()).bind(p.registration()).bind(p.generation()).bind(at).bind(at+300).bind(serde_json::to_value(rss_mdm_task_state::RunState::new(at+300,at)?)?).bind(vec![0u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(run)
}
#[tokio::test]
#[ignore = "T2: public DA owners, resumed installation and actual signed Enrollment flow"]
async fn independent_enrollment_delivery() -> Result<()> {
    let c = Context::open().await?;
    let result = exercise(&c).await;
    c.close().await;
    result
}
async fn exercise(c: &Context) -> Result<()> {
    admission::access(c).await?;
    storage_reads::verify(c).await?;
    let protection = material::protection(c)?;
    let trust = material::seed_trust(
        c,
        &protection,
        &[rss_mdm_agent_wire::task_trust::KeyState::Active],
    )
    .await?;
    let (registration, grant, device) = material::seed_registration(c).await?;
    let capabilities = vec![
        w::Capability::InventoryCollectionV1,
        w::Capability::MdmEnrollmentV1,
    ];
    let (p, pki_trust) =
        material::authenticated_agent(c, registration, grant, &device, capabilities.clone())
            .await?;
    material::seed_ack(c, &trust, registration, p.generation()).await?;
    let context = execution_context();
    let mut tx = c.seed().await?;
    use registration::agent::RuntimeBinding;
    let profile = rss_mdm_agent_wire::enroll::RuntimeProfile {
        capabilities: capabilities.clone(),
        platform: w::TaskPlatform::Windows,
        architecture: w::TaskArchitecture::X86_64,
        execution_context: context.clone(),
    };
    let binding = rss_mdm_agent_channel::Bindings::new(DA)
        .bind(
            &mut tx,
            registration::agent::Binding {
                profile: DA,
                tenant: c.tenant,
                device: device.clone(),
                registration,
                generation: p.generation(),
                epoch: p.epoch(),
                operation: Uuid::new_v4(),
            },
            &profile,
        )
        .await?;
    assert_eq!(binding.registration_id, registration);
    let loaded = rss_mdm_task_trust::trust::load(DA, &mut tx, c.tenant, 1, &protection).await?;
    let signing = Arc::new(rss_mdm_task_trust::Signing::new(
        DA,
        c.tenant,
        Some(loaded),
    )?);
    let mismatch = rss_mdm_task_trust::trust::load(DA, &mut tx, c.tenant, 1, &protection).await?;
    assert!(
        rss_mdm_task_trust::Signing::new(StorageProfile::Mdm, c.tenant, Some(mismatch)).is_err()
    );
    tx.commit().await?;
    audit_boundaries::task_trust(c, &p, signing.clone(), protection.clone(), &trust).await?;
    observation::enrollment(c, &p).await?;
    let target = accepted(c, &p).await?;
    let source = Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
        DA, None,
    ));
    let materials = Arc::new(registration::enrollment::tasks::Materials {
        inventory: Arc::new(
            rss_mdm_inventory_service::assets::enrollment::EnrollmentObservation::new(DA),
        ),
        agent_store: Arc::new(rss_mdm_agent_channel::enrollment_facts::EnrollmentFacts::new(DA)),
        source: Arc::new(rss_mdm_scope_service::registration::EnrollmentSources(
            source,
        )),
        capacity: Arc::new(Capacity),
        events: None,
        instance: c.inputs.installation.instance_id.clone(),
    });
    let transactions = registration::enrollment::tasks::Transactions::bind(
        DA,
        c.runtime.clone(),
        c.tenant,
        c.audit.clone(),
        materials,
    )
    .await?;
    let enrollment = Arc::new(registration::enrollment::tasks::Service::new(
        transactions,
        c.sessions.clone(),
    ));
    let delivery = rss_mdm_agent_channel::delivery::Delivery {
        runtime: c.runtime.clone(),
        tenant: c.tenant,
        audit: c.audit.clone(),
        signing,
        tasks: Arc::new(
            rss_mdm_agent_channel::enrollment_tasks::EnrollmentTasks::new(enrollment.clone()),
        ),
        content: None,
    };
    let audit = || {
        RequestAudit::new(
            DA,
            c.tenant.to_string(),
            "agent_claim",
            AuditIntent::Management,
        )
    };
    let input = w::TaskClaimRequest::new(Uuid::new_v4(), vec![], context.clone())?;
    let before = audit_boundaries::snapshot(c).await?;
    for rejected in audit_boundaries::rejected_audits(c) {
        assert!(matches!(
            delivery.claim(&p, &input, &rejected).await,
            Err(rss_mdm_agent_channel::Error::Forbidden)
        ));
        assert!(matches!(
            delivery
                .download(&p, target, Uuid::new_v4(), None, &rejected)
                .await,
            Err(rss_mdm_agent_channel::Error::Forbidden)
        ));
        rejected.finalize(None);
        assert_eq!(audit_boundaries::snapshot(c).await?, before);
    }
    use rss_transactional_messaging_postgres::PgTransactionFault;
    c.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let unconfirmed = delivery.claim(&p, &input, &audit()).await;
    assert!(
        matches!(
            unconfirmed,
            Err(rss_mdm_agent_channel::Error::CommitUnknown)
        ),
        "expected unconfirmed claim, got {:?}",
        unconfirmed.err()
    );
    let response = delivery.claim(&p, &input, &audit()).await?;
    let signed = response.task().expect("Enrollment offer").clone();
    assert_eq!(signed.payload.task_id(), target);
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let key = trust
        .keys
        .iter()
        .find(|key| key.id == signed.key_id)
        .unwrap();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        URL_SAFE_NO_PAD.decode(&key.public_key)?,
    )
    .verify(
        &signed.payload.signing_bytes(&signed.key_id)?,
        &URL_SAFE_NO_PAD.decode(&signed.signature)?,
    )
    .map_err(|_| anyhow::anyhow!("invalid Enrollment signature"))?;
    assert_eq!(
        serde_json::to_value(&response)?,
        serde_json::to_value(delivery.claim(&p, &input, &audit()).await?)?
    );
    for event in [
        w::TaskEvent::Received,
        w::TaskEvent::Start,
        w::TaskEvent::EnrollmentResult {
            outcome: w::EnrollmentEntryOutcome::Opened,
        },
    ] {
        let start = matches!(event, w::TaskEvent::Start);
        let request = w::TaskEventRequest::new(
            Uuid::new_v4(),
            signed.payload.attempt_id(),
            event,
            context.clone(),
        )?;
        let first = delivery.event(&p, target, &request, &audit()).await?;
        assert_eq!(first.permit().is_some(), start);
        if start {
            let native = rss_mdm_agent_wire::enroll::NativeEnrollmentRequest {
                operation_id: Uuid::new_v4(),
                attempt_id: signed.payload.attempt_id(),
                password: w::Secret::parse(&URL_SAFE_NO_PAD.encode([6; 32]))?,
            };
            assert!(matches!(
                enrollment
                    .native_enrollment(&p, target, &native, &audit())
                    .await,
                Err(registration::enrollment::tasks::Error::Unsupported)
            ));
        }
        let replay = delivery.event(&p, target, &request, &audit()).await?;
        assert_eq!(serde_json::to_value(first)?, serde_json::to_value(replay)?);
    }
    let result: serde_json::Value = sqlx::query_scalar(
        "SELECT result FROM rss_da.enrollment_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(target)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        result,
        serde_json::to_value(w::EnrollmentEntryOutcome::Opened)?
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm'").bind(c.tenant.to_string()).bind(&device).fetch_one(&c.operator).await?;
    assert_eq!(count, 0, "Opened is UI evidence only");
    let forbidden:Vec<String>=sqlx::query_scalar("SELECT nspname::text FROM pg_namespace WHERE nspname IN('mdm_devices','mdm_apple','mdm_windows','mdm_access','mdm_agent','mdm_policy','mdm_scope','mdm_recovery','mdm_webhook')").fetch_all(&c.operator).await?;
    assert!(
        forbidden.is_empty(),
        "MDM private schema unexpectedly installed: {forbidden:?}"
    );
    let mut tx = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_da.registrations WHERE id=$1")
        .bind(registration)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(visible, 0);
    tx.rollback().await?;
    isolation::profiles(c, &p, &context).await?;
    isolation::authority(c).await?;
    shared_state::verify(c, pki_trust).await?;
    // A revocation that wins the registration row lock invalidates the old principal.
    let mut revoke = c.seed().await?;
    sqlx::query(
        "UPDATE rss_da.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(registration)
    .execute(&mut *revoke)
    .await?;
    let next = w::TaskClaimRequest::new(Uuid::new_v4(), vec![], context.clone())?;
    let request_audit = audit();
    let claim = delivery.claim(&p, &next, &request_audit);
    tokio::pin!(claim);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut claim)
            .await
            .is_err()
    );
    revoke.commit().await?;
    assert!(matches!(
        claim.await,
        Err(rss_mdm_agent_channel::Error::Unauthorized)
    ));
    c.runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(
        delivery.claim(&p, &next, &audit()).await,
        Err(rss_mdm_agent_channel::Error::RollbackFailed)
    ));
    Ok(())
}
