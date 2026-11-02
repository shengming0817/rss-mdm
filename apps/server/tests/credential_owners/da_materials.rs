//! RSS custody consumes the DA binding while authenticated Agent coordinates bind wire encryption.
use super::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_device_access_postgres::device_access::participants::AccessRecovery;
use rss_mdm_device_access_postgres::{self as pg, device_access as access};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_recovery_credentials::tasks::product::Product;
use rss_mdm_registration_service::{DevicePrincipal, device::endpoints::DaRegistration};

const SID: &str = "S-1-5-21-1-2-3-1001";

async fn transaction(
    pool: &sqlx::PgPool,
    tenant: Uuid,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

fn envelope(
    task: &w::AccessTaskSpec,
    subject: &w::CredentialSubject,
    recipient: &recovery::Recipient,
) -> Result<w::CredentialEscrow> {
    let aad = task.material_aad(subject, 0)?;
    let mut key = [0; 32];
    let mut nonce = [0; 12];
    openssl::rand::rand_bytes(&mut key)?;
    openssl::rand::rand_bytes(&mut nonce)?;
    let cipher = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key)
            .map_err(|_| anyhow::anyhow!("escrow test AES key"))?,
    );
    let mut ciphertext = URL_SAFE_NO_PAD.encode([83; 32]).into_bytes();
    cipher
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("escrow test encryption"))?;
    let public = openssl::pkey::PKey::public_key_from_der(&recipient.public_key_der()?)?;
    let mut encrypt = openssl::encrypt::Encrypter::new(&public)?;
    encrypt.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
    encrypt.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
    encrypt.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;
    let mut wrapped = vec![0; encrypt.encrypt_len(&key)?];
    let len = encrypt.encrypt(&key, &mut wrapped)?;
    wrapped.truncate(len);
    Ok(w::CredentialEscrow {
        definition_digest: task.definition_digest,
        materials: vec![w::CredentialEnvelope {
            subject: subject.clone(),
            expected_revision: 0,
            wrapped_key: STANDARD.encode(wrapped),
            nonce,
            ciphertext: STANDARD.encode(ciphertext),
        }],
    })
}

async fn material_count(c: &Context, tenant: Uuid) -> Result<(i64, i64)> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.recovery_entries WHERE tenant_id=$1),(SELECT count(*) FROM rss_da.recovery_versions WHERE tenant_id=$1)")
        .bind(tenant).fetch_one(&c.operator).await?)
}

pub(super) async fn verify(
    c: &Context,
    agent: &DevicePrincipal,
    da: &DaRegistration,
    person: Uuid,
) -> Result<()> {
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let account = w::AccessAccount::Windows {
        sid: SID.into(),
        authority: w::AccessWindowsAuthority::Local,
    };
    let configuration = w::AccessConfiguration {
        mac: None,
        windows: w::AccessWindowsConfiguration::RssFactor {
            accounts: vec![w::AccessWindowsKind::Local],
        },
        self_enrollment: false,
        enabled: true,
        role: None,
    };
    let publication = rss_mdm_policy_postgres::device_access::Publication {
        id: Uuid::new_v4(),
        revision: 1,
        version: Uuid::new_v4(),
        target: rss_mdm_policy_postgres::device_access::Target::Device {
            device: da.device.clone(),
        },
        enabled: true,
        configuration: configuration.clone(),
    };
    let mut binding = access::Binding {
        operation_id: Uuid::new_v4(),
        account_disposition: w::AccessAccountDisposition::Keep,
        id: Uuid::new_v4(),
        tenant,
        device: da.device.clone(),
        registration: da.registration_id,
        registration_generation: da.generation,
        person: rss_mdm_device_access::Person {
            instance: agent.installation(),
            principal: person,
        },
        origin: access::Origin::SelfEnrollment,
        generation: 3,
        factor_generation: 4,
        revision: 1,
        state: rss_mdm_device_access::State::Pending,
        intent: rss_mdm_device_access::AccountIntent::Existing {
            account: account.clone(),
        },
        account: Some(account.clone()),
        policy: publication.id,
        policy_version: publication.version,
        configuration,
        received_revision: None,
        applied_revision: None,
        deployment_application: None,
        effect: None,
        applied_windows: None,
        created_by_rss: false,
    };
    let mut tx = seed(c).await?;
    rss_mdm_policy_postgres::device_access::publish_on(
        &mut tx,
        tenant,
        &publication,
        0,
        serde_json::json!({"kind":"system"}),
        now(),
    )
    .await?;
    access::storage::insert_in(&mut tx, &binding).await?;
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1,$2,1,$3,'windows','x86_64',$4)")
        .bind(tenant).bind(agent.registration()).bind(serde_json::to_string(&vec![w::Capability::InventoryCollectionV1,w::Capability::DeviceAccessV1,w::Capability::CredentialsWindowsV1])?)
        .bind(serde_json::json!({"revision":1,"msixSideload":false,"msixUnsigned":false,"osVersion":[10,0,26100,0],"systemBroker":true,"userHelper":true,"interactiveUser":{"identity":SID,"windowsAuthority":{"kind":"local"},"generatedUid":null,"sessionId":Uuid::new_v4(),"administrator":false},"sourceCredentials":[]}))
        .execute(&mut *tx).await?;
    tx.commit().await?;
    let protection = protection(c, "old")?;
    let eligibility = Arc::new(pg::recovery::eligibility::AccessEligibility { admission: None });
    let materials = pg::recovery::AccessMaterials::new(protection.clone(), eligibility.clone());
    let pool = c.inputs.pool("shared", "mdm_command_runtime").await?;
    let mut tx = transaction(&pool, tenant).await?;
    let plan = materials.plan(&mut tx, &binding, now()).await?;
    tx.rollback().await?;
    let task = w::AccessTaskSpec {
        wire_version: w::WIRE_VERSION,
        tenant_id: tenant,
        device_id: agent.device().into(),
        registration_id: agent.registration(),
        generation: agent.generation() as u64,
        platform: w::TaskPlatform::Windows,
        architecture: w::TaskArchitecture::X86_64,
        task_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        permit: w::TaskPermit::Start,
        expires_at: now() + 300,
        deadline: now() + 600,
        binding_id: binding.id,
        instance_id: binding.person.instance,
        principal_id: binding.person.principal,
        binding_generation: binding.generation,
        factor_generation: binding.factor_generation,
        revision: binding.revision,
        definition_digest: binding.definition_digest()?,
        action: w::AccessAction::Apply {
            account: account.clone(),
            configuration: binding.configuration.clone(),
        },
        windows: Some(plan),
        authorization: w::TaskAuthorization::Policy {
            policy_id: binding.policy,
            policy_version: binding.policy_version,
        },
    };
    task.validate()?;
    let subject = w::CredentialSubject::RssLogin {
        binding: binding.id,
        binding_generation: binding.generation,
        sid: SID.into(),
    };
    let escrow = envelope(&task, &subject, protection.active_recipient())?;
    let before = material_count(c, tenant).await?;
    let mut wrong_generation = task.clone();
    wrong_generation.generation += 1;
    let wrong_envelope = envelope(&wrong_generation, &subject, protection.active_recipient())?;
    let mut tx = transaction(&pool, tenant).await?;
    assert!(
        matches!(
            materials
                .escrow(&mut tx, &wrong_generation, &wrong_envelope)
                .await,
            Err(pg::Error::Conflict)
        ),
        "valid ciphertext for a stale Agent generation must not acquire DA custody"
    );
    tx.rollback().await?;
    let mut da_wire = task.clone();
    da_wire.device_id = da.device.clone();
    da_wire.registration_id = da.registration_id;
    da_wire.generation = da.generation as u64;
    let mut tx = transaction(&pool, tenant).await?;
    assert!(
        materials.escrow(&mut tx, &da_wire, &escrow).await.is_err(),
        "DA coordinates cannot substitute the Agent wire AAD"
    );
    tx.rollback().await?;
    assert_eq!(material_count(c, tenant).await?, before);
    let mut tx = transaction(&pool, tenant).await?;
    let receipts = materials.escrow(&mut tx, &task, &escrow).await?;
    assert_eq!(receipts.len(), 1);
    let facts = w::AccessRssFacts {
        factor_generation: binding.factor_generation,
        recovery: receipts[0].clone(),
    };
    materials.settle(&mut tx, &task, &facts).await?;
    let coordinates = recovery::storage::coordinates_in(
        materials.custody(),
        &mut tx,
        tenant,
        &da.device,
        facts.recovery.material,
        facts.recovery.version,
    )
    .await?;
    assert_eq!(coordinates.profile, StorageProfile::Da);
    assert_eq!(
        (
            &coordinates.binding.device,
            coordinates.binding.registration,
            coordinates.binding.generation
        ),
        (&da.device, da.registration_id, da.generation)
    );
    assert_ne!(coordinates.binding.registration, task.registration_id);
    assert_eq!(
        recovery::storage::secret_in(materials.custody(), &mut tx, &protection.keys, &coordinates)
            .await?
            .expose(),
        URL_SAFE_NO_PAD.encode([83; 32]).as_bytes()
    );
    let current =
        recovery::storage::current_in(materials.custody(), &mut tx, tenant, &coordinates.binding)
            .await?
            .unwrap();
    assert_eq!(current.validity, recovery::Validity::Verified);
    assert!(current.escrowed);
    binding.state = rss_mdm_device_access::State::Active;
    binding.received_revision = Some(binding.revision);
    binding.applied_revision = Some(binding.revision);
    binding.applied_windows = Some(w::AccessWindowsFacts::RssFactor(facts.clone()));
    binding.effect = Some(w::AccessEffect::Applied {
        account,
        role: w::AccessRole::Standard,
        mac: None,
        windows: binding.applied_windows.clone(),
    });
    access::storage::save_in(&mut tx, &binding, binding.revision).await?;
    let target = recovery::tasks::Target {
        device: agent.device().into(),
        registration: agent.registration(),
        generation: agent.generation(),
    };
    let rotate = rss_mdm_policy::CredentialOperation::RotateRssLogin {
        binding: binding.id,
        binding_generation: binding.generation,
        sid: SID.into(),
    };
    assert_eq!(
        eligibility
            .resolve(&mut tx, tenant, &rotate, &target)
            .await?,
        coordinates.binding
    );
    let mut stale_target = target.clone();
    stale_target.generation += 1;
    assert!(matches!(
        eligibility
            .resolve(&mut tx, tenant, &rotate, &stale_target)
            .await,
        Err(recovery::Error::Forbidden)
    ));
    tx.commit().await?;
    assert_eq!(
        material_count(c, tenant).await?,
        (before.0 + 1, before.1 + 1)
    );
    verify_access_recovery(c, agent, &binding, protection.clone()).await?;
    let accepted = material_count(c, tenant).await?;
    sqlx::query(
        "UPDATE rss_da.agent_delivery SET enabled=false WHERE tenant_id=$1 AND da_registration=$2",
    )
    .bind(tenant)
    .bind(da.registration_id)
    .execute(&c.operator)
    .await?;
    let mut tx = transaction(&pool, tenant).await?;
    assert!(matches!(
        materials.escrow(&mut tx, &task, &escrow).await,
        Err(pg::Error::Forbidden)
    ));
    assert!(matches!(
        materials.settle(&mut tx, &task, &facts).await,
        Err(pg::Error::Forbidden)
    ));
    assert!(matches!(
        eligibility.resolve(&mut tx, tenant, &rotate, &target).await,
        Err(recovery::Error::Forbidden)
    ));
    tx.rollback().await?;
    assert_eq!(material_count(c, tenant).await?, accepted);
    sqlx::query(
        "UPDATE rss_da.agent_delivery SET enabled=true WHERE tenant_id=$1 AND da_registration=$2",
    )
    .bind(tenant)
    .bind(da.registration_id)
    .execute(&c.operator)
    .await?;
    pool.close().await;
    Ok(())
}

/// Recovery must read Agent liveness from its owner even though the run and binding live in DA.
async fn verify_access_recovery(
    c: &Context,
    agent: &DevicePrincipal,
    binding: &access::Binding,
    protection: Arc<recovery::Protection>,
) -> Result<()> {
    use access::execution;
    use rss_mdm_task_state::{Cancellation, Execution, RunState};
    let runtime = crate::identity::open_runtime(
        &c.inputs.database("shared", "mdm_command_runtime"),
        &c.inputs.installation.target,
        &c.inputs.installation.lineage,
        &[(c.tenant, 1)],
        2,
    )
    .await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let audit = Arc::new(
        c.audit
            .on_runtime(runtime.clone(), c.tenant, &budget.control())
            .await?,
    );
    let service = execution::Service::new(
        execution::Transactions::bind(
            runtime.clone(),
            c.tenant,
            audit.clone(),
            Arc::new(execution::Materials {
                agent_store: Arc::new(
                    rss_mdm_agent_channel::enrollment_facts::EnrollmentFacts::new(
                        StorageProfile::Mdm,
                    ),
                ),
                capacity: Arc::new(crate::assembly::capacity::Capacity),
                recovery: Some(Arc::new(pg::recovery::AccessMaterials::new(
                    protection.clone(),
                    Arc::new(pg::recovery::eligibility::AccessEligibility { admission: None }),
                ))),
                platform: Arc::new(pg::platform_sso::Observation),
            }),
        )
        .await?,
    );
    let id = Uuid::new_v4();
    let at = now();
    let state = RunState::new(at + 600, at)?;
    let original = serde_json::to_value(&state)?;
    let (credential, credential_id) = credential_run(
        c, agent, binding, protection, &runtime, &audit, &original, at,
    )
    .await?;
    let mut tx = seed(c).await?;
    sqlx::query("INSERT INTO rss_da.access_runs(tenant_id,id,policy_version,origin,access_binding,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint) VALUES($1,$2,$3,'\"policy\"',$4,$5,$6,$7,$8,$9,$9,$10,$11,$12)")
        .bind(binding.tenant).bind(id).bind(binding.policy_version).bind(serde_json::to_value(binding)?)
        .bind(agent.device()).bind(agent.registration()).bind(agent.generation()).bind(format!("binding:{}",binding.id))
        .bind(at).bind(at+600).bind(&original).bind(vec![7_u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    async fn recover(
        c: &Context,
        runtime: &rss_transactional_messaging_postgres::PgRuntime,
        audit: &rss_mdm_audit_integration::AuditStore,
        service: &execution::Service,
        id: Uuid,
    ) -> Result<RunState, execution::Error> {
        let request = rss_mdm_audit_integration::RequestAudit::new(
            StorageProfile::Da,
            c.tenant.to_string(),
            "da-recovery-proof",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        execution::transaction::run(
            audit,
            runtime,
            c.tenant,
            &request,
            (service, id),
            |ctx, tx| {
                Box::pin(async move {
                    execution::recovery::recover_one(ctx.0, tx, ctx.1).await?;
                    Ok(execution::storage::read_run(tx, ctx.1).await?.state)
                })
            },
        )
        .await
    }
    let current = recover(c, &runtime, &audit, &service, id).await?;
    assert_eq!(current.execution, Execution::NotStarted);
    assert_eq!(
        current.cancellation,
        Cancellation::None,
        "DA-owned recovery must not classify the real Agent registration as missing from rss_da"
    );
    let current_credential =
        recover_credential(c, &runtime, &audit, &credential, credential_id).await?;
    assert_eq!(current_credential.execution, Execution::NotStarted);
    assert_eq!(
        current_credential.cancellation,
        Cancellation::None,
        "RSS credential recovery also reads transport registration from the Agent owner"
    );
    sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant)
        .bind(agent.registration())
        .execute(&c.operator)
        .await?;
    let retired_agent = recover(c, &runtime, &audit, &service, id).await?;
    assert_eq!(retired_agent.cancellation, Cancellation::Confirmed);
    assert_eq!(
        recover_credential(c, &runtime, &audit, &credential, credential_id)
            .await?
            .cancellation,
        Cancellation::Confirmed
    );
    sqlx::query("UPDATE mdm_access.registrations SET state='active' WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant)
        .bind(agent.registration())
        .execute(&c.operator)
        .await?;
    sqlx::query("UPDATE rss_da.access_runs SET state=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant)
        .bind(id)
        .bind(&original)
        .execute(&c.operator)
        .await?;
    sqlx::query("UPDATE rss_da.credential_runs SET state=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant)
        .bind(credential_id)
        .bind(&original)
        .execute(&c.operator)
        .await?;
    sqlx::query("UPDATE rss_da.registrations SET state='revoked' WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant)
        .bind(binding.registration)
        .execute(&c.operator)
        .await?;
    match recover(c, &runtime, &audit, &service, id).await {
        Ok(retired_da) => assert_ne!(
            retired_da.cancellation,
            Cancellation::None,
            "retired DA cannot retain executable delivery"
        ),
        Err(error) => assert!(matches!(
            error,
            execution::Error::Forbidden | execution::Error::Conflict
        )),
    }
    assert_eq!(
        recover_credential(c, &runtime, &audit, &credential, credential_id)
            .await?
            .cancellation,
        Cancellation::Confirmed,
        "retired DA material authority withdraws an otherwise live Agent credential run"
    );
    sqlx::query("UPDATE rss_da.registrations SET state='active' WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant)
        .bind(binding.registration)
        .execute(&c.operator)
        .await?;
    drop(service);
    drop(credential);
    runtime.close().await;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "reuse one real Agent, DA binding and original worker transaction resources"
)]
async fn credential_run(
    c: &Context,
    agent: &DevicePrincipal,
    binding: &access::Binding,
    protection: Arc<recovery::Protection>,
    runtime: &Arc<rss_transactional_messaging_postgres::PgRuntime>,
    audit: &Arc<rss_mdm_audit_integration::AuditStore>,
    state: &serde_json::Value,
    at: i64,
) -> Result<(recovery::tasks::Service, Uuid)> {
    use recovery::tasks;
    let product = Arc::new(pg::recovery::eligibility::AccessEligibility { admission: None });
    let service = tasks::Service::new(
        tasks::Transactions::bind(
            StorageProfile::Da,
            runtime.clone(),
            c.tenant,
            audit.clone(),
            Arc::new(tasks::Materials {
                product: Some(product),
                agent_store: Arc::new(
                    rss_mdm_agent_channel::enrollment_facts::EnrollmentFacts::new(
                        StorageProfile::Mdm,
                    ),
                ),
                source: Arc::new(rss_mdm_scope_service::registration::EnrollmentSources(
                    Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
                        StorageProfile::Mdm,
                        Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
                    )),
                )),
                capacity: Arc::new(crate::assembly::capacity::Capacity),
                recovery_credentials: protection,
            }),
        )
        .await?,
    );
    let operation = rss_mdm_policy::CredentialOperation::RotateRssLogin {
        binding: binding.id,
        binding_generation: binding.generation,
        sid: SID.into(),
    };
    let schedule = rss_mdm_policy::schedule::Schedule {
        trigger: rss_mdm_policy::schedule::Trigger::Manual,
        misfire: Default::default(),
        not_before: at - 1,
        until: None,
        jitter_seconds: 0,
        window: None,
    };
    // Recovery reads the frozen policy and current material authority; it does not recreate Scope admission.
    let definition = rss_mdm_policy::Definition {
        custom_event: None,
        alias: None,
        scope: Uuid::new_v4(),
        self_service: None,
        action: rss_mdm_policy::Action::Credential {
            operation: operation.clone(),
            architecture: rss_mdm_policy::Architecture::X86_64,
            schedule: schedule.clone(),
            frequency: rss_mdm_policy::Frequency::OncePerVersion,
            run_lifetime_seconds: 600,
        },
    };
    definition.validate()?;
    let frozen = tasks::policy::Frozen::Credential {
        action: Box::new(tasks::credential_tasks::FrozenCredential {
            operation,
            input: tasks::policy::ExecutionInput {
                platform: rss_mdm_policy::Platform::Windows,
                architecture: rss_mdm_policy::Architecture::X86_64,
                schedule,
                run_lifetime_seconds: 600,
            },
        }),
        frequency: rss_mdm_policy::Frequency::OncePerVersion,
    };
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let id = Uuid::new_v4();
    let anchor = recovery::Binding {
        device: binding.device.clone(),
        registration: binding.registration,
        generation: binding.registration_generation,
        subject: recovery::Subject::RssLogin {
            binding: binding.id,
            binding_generation: binding.generation,
            sid: SID.into(),
        },
    };
    let mut tx = seed(c).await?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1,$2,1,$3,1,'enabled',$4,$5,$6)")
        .bind(binding.tenant).bind(policy).bind(version).bind(serde_json::to_value(definition)?)
        .bind(serde_json::to_value(rss_mdm_authorization_service::Actor::Account { user: c.user(binding.person.principal) })?).bind(at).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1,$2,$3,1,'credential',$4,$5)")
        .bind(binding.tenant).bind(version).bind(policy).bind(serde_json::to_value(frozen)?).bind(vec![11_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.credential_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,available_at,deadline,state,dispatch_fingerprint,created_at,source_objects,origin,material_binding) VALUES($1,$2,$3,$4,$5,$6,'rss-recovery-proof',$7,$8,$9,$10,$7,'[]','\"policy\"',$11)")
        .bind(binding.tenant).bind(id).bind(version).bind(agent.device()).bind(agent.registration()).bind(agent.generation())
        .bind(at).bind(at+600).bind(state).bind(vec![13_u8;32]).bind(serde_json::to_value(anchor)?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((service, id))
}

async fn recover_credential(
    c: &Context,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    audit: &rss_mdm_audit_integration::AuditStore,
    service: &recovery::tasks::Service,
    id: Uuid,
) -> Result<rss_mdm_task_state::RunState, recovery::tasks::Error> {
    let request = rss_mdm_audit_integration::RequestAudit::new(
        StorageProfile::Da,
        c.tenant.to_string(),
        "rss-credential-recovery-proof",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    recovery::tasks::transaction::run(
        audit,
        runtime,
        c.tenant,
        &request,
        (service, id),
        |ctx, tx| {
            Box::pin(async move {
                recovery::tasks::actions::recovery::recover_one(
                    StorageProfile::Da,
                    ctx.0,
                    tx,
                    ctx.1,
                )
                .await?;
                Ok(
                    recovery::tasks::storage::read_run(StorageProfile::Da, tx, ctx.1)
                        .await?
                        .state,
                )
            })
        },
    )
    .await
}
