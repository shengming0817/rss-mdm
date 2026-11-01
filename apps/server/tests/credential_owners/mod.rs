//! Each owner is bound directly to the real host transaction, without the Execution factory.
use crate::{authority_t2_support::Context, device_material_support as material};
use anyhow::Result;
use rss_mdm_recovery_credentials as recovery;
use rss_mdm_registration_service::device_access::execution as access;
use std::sync::Arc;
use uuid::Uuid;
mod credentials;
mod registration;
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
async fn seed(c: &Context) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    let mut tx = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
fn keys(active: &str) -> Result<recovery::KeyRing> {
    Ok(recovery::KeyRing::new(
        active.into(),
        vec![
            ("old".into(), zeroize::Zeroizing::new(vec![31; 32])),
            ("new".into(), zeroize::Zeroizing::new(vec![47; 32])),
        ],
    )?)
}
pub(super) fn protection(c: &Context, active: &str) -> Result<Arc<recovery::Protection>> {
    let dir = c.inputs.directory.join("task-trust-ca");
    let recipient = recovery::Recipient::from_pem(
        &std::fs::read(dir.join("ca.pem"))?,
        &std::fs::read(dir.join("ca.key"))?,
    )?;
    Ok(Arc::new(recovery::Protection::new(
        keys(active)?,
        recipient.id().into(),
        vec![recipient],
    )?))
}
struct Owners {
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    access: Arc<access::Service>,
    maintenance: recovery::maintenance::Maintenance,
}
impl Owners {
    async fn open(
        c: &Context,
        profile: &str,
        credentials: Arc<recovery::Protection>,
    ) -> Result<Self> {
        let (pg, binding) = crate::identity::runtime_inputs(
            &c.inputs.database(profile, "mdm_command_runtime"),
            &c.inputs.installation.target,
            &c.inputs.installation.lineage,
            &[(c.tenant, 1)],
        )?;
        let runtime = Arc::new(
            rss_transactional_messaging_postgres::PgRuntime::connect(
                pg.with_pool_limits(0, 4),
                crate::lifecycle::RuntimeTimer,
                binding,
            )
            .await?,
        );
        let budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
        let audit = Arc::new(
            c.audit
                .on_runtime(runtime.clone(), c.tenant, &budget.control())
                .await?,
        );
        let native = material::protection(c)?;
        let source = Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
        ));
        let materials = Arc::new(access::Materials {
            agent_store: Arc::new(super::registration_agent_facts::AgentFacts::new(
                rss_mdm_install_support::StorageProfile::Mdm,
            )),
            source: Arc::new(super::registration_sources::Source(source)),
            capacity: Arc::new(super::capacity::Capacity),
            recovery: Some(Arc::new(recovery::access::AccessMaterials::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                credentials.clone(),
                Arc::new(super::recovery_eligibility::AccessEligibility { admission: None }),
            ))),
            platform: Arc::new(super::access_execution::Platform(
                rss_mdm_apple_channel::flow_store::Store {
                    protection: native.clone(),
                },
            )),
        });
        let access = Arc::new(access::Service::new(
            access::Transactions::bind(runtime.clone(), c.tenant, audit.clone(), materials).await?,
        ));
        let copies = recovery::native::inputs::Copies::bind(
            runtime.clone(),
            c.tenant,
            native.clone(),
            Arc::new(rss_mdm_apple_channel::flow_store::Store { protection: native }),
        )
        .await?;
        let maintenance = recovery::maintenance::Maintenance::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            runtime.clone(),
            c.tenant,
            audit.clone(),
            credentials,
            Some(Arc::new(copies)),
            Arc::new(tokio::sync::Semaphore::new(2)),
            Some(Arc::new(super::recovery_eligibility::AccessEligibility {
                admission: None,
            })),
        );
        Ok(Self {
            runtime,
            access,
            maintenance,
        })
    }
    async fn close(self) {
        self.runtime.close().await;
    }
}
async fn candidate(c: &Context, keys: &recovery::KeyRing) -> Result<(recovery::Coordinates, Uuid)> {
    let (registration, _, device) = material::seed_registration(c).await?;
    let binding = recovery::Binding {
        device,
        registration,
        generation: 2,
        subject: recovery::Subject::LocalAdministrator {
            sid: "S-1-5-21-1-2-3-500".into(),
        },
    };
    let operation = Uuid::new_v4();
    let mut tx = seed(c).await?;
    let coordinate = recovery::storage::reserve_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        Uuid::parse_str(&c.tenant.to_string())?,
        &binding,
        operation,
        0,
    )
    .await?;
    recovery::storage::ingest_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        keys,
        &coordinate,
        operation,
        b"Owner-test-Password!42",
    )
    .await?;
    tx.commit().await?;
    Ok((coordinate, operation))
}

async fn native_candidate(
    c: &Context,
    keys: &recovery::KeyRing,
) -> Result<(recovery::Coordinates, Uuid)> {
    let n = crate::native_identity_t2_support::seed(c, "apple").await?;
    let binding = recovery::Binding {
        device: n.device,
        registration: n.registration,
        generation: 1,
        subject: recovery::Subject::RecoveryLock,
    };
    let operation = Uuid::new_v4();
    let mut tx = seed(c).await?;
    let coordinate = recovery::storage::reserve_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        Uuid::parse_str(&c.tenant.to_string())?,
        &binding,
        operation,
        0,
    )
    .await?;
    recovery::storage::ingest_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        keys,
        &coordinate,
        operation,
        b"Owner-test-Password!42",
    )
    .await?;
    tx.commit().await?;
    Ok((coordinate, operation))
}
// Minimal persisted delivery input and channel copy. The real copy owners decrypt and scrub both.
async fn input_copy(
    c: &Context,
    coordinate: &recovery::Coordinates,
    operation: Uuid,
) -> Result<Uuid> {
    use rss_mdm_native_protection::ProtectionContext;
    use serde_json::json;
    let key = material::protection(c)?;
    let account = c
        .account(&[rss_mdm_authorization_service::Permission::SecurityOperate])
        .await?;
    let proof = c.authenticate(&account).await?;
    let binding = &coordinate.binding;
    let authority = recovery::native::authority::Authority::admitted(
        proof.authorization()?,
        &proof,
        &binding.device,
        binding.registration,
        binding.generation,
        operation,
        vec![rss_mdm_authorization_service::Permission::SecurityOperate],
    )?;
    let input: recovery::native::Create = serde_json::from_value(
        json!({"operationId":operation,"inputVersion":"credential-v1","deadline":now()+300,"target":{"kind":"device"},"task":{"platform":"macos","request":{"kind":"command","command":{"requestType":"SetRecoveryLock","fields":{"NewPassword":{"type":"string","value":"Owner-test-Password!42"}}}}}}),
    )?;
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        operation: Uuid,
        device: &'a str,
        registration: Uuid,
        generation: i64,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Metadata<'a> {
        platform: &'a str,
        deadline: i64,
        input_version: &'a str,
        target: &'a recovery::native::NativeTarget,
    }
    let meta = Metadata {
        platform: "macos",
        deadline: input.deadline,
        input_version: &input.input_version,
        target: &input.target,
    };
    let owner = serde_json::to_string(&Identity {
        operation,
        device: &binding.device,
        registration: binding.registration,
        generation: binding.generation,
    })?;
    let field = serde_json::to_string(&("native.operation.input/v1", &meta))?;
    let sealed = key.seal_bytes(
        &serde_json::to_vec(&input)?,
        &ProtectionContext::new(c.tenant, &owner, &field, 1)?.derive(),
    )?;
    let command_device = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let mut tx = seed(c).await?;
    sqlx::query("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch,registration,registration_generation) VALUES($1,$2,$3,1,1,$4,1)").bind(coordinate.tenant).bind(&binding.device).bind(command_device).bind(binding.registration).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1,$2,1,1)").bind(coordinate.tenant).bind(command_device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) VALUES($1,$2,$3,1,1,$4,$5,$6,'mdm.recovery.native.v1',$2,$4,'published',$6,2)").bind(coordinate.tenant).bind(operation.to_string()).bind(command_device).bind(vec![1u8;32]).bind(input.deadline*1_000_000).bind(now()*1_000_000).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_recovery_tasks.operations(tenant_id,id,device,request,input_context,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,gateway_accepted) VALUES($1,$2,$3,$4,$5,$6,$7,1,1,1,$8,$6,true)").bind(coordinate.tenant).bind(operation).bind(&binding.device).bind(sealed).bind(serde_json::to_value(meta)?).bind(vec![1u8;32]).bind(binding.registration).bind(serde_json::to_value(authority)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_apple.native_commands(tenant_id,id,registration,registration_generation) VALUES($1,$2,$3,1)").bind(coordinate.tenant).bind(operation).bind(binding.registration).execute(&mut *tx).await?;
    let mut command = plist::Dictionary::new();
    command.insert("RequestType".into(), "SetRecoveryLock".into());
    command.insert("NewPassword".into(), "Owner-test-Password!42".into());
    let mut plist = plist::Dictionary::new();
    plist.insert("Command".into(), plist::Value::Dictionary(command));
    plist.insert("CommandUUID".into(), attempt.to_string().into());
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &plist)?;
    let aad = ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(binding.registration, 1i64, attempt))?,
        "apple.attempt.request",
        1,
    )?
    .derive();
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,operation,phase,ordinal,request,state,deadline) VALUES($1,$2,$3,1,$4,'execute',0,$5,'sent',clock_timestamp()+interval '5 minutes')").bind(coordinate.tenant).bind(attempt).bind(binding.registration).bind(operation).bind(key.seal_bytes(&bytes,&aad)?).execute(&mut *tx).await?;
    recovery::storage::link_native_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        &mut tx,
        coordinate.tenant,
        operation,
        binding,
        &recovery::storage::NativeAction {
            reconciles: None,
            action: "set_recovery_lock".into(),
            coordinates: Some(coordinate.clone()),
            recipient: String::new(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(attempt)
}
