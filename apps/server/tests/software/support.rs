//! Legal pre-existing materials for Software's transaction seams; no aggregate test service.
use super::*;
use rss_mdm_resource as r;
use std::{collections::BTreeMap, time::Duration};
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
pub fn schedule() -> rss_mdm_policy::schedule::Schedule {
    serde_json::from_value(json!({"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null})).unwrap()
}
pub fn context() -> w::SoftwareExecutionContext {
    serde_json::from_value(json!({"revision":1,"osVersion":[10,0,26100,0],"systemBroker":true,"userHelper":false,"interactiveUser":null,"msixSideload":false,"msixUnsigned":false,"sourceCredentials":[]})).unwrap()
}
pub fn audit(c: &Context) -> RequestAudit {
    RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        c.tenant.to_string(),
        "software_admission",
        AuditIntent::Management,
    )
}
pub async fn software(c: &Context, name: &str) -> Result<r::Version> {
    software_with_export(c, name, r::SoftwareExport::Disabled).await
}
pub async fn software_with_export(
    c: &Context,
    name: &str,
    export: r::SoftwareExport,
) -> Result<r::Version> {
    let source: rss_mdm_software_service::catalog::SourceDefinition = serde_json::from_value(
        json!({"id":"private","revision":"1","protocol":{"kind":"private"}}),
    )?;
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let export_enabled = !matches!(export, r::SoftwareExport::Disabled);
    let signatures = if export_enabled {
        json!([])
    } else {
        json!([{"evidence":{"reference":"reviewed-signature","length":3,"sha256":vec![4;32]},"artifact":"package","mechanism":"authenticode","publisher":"Acme"}])
    };
    let definition: r::SoftwareDefinition = serde_json::from_value(
        json!({"material":{"format":"msi","installer":"package"},"source":source.snapshot()?,"package":"Acme.App","version":"1.2","artifacts":{"package":{"reference":"app-msi","length":3,"sha256":vec![2;32]}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"system","install":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.2"},"upgradeInvocation":invocation},"signatures":signatures,"provenance":{"kind":"private"},"export":export}),
    )?;
    let version = r::Version::new(
        c.tenant,
        r::Id::new(name)?,
        r::Id::new("1")?,
        r::Kind::Software,
        vec![r::Variant::new(
            r::Platform::Windows,
            r::Architecture::X86_64,
            r::Id::new("msi")?,
            r::Declaration::Software { definition },
        )],
    )?;
    if export_enabled {
        rss_mdm_software_service::publication::derive_document(
            &version,
            &[],
            "https://packages.example.test/",
        )?;
    }
    let owner = planning::owner(c, "mdm_resource_runtime").await?;
    let store = rss_mdm_resource_postgres::ResourceStore::new(
        owner.runtime.clone(),
        c.tenant,
        crate::authority_t2_support::deadline(),
    )
    .await?;
    for (revision, command) in [
        (
            0,
            rss_mdm_resource_postgres::Command::Create(r::Kind::Software),
        ),
        (
            1,
            rss_mdm_resource_postgres::Command::Insert(version.clone()),
        ),
    ] {
        store
            .execute(
                &rss_mdm_resource_postgres::Request {
                    id: r::Id::new(Uuid::new_v4().to_string())?,
                    resource: r::Id::new(name)?,
                    expected_storage_revision: revision,
                    as_of: rss_contract::Timepoint::try_from(now())?,
                    command,
                },
                crate::authority_t2_support::deadline(),
            )
            .await?;
    }
    owner.runtime.close().await;
    let lifecycle = |digest| json!({"revision":1,"state":"enabled","operation":Uuid::new_v4(),"actor":"fixture","at":now(),"digest":digest});
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_software.sources(tenant_id,id,revision,definition,lifecycle) VALUES($1::uuid,'private','1',$2,$3) ON CONFLICT DO NOTHING").bind(c.tenant.to_string()).bind(serde_json::to_value(&source)?).bind(lifecycle(source.snapshot()?.sha256)).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_software.versions(tenant_id,resource,version,lifecycle) VALUES($1::uuid,$2,'1',$3)").bind(c.tenant.to_string()).bind(name).bind(lifecycle(version.digest().bytes())).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(version)
}
pub async fn endpoints(
    c: &Context,
) -> Result<(
    owner::Target,
    owner::Target,
    Uuid,
    Uuid,
    rss_mdm_registration_service::DevicePrincipal,
)> {
    let (device, grant) = material::seed_registration(c).await?;
    let caps = vec![
        w::Capability::InventoryCollectionV1,
        w::Capability::TaskExecuteV1,
        w::Capability::SoftwareMsiSystemV1,
    ];
    let principal = material::authenticated_agent(c, grant, &device, caps.clone()).await?;
    let agent = rss_mdm_registration_service::device::endpoints::PrimaryRegistration {
        device: device.clone(),
        channel: rss_mdm_inventory::Channel::Agent,
    };
    let mdm = planning::endpoint(c).await?;
    let native = mdm.members[0].clone();
    let association = Uuid::new_v4();
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_agent.bindings (tenant_id, device, wire_version, capabilities, platform, architecture, execution_context) VALUES (CAST($1 AS uuid), $2, 1, $3, 'windows', 'x86_64', $4)").bind(c.tenant.to_string()).bind(&device).bind(serde_json::to_string(&caps)?).bind(serde_json::to_value(context())?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.associations(tenant_id,id,version,state,evidence,hardware,confirmed_by,confirmed_at) VALUES($1::uuid,$2,1,'confirmed','operator-verified',$3,'fixture',$4)").bind(c.tenant.to_string()).bind(association).bind(json!({})).bind(now()).execute(&mut *tx).await?;
    for target in [&agent, &native] {
        sqlx::query("INSERT INTO mdm_devices.members (tenant_id, association_id, device, channel) VALUES (CAST($1 AS uuid), $2, $3, $4)").bind(c.tenant.to_string()).bind(association).bind(&target.device).bind(target.channel.as_str()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    native_observation(c, native.device.clone()).await?;
    let object = rss_mdm_inventory_service::objects::DeviceObject {
        object: rss_mdm_inventory_service::objects::ObjectRef::Endpoint(device),
        association_version: None,
        verified: true,
        members: vec![agent.clone()],
    };
    let agent_scope = planning::published(c, &object).await?.scope;
    let native_scope = planning::published(c, &mdm).await?.scope;
    let target = |v: rss_mdm_registration_service::device::endpoints::PrimaryRegistration| {
        owner::Target { device: v.device }
    };
    Ok((
        target(agent),
        target(native),
        agent_scope,
        native_scope,
        principal,
    ))
}
pub async fn policy(
    c: &Context,
    resource: &r::Version,
    scope: Uuid,
    channel: rss_mdm_policy::SoftwareChannel,
    stages: Vec<rss_mdm_policy::SoftwareRolloutStage>,
) -> Result<(Uuid, Uuid)> {
    let id = Uuid::new_v4();
    let version = Uuid::new_v4();
    let variants = BTreeMap::from([(
        rss_mdm_policy::SoftwareTarget::WindowsX86_64,
        "msi".to_owned(),
    )]);
    let native = if channel == rss_mdm_policy::SoftwareChannel::Mdm {
        let r::Declaration::Software { definition } = resource.variants()[0].declaration() else {
            unreachable!()
        };
        BTreeMap::from([(
            rss_mdm_policy::SoftwareTarget::WindowsX86_64,
            owner::native::Package::compile(definition, "https://mdm.example.test".into())?,
        )])
    } else {
        BTreeMap::new()
    };
    let action = owner::frozen::FrozenSoftwareAction {
        native_packages: native,
        channel,
        delivery: rss_mdm_policy::SoftwareDelivery::Direct,
        resource: resource.resource().as_str().into(),
        version: resource.label().as_str().into(),
        variants: variants.clone(),
        resource_digest: resource.digest().bytes(),
        intent: rss_mdm_policy::SoftwareIntent::RequiredInstall,
        schedule: schedule(),
        run_lifetime_seconds: 300,
    };
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":scope,"action":{"kind":"software","resource":{"kind":"software","id":resource.resource().as_str(),"version":resource.label().as_str(),"variants":variants},"channel":channel,"delivery":{"kind":"direct"},"intent":"required_install","schedule":schedule(),"runLifetimeSeconds":300,"rollout":{"stages":stages}}}),
    )?;
    definition.validate()?;
    let frozen = serde_json::to_value(owner::frozen::Published::Software {
        action: Box::new(action),
    })?;
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(id).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(actor)?).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint,resource,resource_version) VALUES($1::uuid,$2,$3,1,'software',$4,$5,$6,$7)").bind(c.tenant.to_string()).bind(version).bind(id).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).bind(resource.resource().as_str()).bind(resource.label().as_str()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((id, version))
}
pub fn stage(scope: Uuid) -> rss_mdm_policy::SoftwareRolloutStage {
    rss_mdm_policy::SoftwareRolloutStage {
        id: Uuid::new_v4(),
        scope,
        opens_at: 0,
        minimum_verified_percent: None,
    }
}
pub(super) async fn accept(
    c: &Context,
    a: &super::Fixture,
    policy: Uuid,
    target: &owner::Target,
    id: Uuid,
) -> Result<w::PolicyEventDecision> {
    decision(c, a, policy, target, id, false, None).await
}
pub(super) async fn decision(
    c: &Context,
    a: &super::Fixture,
    policy: Uuid,
    target: &owner::Target,
    id: Uuid,
    rollback: bool,
    barrier: Option<Arc<tokio::sync::Barrier>>,
) -> Result<w::PolicyEventDecision> {
    let audit = Arc::new(
        c.audit
            .on_runtime(
                a.resources.storage.runtime.clone(),
                c.tenant,
                &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6))
                    .control(),
            )
            .await?,
    );
    let reader = rss_mdm_policy_postgres::PolicyReader::bind(
        rss_mdm_install_support::StorageProfile::Mdm,
        a.resources.storage.runtime.clone(),
        c.tenant,
    );
    let request = audit_request(c);
    let saved = std::sync::Mutex::new(None);
    let result = owner::transaction::run(
        &audit,
        &a.resources.storage.runtime,
        c.tenant,
        &request,
        (
            a.software.transactions.clone(),
            target,
            policy,
            reader,
            id,
            &request,
            barrier,
            rollback,
            &saved,
        ),
        |ctx, tx| {
            Box::pin(async move {
                let policy = owner::sources::storage::read_in(&ctx.3, tx, ctx.2)
                    .await?
                    .ok_or(owner::Error::NotFound)?;
                if let Some(barrier) = &ctx.6 {
                    barrier.wait().await;
                }
                let decision = ctx
                    .0
                    .accept_policy_event_in(
                        tx,
                        &policy,
                        ctx.1,
                        (
                            ctx.4,
                            rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
                        ),
                        now() + 300,
                        ctx.5,
                    )
                    .await?;
                if ctx.7 {
                    *ctx.8.lock().unwrap() = Some(decision);
                    return Err(owner::Error::Conflict.into());
                }
                Ok(decision)
            })
        },
    )
    .await;
    match result {
        Err(owner::Error::Conflict) if rollback => saved
            .into_inner()
            .unwrap()
            .ok_or_else(|| anyhow::anyhow!("preflight rejected before admission")),
        other => Ok(other?),
    }
}
pub(super) async fn verified(
    c: &Context,
    a: &super::Fixture,
    resource: &r::Version,
    id: Uuid,
) -> Result<()> {
    use rss_mdm_software_service::preparation::{Delivery, Selection, Target, evidence};
    let prepare = a.software.materials.inputs.software.clone();
    let steps = owner::transaction::inspect(
        &a.resources.storage.runtime,
        c.tenant,
        (
            prepare,
            resource.resource().as_str(),
            resource.label().as_str(),
            resource.digest().bytes(),
        ),
        |ctx, tx| {
            Box::pin(async move {
                ctx.0
                    .prepare_in(
                        tx,
                        &Selection {
                            resource: ctx.1,
                            version: ctx.2,
                            digest: ctx.3,
                            variant: "msi",
                            uninstall: false,
                        },
                        Target {
                            platform: r::Platform::Windows,
                            architecture: r::Architecture::X86_64,
                        },
                        &Delivery::Direct,
                        &context(),
                    )
                    .await?
                    .ok_or(owner::Error::Forbidden.into())
            })
        },
    )
    .await?;
    let definition_digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&steps)?).into();
    let at = now();
    let result = w::SoftwareTaskResult {
        intent: w::SoftwareTaskIntent::Install,
        definition_digest,
        steps: steps
            .iter()
            .enumerate()
            .map(|(index, step)| {
                Ok(w::SoftwareStepResult {
                    step_id: step.step_id,
                    index: index.try_into()?,
                    step_digest: step.digest()?,
                    target: step.target.clone(),
                    package: step.action.package.clone(),
                    identity: evidence::observed_identity(&step.action),
                    before: w::SoftwareDetectionObservation::Absent {
                        evidence_sha256: [3; 32],
                        observed_at: at,
                    },
                    after: w::SoftwareDetectionObservation::Present {
                        version: evidence::detected_version(&step.action),
                        evidence_sha256: [4; 32],
                        observed_at: at,
                    },
                    process: w::SoftwareProcessObservation::Exited { code: 0 },
                    reboot_required: false,
                    diagnostics: w::TaskDiagnostics::new("".into(), "".into(), 1, at, None)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    assert_eq!(
        evidence::assess_execution(
            &result,
            w::SoftwareTaskIntent::Install,
            definition_digest,
            &steps
        )?,
        evidence::SoftwareEvidenceAssessment::Satisfied
    );
    let deadline:i64=sqlx::query_scalar("SELECT deadline FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    let attempt = Uuid::new_v4();
    let mut state = rss_mdm_task_state::RunState::new(deadline, at)?;
    state.claim(attempt, at)?;
    state.received(attempt, at)?;
    state.start(attempt, at)?;
    state.result(attempt, true)?;
    let result = owner::actions::result::RunResult::Software(owner::actions::result::Software {
        intent: result.intent,
        definition_digest,
        evidence: result,
        effect: w::SelfServiceSoftwareEffect::Verified,
        effect_observed_at: Some(at * 1_000_000),
        effect_received_at: at * 1_000_000,
        received_at: at,
    });
    let mut tx = command::seed_transaction(c).await?;
    assert_eq!(sqlx::query("UPDATE mdm_software_deployment.action_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).bind(serde_json::to_value(state)?).bind(serde_json::to_value(result)?).execute(&mut *tx).await?.rows_affected(),1);
    tx.commit().await?;
    Ok(())
}

fn audit_request(c: &Context) -> RequestAudit {
    audit(c)
}

async fn native_observation(c: &Context, registration: String) -> Result<()> {
    use rss_mdm_inventory::*;
    let tenant = c.tenant;
    let at = now();
    let report = Uuid::new_v4();
    let mut tx = command::seed_transaction(c).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND source = 'mdm.windows'").bind(tenant.to_string()).bind(&registration).fetch_one(&mut *tx).await?;
    let field = builtin::fields()
        .into_iter()
        .find(|f| f.key == builtin::AGENT_INSTALLATION)
        .unwrap();
    let catalog = rss_mdm_inventory_postgres::catalog_in(&mut tx, tenant).await?;
    if catalog.definition(field.key).is_err() {
        assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, tenant, 0, &field).await?);
    }
    let key = field.key;
    let definition = CollectionDefinition::new(
        key.as_str(),
        1,
        Source::MdmWindows,
        vec![CollectionField {
            definition: field,
            scope: CollectionScope::Device,
        }],
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, tenant, &definition).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        rss_mdm_install_support::StorageProfile::Mdm,
        tenant,
        &registration,
        "mdm.windows",
        epoch,
        key.as_str(),
    )?;
    let value = Scalar::String("absent".into());
    let progress = CollectionProgress::native(
        definition.clone(),
        [(
            key,
            NativeValue::Value(CollectedValue::Value(value.clone())),
        )]
        .into(),
        at,
    )?;
    let (sequence, _) = rss_mdm_registration_service::device::store::allocate_report_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        &tenant.to_string(),
        &registration.to_string(),
        ReportSource::MdmWindows,
        &epoch.to_string(),
        1,
        i64::from(u32::MAX),
    )
    .await?
    .unwrap();
    let batch = rss_mdm_inventory_postgres::seal_collection_in(
        &mut tx,
        rss_mdm_inventory_postgres::CollectionCompletion {
            trusted: true,
            scope: &scope,
            run: &report.to_string(),
            sequence: sequence.try_into()?,
            observed_at: at,
            progress: &progress,
        },
    )
    .await?;
    let evidence = rss_mdm_inventory::channel::AgentEvidence {
        catalog_digest: [0; 32],
        provisioned: false,
        checked_identities: vec![],
        identity: "".into(),
        publisher: None,
        version: None,
        architecture: Some("x86_64".into()),
    };
    sqlx::query("INSERT INTO mdm_access.collection_runs (tenant_id, id, device, source, epoch, scope, sequence, started_at, attempts, result, reason, batch, digest, sealed_at, delivery_pending, evidence) VALUES (CAST($1 AS uuid), $2, $3, 'mdm.windows', $4, $5, $6, $7, $8, 'snapshot', 'complete', $9, $10, $7, FALSE, $11)").bind(tenant.to_string()).bind(report).bind(&registration).bind(epoch).bind(scope.encode()?).bind(sequence).bind(at).bind(serde_json::to_string(&progress)?).bind(batch.encode()).bind(batch.fingerprint(&scope)?.iter().map(|b|format!("{b:02x}")).collect::<String>()).bind(serde_json::to_value(evidence)?).execute(&mut *tx).await?;
    let projection = rss_mdm_inventory_postgres::projection_scope(tenant);
    sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence,field_scope) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$9,'known',$10,'mdm.windows',$11,$12,$13)").bind(tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(key.as_str()).bind(serde_json::to_string(&value)?).bind(report.to_string()).bind(at).bind(registration.to_string()).bind(epoch.to_string()).bind(sequence).bind(CollectionScope::Device.canonical()?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
