//! Minimal pre-existing published installer and issued Bootstrap; actual admission stays in production.
use super::*;
use identity::Native;
use rss_mdm_native_protection::{ProtectionContext, Protector};
use rss_mdm_resource as r;
use rss_mdm_software_service::installation::package::{FrozenInstall, Identity, Package};
use serde::Serialize;
pub struct Materials {
    pub directory: std::path::PathBuf,
    pub serial: String,
    pub certificate: Vec<u8>,
    pub csr: Vec<u8>,
}
pub async fn materials(
    c: &Context,
    n: &Native,
    installation: Uuid,
    bootstrap: Uuid,
) -> Result<Materials> {
    let out = tokio::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hack/native_registration_materials.py"
        ))
        .arg(&c.inputs.directory)
        .arg(&n.directory)
        .arg(installation.to_string())
        .arg(bootstrap.to_string())
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "bootstrap material: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout)?;
    let directory = std::path::PathBuf::from(value["directory"].as_str().unwrap());
    Ok(Materials {
        serial: value["serial"].as_str().unwrap().into(),
        certificate: identity::der("x509", &directory.join("bootstrap.pem")).await?,
        csr: identity::der("req", &directory.join("runtime.csr")).await?,
        directory,
    })
}
struct Clock;
impl agent_pki::Clock for Clock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_registration_service::Error> {
        Ok(now())
    }
}
pub fn service(
    c: &Context,
    n: &Native,
    authority: Arc<rss_mdm_software_service::deployment::managed_registration::AuthorityReader>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    m: &Materials,
) -> Result<agent::Service> {
    use rss_mdm_agent_wire::pki::Purpose;
    use rss_mdm_pki_service::{
        Configuration, StepCa,
        providers::{Provider, Providers},
    };
    let mut trust = n.trust.clone();
    trust.purpose = Purpose::Agent;
    let trust = Arc::new(
        rss_mdm_device_trust::device_identity::DeviceIdentityTrust::from_trust(
            rss_mdm_device_trust::DeviceTrust::new(trust, Purpose::Agent, now())?,
            2,
        )?,
    );
    let digest = format!("{:x}", Sha256::digest(&n.root));
    let client = Arc::new(StepCa::new(
        Configuration {
            origin: "https://localhost".into(),
            provisioner: "rss-agent".into(),
            kid: "task-trust".into(),
        },
        &std::fs::read(c.inputs.directory.join("task-trust-ca/ca.pem"))?,
        &std::fs::read(m.directory.join("provider.pk8"))?,
    )?);
    let providers = Arc::new(Providers::new(vec![Provider {
        purpose: Purpose::Agent,
        issuer: digest.clone(),
        client,
        scep_url: None,
    }])?);
    let clock = Arc::new(Clock);
    let issuer = Arc::new(agent_pki::DeviceIssuer::new(
        rss_mdm_install_support::StorageProfile::Mdm,
        providers,
        2,
        true,
        trust,
        clock.clone(),
    )?);
    let mut trust = n.trust.clone();
    trust.purpose = Purpose::AgentBootstrap;
    let bootstrap = agent::bootstrap::Configuration {
        trust: rss_mdm_device_trust::DeviceTrust::new(trust, Purpose::AgentBootstrap, now())?,
        webhooks: rss_mdm_pki_service::scep::Verifier::new(vec![
            rss_mdm_pki_service::scep::Credentials {
                issuer: digest,
                challenge_id: "challenge".into(),
                notify_id: "notify".into(),
                challenge_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[7; 32]),
                notify_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[8; 32]),
            },
        ])?,
    };
    Ok(agent::Service::new(agent::Assembly {
        cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &[9; 32],
        )),
        tenant: c.tenant,
        store: c.database.registration(),
        audit: c.audit.clone(),
        issuer,
        clock,
        binding: Arc::new(rss_mdm_agent_channel::Bindings::new(
            rss_mdm_install_support::StorageProfile::Mdm,
        )),
        native: Some(authority),
        bootstrap: Some(Arc::new(bootstrap)),
        protection,
        installations: Some(Arc::new(crate::agent_configurations::Installations)),
    })?)
}
pub async fn counts(c: &Context) -> Result<(i64, i64)> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_access.certificate_grants WHERE tenant_id=$1::uuid AND source='native')").bind(c.tenant.to_string()).fetch_one(&c.operator).await?)
}
#[derive(Serialize)]
struct InputIdentity<'a> {
    operation: Uuid,
    device: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    platform: String,
    deadline: i64,
    input_version: String,
    target: owner::NativeTarget,
}
#[expect(
    clippy::cognitive_complexity,
    reason = "legal prior installation facts use one fixture transaction and real protected protocol bytes"
)]
pub async fn installation(
    c: &Context,
    n: &Native,
    key: &Protector,
    id: Uuid,
    bootstrap: Uuid,
    m: &Materials,
) -> Result<()> {
    let resource = software(c, "registered-agent").await?;
    let r::Declaration::Software { definition } = resource.variants()[0].declaration() else {
        unreachable!()
    };
    let spec = definition.spec();
    let artifact = spec.artifacts["package"].clone();
    let release = Uuid::new_v4();
    let package = Package {
        release: wire::configuration::Installation {
            release_id: release,
        },
        identity: Identity::WindowsMsi {
            product: Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")?,
            publisher: Some("Acme".into()),
        },
        target: rss_mdm_policy::SoftwareTarget::WindowsX86_64,
        version: spec.version.clone(),
        artifact: artifact.clone(),
        source: spec.source.clone(),
    };
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let frozen = owner::frozen::Published::AgentInstall {
        action: Box::new(FrozenInstall {
            schedule: schedule(),
            run_lifetime_seconds: 300,
            packages: BTreeMap::from([(package.target, package.clone())]),
            actor: actor.clone(),
        }),
    };
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let deadline = now() + 300;
    let input = owner::Create {
        operation_id: id,
        input_version: "1".into(),
        target: owner::NativeTarget::Device,
        task: package.native_task(id, "https://localhost")?,
        deadline,
    };
    let metadata = Metadata {
        platform: "windows".into(),
        deadline,
        input_version: input.input_version.clone(),
        target: input.target.clone(),
    };
    let owner = serde_json::to_string(&InputIdentity {
        operation: id,
        device: &n.device,
    })?;
    let field = serde_json::to_string(&("native.operation.input/v1", &metadata))?;
    let sealed = key.seal_bytes(
        &serde_json::to_vec(&input)?,
        &ProtectionContext::new(c.tenant, &owner, &field, 1)?.derive(),
    )?;
    let authority = owner::authority::Authority::AgentInstall {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
        source_objects: vec![],
        required: vec![rss_mdm_authorization_service::Permission::SoftwareDeploy],
        package: Box::new(package),
        download_origin: "https://localhost".into(),
        tenant: c.tenant.to_string(),
        policy,
        version,
        device: n.device.clone(),
        operation: id,
    };
    let object = rss_mdm_inventory_service::objects::DeviceObject {
        object: rss_mdm_inventory_service::objects::ObjectRef::Endpoint(n.device.clone()),
        association_version: None,
        verified: true,
        members: vec![
            rss_mdm_registration_service::device::endpoints::PrimaryRegistration {
                device: n.device.clone(),
                channel: rss_mdm_inventory::Channel::Mdm,
            },
        ],
    };
    let scope = crate::planning_t2_support::published(c, &object)
        .await?
        .scope;
    let mut tx = command::seed_transaction(c).await?;
    agent::settings::initialize_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        &c.tenant.to_string(),
    )
    .await?;
    let lifecycle = rss_mdm_software_service::catalog::binding_on(
        &mut tx,
        c.tenant,
        resource.resource().as_str(),
        "1",
        resource.digest().bytes(),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("reviewed installer binding not admitted"))?;
    let document = wire::configuration::Package {
        release_id: release,
        tenant_id: Uuid::parse_str(&c.tenant.to_string())?,
        target: wire::configuration::Target {
            platform: w::TaskPlatform::Windows,
            architecture: w::TaskArchitecture::X86_64,
        },
        version: spec.version.clone(),
        format: wire::configuration::InstallerFormat::WindowsMsi,
        filename: "agent.msi".into(),
        length: artifact.length,
        installer_sha256: artifact.sha256,
    };
    let binding = json!({"variant":"msi","software":spec,"resource":resource.resource().as_str(),"version":"1","digest":resource.digest().bytes(),"lifecycle":lifecycle,"installer":artifact});
    sqlx::query("INSERT INTO mdm_agent_packages.releases(tenant_id,id,document,binding,state) VALUES($1::uuid,$2,$3,$4,'published')").bind(c.tenant.to_string()).bind(release).bind(serde_json::to_value(document)?).bind(binding).execute(&mut *tx).await?;
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":scope,"action":{"kind":"ensure_agent_installed","packages":{"windows_x86_64":release},"schedule":schedule(),"runLifetimeSeconds":300}}),
    )?;
    definition.validate()?;
    let definition = serde_json::to_value(definition)?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(definition).bind(serde_json::to_value(actor)?).bind(now()).execute(&mut *tx).await?;
    let frozen = serde_json::to_value(frozen)?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'ensure_agent_installed',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    let command_device = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.command_authorities (tenant_id, device, command_device, generation, epoch) VALUES (CAST($1 AS uuid), $2, $3, 1, 1)").bind(c.tenant.to_string()).bind(&n.device).bind(command_device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1)").bind(c.tenant.to_string()).bind(command_device).execute(&mut *tx).await?;
    let fingerprint = input.digest(key, c.tenant, &n.device)?.as_bytes().to_vec();
    sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) VALUES($1::uuid,$2,$3,1,1,$4,$5,$6,'mdm.software.deployment.v1',$2,$4,'published',$6,2)").bind(c.tenant.to_string()).bind(id.to_string()).bind(command_device).bind(&fingerprint).bind(deadline*1_000_000).bind(now()*1_000_000).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_software_deployment.operations (tenant_id, id, device, request, input_context, fingerprint, generation, epoch, authority, dispatch_fingerprint, gateway_accepted, policy_version, observed_command_version) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, 1, 1, $7, $6, TRUE, $8, 2)").bind(c.tenant.to_string()).bind(id).bind(&n.device).bind(sealed).bind(serde_json::to_value(metadata)?).bind(&fingerprint).bind(serde_json::to_value(authority)?).bind(version).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_windows.native_commands (tenant_id, id, device) VALUES (CAST($1 AS uuid), $2, $3)").bind(c.tenant.to_string()).bind(id).bind(n.device.clone()).execute(&mut *tx).await?;
    let attempt = Uuid::new_v4();
    let owner::Task::Windows {
        request: rss_mdm_windows_mdm::native::Execution::Msi { job },
    } = &input.task
    else {
        anyhow::bail!("expected MSI installation");
    };
    let native = rss_mdm_windows_mdm::software::Installer::new(job.clone())?.install(1)?;
    let message = rss_mdm_windows_mdm::syncml::Message {
        header: rss_mdm_windows_mdm::syncml::Header {
            session_id: 1,
            message_id: 1,
            target: n.device.clone(),
            source: "https://localhost/windows/management".into(),
            credential: None,
            meta: None,
        },
        commands: vec![native],
        final_message: true,
    };
    let (wire, _) = rss_mdm_windows_mdm::syncml::encode_request(
        &message,
        &rss_mdm_windows_mdm::CodecLimits::default(),
    )?;
    let request = key.seal_bytes(
        &wire,
        &ProtectionContext::new(
            c.tenant,
            &serde_json::to_string(&(&n.device, n.epoch, attempt))?,
            "windows.attempt.request",
            1,
        )?
        .derive(),
    )?;
    sqlx::query("INSERT INTO mdm_windows.attempts (tenant_id, id, operation, device, ordinal, credential, session, message, phase, request, protocol_epoch) VALUES (CAST($1 AS uuid), $2, $3, $4, 1, $5, 1, 1, 'execute', $6, $7)").bind(c.tenant.to_string()).bind(attempt).bind(id).bind(n.device.clone()).bind(n.credential).bind(request).bind(n.epoch).execute(&mut *tx).await?;
    let digest = format!("{:x}", Sha256::digest(&n.root));
    let body = serde_json::to_vec(&n.trust)?;
    sqlx::query("INSERT INTO mdm_pki.issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'windows',$2,1,'active',$3,'step_ca',$4)").bind(c.tenant.to_string()).bind(&digest).bind(&n.root).bind(now()+86400).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.trust(tenant_id,purpose,revision,body) VALUES($1::uuid,'windows',1,$2)").bind(c.tenant.to_string()).bind(&body).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.certificates (tenant_id, purpose, fingerprint, issuer, serial, device, not_after, certificate, verification_version, verification_trust) VALUES (CAST($1 AS uuid), 'windows', $2, $3, $4, $5, $6, $7, 1, $8)").bind(c.tenant.to_string()).bind(Sha256::digest(&n.certificate).to_vec()).bind(&digest).bind(&m.serial).bind(n.device.clone()).bind(now()+3600).bind(&n.certificate).bind(Sha256::digest(&body).to_vec()).execute(&mut *tx).await?;
    let facts = rss_mdm_registration_service::installation::Installation {
        id,
        policy,
        version,
        device: n.device.clone(),

        platform: rss_mdm_policy::Platform::Windows,
        source: rss_mdm_inventory::ReportSource::MdmWindows,
        release,
        deadline,
        input_version: "1".into(),
        download_origin: "https://localhost".into(),
        origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
    };
    let source = json!({"installation":id,"device":n.device.clone(),"credential":n.credential,"source":"mdm.windows","runtime":null,"bootstrap":bootstrap});
    sqlx::query("INSERT INTO mdm_access.agent_bootstraps(tenant_id,id,installation,installation_facts,delivery,source,release,issuer,provisioner,download_origin,challenge,deadline,state,fingerprint,certificate) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,'rss-agent','https://localhost',$9,$10,'issued',$11,$12)").bind(c.tenant.to_string()).bind(bootstrap).bind(id).bind(serde_json::to_value(facts)?).bind(Uuid::new_v4()).bind(source).bind(release).bind(digest).bind(vec![7u8;32]).bind(deadline).bind(Sha256::digest(&m.certificate).to_vec()).bind(&m.certificate).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn bootstrap(c: &Context, id: Uuid) -> Result<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('state',state,'source',source,'fingerprint',encode(fingerprint,'hex'),'deadline',deadline) FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?)
}
