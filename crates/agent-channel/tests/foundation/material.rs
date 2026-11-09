//! Task Trust owns its minimal legal trust rows. No production action is a fixture.
use super::Context;
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::task_trust::{KeyState, PublicKey, Trust};
use rss_mdm_native_protection::{ProtectionContext, Protector};
use std::sync::Arc;
use uuid::Uuid;

pub fn protection(c: &Context) -> Result<Arc<Protector>> {
    Ok(Arc::new(Protector::with_fingerprint(
        &std::fs::read(c.inputs.directory.join("native.key"))?,
        &[],
        &std::fs::read(c.inputs.directory.join("fingerprint.key"))?,
    )?))
}
pub async fn seed_trust(c: &Context, protection: &Protector, states: &[KeyState]) -> Result<Trust> {
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let operation = Uuid::new_v4();
    let mut tx = c.operator.begin().await?;
    let mut trust = Trust {
        version: 1,
        service_id: Uuid::parse_str(&c.inputs.installation.instance_id)?,
        tenant,
        revision: 1,
        keys: vec![],
    };
    for state in states {
        let key_id = Uuid::new_v4().to_string();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("key generation"))?;
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| anyhow::anyhow!("key import"))?;
        let aad = ProtectionContext::new(
            c.tenant,
            &format!("da:{key_id}"),
            "task-signing.private-key",
            1,
        )?
        .derive();
        let sealed = protection.seal_bytes(pkcs8.as_ref(), &aad)?;
        sqlx::query(
            "INSERT INTO rss_da.signing_keys(usage,tenant_id,key_id,private_key) VALUES('agent_task',$1,$2,$3)",
        )
        .bind(tenant)
        .bind(&key_id)
        .bind(sealed)
        .execute(&mut *tx)
        .await?;
        trust.keys.push(PublicKey {
            id: key_id,
            public_key: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
            state: *state,
        });
    }
    trust.keys.sort_by(|a, b| a.id.cmp(&b.id));
    trust.validate()?;
    let aad = ProtectionContext::new(
        c.tenant,
        &format!("da:{operation}"),
        "task-signing.operation",
        1,
    )?
    .derive();
    let fingerprint = protection.mac(b"isolated legal trust seed", &aad)?;
    sqlx::query(
        "INSERT INTO rss_da.signing_heads(tenant_id,usage,revision) VALUES($1,'agent_task',1)",
    )
    .bind(tenant)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO rss_da.signing_versions(usage,tenant_id,revision,operation_id,fingerprint_key,fingerprint,body,digest) VALUES('agent_task',$1,1,$2,$3,$4,$5,$6)")
        .bind(tenant).bind(operation).bind(protection.fingerprint_id()).bind(fingerprint.as_slice()).bind(serde_json::to_value(&trust)?).bind(trust.installation_digest()?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(trust)
}
pub async fn seed_registration(c: &Context) -> Result<(String, Uuid)> {
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let grant = Uuid::new_v4();
    let device = Uuid::new_v4().to_string();
    let mut tx = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rss_da.certificate_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) VALUES($1,$2,$2,'download','seed',$3,$4,'windows',repeat('0',64),repeat('1',64),'consumed',clock_timestamp()+interval '1 hour')")
        .bind(tenant).bind(grant).bind(&c.inputs.installation.instance_id).bind(&device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.devices (tenant_id, id, channel, certificate_grant_id, state, purpose, epoch) VALUES ($1, $2, 'agent', $3, 'active', 'primary', $4)")
        .bind(tenant).bind(&device).bind(grant).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((device, grant))
}
pub async fn seed_ack(c: &Context, trust: &Trust, device: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO rss_da.signing_acknowledgements (tenant_id,usage,operation_id,device,revision,digest) VALUES($1::uuid,'agent_task',$2,$3,$4,$5)",
    )
    .bind(c.tenant.to_string())
    .bind(Uuid::new_v4())
    .bind(device)
    .bind(trust.revision as i64)
    .bind(trust.installation_digest()?)
    .execute(&c.operator)
    .await?;
    Ok(())
}

async fn agent_material(
    c: &Context,
    device: &str,
) -> Result<(
    rss_mdm_device_trust::device_identity::VerifiedDevicePeer,
    Vec<u8>,
    Vec<u8>,
    rss_mdm_device_trust::device_identity::DeviceIdentityTrust,
    rss_mdm_certificate::ClientCertificateEvidence,
)> {
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest, Sha256};
    let output = tokio::process::Command::new("python3")
        .args([
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../hack/task_trust_materials.py"
            ),
            c.inputs.directory.to_str().unwrap(),
            &c.tenant.to_string(),
            device,
        ])
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "Agent certificate material: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let paths: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    async fn der(kind: &str, path: &str) -> Result<Vec<u8>> {
        let out = tokio::process::Command::new("openssl")
            .args([kind, "-in", path, "-outform", "DER"])
            .output()
            .await?;
        anyhow::ensure!(out.status.success(), "certificate conversion");
        Ok(out.stdout)
    }
    let root = der("x509", paths["root"].as_str().unwrap()).await?;
    let crl = der("crl", paths["crl"].as_str().unwrap()).await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let trust: rss_mdm_agent_wire::pki::Trust = serde_json::from_value(serde_json::json!({
        "version":1,"service_id":c.inputs.installation.instance_id,"origin":"https://mdm.example.test","tenant":c.tenant.to_string(),"purpose":"agent","revision":1,
        "issuers":[{"digest":format!("{:x}",Sha256::digest(&root)),"mode":"active","certificate":STANDARD.encode(&root),"root":STANDARD.encode(&root),"crl":STANDARD.encode(&crl),"root_crl":STANDARD.encode(&crl),"provisioner":"rss-agent","kid":"task-trust"}]
    }))?;
    let trust = rss_mdm_device_trust::device_identity::DeviceIdentityTrust::from_trust(
        rss_mdm_device_trust::DeviceTrust::new(
            trust,
            rss_mdm_agent_wire::pki::Purpose::Agent,
            now,
        )?,
        2,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let _client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
    let (server, _) = listener.accept().await?;
    let gateway =
        rss_mdm_certificate::GatewayConnection::from_stream(&server, "127.0.0.1".parse()?)?;
    let evidence =
        gateway.client_certificate(&std::fs::read_to_string(paths["leaf"].as_str().unwrap())?)?;
    let peer = trust.verify_peer(&evidence, now)?;
    let csr = tokio::process::Command::new("openssl")
        .args([
            "req",
            "-in",
            &paths["leaf"]
                .as_str()
                .unwrap()
                .replace("leaf.pem", "leaf.csr"),
            "-outform",
            "DER",
        ])
        .output()
        .await?;
    anyhow::ensure!(csr.status.success(), "CSR conversion");
    Ok((
        peer,
        evidence.chain()[0].to_vec(),
        csr.stdout,
        trust,
        evidence,
    ))
}

pub async fn authenticated_agent(
    c: &Context,
    grant: Uuid,
    device: &str,
    capabilities: Vec<rss_mdm_agent_wire::runtime::Capability>,
) -> Result<(
    rss_mdm_registration_service::DevicePrincipal,
    rss_mdm_agent_wire::pki::Trust,
)> {
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest, Sha256};
    let (peer, certificate, csr, trust, evidence) = agent_material(c, device).await?;
    let pki_trust = trust.trust.public()?;
    let service = super::registration_owner::assemble(c, trust).await?;
    let meta = peer.metadata();
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let credential = Uuid::new_v4();
    let issuance = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let epoch: Uuid =
        sqlx::query_scalar("SELECT epoch FROM rss_da.devices WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(device)
            .fetch_one(&c.operator)
            .await?;
    use rss_mdm_agent_wire::{enroll, runtime as w};
    let profile = enroll::RuntimeProfile {
        capabilities,
        platform: w::TaskPlatform::Windows,
        architecture: w::TaskArchitecture::X86_64,
        execution_context: w::SoftwareExecutionContext {
            revision: 1,
            msix_sideload: false,
            msix_unsigned: false,
            os_version: [10, 0, 26100, 0],
            system_broker: true,
            user_helper: false,
            interactive_user: None,
            source_credentials: vec![],
        },
    };
    profile.validate()?;
    let activation = enroll::ActivationReceipt {
        wire_version: 1,
        issuance_id: issuance,
        operation_id: operation,
        runtime: w::BindingProfile {
            wire_version: 1,
            operation_id: operation,
            device_id: device.into(),

            source: w::ReportSource::AgentBuiltin,
            epoch,
            capabilities: profile.capabilities.clone(),
            collections: vec![w::CollectionDefinition::new(
                "device",
                "1",
                w::Source::AgentBuiltin,
                rss_mdm_inventory::builtin::fields()
                    .into_iter()
                    .filter(|field| field.key == rss_mdm_inventory::builtin::MODEL)
                    .map(|field| rss_mdm_inventory_service::collection::wire::to_wire_field(&field))
                    .collect::<Result<Vec<_>, _>>()?,
            )?],
        },
    };
    let fingerprint = format!("{:x}", Sha256::digest(&certificate));
    let mut tx = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rss_da.credentials (tenant_id, id, device, channel, locator, state, purpose) VALUES ($1, $2, $3, 'agent', $4, 'active', 'primary')")
        .bind(tenant).bind(credential).bind(device).bind(&fingerprint).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.report_sources (tenant_id, device, source, epoch, next_sequence, enabled) VALUES ($1, $2, 'agent.builtin', $3, 0, TRUE)")
        .bind(tenant).bind(device).bind(epoch).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.certificate_issuances(tenant_id,id,grant_id,operation_id,request_digest,authority_digest,csr,spki,identity,profile,not_before,not_after,state,certificate_chain,metadata,fingerprint,activation_operation,activation_digest,activation_result,credential) VALUES($1,$2,$3,$4,repeat('1',64),repeat('2',64),$5,$6,$7,$8,$9,$10,'issued',$11,$12,$13,$4,repeat('3',64),$14,$15)")
        .bind(tenant).bind(issuance).bind(grant).bind(operation).bind(csr)
        .bind(meta.spki.iter().map(|v|format!("{v:02x}")).collect::<String>()).bind(&meta.identity)
        .bind(serde_json::to_value(&profile)?)
        .bind(meta.not_before).bind(meta.not_after).bind(serde_json::json!([STANDARD.encode(&certificate)])).bind(serde_json::to_value(meta)?).bind(fingerprint)
        .bind(serde_json::json!({"kind":"agent","receipt":&activation}))
        .bind(credential).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut tx = c.access.clone().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let principal = rss_mdm_registration_service::device::authenticate_endpoint_in(
        super::DA,
        &mut tx,
        c.tenant,
        &peer,
    )
    .await?;
    tx.commit().await?;
    super::audit_boundaries::registration(c, &service, &evidence, &pki_trust).await?;
    Ok((principal, pki_trust))
}
