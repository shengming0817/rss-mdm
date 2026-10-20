//! One-shot shared step-ca setup. Compose owns the CA process and its private issuer keys.
//! ref: smallstep/certificates v0.30.2 ca/adminClient.go, authority/provisioner/scep.go.
use super::*;
use crate::setup::configure;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The only CA input for ordinary deployment. All resource names and credentials are generated.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub origin: String,
    pub root_certificate_file: PathBuf,
    /// Public root CRL, maintained by the offline root owner; never a root private key.
    pub root_crl_file: PathBuf,
    pub administrator_certificate_file: PathBuf,
    pub administrator_key_file: PathBuf,
    /// Defaults to the tenant's product origin. Only exact SCEP paths are exposed.
    pub public_scep_origin: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: installation::Input,
    pub settings: Settings,
    /// Omit for the initial business tenant; later tenants retain their own host binding.
    pub host_id: Option<Uuid>,
}

pub async fn run(request: Request) -> Result<configure::Receipt> {
    let root = Journal::open(&request.installation.directory)?;
    let saved: Value = root.load("installation.json")?.ok_or(Error::Corrupt)?;
    let host = request.host_id.unwrap_or(
        serde_json::from_value(saved["receipt"]["hostId"].clone()).map_err(|_| Error::Corrupt)?,
    );
    let owner = Journal::open(
        &request
            .installation
            .directory
            .join(format!("rss-mdm-{}", host.simple())),
    )?;
    let runtime: Value = owner
        .load("requested-runtime.json")?
        .ok_or(Error::Corrupt)?;
    let current_profile = profile(&request.settings).await?;
    let client = client::Client::new(&current_profile, clock()?)?;
    let renewal = renewal_targets(
        &client,
        &runtime,
        saved["receipt"]["tenantId"] == runtime["identity"]["tenant_id"],
    )
    .await?;
    // Public CRL refresh creates one new configuration; administrator renewal does not change device identity.
    let settings = serde_json::to_vec(&request.settings).map_err(|_| Error::Input)?;
    let crl = crate::config::read(&request.settings.root_crl_file, 16 * 1024 * 1024, false)
        .map_err(|_| Error::Input)?;
    let digest = rss_mdm_device_trust::digest(&[settings.as_slice(), crl.as_slice()].concat());
    let name = format!("step-ca-{}-{}", host.simple(), &digest[..16]);
    let journal = Journal::open(&request.installation.directory.join(name))?;
    journal.secret("settings.json", &settings)?;
    let mut saved = journal.load::<Operation>("operation.json")?;
    if let Some(previous) = &saved {
        let completed = Journal::open(
            &request
                .installation
                .directory
                .join(format!("configuration-{}", previous.id)),
        )?
        .load::<configure::Receipt>("receipt.json")?
        .is_some_and(|r| r.applied.is_some());
        if completed && !renewal.is_empty() && previous.renewal != renewal {
            saved = None;
        }
    }
    let saved = match saved {
        Some(saved) => saved,
        None => {
            let saved = Operation {
                id: Uuid::new_v4(),
                revision: runtime["runtime_binding"]["revision"]
                    .as_u64()
                    .ok_or(Error::Corrupt)?,
                renewal,
            };
            journal.save("operation.json", &saved)?;
            saved
        }
    };
    let operation = saved.id;
    let revision = saved.revision;
    drop(owner);
    drop(root);
    let directory = request.installation.directory.clone();
    let result = configure::run(configure::Request {
        installation: request.installation,
        operation_id: operation,
        host_id: host,
        expected_revision: revision,
        change: configure::Change::StepCa {
            settings: Box::new(request.settings),
        },
    })
    .await?;
    // Channel enablement can refine previously unbound addresses without changing this CA operation.
    let journal = Journal::open(&directory.join(format!("configuration-{operation}")))?;
    let request: configure::Request = journal.load("request.json")?.ok_or(Error::Corrupt)?;
    if let configure::Change::StepCa { settings } = request.change {
        let root = Journal::open(&directory)?;
        let owner = Journal::open(&directory.join(format!("rss-mdm-{}", host.simple())))?;
        let runtime: Value = owner
            .load("requested-runtime.json")?
            .ok_or(Error::Corrupt)?;
        verify_latest(&root, &journal, &runtime, &settings).await?;
        root.save(&format!("ca-settings-{host}.json"), &settings)?;
    }
    Ok(result)
}

async fn profile(settings: &Settings) -> Result<Profile> {
    origin(&settings.origin)?;
    if let Some(public) = &settings.public_scep_origin {
        origin(public)?;
    }
    let url = url::Url::parse(&settings.origin).map_err(|_| Error::Input)?;
    let address = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::lookup_host((
            url.host_str().ok_or(Error::Input)?,
            url.port_or_known_default().ok_or(Error::Input)?,
        )),
    )
    .await
    .map_err(|_| Error::Storage)?
    .map_err(|_| Error::Storage)?
    .min_by_key(|address| !address.is_ipv4())
    .ok_or(Error::Storage)?;
    let certificates = openssl::x509::X509::stack_from_pem(
        &crate::config::read(&settings.administrator_certificate_file, 131072, false)
            .map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    let subject = certificates
        .first()
        .ok_or(Error::Input)?
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .ok_or(Error::Input)?
        .data()
        .to_string()
        .map_err(|_| Error::Input)?;
    Ok(Profile {
        origin: settings.origin.clone(),
        address,
        tls_root_file: settings.root_certificate_file.clone(),
        administrator_subject: subject,
        administrator_certificate_file: settings.administrator_certificate_file.clone(),
        administrator_key_file: settings.administrator_key_file.clone(),
    })
}

pub(in crate::setup) async fn prepare(
    root: &Journal,
    journal: &Journal,
    connection: &mut PgConnection,
    runtime: &mut Value,
    settings: &Settings,
) -> Result<()> {
    let profile = profile(settings).await?;
    let client = client::Client::new(&profile, clock()?)?;
    let issuer_pem = client.intermediates().await?.remove(0);
    let issuer = openssl::x509::X509::from_pem(issuer_pem.as_bytes()).map_err(|_| Error::Input)?;
    let issuer_der = issuer.to_der().map_err(|_| Error::Input)?;
    let issuer_digest = rss_mdm_device_trust::digest(&issuer_der);
    journal.secret("issuer.pem", issuer_pem.as_bytes())?;
    let root_file = copy(journal, "root.pem", &settings.root_certificate_file, false)?;
    let root_der = certificate(&root_file)?;
    let root_crl = crate::config::read(&settings.root_crl_file, 16 * 1024 * 1024, false)
        .map_err(|_| Error::Input)?;
    let root_crl = openssl::x509::X509Crl::from_pem(&root_crl)
        .or_else(|_| openssl::x509::X509Crl::from_der(&root_crl))
        .and_then(|c| c.to_der())
        .map_err(|_| Error::Input)?;
    let tenant: Uuid = serde_json::from_value(runtime["identity"]["tenant_id"].clone())
        .map_err(|_| Error::Corrupt)?;
    let saved: Value = root.load("installation.json")?.ok_or(Error::Corrupt)?;
    let primary = saved["receipt"]["tenantId"] == json!(tenant);
    let product = runtime["product_origin"]
        .as_str()
        .ok_or(Error::Corrupt)?
        .to_owned();
    let public = settings.public_scep_origin.as_deref().unwrap_or(&product);
    let host = runtime["runtime_binding"]["host_id"]
        .as_str()
        .ok_or(Error::Corrupt)?
        .to_owned();
    let prior = root.load::<Value>(&format!("ca-bindings-{host}.json"))?;
    let mut decrypter = None;
    let mut bindings = serde_json::Map::new();
    for purpose in [
        Purpose::Agent,
        Purpose::Windows,
        Purpose::Apple,
        Purpose::AgentBootstrap,
    ] {
        let owner = Journal::open(&journal.path(purpose_name(purpose))?)?;
        let existing = runtime["device_pki"]
            .as_array()
            .ok_or(Error::Corrupt)?
            .iter()
            .find(|p| p["purpose"] == json!(purpose) && p["issuer"] == issuer_digest)
            .cloned();
        let name = existing
            .as_ref()
            .and_then(|p| p["provisioner"].as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| resource_name(names(purpose).0, primary, tenant));
        // Agent's published client contract uses one named provisioner; tenant identity remains in the signed SAN.
        let shared = if purpose == Purpose::Agent {
            Some(Journal::open(
                &root.path(&format!("ca-agent-{issuer_digest}"))?,
            )?)
        } else {
            None
        };
        let key = material(shared.as_ref().unwrap_or(&owner), existing.as_ref())?;
        owner.secret("provisioner.pk8", &key)?;
        let shared_kid = shared
            .as_ref()
            .map(|j| j.load::<String>("kid.json"))
            .transpose()?
            .flatten();
        let (kid, jwk) = jwk(
            &key,
            existing
                .as_ref()
                .and_then(|p| p["kid"].as_str())
                .or(shared_kid.as_deref()),
        )?;
        if let Some(shared) = &shared {
            shared.secret(
                "kid.json",
                &serde_json::to_vec(&kid).map_err(|_| Error::Corrupt)?,
            )?;
        }
        let mut expected = jwk_provisioner(purpose, jwk)?;
        expected.name = name.clone();
        ensure_provider(&client, &expected, Preparation::Create).await?;
        owner.secret(
            "expected-jwk.json",
            &serde_json::to_vec(&expected).map_err(|_| Error::Corrupt)?,
        )?;
        let provider = rss_mdm_pki_service::StepCa::at_address(
            rss_mdm_pki_service::Configuration {
                origin: profile.origin.clone(),
                provisioner: name.clone(),
                kid: kid.clone(),
            },
            &crate::config::read(&root_file, 131072, false).map_err(|_| Error::Input)?,
            &key,
            profile.address,
        )
        .map_err(|_| Error::Input)?;
        provider
            .verify_issuer(&issuer_digest)
            .await
            .map_err(|_| Error::Conflict)?;
        provider
            .verify_provisioner()
            .await
            .map_err(|_| Error::Conflict)?;
        let crl = provider.published_crl().await.map_err(|_| Error::Storage)?;
        let scep_name = names(purpose).1.map(|base| {
            existing
                .as_ref()
                .and_then(|p| p["scep_url"].as_str())
                .and_then(|url| url.rsplit('/').next())
                .map(str::to_owned)
                .unwrap_or_else(|| resource_name(base, primary, tenant))
        });
        let previous = current_trust(connection, tenant, purpose).await?;
        let callbacks = if let Some(name) = &scep_name {
            Some(
                scep_resources(
                    ScepPreparation {
                        purpose,
                        name,
                        public,
                        callback: &callback_origin(runtime, purpose)?,
                        issuer_der: &issuer_der,
                        crl: &crl,
                        previous: prior
                            .as_ref()
                            .map(|p| &p[purpose_name(purpose)]["callbacks"])
                            .filter(|p| {
                                p.is_object() && p["issuer"] == issuer_digest && previous.is_none()
                            }),
                    },
                    &client,
                    &profile,
                    &owner,
                    journal,
                    &mut decrypter,
                )
                .await?,
            )
        } else {
            None
        };
        let device_origin = device_origin(runtime, purpose)?;
        let candidate = Issuer {
            digest: issuer_digest.clone(),
            mode: Mode::Active,
            certificate: STANDARD.encode(&issuer_der),
            root: STANDARD.encode(&root_der),
            crl: STANDARD.encode(&crl),
            root_crl: STANDARD.encode(&root_crl),
            provisioner: scep_name.clone().unwrap_or(name.clone()),
            kid: if scep_name.is_some() {
                String::new()
            } else {
                kid.clone()
            },
        };
        let (trust, active_before) =
            prepared_trust(previous, candidate, tenant, purpose, device_origin)?;
        // Freeze original trust bytes before exporting; CRL refresh cannot change a resumed operation.
        let trust_file = freeze_trust(&owner, &trust)?;
        let provider = json!({"purpose":purpose,"issuer":issuer_digest,"origin":profile.origin,"tls_root_file":root_file,
            "provisioner":name,"kid":kid,"provisioner_key_file":owner.path("provisioner.pk8")?,"scep_url":scep_name.map(|name|format!("{public}/scep/{name}"))});
        owner.secret(
            "runtime-provider.json",
            &serde_json::to_vec(&provider).map_err(|_| Error::Corrupt)?,
        )?;
        bindings.insert(
            purpose_name(purpose).into(),
            json!({"trust_file":trust_file,"callbacks":callbacks}),
        );
        if let Some(callbacks) = &callbacks {
            owner.secret(
                "runtime-callbacks.json",
                &serde_json::to_vec(callbacks).map_err(|_| Error::Corrupt)?,
            )?;
        }
        let attach_trust = !active_before
            || trust
                .issuers
                .iter()
                .any(|g| g.digest == issuer_digest && g.mode == Mode::Active);
        bind_runtime(
            runtime,
            purpose,
            &issuer_digest,
            provider,
            callbacks,
            &trust_file,
            attach_trust,
        )?;
    }
    bindings.insert(
        "_directory".into(),
        json!(journal.path("issuer.pem")?.parent().ok_or(Error::Corrupt)?),
    );
    root.save(&format!("ca-bindings-{host}.json"), &bindings)?;
    root.save(&format!("ca-settings-{host}.json"), settings)?;
    Ok(())
}

fn purpose_name(p: Purpose) -> &'static str {
    match p {
        Purpose::Agent => "agent",
        Purpose::Windows => "windows",
        Purpose::Apple => "apple",
        Purpose::AgentBootstrap => "agent-bootstrap",
    }
}
fn resource_name(base: &str, primary: bool, tenant: Uuid) -> String {
    if primary || base == "rss-agent" {
        base.into()
    } else {
        format!("{base}-{}", tenant.simple())
    }
}
fn channel(runtime: &Value, purpose: Purpose) -> Option<&Value> {
    runtime
        .pointer(channel_path(purpose))
        .filter(|v| v.get("trust_file").is_some())
}
fn channel_mut(runtime: &mut Value, purpose: Purpose) -> Option<&mut Value> {
    runtime
        .pointer_mut(channel_path(purpose))
        .filter(|v| v.get("trust_file").is_some())
}
fn channel_path(p: Purpose) -> &'static str {
    match p {
        Purpose::Agent => "/agent_pki",
        Purpose::Windows => "/native_protocols/windows",
        Purpose::Apple => "/native_protocols/apple",
        Purpose::AgentBootstrap => "/agent_pki/bootstrap",
    }
}
fn default_origin(product: &str, purpose: Purpose) -> Result<String> {
    let port = match purpose {
        Purpose::Agent | Purpose::AgentBootstrap => 9445,
        Purpose::Windows => 8444,
        Purpose::Apple => 9446,
    };
    let mut url = url::Url::parse(product).map_err(|_| Error::Input)?;
    url.set_port(Some(port)).map_err(|_| Error::Input)?;
    Ok(url.origin().ascii_serialization())
}
async fn current_trust(
    c: &mut PgConnection,
    tenant: Uuid,
    purpose: Purpose,
) -> Result<Option<Trust>> {
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let bytes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT body FROM mdm_pki.trust WHERE tenant_id=$1 AND purpose=$2")
            .bind(tenant)
            .bind(rss_mdm_pki_service::registry::purpose(purpose))
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
    tx.rollback().await.map_err(|_| Error::Storage)?;
    bytes
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt))
        .transpose()
}
fn material(journal: &Journal, existing: Option<&Value>) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let path = journal.path("provisioner.pk8")?;
    if !path.exists() {
        if journal.load::<Value>("expected-jwk.json")?.is_some()
            || journal.load::<String>("kid.json")?.is_some()
        {
            return Err(Error::Corrupt);
        }
        let bytes = match existing {
            Some(p) => crate::config::read(
                std::path::Path::new(p["provisioner_key_file"].as_str().ok_or(Error::Corrupt)?),
                32768,
                true,
            )
            .map_err(|_| Error::Corrupt)?,
            None => zeroize::Zeroizing::new(
                openssl::rsa::Rsa::generate(2048)
                    .and_then(openssl::pkey::PKey::from_rsa)
                    .and_then(|p| p.private_key_to_pkcs8())
                    .map_err(|_| Error::Storage)?,
            ),
        };
        journal.secret("provisioner.pk8", &bytes)?;
    }
    crate::config::read(&path, 32768, true).map_err(|_| Error::Corrupt)
}

pub(super) async fn encryption_identity(
    journal: &Journal,
    client: &client::Client,
    profile: &Profile,
) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>)> {
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509NameBuilder, X509Req},
    };
    let owner = Journal::open(&journal.path("scep-encryption")?)?;
    let private = material(&owner, None)?;
    let (kid, public) = jwk(&private, None)?;
    let mut expected = jwk_provisioner(Purpose::Apple, public)?;
    // Deployment-only credential, never exported to the runtime. Fixed non-CA RSA encryption identity.
    expected.name = format!("rss-scep-encryption-{}", &kid[..16]);
    expected.claims.x509.durations.default = "8760h".into();
    expected.claims.x509.durations.max = "8760h".into();
    expected.x509_template.template=STANDARD.encode(r#"{"subject":{"commonName":"rss-scep-encryption"},"keyUsage":["digitalSignature","keyEncipherment"],"basicConstraints":{"isCA":false}}"#);
    ensure_provider(client, &expected, Preparation::Create).await?;
    owner.secret(
        "expected-jwk.json",
        &serde_json::to_vec(&expected).map_err(|_| Error::Corrupt)?,
    )?;
    let path = owner.path("identity.key")?;
    if !path.exists() {
        if owner.load::<Uuid>("signing.json")?.is_some() {
            return Err(Error::Corrupt);
        }
        owner.secret(
            "identity.key",
            &PKey::from_rsa(Rsa::generate(2048).map_err(|_| Error::Storage)?)
                .and_then(|p| p.private_key_to_pem_pkcs8())
                .map_err(|_| Error::Storage)?,
        )?;
    }
    let key = crate::config::read(&path, 32768, true).map_err(|_| Error::Corrupt)?;
    let certificate = owner.path("identity.pem")?;
    if !certificate.exists() {
        if owner.load::<Uuid>("signing.json")?.is_some() {
            return Err(Error::Conflict);
        }
        let pkey = PKey::private_key_from_pem(&key).map_err(|_| Error::Corrupt)?;
        let mut name = X509NameBuilder::new().map_err(|_| Error::Storage)?;
        name.append_entry_by_text("CN", "rss-scep-encryption")
            .map_err(|_| Error::Storage)?;
        let mut csr = X509Req::builder().map_err(|_| Error::Storage)?;
        csr.set_subject_name(&name.build())
            .and_then(|_| csr.set_pubkey(&pkey))
            .and_then(|_| csr.sign(&pkey, MessageDigest::sha256()))
            .map_err(|_| Error::Storage)?;
        let csr = csr.build();
        let der = csr.to_der().map_err(|_| Error::Storage)?;
        let pem = String::from_utf8(csr.to_pem().map_err(|_| Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        owner.secret("request.pem", pem.as_bytes())?;
        let provider = rss_mdm_pki_service::StepCa::at_address(
            rss_mdm_pki_service::Configuration {
                origin: profile.origin.clone(),
                provisioner: expected.name,
                kid,
            },
            &crate::config::read(&profile.tls_root_file, 131072, false)
                .map_err(|_| Error::Input)?,
            &private,
            profile.address,
        )
        .map_err(|_| Error::Input)?;
        let attempt = Uuid::new_v4();
        let now = clock()?;
        // Persist before dispatch. An unknown signing outcome must recover the original certificate.
        owner.save("signing.json", &attempt)?;
        let chain = provider
            .sign(
                rss_mdm_pki_service::Sign {
                    attempt,
                    csr_pem: &pem,
                    csr_digest: &Sha256::digest(&der).into(),
                    subject: "rss-scep-encryption",
                    sans: &[],
                    start: now,
                    end: now + 365 * 86400,
                    deadline: now + 60,
                },
                now,
            )
            .await
            .map_err(|_| Error::Storage)?;
        let leaf = openssl::x509::X509::from_der(chain.first().ok_or(Error::Corrupt)?)
            .map_err(|_| Error::Corrupt)?;
        owner.secret("identity.pem", &leaf.to_pem().map_err(|_| Error::Corrupt)?)?;
    }
    Ok((
        crate::config::read(&certificate, 131072, false)
            .map_err(|_| Error::Corrupt)?
            .to_vec(),
        key,
    ))
}

/// Attach generated CA details when enabling a channel later; callers never enter provider internals.
pub(in crate::setup) async fn attach(
    root: &Journal,
    journal: &Journal,
    connection: &mut PgConnection,
    runtime: &mut Value,
) -> Result<()> {
    let host = runtime["runtime_binding"]["host_id"]
        .as_str()
        .ok_or(Error::Corrupt)?;
    if let Some(settings) = root.load::<Settings>(&format!("ca-settings-{host}.json"))? {
        return prepare(root, journal, connection, runtime, &settings).await;
    }
    Ok(())
}
async fn verify_latest(
    root: &Journal,
    journal: &Journal,
    runtime: &Value,
    settings: &Settings,
) -> Result<()> {
    let host = runtime["runtime_binding"]["host_id"]
        .as_str()
        .ok_or(Error::Corrupt)?;
    let directory = root
        .load::<Value>(&format!("ca-bindings-{host}.json"))?
        .and_then(|v| v["_directory"].as_str().map(PathBuf::from));
    if let Some(directory) = directory
        && directory.join("issuer.pem") != journal.path("issuer.pem")?
    {
        verify(&Journal::open(&directory)?, runtime, settings).await
    } else {
        verify(journal, runtime, settings).await
    }
}
async fn verify(journal: &Journal, runtime: &Value, settings: &Settings) -> Result<()> {
    let profile = profile(settings).await?;
    let client = client::Client::new(&profile, clock()?)?;
    let certificate =
        openssl::x509::X509::from_pem(client.intermediates().await?.remove(0).as_bytes())
            .map_err(|_| Error::Input)?;
    let stored = journal.path("issuer.pem")?;
    if certificate.to_der().map_err(|_| Error::Input)? != super::certificate(&stored)? {
        return Err(Error::Conflict);
    }
    for purpose in [
        Purpose::Agent,
        Purpose::Windows,
        Purpose::Apple,
        Purpose::AgentBootstrap,
    ] {
        let owner = Journal::open(&journal.path(purpose_name(purpose))?)?;
        let expected: wire::Provisioner = owner.load("expected-jwk.json")?.ok_or(Error::Corrupt)?;
        ensure_provider(&client, &expected, Preparation::Import).await?;
        if let Some(expected) = owner.load::<wire::Provisioner>("expected-scep.json")? {
            prepare_scep(
                purpose,
                &callback_origin(runtime, purpose)?,
                Preparation::Import,
                &owner,
                &client,
                &expected,
                None,
            )
            .await?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Operation {
    id: Uuid,
    revision: u64,
    renewal: Vec<String>,
}
fn device_origin(runtime: &Value, purpose: Purpose) -> Result<String> {
    let field = if matches!(purpose, Purpose::Agent | Purpose::AgentBootstrap) {
        "endpoint"
    } else {
        "management"
    };
    let source = if purpose == Purpose::AgentBootstrap {
        channel(runtime, Purpose::Agent)
    } else {
        channel(runtime, purpose)
    };
    source
        .and_then(|v| v.get(field))
        .and_then(|v| v["origin"].as_str())
        .map(|v| Ok(v.to_owned()))
        .unwrap_or_else(|| {
            default_origin(
                runtime["product_origin"].as_str().ok_or(Error::Corrupt)?,
                purpose,
            )
        })
}
fn callback_origin(runtime: &Value, purpose: Purpose) -> Result<String> {
    if purpose == Purpose::AgentBootstrap {
        device_origin(runtime, Purpose::Agent)
    } else {
        Ok(runtime["product_origin"]
            .as_str()
            .ok_or(Error::Corrupt)?
            .to_owned())
    }
}
fn scep_needs_renewal(remote: &wire::Provisioner) -> Result<bool> {
    let cert = STANDARD
        .decode(
            &remote
                .details
                .scep
                .as_ref()
                .ok_or(Error::Conflict)?
                .decrypter
                .certificate,
        )
        .map_err(|_| Error::Input)?;
    let cert = openssl::x509::X509::from_pem(&cert).map_err(|_| Error::Input)?;
    let threshold =
        openssl::asn1::Asn1Time::from_unix(clock()? + 30 * 86400).map_err(|_| Error::Input)?;
    Ok(cert.not_after() <= threshold.as_ref())
}
async fn renewal_targets(
    client: &client::Client,
    runtime: &Value,
    primary: bool,
) -> Result<Vec<String>> {
    let tenant: Uuid = serde_json::from_value(runtime["identity"]["tenant_id"].clone())
        .map_err(|_| Error::Corrupt)?;
    let mut result = Vec::new();
    for purpose in [Purpose::Apple, Purpose::AgentBootstrap] {
        let name = resource_name(names(purpose).1.ok_or(Error::Input)?, primary, tenant);
        if let Some(remote) = client.get::<wire::Provisioner>(&name, clock()?).await?
            && scep_needs_renewal(&remote)?
        {
            result.push(rss_mdm_device_trust::digest(
                remote
                    .details
                    .scep
                    .as_ref()
                    .ok_or(Error::Conflict)?
                    .decrypter
                    .certificate
                    .as_bytes(),
            ));
        }
    }
    Ok(result)
}

struct ScepPreparation<'a> {
    purpose: Purpose,
    name: &'a str,
    public: &'a str,
    callback: &'a str,
    issuer_der: &'a [u8],
    crl: &'a [u8],
    previous: Option<&'a Value>,
}
async fn scep_resources(
    input: ScepPreparation<'_>,
    client: &client::Client,
    profile: &Profile,
    owner: &Journal,
    journal: &Journal,
    decrypter: &mut Option<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>)>,
) -> Result<Value> {
    let ScepPreparation {
        purpose,
        name: scep_name,
        public,
        callback,
        issuer_der,
        crl,
        previous: rebind,
    } = input;
    let issuer_digest = rss_mdm_device_trust::digest(issuer_der);
    let remote = client.get::<wire::Provisioner>(scep_name, clock()?).await?;
    let renew = remote
        .as_ref()
        .map(scep_needs_renewal)
        .transpose()?
        .unwrap_or(false);
    let (cert, private) = if let Some(remote) = remote.as_ref().filter(|_| !renew) {
        let d = &remote
            .details
            .scep
            .as_ref()
            .ok_or(Error::Conflict)?
            .decrypter;
        (
            STANDARD.decode(&d.certificate).map_err(|_| Error::Input)?,
            zeroize::Zeroizing::new(
                STANDARD
                    .decode(d.key.as_bytes())
                    .map_err(|_| Error::Input)?,
            ),
        )
    } else {
        if decrypter.is_none() {
            *decrypter = Some(encryption_identity(journal, client, profile).await?);
        }
        let (cert, private) = decrypter.as_ref().ok_or(Error::Corrupt)?;
        (cert.clone(), private.clone())
    };
    if decrypter.is_none() {
        *decrypter = Some((cert.clone(), private.clone()));
    }
    let source = ScepInput {
        public_url: format!("{public}/scep/{scep_name}"),
        certificate_file: owner.secret("scep.pem", &cert)?,
        private_key_file: owner.secret("scep.key", &private)?,
    };
    let expected = scep_provisioner(purpose, &source, owner, scep_name, issuer_der, crl)?;
    if renew {
        let remote = remote.ok_or(Error::Corrupt)?;
        let mut previous = expected.clone();
        previous
            .details
            .scep
            .as_mut()
            .ok_or(Error::Corrupt)?
            .decrypter = remote
            .details
            .scep
            .as_ref()
            .ok_or(Error::Conflict)?
            .decrypter
            .clone();
        // Compare every policy before replacing only the expiring encryption identity.
        remote.matches(&previous)?;
        let mut updated = remote;
        updated.details.scep = expected.details.scep.clone();
        owner.secret(
            "renewed-scep.json",
            &serde_json::to_vec(&updated).map_err(|_| Error::Corrupt)?,
        )?;
        client.update(scep_name, &updated, clock()?).await?;
    }
    prepare_scep(
        purpose,
        callback,
        Preparation::Create,
        owner,
        client,
        &expected,
        rebind,
    )
    .await?;
    owner.secret(
        "expected-scep.json",
        &serde_json::to_vec(&expected).map_err(|_| Error::Corrupt)?,
    )?;
    let challenge: Value = owner
        .load("challenge-runtime.json")?
        .ok_or(Error::Corrupt)?;
    let notify: Value = owner.load("notify-runtime.json")?.ok_or(Error::Corrupt)?;
    Ok(json!({"issuer":issuer_digest,"challenge":challenge,"notify":notify}))
}
fn prepared_trust(
    previous: Option<Trust>,
    mut candidate: Issuer,
    tenant: Uuid,
    purpose: Purpose,
    device_origin: String,
) -> Result<(Trust, bool)> {
    // CA qualification uses fresh publications; persisted trust may retain an older, signed CRL.
    rss_mdm_device_trust::DeviceTrust::new(
        Trust {
            version: 1,
            origin: device_origin.clone(),
            tenant,
            purpose,
            revision: 1,
            issuers: vec![candidate.clone()],
        },
        purpose,
        clock()?,
    )
    .map_err(|_| Error::Conflict)?;
    let mut trust = previous.unwrap_or(Trust {
        version: 1,
        origin: device_origin.clone(),
        tenant,
        purpose,
        revision: 0,
        issuers: vec![],
    });
    if trust.origin != device_origin {
        return Err(Error::Conflict);
    }
    let active_before = !trust.issuers.is_empty();
    if let Some(existing) = trust
        .issuers
        .iter_mut()
        .find(|g| g.digest == candidate.digest)
    {
        if existing.certificate != candidate.certificate
            || existing.root != candidate.root
            || existing.provisioner != candidate.provisioner
            || existing.kid != candidate.kid
        {
            return Err(Error::Conflict);
        }
        existing.crl = candidate.crl.clone();
    } else {
        trust.revision += 1;
        candidate.mode = if active_before {
            Mode::Prepared
        } else {
            Mode::Active
        };
        trust.issuers.push(candidate.clone());
    }
    for generation in &mut trust.issuers {
        if generation.root == candidate.root {
            generation.root_crl = candidate.root_crl.clone();
        }
    }
    rss_mdm_device_trust::DeviceTrust::restore(trust.clone(), purpose, clock()?)
        .map_err(|_| Error::Conflict)?;
    Ok((trust, active_before))
}

fn validate_callbacks(existing: &Value, desired: &Value) -> Result<()> {
    for phase in ["challenge", "notify"] {
        let bytes = |value: &Value| {
            crate::config::read(
                std::path::Path::new(value[phase]["secret_file"].as_str().ok_or(Error::Corrupt)?),
                32768,
                true,
            )
            .map_err(|_| Error::Corrupt)
        };
        if existing[phase]["id"] != desired[phase]["id"]
            || bytes(existing)?.as_slice() != bytes(desired)?.as_slice()
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

fn bind_runtime(
    runtime: &mut Value,
    purpose: Purpose,
    issuer: &str,
    provider: Value,
    callbacks: Option<Value>,
    trust_file: &std::path::Path,
    attach_trust: bool,
) -> Result<()> {
    let providers = runtime["device_pki"].as_array_mut().ok_or(Error::Corrupt)?;
    if let Some(p) = providers
        .iter_mut()
        .find(|p| p["purpose"] == json!(purpose) && p["issuer"] == issuer)
    {
        *p = provider;
    } else {
        providers.push(provider);
    }
    if let Some(callbacks) = callbacks
        && let Some(channel) = channel_mut(runtime, purpose)
    {
        let hooks = channel["webhooks"].as_array_mut().ok_or(Error::Corrupt)?;
        if let Some(hook) = hooks.iter_mut().find(|h| h["issuer"] == issuer) {
            validate_callbacks(hook, &callbacks)?;
            *hook = callbacks;
        } else {
            hooks.push(callbacks);
        }
    }
    if attach_trust && let Some(channel) = channel_mut(runtime, purpose) {
        channel["trust_file"] = json!(trust_file);
    }
    Ok(())
}

fn freeze_trust(owner: &Journal, trust: &Trust) -> Result<PathBuf> {
    if owner.load::<Trust>("trust.json")?.is_none() {
        owner.secret(
            "trust.json",
            &serde_json::to_vec(trust).map_err(|_| Error::Corrupt)?,
        )
    } else {
        owner.path("trust.json")
    }
}
