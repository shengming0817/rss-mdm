use super::*;
use rss_mdm_agent_wire::{da, pki};
use rss_mdm_native_protection::Protector;
#[path = "../../../../hack/test-support/da_provider.rs"]
mod provider;
pub struct Material {
    provider: provider::Provider,
    pub protection: Arc<Protector>,
}
impl std::ops::Deref for Material {
    type Target = provider::Provider;
    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}
impl registration::certificate_issuance::Clock for context::Timer {
    fn unix_seconds(&self) -> std::result::Result<i64, registration::Error> {
        Ok(now())
    }
}
impl Material {
    pub async fn new(c: &Context) -> Result<Self> {
        Ok(Self {
            provider: provider::Provider::new(&c.inputs.directory).await?,
            protection: Arc::new(Protector::with_fingerprint(
                &std::fs::read(c.inputs.directory.join("native.key"))?,
                &[],
                &std::fs::read(c.inputs.directory.join("fingerprint.key"))?,
            )?),
        })
    }
    pub fn issued_count(&self) -> Result<usize> {
        Ok(
            std::fs::read_to_string(self.directory.join("issued.jsonl"))?
                .lines()
                .count(),
        )
    }
    pub async fn assemble(
        &self,
        c: &Context,
        device_origin: &str,
    ) -> Result<Arc<registration::agent::da::RegistrationService>> {
        let trust = self
            .publish(
                &c.operator,
                &c.tenant.to_string(),
                &c.inputs.installation.instance_id,
                device_origin,
            )
            .await?;
        let client = Arc::new(rss_mdm_pki_service::StepCa::at_address(
            rss_mdm_pki_service::Configuration {
                origin: format!("https://localhost:{}", self.port),
                provisioner: "rss-da-device".into(),
                kid: "da-test".into(),
            },
            &std::fs::read(self.directory.join("task-trust-ca/ca.pem"))?,
            &std::fs::read(self.directory.join("provider.pk8"))?,
            format!("127.0.0.1:{}", self.port).parse()?,
        )?);
        let providers = Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![
            rss_mdm_pki_service::providers::Provider {
                purpose: pki::Purpose::DaDevice,
                issuer: trust.issuers[0].digest.clone(),
                client,
                scep_url: None,
            },
        ])?);
        let registry = Arc::new(rss_mdm_pki_service::registry::Registry::new(
            DA,
            c.access.clone(),
            c.access_audit.clone(),
            c.execution(),
            providers.clone(),
        ));
        let clock = Arc::new(context::Timer);
        let issuer = Arc::new(registration::certificate_issuance::DeviceIssuer::new(
            DA,
            providers,
            2,
            true,
            pki::Purpose::DaDevice,
            registry,
            Uuid::parse_str(&c.inputs.installation.instance_id)?,
            clock.clone(),
        )?);
        Ok(Arc::new(registration::agent::da::RegistrationService::new(
            registration::agent::da::Assembly {
                cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                    ring::hmac::HMAC_SHA256,
                    &[5; 32],
                )),
                probe: c.execution(),
                store: Arc::new(registration::Store::for_device_access(c.access.clone())),
                audit: c.access_audit.clone(),
                issuer,
                clock,
                protection: self.protection.clone(),
            },
        )?))
    }
}
pub async fn success<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let path = response.url().path().to_owned();
    let status = response.status();
    let text = response.text().await?;
    anyhow::ensure!(status.is_success(), "{path} returned HTTP {status}: {text}");
    Ok(serde_json::from_str(&text)?)
}
pub async fn empty(response: reqwest::Response) -> Result<()> {
    let path = response.url().path().to_owned();
    let status = response.status();
    let text = response.text().await?;
    anyhow::ensure!(status.is_success(), "{path} returned HTTP {status}: {text}");
    Ok(())
}
pub fn verify(signed: &da::SignedConfiguration, trust: &da::ConfigurationTrust) -> Result<()> {
    rss_mdm_task_trust::configuration::verify(signed, trust, super::now())?;
    Ok(())
}
pub async fn administrator(c: &Context) -> Result<String> {
    administrator_for(c, None).await
}
pub async fn device_administrator(
    c: &Context,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<String> {
    administrator_for(c, Some(device)).await
}
async fn administrator_for(
    c: &Context,
    device: Option<&rss_mdm_agent_wire::DeviceId>,
) -> Result<String> {
    use rss_identity_core::account::{LoginKey, Password};
    let principal = seed_administrator(c, device).await?;
    // This SDK future is nested inside the complete protocol proof; keep its state on the heap.
    let issued = Box::pin(c.authority.login_local_bearer(
        c.execution(),
        LoginKey::parse(&format!("da-{principal}"))?,
        Password::new("foundation-only-valid-password".into())?,
        rss_identity_postgres::AttemptSource::parse("da-foundation")?,
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            Duration::from_secs(10),
        ),
    ))
    .await?;
    Ok(issued.secret().expose().into())
}
pub(super) async fn seed_administrator(
    c: &Context,
    device: Option<&rss_mdm_agent_wire::DeviceId>,
) -> Result<Uuid> {
    use rss_identity_core::account::Password;
    use rss_mdm_authorization_service as access;
    let principal = Uuid::new_v4();
    let login = format!("da-{principal}");
    let password = "foundation-only-valid-password";
    let kdf = rss_identity_core::account::PasswordKdf::new(
        std::num::NonZeroUsize::new(4).unwrap(),
        std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
    )?;
    let hash = kdf.hash(Password::new(password.into())?).await?;
    let mut tx = c.seed().await?;
    sqlx::query(
        "INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(c.tenant.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(principal)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO identity_authority.local_credentials(tenant_id,principal_id,login_key,password_hash) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(principal).bind(&login).bind(hash.as_str()).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(principal)
    .execute(&mut *tx)
    .await?;
    let user = access::User {
        instance_id: c.inputs.installation.instance_id.clone(),
        tenant_id: c.tenant.to_string(),
        principal_id: principal.to_string(),
    };
    let rule = access::Rule {
        subject: access::Subject::User { user },
        grants: if let Some(device) = device {
            vec![access::Grant {
                operation: access::Permission::ConfigurationWrite,
                scope: access::Scope::Device { id: *device },
            }]
        } else {
            [
                access::Permission::AccountWrite,
                access::Permission::PolicyWrite,
                access::Permission::EnterpriseApplicationsRead,
                access::Permission::OperationRead,
                access::Permission::Enrollment,
                access::Permission::Credentials,
                access::Permission::InventoryRead,
                access::Permission::ConfigurationWrite,
                access::Permission::RegistrationConfigurationWrite,
                access::Permission::RegistrationConfigurationRead,
            ]
            .into_iter()
            .map(|operation| access::Grant {
                operation,
                scope: if operation.device() {
                    access::Scope::AllDevices
                } else {
                    access::Scope::Tenant
                },
            })
            .collect()
        },
    };
    sqlx::query("INSERT INTO rss_da.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)").bind(c.tenant.to_string()).bind(&c.inputs.installation.instance_id).bind(Uuid::new_v4()).bind(serde_json::to_value(rule)?).execute(&mut *tx).await?;
    tx.commit().await?;
    kdf.close();
    kdf.wait_closed().await;
    Ok(principal)
}
