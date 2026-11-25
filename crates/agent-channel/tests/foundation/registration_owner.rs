//! The real registration owner is constructible with just the installed Agent participants.
use super::*;
use registration::agent;
struct Retire;
impl registration::Retirement for Retire {
    fn events(&self) -> Option<&dyn registration::EventSink> {
        None
    }
    fn retire<'a>(
        &'a self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        c: &'a mut sqlx::PgConnection,
        facts: &'a mut Vec<rss_mdm_audit_integration::Fact>,
        tenant: &'a str,
        id: &'a rss_mdm_agent_wire::DeviceId,
        _state: &'a str,
    ) -> agent::Pending<'a, ()> {
        Box::pin(async move {
            registration::enrollment::tasks::retirement::retire_in(
                execution, DA, c, facts, tenant, *id,
            )
            .await
            .map_err(|_| registration::Error::Storage)?;
            rss_mdm_pki_service::certificates::revoke_registration_in(DA, c, tenant, id)
                .await
                .map_err(|_| registration::Error::Storage)?;
            Ok(())
        })
    }
}
impl registration::certificate_issuance::Clock for context::Timer {
    fn unix_seconds(&self) -> std::result::Result<i64, registration::Error> {
        Ok(now())
    }
}
pub async fn assemble(
    c: &Context,
    trust: rss_mdm_device_trust::device_identity::DeviceIdentityTrust,
) -> Result<agent::Service> {
    use rss_mdm_agent_wire::pki::Purpose;
    use rss_mdm_pki_service::{
        Configuration, StepCa,
        providers::{Provider, Providers},
    };
    let key = tokio::process::Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-outform", "DER", "-in"])
        .arg(c.inputs.directory.join("task-trust-ca/ca.key"))
        .output()
        .await?;
    anyhow::ensure!(key.status.success(), "fixture signing key conversion");
    let client = Arc::new(StepCa::new(
        Configuration {
            origin: "https://localhost".into(),
            provisioner: "rss-agent".into(),
            kid: "task-trust".into(),
        },
        &std::fs::read(c.inputs.directory.join("task-trust-ca/ca.pem"))?,
        &key.stdout,
    )?);
    let providers = Arc::new(Providers::new(vec![Provider {
        purpose: Purpose::Agent,
        issuer: trust.trust.active()?.digest.clone(),
        client,
        scep_url: None,
    }])?);
    let registry = Arc::new(rss_mdm_pki_service::registry::Registry::new(
        DA,
        c.access.clone(),
        c.access_audit.clone(),
        c.execution(),
        providers.clone(),
    ));
    let public = trust.trust.public()?;
    let mut tx = c.seed().await?;
    sqlx::query("INSERT INTO rss_da.pki_trust(tenant_id,purpose,revision,body) VALUES($1::uuid,'agent',$2,$3) ON CONFLICT DO NOTHING").bind(c.tenant.to_string()).bind(public.revision as i64).bind(serde_json::to_vec(&public)?).execute(&mut *tx).await?;
    for issuer in &public.issuers {
        sqlx::query("INSERT INTO rss_da.pki_issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'agent',$2,$3,$4,$5,'step_ca',$6) ON CONFLICT DO NOTHING").bind(c.tenant.to_string()).bind(&issuer.digest).bind(public.revision as i64).bind(serde_json::to_value(issuer.mode)?.as_str().unwrap()).bind(serde_json::to_vec(issuer)?).bind(trust.expires()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let clock = Arc::new(context::Timer);
    let issuer = Arc::new(registration::certificate_issuance::DeviceIssuer::new(
        DA,
        providers,
        2,
        true,
        Purpose::Agent,
        registry,
        Uuid::parse_str(&c.inputs.installation.instance_id)?,
        clock.clone(),
    )?);
    let service = agent::Service::new(agent::Assembly {
        cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &[5; 32],
        )),
        origins: agent::connections::InstalledOrigins::new(
            "https://localhost:9445".into(),
            &["https://localhost".into()],
        )?,
        probe: c.execution(),
        store: Arc::new(registration::Store::from_pool(
            DA,
            c.access.clone(),
            Arc::new(Retire),
        )),
        audit: c.access_audit.clone(),
        issuer,
        clock,
        binding: Arc::new(rss_mdm_agent_channel::Bindings::new(DA)),
        native: None,
        bootstrap: None,
        protection: material::protection(c)?,
        installations: None,
    })?;
    assert_eq!(service.profile(), DA);
    assert_eq!(
        service.service_id()?.to_string(),
        c.inputs.installation.instance_id
    );
    Ok(service)
}
