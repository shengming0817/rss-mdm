//! Independent business proof: real Identity guard/proof, DA rows, Audit and signed native evidence.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_identity_core::{
    account::{LoginKey, Password},
    session::{BearerSecret, SessionSecret},
};
use rss_mdm_agent_wire::{da, runtime as wire};
use rss_mdm_authorization_service::{context::AuthorizedPrincipal, credential::RequestCredential};
use rss_mdm_device_access::deployment::{Deployment, Observation};
use rss_mdm_device_access_postgres as pg;
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(10))
}
pub(super) fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[49; 32]).unwrap()
}
pub(super) fn authority_id() -> Uuid {
    Uuid::from_u128(0x229df54fe9804bc1aa8f006c14890c15)
}
fn authorities() -> Result<Arc<pg::evidence::Authorities>> {
    Ok(Arc::new(pg::evidence::Authorities::new(vec![
        pg::evidence::Authority {
            id: authority_id(),
            public_key: key().public_key().as_ref().try_into()?,
        },
    ])?))
}
pub fn assemble(
    c: &Context,
    m: &material::Material,
) -> Result<Arc<rss_mdm_device_access_http::Business>> {
    if let Some(business) = c.business.get() {
        return Ok(business.clone());
    }
    let evidence = authorities()?;
    let runtime = rss_mdm_device_access_runtime::Runtime::assemble(
        rss_mdm_device_access_runtime::Resources {
            report_limits: pg::reports::Limits {
                history_count: 2,
                reports_per_minute: 10,
                ..Default::default()
            },
            tenant: c.tenant,
            installation: Uuid::parse_str(&c.inputs.installation.instance_id)?,
            identity_instance: rss_identity_core::InstanceId::parse(
                &c.inputs.installation.instance_id,
            )?,
            pool: c.access.clone(),
            audit: c.access_audit.clone(),
            proof_audit: c.proof_audit.clone(),
            cursor: rss_mdm_query::cursor::CursorCodec::new(&[37; 32])?,
            protection: m.protection.clone(),
            platform: Some(super::platform::runtime(c)?),
            evidence: evidence.clone(),
            broker_query: None,
            agent_facts: None,
        },
        None,
    )?;
    c.platform.bind(&runtime.platform)?;
    let business = Arc::new(rss_mdm_device_access_http::Business {
        evidence,
        service: runtime.business,
        admission: runtime.admission,
        platform: Arc::new(rss_mdm_device_access_http::platform_sso::HttpState {
            context: runtime.platform,
            authority: c.authority.clone(),
            origin: "https://localhost".into(),
        }),
    });
    anyhow::ensure!(
        c.business.set(business.clone()).is_ok(),
        "single DA assembly"
    );
    Ok(business)
}
pub(super) async fn login(
    c: &Context,
    principal: Uuid,
) -> Result<(AuthorizedPrincipal, SessionSecret)> {
    let issued = Box::pin(c.authority.login_local(
        c.tenant,
        LoginKey::parse(&format!("da-{principal}"))?,
        Password::new("foundation-only-valid-password".into())?,
        rss_identity_postgres::AttemptSource::parse("da-business")?,
        None,
        deadline(),
    ))
    .await?;
    let secret = SessionSecret::parse(issued.secret().expose().into())?;
    let actor = Box::pin(c.sessions.authenticate(
        &c.authorization,
        RequestCredential::Cookie(SessionSecret::parse(secret.expose().into())?),
    ))
    .await?;
    Ok((actor, secret))
}
pub(super) fn audit(c: &Context) -> rss_mdm_audit_integration::RequestAudit {
    rss_mdm_audit_integration::RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        DA,
        c.tenant.to_string(),
        "da-business-proof",
        rss_mdm_audit_integration::AuditIntent::Management,
    )
}
pub(super) fn signed(value: &Observation) -> Result<pg::evidence::SignedObservation> {
    let payload = serde_json::to_vec(value)?;
    let mut message = b"rss.da.deployment.v1\0".to_vec();
    message.extend_from_slice(&payload);
    Ok(pg::evidence::SignedObservation {
        payload: URL_SAFE_NO_PAD.encode(&payload),
        signature: URL_SAFE_NO_PAD.encode(key().sign(&message).as_ref()),
    })
}
// Committed DA business effects; Identity and request-completion facts have separate owners.
async fn counts(c: &Context) -> Result<(i64, i64, i64, i64)> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.bindings WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_da.operations WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='da.business'),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid)")
        .bind(c.tenant.to_string()).fetch_one(&c.operator).await?)
}
async fn request_audits(c: &Context) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='da.request'")
        .bind(c.tenant.to_string()).fetch_one(&c.operator).await?)
}
pub async fn verify(
    c: &Context,
    m: &material::Material,
    receipt: &da::Registration,
    client: &reqwest::Client,
    base: &str,
) -> Result<()> {
    use rss_mdm_policy_postgres::device_access::{Publication, Target};
    let business = assemble(c, m)?;
    let token = material::administrator(c)
        .await
        .context("create and log in business proof principal")?;
    let bearer = c
        .authority
        .inspect_bearer(c.tenant, BearerSecret::parse(token)?, deadline())
        .await?;
    let principal = bearer.account().principal.as_uuid();
    let (actor, session_secret) = Box::pin(login(c, principal))
        .await
        .context("business proof cookie login")?;
    let configuration = wire::AccessConfiguration {
        mac: None,
        windows: wire::AccessWindowsConfiguration::Whfb,
        self_enrollment: true,
        enabled: true,
        role: None,
    };
    let mut tx = c.seed().await?;
    let existing = rss_mdm_policy_postgres::device_access::selected_on(
        &mut tx,
        Uuid::parse_str(&c.tenant.to_string())?,
        &receipt.device,
    )
    .await?;
    tx.rollback().await?;
    let publication = Publication {
        managed_fields: vec![],
        id: existing.as_ref().map(|v| v.id).unwrap_or_else(Uuid::new_v4),
        revision: existing.as_ref().map(|v| v.revision + 1).unwrap_or(1),
        version: Uuid::new_v4(),
        target: Target::TenantDefault,
        enabled: true,
        configuration,
    };
    let publish = pg::configuration::Change {
        operation_id: Uuid::new_v4(),
        expected_revision: publication.revision - 1,
        publication: publication.clone(),
    };
    business
        .service
        .publish_configuration(&actor, &publish, None, &audit(c))
        .await?;
    let account = wire::AccessAccount::Windows {
        sid: "S-1-12-1-1-2-3-4".into(),
        authority: wire::AccessWindowsAuthority::Entra {
            tenant_id: Uuid::new_v4(),
            object_id: Uuid::new_v4(),
        },
    };
    let binding = Uuid::new_v4();
    let change = pg::device_access::Change {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        action: pg::device_access::Action::Put {
            person: rss_mdm_device_access::Person {
                instance: Uuid::parse_str(&c.inputs.installation.instance_id)?,
                principal,
            },
            intent: rss_mdm_device_access::AccountIntent::Existing {
                account: account.clone(),
            },
            policy: publication.id,
        },
    };
    let fingerprints = std::collections::BTreeMap::new();
    let context = change.step_up_context(&actor, &receipt.device, binding, &fingerprints)?;
    let proof = Box::pin(operation_proof(c, &session_secret, context)).await?;
    let before = counts(c).await?;
    // Failure occurs after binding, receipt and outbox writes, within the original Identity transaction.
    sqlx::raw_sql("CREATE FUNCTION public.reject_da_business_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'DA receipt rollback probe'; END $$; CREATE TRIGGER rollback_probe AFTER INSERT ON rss_da.operations FOR EACH ROW EXECUTE FUNCTION public.reject_da_business_receipt();").execute(&c.operator).await?;
    let failed = Box::pin(business.service.change_device_access(
        &actor,
        &receipt.device,
        binding,
        &change,
        Some(&proof),
        &fingerprints,
        business.admission.as_ref(),
        &audit(c),
    ))
    .await;
    sqlx::raw_sql("DROP TRIGGER rollback_probe ON rss_da.operations; DROP FUNCTION public.reject_da_business_receipt();").execute(&c.operator).await?;
    assert!(failed.is_err());
    assert_eq!(
        counts(c).await?,
        before,
        "business, receipt, Audit and outbox roll back together"
    );
    let accepted = Box::pin(business.service.change_device_access(
        &actor,
        &receipt.device,
        binding,
        &change,
        Some(&proof),
        &fingerprints,
        business.admission.as_ref(),
        &audit(c),
    ))
    .await?;
    assert_eq!(accepted.device, receipt.device);
    let page = material::success::<serde_json::Value>(
        client
            .get(format!(
                "{base}/api/v1/devices/{}/device-access",
                receipt.device
            ))
            .header(
                "cookie",
                format!("__Host-identity-session={}", session_secret.expose()),
            )
            .query(&[(
                "filter",
                format!("id=={binding};desired.windows.kind==whfb"),
            )])
            .send()
            .await?,
    )
    .await?;
    assert_eq!(
        page["items"]
            .as_array()
            .context("DA binding directory")?
            .len(),
        1
    );
    assert_eq!(page["items"][0]["id"], binding.to_string());
    let mut tx = c.seed().await?;
    for name in ["directory-target", "directory-sentinel"] {
        let rp = pg::enterprise::RelyingParty {
            id: name.into(),
            revision: 1,
            enabled: true,
            callback: format!("https://{name}.example.test/callback"),
            target_fingerprint: "a".repeat(64),
            capabilities: vec![],
        };
        sqlx::query("INSERT INTO rss_da.relying_parties(tenant_id,id,revision,document) VALUES($1::uuid,$2,1,$3)").bind(c.tenant.to_string()).bind(name).bind(serde_json::to_value(rp)?).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let page = material::success::<serde_json::Value>(
        client
            .get(format!(
                "{base}/api/v1/device-access/enterprise/configuration"
            ))
            .header(
                "cookie",
                format!("__Host-identity-session={}", session_secret.expose()),
            )
            .query(&[(
                "filter",
                "kind==relying_party;value.id==directory-target;value.enabled==true",
            )])
            .send()
            .await?,
    )
    .await?;
    assert_eq!(
        page["items"]
            .as_array()
            .context("enterprise directory")?
            .len(),
        1
    );
    assert_eq!(page["items"][0]["id"], "rp:directory-target");

    let settled = counts(c).await?;
    assert_eq!(settled.0, before.0 + 1);
    assert_eq!(settled.1, before.1 + 1);
    assert_eq!(settled.2, before.2 + 1);
    assert_eq!(settled.3, before.3 + 1);
    let replay = Box::pin(business.service.change_device_access(
        &actor,
        &receipt.device,
        binding,
        &change,
        None,
        &fingerprints,
        business.admission.as_ref(),
        &audit(c),
    ))
    .await?;
    assert_eq!(
        serde_json::to_value(&replay)?,
        serde_json::to_value(&accepted)?
    );
    assert_eq!(counts(c).await?, settled);
    c.authority
        .revoke_current_session(
            c.authority
                .inspect_session(
                    c.tenant,
                    SessionSecret::parse(session_secret.expose().into())?,
                    deadline(),
                )
                .await?,
            deadline(),
        )
        .await?;
    assert!(
        Box::pin(business.service.change_device_access(
            &actor,
            &receipt.device,
            binding,
            &change,
            None,
            &fingerprints,
            business.admission.as_ref(),
            &audit(c)
        ))
        .await
        .is_err(),
        "stale in-memory actor cannot replay after Identity revocation"
    );
    assert!(
        business
            .service
            .device_access_operation(&actor, &receipt.device, change.operation_id)
            .await
            .is_err()
    );
    let (current, _) = Box::pin(login(c, principal)).await?;
    let recovered = business
        .service
        .device_access_operation(&current, &receipt.device, change.operation_id)
        .await?;
    assert_eq!(
        serde_json::to_value(&recovered)?,
        serde_json::to_value(&accepted)?
    );
    let anchor = registration::device::endpoints::DaRegistration {
        device: receipt.device.clone(),
    };
    let observation = Observation {
        tenant: Uuid::parse_str(&c.tenant.to_string())?,
        installation: Uuid::parse_str(&c.inputs.installation.instance_id)?,
        device: receipt.device.clone(),

        authority: authority_id(),
        sequence: 1,
        issued_at: now() - 1,
        expires_at: now() + 600,
        revoked: false,
        policy: publication.id,
        policy_version: publication.version,
        configuration: None,
        deployment: Deployment::Windows {
            interactive_broker: true,
        },
        local_session: Some(wire::AccessLocalSession {
            account,
            session_id: Uuid::new_v4(),
        }),
        applications: Vec::new(),
    };
    let url = format!("{base}/deployment-evidence");
    let before_evidence = counts(c).await?;
    material::empty(
        client
            .post(&url)
            .json(&signed(&observation)?)
            .send()
            .await?,
    )
    .await?;
    let evidence_count = counts(c).await?;
    assert_eq!(
        evidence_count,
        (
            before_evidence.0,
            before_evidence.1,
            before_evidence.2 + 1,
            before_evidence.3
        ),
        "accepted deployment evidence appends its DA business Audit fact"
    );
    material::empty(
        client
            .post(&url)
            .json(&signed(&observation)?)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(
        counts(c).await?,
        evidence_count,
        "same signed observation appends no second fact"
    );
    let mut tx = c.seed().await?;
    assert!(
        business
            .evidence
            .native_on(&mut tx, c.tenant, observation.installation, &anchor, now())
            .await?
            .windows_session(now())
    );
    tx.rollback().await?;
    let mut invalid = Vec::new();
    let mut v = observation.clone();
    v.expires_at = now() - 1;
    invalid.push(v);
    let mut v = observation.clone();
    v.installation = Uuid::new_v4();
    invalid.push(v);
    let mut v = observation.clone();
    v.tenant = Uuid::new_v4();
    invalid.push(v);
    let mut v = observation.clone();
    v.device = Uuid::new_v4().to_string();
    invalid.push(v);
    let mut v = observation.clone();
    v.device.push_str("-different");
    invalid.push(v);
    let mut v = observation.clone();
    v.authority = Uuid::new_v4();
    invalid.push(v);
    let mut v = observation.clone();
    v.revoked = true;
    invalid.push(v); // same sequence with changed content
    for v in invalid {
        let requests_before = request_audits(c).await?;
        assert!(
            client
                .post(&url)
                .json(&signed(&v)?)
                .send()
                .await?
                .status()
                .is_client_error()
        );
        assert_eq!(
            counts(c).await?,
            evidence_count,
            "rejected evidence commits no DA business effects"
        );
        assert_eq!(
            request_audits(c).await?,
            requests_before + 1,
            "rejected evidence retains its request Audit fact"
        );
    }
    let mut tampered = signed(&observation)?;
    tampered.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    let requests_before = request_audits(c).await?;
    assert_eq!(
        client.post(&url).json(&tampered).send().await?.status(),
        403
    );
    assert_eq!(counts(c).await?, evidence_count);
    assert_eq!(
        request_audits(c).await?,
        requests_before + 1,
        "invalid signature retains its denial Audit fact"
    );
    let mut tx = c.seed().await?;
    assert!(
        pg::evidence::Authorities::default()
            .native_on(&mut tx, c.tenant, observation.installation, &anchor, now())
            .await
            .is_err()
    );
    tx.rollback().await?;
    let override_config = pg::configuration::Change {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        publication: Publication {
            revision: 1,
            id: Uuid::new_v4(),
            version: Uuid::new_v4(),
            target: Target::Device {
                device: receipt.device.clone(),
            },
            enabled: false,
            ..publication.clone()
        },
    };
    business
        .service
        .publish_configuration(&current, &override_config, None, &audit(c))
        .await?;
    super::configuration::reject_account_change(
        c,
        m,
        &receipt.device,
        &override_config.publication,
    )
    .await?;
    let mut tx = c.seed().await?;
    assert!(
        business
            .admission
            .policy(&mut tx, observation.tenant, &receipt.device, publication.id)
            .await
            .is_err(),
        "disabled override must block tenant-default fallback"
    );
    assert!(
        business
            .admission
            .policy(
                &mut tx,
                observation.tenant,
                "another-da-device",
                publication.id
            )
            .await
            .is_ok()
    );
    assert!(
        business
            .evidence
            .native_on(&mut tx, c.tenant, observation.installation, &anchor, now())
            .await
            .is_err(),
        "old deployment evidence cannot survive current configuration revocation"
    );
    tx.rollback().await?;
    let absent:bool=sqlx::query_scalar("SELECT to_regclass('mdm_agent.bindings') IS NULL AND to_regclass('mdm_apple.devices') IS NULL AND to_regclass('mdm_windows.devices') IS NULL AND to_regclass('mdm_webhook.events') IS NULL").fetch_one(&c.operator).await?;
    assert!(
        absent,
        "independent DA business never requires an MDM deployment"
    );
    Ok(())
}

// The WebAuthn and Identity owner futures are large in debug builds. Heap-pin each
// ceremony step so neither this proof nor its enclosing business scenario embeds them.
pub(super) async fn operation_proof(
    c: &Context,
    session_secret: &SessionSecret,
    context: rss_identity_core::step_up::StepUpContext,
) -> Result<wire::Secret> {
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
    let origin = url::Url::parse(c.browser_origin.get().expect("initialized host origin"))?;
    let webauthn = Box::pin(rss_identity_postgres::WebauthnAuthority::connect(
        c.authority.clone(),
        "localhost".into(),
        origin.clone(),
        deadline(),
    ))
    .await?;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let session = Box::pin(c.authority.inspect_session(
        c.tenant,
        SessionSecret::parse(session_secret.expose().into())?,
        deadline(),
    ))
    .await?;
    let registration = Box::pin(webauthn.begin_registration(
        session,
        "DA business proof".into(),
        false,
        rss_identity_postgres::RegistrationAuthorization::First,
        deadline(),
    ))
    .await?;
    let response = authenticator.do_registration(origin.clone(), registration.options)?;
    let session = Box::pin(c.authority.inspect_session(
        c.tenant,
        SessionSecret::parse(session_secret.expose().into())?,
        deadline(),
    ))
    .await?;
    Box::pin(webauthn.finish_registration(session, registration.id, response, deadline())).await?;
    let session = Box::pin(c.authority.inspect_session(
        c.tenant,
        SessionSecret::parse(session_secret.expose().into())?,
        deadline(),
    ))
    .await?;
    let challenge = Box::pin(webauthn.begin_authentication(session, context, deadline())).await?;
    let response = authenticator.do_authentication(origin, challenge.options)?;
    let session = Box::pin(c.authority.inspect_session(
        c.tenant,
        SessionSecret::parse(session_secret.expose().into())?,
        deadline(),
    ))
    .await?;
    let grant =
        Box::pin(webauthn.finish_authentication(session, challenge.id, response, deadline()))
            .await?;
    Ok(wire::Secret::parse(grant.expose())?)
}
