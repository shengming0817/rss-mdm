use super::*;
use rss_mdm_agent_wire::connections::SignedConfiguration as Signed;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal as Principal};
use rss_mdm_management_http::agent_enrollment::{App, routes};
use rss_mdm_registration_service::agent::connections;
use tower::ServiceExt;

pub(super) const PRIMARY: &str = "https://localhost:9445";
const REMAINING: &str = "https://localhost";

pub(super) async fn first_install_and_rotation(
    c: &Context,
    service: Arc<agent::Service>,
) -> Result<()> {
    recovery_before_issuance(c, service.clone()).await?;
    let proof = editor(c).await?;
    let input = create_input();
    let file = download(c, &proof, &input, service.clone()).await?;
    let state = service.connection_state(&proof).await?;
    verify(&file, &state)?;
    rotate(c, &service, &proof, &file.configuration.connections).await?;
    // Replaying the original operation after rotation still returns the original bytes.
    let create = serde_json::from_value(input)?;
    let replay = service
        .create_configuration(&proof, &create, &c.request(&proof)?)
        .await?;
    assert!(serde_json::to_vec(&file)? == serde_json::to_vec(&replay)?);
    let cold = fresh_tenant(&service).await?;
    let admin = editor(&cold).await?;
    assert_eq!(
        concurrent_files(&cold, &service, &admin)
            .await?
            .configuration
            .revision,
        1
    );
    cold.close().await;
    Ok(())
}

fn create_input() -> Value {
    json!({"operationId":Uuid::new_v4(), "secret":URL_SAFE_NO_PAD.encode([13;32]),
        "quantity":{"kind":"unlimited"}, "targets":[{"platform":"windows","architecture":"x86_64"}]})
}

async fn editor(c: &Context) -> Result<Arc<Principal>> {
    let account = c
        .account(&[
            Permission::AgentEnrollmentWrite,
            Permission::RegistrationConfigurationRead,
        ])
        .await?;
    Ok(Arc::new(c.authenticate(&account).await?))
}

async fn recovery_before_issuance(c: &Context, service: Arc<agent::Service>) -> Result<()> {
    let read = c
        .account(&[Permission::RegistrationConfigurationRead])
        .await?;
    let reader = Arc::new(c.authenticate(&read).await?);
    let recovery = axum::Router::new()
        .nest(
            "/{tenant}",
            routes(App {
                registration: Some(service.clone()),
                endpoint_configured: true,
            })
            .into_axum(),
        )
        .layer(axum::Extension(c.read_auth(reader.clone())));
    let request =
        axum::http::Request::get(format!("/{}/agent-connections/configuration", c.tenant))
            .body(axum::body::Body::empty())?;
    assert_eq!(recovery.oneshot(request).await?.status(), 409);
    let untouched = service.connection_state(&reader).await?;
    assert!(untouched.configuration.is_none() && untouched.verification_keys.is_empty());
    Ok(())
}

async fn post(
    c: &Context,
    proof: &Arc<Principal>,
    input: &Value,
    app: App,
) -> Result<axum::response::Response> {
    let router = axum::Router::new()
        .nest("/{tenant}", routes(app).into_axum())
        .layer(axum::Extension(c.read_auth(proof.clone())))
        .layer(axum::Extension(c.request(proof)?));
    let request = axum::http::Request::post(format!("/{}/agent-configurations", c.tenant))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(input)?))?;
    Ok(router.oneshot(request).await?)
}

async fn download(
    c: &Context,
    proof: &Arc<Principal>,
    input: &Value,
    service: Arc<agent::Service>,
) -> Result<wire::configuration::ConfigurationFile> {
    for (endpoint_configured, status, code) in [
        (false, 409, "agent_endpoint_not_configured"),
        (true, 503, "service_unavailable"),
    ] {
        let response = post(
            c,
            proof,
            input,
            App {
                registration: None,
                endpoint_configured,
            },
        )
        .await?;
        assert_eq!(response.status().as_u16(), status);
        let error = axum::body::to_bytes(response.into_body(), 4096).await?;
        assert_eq!(serde_json::from_slice::<Value>(&error)?["code"], code);
    }
    let response = post(
        c,
        proof,
        input,
        App {
            registration: Some(service),
            endpoint_configured: true,
        },
    )
    .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"rss-agent-enrollment.json\""
    );
    let file: wire::configuration::ConfigurationFile =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
    Ok(file)
}

fn verify(file: &wire::configuration::ConfigurationFile, state: &connections::State) -> Result<()> {
    let initial = &file.configuration.connections;
    assert_eq!(state.configuration.as_ref(), Some(initial));
    assert_eq!(initial.configuration.preferred_origin, PRIMARY);
    assert_eq!(initial.configuration.origins, [REMAINING, PRIMARY]);
    let key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        URL_SAFE_NO_PAD.decode(&state.verification_keys[&file.configuration.key_id])?,
    );
    for (bytes, signature) in [
        (
            file.configuration.signing_bytes(&file.secret)?,
            &file.signature,
        ),
        (initial.configuration.signing_bytes()?, &initial.signature),
    ] {
        key.verify(&bytes, &URL_SAFE_NO_PAD.decode(signature)?)
            .map_err(|_| anyhow::anyhow!("invalid installed configuration signature"))?;
    }
    Ok(())
}

async fn rotate(
    c: &Context,
    service: &agent::Service,
    proof: &Principal,
    initial: &Signed,
) -> Result<()> {
    let mut runtime: Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    runtime["identity"]["instance_id"] = json!(c.inputs.installation.instance_id);
    runtime["native_protection"]["active_file"] = json!(c.inputs.directory.join("native.key"));
    runtime["native_protection"]["fingerprint_file"] =
        json!(c.inputs.directory.join("fingerprint.key"));
    runtime["agent_pki"] = json!({"mode":"step_ca","endpoint":{"origin":REMAINING}});
    let pool = c.inputs.pool("shared", "mdm_owner").await?;
    let mut operator = pool.acquire().await?;
    let config: crate::config::Config = serde_json::from_value(runtime.clone())?;
    let binding = &config.runtime_binding;
    let directory = tempfile::tempdir()?;
    let journal = rss_mdm_install_support::maintenance::journal::Journal::open(
        &directory.path().canonicalize()?.join("host"),
    )?;
    for agent_mounted in [false, true, true] {
        let observed = crate::installation::host::Observation::new(
            binding,
            config.identity.instance_id.clone(),
            agent_mounted,
            vec![],
        );
        let applied = serde_json::from_value(serde_json::to_value(observed)?)?;
        crate::installation::runtime_files::complete_observation(
            &journal,
            &config,
            &runtime,
            applied,
            Some(&mut operator),
        )
        .await?;
        if !agent_mounted {
            let current = service
                .connection_state(proof)
                .await?
                .configuration
                .unwrap();
            assert_eq!(
                current.configuration.revision,
                initial.configuration.revision
            );
        }
    }
    drop(operator);
    pool.close().await;
    let rotated = service
        .connection_state(proof)
        .await?
        .configuration
        .expect("issued tenant");
    rotated
        .configuration
        .validate_successor(&initial.configuration)?;
    assert_eq!(
        rotated.configuration.revision,
        initial.configuration.revision + 1
    );
    assert_eq!(rotated.configuration.preferred_origin, REMAINING);
    Ok(())
}
pub(super) async fn fresh_tenant(service: &agent::Service) -> Result<Context> {
    let c = Context::open("shared", &[]).await?;
    let mut setup = command::seed_transaction(&c).await?;
    agent::settings::initialize_on(service.profile(), &mut setup, &c.tenant.to_string()).await?;
    setup.commit().await?;
    Ok(c)
}

async fn concurrent_files(
    c: &Context,
    service: &agent::Service,
    proof: &Principal,
) -> Result<Signed> {
    let first = serde_json::from_value(create_input())?;
    let other = serde_json::from_value(create_input())?;
    let first_audit = c.request(proof)?;
    let other_audit = c.request(proof)?;
    let (first, other) = tokio::try_join!(
        service.create_configuration(proof, &first, &first_audit),
        service.create_configuration(proof, &other, &other_audit)
    )?;
    let active = first.configuration.connections;
    assert_eq!(active, other.configuration.connections);
    Ok(active)
}
