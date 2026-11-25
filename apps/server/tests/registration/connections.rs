use super::*;
use rss_mdm_authorization_service::Permission;
use rss_mdm_registration_service::agent::connections;

pub(super) const PRIMARY: &str = "https://localhost:9445";
const REMAINING: &str = "https://localhost";

async fn installation_origin(c: &Context) -> Result<String> {
    let pool = c.inputs.pool("shared", "mdm_command_runtime").await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let origin = connections::installation_origin_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        &c.tenant.to_string(),
        PRIMARY,
    )
    .await?;
    tx.commit().await?;
    pool.close().await;
    Ok(origin)
}

pub(super) async fn first_install_and_rotation(
    c: &Context,
    service: Arc<agent::Service>,
) -> Result<()> {
    // The native command role resolves a locator before any tenant signing material exists.
    assert_eq!(installation_origin(c).await?, PRIMARY);
    let account = c
        .account(&[
            Permission::AgentEnrollmentWrite,
            Permission::RegistrationConfigurationRead,
            Permission::RegistrationConfigurationWrite,
        ])
        .await?;
    let proof = Arc::new(c.authenticate(&account).await?);
    let input = json!({
        "operationId": Uuid::new_v4(), "secret": URL_SAFE_NO_PAD.encode([13;32]),
        "quantity": {"kind": "unlimited"}, "targets": [{"platform":"windows","architecture":"x86_64"}]
    });
    use rss_mdm_management_http::agent_enrollment::{App, routes};
    use tower::ServiceExt;
    let post = |app: App| -> Result<_> {
        let router = axum::Router::new()
            .nest("/{tenant}", routes(app).into_axum())
            .layer(axum::Extension(c.read_auth(proof.clone())))
            .layer(axum::Extension(c.request(&proof)?));
        let request = axum::http::Request::post(format!("/{}/agent-configurations", c.tenant))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&input)?))?;
        Ok(router.oneshot(request))
    };
    for (endpoint_configured, status, code) in [
        (false, 409, "agent_endpoint_not_configured"),
        (true, 503, "service_unavailable"),
    ] {
        let response = post(App {
            registration: None,
            endpoint_configured,
        })?
        .await?;
        assert_eq!(response.status().as_u16(), status);
        let error = axum::body::to_bytes(response.into_body(), 4096).await?;
        assert_eq!(serde_json::from_slice::<Value>(&error)?["code"], code);
    }
    let response = post(App {
        registration: Some(service.clone()),
        endpoint_configured: true,
    })?
    .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"rss-agent-enrollment.json\""
    );
    let file: wire::configuration::ConfigurationFile =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
    let initial = &file.configuration.connections;
    let state = service.connection_state(&proof).await?;
    assert!(state.draft.is_none() && state.deployments.is_empty());
    assert_eq!(state.published.as_ref(), Some(initial));
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
    let rotate = connections::Save {
        operation_id: Uuid::new_v4(),
        expected_revision: initial.configuration.revision,
        preferred_origin: REMAINING.into(),
        origins: vec![REMAINING.into()],
    };
    let draft = service
        .save_connections(&proof, &rotate, &c.request(&proof)?)
        .await?;
    let publish = connections::Publish {
        operation_id: Uuid::new_v4(),
        expected_revision: draft.configuration.revision,
    };
    let mut observation = command::seed_transaction(c).await?;
    connections::record_deployment_on(
        service.profile(),
        &mut observation,
        initial.configuration.tenant_id,
        REMAINING,
        service.service_id()?,
        Uuid::new_v4(),
        1,
    )
    .await?;
    observation.commit().await?;
    let rotated = service
        .publish_connections(&proof, &publish, &c.request(&proof)?)
        .await?;
    rotated
        .configuration
        .validate_successor(&initial.configuration)?;
    assert!(rotated.configuration.revision > initial.configuration.revision);
    assert_eq!(installation_origin(c).await?, REMAINING);
    // Idempotent delivery retains the exact original file even after a change of address.
    let create = serde_json::from_value(input)?;
    let replay = service
        .create_configuration(&proof, &create, &c.request(&proof)?)
        .await?;
    assert!(serde_json::to_vec(&file)? == serde_json::to_vec(&replay)?);
    Ok(())
}
