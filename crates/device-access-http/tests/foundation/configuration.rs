//! Real authorization, transaction locking and managed-source proofs in the DA foundation.
use super::*;
use rss_mdm_agent_wire::da;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_policy_postgres::device_access as policy;

pub async fn concurrent_export(
    c: &Context,
    client: &reqwest::Client,
    base: &str,
    token: &str,
    principal: &AuthorizedPrincipal,
    export: &da::Export,
) -> Result<()> {
    let mut tx = c.seed().await?;
    rss_mdm_authorization_service::lock_on(
        principal.authority_profile(),
        &mut tx,
        principal.tenant_id(),
        principal.instance_id(),
    )
    .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    let mut request = export.clone();
    request.operation_id = Uuid::new_v4();
    let request = client
        .post(format!("{base}/configurations"))
        .bearer_auth(token)
        .json(&request);
    let export = tokio::spawn(async move { request.send().await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&c.operator)
            .await?;
            if waiting {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    // A query holding authorization can take the publication lock while export waits.
    // The former export ordering held this lock and created a real PostgreSQL lock ring.
    tokio::time::timeout(
        Duration::from_secs(2),
        policy::lock_publications_on(&mut tx, Uuid::parse_str(&c.tenant.to_string())?),
    )
    .await??;
    tx.rollback().await?;
    material::success::<da::SignedConfiguration>(export.await??).await?;
    material::success::<serde_json::Value>(
        client
            .get(format!("{base}/admin/configurations"))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    Ok(())
}

pub async fn reject_account_change(
    c: &Context,
    m: &material::Material,
    device: &str,
    publication: &policy::Publication,
) -> Result<()> {
    let token = material::device_administrator(c, device).await?;
    let actor = c
        .sessions
        .authenticate(
            &c.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Bearer(
                rss_identity_core::session::BearerSecret::parse(token)?,
            ),
        )
        .await?;
    let mut changed = publication.clone();
    changed.enabled = !changed.enabled;
    changed.revision += 1;
    changed.version = Uuid::new_v4();
    let result = business::assemble(c, m)?
        .service
        .publish_configuration(
            &actor,
            &rss_mdm_device_access_postgres::configuration::Change {
                operation_id: Uuid::new_v4(),
                expected_revision: publication.revision,
                publication: changed,
            },
            None,
            &business::audit(c),
        )
        .await;
    assert!(
        matches!(
            result,
            Err(rss_mdm_device_access_postgres::Error::Forbidden)
        ),
        "configuration permission cannot enable/disable server account policy"
    );
    Ok(())
}

pub async fn publish_protected(
    c: &Context,
    m: &material::Material,
    change: &rss_mdm_device_access_postgres::configuration::Change,
) -> Result<()> {
    let token = material::administrator(c).await?;
    let principal = c
        .authority
        .inspect_bearer(
            c.tenant,
            rss_identity_core::session::BearerSecret::parse(token)?,
            platform::deadline(),
        )
        .await?
        .account()
        .principal
        .as_uuid();
    let (actor, secret) = Box::pin(business::login(c, principal)).await?;
    let service = &business::assemble(c, m)?.service;
    assert!(matches!(
        service
            .publish_configuration(&actor, change, None, &business::audit(c))
            .await,
        Err(rss_mdm_device_access_postgres::Error::Unauthorized)
    ));
    let proof = Box::pin(business::operation_proof(
        c,
        &secret,
        change.step_up_context(&actor)?,
    ))
    .await?;
    service
        .publish_configuration(&actor, change, Some(&proof), &business::audit(c))
        .await?;
    Ok(())
}

pub async fn diagnostic(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    device: &str,
) -> Result<serde_json::Value> {
    material::success(
        client
            .get(format!("{base}/admin/devices/{device}/configuration"))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "Existing foundation owns real transport, policy and signed platform evidence"
)]
pub async fn verify_sources(
    c: &Context,
    m: &material::Material,
    client: &reqwest::Client,
    base: &str,
    token: &str,
    actor: &AuthorizedPrincipal,
    publication: &mut policy::Publication,
    observation: &mut rss_mdm_device_access::deployment::Observation,
    ordinary: &da::SignedConfiguration,
) -> Result<()> {
    use rss_mdm_agent_wire::runtime::AccessWindowsConfiguration;
    use rss_mdm_device_access::deployment::ConfigurationDeployment;
    use rss_mdm_device_access_postgres::configuration::Change;
    let url = format!("{base}/deployment-evidence");
    let managed = observation.configuration.clone();
    let original = publication.configuration.clone();
    let initial = diagnostic(client, base, token, &observation.device).await?;
    assert_eq!(initial["evidence"], "verified");
    assert_eq!(
        initial["resolution"]["fields"][0]["source"],
        "managed_mandatory"
    );
    assert_eq!(initial["resolution"]["fields"][0]["locked"], true);
    for configuration in [
        None,
        Some(ConfigurationDeployment {
            artifact: ordinary.decode()?.operation_id,
            digest: ordinary.digest.clone(),
            native_digest: ordinary.decode()?.native.digest,
            delivery: da::DeliveryPermission::Da,
            state: da::SourceState::Present,
        }),
    ] {
        observation.sequence += 1;
        observation.configuration = configuration;
        material::empty(
            client
                .post(&url)
                .json(&business::signed(observation)?)
                .send()
                .await?,
        )
        .await?;
        let value = diagnostic(client, base, token, &observation.device).await?;
        assert_eq!(
            value["resolution"]["blocked"], "read_failed",
            "new snapshots cannot silently clear mandatory source history"
        );
        assert!(value["resolution"]["configuration"].is_null());
    }
    observation.configuration = managed.clone();
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    // A -> B -> A: a narrower, still valid old managed package cannot erase a
    // Windows lock established by the newer package without a protected release.
    publication
        .managed_fields
        .push(da::ConfigurationField::Windows);
    publication.revision += 1;
    publication.version = Uuid::new_v4();
    publish_protected(
        c,
        m,
        &Change {
            operation_id: Uuid::new_v4(),
            expected_revision: publication.revision - 1,
            publication: publication.clone(),
        },
    )
    .await?;
    let broader: da::SignedConfiguration = material::success(
        client
            .post(format!("{base}/configurations"))
            .bearer_auth(token)
            .json(&da::Export {
                operation_id: Uuid::new_v4(),
                policy: publication.id,
                version: publication.version,
                delivery: da::DeliveryPermission::ManagedMandatory,
                lifetime_seconds: 600,
            })
            .send()
            .await?,
    )
    .await?;
    let content = broader.decode()?;
    observation.configuration = Some(ConfigurationDeployment {
        artifact: content.operation_id,
        digest: broader.digest,
        native_digest: content.native.digest,
        delivery: da::DeliveryPermission::ManagedMandatory,
        state: da::SourceState::Present,
    });
    observation.policy_version = publication.version;
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    let locked = diagnostic(client, base, token, &observation.device).await?;
    assert_eq!(locked["resolution"]["fields"][1]["locked"], true);
    for candidate in [managed.clone(), None] {
        observation.configuration = candidate;
        observation.sequence += 1;
        material::empty(
            client
                .post(&url)
                .json(&business::signed(observation)?)
                .send()
                .await?,
        )
        .await?;
        let blocked = diagnostic(client, base, token, &observation.device).await?;
        assert!(!blocked["resolution"]["blocked"].is_null());
        assert!(
            blocked["resolution"]["configuration"].is_null(),
            "old narrow package cannot release Windows"
        );
    }
    publication.managed_fields = vec![da::ConfigurationField::Mac];
    publication.revision += 1;
    publication.version = Uuid::new_v4();
    publish_protected(
        c,
        m,
        &Change {
            operation_id: Uuid::new_v4(),
            expected_revision: publication.revision - 1,
            publication: publication.clone(),
        },
    )
    .await?;
    observation.configuration = managed.clone();
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    let released = diagnostic(client, base, token, &observation.device).await?;
    assert!(released["resolution"]["blocked"].is_null());
    assert_eq!(released["resolution"]["fields"][1]["locked"], false);
    // Ordinary V2 changes differ in both groups. The managed Mac V1 stays locked while
    // Windows takes V2; this must not make old evidence current for native login.
    publication.version = Uuid::new_v4();
    publication.revision += 1;
    publication.configuration.mac = None;
    publication.configuration.windows = AccessWindowsConfiguration::Whfb;
    let service = &business::assemble(c, m)?.service;
    service
        .publish_configuration(
            actor,
            &Change {
                operation_id: Uuid::new_v4(),
                expected_revision: publication.revision - 1,
                publication: publication.clone(),
            },
            None,
            &business::audit(c),
        )
        .await?;
    let value = diagnostic(client, base, token, &observation.device).await?;
    assert_eq!(value["evidence"], "verified");
    assert!(value["resolution"]["blocked"].is_null());
    assert_eq!(
        value["resolution"]["configuration"]["mac"],
        serde_json::to_value(&original.mac)?
    );
    assert_eq!(
        value["resolution"]["configuration"]["windows"]["kind"],
        "whfb"
    );
    assert_eq!(value["resolution"]["fields"][0]["backendIgnored"], true);
    assert_eq!(value["resolution"]["fields"][1]["locked"], false);
    let mut tx = c.seed().await?;
    let anchor = registration::device::endpoints::current_da_in(
        &mut tx,
        &c.tenant.to_string(),
        &observation.device,
    )
    .await?
    .unwrap();
    assert!(
        business::assemble(c, m)?
            .evidence
            .native_on(&mut tx, c.tenant, observation.installation, &anchor, now())
            .await
            .is_err()
    );
    tx.rollback().await?;

    // Only an authenticated, stepped-up release can remove the remembered lock.
    publication.managed_fields.clear();
    publication.version = Uuid::new_v4();
    publication.revision += 1;
    publish_protected(
        c,
        m,
        &Change {
            operation_id: Uuid::new_v4(),
            expected_revision: publication.revision - 1,
            publication: publication.clone(),
        },
    )
    .await?;
    observation.configuration = None;
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    let released = diagnostic(client, base, token, &observation.device).await?;
    assert!(released["resolution"]["blocked"].is_null());
    assert_eq!(released["resolution"]["fields"][0]["locked"], false);

    // Restore the real native fixture with an explicitly reauthorized managed source.
    publication.configuration = original;
    publication.managed_fields = vec![da::ConfigurationField::Mac];
    publication.version = Uuid::new_v4();
    publication.revision += 1;
    publish_protected(
        c,
        m,
        &Change {
            operation_id: Uuid::new_v4(),
            expected_revision: publication.revision - 1,
            publication: publication.clone(),
        },
    )
    .await?;
    observation.configuration = managed;
    observation.policy_version = publication.version;
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    let restored = diagnostic(client, base, token, &observation.device).await?;
    assert_eq!(restored["evidence"], "verified");
    assert_eq!(restored["resolution"]["fields"][0]["locked"], true);
    Ok(())
}
