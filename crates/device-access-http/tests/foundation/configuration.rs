//! Real authorization, transaction locking and managed-source proofs in the DA foundation.
use super::*;
use rss_mdm_agent_wire::da;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_policy_postgres::device_access as policy;

pub async fn concurrent_export(
    c: &Context,
    client: &reqwest::Client,
    token: &str,
    principal: &AuthorizedPrincipal,
    export: &da::Export,
) -> Result<()> {
    let management = c.management_base();
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
        .post(format!("{management}/configurations"))
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
    let directory = material::success::<serde_json::Value>(
        client
            .get(format!("{management}/admin/configurations"))
            .query(&[("filter", "enabled==true;configuration.windows.kind==whfb")])
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert!(
        !directory["items"]
            .as_array()
            .context("configuration directory")?
            .is_empty()
    );
    assert!(
        directory["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["enabled"] == true && v["configuration"]["windows"]["kind"] == "whfb")
    );
    let missing = material::success::<serde_json::Value>(
        client
            .get(format!("{management}/admin/configurations"))
            .query(&[("filter", "enabled==false")])
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(
        missing["items"],
        serde_json::json!([]),
        "configuration filter must exclude the published enabled row"
    );
    Ok(())
}

pub async fn reject_account_change(
    c: &Context,
    m: &material::Material,
    device: &rss_mdm_agent_wire::DeviceId,
    publication: &da::Publication,
) -> Result<()> {
    let token = material::device_administrator(c, device).await?;
    let actor = c
        .sessions
        .authenticate(
            c.execution(),
            &c.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Bearer(
                rss_identity_core::session::BearerSecret::parse(token)?,
            ),
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(10),
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
            c.execution(),
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
    device: &rss_mdm_agent_wire::DeviceId,
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
    publication: &mut da::Publication,
    observation: &mut rss_mdm_device_access::deployment::Observation,
    ordinary: &da::SignedConfiguration,
) -> Result<()> {
    let management = c.management_base();
    use rss_mdm_agent_wire::runtime::AccessWindowsConfiguration;
    use rss_mdm_device_access::deployment::ConfigurationDeployment;
    use rss_mdm_device_access_postgres::configuration::Change;
    let url = format!("{base}/deployment-evidence");
    let managed = observation.configuration.clone();
    let original = publication.configuration.clone();
    let initial = diagnostic(client, &management, token, &observation.device).await?;
    assert_eq!(initial["evidence"], "verified");
    assert_eq!(
        initial["resolution"]["fields"][0]["source"],
        "managed_mandatory"
    );
    assert_eq!(initial["resolution"]["fields"][0]["locked"], true);
    let effective = serde_json::from_value(initial["resolution"]["configuration"].clone())?;
    let managed_artifact = managed.as_ref().unwrap().artifact;
    let applied = rss_mdm_device_access::deployment::ConfigurationReadback {
        backend_artifact: ordinary.decode()?.operation_id,
        effective,
        managed_sources: [(da::ConfigurationField::Mac, managed_artifact)].into(),
    };
    for (artifact, expected) in [(Uuid::new_v4(), false), (applied.backend_artifact, true)] {
        observation.configuration.as_mut().unwrap().applied =
            Some(rss_mdm_device_access::deployment::ConfigurationReadback {
                backend_artifact: artifact,
                ..applied.clone()
            });
        observation.sequence += 1;
        material::empty(
            client
                .post(&url)
                .json(&business::signed(observation)?)
                .send()
                .await?,
        )
        .await?;
        let read = diagnostic(client, &management, token, &observation.device).await?;
        assert_eq!(read["application"] == "verified_applied", expected);
    }
    let mut other = observation.clone();
    other.authority = business::second_authority();
    other.sequence = 1;
    other.configuration.as_mut().unwrap().applied = None;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(&other)?)
            .send()
            .await?,
    )
    .await?;
    let mut tx = c.seed().await?;
    let anchor = registration::device::endpoints::current_da_in(
        &mut tx,
        &c.tenant.to_string(),
        &other.device,
    )
    .await?
    .unwrap();
    business::assemble(c, m)?
        .evidence
        .native_on(&mut tx, c.tenant, other.installation, &anchor, now())
        .await?;
    // Remove the second witness before exercising subsequent single-authority withdrawals.
    sqlx::query(
        "DELETE FROM rss_da.deployment_evidence WHERE tenant_id=$1 AND device=$2 AND authority=$3",
    )
    .bind(other.tenant)
    .bind(other.device.into_uuid())
    .bind(other.authority)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    for configuration in [
        None,
        Some(ConfigurationDeployment {
            applied: None,
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
        let value = diagnostic(client, &management, token, &observation.device).await?;
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
            .post(format!("{management}/configurations"))
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
        applied: None,
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
    let locked = diagnostic(client, &management, token, &observation.device).await?;
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
        let blocked = diagnostic(client, &management, token, &observation.device).await?;
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
    let released = diagnostic(client, &management, token, &observation.device).await?;
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
    let value = diagnostic(client, &management, token, &observation.device).await?;
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
    let released = diagnostic(client, &management, token, &observation.device).await?;
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
    observation.configuration = managed.clone();
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
    let stale = diagnostic(client, &management, token, &observation.device).await?;
    assert_eq!(
        stale["resolution"]["fields"][0]["locked"], false,
        "regranting a field cannot restore authority to a pre-release artifact"
    );
    let renewed: da::SignedConfiguration = material::success(
        client
            .post(format!("{management}/configurations"))
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
    let content = renewed.decode()?;
    observation.configuration = Some(ConfigurationDeployment {
        artifact: content.operation_id,
        digest: renewed.digest,
        native_digest: content.native.digest,
        delivery: content.delivery,
        state: da::SourceState::Present,
        applied: None,
    });
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    let restored = diagnostic(client, &management, token, &observation.device).await?;
    assert_eq!(restored["evidence"], "verified");
    assert_eq!(restored["resolution"]["fields"][0]["locked"], true);
    // Replay the old carrier after the new lock is established; its higher observation
    // sequence cannot replace the remembered artifact with a pre-release revision.
    let active = std::mem::replace(&mut observation.configuration, managed);
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    let replay = diagnostic(client, &management, token, &observation.device).await?;
    assert_eq!(replay["resolution"]["blocked"], "read_failed");
    observation.configuration = active;
    observation.sequence += 1;
    material::empty(
        client
            .post(&url)
            .json(&business::signed(observation)?)
            .send()
            .await?,
    )
    .await?;
    Ok(())
}

pub async fn verify_override(
    c: &Context,
    m: &material::Material,
    client: &reqwest::Client,
    token: &str,
    observation: &rss_mdm_device_access::deployment::Observation,
    device_policy: &da::Publication,
    base: &str,
) -> Result<()> {
    use rss_mdm_device_access::deployment::{ConfigurationDeployment, ConfigurationReadback};
    use rss_mdm_device_access_postgres::configuration::Change;
    let management = c.management_base();
    let read:serde_json::Value=sqlx::query_scalar("SELECT definition FROM rss_da.policies WHERE tenant_id=$1::uuid AND definition#>>'{target,kind}'='tenant_default'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    let mut default: da::Publication = serde_json::from_value(read)?;
    default.managed_fields = vec![da::ConfigurationField::Mac];
    default.configuration = device_policy.configuration.clone();
    let (separate, peer) = super::activate_grant(
        m,
        client,
        client
            .post(format!("{management}/grants"))
            .bearer_auth(token),
        base,
        1,
    )
    .await?;
    let mut observation = observation.clone();
    observation.device = separate.device;
    let mut target = device_policy.clone();
    target.id = Uuid::new_v4();
    target.version = Uuid::new_v4();
    target.revision = 1;
    target.target = da::Target::Device {
        device: separate.device,
    };
    target.managed_fields.clear();
    let principal = c
        .authority
        .inspect_bearer(
            c.execution(),
            rss_identity_core::session::BearerSecret::parse(token.to_owned())?,
            platform::deadline(),
        )
        .await?
        .account()
        .principal
        .as_uuid();
    let (cookie, csrf) = super::credentials::login(c, client, principal).await?;
    let _: da::Publication = material::success(
        client
            .post(format!(
                "{}/api/v1/tenants/{}/device-access/configurations",
                c.browser_origin, c.tenant
            ))
            .header("origin", &c.browser_origin)
            .header("x-identity-request", "1")
            .header("x-csrf-token", csrf)
            .header("cookie", cookie)
            .json(&Change {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                publication: target.clone(),
            })
            .send()
            .await?,
    )
    .await?;
    default.revision += 1;
    default.version = Uuid::new_v4();
    publish_protected(
        c,
        m,
        &Change {
            operation_id: Uuid::new_v4(),
            expected_revision: default.revision - 1,
            publication: default.clone(),
        },
    )
    .await?;
    let export = |p: &da::Publication, delivery| {
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(token)
            .json(&da::Export {
                operation_id: Uuid::new_v4(),
                policy: p.id,
                version: p.version,
                delivery,
                lifetime_seconds: 600,
            })
            .send()
    };
    let source: da::SignedConfiguration =
        material::success(export(&default, da::DeliveryPermission::ManagedMandatory).await?)
            .await?;
    let backend: da::SignedConfiguration =
        material::success(export(&target, da::DeliveryPermission::Da).await?).await?;
    let trust: da::ConfigurationTrust = material::success(
        peer.get(format!("{base}/configuration-trust"))
            .send()
            .await?,
    )
    .await?;
    material::empty(
        peer.post(format!("{base}/configuration-trust/acknowledgements"))
            .json(&rss_mdm_agent_wire::task_trust::Acknowledgement {
                version: 1,
                operation: Uuid::new_v4(),
                device_id: separate.device,
                revision: trust.revision,
                digest: trust.installation_digest()?,
            })
            .send()
            .await?,
    )
    .await?;
    let current_url = format!("{base}/configuration");
    let snapshot: da::CurrentConfiguration =
        material::success(peer.get(&current_url).send().await?).await?;
    assert_eq!(snapshot.identity.device_id, separate.device);
    assert_eq!(snapshot.publication.unwrap().id, target.id);
    assert_eq!(snapshot.artifact.unwrap().digest, backend.digest);
    assert_eq!(snapshot.authorities.len(), 2);
    let authority = snapshot
        .authorities
        .iter()
        .find(|a| a.policy == default.id)
        .unwrap();
    let signed = source.decode()?;
    assert!(authority.covers_managed_field(&signed, da::ConfigurationField::Mac));
    observation.policy = default.id;
    observation.policy_version = default.version;
    observation.applications.clear();
    observation.configuration = Some(ConfigurationDeployment {
        artifact: signed.operation_id,
        digest: source.digest,
        native_digest: signed.native.digest.clone(),
        delivery: da::DeliveryPermission::ManagedMandatory,
        state: da::SourceState::Present,
        applied: Some(ConfigurationReadback {
            backend_artifact: backend.decode()?.operation_id,
            effective: target.configuration.clone(),
            managed_sources: [(da::ConfigurationField::Mac, signed.operation_id)].into(),
        }),
    });
    observation.sequence += 1;
    material::empty(
        client
            .post(format!("{base}/deployment-evidence"))
            .json(&business::signed(&observation)?)
            .send()
            .await?,
    )
    .await?;
    let current = diagnostic(client, &management, token, &observation.device).await?;
    assert_eq!(current["publication"]["id"], serde_json::json!(target.id));
    assert_eq!(current["application"], "verified_applied");
    default.managed_fields.clear();
    default.revision += 1;
    default.version = Uuid::new_v4();
    publish_protected(
        c,
        m,
        &Change {
            operation_id: Uuid::new_v4(),
            expected_revision: default.revision - 1,
            publication: default.clone(),
        },
    )
    .await?;
    let after: da::CurrentConfiguration =
        material::success(peer.get(&current_url).send().await?).await?;
    assert_eq!(after.publication.unwrap().id, target.id);
    let release = after
        .authorities
        .iter()
        .find(|a| a.policy == default.id)
        .unwrap();
    assert_eq!(
        release.fields[&da::ConfigurationField::Mac],
        da::FieldAuthority {
            authorized: false,
            revision: default.revision as u64
        }
    );
    assert!(!release.covers_managed_field(&signed, da::ConfigurationField::Mac));
    let released = diagnostic(client, &management, token, &observation.device).await?;
    assert_eq!(released["resolution"]["fields"][0]["locked"], false);
    // Damage only this device's backend envelope. The independent issuer release
    // remains readable to both the device and the administrator.
    let operation = backend.decode()?.operation_id;
    let update =
        "UPDATE rss_da.configuration_exports SET result=$3 WHERE tenant_id=$1 AND operation=$2";
    assert_eq!(
        sqlx::query(update)
            .bind(separate.tenant)
            .bind(operation)
            .bind(serde_json::json!({}))
            .execute(&c.operator)
            .await?
            .rows_affected(),
        1
    );
    let invalid: da::CurrentConfiguration =
        material::success(peer.get(&current_url).send().await?).await?;
    assert_eq!(invalid.state, da::SourceState::Invalid);
    assert!(invalid.artifact.is_none());
    let issuer = invalid
        .authorities
        .iter()
        .find(|a| a.policy == default.id)
        .unwrap();
    assert_eq!(issuer.fields, release.fields);
    assert_eq!(
        peer.get(format!("{base}/configurations/{operation}"))
            .send()
            .await?
            .status(),
        409
    );
    let invalid = diagnostic(client, &management, token, &observation.device).await?;
    assert_eq!(invalid["resolution"], released["resolution"]);
    assert_eq!(invalid["application"], "unknown");
    sqlx::query(update)
        .bind(separate.tenant)
        .bind(operation)
        .bind(serde_json::to_value(&backend)?)
        .execute(&c.operator)
        .await?;
    Ok(())
}
