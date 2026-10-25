use super::*;
use crate::audit_test_support::audit_count;
use crate::test_support::{http::*, runtime::*, *};
use anyhow::Context;
use uuid::Uuid;
const PATH: &str = "/api/v1/settings/first-use";
const ADMISSION: &str = "/api/v1/registration-channels/windows_mdm/admission";
fn input(revision: i64, complete: bool) -> Value {
    json!({"expectedRevision":revision,"intent":{"channels":["windows_mdm"],"capabilities":{"smtp":{"kind":"skip","reason":"本轮不配置邮件"}},"completionRequested":complete}})
}
async fn ok(
    browser: &mut Browser,
    router: &Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let (status, value) = browser.call(router, method, path, body).await?;
    ensure!(status == StatusCode::OK, "{path}: {status} {value}");
    Ok(value)
}
async fn put(browser: &mut Browser, router: &Router, path: &str, body: Value) -> Result<Value> {
    browser.operation = Some(Uuid::new_v4());
    ok(browser, router, Method::PUT, path, Some(body)).await
}
fn progress_router(
    f: &authority::Authority,
    directory: crate::settings::Directory,
    channels: Arc<dyn rss_mdm_management_http::enrollment::channels::Source>,
) -> Result<Router> {
    let source = Arc::new(crate::first_use::FirstUse {
        directory: Arc::new(directory),
        tenant: f.identity.tenant,
        instance: f.identity.instance,
        audit: f.audit.clone(),
        admission: rss_mdm_registration_service::admission::Admission::new(
            f.registration.clone(),
            f.audit.clone(),
        ),
        channels: channels.clone(),
    });
    let enrollment = Arc::new(crate::enrollment::http::HttpState {
        channels,
        service: Arc::new(crate::enrollment::EnrollmentService::new(
            f.registration.clone(),
            f.credentials.clone(),
            f.audit.clone(),
        )),
        native: Arc::new(crate::enrollment_progress::EnrollmentProgress {
            sessions: Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    f.identity.authority.clone(),
                    f.identity.tenant,
                ),
            ),
            windows: None,
            apple: None,
        }),
        devices: Arc::new(crate::device::DeviceService::new(
            f.registration.clone(),
            case_tenant().into(),
            f.audit.clone(),
        )),
        apple: false,
        windows: true,
    });
    f.router(
        Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::first_use::routes(source)
                .merge(
                    rss_mdm_management_http::enrollment::channels::routes().with_state(enrollment),
                )
                .into_axum(),
        ),
    )
}
#[tokio::test]
#[ignore = "MODULE=settings.first_use: real owner readiness, durable intent, CAS and authority"]
async fn progress_recovers_and_completes_only_selected_ready_requirements() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let directory = crate::test_support::settings::directory(&mut fixture).await?;
    let config: Config = serde_json::from_value(fixture.base.clone())?;
    let channels = Arc::new(crate::channel_status::Channels::new(&config));
    let windows = config
        .native_protocols
        .windows
        .context("Windows readiness fixture")?;
    let loaded = channels.material(
        crate::channel_status::ChannelName::Windows,
        crate::windows::Windows::load(
            windows,
            crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,
            crate::device_pki::providers(&config.device_pki)?,
            None,
        ),
    )?;
    channels.mounted(crate::channel_status::ChannelName::Windows)?;
    let loaded = loaded.context("Windows materials ready")?;
    let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
        fixture.pool.clone(),
        fixture.audit.clone(),
        vec![loaded.channel.ca.trust.clone()],
        crate::device_pki::providers(&config.device_pki)?,
    ));
    let channels = Arc::new(crate::registration_channels::Channels {
        preparation: channels,
        windows: Some(Arc::new(loaded)),
        agent: None,
        apple: None,
        pki,
        clock: Arc::new(crate::clock::SystemClock),
    });
    let router = progress_router(&fixture, directory.clone(), channels.clone())?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            let mut admin = crate::test_support::authority::Authority::prepared_browser("admin")?;
            let initial = ok(&mut admin, &router, Method::GET, PATH, None).await?;
            ensure!(
                initial["saved"]["revision"] == 0
                    && initial["complete"] == false
                    && initial["canComplete"] == false
            );
            let draft = put(&mut admin, &router, PATH, input(0, false)).await?;
            ensure!(draft["saved"]["revision"] == 1);
            let original = admin.operation.unwrap();
            let resumed = ok(&mut admin, &router, Method::GET, PATH, None).await?;
            ensure!(
                resumed["saved"] == draft["saved"]
                    && resumed["steps"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|s| s["status"] == "skipped")
            );
            put(
                &mut admin,
                &router,
                ADMISSION,
                json!({"expectedRevision":0,"admission":"paused"}),
            )
            .await?;
            admin.operation = Some(Uuid::new_v4());
            let rejected = admin
                .call(&router, Method::PUT, PATH, Some(input(1, true)))
                .await?;
            ensure!(
                rejected.0 == StatusCode::CONFLICT && rejected.1["code"] == "first_use_not_ready"
            );
            ensure!(
                ok(&mut admin, &router, Method::GET, PATH, None).await?["saved"]["revision"] == 1
            );
            put(
                &mut admin,
                &router,
                ADMISSION,
                json!({"expectedRevision":1,"admission":"allowed"}),
            )
            .await?;
            let complete = put(&mut admin, &router, PATH, input(1, true)).await?;
            ensure!(complete["saved"]["revision"] == 2);
            ensure!(ok(&mut admin, &router, Method::GET, PATH, None).await?["complete"] == true);
            let completed_id = admin.operation.unwrap();
            // A later owner change alters current readiness, never the historical receipt.
            put(
                &mut admin,
                &router,
                ADMISSION,
                json!({"expectedRevision":2,"admission":"paused"}),
            )
            .await?;
            let degraded = ok(&mut admin, &router, Method::GET, PATH, None).await?;
            ensure!(
                degraded["complete"] == false
                    && degraded["saved"]["intent"]["completionRequested"] == true
            );
            admin.operation = Some(completed_id);
            ensure!(
                ok(&mut admin, &router, Method::PUT, PATH, Some(input(1, true))).await? == complete
            );
            let mut first = admin.clone();
            first.operation = Some(Uuid::new_v4());
            let mut second = admin.clone();
            second.operation = Some(Uuid::new_v4());
            let (a, b) = tokio::join!(
                first.call(&router, Method::PUT, PATH, Some(input(2, false))),
                second.call(&router, Method::PUT, PATH, Some(input(2, false)))
            );
            let mut statuses = vec![a?.0.as_u16(), b?.0.as_u16()];
            statuses.sort();
            ensure!(statuses == vec![200, 409]);
            admin.operation = Some(original);
            ensure!(
                admin
                    .call(&router, Method::PUT, PATH, Some(input(0, true)))
                    .await?
                    .0
                    == StatusCode::CONFLICT
            );
            ensure!(
                ok(
                    &mut admin,
                    &router,
                    Method::GET,
                    &format!("{PATH}/operations/{completed_id}"),
                    None
                )
                .await?
                    == complete
            );
            let mut other = crate::test_support::authority::Authority::prepared_browser("other")?;
            let subject = prepared_subject(&other)?;
            identity::seed_grants(case_tenant(), &subject, vec![]).await?;
            ensure!(other.call(&router, Method::GET, PATH, None).await?.0 == StatusCode::FORBIDDEN);
            other.operation = Some(Uuid::new_v4());
            ensure!(
                other
                    .call(&router, Method::PUT, PATH, Some(input(3, false)))
                    .await?
                    .0
                    == StatusCode::FORBIDDEN
            );
            let restarted = progress_router(&fixture, directory.clone(), channels.clone())?;
            async {
                let after = ok(&mut admin, &restarted, Method::GET, PATH, None).await?;
                ensure!(
                    after["saved"]["revision"] == 3
                        && after["saved"]["intent"]["capabilities"]["smtp"]["kind"] == "skip"
                );
                let mut observe = input(3, false);
                observe["intent"]["capabilities"]["smtp"] = json!({"kind":"configure"});
                put(&mut admin, &restarted, PATH, observe).await?;
                let before = audit_count(|r| r.action() == "first_use_read").await?;
                let progress = ok(&mut admin, &restarted, Method::GET, PATH, None).await?;
                ensure!(progress["steps"].as_array().unwrap().iter().any(|s| s["id"]
                        == "smtp"
                        && !s["evidence"].as_array().unwrap().is_empty()));
                ensure!(
                    audit_count(|r| r.action() == "first_use_read").await? == before,
                    "ordinary progress observations must not enqueue audit"
                );
                // A valid peer-tenant credential cannot be used against this host.
                let peer = identity::credential_for(case::peer(), "admin")?;
                let mut cross = Browser {
                    cookies: BTreeMap::from([(
                        "__Host-identity-session".into(),
                        peer.expose().into(),
                    )]),
                    csrf: Some(peer.csrf()),
                    ..Default::default()
                };
                ensure!(
                    !cross
                        .call(&restarted, Method::GET, PATH, None)
                        .await?
                        .0
                        .is_success()
                );
                Ok(())
            }
            .await
        })
        .await
}
#[tokio::test]
#[ignore = "MODULE=settings.first_use: real audited transaction outcome and immutable operation recovery"]
async fn commit_unknown_recovers_original_receipt_and_audit_failure_rolls_back() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            let secret = identity::credential(&fixture.identity, "admin")?;
            let session = fixture
                .identity
                .authority
                .inspect_session(fixture.identity.tenant, secret, crate::identity::deadline())
                .await?;
            let proof = AuthorizedPrincipal::new(session)?
                .load_authorization(&fixture.authorization.clone())
                .await?;
            let id = Uuid::new_v4();
            let audit = RequestAudit::new(case_tenant().into(), "first_use_update", rss_mdm_audit_integration::AuditIntent::Management);
            proof.bind_audit(&audit)?;
            audit.operation(id, "first_use_update", rss_mdm_audit_integration::AuditIntent::Management);
            let update: Update = serde_json::from_value(input(0, false))?;
            let digest = store::fingerprint(&proof, &update)?;
            fixture
                .audit
                .inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck);
            ensure!(matches!(
                store::update(&fixture.audit, &proof, &audit, id, &update, &digest, None).await,
                Err(Error::CommitUnknown)
            ));
            let receipt = store::operation(
                &fixture.audit,
                &proof,
                &audit,
                id,
                Permission::RegistrationConfigurationRead,
            )
            .await?
            .unwrap();
            ensure!(receipt.saved.revision == 1);
            let replay =
                store::update(&fixture.audit, &proof, &audit, id, &update, &digest, None).await?;
            ensure!(serde_json::to_value(replay)? == serde_json::to_value(receipt)?);
            ensure!(store::read(&fixture.audit, &proof, &audit).await?.revision == 1);
            // Tenant/actor/id are independent operation coordinates, including the same UUID.
        let (peer_identity,peer_resources)=identity::identity(case::peer()).await?;
        peer_resources.finish(async {
            let peer_secret=identity::credential_for(case::peer(),"admin")?;
            let peer_session=peer_identity.authority.inspect_session(peer_identity.tenant,peer_secret,crate::identity::deadline()).await?;
            let peer_proof=AuthorizedPrincipal::new(peer_session)?.load_authorization(&fixture.authorization.clone()).await?;
            let peer_audit=RequestAudit::new(case::peer().into(),"first_use_update", rss_mdm_audit_integration::AuditIntent::Management);
            peer_proof.bind_audit(&peer_audit)?;peer_audit.operation(id,"first_use_update", rss_mdm_audit_integration::AuditIntent::Management);
            ensure!(store::read(&fixture.audit,&peer_proof,&peer_audit).await?.revision==0);
            let peer_digest=store::fingerprint(&peer_proof,&update)?;
            ensure!(store::update(&fixture.audit,&peer_proof,&peer_audit,id,&update,&peer_digest,None).await?.saved.revision==1);
            peer_audit.finalize(None);
            Ok(())
        }).await?;
        // Enforce RLS independently of the HTTP host's credential rejection.
        use sqlx::Connection;
        let config:Config=serde_json::from_value(fixture.base.clone())?;
        let mut connection=sqlx::PgConnection::connect_with(&config.access_options()?).await?;
        let mut tx=connection.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
        let visible:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_first_use.intents WHERE tenant_id=$1::uuid").bind(case::peer()).fetch_one(&mut *tx).await?;
        ensure!(visible==0);
        let denied=sqlx::query("INSERT INTO mdm_first_use.operations(tenant_id,actor,operation_id,instance_id,fingerprint,receipt) VALUES($1::uuid,'cross',$2,$3::uuid,$4,'{}')")
            .bind(case::peer()).bind(Uuid::new_v4()).bind(INSTANCE).bind(vec![0u8;32]).execute(&mut *tx).await;
        ensure!(denied.err().and_then(|e|e.as_database_error().and_then(|e|e.code()).map(|c|c.into_owned()))==Some("42501".into()));
        tx.rollback().await?;connection.close().await?;
        // An Audit identity collision must roll back both intent and operation receipt.
        let conflict_id=Uuid::new_v4();
        let conflict_audit=RequestAudit::new(case_tenant().into(),"first_use_update", rss_mdm_audit_integration::AuditIntent::Management);
        proof.bind_audit(&conflict_audit)?;conflict_audit.operation(conflict_id,"first_use_update", rss_mdm_audit_integration::AuditIntent::Management);
        let fact=rss_mdm_audit_integration::Fact::business(&conflict_audit, &format!("first-use:{}:{}:{conflict_id}",proof.instance_id(),proof.principal_id()), 200, "success", None)?;
        let budget=rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
        let staged=fixture.audit.write(fixture.identity.tenant,&budget.source_control(),(&fixture.audit,&fact),|(store,fact),tx|Box::pin(async move {store.append(tx, fact).await})).await;
        ensure!(staged.fold(|_|true,|_|false,|_|false,|_|false,|_|false,|_|false));
        let conflict_input:Update=serde_json::from_value(input(1,false))?;
        let conflict_digest=store::fingerprint(&proof,&conflict_input)?;
        ensure!(store::update(&fixture.audit,&proof,&conflict_audit,conflict_id,&conflict_input,&conflict_digest,None).await.is_err());
        ensure!(store::read(&fixture.audit,&proof,&conflict_audit).await?.revision==1);
        ensure!(store::operation(&fixture.audit,&proof,&conflict_audit,conflict_id,Permission::RegistrationConfigurationRead).await?.is_none());
        conflict_audit.finalize(None);
        audit.finalize(None);
            Ok(())
        })
        .await
}

// The registration configuration journey supplies one actually published package.
// Settings owns the product-wide readiness projection.
pub(crate) async fn published_agent_package_readiness(base: &Value) -> Result<()> {
    use anyhow::Context;
    let mut fixture = authority::Authority::from_config(base.clone()).await?;
    let directory = crate::test_support::settings::directory(&mut fixture).await?;
    let config: Config = serde_json::from_value(base.clone())?;
    let channels = Arc::new(crate::registration_channels::Channels {
        preparation: Arc::new(crate::channel_status::Channels::new(&config)),
        windows: None,
        apple: None,
        agent: None,
        pki: directory.pki.clone(),
        clock: directory.clock.clone(),
    });
    let first_use = progress_router(&fixture, directory.clone(), channels)?;
    // Reuse the same Authority while exercising both independent owner routers.
    let router = crate::test_support::settings::catalog(&fixture, directory)?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let mut user = authority::Authority::prepared_browser("admin")?;
    let settings = user
        .call(&router, Method::GET, "/api/v1/settings/catalog", None)
        .await?;
    ensure!(settings.0 == StatusCode::OK);
    let capability = settings.1["items"]
        .as_array()
        .context("settings items")?
        .iter()
        .find(|item| item["id"] == "agent-package")
        .context("package capability")?;
    ensure!(
        capability["status"] == "configured"
            && capability["configuredCount"] == 1
            && capability["lifecycle"] == "business_configuration",
        "single package projection {capability:?}"
    );
    let path = "/api/v1/settings/first-use";
    let initial = user.call(&first_use, Method::GET, path, None).await?;
    ensure!(initial.0 == StatusCode::OK);
    let previous = user.operation.replace(Uuid::new_v4());
    let selected = user.call(&first_use, Method::PUT, path, Some(json!({"expectedRevision":initial.1["saved"]["revision"],"intent":{"channels":["agent"],"capabilities":{"agent_package":{"kind":"configure"}},"completionRequested":false}}))).await?;
    user.operation = previous;
    ensure!(
        selected.0 == StatusCode::OK,
        "first use selection {selected:?}"
    );
    let progress = user.call(&first_use, Method::GET, path, None).await?;
    ensure!(progress.0 == StatusCode::OK);
    let step = progress.1["steps"]
        .as_array()
        .context("first use steps")?
        .iter()
        .find(|step| step["id"] == "agent_package")
        .context("package readiness")?;
    ensure!(
        step["status"] == "ready",
        "single package first use {step:?}"
    );

    Ok(())
    }).await
}
