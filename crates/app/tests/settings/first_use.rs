use super::*;
use crate::test_support::*;
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
#[tokio::test]
#[ignore = "MODULE=settings.first_use: real owner readiness, durable intent, CAS and authority"]
async fn progress_recovers_and_completes_only_selected_ready_requirements() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let (router, resources) = app(&base).await?;
    resources
        .finish(async {
            let mut admin = Browser::default();
            ensure!(admin.login(&router, "admin").await? == StatusCode::OK);
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
            let mut other = Browser::default();
            ensure!(other.login(&router, "other").await? == StatusCode::OK);
            let subject = browser_subject(&other, &router).await?;
            identity::set_grants(case_tenant(), &subject, vec![]).await?;
            ensure!(other.call(&router, Method::GET, PATH, None).await?.0 == StatusCode::FORBIDDEN);
            other.operation = Some(Uuid::new_v4());
            ensure!(
                other
                    .call(&router, Method::PUT, PATH, Some(input(3, false)))
                    .await?
                    .0
                    == StatusCode::FORBIDDEN
            );
            let (restarted, resources) = app(&base).await?;
            resources
                .finish(async {
                    let after = ok(&mut admin, &restarted, Method::GET, PATH, None).await?;
                    ensure!(
                        after["saved"]["revision"] == 3
                            && after["saved"]["intent"]["capabilities"]["smtp"]["kind"] == "skip"
                    );
                    let mut observe = input(3, false);
                    observe["intent"]["capabilities"]["smtp"] = json!({"kind":"configure"});
                    put(&mut admin, &restarted, PATH, observe).await?;
                    let before = audit_count(|r| r.action() == "first_use_read")?;
                    let progress = ok(&mut admin, &restarted, Method::GET, PATH, None).await?;
                    ensure!(progress["steps"].as_array().unwrap().iter().any(|s| s["id"]
                        == "smtp"
                        && !s["evidence"].as_array().unwrap().is_empty()));
                    ensure!(
                        audit_count(|r| r.action() == "first_use_read")? == before + 1,
                        "owner observations changed the enclosing Audit action"
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
                })
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
                .load_authorization(&fixture.access.authorization_store())
                .await?;
            let id = Uuid::new_v4();
            let audit = RequestAudit::new(case_tenant().into(), "first_use_update");
            proof.bind_audit(&audit)?;
            audit.operation(id, "first_use_update");
            let update: Update = serde_json::from_value(input(0, false))?;
            let digest = store::fingerprint(&proof, &update)?;
            fixture
                .audit
                .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
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
            let peer_proof=AuthorizedPrincipal::new(peer_session)?.load_authorization(&fixture.access.authorization_store()).await?;
            let peer_audit=RequestAudit::new(case::peer().into(),"first_use_update");
            peer_proof.bind_audit(&peer_audit)?;peer_audit.operation(id,"first_use_update");
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
        let conflict_audit=RequestAudit::new(case_tenant().into(),"first_use_update");
        proof.bind_audit(&conflict_audit)?;conflict_audit.operation(conflict_id,"first_use_update");
        let fact=rss_mdm_audit_integration::Fact::business(&conflict_audit,&format!("first-use:{}:{}:{conflict_id}",proof.instance_id(),proof.principal_id()),b"different-request",200,"success",None)?;
        let budget=rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
        let staged=fixture.audit.write(fixture.identity.tenant,&budget.control(),(&fixture.audit,&fact),|(store,fact),tx|Box::pin(async move {store.append(tx,fact,false).await})).await;
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
