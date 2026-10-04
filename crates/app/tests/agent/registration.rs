//! Persistent grants, candidate possession, activation ACK recovery and same-identity rotation.
use crate::test_support::*;
use rss_mdm_agent_wire::enroll as wire;
use rss_mdm_audit_integration::RequestAudit;
#[tokio::test]
#[ignore = "MODULE=agent.registration"]
async fn registration_binding_and_replay() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let router = crate::test_support::agent::router(&fixture).await?;
    let mut browser = fixture.browser("other")?;
    // Self enrollment requires a live identity, not an enrollment permission.
    let agent = crate::test_support::agent::register(&router, &mut browser).await?;
    let replay = agent_call(
        &router,
        Method::POST,
        "/api/v1/agent/enroll/certificates",
        None,
        Some(agent.request.clone()),
    )
    .await?;
    ensure!(replay.0 == StatusCode::OK);
    let mut changed = agent.request.clone();
    changed["operationId"] = json!(Uuid::new_v4());
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/v1/agent/enroll/certificates",
            None,
            Some(changed)
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    for path in [
        "/api/agent/v1/registrations",
        "/api/agent/v1/reports",
        "/api/agent/enroll/v1/certificates",
        "/api/agent/runtime/v1/reports",
        "/api/agent/v3/registrations",
        "/api/agent/v6/registrations",
        "/api/agent/v6/reports",
        "/api/agent/v6/tasks/claim",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header("host", "mdm.example.test")
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::NOT_FOUND,
            "retired route {path}"
        );
    }
    let body = json!({"wireVersion":1,"collection":agent.registration["collections"][0],"reportId":Uuid::new_v4(),"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"collectionFailed"}});
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/v1/agent/runtime/reports",
            Some(agent.credential),
            Some(body.clone())
        )
        .await?
        .0 == StatusCode::ACCEPTED
    );
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/v1/agent/runtime/reports",
            Some(agent.password),
            Some(body.clone())
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    use sqlx::Connection;
    use std::str::FromStr;
    let cookie = browser
        .cookies
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/agent/runtime/reports")
                .header("host", "mdm.example.test:9445")
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    ensure!(
        response.status() == StatusCode::UNAUTHORIZED,
        "browser Cookie replaced Agent mTLS"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/agent-grants")
                .header("host", "mdm.example.test")
                .header("origin", "https://mdm.example.test")
                .header("x-identity-request", "1")
                .extension(crate::test_support::agent::evidence(agent.credential).unwrap())
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&agent.request)?))?,
        )
        .await?;
    ensure!(
        response.status() == StatusCode::UNAUTHORIZED,
        "Agent credential granted browser management access"
    );
    let registration = agent.registration["registrationId"].as_str().unwrap();
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut owner = sqlx::PgConnection::connect_with(&options).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut owner)
        .await?;
    let before: (i16, String) = sqlx::query_as("SELECT wire_version,capabilities FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=$2::uuid")
        .bind(case_tenant()).bind(registration).fetch_one(&mut owner).await?;
    for query in [
        "UPDATE mdm_agent.bindings SET wire_version=6 WHERE tenant_id=$1::uuid AND registration=$2::uuid",
        "UPDATE mdm_agent.bindings SET capabilities='[\"inventory.collect.v6\"]' WHERE tenant_id=$1::uuid AND registration=$2::uuid",
    ] {
        let error = sqlx::query(query)
            .bind(case_tenant())
            .bind(registration)
            .execute(&mut owner)
            .await
            .unwrap_err();
        let error = error
            .as_database_error()
            .expect("database constraint rejection");
        ensure!(
            error.code().as_deref() == Some("23514")
                && error.constraint() == Some("agent_binding_profile")
        );
    }
    let after: (i16, String) = sqlx::query_as("SELECT wire_version,capabilities FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=$2::uuid")
        .bind(case_tenant()).bind(registration).fetch_one(&mut owner).await?;
    ensure!(
        before == after && after.0 == 1,
        "rejected binding mutation changed persistent identity"
    );
    owner.close().await?;
    let mut retired_profile = agent.request.clone();
    retired_profile["operationId"] = json!(Uuid::new_v4());
    retired_profile["runtime"]["capabilities"] = json!(["inventory.collect.v6"]);
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/v1/agent/enroll/certificates",
            None,
            Some(retired_profile)
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    let native_password=browser.call(&router,Method::POST,"/api/v1/enrollments",Some(json!({"deviceId":"claimed-device","password":agent.password,"source":"agent.builtin"}))).await?;
    ensure!(native_password.0 == StatusCode::BAD_REQUEST);
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=agent.registration"]
async fn registration_recovery_preserves_credential_rotation() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let service = crate::test_support::agent::service(&fixture).await?;
    let router = crate::test_support::agent::router(&fixture).await?;
    let mut browser = fixture.browser("other")?;
    let agent = crate::test_support::agent::register(&router, &mut browser).await?;
    let quota_user = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    let quotas = rss_mdm_registration_service::quotas::Quotas::new(
        fixture.access.registration(),
        fixture.audit.clone(),
    );
    let initial_usage = quotas.usage(&quota_user, None).await?;
    ensure!(initial_usage.channels[0].active == 1 && initial_usage.channels[0].reserved == 0);
    let registration: Uuid = serde_json::from_value(agent.registration["registrationId"].clone())?;
    let secret = credential("rotation-secret");
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"secret":secret,"platform":"macos","csr":crate::test_support::agent::csr()?});
    let grant = browser
        .call(
            &router,
            Method::POST,
            &format!("/api/v1/agent-registrations/{registration}/recovery"),
            Some(input),
        )
        .await?;
    ensure!(grant.0 == StatusCode::OK, "recovery grant {grant:?}");
    ensure!(quotas.usage(&quota_user, None).await?.channels[0].used == 1);
    let sign = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":grant.1["grantId"],"secret":secret,"csr":crate::test_support::agent::csr()?,"runtime":agent.request["runtime"]});
    let candidate = agent_call(
        &router,
        Method::POST,
        "/api/v1/agent/enroll/certificates",
        None,
        Some(sign),
    )
    .await?;
    ensure!(candidate.0 == StatusCode::OK, "candidate {candidate:?}");
    use base64::{Engine, engine::general_purpose::STANDARD};
    let chain = candidate.1["certificateChain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| STANDARD.decode(v.as_str().unwrap()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let peer = crate::test_support::agent_tls::peer(
        service.trust(),
        &chain,
        &std::path::PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?),
    )
    .await?;
    let input = wire::ActivationRequest {
        wire_version: 1,
        issuance_id: serde_json::from_value(candidate.1["issuanceId"].clone())?,
        operation_id: Uuid::new_v4(),
    };
    let a = || RequestAudit::new(case_tenant().into(), "agent_certificate_activate");
    fixture
        .audit
        .inject_next_fault(rss_audit_postgres::PgFault::BeforeCommitPending);
    ensure!(service.activate(&peer, &input, &a()).await.is_err());
    ensure!(
        service
            .authenticate(&crate::test_support::agent::evidence(agent.credential).unwrap())
            .await
            .is_ok()
    );
    fixture
        .audit
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    ensure!(service.activate(&peer, &input, &a()).await.is_err());
    let recovered = service.activate(&peer, &input, &a()).await?;
    ensure!(
        serde_json::to_value(&recovered.runtime)? == agent.registration,
        "rotation changed identity or frozen collections"
    );
    ensure!(service.authenticate(&peer).await?.registration() == registration);
    ensure!(quotas.usage(&quota_user, None).await?.channels[0].used == 1);
    ensure!(
        service
            .authenticate(&crate::test_support::agent::evidence(agent.credential).unwrap())
            .await
            .err()
            .unwrap()
            .code
            == wire::ErrorCode::CredentialRetired
    );
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=agent.registration"]
async fn browser_approval_quota_expiry_and_restart_are_durable() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let service = crate::test_support::agent::service(&fixture).await?;
    let user = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    let mut quota_tx = fixture.access.begin(case_tenant()).await?;
    sqlx::query("INSERT INTO mdm_access.registration_quota_settings(tenant_id,subject,revision,agent) VALUES($1::uuid,$2,1,1)")
        .bind(case_tenant()).bind(format!("user:{}:{}",user.instance_id(),user.principal_id())).execute(&mut *quota_tx).await?;
    quota_tx.commit().await?;
    let a = || RequestAudit::new(case_tenant().into(), "agent_authorization_request");
    let input: wire::GrantRequest = serde_json::from_value(
        json!({"wireVersion":1,"operationId":Uuid::new_v4(),"secret":credential("pending"),"platform":"macos","csr":crate::test_support::agent::csr()?}),
    )?;
    let pending = service.request(&input, &a()).await?;
    ensure!(pending.state == wire::GrantState::Pending);
    let sign: wire::CertificateRequest = serde_json::from_value(
        json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":pending.grant_id,"secret":input.secret,"csr":input.csr,"runtime":{"capabilities":["inventory.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)}}),
    )?;
    ensure!(
        service.issue(&sign, &a()).await.err().unwrap().code == wire::ErrorCode::PermissionDenied
    );
    ensure!(
        service
            .preview(&user, pending.grant_id)
            .await?
            .public_key_fingerprint
            .len()
            == 64
    );
    let approval = Uuid::new_v4();
    let approved = service
        .approve(&user, pending.grant_id, approval, &a())
        .await?;
    ensure!(approved.state == wire::GrantState::Available);
    let mut second = input.clone();
    second.operation_id = Uuid::new_v4();
    second.platform = rss_mdm_agent_wire::runtime::TaskPlatform::Windows;
    ensure!(
        service
            .create(&user, &second, &a())
            .await
            .err()
            .unwrap()
            .code
            == wire::ErrorCode::RegistrationLimit
    );
    let revoke = Uuid::new_v4();
    service
        .revoke(&user, pending.grant_id, revoke, &a())
        .await?;
    ensure!(
        service
            .approve(&user, pending.grant_id, approval, &a())
            .await?
            == approved,
        "approval replay must retain the fixed result"
    );
    ensure!(service.issue(&sign, &a()).await.err().unwrap().code == wire::ErrorCode::GrantRevoked);
    let created = service.create(&user, &second, &a()).await?;
    let restart = crate::test_support::agent::service(&fixture).await?;
    ensure!(restart.create(&user, &second, &a()).await? == created);
    let mut invalid = second.clone();
    invalid.lifetime_seconds = Some(604801);
    ensure!(
        restart
            .create(&user, &invalid, &a())
            .await
            .err()
            .unwrap()
            .code
            == wire::ErrorCode::MalformedRequest
    );
    pg(&format!(
        "UPDATE mdm_access.agent_grants SET created_at=clock_timestamp()-interval '25 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        created.grant_id
    ))?;
    let mut expired = sign;
    expired.grant_id = created.grant_id;
    ensure!(
        restart.issue(&expired, &a()).await.err().unwrap().code == wire::ErrorCode::GrantExpired
    );
    Ok(())
}
