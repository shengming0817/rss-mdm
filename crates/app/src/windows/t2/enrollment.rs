use crate::windows::test_support::*;
use crate::windows::*;
use crate::{api::Assembly, device::test_support::options};
use anyhow::ensure;
use sqlx::{Connection, PgConnection};
use std::time::Duration;
#[tokio::test]
#[ignore = "make t2 MODULE=windows.enrollment"]
async fn discovery_wstep_replay_and_tls_identity() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let app = &host.app;
    let client = &host.client;
    ensure!(
        client
            .get(format!(
                "{}/accepted-peer",
                app.windows()?.config.enrollment.origin
            ))
            .header("x-forwarded-for", "198.51.100.23")
            .send()
            .await?
            .text()
            .await?
            == "127.0.0.1",
        "TLS requests lost the RSS-owned accepted peer"
    );
    let peer = host.peer().await?;
    let token = peer
        .issue
        .header
        .security
        .as_ref()
        .unwrap()
        .username
        .as_ref()
        .unwrap();
    discover_and_policy(
        client,
        app,
        peer.receipt.enrollment_id,
        token.password.0.as_str(),
    )
    .await?;
    rejected_csrs(client, &peer.path, &peer.issue).await?;
    let retry = client
        .post(&peer.path)
        .header("content-type", "application/soap+xml")
        .body(peer.wire.clone())
        .send()
        .await?;
    ensure!(retry.status() == StatusCode::OK);
    let replay =
        soap::decode_response(&peer.issue, &retry.bytes().await?, &CodecLimits::default())?;
    let Body::IssueResponse(replay) = replay.body else {
        anyhow::bail!("missing issuance replay");
    };
    ensure!(replay.provisioning.0 == peer.provisioning);
    let root = &host.root;
    let root_cert = &host.root_cert;
    let url = &peer.url;
    ensure!(
        client
            .post(url)
            .body("no certificate")
            .send()
            .await
            .is_err(),
        "management accepted an anonymous TLS handshake"
    );
    let rogue_identity = reqwest::Identity::from_pem(
        &[
            std::fs::read(root.join("rogue-client.pem"))?,
            std::fs::read(root.join("device.key"))?,
        ]
        .concat(),
    )?;
    let rogue = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root_cert.clone())
        .identity(rogue_identity)
        .timeout(Duration::from_secs(12))
        .build()?;
    ensure!(
        rogue
            .post(url)
            .body("untrusted chain")
            .send()
            .await
            .is_err(),
        "management accepted an untrusted client CA"
    );
    let reference = host.reference;
    let secret = rss_identity_core::session::SessionSecret::parse(host.secret.expose().into())?;
    let actor = app
        .identity
        .authority
        .authenticate_session(app.identity.tenant, secret, crate::identity::deadline())
        .await?;
    app.identity
        .authority
        .revoke_current_session(actor, crate::identity::deadline())
        .await?;
    ensure!(
        app.identity
            .authenticate(app.credentials.get(reference)?)
            .await
            .is_err()
    );
    host.close().await?;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "integration matrix keeps actual Discovery/XCEP success and denial assertions together"
)]
async fn discover_and_policy(
    client: &reqwest::Client,
    app: &Assembly,
    enrollment: Uuid,
    password: &str,
) -> anyhow::Result<()> {
    let origin = &app.windows()?.config.enrollment.origin;
    let mut discovery = soap::decode(
        include_bytes!("../../../../windows-mdm/tests/fixtures/discovery-request.xml"),
        Operation::Discover,
        &CodecLimits::default(),
    )?;
    let discovery_url = format!("{origin}/EnrollmentServer/Discovery.svc");
    discovery.header.to = Some(discovery_url.clone());
    let response = client
        .post(&discovery_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&discovery, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let discovery_audit = response.headers()["x-request-id"].to_str()?.to_owned();
    let decoded = soap::decode_response(
        &discovery,
        &response.bytes().await?,
        &CodecLimits::default(),
    )?;
    let Body::DiscoverResponse(found) = decoded.body else {
        anyhow::bail!("not Discovery response")
    };
    ensure!(found.enrollment_version == "4.0");
    ensure!(found.policy_url == format!("{origin}/EnrollmentServer/Policy.svc"));
    ensure!(found.enrollment_url == format!("{origin}/EnrollmentServer/Enrollment.svc"));
    let mut policy = soap::decode(
        include_bytes!("../../../../windows-mdm/tests/fixtures/policy-request.xml"),
        Operation::GetPolicies,
        &CodecLimits::default(),
    )?;
    policy.header.to = Some(found.policy_url.clone());
    let token = policy
        .header
        .security
        .as_mut()
        .unwrap()
        .username
        .as_mut()
        .unwrap();
    token.username = Secret(enrollment.to_string());
    token.password = Secret(password.to_owned());
    let response = client
        .post(&found.policy_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&policy, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let policy_audit = response.headers()["x-request-id"].to_str()?.to_owned();
    let decoded =
        soap::decode_response(&policy, &response.bytes().await?, &CodecLimits::default())?;
    let Body::GetPoliciesResponse(found_policy) = decoded.body else {
        anyhow::bail!("not XCEP response")
    };
    ensure!(found_policy.minimum_key_length == 2048 && found_policy.validity_seconds == 90 * 86400);
    for (request, url) in [(&discovery, &discovery_url), (&policy, &found.policy_url)] {
        let mut bad = request.clone();
        bad.header.to = Some("https://outside.invalid/EnrollmentServer/Policy.svc".into());
        for (message, host) in [(&bad, None), (request, Some("outside.invalid"))] {
            let mut call = client
                .post(url)
                .header("content-type", "application/soap+xml")
                .body(soap::encode(message, &CodecLimits::default())?);
            if let Some(host) = host {
                call = call.header("host", host);
            }
            let response = call.send().await?;
            ensure!(response.status() == StatusCode::INTERNAL_SERVER_ERROR);
            let fault = soap::decode(
                &response.bytes().await?,
                Operation::Fault,
                &CodecLimits::default(),
            )?;
            ensure!(matches!(
                fault.body,
                Body::Fault(soap::FaultKind::MessageFormat)
            ));
        }
    }
    policy
        .header
        .security
        .as_mut()
        .unwrap()
        .username
        .as_mut()
        .unwrap()
        .password = Secret(crate::enrollment::random());
    let denied = client
        .post(&found.policy_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&policy, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(denied.status() == StatusCode::INTERNAL_SERVER_ERROR);
    let fault = soap::decode(
        &denied.bytes().await?,
        Operation::Fault,
        &CodecLimits::default(),
    )?;
    ensure!(matches!(
        fault.body,
        Body::Fault(soap::FaultKind::Authentication)
    ));
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    for (request, action) in [
        (discovery_audit, "windows_discovery"),
        (policy_audit, "windows_policy"),
    ] {
        let count = crate::audit_test_support::read(&mut pg)
            .await?
            .iter()
            .filter(|r| {
                r.request() == Some(request.as_str())
                    && r.action() == action
                    && r.result() == "success"
            })
            .count();
        ensure!(count == 1);
    }
    pg.close().await?;
    Ok(())
}
async fn rejected_csrs(
    client: &reqwest::Client,
    path: &str,
    issue: &soap::Message,
) -> anyhow::Result<()> {
    let Body::Issue(original) = &issue.body else {
        anyhow::bail!("expected Issue")
    };
    let mut trailing = original.csr.0.clone();
    trailing.push(0);
    let mut bad_proof = original.csr.0.clone();
    *bad_proof.last_mut().unwrap() ^= 1;
    for csr in [trailing, bad_proof] {
        let mut request = issue.clone();
        let Body::Issue(body) = &mut request.body else {
            unreachable!()
        };
        body.csr = Secret(csr);
        let response = client
            .post(path)
            .header("content-type", "application/soap+xml")
            .body(soap::encode(&request, &CodecLimits::default())?)
            .send()
            .await?;
        ensure!(response.status() == StatusCode::INTERNAL_SERVER_ERROR);
        let fault = soap::decode(
            &response.bytes().await?,
            Operation::Fault,
            &CodecLimits::default(),
        )?;
        ensure!(matches!(
            fault.body,
            Body::Fault(soap::FaultKind::CertificateRequest)
        ));
    }
    Ok(())
}
