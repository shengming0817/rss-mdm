//! Synthetic RSA/JWKS, real HTTPS/PG enrollment. Real Entra/Windows interoperability is T3.
use super::super::test_support::*;
use crate::device::test_support::options;
use anyhow::ensure;
use axum::{
    Json, Router,
    http::{Method, StatusCode},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_identity_core::entra::EntraTokenProfile;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
use x509_cert::der::{Decode, Reader, SliceReader, asn1::UintRef};

struct Jwt {
    key: ring::signature::RsaKeyPair,
    profile: EntraTokenProfile,
}
impl Jwt {
    fn new(profile: EntraTokenProfile) -> anyhow::Result<(Self, Value)> {
        let root = root()?;
        let output = std::process::Command::new("openssl")
            .args(["rsa", "-in"])
            .arg(root.join("device.key"))
            .args(["-traditional", "-outform", "DER"])
            .output()?;
        ensure!(output.status.success(), "fixture RSA conversion failed");
        let key = ring::signature::RsaKeyPair::from_der(&output.stdout)
            .map_err(|_| anyhow::anyhow!("fixture RSA"))?;
        use ring::signature::KeyPair;
        let mut reader = SliceReader::new(key.public_key().as_ref())?;
        let (modulus, exponent) =
            reader.sequence(|r| Ok((UintRef::decode(r)?, UintRef::decode(r)?)))?;
        reader.finish(())?;
        let jwk = json!({"kty":"RSA","use":"sig","alg":"RS256","kid":"mdm-synthetic","n":URL_SAFE_NO_PAD.encode(modulus.as_bytes()),"e":URL_SAFE_NO_PAD.encode(exponent.as_bytes())});
        Ok((Self { key, profile }, jwk))
    }
    fn token(
        &self,
        user: Uuid,
        device: Option<Uuid>,
        changes: &[(&str, Value)],
    ) -> anyhow::Result<String> {
        let p = &self.profile;
        let mut claims = json!({"iss":p.issuer(),"aud":p.app_id,"ver":"2.0","idtyp":"user","tid":p.tenant,"oid":user,"azp":p.authorized_clients[0],"iat":now()-1,"nbf":now()-1,"exp":now()+300,"scp":"mdm.enroll"});
        if let Some(device) = device {
            claims[&p.device_claim] = json!(device);
        }
        for (key, value) in changes {
            claims[*key] = value.clone();
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"mdm-synthetic"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow::anyhow!("fixture JWT signing"))?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}
fn browser(host: &Host) -> crate::test_support::Browser {
    crate::test_support::Browser {
        cookies: BTreeMap::from([(
            "__Host-identity-session".into(),
            host.secret.expose().into(),
        )]),
        csrf: Some(host.secret.csrf()),
        ..Default::default()
    }
}
fn issue(host: &Host, token: String, opaque: Option<&str>) -> anyhow::Result<soap::Message> {
    let mut message = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/issue-request.xml"),
        Operation::Issue,
        &CodecLimits::default(),
    )?;
    message.header.to = Some(format!(
        "{}/EnrollmentServer/Enrollment.svc",
        host.app.windows()?.config.enrollment.origin
    ));
    let security = message.header.security.as_mut().unwrap();
    security.username = None;
    security.binary_token = Some(soap::BinaryToken {
        id: "entra-access-token".into(),
        bytes: Secret(token.into_bytes()),
    });
    let Body::Issue(input) = &mut message.body else {
        unreachable!()
    };
    input.request =
        soap::CertificateRequest::Pkcs10(Secret(std::fs::read(host.root.join("device.csr"))?));
    for (key, value) in &mut input.additional_context.0 {
        if key == "EnrollmentType" {
            *value = "Device".into();
        }
    }
    if let Some(opaque) = opaque {
        input
            .additional_context
            .0
            .push(("EnrollmentData".into(), opaque.into()));
    }
    Ok(message)
}
async fn send(host: &Host, message: &soap::Message) -> anyhow::Result<(StatusCode, Vec<u8>)> {
    let response = host
        .client
        .post(message.header.to.as_deref().unwrap())
        .header("content-type", "application/soap+xml")
        .body(soap::encode(message, &CodecLimits::default())?)
        .send()
        .await?;
    Ok((response.status(), response.bytes().await?.to_vec()))
}
async fn scalar(_host: &Host, sql: &'static str) -> anyhow::Result<i64> {
    use sqlx::Connection;
    let mut c = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut c)
        .await?;
    Ok(sqlx::query_scalar(sql).fetch_one(&mut c).await?)
}
async fn native_state() -> anyhow::Result<Value> {
    use sqlx::Connection;
    let mut c = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut c)
        .await?;
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('admissions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY request_id) FROM mdm_windows.entra_admissions t WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid),'consents',(SELECT jsonb_agg(to_jsonb(t) ORDER BY digest) FROM mdm_windows.entra_consents t WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid),'intents',(SELECT jsonb_agg(to_jsonb(t) ORDER BY request_id) FROM mdm_access.enrollment_intents t WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid),'registrations',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM mdm_access.registrations t WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid),'credentials',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM mdm_access.credentials t WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid))").fetch_one(&mut c).await?)
}
#[tokio::test]
#[ignore = "make t2 MODULE=windows.entra"]
async fn consent_native_issuance_replay_scope_and_revocation() -> anyhow::Result<()> {
    let profile = EntraTokenProfile {
        tenant: Uuid::new_v4(),
        app_id: Uuid::new_v4(),
        authorized_clients: vec![Uuid::new_v4()],
        required_scopes: vec!["mdm.enroll".into()],
        device_claim: "deviceid".into(),
    };
    let (jwt, jwk) = Jwt::new(profile.clone())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/keys", listener.local_addr()?);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/keys",
                get(move || {
                    let keys = json!({"keys":[jwk.clone()]});
                    async move { Json(keys) }
                }),
            ),
        )
        .await
    });
    let verifier = Arc::new(rss_identity_oidc::entra::HttpEntra::for_loopback_test(
        endpoint,
    )?);
    let binding = rss_mdm_windows_channel::entra::Config {
        provider_id: Uuid::new_v4(),
        token: profile,
    };
    let mut host = Host::with_entra(binding, verifier, true).await?;
    host.listen().await?;
    let user = Uuid::new_v4();
    let scoped_other = Uuid::new_v4();
    let device = Uuid::new_v4();
    let token = jwt.token(user, Some(device), &[])?;
    let tou = jwt.token(user, None, &[])?;
    let sessions=scalar(&host,"SELECT count(*) FROM identity_authority.sessions WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid").await?;
    let accounts=scalar(&host,"SELECT count(*) FROM identity_authority.accounts WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid").await?;
    let initial = issue(&host, token.clone(), None)?;
    ensure!(
        send(&host, &initial).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "absent policy admitted enrollment"
    );
    let mut admin = browser(&host);
    let (status, read) = admin
        .call(
            &host.browser,
            Method::GET,
            "/api/v1/windows/entra-policy",
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK && read["policy"]["enabled"] == false);
    let policy = json!({"enabled":true,"allUsers":false,"users":[user,scoped_other],"termsVersion":"2026-10","allowBackground":false});
    let (status, updated) = admin
        .call(
            &host.browser,
            Method::PUT,
            "/api/v1/windows/entra-policy",
            Some(json!({"expectedRevision":0,"operationId":Uuid::new_v4(),"policy":policy})),
        )
        .await?;
    ensure!(status == StatusCode::OK, "policy update {status} {updated}");
    ensure!(
        send(&host, &initial).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "missing consent admitted enrollment"
    );
    let terms_url = format!(
        "{}/api/v1/windows/entra/terms",
        host.app.windows()?.config.enrollment.origin
    );
    let terms = host.client.get(&terms_url).bearer_auth(&tou).send().await?;
    ensure!(
        terms.status() == StatusCode::OK,
        "TOU must accept personnel token without deviceid"
    );
    ensure!(terms.json::<Value>().await?["termsVersion"] == "2026-10");
    let accept = host
        .client
        .post(&terms_url)
        .bearer_auth(&tou)
        .json(&json!({"termsVersion":"2026-10","accepted":true}))
        .send()
        .await?;
    ensure!(
        accept.status() == StatusCode::OK,
        "TOU accept {}",
        accept.status()
    );
    let consent: Value = accept.json().await?;
    let opaque = consent["opaqueBlob"].as_str().unwrap();
    ensure!(scalar(&host,"SELECT count(*) FROM identity_authority.accounts WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid").await?==accounts,"TOU or denied scope created account");
    let other = issue(
        &host,
        jwt.token(scoped_other, Some(device), &[])?,
        Some(opaque),
    )?;
    ensure!(
        send(&host, &other).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "consent transplanted to another subject"
    );
    let outside = issue(
        &host,
        jwt.token(Uuid::new_v4(), Some(device), &[])?,
        Some(opaque),
    )?;
    ensure!(
        send(&host, &outside).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "outside-scope subject admitted enrollment"
    );
    for changes in [
        vec![("aud", json!(Uuid::new_v4()))],
        vec![("idtyp", json!("app"))],
        vec![("ver", json!("1.0"))],
        vec![("scp", json!("other"))],
    ] {
        ensure!(
            send(
                &host,
                &issue(
                    &host,
                    jwt.token(user, Some(device), &changes)?,
                    Some(opaque)
                )?
            )
            .await?
            .0 == StatusCode::INTERNAL_SERVER_ERROR
        );
    }
    let no_device = issue(&host, tou.clone(), Some(opaque))?;
    ensure!(
        send(&host, &no_device).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "actual enrollment accepted missing deviceid"
    );
    let valid = issue(&host, token.clone(), Some(opaque))?;
    // The first policy read succeeds; a transactional fixture hides it only after request insertion.
    use sqlx::{Connection, Executor};
    let mut fault = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    fault.execute("CREATE FUNCTION mdm_access.hide_entra_policy() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN IF NEW.authority_kind='windows_entra' THEN ALTER TABLE mdm_windows.entra_policy RENAME TO entra_policy_fixture_unavailable; END IF; RETURN NEW; END $$; CREATE TRIGGER hide_entra_policy AFTER INSERT ON mdm_access.requests FOR EACH ROW EXECUTE FUNCTION mdm_access.hide_entra_policy()").await?;
    let failed = send(&host, &valid).await?;
    fault.execute("DROP TRIGGER hide_entra_policy ON mdm_access.requests; DROP FUNCTION mdm_access.hide_entra_policy()").await?;
    ensure!(failed.0 == StatusCode::INTERNAL_SERVER_ERROR);
    ensure!(
        matches!(
            soap::decode_response(&valid, &failed.1, &CodecLimits::default())?.body,
            Body::Fault(soap::FaultKind::EnrollmentServer)
        ),
        "policy storage failure was reported as authorization"
    );
    let canonical: Vec<u8> = sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='mdm.request' ORDER BY position DESC LIMIT 1").bind(case_tenant()).fetch_one(&mut fault).await?;
    let record = rss_audit_core::decode_untrusted(&canonical)?;
    let payload: Value = serde_json::from_slice(record.event().context().payload().as_bytes())?;
    ensure!(
        payload["result"] == "failed",
        "policy storage failure was audited as a denial"
    );
    ensure!(scalar(&host,"SELECT count(*) FROM mdm_access.requests WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND authority_kind='windows_entra'").await?==0, "policy read fault committed admission");
    // Admission commits before issuance. A later intent failure must still settle the HTTP audit.
    fault.execute("CREATE FUNCTION mdm_access.reject_entra_intent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture issuance failure'; END $$; CREATE TRIGGER reject_entra_intent BEFORE INSERT ON mdm_access.enrollment_intents FOR EACH ROW EXECUTE FUNCTION mdm_access.reject_entra_intent()").await?;
    let requests_before=scalar(&host,"SELECT count(*) FROM mdm_audit.receipts WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND source_id='mdm.request'").await?;
    let failed = send(&host, &valid).await?;
    fault.execute("DROP TRIGGER reject_entra_intent ON mdm_access.enrollment_intents; DROP FUNCTION mdm_access.reject_entra_intent()").await?;
    ensure!(
        failed.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "fixture did not fail after admission"
    );
    ensure!(scalar(&host,"SELECT count(*) FROM mdm_access.requests WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND authority_kind='windows_entra' AND state='pending'").await?==1,"admission did not commit before issuance failure");
    ensure!(scalar(&host,"SELECT count(*) FROM mdm_audit.receipts WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND source_id='mdm.request'").await?==requests_before+1,"later issuance failure lost request audit");
    let (status, first) = send(&host, &valid).await?;
    ensure!(
        status == StatusCode::OK,
        "native issuance {status}: {}",
        String::from_utf8_lossy(&first)
    );
    let Body::IssueResponse(first) =
        soap::decode_response(&valid, &first, &CodecLimits::default())?.body
    else {
        anyhow::bail!("missing provisioning")
    };
    let (status, replay) = send(&host, &valid).await?;
    ensure!(
        status == StatusCode::OK,
        "native retry {status}: {}",
        String::from_utf8_lossy(&replay)
    );
    let Body::IssueResponse(replay) =
        soap::decode_response(&valid, &replay, &CodecLimits::default())?.body
    else {
        unreachable!()
    };
    ensure!(
        first.provisioning == replay.provisioning,
        "retry minted a new credential"
    );
    ensure!(scalar(&host,"SELECT count(*) FROM identity_authority.sessions WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid").await?==sessions,"native enrollment minted a browser session");
    ensure!(scalar(&host,"SELECT count(*) FROM mdm_access.requests WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND authority_kind='windows_entra' AND NOT self_service AND credential_ref IS NULL AND state='bound'").await?==1);
    ensure!(scalar(&host,"SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND state='active'").await?==1);
    // Only the valid CSR changes: all personnel, device, consent and profile facts stay identical.
    let before = native_state().await?;
    let mut changed_csr = issue(&host, token.clone(), Some(opaque))?;
    let alternate = std::fs::read(host.root.join("renew-device.csr"))?;
    let alternate_csr = rss_mdm_certificate::windows::Csr::verify(&alternate)?;
    let original_csr =
        rss_mdm_certificate::windows::Csr::verify(&std::fs::read(host.root.join("device.csr"))?)?;
    ensure!(alternate_csr.digest() != original_csr.digest());
    if let Body::Issue(input) = &mut changed_csr.body {
        input.request = soap::CertificateRequest::Pkcs10(Secret(alternate));
    }
    ensure!(
        send(&host, &changed_csr).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "consumed consent accepted a replacement valid CSR"
    );
    ensure!(
        native_state().await? == before,
        "replacement CSR changed native authority or credentials"
    );
    let (status, unchanged) = send(&host, &valid).await?;
    ensure!(status == StatusCode::OK);
    let Body::IssueResponse(unchanged) =
        soap::decode_response(&valid, &unchanged, &CodecLimits::default())?.body
    else {
        anyhow::bail!("missing exact replay")
    };
    ensure!(unchanged.provisioning == first.provisioning);
    let mut transplant = issue(
        &host,
        jwt.token(user, Some(Uuid::new_v4()), &[])?,
        Some(opaque),
    )?;
    ensure!(
        send(&host, &transplant).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "single-use consent reused for another device"
    );
    if let Body::Issue(input) = &mut transplant.body {
        input.request =
            soap::CertificateRequest::Pkcs10(Secret(std::fs::read(host.root.join("weak.csr"))?));
    }
    ensure!(send(&host, &transplant).await?.0 == StatusCode::INTERNAL_SERVER_ERROR);
    // Organization authority keeps its canonical user and is exempt from personal quotas.
    let mut owner = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut owner)
        .await?;
    let (actor,instance):(String,String)=sqlx::query_as("SELECT g.actor,g.instance FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND q.authority_kind='windows_entra'").fetch_one(&mut owner).await?;
    let quota_path = format!("/api/v1/registration-quotas/users/{instance}/{actor}");
    let (status, usage) = admin
        .call(
            &host.browser,
            Method::GET,
            &format!("{quota_path}/usage"),
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK, "quota usage {status} {usage}");
    let windows = usage["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["channel"] == "windows_mdm")
        .unwrap();
    ensure!(
        windows["used"] == 0 && windows["active"] == 0 && windows["reserved"] == 0,
        "organization registration consumed personal quota: {usage}"
    );
    admin.operation = Some(Uuid::new_v4());
    let (status,value)=admin.call(&host.browser,Method::PUT,&quota_path,Some(json!({"expectedRevision":0,"limits":{"agent":null,"windows_mdm":0,"macos_mdm":null}}))).await?;
    ensure!(status == StatusCode::OK, "quota zero {status} {value}");
    admin.operation = None;
    ensure!(
        send(&host, &valid).await?.0 == StatusCode::OK,
        "personal quota zero denied an exact organization retry"
    );
    let accept = host
        .client
        .post(&terms_url)
        .bearer_auth(&tou)
        .json(&json!({"termsVersion":"2026-10","accepted":true}))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    let another = issue(
        &host,
        jwt.token(user, Some(Uuid::new_v4()), &[])?,
        accept["opaqueBlob"].as_str(),
    )?;
    ensure!(
        send(&host, &another).await?.0 == StatusCode::OK,
        "personal quota zero denied a new authorized organization device"
    );
    let (status, usage) = admin
        .call(
            &host.browser,
            Method::GET,
            &format!("{quota_path}/usage"),
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK);
    let windows = usage["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["channel"] == "windows_mdm")
        .unwrap();
    ensure!(
        windows["used"] == 0 && windows["active"] == 0 && windows["reserved"] == 0,
        "new organization device consumed personal quota: {usage}"
    );
    let (status,value)=admin.call(&host.browser,Method::PUT,"/api/v1/windows/entra-policy",Some(json!({"expectedRevision":1,"operationId":Uuid::new_v4(),"policy":{"enabled":false,"allUsers":false,"users":[user],"termsVersion":"2026-10","allowBackground":false}}))).await?;
    ensure!(status == StatusCode::OK, "revoke {status} {value}");
    ensure!(
        send(&host, &valid).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "revoked policy allowed replay"
    );
    host.close().await?;
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=windows.entra"]
async fn background_policy_does_not_enable_identity_jit() -> anyhow::Result<()> {
    let profile = EntraTokenProfile {
        tenant: Uuid::new_v4(),
        app_id: Uuid::new_v4(),
        authorized_clients: vec![Uuid::new_v4()],
        required_scopes: vec!["mdm.enroll".into()],
        device_claim: "deviceid".into(),
    };
    let (jwt, jwk) = Jwt::new(profile.clone())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/keys", listener.local_addr()?);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/keys",
                get(move || {
                    let keys = json!({"keys":[jwk.clone()]});
                    async move { Json(keys) }
                }),
            ),
        )
        .await
    });
    let verifier = Arc::new(rss_identity_oidc::entra::HttpEntra::for_loopback_test(
        endpoint,
    )?);
    let mut host = Host::with_entra(
        rss_mdm_windows_channel::entra::Config {
            provider_id: Uuid::new_v4(),
            token: profile,
        },
        verifier,
        false,
    )
    .await?;
    host.listen().await?;
    let user = Uuid::new_v4();
    let mut admin = browser(&host);
    let (status,value)=admin.call(&host.browser,Method::PUT,"/api/v1/windows/entra-policy",Some(json!({"expectedRevision":0,"operationId":Uuid::new_v4(),"policy":{"enabled":true,"allUsers":false,"users":[user],"termsVersion":"2026-10","allowBackground":true}}))).await?;
    ensure!(
        status == StatusCode::OK,
        "background policy {status} {value}"
    );
    let before=scalar(&host,"SELECT count(*) FROM identity_authority.accounts WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid").await?;
    let message = issue(&host, jwt.token(user, Some(Uuid::new_v4()), &[])?, None)?;
    ensure!(
        send(&host, &message).await?.0 == StatusCode::INTERNAL_SERVER_ERROR,
        "background policy implicitly enabled JIT"
    );
    ensure!(scalar(&host,"SELECT count(*) FROM identity_authority.accounts WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid").await?==before);
    ensure!(scalar(&host,"SELECT count(*) FROM mdm_access.requests WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND authority_kind='windows_entra'").await?==0);
    host.close().await?;
    server.abort();
    Ok(())
}
