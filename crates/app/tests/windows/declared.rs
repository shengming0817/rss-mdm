//! Real TLS/PG proof for the certificate-only independent WinDC channel.
use crate::device::test_support::options;
use crate::windows::test_support::*;
use crate::windows::*;
use anyhow::{Context, ensure};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_registration_service::Purpose;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
    syncml,
};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;
use x509_cert::der::{Decode, EncodePem, pem::LineEnding};

// xmlsec1 is an independent implementation of the native XMLDSIG profile.
// Every private key and signed document lives in a disposable local fixture.
async fn signed(message: &soap::Message, key: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    sign_xml(
        String::from_utf8(soap::encode(message, &CodecLimits::default())?)?,
        key,
    )
    .await
}
async fn sign_xml(xml: String, key: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let signature = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:KeyName>fixture</ds:KeyName><o:SecurityTokenReference><o:Reference URI="#parent-cert" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509"/></o:SecurityTokenReference></ds:KeyInfo></ds:Signature>"##;
    let xml = xml.replace("</o:Security>", &(signature.to_owned() + "</o:Security>"));
    let temp = tempfile::tempdir()?;
    let template = temp.path().join("template.xml");
    let output = temp.path().join("signed.xml");
    std::fs::write(&template, xml)?;
    let mut process = tokio::process::Command::new("xmlsec1")
        .args([
            "--sign",
            "--enabled-reference-uris",
            "empty",
            "--privkey-pem:fixture",
        ])
        .arg(key)
        .arg("--output")
        .arg(&output)
        .arg(&template)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let status =
        match tokio::time::timeout(std::time::Duration::from_secs(30), process.wait()).await {
            Ok(status) => status?,
            Err(error) => {
                process.kill().await?;
                process.wait().await?;
                return Err(error.into());
            }
        };
    ensure!(
        status.success(),
        "independent XMLDSIG fixture signing failed"
    );
    // KeyName only selects the supplied fixture key for the independent tool.
    // The enveloped transform excludes the whole Signature; removing this unsigned
    // fixture selector preserves both digests and leaves the exact WS-Security profile.
    Ok(std::fs::read_to_string(output)?
        .replace("<ds:KeyName>fixture</ds:KeyName>", "")
        .into_bytes())
}

#[tokio::test]
#[ignore = "make t2 MODULE=windows.declared"]
async fn signed_parent_enrollment_independent_tls_and_retirement() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let w = &host.app.windows()?.channel;
    let discovery = format!(
        "{}/EnrollmentConfiguration?api-version=1.0",
        w.enrollment_origin
    );
    let value = host
        .client
        .post(&discovery)
        .json(&serde_json::json!({"enrollmentType":"User","osVersion":"10.0.22631.3958"}))
        .send()
        .await?;
    ensure!(value.status() == StatusCode::OK);
    let value: serde_json::Value = value.json().await?;
    ensure!(value["AuthPolicy"] == "Certificate");
    let path = value["EnrollmentServiceUrl"].as_str().unwrap();
    for claim in [
        serde_json::json!({"enrollmentType":"Device","osVersion":"10.0.22631.3958"}),
        serde_json::json!({"enrollmentType":"User","osVersion":"10.0.27000.0"}),
    ] {
        ensure!(
            !host
                .client
                .post(&discovery)
                .json(&claim)
                .send()
                .await?
                .status()
                .is_success()
        );
    }
    let parent_cert = w.ca.sign(&w.ca.restore_intent(
        &peer.intent.tbs,
        &certificate::Csr::verify(&peer.intent.csr)?,
        peer.intent.registration,
    )?)?;
    let at = now();
    let format_time = |at| {
        time::OffsetDateTime::from_unix_timestamp(at)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let mut issue = peer.issue.clone();
    issue.header.to = Some(path.into());
    issue.header.message_id = Some(format!("urn:uuid:{}", Uuid::new_v4()));
    issue.header.security = Some(soap::Security {
        timestamp: Some(soap::Timestamp {
            id: "linked-time".into(),
            created: format_time(at),
            expires: format_time(at + 300),
        }),
        username: None,
        certificate: Some(soap::CertificateToken {
            id: "parent-cert".into(),
            certificate: Secret(parent_cert.clone()),
        }),
        signature: false,
    });
    let Body::Issue(input) = &mut issue.body else {
        panic!()
    };
    input.request = soap::CertificateRequest::Pkcs10(Secret(std::fs::read(
        host.root.join("renew-device.csr"),
    )?));
    let mut policy = issue.clone();
    policy.body = Body::GetPolicies;
    policy.header.to = Some(value["EnrollmentPolicyServiceUrl"].as_str().unwrap().into());
    let response = host
        .client
        .post(policy.header.to.as_ref().unwrap())
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&policy, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(
        soap::decode(
            &response.bytes().await?,
            Operation::GetPoliciesResponse,
            &CodecLimits::default()
        )
        .is_ok()
    );
    let key = host.root.join("device.key");
    let wire = signed(&issue, &key).await?;
    let proof = w.ca.linked_proof(&wire, at)?;
    ensure!(proof.fingerprint() == w.ca.verify(&[parent_cert.into()], at)?.fingerprint());
    ensure!(w.ca.linked_proof(&wire, at + 301).is_err());
    ensure!(
        w.ca.linked_proof(
            &String::from_utf8(wire.clone())?
                .replace("TEST-DEVICE", "tampered")
                .into_bytes(),
            at
        )
        .is_err()
    );
    let original = String::from_utf8(wire.clone())?;
    let reference = r#"URI="""#;
    let negative = [
        original.replace("</s:Envelope>", "<s:Body/></s:Envelope>"),
        original.replace("</o:Security>", "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/></o:Security>"),
        original.replace("linked-time", "parent-cert"),
        original.replace(reference, r#"URI="https://invalid.example/reference""#),
        original.replace("URI=\"#parent-cert\"", "URI=\"#linked-time\""),
        original.replace("rsa-sha256", "rsa-sha1"),
        original.replace("enveloped-signature", "xpath"),
        original.replace("</ds:Transforms>", "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></ds:Transforms>"),
        original.replace("</ds:SignedInfo>", "<ds:Reference URI=\"\"/></ds:SignedInfo>"),
        format!("<?fixture prohibited?>{original}"),
        original.replace("<s:Envelope", "<!DOCTYPE s:Envelope [<!ENTITY malicious SYSTEM 'file:///etc/passwd'>]><s:Envelope"),
        original.replace("</s:Body>", &format!("{}{} </s:Body>", "<nested>".repeat(65), "</nested>".repeat(65))),
        original.replace("</s:Body>", &("<node/>".repeat(4097) + "</s:Body>")),
    ];
    for (index, invalid) in negative.into_iter().enumerate() {
        ensure!(
            invalid != original,
            "negative fixture mutation {index} did not apply"
        );
        ensure!(
            w.ca.linked_proof(invalid.as_bytes(), at).is_err(),
            "unsafe signature shape {index} accepted"
        );
    }
    // Prefix spelling and attribute order are not identity. Sign an equivalent
    // representation independently before passing the original bytes to verification.
    let equivalent = String::from_utf8(soap::encode(&issue, &CodecLimits::default())?)?
        .replace("<s:", "<env:")
        .replace("</s:", "</env:")
        .replace(" s:", " env:")
        .replace("xmlns:s=", "xmlns:env=");
    let attributes = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing""#;
    let reordered = original.replace(attributes, r#"xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope""#);
    ensure!(
        reordered != original,
        "attribute order fixture did not apply"
    );
    ensure!(w.ca.linked_proof(reordered.as_bytes(), at)?.fingerprint() == proof.fingerprint());
    let equivalent = sign_xml(equivalent, &key).await?;
    ensure!(w.ca.linked_proof(&equivalent, at)?.fingerprint() == proof.fingerprint());
    let post = |wire: Vec<u8>| {
        host.client
            .post(path)
            .header("content-type", "application/soap+xml")
            .body(wire)
    };
    ensure!(
        !post(soap::encode(&issue, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            .is_success(),
        "exported BST must not authenticate"
    );
    host.app
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    let unknown = post(wire.clone()).send().await?;
    ensure!(
        unknown.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "linked issuance did not expose SOAP fault"
    );
    ensure!(matches!(
        soap::decode_response(&issue, &unknown.bytes().await?, &CodecLimits::default())?.body,
        Body::Fault(soap::FaultKind::EnrollmentServer)
    ));
    let response = post(wire.clone()).send().await?;
    ensure!(
        response.status() == StatusCode::OK,
        "linked WSTEP: {}",
        response.status()
    );
    let first = response.bytes().await?;
    let decoded = soap::decode_response(&issue, &first, &CodecLimits::default())?;
    let Body::IssueResponse(provision) = decoded.body else {
        panic!()
    };
    let replay = post(wire.clone()).send().await?;
    ensure!(replay.status() == StatusCode::OK);
    let replay = soap::decode_response(&issue, &replay.bytes().await?, &CodecLimits::default())?;
    ensure!(
        matches!(replay.body, Body::IssueResponse(ref p) if p.provisioning.0 == provision.provisioning.0)
    );
    let mut changed = issue.clone();
    changed.header.message_id = issue.header.message_id.clone();
    if let Body::Issue(body) = &mut changed.body {
        body.context = Some("changed".into());
    }
    ensure!(
        !post(signed(&changed, &key).await?)
            .send()
            .await?
            .status()
            .is_success()
    );

    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let row = sqlx::query("SELECT r.id,r.request_id,r.generation,r.ready,i.secrets,e.certificate FROM mdm_access.registrations r JOIN mdm_access.enrollment_intents i ON(i.tenant_id,i.request_id)=(r.tenant_id,r.request_id) JOIN mdm_access.enrollment_certificates e ON(e.tenant_id,e.request_id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.parent_id=$2 AND r.purpose='windows_declared' AND r.state='active'")
        .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    let child: Uuid = row.try_get("id")?;
    let request: Uuid = row.try_get("request_id")?;
    let certificate: Vec<u8> = row.try_get("certificate")?;
    ensure!(child != peer.intent.registration && !row.try_get::<bool, _>("ready")?);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(child).fetch_one(&mut pg).await?;
    ensure!(count == 0, "child must not manufacture report authority");
    let cert_pem = x509_cert::Certificate::from_der(&certificate)?.to_pem(LineEnding::LF)?;
    let child_client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(host.root_cert.clone())
        .identity(reqwest::Identity::from_pem(
            &[
                cert_pem.as_bytes(),
                &std::fs::read(host.root.join("renew-device.key"))?,
            ]
            .concat(),
        )?)
        .build()?;
    let secrets = w.open_secrets_fixture(
        case_tenant(),
        request,
        &row.try_get::<Vec<u8>, _>("secrets")?,
    )?;
    let child_url = w.management_url(Purpose::WindowsDeclared);
    let mut message = peer.message.clone();
    message.header.target = child_url.clone();
    message.header.credential.as_mut().unwrap().data =
        Secret(STANDARD.encode(format!("{}:{}", child, secrets.client_password.as_str())));
    let child_wire = syncml::encode(&message, &CodecLimits::default())?;
    let manage = |client: &reqwest::Client, url: &str, wire: Vec<u8>| {
        client
            .post(url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(wire)
    };
    ensure!(
        manage(&peer.mutual, &child_url, child_wire.clone())
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        manage(
            &child_client,
            &peer.url,
            syncml::encode(&peer.message, &CodecLimits::default())?
        )
        .send()
        .await?
        .status()
            == StatusCode::UNAUTHORIZED
    );
    let initial = manage(&child_client, &child_url, child_wire.clone())
        .send()
        .await?;
    ensure!(
        initial.status() == StatusCode::OK,
        "child SyncML: {}",
        initial.status()
    );
    let authenticated = authenticate_child(&child_client, &child_url, &message, &peer.ack).await?;
    let ready: bool = sqlx::query_scalar(
        "SELECT ready FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(child)
    .fetch_one(&mut pg)
    .await?;
    ensure!(ready);
    let source_count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(child).fetch_one(&mut pg).await?;
    ensure!(source_count == 0);
    #[cfg(feature = "integration")]
    mi_effect(
        &host,
        &child_client,
        &child_url,
        &message,
        &authenticated,
        &peer.ack,
    )
    .await?;
    host.app
        .devices
        .revoke(
            &peer.proof,
            crate::test_support::case::name("tls-device"),
            peer.intent.registration,
            Uuid::new_v4(),
        )
        .await?;
    let state: String = sqlx::query_scalar(
        "SELECT state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(child)
    .fetch_one(&mut pg)
    .await?;
    ensure!(state == "revoked");
    ensure!(
        manage(&child_client, &child_url, child_wire)
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED
    );
    ensure!(!post(wire).send().await?.status().is_success());
    pg.close().await?;
    host.close().await?;
    Ok(())
}

#[cfg(feature = "integration")]
struct MiOperation {
    client: crate::execution::test_support::Client,
    operation: Uuid,
    document: String,
}
#[cfg(feature = "integration")]
async fn mi_admit(host: &Host) -> anyhow::Result<MiOperation> {
    use crate::execution::test_support::Client;
    use axum::http::Method;
    use serde_json::json;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    client.set_authorized(false).await?;
    let id = Uuid::new_v4();
    let document = format!(
        r#"<DeclaredConfiguration schema="1.0" context="Device" id="{id}" checksum="immutable-v1" osdefinedscenario="MSFTExtensibilityMIProviderConfig"><DSC namespace="root/test" className="ExampleProvider"><Key name="Name">resource</Key><Value name="Text">sensitive</Value></DSC></DeclaredConfiguration>"#
    );
    let operation = Uuid::new_v4();
    let input = json!({"operationId":operation,"inputVersion":"mi-1","deadline":now()+300,"target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/DeclaredConfiguration/Host/Complete/Documents/*/Document","instance":[id],"operation":"replace","value":{"type":"xml","value":document}}}}});
    ensure!(
        client.call(Method::POST, "", Some(input.clone())).await?.0 == StatusCode::FORBIDDEN,
        "MI must default deny"
    );
    let grants = ["operation_read","operation_cancel","windows_mi_execute"].into_iter().map(|permission| json!({"operation":permission,"scope":{"kind":"device","id":crate::test_support::case::name("tls-device")}})).collect::<Vec<_>>();
    let value = json!({"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants});
    let granted = client
        .browser
        .call(
            &client.router,
            Method::PUT,
            &format!("/api/v1/authorization/rules/{}", Uuid::new_v4()),
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":value})),
        )
        .await?;
    ensure!(granted.0 == StatusCode::OK, "MI permission: {granted:?}");
    ensure!(client.call(Method::POST, "", Some(input)).await?.0 == StatusCode::ACCEPTED);
    ensure!(
        client
            .call(
                Method::POST,
                &format!("/{operation}/approve"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    client.publish_operation(operation).await?;
    Ok(MiOperation {
        client,
        operation,
        document,
    })
}
#[cfg(feature = "integration")]
async fn mi_dispatch(
    child: &reqwest::Client,
    url: &str,
    initial: &syncml::Message,
    authenticated: &syncml::Message,
) -> anyhow::Result<syncml::Message> {
    use crate::execution::test_support::native;
    use syncml::Command;
    let response = authenticated.clone();
    let gets = response
        .commands
        .iter()
        .filter_map(|c| {
            if let Command::Get { id, items, .. } = c {
                Some((*id, items[0].target.clone().unwrap()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        gets.len() == 2,
        "child has capability queries, no Inventory queries: {gets:?}"
    );
    let response = native::post(
        child,
        url,
        &native::report(initial, &gets, "10.0.22631.3958", 200),
    )
    .await?;
    ensure!(response.status() == StatusCode::OK);
    let response = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
    ensure!(
        response
            .commands
            .iter()
            .any(|c| matches!(c, Command::Replace { .. })),
        "MI was not sent: {response:?}"
    );
    Ok(response)
}

#[cfg(feature = "integration")]
async fn mi_effect(
    host: &Host,
    child: &reqwest::Client,
    url: &str,
    initial: &syncml::Message,
    authenticated: &syncml::Message,
    parent_ack: &syncml::Message,
) -> anyhow::Result<()> {
    use crate::execution::test_support::native;
    use axum::http::Method;
    let MiOperation {
        mut client,
        operation,
        document,
    } = mi_admit(host).await?;
    let response = mi_dispatch(child, url, initial, authenticated).await?;
    let observed = native::post(child, url, &result_packet(initial, &response, None)).await?;
    ensure!(observed.status() == StatusCode::OK);
    let observed = syncml::decode(&observed.bytes().await?, &CodecLimits::default())?;
    ensure!(has_declared_query(&observed));
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["commandStatus"]
            != "applied",
        "ACK became effect"
    );
    let result = |state| native_result(&document, "Set", state);
    let partial = native::post(
        child,
        url,
        &with_summary(
            result_packet(initial, &observed, Some(&result(20))),
            &document,
            "result-v1",
            20,
        )?,
    )
    .await?;
    ensure!(partial.status() == StatusCode::OK);
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["commandStatus"]
            != "applied",
        "partial native state became effect"
    );
    // More duplicate summaries than the attempt budget must not spend a single retry.
    let mut previous = syncml::decode(&partial.bytes().await?, &CodecLimits::default())?;
    previous =
        repeated_summaries(child, url, initial, previous, &document, "result-v1", 20).await?;
    ensure!(!has_declared_query(&previous));
    mi_version_changes(
        &mut client,
        operation,
        &document,
        child,
        url,
        initial,
        parent_ack,
    )
    .await
}
#[cfg(feature = "integration")]
async fn mi_version_changes(
    client: &mut crate::execution::test_support::Client,
    operation: Uuid,
    document: &str,
    child: &reqwest::Client,
    url: &str,
    initial: &syncml::Message,
    parent_ack: &syncml::Message,
) -> anyhow::Result<()> {
    use crate::execution::test_support::native;
    client.publish_operation(operation).await?;
    let mut initial = with_summary(initial.clone(), document, "result-v1", 20)?;
    initial.header.session_id += 1;
    let response = authenticate_child(child, url, &initial, parent_ack).await?;
    ensure!(
        !has_declared_query(&response),
        "unchanged summary retried across sessions"
    );
    let mut notice = with_summary(
        result_packet(&initial, &response, None),
        document,
        "result-v2",
        20,
    )?;
    let queried = native::post(child, url, &notice).await?;
    ensure!(queried.status() == StatusCode::OK);
    let queried = syncml::decode(&queried.bytes().await?, &CodecLimits::default())?;
    ensure!(
        has_declared_query(&queried),
        "changed result checksum did not trigger full Results"
    );
    let progress = native_result(document, "Set", 20).replace("result-v1", "result-v2");
    notice = with_summary(
        result_packet(&initial, &queried, Some(&progress)),
        document,
        "result-v2",
        20,
    )?;
    let response = native::post(child, url, &notice).await?;
    ensure!(response.status() == StatusCode::OK);
    let response = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
    ensure!(
        !has_declared_query(&response),
        "full progress result was immediately replaced"
    );
    notice = with_summary(
        result_packet(&initial, &response, None),
        document,
        "result-v2",
        60,
    )?;
    let queried = native::post(child, url, &notice).await?;
    ensure!(queried.status() == StatusCode::OK);
    let queried = syncml::decode(&queried.bytes().await?, &CodecLimits::default())?;
    ensure!(
        has_declared_query(&queried),
        "changed state did not trigger full Results"
    );
    mi_complete(child, url, &initial, &queried, document, client, operation).await
}
#[cfg(feature = "integration")]
async fn mi_complete(
    child: &reqwest::Client,
    url: &str,
    initial: &syncml::Message,
    queried: &syncml::Message,
    document: &str,
    client: &mut crate::execution::test_support::Client,
    operation: Uuid,
) -> anyhow::Result<()> {
    use crate::execution::test_support::native;
    use axum::http::Method;
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["commandStatus"]
            != "applied",
        "summary became effect"
    );
    let previous = queried.clone();
    let previous =
        repeated_summaries(child, url, initial, previous, document, "result-v2", 60).await?;
    let mut packet = with_summary(
        result_packet(
            initial,
            queried,
            Some(&native_result(document, "Set", 60).replace("result-v1", "result-v2")),
        ),
        document,
        "result-v2",
        60,
    )?;
    packet.header.message_id = previous.header.message_id + 1;
    let complete = native::post(child, url, &packet).await?;
    ensure!(complete.status() == StatusCode::OK);
    ensure!(
        !has_declared_query(&syncml::decode(
            &complete.bytes().await?,
            &CodecLimits::default()
        )?),
        "full success was replaced by an empty observation"
    );
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='observe'").bind(case_tenant()).bind(operation).fetch_one(&mut pg).await?;
    ensure!(
        attempts == 3,
        "duplicate summaries consumed attempts: {attempts}"
    );
    let detail = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        detail.1["commandStatus"] == "applied",
        "full result did not settle: {detail:?}"
    );
    Ok(())
}

#[cfg(feature = "integration")]
async fn repeated_summaries(
    child: &reqwest::Client,
    url: &str,
    initial: &syncml::Message,
    mut previous: syncml::Message,
    document: &str,
    version: &str,
    state: u32,
) -> anyhow::Result<syncml::Message> {
    for _ in 0..35 {
        let packet = with_summary(
            result_packet(initial, &previous, None),
            document,
            version,
            state,
        )?;
        let response = crate::execution::test_support::native::post(child, url, &packet).await?;
        ensure!(response.status() == StatusCode::OK);
        previous = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
        ensure!(
            !has_declared_query(&previous),
            "duplicate summary created another query"
        );
    }
    Ok(previous)
}

struct LinkedPeer {
    id: Uuid,
    generation: i64,
    certificate: Vec<u8>,
    mutual: reqwest::Client,
    message: syncml::Message,
    url: String,
    issue: soap::Message,
    wire: Vec<u8>,
}
fn identity_client(
    host: &Host,
    certificate: &[u8],
    key: &std::path::Path,
) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(host.root_cert.clone())
        .identity(reqwest::Identity::from_pem(
            &[
                x509_cert::Certificate::from_der(certificate)?
                    .to_pem(LineEnding::LF)?
                    .as_bytes(),
                &std::fs::read(key)?,
            ]
            .concat(),
        )?)
        .timeout(std::time::Duration::from_secs(12))
        .build()?)
}
async fn linked_peer(
    host: &Host,
    parent: &Peer,
    certificate: &[u8],
    key: &std::path::Path,
) -> anyhow::Result<LinkedPeer> {
    let w = &host.app.windows()?.channel;
    let mut issue = parent.issue.clone();
    issue.header.to = Some(format!(
        "{}/EnrollmentServer/LinkedEnrollment.svc",
        w.enrollment_origin
    ));
    issue.header.message_id = Some(format!("urn:uuid:{}", Uuid::new_v4()));
    let format_time = |at| {
        time::OffsetDateTime::from_unix_timestamp(at)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    issue.header.security = Some(soap::Security {
        timestamp: Some(soap::Timestamp {
            id: "linked-time".into(),
            created: format_time(now()),
            expires: format_time(now() + 300),
        }),
        username: None,
        certificate: Some(soap::CertificateToken {
            id: "parent-cert".into(),
            certificate: Secret(certificate.to_vec()),
        }),
        signature: false,
    });
    let Body::Issue(input) = &mut issue.body else {
        unreachable!()
    };
    input.request = soap::CertificateRequest::Pkcs10(Secret(std::fs::read(
        host.root.join("renew-device.csr"),
    )?));
    let wire = signed(&issue, key).await?;
    let response = host
        .client
        .post(issue.header.to.as_ref().unwrap())
        .header("content-type", "application/soap+xml")
        .body(wire.clone())
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "linked enrollment: {}",
        response.status()
    );
    let response =
        soap::decode_response(&issue, &response.bytes().await?, &CodecLimits::default())?;
    ensure!(matches!(response.body, Body::IssueResponse(_)));
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let row = sqlx::query("SELECT r.id,r.generation,r.request_id,i.secrets,e.certificate FROM mdm_access.registrations r JOIN mdm_access.enrollment_intents i ON(i.tenant_id,i.request_id)=(r.tenant_id,r.request_id) JOIN mdm_access.enrollment_certificates e ON(e.tenant_id,e.request_id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.parent_id=$2 AND r.purpose='windows_declared' AND r.state='active'")
        .bind(case_tenant()).bind(parent.intent.registration).fetch_one(&mut pg).await?;
    let id: Uuid = row.try_get("id")?;
    let certificate: Vec<u8> = row.try_get("certificate")?;
    let secrets = w.open_secrets_fixture(
        case_tenant(),
        row.try_get("request_id")?,
        &row.try_get::<Vec<u8>, _>("secrets")?,
    )?;
    let url = w.management_url(Purpose::WindowsDeclared);
    let mut message = parent.message.clone();
    message.header.target = url.clone();
    message.header.credential.as_mut().unwrap().data =
        Secret(STANDARD.encode(format!("{}:{}", id, secrets.client_password.as_str())));
    let mutual = identity_client(host, &certificate, &host.root.join("renew-device.key"))?;
    let result = LinkedPeer {
        id,
        generation: row.try_get("generation")?,
        certificate,
        mutual,
        message,
        url,
        issue,
        wire,
    };
    pg.close().await?;
    Ok(result)
}
async fn authenticate_child(
    client: &reqwest::Client,
    url: &str,
    first: &syncml::Message,
    parent_ack: &syncml::Message,
) -> anyhow::Result<syncml::Message> {
    ensure!(manage(client, url, first).await? == StatusCode::OK);
    let mut ack = parent_ack.clone();
    ack.header.target = url.into();
    ack.header.session_id = first.header.session_id;
    for command in &first.commands {
        if let syncml::Command::Alert {
            alert: syncml::Alert::DeclaredConfiguration { .. },
            ..
        } = command
        {
            let mut command = command.clone();
            if let syncml::Command::Alert { id, .. } = &mut command {
                *id = ack
                    .commands
                    .iter()
                    .map(syncml::Command::id)
                    .max()
                    .unwrap_or(0)
                    + 1;
            }
            ack.commands.push(command);
        }
    }
    if let syncml::Command::Status(status) = &mut ack.commands[0] {
        status.challenge.as_mut().unwrap().nonce =
            Some(Secret(STANDARD.encode(Uuid::new_v4().as_bytes())));
    }
    let response = client
        .post(url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(syncml::encode(&ack, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "child authentication: {}",
        response.status()
    );
    Ok(syncml::decode(
        &response.bytes().await?,
        &CodecLimits::default(),
    )?)
}
async fn manage(
    client: &reqwest::Client,
    url: &str,
    message: &syncml::Message,
) -> anyhow::Result<StatusCode> {
    Ok(client
        .post(url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(syncml::encode(message, &CodecLimits::default())?)
        .send()
        .await?
        .status())
}
async fn fixture_command(program: &str, arguments: &[&std::ffi::OsStr]) -> anyhow::Result<()> {
    let mut process = tokio::process::Command::new(program)
        .args(arguments)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let status =
        match tokio::time::timeout(std::time::Duration::from_secs(30), process.wait()).await {
            Ok(status) => status?,
            Err(error) => {
                process.kill().await?;
                process.wait().await?;
                return Err(error.into());
            }
        };
    ensure!(status.success(), "{program} fixture command failed");
    Ok(())
}
struct Renewed {
    _temporary: tempfile::TempDir,
    key: std::path::PathBuf,
    certificate: Vec<u8>,
    mutual: reqwest::Client,
}
async fn renew(
    host: &Host,
    issue: &soap::Message,
    client: &reqwest::Client,
    certificate: &[u8],
    key: &std::path::Path,
) -> anyhow::Result<Renewed> {
    let temporary = tempfile::tempdir()?;
    let new_key = temporary.path().join("new.key");
    let csr = temporary.path().join("new.csr");
    fixture_command(
        "openssl",
        &[
            "req".as_ref(),
            "-new".as_ref(),
            "-newkey".as_ref(),
            "rsa:2048".as_ref(),
            "-nodes".as_ref(),
            "-subj".as_ref(),
            "/CN=Independent renewed channel".as_ref(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-keyout".as_ref(),
            new_key.as_os_str(),
            "-out".as_ref(),
            csr.as_os_str(),
        ],
    )
    .await?;
    let signer = temporary.path().join("signer.pem");
    std::fs::write(
        &signer,
        x509_cert::Certificate::from_der(certificate)?.to_pem(LineEnding::LF)?,
    )?;
    let cms = temporary.path().join("renew.p7");
    fixture_command(
        "openssl",
        &[
            "cms".as_ref(),
            "-sign".as_ref(),
            "-binary".as_ref(),
            "-nodetach".as_ref(),
            "-nosmimecap".as_ref(),
            "-md".as_ref(),
            "sha256".as_ref(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-in".as_ref(),
            csr.as_os_str(),
            "-signer".as_ref(),
            signer.as_os_str(),
            "-inkey".as_ref(),
            key.as_os_str(),
            "-out".as_ref(),
            cms.as_os_str(),
        ],
    )
    .await?;
    let mut request = issue.clone();
    request.header.security = None;
    request.header.message_id = Some(format!("urn:uuid:{}", Uuid::new_v4()));
    let Body::Issue(body) = &mut request.body else {
        unreachable!()
    };
    body.request = soap::CertificateRequest::RenewalPkcs7(Secret(std::fs::read(cms)?));
    body.additional_context.0.clear();
    let wire = soap::encode(&request, &CodecLimits::default())?;
    let send = || {
        client
            .post(request.header.to.as_ref().unwrap())
            .header("content-type", "application/soap+xml")
            .body(wire.clone())
            .send()
    };
    let response = send().await?;
    ensure!(
        response.status() == StatusCode::OK,
        "renewal: {}",
        response.status()
    );
    let response =
        soap::decode_response(&request, &response.bytes().await?, &CodecLimits::default())?;
    let replay = soap::decode_response(
        &request,
        &send().await?.bytes().await?,
        &CodecLimits::default(),
    )?;
    let (Body::IssueResponse(first), Body::IssueResponse(replay)) = (response.body, replay.body)
    else {
        anyhow::bail!("renewal response");
    };
    ensure!(
        first.provisioning == replay.provisioning,
        "renewal replay changed certificate"
    );
    let xml = String::from_utf8(first.provisioning.0)?;
    let encoded = xml
        .split("name=\"EncodedCertificate\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or_else(|| anyhow::anyhow!("renewal certificate missing"))?;
    let certificate = STANDARD.decode(encoded)?;
    let mutual = identity_client(host, &certificate, &new_key)?;
    Ok(Renewed {
        _temporary: temporary,
        key: new_key,
        certificate,
        mutual,
    })
}
#[tokio::test]
#[ignore = "make t2 MODULE=windows.declared"]
async fn linked_renewal_and_parent_child_supersession() -> anyhow::Result<()> {
    let mut host = Host::renewal_window().await?;
    host.listen().await?;
    let parent = host.peer().await?;
    let ca = &host.app.windows()?.channel.ca;
    let certificate = ca.sign(&ca.restore_intent(
        &parent.intent.tbs,
        &certificate::Csr::verify(&parent.intent.csr)?,
        parent.intent.registration,
    )?)?;
    let child = linked_peer(&host, &parent, &certificate, &host.root.join("device.key")).await?;
    authenticate_child(&child.mutual, &child.url, &child.message, &parent.ack).await?;
    let renewed_child = renew(
        &host,
        &child.issue,
        &child.mutual,
        &child.certificate,
        &host.root.join("renew-device.key"),
    )
    .await?;
    let mut message = child.message.clone();
    message.header.session_id += 120;
    ensure!(
        manage(&child.mutual, &child.url, &message).await? == StatusCode::OK,
        "old child disabled before proof"
    );
    message.header.session_id += 1;
    ensure!(manage(&renewed_child.mutual, &child.url, &message).await? == StatusCode::OK);
    message.header.session_id += 1;
    ensure!(manage(&child.mutual, &child.url, &message).await? == StatusCode::UNAUTHORIZED);
    let renewed_parent = renew(
        &host,
        &parent.issue,
        &parent.mutual,
        &certificate,
        &host.root.join("device.key"),
    )
    .await?;
    let mut parent_message = parent.message.clone();
    parent_message.header.session_id += 130;
    ensure!(manage(&renewed_parent.mutual, &parent.url, &parent_message).await? == StatusCode::OK);
    message.header.session_id += 1;
    ensure!(
        manage(&renewed_child.mutual, &child.url, &message).await? == StatusCode::OK,
        "parent renewal retired child"
    );
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let row=sqlx::query("SELECT generation,parent_id,state,(SELECT count(*) FROM mdm_access.report_sources s WHERE (s.tenant_id,s.registration)=(r.tenant_id,r.id)) AS sources FROM mdm_access.registrations r WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(child.id).fetch_one(&mut pg).await?;
    ensure!(
        row.try_get::<i64, _>("generation")? == child.generation
            && row.try_get::<Uuid, _>("parent_id")? == parent.intent.registration
            && row.try_get::<String, _>("state")? == "active"
            && row.try_get::<i64, _>("sources")? == 0
    );
    let old = host
        .client
        .post(child.issue.header.to.as_ref().unwrap())
        .header("content-type", "application/soap+xml")
        .body(child.wire.clone())
        .send()
        .await?;
    ensure!(
        !old.status().is_success(),
        "old parent certificate replay revived child"
    );
    let next = linked_peer(
        &host,
        &parent,
        &renewed_parent.certificate,
        &renewed_parent.key,
    )
    .await?;
    ensure!(next.id != child.id && next.generation > child.generation);
    message.header.session_id += 1;
    ensure!(manage(&renewed_child.mutual, &child.url, &message).await? == StatusCode::UNAUTHORIZED);
    ensure!(manage(&next.mutual, &next.url, &next.message).await? == StatusCode::OK);
    host.replace(&parent).await?;
    let states: Vec<String> = sqlx::query_scalar(
        "SELECT state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=ANY($2)",
    )
    .bind(case_tenant())
    .bind(vec![child.id, next.id])
    .fetch_all(&mut pg)
    .await?;
    ensure!(states.len() == 2 && states.iter().all(|s| s == "superseded"));
    let mut next_message = next.message.clone();
    next_message.header.session_id += 140;
    ensure!(manage(&next.mutual, &next.url, &next_message).await? == StatusCode::UNAUTHORIZED);
    ensure!(
        !host
            .client
            .post(next.issue.header.to.as_ref().unwrap())
            .header("content-type", "application/soap+xml")
            .body(next.wire)
            .send()
            .await?
            .status()
            .is_success()
    );
    pg.close().await?;
    host.close().await?;
    Ok(())
}

#[cfg(feature = "integration")]
async fn claim_count(pg: &mut PgConnection, policy: Uuid) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2").bind(case_tenant()).bind(policy).fetch_one(pg).await?)
}
#[cfg(feature = "integration")]
async fn automation(host: &Host) -> anyhow::Result<rss_runtime::ShutdownStack> {
    use std::time::Duration;
    let service = crate::automation::Automation::connect(
        host.app.flow.planning.clone(),
        host.app.flow.assets.clone(),
        host.app.flow.compliance.clone(),
        options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(service.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(
        service
            .registration(host.notifications.signals.flow())
            .critical(),
    );
    launch.finish();
    Ok(owner)
}
#[cfg(feature = "integration")]
fn has_declared_query(message: &syncml::Message) -> bool {
    message.commands.iter().any(|c| matches!(c, syncml::Command::Get { items, .. } if items.iter().any(|i| i.target.as_ref().is_some_and(|u| u.contains("/Results/")))))
}
fn with_summary(
    mut packet: syncml::Message,
    document: &str,
    version: &str,
    state: u32,
) -> anyhow::Result<syncml::Message> {
    let identity = rss_mdm_windows_mdm::native::declared::Document::parse(document)?.identity;
    let context = match identity.scope {
        rss_mdm_windows_mdm::native::Scope::Device => "Device",
        rss_mdm_windows_mdm::native::Scope::User => "User",
    };
    packet.commands.retain(|c| {
        !matches!(
            c,
            syncml::Command::Alert {
                alert: syncml::Alert::DeclaredConfiguration { .. },
                ..
            }
        )
    });
    let id = packet
        .commands
        .iter()
        .map(syncml::Command::id)
        .max()
        .unwrap_or(0)
        + 1;
    packet.commands.push(syncml::Command::Alert {
        id,
        alert: syncml::Alert::DeclaredConfiguration {
            summary: Secret(format!(r#"<DeclaredConfigurations schema="1.0"><DeclaredConfiguration id="{}" context="{context}" checksum="{}" result_checksum="{version}" state="{state}"/></DeclaredConfigurations>"#, identity.id, identity.checksum)),
            explicit_format: true,
        },
    });
    Ok(packet)
}
fn result_packet(
    first: &syncml::Message,
    sent: &syncml::Message,
    value: Option<&str>,
) -> syncml::Message {
    use syncml::{Command, CommandName, Item, Results, Status};
    let mut commands = Vec::new();
    let status = |id, command_ref, command| {
        Command::Status(Status {
            id,
            message_ref: sent.header.message_id,
            command_ref,
            command,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        })
    };
    commands.push(status(1, 0, CommandName::SyncHdr));
    for command in &sent.commands {
        let (kind, items) = match command {
            Command::Replace { items, .. } => (CommandName::Replace, items),
            Command::Delete { items, .. } => (CommandName::Delete, items),
            Command::Get { items, .. } => (CommandName::Get, items),
            _ => continue,
        };
        commands.push(status(commands.len() as u32 + 1, command.id(), kind));
        if kind == CommandName::Get {
            for item in items {
                let uri = item.target.as_deref().unwrap();
                let value = if uri.ends_with("/SwV") {
                    Some("10.0.22631.3958")
                } else if uri.ends_with("/Edition") {
                    Some("48")
                } else {
                    value
                };
                if let Some(value) = value {
                    commands.push(Command::Results(Results {
                        id: commands.len() as u32 + 1,
                        message_ref: Some(sent.header.message_id),
                        command_ref: Some(command.id()),
                        command: Some(CommandName::Get),
                        meta: None,
                        items: vec![Item {
                            source: Some(uri.into()),
                            target: None,
                            meta: None,
                            data: Some(Secret(value.into())),
                            more_data: false,
                        }],
                    }));
                }
            }
        }
    }
    syncml::Message {
        header: syncml::Header {
            message_id: sent.header.message_id + 1,
            credential: None,
            ..first.header.clone()
        },
        commands,
        final_message: true,
    }
}
#[cfg(feature = "integration")]
async fn begin_declared(
    child: &LinkedPeer,
    parent_ack: &syncml::Message,
    session: u32,
) -> anyhow::Result<(syncml::Message, syncml::Message)> {
    let mut first = child.message.clone();
    first.header.session_id = session;
    let sent = authenticate_child(&child.mutual, &child.url, &first, parent_ack).await?;
    Ok((first, sent))
}

#[cfg(feature = "integration")]
fn native_result(document: &str, operation: &str, state: u32) -> String {
    document
        .replace("DeclaredConfiguration", "DeclaredConfigurationResult")
        .replace(
            " checksum=",
            &format!(
                r#" result_checksum="result-v1" operation="{operation}" state="{state}" checksum="#
            ),
        )
        .replace(
            "className=",
            &format!(r#"status="200" state="{state}" className="#),
        )
}
#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=windows.declared"]
async fn declared_policy_delete_claims_recover_from_unknown_commit() -> anyhow::Result<()> {
    use crate::execution::test_support::{
        Client,
        configuration::{change, published, resource_input, wait_diagnosis},
        native,
    };
    use axum::http::Method;
    use serde_json::json;
    let mut host = Host::open().await?;
    host.listen().await?;
    let parent = host.peer().await?;
    let ca = &host.app.windows()?.channel.ca;
    let certificate = ca.sign(&ca.restore_intent(
        &parent.intent.tbs,
        &certificate::Csr::verify(&parent.intent.csr)?,
        parent.intent.registration,
    )?)?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let mut grants = [
        "resource_read",
        "resource_write",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
    ]
    .into_iter()
    .map(|operation| json!({"operation":operation,"scope":{"kind":"tenant"}}))
    .collect::<Vec<_>>();
    grants.extend(
        [
            "windows_mi_execute",
            "configuration_write",
            "inventory_read",
            "operation_read",
            "operation_cancel",
        ]
        .into_iter()
        .map(|operation| json!({"operation":operation,"scope":{"kind":"all_devices"}})),
    );
    let rule=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
    ensure!(rule.0 == StatusCode::OK, "policy grants: {rule:?}");
    let worker = automation(&host).await?;
    let commands = client.command_worker(host.notifications.signals.clone())?;
    let scope = Uuid::new_v4();
    let created=change(&mut client,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":crate::test_support::case::name("tls-device")}],"limitations":null,"exclusions":[]}})).await?;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let read = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!(
                        "/api/v2/scopes/{scope}/tasks/{}",
                        created["task"].as_str().unwrap()
                    ),
                    None,
                )
                .await?;
            if read.1["status"] == "completed" {
                return Ok::<_, anyhow::Error>(());
            }
            ensure!(read.1["status"] != "failed", "Scope failed: {read:?}");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await??;
    let id = Uuid::new_v4();
    let document = format!(
        r#"<DeclaredConfiguration schema="1.0" context="Device" id="{id}" checksum="policy-v1" osdefinedscenario="MSFTExtensibilityMIProviderConfig"><DSC namespace="root/test" className="ExampleProvider"><Key name="Name">resource</Key><Value name="Text">first-value</Value></DSC></DeclaredConfiguration>"#
    );
    let task = |id: Uuid, document: &str, operation: &str| json!({"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/DeclaredConfiguration/Host/Complete/Documents/*/Document","instance":[id],"operation":operation,"value":{"type":"xml","value":document}}}});
    let resource=resource_input(&mut client,json!({"target":{"kind":"device"},"apply":task(id,&document,"replace"),"remove":task(id,&document,"delete")}),&["first-value"]).await?;
    let first = Uuid::new_v4();
    let definition = |resource: &str| json!({"scope":scope,"action":{"kind":"configuration","resource":{"id":resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"remove"}});
    change(
        &mut client,
        &format!("/api/v3/policies/{first}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition(&resource)}),
    )
    .await?;
    wait_diagnosis(&mut client, first, "windows_declared_enrollment_not_ready").await?;
    remote_not_ready(&mut client, &resource).await?;
    let child = linked_peer(&host, &parent, &certificate, &host.root.join("device.key")).await?;
    wait_diagnosis(&mut client, first, "windows_declared_enrollment_not_ready").await?;
    remote_not_ready(&mut client, &resource).await?;
    authenticate_child(&child.mutual, &child.url, &child.message, &parent.ack).await?;
    let apply = published(&mut client, first)
        .await
        .context("publish WinDC Set after readiness")?;
    ensure!(apply.len() == 1);
    let (initial, mut sent) = begin_declared(&child, &parent.ack, 1800).await?;
    let mut writes = 0;
    for _ in 0..6 {
        writes += sent
            .commands
            .iter()
            .filter(|c| matches!(c, syncml::Command::Replace { .. }))
            .count();
        if sent
            .commands
            .iter()
            .all(|c| matches!(c, syncml::Command::Status(_)))
        {
            break;
        }
        let packet = result_packet(&initial, &sent, Some(&native_result(&document, "Set", 60)));
        let response = native::post(&child.mutual, &child.url, &packet).await?;
        ensure!(response.status() == StatusCode::OK);
        sent = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
    }
    ensure!(
        writes == 1
            && client
                .call(Method::GET, &format!("/{}", apply[0]), None)
                .await?
                .1["commandStatus"]
                == "applied"
    );
    let other_id = Uuid::new_v4();
    let other_document = document
        .replace(&id.to_string(), &other_id.to_string())
        .replace("first-value", "competing-value");
    let other_resource=resource_input(&mut client,json!({"target":{"kind":"device"},"apply":task(other_id,&other_document,"replace"),"remove":task(other_id,&other_document,"delete")}),&["competing-value"]).await?;
    let second = Uuid::new_v4();
    change(
        &mut client,
        &format!("/api/v3/policies/{second}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition(&other_resource)}),
    )
    .await?;
    wait_diagnosis(&mut client, second, "configuration_conflict").await?;
    change(
        &mut client,
        &format!("/api/v3/policies/{second}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    change(
        &mut client,
        &format!("/api/v3/policies/{first}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let removed = published(&mut client, first)
        .await
        .context("publish WinDC Delete after disable")?;
    ensure!(removed.len() == 1 && removed != apply);
    let (initial, mut sent) = begin_declared(&child, &parent.ack, 1801).await?;
    let mut deletes = 0;
    for _ in 0..6 {
        if sent.commands.iter().any(|c|matches!(c,syncml::Command::Get{items,..} if items.iter().any(|i|i.target.as_ref().is_some_and(|u|u.contains("/Results/"))))){break;}
        deletes += sent
            .commands
            .iter()
            .filter(|c| matches!(c, syncml::Command::Delete { .. }))
            .count();
        let response = native::post(
            &child.mutual,
            &child.url,
            &result_packet(&initial, &sent, None),
        )
        .await?;
        ensure!(response.status() == StatusCode::OK);
        sent = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
    }
    ensure!(deletes == 1, "Delete dispatch count {deletes}");
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;

    ensure!(
        claim_count(&mut pg, first).await? > 0,
        "ACK released claims"
    );
    ensure!(
        client
            .call(Method::GET, &format!("/{}", removed[0]), None)
            .await?
            .1["commandStatus"]
            != "applied"
    );
    let partial = with_summary(
        result_packet(
            &initial,
            &sent,
            Some(&native_result(&document, "Delete", 10)),
        ),
        &document,
        "result-v1",
        10,
    )?;
    let response = native::post(&child.mutual, &child.url, &partial).await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(
        claim_count(&mut pg, first).await? > 0,
        "pending Delete released claims"
    );
    // A fresh session retrieves the same operation's Observe plan after uncertainty.
    let (initial, mut sent) = begin_declared(&child, &parent.ack, 1802).await?;
    for _ in 0..6 {
        if sent.commands.iter().any(|c|matches!(c,syncml::Command::Get{items,..} if items.iter().any(|i|i.target.as_ref().is_some_and(|u|u.contains("/Results/"))))){break;}
        let response = native::post(
            &child.mutual,
            &child.url,
            &result_packet(&initial, &sent, None),
        )
        .await?;
        ensure!(response.status() == StatusCode::OK);
        sent = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
    }
    let packet = with_summary(
        result_packet(
            &initial,
            &sent,
            Some(&native_result(&document, "Delete", 70)),
        ),
        &document,
        "result-v1",
        70,
    )?;
    let wire = syncml::encode(&packet, &CodecLimits::default())?;
    host.app.execution.inject_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    let response = native::post(&child.mutual, &child.url, &packet).await?;
    ensure!(
        response.status() == StatusCode::SERVICE_UNAVAILABLE,
        "commit unknown: {}",
        response.status()
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(worker.shutdown().join().await?.is_clean());
    drop(client);
    host = host.restart().await?;
    let response = child
        .mutual
        .post(&child.url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(wire.clone())
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "restart exact replay: {}",
        response.status()
    );
    let stable = response.bytes().await?;
    let replay = child
        .mutual
        .post(&child.url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(wire)
        .send()
        .await?;
    ensure!(
        replay.status() == StatusCode::OK && replay.bytes().await? == stable,
        "replay response changed"
    );
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let worker = automation(&host).await?;
    let commands = client.command_worker(host.notifications.signals.clone())?;
    // Unknown submission may leave a fenced claim until lease expiry. The existing worker
    // uses a 30s lease, 5s scan and 6s attempt; include that recovery path in this bound.
    let released = tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            if claim_count(&mut pg, first).await? == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    if released.is_err() {
        let status = client
            .call(Method::GET, &format!("/{}", removed[0]), None)
            .await?;
        let claims: Vec<(String, Option<Uuid>, Option<String>)> = sqlx::query_as("SELECT object_kind,operation,diagnosis FROM mdm_planning.configuration_objects WHERE tenant_id=$1::uuid AND device=$2")
            .bind(case_tenant()).bind(crate::test_support::case::name("tls-device")).fetch_all(&mut pg).await?;
        let recovery: serde_json::Value = sqlx::query_scalar("SELECT jsonb_build_object('input',d.input_revision,'observed',d.observed_revision,'targets',(SELECT jsonb_agg(jsonb_build_object('entity',r.entity,'result',r.result,'failures',r.failures,'leaseUntil',r.lease_until,'nextRun',r.next_run)) FROM rss_reconcile.targets r WHERE r.tenant_id=d.tenant_id AND r.entity='configuration:'||d.device)) FROM mdm_planning.configuration_devices d WHERE d.tenant_id=$1::uuid AND d.device=$2")
            .bind(case_tenant()).bind(crate::test_support::case::name("tls-device")).fetch_one(&mut pg).await?;
        anyhow::bail!(
            "Delete did not release claims: status={}, objects={claims:?}, recovery={recovery}",
            status.1["commandStatus"]
        );
    }
    released??;
    ensure!(
        client
            .call(Method::GET, &format!("/{}", removed[0]), None)
            .await?
            .1["commandStatus"]
            == "applied"
    );
    change(
        &mut client,
        &format!("/api/v3/policies/{second}"),
        2,
        json!({"action":"put","enabled":true,"definition":definition(&other_resource)}),
    )
    .await?;
    ensure!(
        published(&mut client, second).await?.len() == 1,
        "released class could not be claimed"
    );
    let delete_attempts:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute'").bind(case_tenant()).bind(removed[0]).fetch_one(&mut pg).await?;
    ensure!(delete_attempts == 1, "recovery reissued Delete");
    pg.close().await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(worker.shutdown().join().await?.is_clean());
    host.close().await?;
    Ok(())
}

#[cfg(feature = "integration")]
async fn remote_not_ready(
    client: &mut crate::execution::test_support::Client,
    resource: &str,
) -> anyhow::Result<()> {
    use axum::http::Method;
    use serde_json::json;
    let operation = Uuid::new_v4();
    let response=client.browser.call(&client.router,Method::POST,"/api/v3/remote-operations",Some(json!({"operationId":operation,"resource":{"id":resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"targets":{"kind":"devices","devices":[crate::test_support::case::name("tls-device")]},"action":{"kind":"apply_configuration"},"deadline":now()+600}))).await?;
    ensure!(
        response.0 == StatusCode::OK,
        "remote native input: {response:?}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let read = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v3/remote-operations/{operation}"),
                    None,
                )
                .await?;
            ensure!(read.0 == StatusCode::OK, "remote read: {read:?}");
            if !read.1["items"].as_array().unwrap().is_empty() {
                ensure!(
                    read.1["items"][0]["diagnosis"] == "windows_declared_enrollment_not_ready"
                        && read.1["items"][0]["status"] == "blocked",
                    "wrong remote diagnosis: {read:?}"
                );
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(())
}
#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=windows.declared"]
async fn declared_readiness_has_closed_http_diagnosis_and_primary_remains_available()
-> anyhow::Result<()> {
    use crate::execution::test_support::Client;
    use axum::http::Method;
    use serde_json::json;
    let mut host = Host::open().await?;
    host.listen().await?;
    let parent = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    client.set_authorized(true).await?;
    let grants=["windows_mi_execute"].into_iter().map(|operation|json!({"operation":operation,"scope":{"kind":"device","id":crate::test_support::case::name("tls-device")}})).collect::<Vec<_>>();
    let rule=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
    ensure!(rule.0 == StatusCode::OK);
    let id = Uuid::new_v4();
    let document = format!(
        r#"<DeclaredConfiguration schema="1.0" context="Device" id="{id}" checksum="readiness-v1" osdefinedscenario="MSFTExtensibilityMIProviderConfig"><DSC namespace="root/test" className="ExampleProvider"><Key name="Name">resource</Key><Value name="Text">value</Value></DSC></DeclaredConfiguration>"#
    );
    let input = || json!({"operationId":Uuid::new_v4(),"inputVersion":"1","deadline":now()+300,"target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/DeclaredConfiguration/Host/Complete/Documents/*/Document","instance":[id],"operation":"replace","value":{"type":"xml","value":document}}}}});
    let missing = client.call(Method::POST, "", Some(input())).await?;
    ensure!(
        missing.0 == StatusCode::CONFLICT
            && missing.1["code"] == "windows_declared_enrollment_not_ready",
        "missing: {missing:?}"
    );
    let ordinary = json!({"operationId":Uuid::new_v4(),"inputVersion":"1","deadline":now()+300,"target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/DMClient/Provider/*/ConfigRefresh/Enabled","instance":[host.app.windows()?.channel.provider_id],"operation":"get","value":null}}}});
    let primary = client.call(Method::POST, "", Some(ordinary)).await?;
    ensure!(
        primary.0 == StatusCode::ACCEPTED,
        "Primary depended on child: {primary:?}"
    );
    let ca = &host.app.windows()?.channel.ca;
    let certificate = ca.sign(&ca.restore_intent(
        &parent.intent.tbs,
        &certificate::Csr::verify(&parent.intent.csr)?,
        parent.intent.registration,
    )?)?;
    let child = linked_peer(&host, &parent, &certificate, &host.root.join("device.key")).await?;
    let unready = client.call(Method::POST, "", Some(input())).await?;
    ensure!(
        unready.0 == StatusCode::CONFLICT
            && unready.1["code"] == "windows_declared_enrollment_not_ready",
        "unready: {unready:?}"
    );
    authenticate_child(&child.mutual, &child.url, &child.message, &parent.ack).await?;
    ensure!(client.call(Method::POST, "", Some(input())).await?.0 == StatusCode::ACCEPTED);
    host.app
        .devices
        .revoke(
            &parent.proof,
            crate::test_support::case::name("tls-device"),
            parent.intent.registration,
            Uuid::new_v4(),
        )
        .await?;
    let retired = client.call(Method::POST, "", Some(input())).await?;
    ensure!(
        retired.0 == StatusCode::CONFLICT
            && retired.1["code"] == "windows_declared_enrollment_not_ready",
        "parent retirement: {retired:?}"
    );
    host.close().await?;
    Ok(())
}
