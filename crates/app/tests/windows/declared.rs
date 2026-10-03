//! Real TLS/PG proof for the certificate-only independent WinDC channel.
use crate::device::test_support::options;
use crate::windows::test_support::*;
use crate::windows::*;
use anyhow::ensure;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use libxml::{
    parser::Parser,
    tree::c14n::{CanonicalizationMode, CanonicalizationOptions},
};
use ring::{
    rand::SystemRandom,
    signature::{self},
};
use rss_mdm_registration_service::Purpose;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
    syncml,
};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;
use x509_cert::der::{Decode, EncodePem, pem::LineEnding};

// Sign the complete original SOAP document. Reference URI="" and the native single
// enveloped transform use inclusive C14N; SignedInfo uses exclusive C14N.
fn signed(message: &soap::Message, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let xml = String::from_utf8(soap::encode(message, &CodecLimits::default())?)?;
    let doc = Parser::default().parse_string(&xml)?;
    let canonical = doc
        .canonicalize(
            CanonicalizationOptions {
                mode: CanonicalizationMode::Canonical1_0,
                ..Default::default()
            },
            None,
        )
        .map_err(|_| anyhow::anyhow!("fixture document canonicalization"))?;
    let digest = STANDARD.encode(Sha256::digest(canonical.as_bytes()));
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>SIGNATURE</ds:SignatureValue><ds:KeyInfo><o:SecurityTokenReference><o:Reference URI="#parent-cert" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509"/></o:SecurityTokenReference></ds:KeyInfo></ds:Signature>"##
    );
    let xml = xml.replace("</o:Security>", &(signature + "</o:Security>"));
    let doc = Parser::default().parse_string(&xml)?;
    let header = doc
        .get_root_element()
        .unwrap()
        .get_child_elements()
        .into_iter()
        .find(|n| n.get_name() == "Header")
        .unwrap();
    let security = header
        .get_child_elements()
        .into_iter()
        .find(|n| n.get_name() == "Security")
        .unwrap();
    let sig = security
        .get_child_elements()
        .into_iter()
        .find(|n| n.get_name() == "Signature")
        .unwrap();
    let mut info = sig
        .get_child_elements()
        .into_iter()
        .find(|n| n.get_name() == "SignedInfo")
        .unwrap();
    let canonical = info
        .canonicalize(CanonicalizationOptions::default())
        .map_err(|_| anyhow::anyhow!("fixture SignedInfo canonicalization"))?;
    let key = signature::RsaKeyPair::from_pkcs8(key).map_err(|_| anyhow::anyhow!("fixture key"))?;
    let mut bytes = vec![0; key.public().modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        canonical.as_bytes(),
        &mut bytes,
    )
    .map_err(|_| anyhow::anyhow!("fixture signature"))?;
    Ok(xml
        .replace("SIGNATURE", &STANDARD.encode(bytes))
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
    let key = std::fs::read(host.root.join("device.pk8"))?;
    let wire = signed(&issue, &key)?;
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
        !post(signed(&changed, &key)?)
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
    mi_effect(&host, &child_client, &child_url, &message, &peer.ack).await?;
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
async fn mi_effect(
    host: &Host,
    child: &reqwest::Client,
    url: &str,
    initial: &syncml::Message,
    parent_ack: &syncml::Message,
) -> anyhow::Result<()> {
    use crate::execution::test_support::{Client, native};
    use axum::http::Method;
    use serde_json::json;
    use syncml::{Command, CommandName, Item, Results, Status};
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
    let mut ack = parent_ack.clone();
    ack.header.target = url.into();
    let response = native::post(child, url, &ack).await?;
    ensure!(response.status() == StatusCode::OK);
    let response = syncml::decode(&response.bytes().await?, &CodecLimits::default())?;
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
    let packet = |sent: &syncml::Message, number: u32, result: Option<&str>| {
        let mut commands = vec![Command::Status(Status {
            id: 1,
            message_ref: sent.header.message_id,
            command_ref: 0,
            command: CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        })];
        for c in &sent.commands {
            let (kind, items) = match c {
                Command::Replace { items, .. } => (CommandName::Replace, items),
                Command::Get { items, .. } => (CommandName::Get, items),
                _ => continue,
            };
            commands.push(Command::Status(Status {
                id: commands.len() as u32 + 1,
                message_ref: sent.header.message_id,
                command_ref: c.id(),
                command: kind,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }));
            if kind == CommandName::Get
                && let Some(value) = result
            {
                commands.push(Command::Results(Results {
                    id: commands.len() as u32 + 1,
                    message_ref: Some(sent.header.message_id),
                    command_ref: Some(c.id()),
                    command: Some(CommandName::Get),
                    meta: None,
                    items: vec![Item {
                        source: items[0].target.clone(),
                        target: None,
                        meta: None,
                        data: Some(Secret(value.into())),
                        more_data: false,
                    }],
                }));
            }
        }
        syncml::Message {
            header: syncml::Header {
                message_id: number,
                credential: None,
                ..initial.header.clone()
            },
            commands,
            final_message: true,
        }
    };
    let observed = native::post(child, url, &packet(&response, 4, None)).await?;
    ensure!(observed.status() == StatusCode::OK);
    let observed = syncml::decode(&observed.bytes().await?, &CodecLimits::default())?;
    ensure!(observed.commands.iter().any(|c|matches!(c,Command::Get{items,..} if items[0].target.as_ref().unwrap().contains("/Results/"))));
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["commandStatus"]
            != "applied",
        "ACK became effect"
    );
    let result = |state| {
        document
            .replace("DeclaredConfiguration", "DeclaredConfigurationResult")
            .replace(
                " checksum=",
                &format!(
                    r#" result_checksum="result-v1" operation="Set" state="{state}" checksum="#
                ),
            )
            .replace(
                "className=",
                &format!(r#"status="200" state="{state}" className="#),
            )
    };
    let partial = native::post(child, url, &packet(&observed, 5, Some(&result(20)))).await?;
    ensure!(partial.status() == StatusCode::OK);
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["commandStatus"]
            != "applied",
        "partial native state became effect"
    );
    client.publish_operation(operation).await?;
    let summary = format!(
        r#"<DeclaredConfigurations schema="1.0"><DeclaredConfiguration id="{id}" context="Device" checksum="immutable-v1" result_checksum="result-v1" state="60"/></DeclaredConfigurations>"#
    );
    let notice = syncml::Message {
        header: syncml::Header {
            message_id: 6,
            credential: None,
            ..initial.header.clone()
        },
        commands: vec![Command::Alert {
            id: 1,
            alert: syncml::Alert::DeclaredConfiguration {
                summary: Secret(summary),
                explicit_format: true,
            },
        }],
        final_message: true,
    };
    let queried = native::post(child, url, &notice).await?;
    ensure!(queried.status() == StatusCode::OK);
    let queried = syncml::decode(&queried.bytes().await?, &CodecLimits::default())?;
    ensure!(
        queried
            .commands
            .iter()
            .any(|c| matches!(c, Command::Get { .. })),
        "1224 did not trigger full Results"
    );
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["commandStatus"]
            != "applied",
        "summary became effect"
    );
    let complete = native::post(child, url, &packet(&queried, 7, Some(&result(60)))).await?;
    ensure!(complete.status() == StatusCode::OK);
    let detail = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        detail.1["commandStatus"] == "applied",
        "full result did not settle: {detail:?}"
    );
    Ok(())
}
