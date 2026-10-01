#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::test_support::software::{Fixture, create_software_version, write};
use crate::test_support::*;
async fn private_formats(
    user: &mut Browser,
    router: &Router,
    client: &Client,
    origin: &str,
    cookie: &str,
    source: Value,
) -> Result<()> {
    use std::io::Write;
    let manifest = rss_mdm_resource::BundleManifest {
        schema: 1,
        platform: rss_mdm_resource::Platform::Windows,
        architecture: rss_mdm_resource::Architecture::X86_64,
        entries: std::collections::BTreeMap::from([
            (
                "install.ps1".into(),
                rss_mdm_resource::BundleEntry {
                    length: 4,
                    sha256: rss_mdm_resource::Digest::of(b"exit").bytes(),
                },
            ),
            (
                "payload.bin".into(),
                rss_mdm_resource::BundleEntry {
                    length: 3,
                    sha256: rss_mdm_resource::Digest::of(b"abc").bytes(),
                },
            ),
        ]),
    };
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in [
        ("manifest.json", serde_json::to_vec(&manifest)?),
        ("install.ps1", b"exit".to_vec()),
        ("payload.bin", b"abc".to_vec()),
    ] {
        zip.start_file(name, options)?;
        zip.write_all(&bytes)?;
    }
    let bundle = zip.finish()?.into_inner();
    for (format, platform, executor, bytes, manifest) in [
        (
            "pkg",
            "macos",
            "package_installer",
            b"controlled PKG fixture".to_vec(),
            Value::Null,
        ),
        (
            "bundle",
            "windows",
            "power_shell7",
            bundle,
            serde_json::to_value(manifest)?,
        ),
    ] {
        let id = Uuid::new_v4();
        let path = format!("/api/v3/resources/{id}");
        write(
            user,
            router,
            &path,
            0,
            json!({"action":"create","kind":"software"}),
        )
        .await?;
        let definition = json!({"source":source,"package":format!("Private.{format}"),"version":"1","artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":rss_mdm_resource::Digest::of(&bytes).bytes()}},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"behavior":if format == "bundle" {serde_json::json!({"kind":"bundle","archive":"package","manifest":manifest,"install":{"interpreter":executor,"entry":if format=="bundle"{Some("install.ps1")}else{None},"invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"uninstall":null,"detect":if format=="pkg"{json!({"kind":"pkg_receipt","receipt":"com.acme.pkg","version":"1"})}else{json!({"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"})}})} else {serde_json::json!({"kind":format,"installer":"package","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":if format=="pkg"{json!({"kind":"pkg_receipt","receipt":"com.acme.pkg","version":"1"})}else{json!({"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"})},"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}})},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
        write(user,router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":platform,"architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
        let upload = Uuid::new_v4();
        let session = format!("{origin}{path}/uploads/{upload}");
        let csrf = user.csrf.as_ref().unwrap().clone();
        let request = |method, url: &str| {
            client
                .request(method, url)
                .header("host", "mdm.example.test")
                .header("origin", "https://mdm.example.test")
                .header("x-identity-request", "1")
                .header("x-csrf-token", &csrf)
                .header("cookie", cookie)
                .header("content-type", "application/octet-stream")
        };
        let begin = request(
            Method::POST,
            &format!(
                "{session}?version=v1&variant=default&platform={platform}&architecture=x86_64"
            ),
        )
        .send()
        .await?;
        ensure!(begin.status() == StatusCode::OK);
        let half = bytes.len() / 2;
        ensure!(
            request(Method::PATCH, &format!("{session}?offset=0"))
                .body(bytes[..half].to_vec())
                .send()
                .await?
                .status()
                == StatusCode::OK
        );
        let resumed: Value = request(Method::GET, &session).send().await?.json().await?;
        ensure!(resumed["offset"] == half);
        let conflict = request(Method::PATCH, &format!("{session}?offset=0"))
            .body(vec![0])
            .send()
            .await?;
        ensure!(conflict.status() == StatusCode::CONFLICT);
        ensure!(conflict.json::<Value>().await?["offset"] == half);
        let foreign = request(
            Method::GET,
            &format!(
                "{origin}/api/v3/resources/{}/uploads/{upload}",
                Uuid::new_v4()
            ),
        )
        .send()
        .await?;
        ensure!(foreign.status() == StatusCode::FORBIDDEN);
        ensure!(
            request(Method::PATCH, &format!("{session}?offset={half}"))
                .body(bytes[half..].to_vec())
                .send()
                .await?
                .status()
                == StatusCode::OK
        );
        let response = request(Method::POST, &format!("{session}/complete"))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status == StatusCode::CREATED, "{format}: {status} {body}");
        let approved = write(
            user,
            router,
            &format!("/api/v3/software/resources/{id}/versions/v1"),
            0,
            json!({"action":"approve","evidence":["private-format-review"]}),
        )
        .await?;
        ensure!(approved["admission"]["state"] == "approved");
    }
    Ok(())
}

async fn dependency_denial_over_http(
    user: &mut Browser,
    router: &Router,
    definition: &Value,
) -> Result<()> {
    let (dependency, digest) = create_software_version(user, router, definition.clone()).await?;
    let mut input = definition.clone();
    input["dependencies"] = json!([{"resource":dependency,"version":"v1","sha256":digest}]);
    let (dependent, _) = create_software_version(user, router, input).await?;
    let response = user.call(router, Method::POST, &format!("/api/v3/software/resources/{dependent}/versions/v1"),
        Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"approve","evidence":["review"]}}))).await?;
    ensure!(
        response.0 == StatusCode::FORBIDDEN,
        "dependency admission HTTP mapping: {response:?}"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=software.http: private formats and authenticated dependency admission"]
async fn private_formats_and_dependency_routes() -> Result<()> {
    let fixture = Fixture::open(false).await?;
    fixture.seed_content(b"abc").await?;
    let cookie = fixture
        .user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let definition =
        publication_support::private_definition(fixture.registered["snapshot"].clone(), b"abc");
    let mut user = fixture.user.clone();
    private_formats(
        &mut user,
        &fixture.router,
        &fixture.client,
        &fixture.origin,
        &cookie,
        fixture.registered["snapshot"].clone(),
    )
    .await?;
    dependency_denial_over_http(&mut user, &fixture.router, &definition).await
}

mod publication;

mod imports;
