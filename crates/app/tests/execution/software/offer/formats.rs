//! Actual management HTTP, PG, content and signed task seams for every new native form.
use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::*;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};

fn invocation(user: bool) -> Value {
    json!({"runAs":if user {"logged_in_user"} else {"system"},"arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[3010]}})
}
fn zip(files: Vec<(&str, Vec<u8>)>) -> Result<Vec<u8>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in files {
        archive.start_file(
            path,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )?;
        archive.write_all(&bytes)?;
    }
    Ok(archive.finish()?.into_inner())
}
fn msix(bundle: bool, user: bool) -> Result<(Value, Vec<u8>)> {
    let identity = json!({"name":"Acme.App","publisher":"CN=Acme","version":[1,0,0,0],"architecture":"x86_64","resourceId":""});
    let package = zip(vec![("AppxManifest.xml", br#"<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Acme.App" Publisher="CN=Acme" Version="1.0.0.0" ProcessorArchitecture="x64"/><Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22621.0"/></Dependencies></Package>"#.to_vec()), ("payload.bin", b"controlled MSIX material".to_vec())])?;
    let (container, bytes) = if bundle {
        let xml = format!(
            r#"<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Acme.App" Publisher="CN=Acme" Version="1.0.0.0"/><Packages><Package FileName="Acme.x64.msix" Type="application" Architecture="x64" Version="1.0.0.0" Size="{}"/></Packages></Bundle>"#,
            package.len()
        );
        (
            json!({"kind":"bundle","installer":"package","members":[{"path":"Acme.x64.msix","identity":identity,"length":package.len(),"sha256":<[u8;32]>::from(Sha256::digest(&package))}]}),
            zip(vec![
                ("AppxMetadata/AppxBundleManifest.xml", xml.into_bytes()),
                ("Acme.x64.msix", package),
            ])?,
        )
    } else {
        (json!({"kind":"package","installer":"package"}), package)
    };
    Ok((
        json!({"kind":"msix","container":container,"identity":identity,"dependencies":[],"deployment":if user {json!({"kind":"target_user_registration","target":{"kind":"active_interactive"}})}else{json!({"kind":"device_provisioning"})},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":false,"uninstall":true,"invocation":invocation(user),"upgrade":"in_place"}),
        bytes,
    ))
}

#[allow(
    clippy::cognitive_complexity,
    reason = "native format matrix asserts each distinct full backend behavior over real HTTP and PG"
)]
async fn chain(format: &str, bundle: bool, user: bool) -> Result<()> {
    let platform = if format == "dmg_app" || format == "dmg_pkg" {
        Platform::MacOs
    } else {
        Platform::Windows
    };
    let mut local = context(platform);
    local["interactiveUser"] = json!({"identity":if platform==Platform::Windows {"S-1-5-21-100-200-300-1001"} else {"501"},"sessionId":Uuid::new_v4(),"administrator":true});
    if platform == Platform::Windows {
        local["msixSideload"] = json!(true);
    }
    let profiles = match format {
        "exe" => json!([
            "inventory.collect.v5",
            "software.msi.system.v5",
            "software.exe.system.v5"
        ]),
        "dmg_app" => json!([
            "inventory.collect.v5",
            "software.pkg.system.v5",
            "software.dmg.app.system.v5"
        ]),
        "dmg_pkg" => json!([
            "inventory.collect.v5",
            "software.pkg.system.v5",
            "software.dmg.pkg.system.v5"
        ]),
        "msix" if user => json!([
            "inventory.collect.v5",
            "software.msi.system.v5",
            "software.msix.registration.user.v5"
        ]),
        "msix" => json!([
            "inventory.collect.v5",
            "software.msi.system.v5",
            "software.msix.provisioning.system.v5"
        ]),
        _ => anyhow::bail!("unknown matrix entry"),
    };
    let mut f = Fixture::with_profiles(platform, profiles, local.clone()).await?;
    let stack = worker(&f.base, f.content.clone()).await?;
    let (behavior, bytes) = match format {
        "exe" => (
            json!({"kind":"exe","installer":"package","scope":"system","install":invocation(false),"upgradeInvocation":invocation(false),"upgrade":"in_place","uninstall":null,"layout":{"setup.exe":"package"},"detect":{"kind":"registry","scope":"system","key":"Software\\Acme\\App","value":"Version","version":"1.0"}}),
            b"controlled offline executable".to_vec(),
        ),
        "dmg_app" => (
            json!({"kind":"dmg","image":"package","volume":"Acme","scope":"system","invocation":invocation(false),"upgrade":"in_place","payload":{"kind":"app_copy","application":{"path":"Acme.app","bundleId":"com.acme.app","version":"1.0","materialSha256":vec![7;32],"targetName":"Acme.app"},"uninstall":true}}),
            b"controlled app disk image".to_vec(),
        ),
        "dmg_pkg" => (
            json!({"kind":"dmg","image":"package","volume":"Acme","scope":"system","invocation":invocation(false),"upgrade":"in_place","payload":{"kind":"contained_pkg","path":"Acme.pkg","length":3,"sha256":vec![7;32],"receipt":"com.acme.app","uninstall":null}}),
            b"controlled pkg disk image".to_vec(),
        ),
        "msix" => msix(bundle, user)?,
        _ => unreachable!(),
    };
    let resource = Uuid::new_v4();
    let path = format!("/api/v4/resources/{resource}");
    let version = if format == "msix" { "1.0.0.0" } else { "1.0" };
    // Non-MSIX cases prove prerequisites use the same support decision and result binding.
    let deps = if format == "msix" {
        json!([])
    } else {
        json!([{"resource":f.dependency,"version":"v1","sha256":f.dependency_digest}])
    };
    let definition = json!({"source":f.source_snapshot,"package":"Acme.App","version":version,"provenance":{"kind":"private"},"artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":<[u8;32]>::from(Sha256::digest(&bytes))}},"behavior":behavior,"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":deps,"export":{"kind":"disabled"}});
    write(
        &mut f.author,
        &f.router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let (os, arch, selector) = if platform == Platform::Windows {
        ("windows", "x86_64", "windows_x86_64")
    } else {
        ("macos", "aarch64", "macos_aarch64")
    };
    write(&mut f.author,&f.router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":os,"architecture":arch,"key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    let request = Request::builder().method(Method::POST)
        .uri(format!("/api/v3/resources/{resource}/content?version=v1&variant=default&platform={os}&architecture={arch}&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",f.author.csrf.as_ref().unwrap())
        .header("cookie",f.author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(bytes.clone()))?;
    let upload = f.router.clone().oneshot(request).await?;
    ensure!(
        upload.status() == StatusCode::CREATED,
        "{format} upload: {}",
        upload.status()
    );
    write(
        &mut f.author,
        &f.router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let admitted = write(
        &mut f.author,
        &f.router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        0,
        json!({"action":"approve","evidence":["hash-only enterprise review"]}),
    )
    .await?;
    let policy = Uuid::new_v4();
    let policy_path = format!("/api/v3/policies/{policy}");
    write(&mut f.author,&f.router,&policy_path,0,json!({"action":"put","enabled":true,"definition":{"scope":f.scope,"action":{"kind":"software","resource":{"kind":"software","id":resource,"version":"v1","variants":{selector:"default"}},"intent":"required_install","delivery":{"kind":"direct"},"admissionOperation":admitted["admission"]["operation"],"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":f.scope,"opensAt":0}]}}}})).await?;
    let task = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let r = agent_call(
                &f.router,
                Method::POST,
                "/api/agent/v5/tasks/claim",
                Some(&f.credential),
                Some(
                    json!({"wireVersion":5,"profiles":[],"executionContext":local,"operationId":Uuid::new_v4()}),
                ),
            )
            .await?;
            ensure!(r.0 == StatusCode::OK, "claim: {r:?}");
            if !r.1["task"].is_null() {
                break anyhow::Ok(r.1["task"].clone());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let spec: rss_mdm_agent_wire::SoftwareTaskSpec =
        serde_json::from_value(task["payload"].clone())?;
    ensure!(spec.steps.len() == if format == "msix" { 1 } else { 2 });
    let root = spec.steps.last().unwrap();
    ensure!(
        root.action.behavior.kind()
            == if format.starts_with("dmg") {
                "dmg"
            } else {
                format
            }
    );
    ensure!(
        root.target
            == if user {
                rss_mdm_agent_wire::SoftwareExecutionTarget::User {
                    identity: local["interactiveUser"]["identity"]
                        .as_str()
                        .unwrap()
                        .into(),
                    session_id: serde_json::from_value(
                        local["interactiveUser"]["sessionId"].clone(),
                    )?,
                }
            } else {
                rss_mdm_agent_wire::SoftwareExecutionTarget::Device
            }
    );
    let content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v5/tasks/{}/content?attempt={}&artifact={}%2Fpackage",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap(),
            spec.steps.len() - 1
        ))
        .header("host", "mdm.example.test")
        .header("authorization", format!("Bearer {}", f.credential))
        .body(Body::empty())?;
    let content = f.router.clone().oneshot(content).await?;
    ensure!(content.status() == StatusCode::OK);
    ensure!(content.into_body().collect().await?.to_bytes() == bytes);
    for kind in ["received", "start"] {
        let r = event_with(&f.router, &f.credential, &task, json!({"kind":kind})).await?;
        ensure!(r.0 == StatusCode::OK, "{kind}: {r:?}");
    }
    let mut result = result_event(&task, "install", Some(0), "present", false)?;
    let output_marker = "private installer stdout marker";
    if format == "exe" {
        result["steps"][0]["diagnostics"]["stdout"] = json!(output_marker);
    }
    if format == "msix" {
        let mut wrong = result.clone();
        wrong["steps"][0]["identity"]["kind"] = json!(if user {
            "msix_provisioning"
        } else {
            "msix_registration"
        });
        ensure!(
            event_with(&f.router, &f.credential, &task, wrong)
                .await?
                .0
                .is_client_error(),
            "wrong native effect accepted"
        );
    }
    let r = event_with(&f.router, &f.credential, &task, result).await?;
    ensure!(r.0 == StatusCode::OK, "result: {r:?}");
    if format == "exe" {
        let runs = f
            .author
            .call(&f.router, Method::GET, &format!("{policy_path}/runs"), None)
            .await?;
        ensure!(
            !runs.1.to_string().contains(output_marker),
            "software list exposed complete process output"
        );
    }
    let rollout = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        rollout.1["stages"][0]["verifiedSuccess"] == 1,
        "rollout: {rollout:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn exe_complete_backend_chain() -> Result<()> {
    chain("exe", false, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn dmg_app_complete_backend_chain() -> Result<()> {
    chain("dmg_app", false, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn dmg_pkg_complete_backend_chain() -> Result<()> {
    chain("dmg_pkg", false, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn msix_registration_complete_backend_chain() -> Result<()> {
    chain("msix", false, true).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn msix_provisioning_complete_backend_chain() -> Result<()> {
    chain("msix", false, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn msixbundle_registration_complete_backend_chain() -> Result<()> {
    chain("msix", true, true).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn msixbundle_provisioning_complete_backend_chain() -> Result<()> {
    chain("msix", true, false).await
}
