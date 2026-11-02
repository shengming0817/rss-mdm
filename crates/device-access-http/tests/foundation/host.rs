//! Concrete standalone application: initialize its management account, serve TLS and drain.
use super::*;
use std::{os::unix::fs::PermissionsExt, path::Path};

fn private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub async fn verify(
    c: &Context,
    m: &material::Material,
    registration: &registration::agent::da::RegistrationService,
) -> Result<()> {
    let management: Uuid =
        sqlx::query_scalar("SELECT management_tenant_id FROM rss_da.authorization_installation")
            .fetch_one(&c.operator)
            .await?;
    let browser = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let protocol = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let browser_address = browser.local_addr()?;
    let protocol_address = protocol.local_addr()?;
    let origin = format!("https://localhost:{}", browser_address.port());
    let trust = registration.trust().trust.public()?;
    let trust_file = m.directory.join("host-trust.json");
    private(&trust_file, &serde_json::to_vec(&trust)?)?;
    let cursor = m.directory.join("host-cursor.key");
    private(&cursor, &[7; 32])?;
    std::fs::set_permissions(
        m.directory.join("provider.pk8"),
        std::fs::Permissions::from_mode(0o600),
    )?;
    let runtime_file = m.directory.join("host-runtime.json");
    let listener = |address: std::net::SocketAddr, origin: &str| {
        serde_json::json!({
            "listen":address,"origin":origin,"certificate_file":m.directory.join("server.pem"),
            "private_key_file":m.directory.join("server.key")
        })
    };
    let value = serde_json::json!({
        "installation":{"instance":c.inputs.installation.instance_id,"tenant":c.tenant.to_string(),
          "management_tenant":management,"target":c.inputs.installation.target,"lineage":c.inputs.installation.lineage,"epoch":1},
        "database":c.inputs.database("da_access"),"identity_database":c.inputs.database("da_identity_runtime"),
        "audit":{"mode":"plain"},"browser":listener(browser_address,&origin),
        "registration":{"listener":listener(protocol_address,&trust.origin),"trust_file":trust_file,
          "providers":[{"purpose":"da_device","issuer":trust.issuers[0].digest,
            "origin":format!("https://localhost:{}",m.port),"tls_root_file":m.directory.join("task-trust-ca/ca.pem"),
            "provisioner":"rss-da-device","kid":"da-test","provisioner_key_file":m.directory.join("provider.pk8")}],
          "certificate_days":365,"configuration_revision":null,"configuration_lifetime":3600},
        "protection":{"active_file":c.inputs.directory.join("native.key"),"historical_files":[],
          "fingerprint_file":c.inputs.directory.join("fingerprint.key")},"cursor_key_file":cursor,
        "deployment_authorities":[],"platform_sso":null,"enterprise":null,"oidc":null,"recovery":null
    });
    private(&runtime_file, &serde_json::to_vec(&value)?)?;
    let password_file = m.directory.join("host-password");
    let password = "host-account-test-only-88!";
    private(&password_file, password.as_bytes())?;
    let principal = Uuid::new_v4();
    let login = format!("host-{}", principal.simple());
    rss_da_app::maintenance::account(
        rss_da_app::maintenance::Account {
            runtime_file: runtime_file.clone(),
            maintenance_database: serde_json::from_value(serde_json::to_value(
                c.inputs.database("da_identity_maintenance"),
            )?)?,
            tenant: management,
            principal,
            login: login.clone(),
            password_file,
            operation_id: Uuid::new_v4(),
        },
        rss_da_app::maintenance::AccountOperation::Initialize,
    )
    .await?;
    drop((browser, protocol));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let config = rss_da_app::config::load(&runtime_file)?;
    let running = tokio::spawn(rss_da_app::host::serve(config, async move {
        stopped.await.map_err(std::io::Error::other)
    }));
    let result = async {
        let client = m.client(None)?;
        let base = format!("{origin}/api/v1/identity/tenants/{management}");
        let response = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Ok(response) = client.get(format!("{base}/session")).send().await {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        let response = client
            .post(format!("{base}/login"))
            .header("origin", &origin)
            .header("x-identity-request", "1")
            .json(&serde_json::json!({"login":login,"password":password}))
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let cookie = response
            .headers()
            .get("set-cookie")
            .ok_or_else(|| anyhow::anyhow!("session cookie absent"))?
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let signed_in: serde_json::Value = response.json().await?;
        assert_eq!(signed_in["identity"]["principalId"], principal.to_string());
        assert!(!signed_in["csrfToken"].as_str().unwrap().is_empty());
        let response = client
            .get(format!("{base}/session"))
            .header("cookie", cookie)
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let session: serde_json::Value = response.json().await?;
        assert_eq!(session["identity"], signed_in["identity"]);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = stop.send(());
    let shutdown = tokio::time::timeout(Duration::from_secs(50), running).await???;
    result?;
    let _ = shutdown;
    assert!(
        tokio::net::TcpStream::connect(browser_address)
            .await
            .is_err()
    );
    assert!(
        tokio::net::TcpStream::connect(protocol_address)
            .await
            .is_err()
    );
    Ok(())
}
