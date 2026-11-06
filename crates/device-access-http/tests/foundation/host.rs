//! Concrete standalone application: initialize its management account, serve TLS and drain.
use super::*;
use anyhow::Context as _;
use std::{os::unix::fs::PermissionsExt, path::Path};

pub(super) fn private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub struct InstalledHost {
    pub runtime_file: std::path::PathBuf,
    pub accounts: Vec<rss_da_app::maintenance::OriginalAccount>,
}
pub async fn verify(
    c: &Context,
    m: &material::Material,
    registration: &registration::agent::da::RegistrationService,
) -> Result<InstalledHost> {
    let management: Uuid =
        sqlx::query_scalar("SELECT management_tenant_id FROM rss_da.authorization_installation")
            .fetch_one(&c.operator)
            .await?;
    let browser = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let protocol = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let browser_address = browser.local_addr()?;
    let protocol_address = protocol.local_addr()?;
    let origin = format!("https://localhost:{}", browser_address.port());
    c.browser_origin
        .set(origin.clone())
        .expect("one host origin");
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
    let tenants = [management, Uuid::parse_str(&c.tenant.to_string())?];
    for tenant in tenants {
        rss_da_app::maintenance::account(
            rss_da_app::maintenance::Account {
                runtime_file: runtime_file.clone(),
                maintenance_database: serde_json::from_value(serde_json::to_value(
                    c.inputs.database("da_identity_maintenance"),
                )?)?,
                tenant,
                principal,
                login: login.clone(),
                password_file: password_file.clone(),
                operation_id: Uuid::new_v4(),
            },
            rss_da_app::maintenance::AccountOperation::Initialize,
        )
        .await
        .context("initialize standalone account and authorization")?;
    }
    let mut damaged = value.clone();
    damaged["browser"]["private_key_file"] = serde_json::json!(m.directory.join("device1.key"));
    assert!(
        rss_da_app::maintenance::diagnose(serde_json::from_value(damaged)?)
            .await
            .is_err()
    );
    rss_da_app::maintenance::diagnose(rss_da_app::config::load(&runtime_file)?)
        .await
        .context("diagnose initialized standalone host")?;
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
        transport::slow_body(m, &origin, c.tenant).await?;
        let response = client
            .post(format!(
                "{origin}/api/v1/identity/tenants/{}/login",
                c.tenant
            ))
            .header("origin", &origin)
            .header("x-identity-request", "1")
            .json(&serde_json::json!({"login":login,"password":password}))
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()?
            .split(';')
            .next()
            .unwrap();
        let response = client
            .get(format!("{origin}/api/v1/da/pki/da_device/trust"))
            .header("cookie", cookie)
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let observed: rss_mdm_agent_wire::pki::Trust = response.json().await?;
        assert_eq!(observed.purpose, rss_mdm_agent_wire::pki::Purpose::DaDevice);
        vault_user_http(c, &client, &origin).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(50), running).await???;
    result?;
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
    Ok(InstalledHost {
        runtime_file,
        accounts: tenants
            .into_iter()
            .map(|tenant| rss_da_app::maintenance::OriginalAccount {
                tenant,
                principal,
                login: login.clone(),
                password_file: password_file.clone(),
            })
            .collect(),
    })
}

async fn vault_user_http(c: &Context, client: &reqwest::Client, origin: &str) -> Result<()> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use rss_mdm_agent_wire::vault::*;
    let id = Uuid::new_v4();
    let login = format!("vault-http-{id}");
    let password = "vault-http-test-only-password";
    let kdf = rss_identity_core::account::PasswordKdf::new();
    let hash = kdf
        .hash(rss_identity_core::account::Password::new(password.into())?)
        .await?;
    kdf.close();
    kdf.wait_closed().await;
    let mut tx = c.seed().await?;
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO identity_authority.local_credentials(tenant_id,principal_id,login_key,password_hash) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(id).bind(&login).bind(hash.as_str()).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let grants:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.authorization_rules WHERE tenant_id=$1::uuid AND document::text LIKE $2").bind(c.tenant.to_string()).bind(format!("%{id}%")).fetch_one(&mut *tx).await?;
    assert_eq!(grants, 0);
    tx.commit().await?;
    let login_response = client
        .post(format!(
            "{origin}/api/v1/identity/tenants/{}/login",
            c.tenant
        ))
        .header("origin", origin)
        .header("x-identity-request", "1")
        .json(&serde_json::json!({"login":login,"password":password}))
        .send()
        .await?;
    assert_eq!(login_response.status(), reqwest::StatusCode::OK);
    let cookie = login_response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let login_value: serde_json::Value = login_response.json().await?;
    let csrf = login_value["csrfToken"].as_str().unwrap();
    let recovery = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let d = Device {
        id: Uuid::new_v4(),
        public_key: B64.encode(key.public_key().as_ref()),
    };
    let request = Prepare {
        operation: Uuid::new_v4(),
        device: d.id,
        action: Action::Initialize {
            vault: Uuid::new_v4(),
            recovery_key: B64.encode(recovery.public_key().as_ref()),
            root_envelope: B64.encode([3; 60]),
            device: d,
        },
    };
    let post = |path: &str| {
        client
            .post(format!("{origin}/api/v1/da/vault/{path}"))
            .header("origin", origin)
            .header("cookie", &cookie)
            .header("x-identity-request", "1")
            .header("x-csrf-token", csrf)
    };
    let response = post("challenges").json(&request).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let h: Challenge = response.json().await?;
    let payload = h.signing_bytes()?;
    let mut execute = Execute {
        challenge: h,
        signature: B64.encode(key.sign(&payload).as_ref()),
        recovery_signature: None,
    };
    assert_eq!(
        post("execute").json(&execute).send().await?.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    execute.recovery_signature = Some(B64.encode(recovery.sign(&payload).as_ref()));
    let response = post("execute").json(&execute).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(matches!(
        response.json::<Response>().await?,
        Response::Receipt { .. }
    ));
    Ok(())
}
