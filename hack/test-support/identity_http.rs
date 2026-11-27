//! Run against each actual Browser listener after host admission is ready.
pub async fn anonymous_session(client: &reqwest::Client, tenant_url: &str) -> anyhow::Result<()> {
    let url = format!("{tenant_url}/session");
    for credentials in [None, Some("Bearer invalid")] {
        let mut request = client.get(&url);
        if let Some(value) = credentials {
            request = request.header("authorization", value);
        }
        let response = request.send().await?;
        let (status, code) = if credentials.is_some() {
            (400, "malformed_request")
        } else {
            (401, "invalid_credential")
        };
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(
            response.json::<serde_json::Value>().await?,
            serde_json::json!({"code":code})
        );
    }
    Ok(())
}

pub fn surface(document: &serde_json::Value, raw_profile: bool) {
    let endpoints: Vec<_> = document["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["path"]
                .as_str()
                .is_some_and(|p| p.starts_with("/api/v1/identity/"))
        })
        .collect();
    assert_eq!(endpoints.len(), 38 + usize::from(raw_profile));
    assert_eq!(
        endpoints
            .iter()
            .filter(|e| e["path"] == "/api/v1/identity/tenants/{tenant}/profile")
            .count(),
        usize::from(raw_profile)
    );
    assert!(document.get("externalOwners").is_none());
    assert!(endpoints.iter().all(|e| e["listener"] == "browser"));
    let conditional = endpoints
        .iter()
        .filter(|e| e["conditions"].as_array().is_some_and(|c| !c.is_empty()))
        .count();
    assert_eq!(conditional, 11);
}

/// Exercise the same browser exchange through each host's production middleware.
pub async fn session_lifecycle(
    client: &reqwest::Client,
    base: &str,
    origin: &str,
    login: &str,
    password: &str,
) -> anyhow::Result<()> {
    async fn issued(response: reqwest::Response) -> anyhow::Result<(String, serde_json::Value)> {
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let header = response.headers()["set-cookie"].to_str()?;
        for attribute in [
            "__Host-identity-session=",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Path=/",
        ] {
            assert!(header.contains(attribute));
        }
        let credential = header.split(';').next().unwrap().to_owned();
        let body: serde_json::Value = response.json().await?;
        assert!(body["csrfToken"].as_str().is_some_and(|v| !v.is_empty()));
        assert!(body["session"]["absoluteExpiresAt"].is_i64());
        Ok((credential, body))
    }
    let signed_in = client
        .post(format!("{base}/login"))
        .header("origin", origin)
        .header("x-identity-request", "1")
        .json(&serde_json::json!({"login":login,"password":password}))
        .send()
        .await?;
    let (cookie, body) = issued(signed_in).await?;
    let request = |method: &str, cookie: &str, csrf: &str| {
        client
            .post(format!("{base}/session/{method}"))
            .header("origin", origin)
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
    };
    let inspected: serde_json::Value = client
        .get(format!("{base}/session"))
        .header("cookie", &cookie)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(inspected, body);
    assert_eq!(
        request("refresh", &cookie, "invalid")
            .send()
            .await?
            .status(),
        403
    );
    let (rotated, fresh) = issued(
        request("refresh", &cookie, body["csrfToken"].as_str().unwrap())
            .send()
            .await?,
    )
    .await?;
    assert_ne!(rotated, cookie);
    assert_eq!(fresh["identity"], body["identity"]);
    assert_eq!(
        fresh["session"]["absoluteExpiresAt"],
        body["session"]["absoluteExpiresAt"]
    );
    let logout = request("logout", &rotated, fresh["csrfToken"].as_str().unwrap())
        .send()
        .await?;
    assert_eq!(logout.status(), 204);
    assert!(
        logout.headers()["set-cookie"]
            .to_str()?
            .contains("Max-Age=0")
    );
    assert_eq!(
        client
            .get(format!("{base}/session"))
            .header("cookie", rotated)
            .send()
            .await?
            .status(),
        401
    );
    Ok(())
}

pub fn federation_config(
    directory: &std::path::Path,
    origin: &str,
    hex_keys: bool,
) -> anyhow::Result<serde_json::Value> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let key = |label: &str, byte: u8| -> anyhow::Result<std::path::PathBuf> {
        let path = directory.join(format!("oidc-{label}-{}", uuid::Uuid::new_v4()));
        let bytes = if hex_keys {
            format!("{byte:02x}").repeat(32).into_bytes()
        } else {
            vec![byte; 32]
        };
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?
            .write_all(&bytes)?;
        Ok(path)
    };
    Ok(
        serde_json::json!({"group_facts_max_age_seconds":300,"assurance_profiles":[],"private_providers":[],
        "state_key_file":key("state",61)?,"active_credential_key":"test","credential_keys":{"test":key("credential",62)?},
        "return_targets":{"security":format!("{origin}/identity-security")}}),
    )
}

pub async fn federation_surface(
    client: &reqwest::Client,
    base: &str,
    tenant: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let callback = format!("{base}/api/v1/identity/oidc/callback");
    let options = client
        .get(format!(
            "{base}/api/v1/identity/tenants/{tenant}/login-options"
        ))
        .send()
        .await?;
    assert_eq!(options.status().as_u16(), if enabled { 200 } else { 404 });
    if enabled {
        assert_eq!(
            options.json::<serde_json::Value>().await?,
            serde_json::json!({"providers":[]})
        );
    }
    assert_eq!(
        client.head(&callback).send().await?.status().as_u16(),
        if enabled { 405 } else { 404 }
    );
    let response = client.get(&callback).send().await?;
    if enabled {
        if response.status() == 303 {
            assert_eq!(response.headers()["location"], "/auth/error?reason=failed");
        } else {
            assert_eq!(response.url().path(), "/auth/error");
            assert_eq!(response.url().query(), Some("reason=failed"));
        }
    } else {
        assert_eq!(response.status(), 404);
    }
    Ok(())
}
