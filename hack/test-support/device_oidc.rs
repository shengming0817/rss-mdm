//! Real browser ceremony shared by the standalone and embedded DA production-host tests.
use anyhow::{Context, Result, ensure};
use reqwest::{Client, Response};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};
use uuid::Uuid;

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../hack/test-support/identity_keycloak.py"
);

pub struct Keycloak {
    directory: PathBuf,
    info: Value,
    origin: String,
    provider: std::sync::OnceLock<Uuid>,
    _process: Child,
}
impl Keycloak {
    pub async fn start(parent: &Path, origin: &str) -> Result<Self> {
        let directory = parent.join(format!("oidc-{}", Uuid::new_v4()));
        let mut process = Command::new("python3")
            .arg(SCRIPT)
            .arg("serve")
            .arg(&directory)
            .arg(format!("{origin}/api/v1/identity/oidc/callback"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut lines =
            BufReader::new(process.stdout.take().context("Keycloak readiness")?).lines();
        let ready = tokio::time::timeout(Duration::from_secs(180), lines.next_line())
            .await??
            .context("Keycloak did not start")?;
        Ok(Self {
            directory,
            info: serde_json::from_str(&ready)?,
            origin: origin.into(),
            provider: Default::default(),
            _process: process,
        })
    }
    pub fn configure(&self, config: &mut Value, tenant: &str) {
        let endpoint = json!({"issuer":self.info["issuer"],"client_id":"host","tenant_id":tenant});
        let mut trusted = endpoint.clone();
        trusted["keycloak_totp"] = true.into();
        let mut access = endpoint;
        access["cidrs"] = json!([self.info["cidr"]]);
        config["assurance_profiles"] = json!([trusted]);
        config["private_providers"] = json!([access]);
    }
    pub async fn install(
        &self,
        client: &Client,
        base: &str,
        tenant: &str,
        cookie: &str,
        csrf: &str,
    ) -> Result<()> {
        let providers = format!("{base}/api/v1/identity/tenants/{tenant}/providers");
        let post = |url: &str| {
            client
                .post(url)
                .header("cookie", cookie)
                .header("origin", &self.origin)
                .header("x-identity-request", "1")
                .header("x-csrf-token", csrf)
        };
        let settings = json!({"issuer":self.info["issuer"],"clientId":"host",
            "redirectUri":format!("{}/api/v1/identity/oidc/callback",self.origin),"scopes":["openid"],
            "claims":{"subject":{"kind":"oidc"},"profile":{"maxAgeSeconds":14400}},"jit":false});
        let created: Value = post(&providers)
            .json(
                &json!({"settings":settings,"clientSecret":self.info["clientSecret"],
            "caPem":std::fs::read_to_string(self.directory.join("tls.crt"))?}),
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let id = Uuid::parse_str(created["id"].as_str().context("created provider")?)?;
        post(&format!("{providers}/{id}/enabled"))
            .json(&json!({"expectedVersion":created["version"],"enabled":true}))
            .send()
            .await?
            .error_for_status()?;
        self.provider
            .set(id)
            .map_err(|_| anyhow::anyhow!("provider already installed"))
    }
    pub async fn link_employee(
        &self,
        pool: &sqlx::PgPool,
        tenant: &str,
        person: Uuid,
    ) -> Result<()> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO identity_authority.external_identities(tenant_id,identity_id,principal_id,provider_id,issuer,subject) VALUES($1::uuid,$2,$3,$4,$5,$6)")
            .bind(tenant).bind(Uuid::new_v4()).bind(person).bind(self.provider.get().context("configured IdP")?)
            .bind(self.info["issuer"].as_str().context("issuer")?).bind(format!("oidc:{}",self.info["subject"].as_str().context("Keycloak subject")?))
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn expire_grant(
        &self,
        pool: &sqlx::PgPool,
        tenant: &str,
        principal: Uuid,
    ) -> Result<()> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let count=sqlx::query("UPDATE identity_authority.step_up_grants SET authenticated_at=1,expires_at=2 WHERE tenant_id=$1::uuid AND principal_id=$2 AND source->>'method'='oidc' AND source->>'provider'=$3").bind(tenant).bind(principal).bind(self.provider.get().context("configured provider")?.to_string()).execute(&mut *tx).await?.rows_affected();
        ensure!(count == 1, "expected one active OIDC grant");
        tx.commit().await?;
        Ok(())
    }
    pub async fn grant(
        &self,
        client: &Client,
        base: &str,
        resource: &str,
        session: &str,
        csrf: &str,
        input: &Value,
    ) -> Result<String> {
        let provider = self.provider.get().context("configured IdP")?;
        let reply = client
            .post(format!("{resource}/step-up/oidc/{provider}"))
            .header("cookie", session)
            .header("origin", &self.origin)
            .header("x-identity-request", "1")
            .header("x-csrf-token", csrf)
            .json(&json!({"returnTarget":"security","change":input}))
            .send()
            .await?
            .error_for_status()?;
        ensure!(
            reply.headers()["referrer-policy"] == "no-referrer",
            "authorization response privacy"
        );
        let browser = cookie(&reply, "__Host-identity-oidc-browser=")?;
        let data: Value = reply.json().await?;
        let url = data["authorizationUrl"]
            .as_str()
            .context("missing authorization URL")?;
        let mut login = Command::new("python3")
            .arg(SCRIPT)
            .arg("authorize")
            .arg(&self.directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        login
            .stdin
            .take()
            .context("Keycloak form input")?
            .write_all(url.as_bytes())
            .await?;
        let result =
            tokio::time::timeout(Duration::from_secs(70), login.wait_with_output()).await??;
        ensure!(
            result.status.success(),
            "Keycloak password/TOTP login failed"
        );
        let callback = reqwest::Url::parse(std::str::from_utf8(&result.stdout)?.trim())?;
        let url = format!(
            "{base}{}?{}",
            callback.path(),
            callback.query().context("callback query")?
        );
        let wrong_browser = client
            .get(&url)
            .header(
                "cookie",
                format!("{session}; __Host-identity-oidc-browser={}", "x".repeat(43)),
            )
            .send()
            .await
            .map_err(|e| e.without_url())?;
        ensure!(
            wrong_browser.status() == 303
                && wrong_browser.headers()["location"] == "/auth/error?reason=failed"
                && !wrong_browser.headers().contains_key("set-cookie"),
            "a different browser received a callback grant"
        );
        let response = client
            .get(url)
            .header("cookie", format!("{session}; {browser}"))
            .send()
            .await
            .map_err(|e| e.without_url())?;
        ensure!(
            response.status() == 303,
            "callback status {}",
            response.status()
        );
        ensure!(
            response.headers()["location"] == format!("{}/identity-security", self.origin),
            "callback did not resume original target"
        );
        cookie(&response, "__Host-identity-operation=")
    }
}
fn cookie(response: &Response, prefix: &str) -> Result<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok()?.split(';').next())
        .find(|v| v.starts_with(prefix))
        .map(str::to_owned)
        .context("expected browser cookie absent")
}
