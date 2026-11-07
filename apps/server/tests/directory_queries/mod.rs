//! Real management routes and PostgreSQL owners. This proof does not exercise device effects.
mod seed;
use crate::authority_t2_support::Context;
use anyhow::{Context as _, Result};
use rss_mdm_authorization_service::{self as access, Permission as P};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

struct Http {
    client: reqwest::Client,
    address: std::net::SocketAddr,
    cookie: String,
    csrf: String,
}
impl Http {
    async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<(u16, Value)> {
        let response = self
            .client
            .get(format!("http://{}{path}", self.address))
            .query(query)
            .header("host", "mdm.example.test")
            .header("x-rss-public-origin", "https://mdm.example.test")
            .header("x-forwarded-for", "127.0.0.1")
            .header("cookie", &self.cookie)
            .send()
            .await?;
        let status = response.status().as_u16();
        let text = response.text().await?;
        Ok((
            status,
            serde_json::from_str(&text)
                .with_context(|| format!("{path}: {status}, non-JSON response"))?,
        ))
    }
    async fn put(&self, path: &str, body: Value) -> Result<(u16, Value)> {
        let response = self
            .client
            .put(format!("http://{}{path}", self.address))
            .header("host", "mdm.example.test")
            .header("x-rss-public-origin", "https://mdm.example.test")
            .header("x-forwarded-for", "127.0.0.1")
            .header("cookie", &self.cookie)
            .header("origin", "https://mdm.example.test")
            .header("x-identity-request", "1")
            .header("x-csrf-token", &self.csrf)
            .json(&body)
            .send()
            .await?;
        let status = response.status().as_u16();
        Ok((status, response.json().await?))
    }
    async fn selected(&self, path: &str, filter: &str) -> Result<Value> {
        let (status, body) = self
            .get(path, &[("filter", filter), ("limit", "1")])
            .await?;
        anyhow::ensure!(status == 200, "{path}: {status}: {body}");
        let page = page(&body);
        let items = page["items"].as_array().context("directory items")?;
        anyhow::ensure!(items.len() == 1, "{path} must match a real object: {body}");
        Ok(items[0].clone())
    }
}
// Saved queries use their existing AssetEnvelope; other management collections expose Page directly.
fn page(body: &Value) -> &Value {
    body.get("asset").unwrap_or(body)
}

#[tokio::test]
#[ignore = "T2: directory field models execute through real management HTTP and tenant-scoped PostgreSQL before paging"]
#[allow(
    clippy::disallowed_methods,
    reason = "real App lifecycle and loopback HTTP fixture"
)]
async fn public_business_fields_reach_objects_beyond_the_first_page() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let manager = c
        .account(&[
            P::ResourceRead,
            P::GroupRead,
            P::GroupWrite,
            P::InventoryRead,
            P::InventorySensitiveRead,
            P::PolicyRead,
            P::ScopeRead,
            P::ComplianceRuleRead,
            P::CertificateArchiveRead,
            P::WebhookRead,
            P::RegistrationConfigurationRead,
            P::UserGroupRead,
            P::AuthorizationRead,
        ])
        .await?;
    let proof = c.authenticate(&manager).await?;
    let fixtures = seed::all(&c, &proof).await?;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = reservation.local_addr()?;
    let config = serde_json::from_value(crate::host_t2_support::configuration(
        &c.inputs,
        "shared",
        c.tenant,
        address,
        Uuid::new_v4(),
    )?)?;
    let access::credential::RequestCredential::Cookie(cookie) = manager.credential()? else {
        anyhow::bail!("cookie fixture required")
    };
    let http = Http {
        client: reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()?,
        address,
        cookie: format!("__Host-identity-session={}", cookie.expose()),
        csrf: cookie.csrf(),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    drop(reservation);
    let mut server = tokio::spawn(crate::serve(
        config,
        async move {
            stopped
                .await
                .map_err(|_| std::io::Error::other("test stop closed"))
        },
        Arc::new(crate::Monotonic(std::time::Instant::now)),
    ));
    let exercise = async {
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if server.is_finished() {
                    anyhow::bail!("App terminated before directory verification");
                }
                if http
                    .client
                    .get(format!("http://{address}/readyz"))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        let mut failures = Vec::new();
        for (path, filter, expected) in &fixtures.cases {
            match http.selected(path, filter).await {
                Ok(item) if item["id"] == *expected || item["key"] == *expected => (),
                Ok(item) => failures.push(format!("{path}: wrong result {item}")),
                Err(error) => failures.push(error.to_string()),
            }
        }
        anyhow::ensure!(
            failures.is_empty(),
            "directory coverage:\n{}",
            failures.join("\n")
        );
        // The target is outside the original page, yet query filtering is not confined to that page.
        let (status, raw) = http
            .get("/api/v1/resources", &[("sort", "id"), ("limit", "1")])
            .await?;
        assert_eq!(status, 200, "{raw}");
        assert_ne!(raw["items"][0]["id"], fixtures.resource);
        let filter = "presentation.category==Tools";
        let mut cursor = None;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..20 {
            let mut query = vec![
                ("filter", filter),
                ("sort", "presentation.name"),
                ("limit", "1"),
            ];
            if let Some(token) = cursor.as_deref() {
                query.push(("cursor", token));
            }
            let (status, body) = http.get("/api/v1/resources", &query).await?;
            assert_eq!(status, 200, "{body}");
            for row in body["items"].as_array().unwrap() {
                assert!(seen.insert(row["id"].as_str().unwrap().to_owned()));
            }
            let next = body["nextCursor"].as_str().map(str::to_owned);
            if let Some(token) = &next {
                assert_eq!(
                    http.get(
                        "/api/v1/resources",
                        &[("filter", "active==true"), ("cursor", token)]
                    )
                    .await?
                    .0,
                    409
                );
                assert_eq!(
                    http.get(
                        "/api/v1/resources",
                        &[("filter", filter), ("sort", "-id"), ("cursor", token)]
                    )
                    .await?
                    .0,
                    409
                );
            }
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        assert_eq!(seen.len(), 6);
        for filter in [
            "presentation.name=icontains='%'",
            "presentation.name=icontains='_'",
            "presentation.name=icontains='工具'",
        ] {
            assert!(
                http.selected("/api/v1/resources", filter)
                    .await?
                    .is_object()
            );
        }
        for (path, filter) in [
            ("/api/v1/resources", "presentation.unknown==x"),
            ("/api/v1/webhooks/subscriptions", "settings.secret==x"),
            ("/api/v1/api-keys", "secretDigest==x"),
            (
                "/api/v1/certificate-archive/entries",
                "latest.facts.certificates.subject==x",
            ),
            ("/api/v1/resources", "revision==wrong"),
        ] {
            assert_eq!(
                http.get(path, &[("filter", filter)]).await?.0,
                400,
                "{path}: {filter}"
            );
        }
        seed::projection_atomicity(&c, &proof).await?;
        let saved = Uuid::from_u128(1002);
        let path = format!("/api/v1/saved-queries/{saved}");
        let write = |revision,filter:&str| json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":{"action":"put","definition":{"name":"updated directory","query":{"filter":filter,"fields":["device.name"]}}}});
        let (status,body)=http.put(&path,write(1,"device.name == updated")).await?;
        assert_eq!(status,200,"{body}");
        seed::saved_projection(&c,saved,Some("device.name==updated"),2).await?;
        assert_eq!(http.put(&path,write(1,"device.name==stale")).await?.0,409);
        seed::saved_projection(&c,saved,Some("device.name==updated"),2).await?;
        let (status,body)=http.put(&path,json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"input":{"action":"delete"}})).await?;
        assert_eq!(status,200,"{body}");
        seed::saved_projection(&c,saved,None,3).await?;
        let (_,nulls)=http.get("/api/v1/resources", &[("filter","activeVersion=isnull=true"),("limit","100")]).await?;
        assert!(nulls["items"].as_array().unwrap().iter().all(|v|v["activeVersion"].is_null()));
        let (_,exact)=http.get("/api/v1/resources", &[("filter","presentation.name=='Zulu éclair %_ O\\'Reilly\\\\工具'")]).await?;
        assert_eq!(exact["items"],json!([]));
        seed::execution_plans(&c).await?;
        assert_eq!(http.selected("/api/v1/resources", "kind==software;presentation.name=icontains=éclair").await?["id"], fixtures.resource);
        let (_, first) = http.get("/api/v1/resources", &[("filter","presentation.category==Tools"),("limit","1")]).await?;
        let token = first["nextCursor"].as_str().context("authority cursor")?;
        let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
        sqlx::query("UPDATE mdm_access.authorization_rules SET revision=revision+1 WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3")
            .bind(c.tenant.to_string()).bind(proof.instance_id()).bind(manager.rule).execute(&mut *tx).await?;
        tx.commit().await?;
        assert_eq!(http.get("/api/v1/resources", &[("filter","presentation.category==Tools"),("cursor",token)]).await?.0,409);

        Ok::<_, anyhow::Error>(())
    }
    .await;
    let _ = stop.send(());
    let stopped = tokio::time::timeout(Duration::from_secs(40), &mut server).await;
    if stopped.is_err() {
        server.abort();
        let _ = server.await;
    }
    let cleanup = match stopped {
        Ok(result) => result.context("App task join")?.context("App stop"),
        Err(_) => Err(anyhow::anyhow!("App stop timed out")),
    };
    c.close().await;
    exercise?;
    cleanup
}
