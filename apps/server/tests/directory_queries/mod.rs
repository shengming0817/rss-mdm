//! Real management routes and PostgreSQL owners. This proof does not exercise device effects.
mod certificates;
mod coverage;
mod diagnostics;
pub(super) mod history;
mod materials;
mod metadata;
mod owners;
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
        let items = page(&body)["items"].as_array().context("directory items")?;
        anyhow::ensure!(items.len() == 1, "{path} must match a real object: {body}");
        let row = items[0].clone();
        // Even a singleton owner must prove that a valid unmatched predicate reaches SQL.
        let key = if path == "/api/v1/device-views" {
            "reference.id"
        } else {
            [
                "id",
                "key",
                "configurationId",
                "entryId",
                "account",
                "serial",
                "fieldId",
                "principalId",
                "attempt",
                "operationId",
                "releaseId",
                "source",
                "version",
            ]
            .into_iter()
            .find(|key| row[*key].is_string())
            .context("public directory identity")?
        };
        let absent = match key {
            "account" => format!("{}@example.test", Uuid::new_v4()),
            "key" => format!("custom.directory_{}", Uuid::new_v4().simple()),
            _ => Uuid::new_v4().to_string(),
        };
        let (status, missing) = self
            .get(
                path,
                &[("filter", &format!("{key}=={absent}")), ("limit", "1")],
            )
            .await?;
        anyhow::ensure!(
            status == 200 && page(&missing)["items"] == json!([]),
            "{path} ignored an unmatched {key} predicate: {status}: {missing}"
        );
        Ok(row)
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
            P::SoftwareRead,
            P::ReleaseRead,
            P::AgentEnrollmentRead,
            P::UserAttributeDefinitionsRead,
            P::GroupRead,
            P::GroupWrite,
            P::InventoryRead,
            P::InventorySensitiveRead,
            P::PolicyRead,
            P::OperationRead,
            P::ComplianceRuleRead,
            P::CertificateArchiveRead,
            P::Credentials,
            P::WebhookRead,
            P::RegistrationConfigurationRead,
            P::RuntimeDiagnosticsRead,
            P::UserGroupRead,
            P::AuthorizationRead,
            P::AuthorizationWrite,
        ])
        .await?;
    let proof = c.authenticate(&manager).await?;
    let mut fixtures = seed::all(&c, &proof).await?;
    metadata::seed(&c, &proof, &mut fixtures.cases).await?;
    owners::seed(&c, &proof, &mut fixtures.cases).await?;
    let (pki, mut ca_server) = certificates::seed(&c, &proof, &mut fixtures.cases).await?;
    let recovery = materials::seed(&c, &mut fixtures.cases).await?;
    let history = history::seed(&c, &proof).await?;
    let ordinary = c.account(&[P::InventoryRead]).await?;
    let diagnostic_reader = c.account(&[P::RuntimeDiagnosticsRead]).await?;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = reservation.local_addr()?;
    let mut config = crate::host_t2_support::configuration(
        &c.inputs,
        "shared",
        c.tenant,
        address,
        Uuid::new_v4(),
    )?;
    config["agent_pki"] = pki["agent_pki"].clone();
    config["device_pki"] = pki["device_pki"].clone();
    config["recovery_credentials"] = recovery;
    let content = c
        .inputs
        .directory
        .join(format!("directory-content-{}", c.tenant));
    std::fs::create_dir(&content)?;
    config["content"] = json!({"storage":{"kind":"volume","directory":content},"imports":{},"max_artifact_bytes":1048576,"max_temporary_bytes":4194304,"max_uploads":2,"transfer_seconds":30,"retention_seconds":60,"max_bundle_entries":16,"max_expansion_ratio":10});
    let target = format!("directory-{}", c.tenant);
    config["publication"]["sources"] = json!([{"name":target,"credentials":{},"target":{"Winget":{"base":format!("https://mdm.example.test/api/v1/software/native/sources/{target}/"),"artifacts_base":format!("https://mdm.example.test/api/v1/software/native/sources/{target}/artifacts/")}}}]);
    let config = serde_json::from_value(config)?;
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
        let mut readiness = None;
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if server.is_finished() {
                    anyhow::bail!("App terminated before directory verification");
                }
                readiness=http.get("/readyz",&[]).await.ok();
                if readiness.as_ref().is_some_and(|(status,body)|*status==200 && body["ready"]==true)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await.with_context(|| format!("directory App readiness: {readiness:?}"))??;
        // Real HTTP contracts expose each owner and retain first-use permission boundaries.
        let (status, diagnostics) = http.get("/api/v1/runtime/diagnostics", &[]).await?;
        assert_eq!(status, 200, "{diagnostics}");
        let names = diagnostics["components"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), 21);
        for name in ["baseline", "policy", "group", "scope", "asset_query", "compliance", "device_associations", "device_control", "software_deployment", "script_execution", "collection_execution"] { assert!(names.contains(name), "{name}"); }
        assert!(!names.contains("automation") && !names.contains("execution_recovery"));
        assert_eq!(diagnostics["firstUse"]["access"], "available");
        assert!(diagnostics["firstUse"]["summary"].get("saved").is_none());
        let access::credential::RequestCredential::Cookie(secret) = diagnostic_reader.credential()? else { anyhow::bail!("cookie fixture") };
        let restricted = Http { client: http.client.clone(), address: http.address, cookie: format!("__Host-identity-session={}", secret.expose()), csrf: secret.csrf() };
        let (status, restricted_body) = restricted.get("/api/v1/runtime/diagnostics", &[]).await?;
        assert_eq!(status, 200, "{restricted_body}");
        assert_eq!(restricted_body["firstUse"]["access"], "forbidden");
        assert!(restricted_body["firstUse"].get("summary").is_none());
        diagnostics::exercise(&c, &manager, &diagnostic_reader, &restricted, &http).await?;
        // Reading the original configuration operation must work in its read-only snapshot.
        let operation: Uuid = sqlx::query_scalar("SELECT operation_id FROM mdm_access.agent_configurations WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(Uuid::from_u128(7000)).fetch_one(&c.operator).await?;
        let (status, receipt) = http.get(&format!("/api/v1/agent-configuration-operations/{operation}"), &[]).await?;
        assert_eq!(status, 200, "{receipt}");
        assert_eq!(receipt["configuration"]["configurationId"], Uuid::from_u128(7000).to_string());
        let (status, absent) = http.get(&format!("/api/v1/agent-configuration-operations/{}", Uuid::new_v4()), &[]).await?;
        assert_eq!(status, 200);
        assert!(absent.is_null());
        let mut failures = Vec::new();
        for (path, filter, expected) in &fixtures.cases {
            match http.selected(path, filter).await {
                Ok(item) if ["id","key","configurationId","source","entryId","account","serial","fieldId","version","principalId", "attempt", "operationId", "releaseId"].iter().any(|key|item[*key]==*expected) || item["reference"]["id"]==*expected => (),
                Ok(item) => failures.push(format!("{path}: wrong result {item}")),
                Err(error) => failures.push(error.to_string()),
            }
        }
        anyhow::ensure!(
            failures.is_empty(),
            "directory coverage:\n{}",
            failures.join("\n")
        );
        let access::credential::RequestCredential::Cookie(secret)=ordinary.credential()? else {anyhow::bail!("cookie fixture")};
        let ordinary_http=Http{client:http.client.clone(),address:http.address,cookie:format!("__Host-identity-session={}",secret.expose()),csrf:secret.csrf()};
        assert_eq!(ordinary_http.get("/api/v1/runtime/diagnostics", &[]).await?.0, 403);
        let (status,body)=ordinary_http.get("/api/v1/device-views",&[("filter","search=icontains=éclair")]).await?;
        assert_eq!(status,200,"{body}");
        assert_eq!(body["items"],json!([]));
        for (path, filter, expected) in &fixtures.cases {
            if path == "/api/v1/device-views" && !filter.contains("éclair") {
                assert_eq!(ordinary_http.selected(path,filter).await?["reference"]["id"],*expected);
            }
        }
        let (status,cross_target)=http.get("/api/v1/agent-configurations",&[("filter","createdBy==DirectoryTarget;platform==windows;architecture==aarch64")]).await?;
        assert_eq!(status,200,"{cross_target}");assert_eq!(cross_target["items"],json!([]));
        history::exercise(&c,&http,&ordinary_http,&history).await?;
        coverage::check(&fixtures.cases)?;
        let mut tx=crate::command_runtime_t2_support::seed_transaction(&c).await?;
        sqlx::query("UPDATE mdm_software_release.aggregates SET directory=jsonb_set(directory,'{outcome}','\"corrupt\"') WHERE tenant_id=$1::uuid AND id='retained-publication'").bind(c.tenant.to_string()).execute(&mut *tx).await?;tx.commit().await?;
        let (status,_)=http.get("/api/v1/software/publications",&[("filter","id==retained-publication")]).await?;
        assert!(status>=500,"a corrupt publication projection cannot be returned");
        let mut tx=crate::command_runtime_t2_support::seed_transaction(&c).await?;
        sqlx::query("UPDATE mdm_software_release.aggregates SET directory=jsonb_set(directory,'{outcome}','\"pending\"') WHERE tenant_id=$1::uuid AND id='retained-publication'").bind(c.tenant.to_string()).execute(&mut *tx).await?;tx.commit().await?;
        bounded_sort_pages(&http).await?;
        text_range_boundaries(&http).await?;
        for filter in ["presentation.name=icontains=σ", "presentation.name=icontains=ς", "presentation.name=icontains='.'", "presentation.name=icontains='[*]'", "id=icontains='/'"] {
            assert_eq!(http.selected("/api/v1/resources",filter).await?["id"],"scripts/install");
        }
        assert_eq!(http.selected("/api/v1/resources",r#"id==scripts/install;presentation.name=icontains='O\'Reilly'"#).await?["id"],"scripts/install");
        assert_eq!(http.selected("/api/v1/resources",r#"presentation.name=icontains='\\工具'"#).await?["id"],"z-directory-agent_collection");
        for filter in ["presentation.name=icontains='.*'", "presentation.name=icontains='(?q)'", "presentation.name=icontains='Σx'"] {
            let (status,body)=http.get("/api/v1/resources",&[("filter",filter)]).await?;
            assert_eq!(status,200,"{body}");
            assert_eq!(body["items"],json!([]));
        }
        assert_eq!(http.selected("/api/v1/resources","kind==script;id=gt=z-directory-configuration").await?["id"],"z-directory-script");
        assert_eq!(http.selected("/api/v1/certificate-archive/entries",&format!("id=gt={}",Uuid::from_u128(1001))).await?["id"],Uuid::from_u128(1002).to_string());
        // The target is outside the original page, yet query filtering is not confined to that page.
        let (status, raw) = http
            .get("/api/v1/resources", &[("sort", "id"), ("limit", "1")])
            .await?;
        assert_eq!(status, 200, "{raw}");
        assert_ne!(raw["items"][0]["id"], fixtures.resource);
        let filter = "presentation.category==Tools";
        let mut cursor = None;
        let mut seen = std::collections::BTreeSet::new();
        let mut ordered=Vec::new();
        for _ in 0..20 {
            let mut query = vec![
                ("filter", filter),
                ("sort", "activeVersion"),
                ("limit", "1"),
            ];
            if let Some(token) = cursor.as_deref() {
                query.push(("cursor", token));
            }
            let (status, body) = http.get("/api/v1/resources", &query).await?;
            assert_eq!(status, 200, "{body}");
            for row in body["items"].as_array().unwrap() {
                assert!(seen.insert(row["id"].as_str().unwrap().to_owned()));
                ordered.push(row["id"].as_str().unwrap().to_owned());
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
        assert_eq!(ordered, ["z-directory-software","z-directory-agent_collection","z-directory-configuration","z-directory-native_collection","z-directory-script","z-directory-telemetry_profile"]);
        let (_,mixed)=http.get("/api/v1/resources",&[("filter","(kind==software,kind==script);presentation.category==Tools")]).await?;
        assert_eq!(mixed["items"].as_array().unwrap().iter().map(|v|v["id"].as_str().unwrap()).collect::<Vec<_>>(),["z-directory-script","z-directory-software"]);
        let mut certificate_cursor=None;
        let mut certificates=Vec::new();
        loop {
            let mut query=vec![("sort","-latest.metadata.name"),("limit","1")];
            if let Some(cursor)=certificate_cursor.as_deref(){query.push(("cursor",cursor));}
            let (status,result)=http.get("/api/v1/certificate-archive/entries",&query).await?;
            assert_eq!(status,200,"{result}");
            certificates.extend(result["items"].as_array().unwrap().iter().map(|v|v["id"].as_str().unwrap().to_owned()));
            certificate_cursor=result["nextCursor"].as_str().map(str::to_owned);
            if certificate_cursor.is_none(){break;}
            assert!(certificates.len()<4);
        }
        assert_eq!(certificates,[Uuid::from_u128(1001).to_string(),Uuid::from_u128(1002).to_string(),Uuid::from_u128(1000).to_string()]);
        for filter in [
            "presentation.name=icontains='%'",
            "presentation.name=icontains='_'",
            "presentation.name=icontains='工具'",
        ] {
            assert_eq!(http.selected("/api/v1/resources",filter).await?["id"],"z-directory-agent_collection");
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
            ("/api/v1/resources", "activeVersion=gt=1"),
            ("/api/v1/policies", "definition.action.packages.linux_x86_64==00000000-0000-0000-0000-000000000001"),
        ] {
            assert_eq!(
                http.get(path, &[("filter", filter)]).await?.0,
                400,
                "{path}: {filter}"
            );
        }
        unicode_bidirectional(&c, &http).await?;
        seed::corrupt_resource(&c,true).await?;
        let (status,body)=http.get("/api/v1/resources",&[("filter","id=in=(a-directory-script,b-directory-script)"),("limit","1")]).await?;
        seed::corrupt_resource(&c,false).await?;
        assert!(status>=500,"corrupt lookahead accepted: {body}");
        assert!(body.get("nextCursor").is_none());
        seed::corrupt_saved(&c,true).await?;
        let (status,body)=http.get("/api/v1/saved-queries",&[("filter",&format!("id=={}",Uuid::from_u128(1000)))]).await?;
        seed::corrupt_saved(&c,false).await?;
        assert!(status>=500,"mismatched AST/text accepted: {body}");
        let saved = Uuid::from_u128(1002);
        let path = format!("/api/v1/saved-queries/{saved}");
        let write = |revision,filter:&str| json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":{"action":"put","definition":{"name":"updated directory","query":{"filter":filter,"fields":["device.name"]}}}});
        let (status,body)=http.put(&path,write(1,"device.name=='updated'")).await?;
        assert_eq!(status,200,"{body}");
        seed::saved_projection(&c,saved,Some("device.name==updated"),2).await?;
        assert_eq!(http.put(&path,write(1,"device.name==stale")).await?.0,409);
        seed::saved_projection(&c,saved,Some("device.name==updated"),2).await?;
        let (status,body)=http.put(&path,json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"input":{"action":"delete"}})).await?;
        assert_eq!(status,200,"{body}");
        seed::saved_projection(&c,saved,None,3).await?;
        let (_,nulls)=http.get("/api/v1/resources", &[("filter","activeVersion=isnull=true"),("limit","100")]).await?;
        assert_eq!(nulls["items"].as_array().unwrap().len(),20);
        assert!(nulls["items"].as_array().unwrap().iter().all(|v|v["activeVersion"].is_null()));
        assert!(nulls["items"].as_array().unwrap().iter().any(|v|v["id"]=="a-directory-script"));
        assert_eq!(http.get("/api/v1/resources",&[("sort","presentation.description")]).await?.0,400);
        assert_eq!(http.get("/api/v1/api-keys",&[("filter","createdBy.principalId==bogus")]).await?.0,400);
        let (_,exact)=http.get("/api/v1/resources", &[("filter","presentation.name=='Zulu éclair %_ O\\'Reilly\\\\工具'")]).await?;
        assert_eq!(exact["items"],json!([]));
        let (status,body)=http.get("/api/v1/policies",&[("filter","definition.action.packages.windows_x86_64==00000000-0000-0000-0000-000000000001")]).await?;
        assert_eq!(status,200,"{body}");
        assert_eq!(body["items"],json!([]));
        seed::collection_semantics(&c).await?;
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
    ca_server.start_kill()?;
    ca_server.wait().await?;
    c.close().await;
    exercise.with_context(|| format!("App completion: {cleanup:?}"))?;
    cleanup
}

async fn bounded_sort_pages(http: &Http) -> Result<()> {
    for path in [
        "/api/v1/saved-queries",
        "/api/v1/compliance-rules",
        "/api/v1/authorization/user-groups",
        "/api/v1/api-keys",
    ] {
        for (sort, expected) in [("name", [1000, 1001, 1002]), ("-name", [1002, 1000, 1001])] {
            let mut cursor = None;
            let mut ids = Vec::new();
            loop {
                let mut query = vec![("sort", sort), ("limit", "1")];
                if let Some(token) = cursor.as_deref() {
                    query.push(("cursor", token));
                }
                let (status, body) = http.get(path, &query).await?;
                assert_eq!(status, 200, "{path}: {body}");
                ids.extend(
                    page(&body)["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v["id"].as_str().unwrap().to_owned()),
                );
                cursor = page(&body)["nextCursor"].as_str().map(str::to_owned);
                if cursor.is_none() {
                    break;
                }
                assert!(ids.len() < 4, "nonterminating {path} sort {sort}");
            }
            assert_eq!(
                ids,
                expected.map(|id| Uuid::from_u128(id).to_string()),
                "{path}: {sort}"
            );
        }
    }
    for sort in ["toolName", "alias", "customEvent", "resource", "category"] {
        let (status, body) = http
            .get("/api/v1/policies", &[("sort", sort), ("limit", "1")])
            .await?;
        assert_eq!(status, 200, "{body}");
        let token = body["nextCursor"]
            .as_str()
            .context("Policy sorting must page")?;
        let (status, next) = http
            .get(
                "/api/v1/policies",
                &[("sort", sort), ("limit", "1"), ("cursor", token)],
            )
            .await?;
        assert_eq!(status, 200, "{next}");
        assert_ne!(body["items"][0]["id"], next["items"][0]["id"]);
    }
    Ok(())
}

async fn text_range_boundaries(http: &Http) -> Result<()> {
    let (status, all) = http.get("/api/v1/policies", &[("sort", "id")]).await?;
    assert_eq!(status, 200, "{all}");
    for boundary in [
        "policy_".to_owned(),
        "policy_7".to_owned(),
        format!("policy_{}", "f".repeat(40)),
    ] {
        let (status, result) = http
            .get(
                "/api/v1/policies",
                &[
                    ("filter", &format!("toolName=gt={boundary}")),
                    ("sort", "id"),
                ],
            )
            .await?;
        assert_eq!(status, 200, "{result}");
        let expected = all["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["toolName"].as_str().unwrap() > boundary.as_str())
            .map(|r| r["id"].clone())
            .collect::<Vec<_>>();
        let actual = result["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].clone())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "boundary {boundary}");
    }
    Ok(())
}
async fn unicode_bidirectional(c: &Context, http: &Http) -> Result<()> {
    let classes: &[&[&str]] = &[
        &["Σ", "σ", "ς"],
        &["I", "i", "İ", "ı"],
        &["ß", "ẞ"],
        &["É", "é"],
        &["K", "k", "K"],
        &["Μ", "μ", "µ"],
        &["S", "s", "ſ"],
    ];
    let mut revision = 2;
    for class in classes {
        for stored in *class {
            seed::literal_name(c, stored, revision).await?;
            revision += 1;
            for needle in *class {
                assert_eq!(
                    http.selected(
                        "/api/v1/resources",
                        &format!("id==scripts/install;presentation.name=icontains={needle}")
                    )
                    .await?["id"],
                    "scripts/install",
                    "stored {stored}, needle {needle}"
                );
            }
        }
    }
    seed::literal_name(c, "ß", revision).await?;
    let (status, body) = http
        .get(
            "/api/v1/resources",
            &[(
                "filter",
                "id==scripts/install;presentation.name=icontains=ss",
            )],
        )
        .await?;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["items"], json!([]));
    seed::literal_name(c, "Σ.[*] O'Reilly", revision + 1).await?;
    Ok(())
}
