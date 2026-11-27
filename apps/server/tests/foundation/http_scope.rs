//! Host scope rejects before authentication; the final Router must still honor wire contracts.
use crate::{authority_t2_support::*, host_t2_support as host};
use anyhow::Result;
use uuid::Uuid;

#[derive(Clone, Default)]
struct Diagnostics(
    std::sync::Arc<std::sync::Mutex<Vec<serde_json::Map<String, serde_json::Value>>>>,
);
#[derive(Default)]
struct Fields(serde_json::Map<String, serde_json::Value>);
impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Diagnostics {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "rss_mdm_app::http_scope" {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }
}
async fn rejected(
    diagnostics: &Diagnostics,
    response: reqwest::Response,
    status: u16,
    code: &str,
) -> Result<serde_json::Value> {
    let request_id = response.headers()["x-request-id"].to_str()?.to_owned();
    let body = host::reject(response, status, code).await?;
    let events = diagnostics.0.lock().unwrap();
    let event = events
        .iter()
        .find(|e| e["request_id"] == request_id)
        .expect("scope response must correlate to its server diagnostic");
    assert_eq!(event["event"], "mdm_request");
    assert_eq!(event["stage"], "execution_scope");
    assert_eq!(event["status"], status);
    assert_eq!(
        event["failure"],
        match status {
            400 => "malformed_scope",
            403 => "scope_denied",
            _ => "scope_unavailable",
        }
    );
    assert_eq!(
        event.len(),
        5,
        "closed diagnostics cannot include caller paths or provider details"
    );
    Ok(body)
}

#[tokio::test]
#[ignore = "T2: final App projects malformed, missing, deleted and failed tenant lookups with real PostgreSQL roles"]
async fn scope_failures_are_typed_on_product_and_identity_routes() -> Result<()> {
    use tracing_subscriber::prelude::*;
    let diagnostics = Diagnostics::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(diagnostics.clone()),
    )?;
    let c = Context::open("http_scope", &[]).await?;
    let management = crate::identity::management_tenant(
        &c.inputs.database("http_scope", "mdm_identity_runtime"),
        rss_identity_core::InstanceId::parse(&c.inputs.installation.instance_id)?,
    )
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.tenants(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(management.to_string())
    .execute(&c.operator)
    .await?;
    let deleted = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    seed_tenant(&c.operator, deleted).await?;
    sqlx::query("UPDATE public.mdm_tenants SET deleted=true WHERE tenant_id=$1::uuid")
        .bind(deleted.to_string())
        .execute(&c.operator)
        .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let configuration = host::configuration(
        &c.inputs,
        "http_scope",
        listener.local_addr()?,
        Uuid::new_v4(),
    )
    .await?;
    drop(listener);
    let mut federated = configuration.clone();
    federated["identity"]["oidc"] =
        identity_http::federation_config(&c.inputs.directory, "https://mdm.example.test", true)?;
    let business_tenant = c.tenant.to_string();
    host::run(federated, |client, base| async move {
        identity_http::federation_surface(&client, &base, &business_tenant, true).await?;
        assert_eq!(
            client
                .get(format!(
                    "{base}/api/v1/identity/tenants/{management}/login-options"
                ))
                .send()
                .await?
                .status(),
            403
        );
        Ok(())
    })
    .await?;
    let result = {
        let c = &c;
        host::run(configuration, |client, base| async move {
            let contract = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
            identity_http::surface(&contract, false);
            identity_http::federation_surface(&client, &base, &c.tenant.to_string(), false).await?;
            identity_http::anonymous_session(
                &client,
                &format!("{base}/api/v1/identity/tenants/{}", c.tenant),
            )
            .await?;
            let account = c.account(&[]).await?;
            identity_http::session_lifecycle(
                &client,
                &format!("{base}/api/v1/identity/tenants/{}", c.tenant),
                "https://mdm.example.test",
                &format!("foundation-{}", account.user.principal_id),
                "foundation-only-valid-password",
            )
            .await?;
            assert_eq!(
                client
                    .get(format!(
                        "{base}/api/v1/identity/tenants/{}/profile",
                        c.tenant
                    ))
                    .send()
                    .await?
                    .status(),
                404
            );
            for (tenant, status, code) in [
                ("malformed".to_owned(), 400, "malformed_request"),
                (Uuid::new_v4().to_string(), 403, "permission_denied"),
                (deleted.to_string(), 403, "permission_denied"),
            ] {
                for path in [
                    format!("/api/v1/tenants/{tenant}/device-views"),
                    format!("/api/v1/identity/tenants/{tenant}/session"),
                ] {
                    let body = rejected(
                        &diagnostics,
                        client.get(format!("{base}{path}")).send().await?,
                        status,
                        code,
                    )
                    .await?;
                    if path.starts_with("/api/v1/tenants/") {
                        let endpoint = contract["endpoints"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|e| {
                                e["method"] == "GET"
                                    && e["path"] == "/api/v1/tenants/{tenant}/device-views"
                            })
                            .unwrap();
                        assert!(
                            endpoint["responses"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|r| r["status"] == status)
                                .any(|r| {
                                    let id = r["body"]["schema"]["schemaId"].as_str().unwrap();
                                    jsonschema::validator_for(&contract["schemas"][id])
                                        .unwrap()
                                        .is_valid(&body)
                                })
                        );
                    }
                }
            }
            // A live tenant proceeds to authentication; this rules out unconditional scope rejection.
            let product = format!("{base}/api/v1/tenants/{}/device-views", c.tenant);
            assert_eq!(client.get(&product).send().await?.status(), 401);
            let sdk = format!("{base}/api/v1/identity/tenants/{}/session", c.tenant);
            host::reject(client.get(&sdk).send().await?, 401, "invalid_credential").await?;
            // Dedicated profile: revoke only the actual scope reader, then restore the same privilege.
            sqlx::query("REVOKE SELECT ON public.mdm_tenants FROM mdm_identity_runtime")
                .execute(&c.operator)
                .await?;
            let failed = async {
                rejected(
                    &diagnostics,
                    client.get(&product).send().await?,
                    503,
                    "service_unavailable",
                )
                .await?;
                rejected(
                    &diagnostics,
                    client.get(&sdk).send().await?,
                    503,
                    "identity_unavailable",
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            sqlx::query("GRANT SELECT ON public.mdm_tenants TO mdm_identity_runtime")
                .execute(&c.operator)
                .await?;
            failed?;
            host::reject(client.get(&sdk).send().await?, 401, "invalid_credential").await?;
            Ok(())
        })
        .await
    };
    c.close().await;
    result
}

#[path = "../../../../hack/test-support/identity_http.rs"]
mod identity_http;
