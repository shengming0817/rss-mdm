//! Host scope rejects before authentication; the final Router must still honor wire contracts.
use crate::{authority_t2_support::*, host_t2_support as host};
use anyhow::Result;
use uuid::Uuid;

#[tokio::test]
#[ignore = "T2: final App projects malformed, missing, deleted and failed tenant lookups with real PostgreSQL roles"]
async fn scope_failures_are_typed_on_product_and_identity_routes() -> Result<()> {
    let c = Context::open("http_scope", &[]).await?;
    let management = crate::identity::management_tenant(
        &c.inputs.database("http_scope", "mdm_identity_runtime"),
        rss_identity_core::InstanceId::parse(&c.inputs.installation.instance_id)?,
    )
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
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
    let result = {
        let c = &c;
        host::run(configuration, |client, base| async move {
            let contract = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
            for (tenant, status, code) in [
                ("malformed".to_owned(), 400, "malformed_request"),
                (Uuid::new_v4().to_string(), 403, "permission_denied"),
                (deleted.to_string(), 403, "permission_denied"),
            ] {
                for path in [
                    format!("/api/v1/tenants/{tenant}/device-views"),
                    format!("/api/v1/identity/tenants/{tenant}/login-options"),
                ] {
                    let body = host::reject(
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
            let sdk = format!("{base}/api/v1/identity/tenants/{}/login-options", c.tenant);
            assert_eq!(client.get(&sdk).send().await?.status(), 200);
            // Dedicated profile: revoke only the actual scope reader, then restore the same privilege.
            sqlx::query("REVOKE SELECT ON public.mdm_tenants FROM mdm_identity_runtime")
                .execute(&c.operator)
                .await?;
            let failed = async {
                host::reject(
                    client.get(&product).send().await?,
                    503,
                    "service_unavailable",
                )
                .await?;
                host::reject(client.get(&sdk).send().await?, 503, "identity_unavailable").await?;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            sqlx::query("GRANT SELECT ON public.mdm_tenants TO mdm_identity_runtime")
                .execute(&c.operator)
                .await?;
            failed?;
            assert_eq!(client.get(&sdk).send().await?.status(), 200);
            Ok(())
        })
        .await
    };
    c.close().await;
    result
}
