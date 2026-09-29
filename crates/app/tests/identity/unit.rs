use super::*;
use axum::http::HeaderMap;
#[test]
fn private_provider_permission_is_explicit_and_tenant_bound() {
    let mut value = serde_json::json!({
        "group_facts_max_age_seconds":300,"state_key_file":"/private/state",
        "active_credential_key":"one","credential_keys":{},"return_targets":{},
        "assurance_profiles":[]
    });
    assert!(serde_json::from_value::<OidcConfig>(value.clone()).is_err());
    value["private_providers"] = serde_json::json!([]);
    let config: OidcConfig = serde_json::from_value(value.clone()).unwrap();
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    assert!(config.private_access(tenant).unwrap().is_empty());
    value["private_providers"] = serde_json::json!([{
        "tenant_id":tenant.to_string(),"issuer":"https://idp.example.test/realms/mdm",
        "client_id":"mdm","cidrs":["10.20.0.0/24"]
    }]);
    let config: OidcConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(config.private_access(tenant).unwrap().len(), 1);
    let other = TenantId::parse("33333333-3333-4333-8333-333333333333").unwrap();
    assert!(config.private_access(other).is_err());
    value["private_providers"][0]["cidrs"] = serde_json::json!(["127.0.0.0/8"]);
    let config: OidcConfig = serde_json::from_value(value).unwrap();
    assert!(config.transport(tenant).is_err());
}

#[tokio::test]
async fn forwarding_requires_the_actual_accepted_gateway() -> anyhow::Result<()> {
    use axum::{Extension, middleware, routing::get};
    for (gateway, expected) in [
        ("127.0.0.1", StatusCode::OK),
        ("127.0.0.2", StatusCode::FORBIDDEN),
    ] {
        let router = Router::new()
            .route(
                "/peer",
                get(
                    |Extension(peer): Extension<rss_identity_http_axum::ClientAddress>,
                     headers: HeaderMap| async move {
                        assert!(
                            !headers.contains_key("x-forwarded-for")
                                && !headers.contains_key("forwarded")
                                && !headers.contains_key("x-real-ip")
                        );
                        peer.0.to_string()
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                gateway.parse::<std::net::IpAddr>()?,
                ingress,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        owner
            .startup()?
            .stage_task_with_token(rss_axum::serve_http1_registration(
                listener,
                router,
                rss_axum::PlainTransport,
                "gateway-test",
                crate::lifecycle::http_policy(),
            ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()?;
        let url = format!("http://{address}/peer");
        let response = client
            .get(&url)
            .header("x-forwarded-for", "203.0.113.7")
            .header("forwarded", "for=forged")
            .header("x-real-ip", "forged")
            .send()
            .await?;
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            assert_eq!(response.text().await?, "203.0.113.7");
        }
        for forwarded in [None, Some("203.0.113.7, 203.0.113.8")] {
            let mut request = client.get(&url);
            if let Some(value) = forwarded {
                request = request.header("x-forwarded-for", value);
            }
            assert_eq!(request.send().await?.status(), StatusCode::FORBIDDEN);
        }
        drop(client);
        assert!(owner.shutdown().join().await?.is_clean());
    }
    Ok(())
}
