use super::*;
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
    assert!(
        rss_mdm_device_access_runtime::oidc::private_access(&config.private_providers)
            .unwrap()
            .is_empty()
    );
    value["private_providers"] = serde_json::json!([{
        "tenant_id":tenant.to_string(),"issuer":"https://idp.example.test/realms/mdm",
        "client_id":"mdm","cidrs":["10.20.0.0/24"]
    }]);
    let config: OidcConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        rss_mdm_device_access_runtime::oidc::private_access(&config.private_providers)
            .unwrap()
            .len(),
        1
    );
    value["private_providers"][0]["cidrs"] = serde_json::json!(["127.0.0.0/8"]);
    let config: OidcConfig = serde_json::from_value(value).unwrap();
    assert!(
        config
            .transport(
                policy::RuntimePolicy::installation()
                    .transport
                    .build()
                    .unwrap()
            )
            .is_err()
    );
}

#[test]
fn configured_authentication_claim_covers_every_password_operation() {
    let mut policy = policy::RuntimePolicy::installation();
    policy.request_seconds = 45;
    policy.maintenance_seconds = 60;
    policy.jwks.max_tenants = std::num::NonZeroUsize::new(1024).unwrap();
    assert!(
        policy
            .compile(
                InstanceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                rss_audit_postgres::Integrity::Plain
            )
            .is_ok()
    );
    policy.authentication.claim_seconds = 59;
    assert!(
        policy
            .compile(
                InstanceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                rss_audit_postgres::Integrity::Plain
            )
            .is_err()
    );
    policy.authentication.claim_seconds = 60;
    policy.password.reserved_memory_bytes = std::num::NonZeroU64::new(
        rss_identity_core::account::PasswordPolicy::MEMORY_BYTES
            * policy.password.concurrency.get() as u64,
    )
    .unwrap();
    assert!(
        policy
            .compile(
                InstanceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                rss_audit_postgres::Integrity::Plain
            )
            .is_err()
    );
}

#[tokio::test]
async fn host_kdf_drain_waits_for_password_work_after_request_drop() {
    use rss_runtime::ManagedResource;
    use std::{future::Future, task::Poll};
    let policy = policy::RuntimePolicy::installation();
    let kdf = Arc::new(policy.password.build().unwrap());
    let mut work = Box::pin(kdf.hash(
        rss_identity_core::account::Password::new("host-drain-capacity-proof".into()).unwrap(),
    ));
    std::future::poll_fn(|cx| match work.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("real password job completed before the request-drop seam"),
    })
    .await;
    drop(work);
    let resource = KdfResource {
        kdf: kdf.clone(),
        timeout: Duration::from_secs(5),
    };
    tokio::time::timeout(resource.shutdown_timeout(), resource.shutdown())
        .await
        .unwrap()
        .unwrap();
    // The host cannot finish its drain while the retained blocking task still owns resources.
    std::future::poll_fn(|cx| {
        let mut closed = Box::pin(kdf.wait_closed());
        assert!(closed.as_mut().poll(cx).is_ready());
        Poll::Ready(())
    })
    .await;
    assert!(
        kdf.hash(rss_identity_core::account::Password::new("closed-password-work".into()).unwrap())
            .await
            .is_err()
    );
}
