//! Configuration reaches the actual Identity owner, including live quota changes and HTTP feedback.
use crate::authority_t2_support::{Account, Context};
use anyhow::Result;
use rss_identity_postgres::{AuthenticatedSession, Authority, AuthorityError};
use rss_mdm_authorization_service::{Permission, credential::RequestCredential};
use std::{num::NonZeroU32, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

async fn actor(
    c: &Context,
    authority: &Authority,
    account: &Account,
) -> Result<AuthenticatedSession> {
    let RequestCredential::Cookie(secret) = account.credential()? else {
        anyhow::bail!("fixture account requires a real session")
    };
    Ok(authority
        .inspect_session(
            c.execution(),
            secret,
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?)
}

#[tokio::test]
#[ignore = "T2: nondefault production authentication policy controls real PG admission and HTTP Retry-After"]
async fn configured_source_window_reaches_http_admission() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c.account(&[Permission::InventoryRead]).await?;
    let mut policy = crate::identity::policy::RuntimePolicy::installation();
    policy.authentication.source.limit = 2;
    policy.authentication.source.seconds = 90;
    let authority = c.authority_with_policy(&policy).await?;
    let origin = url::Url::parse("https://mdm.example.test")?;
    let webauthn = rss_identity_postgres::WebauthnAuthority::new(
        authority.clone(),
        "mdm.example.test".into(),
        origin,
    )?;
    let state = rss_mdm_identity_http::AppState {
        wall_time: rss_mdm_audit_integration::budget::RuntimeTimer::wall_time,
        authority,
        config: rss_identity_web_credentials::HttpConfig::new(
            "https://mdm.example.test",
            Duration::from_secs(10),
        )?,
    };
    let router = rss_mdm_identity_http::local_routes(Some((&state, &webauthn)))
        .into_checked_axum(rss_mdm_http_contract::module::Listener::Browser)
        .layer(axum::Extension(c.execution()))
        .layer(axum::Extension(rss_identity_postgres::RpGeneration::new(
            1,
        )?));
    let send = |ip: &str| {
        let router = router.clone();
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/v1/identity/tenants/{}/login", c.tenant))
            .header("host", "mdm.example.test")
            .header("origin", "https://mdm.example.test")
            .header("x-identity-request", "1")
            .header("content-type", "application/json")
            .extension(rss_mdm_identity_http::ClientAddress(ip.parse().unwrap()))
            .body(axum::body::Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "login":format!("foundation-{}", account.user.principal_id),
                    "password":"foundation-only-valid-password"
                }))
                .unwrap(),
            ))
            .unwrap();
        async move { router.oneshot(request).await }
    };
    for _ in 0..2 {
        let response = send("192.0.2.17").await?;
        assert_eq!(response.status(), 200);
        assert!(
            response
                .headers()
                .get_all("set-cookie")
                .iter()
                .any(|v| v.to_str().unwrap().starts_with("__Host-identity-session="))
        );
    }
    let response = send("192.0.2.17").await?;
    assert_eq!(response.status(), 429);
    let retry: u32 = response.headers()["retry-after"].to_str()?.parse()?;
    assert!((1..=90).contains(&retry));
    assert!(
        matches!(response.extensions().get::<rss_mdm_identity_http::HttpFailure>(),
        Some(rss_mdm_identity_http::HttpFailure::Authority(AuthorityError::RateLimited { retry_after_seconds })) if retry_after_seconds.get() == retry)
    );
    let body = axum::body::to_bytes(response.into_body(), 65536).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body)?["code"],
        "rate_limited"
    );
    assert_eq!(send("192.0.2.18").await?.status(), 200);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: 1024 profile members and array entries persist completely; lowering receipt quota preserves original replay"]
async fn complete_profile_and_existing_receipts_survive_quota_adjustment() -> Result<()> {
    use rss_identity_core::{
        PrincipalId,
        account::AccountKey,
        profile::{Extensions, LocalProfile},
    };
    use rss_identity_postgres::ProfileChange;
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            Permission::IdentityAccountsManage,
            Permission::UserAttributeDefinitionsWrite,
        ])
        .await?;
    let target = AccountKey {
        tenant: c.tenant,
        principal: PrincipalId::parse(&account.user.principal_id)?,
    };
    let mut policy = crate::identity::policy::RuntimePolicy::installation();
    policy.profile.receipt_capacity = NonZeroU32::new(2).unwrap();
    let authority = c.authority_with_policy(&policy).await?;
    let mut properties = (0..1023)
        .map(|i| (format!("f{i:04}"), serde_json::json!(i)))
        .collect::<serde_json::Map<_, _>>();
    properties.insert(
        "items".into(),
        serde_json::json!((0..1024).collect::<Vec<_>>()),
    );
    let value = serde_json::Value::Object(properties);
    assert!(serde_json::to_vec(&value)?.len() < 65536);
    let local = LocalProfile {
        display_name: None,
        username: None,
        email: None,
        extensions: Extensions::try_from(value.clone())?,
        max_age_seconds: 60,
    };
    let first = ProfileChange {
        operation_id: rss_identity_postgres::ProfileOperationId::now(),
        expected_revision: 0,
        value: Some(local.clone()),
    };
    let receipt = authority
        .update_local_profile(
            actor(&c, &authority, &account).await?,
            target,
            first.clone(),
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?;
    assert_eq!(receipt.revision, 1);
    let restored = authority
        .read_local_profile(
            &actor(&c, &authority, &account).await?,
            target,
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?;
    assert_eq!(restored.revision, 1);
    let restored = restored.value.unwrap().extensions.into_value();
    assert_eq!(restored, value);
    assert_eq!(restored.as_object().unwrap().len(), 1024);
    assert_eq!(restored["items"].as_array().unwrap().len(), 1024);
    complete_product_mapping(&c, &authority, &account, &value).await?;
    let second = ProfileChange {
        operation_id: rss_identity_postgres::ProfileOperationId::now(),
        expected_revision: 1,
        value: Some(LocalProfile {
            display_name: Some("second".into()),
            ..local.clone()
        }),
    };
    assert_eq!(
        authority
            .update_local_profile(
                actor(&c, &authority, &account).await?,
                target,
                second,
                crate::authority_t2_support::identity_cutoff()
            )
            .await?
            .revision,
        2
    );
    policy.profile.receipt_capacity = NonZeroU32::new(1).unwrap();
    let limited = c.authority_with_policy(&policy).await?;
    let replay = limited
        .update_local_profile(
            actor(&c, &limited, &account).await?,
            target,
            first.clone(),
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?;
    assert_eq!(
        (replay.operation_id, replay.revision),
        (receipt.operation_id, receipt.revision)
    );
    let recovered = limited
        .local_profile_receipt(
            &actor(&c, &limited, &account).await?,
            target,
            first.operation_id,
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?
        .unwrap();
    assert_eq!(
        (recovered.operation_id, recovered.revision),
        (receipt.operation_id, receipt.revision)
    );
    let third = ProfileChange {
        operation_id: rss_identity_postgres::ProfileOperationId::now(),
        expected_revision: 2,
        value: Some(local),
    };
    assert!(matches!(
        limited
            .update_local_profile(
                actor(&c, &limited, &account).await?,
                target,
                third.clone(),
                crate::authority_t2_support::identity_cutoff()
            )
            .await,
        Err(AuthorityError::ProfileReceiptCapacityReached)
    ));
    assert!(
        limited
            .local_profile_receipt(
                &actor(&c, &limited, &account).await?,
                target,
                third.operation_id,
                crate::authority_t2_support::identity_cutoff()
            )
            .await?
            .is_none()
    );
    let restored = limited
        .read_local_profile(
            &actor(&c, &limited, &account).await?,
            target,
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?;
    assert_eq!(restored.revision, 2);
    assert_eq!(
        restored.value.unwrap().display_name.as_deref(),
        Some("second")
    );
    c.close().await;
    Ok(())
}

// Consume the persisted Identity observation through the real product definition and projection owners.
async fn complete_product_mapping(
    c: &Context,
    authority: &Authority,
    account: &Account,
    value: &serde_json::Value,
) -> Result<()> {
    use crate::administration::user_profiles::{Backend, model::*};
    use rss_identity_core::{
        InstanceId,
        account::{LoginKey, Password},
        session::SessionSecret,
    };
    let issued = Box::pin(authority.login_local(
        c.execution(),
        LoginKey::parse(&format!("foundation-{}", account.user.principal_id))?,
        Password::new("foundation-only-valid-password".into())?,
        rss_identity_postgres::AttemptSource::parse("profile-capacity")?,
        None,
        crate::authority_t2_support::identity_cutoff(),
    ))
    .await?;
    let principal =
        rss_mdm_authorization_service::session::SessionAuthority::new(authority.clone())
            .authenticate(
                c.execution(),
                &c.access(),
                RequestCredential::Cookie(SessionSecret::parse(
                    issued.secret().expose().to_owned(),
                )?),
                crate::authority_t2_support::identity_cutoff(),
            )
            .await?;
    let backend = Backend {
        source_page_size: 1024,
        cursor: rss_mdm_query::cursor::CursorCodec::new(&[39; 32])?,
        identity: authority.clone(),

        instance: InstanceId::parse(&c.inputs.installation.instance_id)?,
        audit: c.audit.clone(),
    };
    for (name, pointer, value_type) in [
        ("array", "/extensions/items", ValueType::Array),
        ("object", "/extensions", ValueType::Object),
    ] {
        for max_items in [None, Some(1024)] {
            let audit = c.request(&principal)?;
            backend
                .change(
                    &principal,
                    &audit,
                    Uuid::new_v4(),
                    &Change {
                        operation_id: Uuid::new_v4(),
                        expected_revision: 0,
                        value: Some(DefinitionValue {
                            key: format!("{name}_{}", max_items.unwrap_or(0)),
                            display_name: name.into(),
                            source: ProfileSource::IdentityLocal,
                            pointer: pointer.into(),
                            value_type,
                            max_length: None,
                            max_items,
                            minimum: None,
                            maximum: None,
                            enabled: true,
                            sensitive: false,
                            visibility: Visibility::Both,
                            display_use: DisplayUse::Profile,
                            required: true,
                            use_existing_observation: true,
                        }),
                    },
                )
                .await?;
        }
    }
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));
    let profile = backend
        .profile(
            &principal,
            &c.request(&principal)?,
            None,
            ProfileQuery {
                view: View::Current,
                preview: false,
            },
            budget.deadline(),
        )
        .await?;
    assert_eq!(profile.fields.len(), 4);
    assert_eq!(profile.completeness.complete, 4);
    for field in profile.fields {
        assert_eq!(field.status, FieldStatus::Available);
        let expected = if field.value_type == ValueType::Array {
            &value["items"]
        } else {
            value
        };
        assert_eq!(field.value.as_ref(), Some(expected));
    }
    Ok(())
}
