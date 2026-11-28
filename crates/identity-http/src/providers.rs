use crate::transport::*;
use crate::{ACTION, Declaration, IDENTITY, Route, Router, get, post, put, route_module};
// Optional OIDC management adapter.
use crate::{
    AppState,
    accounts::{Error, body},
    boundary::*,
    dto,
};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_identity_core::federation::*;
use rss_identity_postgres::{AuthorityError, Federation};
use serde::Deserialize;
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone)]
struct Management {
    federation: Federation,
}
pub fn routes(runtime: Option<(&Federation, &AppState)>) -> Router<(), impl Declaration + use<>> {
    route_module! { struct Providers for [Browser] { providers, create_provider, update_provider, provider_enabled, test_provider } }
    let routes = Providers {
        providers: Route::new(
            "/api/v1/identity/tenants/{tenant}/providers",
            get(providers, &IDENTITY, ACTION),
        ),
        create_provider: Route::new(
            "/api/v1/identity/tenants/{tenant}/providers",
            post(create_provider, &IDENTITY, ACTION),
        ),
        update_provider: Route::new(
            "/api/v1/identity/tenants/{tenant}/providers/{provider}",
            put(update_provider, &IDENTITY, ACTION),
        ),
        provider_enabled: Route::new(
            "/api/v1/identity/tenants/{tenant}/providers/{provider}/enabled",
            post(provider_enabled, &IDENTITY, ACTION),
        ),
        test_provider: Route::new(
            "/api/v1/identity/tenants/{tenant}/providers/{provider}/test",
            post(test_provider, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    crate::browser(routes, runtime.map(|(_, s)| s), 32768).bind_with(runtime.as_ref(), |(f, _)| {
        Management {
            federation: (*f).clone(),
        }
    })
}

async fn providers(
    State(s): State<Management>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
    Headers(h): Headers<PASSIVE>,
) -> Result<Json<dto::Providers>> {
    let actor =
        crate::accounts::management_actor(&s.federation.authority(), binding, &h, b, false).await?;
    Ok(Json(dto::Providers {
        providers: s
            .federation
            .list_providers(actor, b)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    }))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateProvider {
    settings: dto::ProviderSettings,
    client_secret: String,
    ca_pem: Option<String>,
}
async fn create_provider(
    State(s): State<Management>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<CreateProvider, WRITE>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<201, Json<dto::Provider>>> {
    let actor =
        crate::accounts::management_actor(&s.federation.authority(), binding, r.headers(), b, true)
            .await?;
    let v: CreateProvider = body(r, b).await?;
    let credentials =
        ProviderCredentials::new(v.client_secret, v.ca_pem).map_err(AuthorityError::from)?;
    let settings = v.settings.into_domain().map_err(AuthorityError::from)?;
    Ok(rss_mdm_http_contract::signature::WithStatus(Json(
        dto::Provider::from(
            s.federation
                .create_provider(actor, settings, credentials, b)
                .await?,
        ),
    )))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateProvider {
    expected_version: i64,
    settings: dto::ProviderSettings,
    client_secret: String,
    ca_pem: Option<String>,
}
async fn update_provider(
    State(s): State<Management>,
    Path((_t, crate::boundary::Provider(p))): Path<(String, crate::boundary::Provider)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<UpdateProvider, WRITE>,
) -> Result<Json<dto::Provider>> {
    let actor =
        crate::accounts::management_actor(&s.federation.authority(), binding, r.headers(), b, true)
            .await?;
    let v: UpdateProvider = body(r, b).await?;
    let credentials =
        ProviderCredentials::new(v.client_secret, v.ca_pem).map_err(AuthorityError::from)?;
    let settings = v.settings.into_domain().map_err(AuthorityError::from)?;
    Ok(Json(dto::Provider::from(
        s.federation
            .update_provider(actor, p, v.expected_version, settings, credentials, b)
            .await?,
    )))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderToggle {
    expected_version: i64,
    enabled: bool,
}
async fn provider_enabled(
    State(s): State<Management>,
    Path((_t, crate::boundary::Provider(p))): Path<(String, crate::boundary::Provider)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<ProviderToggle, WRITE>,
) -> Result<Json<dto::Provider>> {
    let actor =
        crate::accounts::management_actor(&s.federation.authority(), binding, r.headers(), b, true)
            .await?;
    let v: ProviderToggle = body(r, b).await?;
    Ok(Json(dto::Provider::from(
        s.federation
            .enable_provider(actor, p, v.expected_version, v.enabled, b)
            .await?,
    )))
}
async fn test_provider(
    State(s): State<Management>,
    Path((_t, crate::boundary::Provider(p))): Path<(String, crate::boundary::Provider)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Headers(h): Headers<WRITE>,
) -> Result<Json<TestReport>> {
    let actor =
        crate::accounts::management_actor(&s.federation.authority(), binding, &h, b, true).await?;
    match s.federation.test_provider(actor, p, b).await {
        Ok(report) => Ok(Json(TestReport::Passed {
            passed: true,
            report: dto::ConnectionReport::from(report),
        })),
        Err(AuthorityError::Federation(FederationError::Provider(failure))) => {
            Ok(Json(TestReport::Failed {
                passed: false,
                diagnostic: dto::ProviderDiagnostic::from(failure),
            }))
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(untagged)]
enum TestReport {
    Passed {
        passed: bool,
        report: dto::ConnectionReport,
    },
    Failed {
        passed: bool,
        diagnostic: dto::ProviderDiagnostic,
    },
}
