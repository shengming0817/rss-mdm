//! One protected path: current SDK proof -> MDM capability -> private data access.
use crate::authorization::context::RequestAuth;
use crate::{ConfigIssue, Database, Failure};
use crate::{
    Error, assets::collection::CollectionService,
    authorization::identity_management::IdentityManagementPolicy, device::coordinates::Coordinates,
    enrollment::credentials::Credentials, identity::Identity,
};
use crate::{authorization::context::AuthorizedPrincipal, clock::Clock};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_identity_core::session::SessionSecret;
use rss_mdm_audit_integration::{FailureReason, RequestAudit, WriteOutcome};
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use std::{sync::Arc, time::Duration};
pub(crate) struct Assembly {
    pub(crate) content_writer: Option<Arc<crate::content::Store>>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: Arc<crate::execution::ExecutionService>,
    pub(crate) flow: Arc<crate::flow::Flow>,
    pub(crate) identity: Arc<Identity>,
    pub(crate) credentials: Arc<Credentials>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) identity_management: Arc<IdentityManagementPolicy>,
    pub(crate) collection: Arc<CollectionService>,
    pub(crate) readiness: Arc<crate::inventory_runtime::Readiness>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) apple: Option<Arc<crate::apple::Apple>>,
    pub(crate) windows: Option<Arc<crate::windows::Windows>>,
    pub(crate) access: Arc<Database>,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
impl Assembly {
    pub(crate) fn apple(&self) -> Result<&Arc<crate::apple::Apple>, Error> {
        self.apple.as_ref().ok_or(Error::Unsupported)
    }
    pub(crate) fn windows(&self) -> Result<&Arc<crate::windows::Windows>, Error> {
        self.windows.as_ref().ok_or(Error::Unsupported)
    }
}

#[cfg(test)]
pub(crate) async fn application_fixture(
    config: crate::config::Config,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    access: Arc<Database>,
    identity: Option<Identity>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
) -> Result<
    (
        Router,
        Arc<crate::execution::ExecutionService>,
        Arc<rss_transactional_messaging_postgres::PgRuntime>,
    ),
    Error,
> {
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access.clone(),
        rss_request_context::TenantId::parse(&config.identity.tenant_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?,
        monotonic.clone(),
    )
    .await?;
    let planning = config
        .flow
        .open(
            audit_store.clone(),
            rss_request_context::TenantId::parse(&config.identity.tenant_id)
                .map_err(|_| Error::Malformed)?,
            clock.clone(),
            |_| {},
        )
        .await?;
    let execution = crate::flow::execution::open(&config, audit_store.clone()).await?;
    let compiled = config.compile()?;
    let identity = match identity {
        Some(identity) => identity,
        None => {
            Identity::connect(
                &compiled.config,
                compiled.identity_management.clone(),
                |_| {},
            )
            .await?
        }
    };
    let plan_runtime = planning.runtime.clone();
    Ok((
        from_compiled(
            compiled,
            AssemblyDependencies {
                audit_store,
                execution: execution.clone(),
                clock,
                monotonic,
                access,
                runtime,
                flow: planning,
                identity,
            },
        )?
        .browser,
        execution,
        plan_runtime,
    ))
}
pub(crate) struct AssemblyDependencies {
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: Arc<crate::execution::ExecutionService>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) monotonic: Arc<dyn rss_observation::Clock>,
    pub(crate) access: Arc<Database>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) flow: Arc<crate::flow::Flow>,
    pub(crate) identity: Identity,
}
pub(crate) fn from_compiled(
    compiled: crate::config::Compiled,
    dependencies: AssemblyDependencies,
) -> Result<crate::native::Routers, Error> {
    let crate::config::Compiled {
        config,
        identity_management,
    } = compiled;
    let AssemblyDependencies {
        audit_store,
        execution,
        clock,
        monotonic,
        access,
        runtime,
        flow: planning,
        identity,
    } = dependencies;
    let devices = Arc::new(crate::device::DeviceService::new(
        access.clone(),
        config.identity.tenant_id.clone(),
        audit_store.clone(),
    ));
    let host = config
        .product_origin
        .strip_prefix("https://")
        .ok_or(Error::Configuration(ConfigIssue::ProductOrigin))?
        .to_owned();
    let windows = config
        .native_protocols
        .windows
        .map(|config| crate::windows::Windows::load(config, clock.unix_seconds()?).map(Arc::new))
        .transpose()?;
    let apple = config
        .native_protocols
        .apple
        .map(|config| crate::apple::Apple::load(config, clock.unix_seconds()?).map(Arc::new))
        .transpose()?;
    let content_writer = execution.content.clone();
    let state = Arc::new(Assembly {
        content_writer,
        audit_store,
        apple,
        execution,
        flow: planning,
        windows,
        access: access.clone(),
        identity: Arc::new(identity),
        credentials: Arc::new(Credentials::new(monotonic.clone(), 10000)),
        clock,
        identity_management,
        collection: Arc::new(CollectionService::new(
            devices.clone(),
            access.clone(),
            runtime.clone(),
        )),
        readiness: runtime.readiness.clone(),
        devices,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    Ok(from_state(state, host, monotonic))
}

pub(crate) fn from_state(
    state: Arc<Assembly>,
    host: String,
    monotonic: Arc<dyn rss_observation::Clock>,
) -> crate::native::Routers {
    let agent = Arc::new(crate::agent::HttpState {
        audit_store: state.audit_store.clone(),
        access: state.access.clone(),
        identity: state.identity.clone(),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        collection: state.collection.clone(),
    });
    let plans = Arc::new(crate::flow::actions::ActionWorkflow {
        writer: rss_transactional_messaging_postgres::PgOutboxWriter::new(
            state.flow.runtime.clone(),
            crate::execution::messaging_domain(),
        ),
        runtime: state.flow.runtime.clone(),
        tenant: state.execution.tenant,
        audit: state.audit_store.clone(),
        plans: crate::planning::actions::ActionPlans {
            audit_store: state.audit_store.clone(),
            content: state.execution.content.clone(),
        },
        execution: state.execution.clone(),
    });
    let execution = Arc::new(crate::execution::http::HttpState {
        execution: state.execution.clone(),
        devices: state.devices.clone(),
        apple: state.apple.is_some(),
        windows: state.windows.is_some(),
    });
    let planning = Arc::new(crate::planning::http::HttpState {
        planning: state.flow.planning.clone(),
    });
    let assets = Arc::new(crate::assets::http::HttpState {
        assets: state.flow.assets.clone(),
    });
    let authorization = Arc::new(crate::authorization::http::HttpState {
        audit_store: state.audit_store.clone(),
    });
    let apple_state = Arc::new(crate::apple::HttpState {
        audit_store: state.audit_store.clone(),
        access: state.access.clone(),
        apple: state.apple.clone(),
        clock: state.clock.clone(),
        execution: state.execution.clone(),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        identity: state.identity.clone(),
        requests: state.requests.clone(),
    });
    let windows_state = Arc::new(crate::windows::HttpState {
        audit_store: state.audit_store.clone(),
        access: state.access.clone(),
        clock: state.clock.clone(),
        execution: state.execution.clone(),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        identity: state.identity.clone(),
        requests: state.requests.clone(),
        windows: state.windows.clone(),
    });
    let collection = Arc::new(crate::collection::apple::HttpState {
        audit_store: state.audit_store.clone(),
        apple: state.apple.is_some(),
        tenant: state.identity.tenant,
    });
    let authentication_state = Arc::new(crate::authorization::http::AuthenticationState {
        identity: state.identity.clone(),
        access: state.access.clone(),
        requests: state.requests.clone(),
    });
    let identity_context_state = Arc::new(IdentityContextState {
        identity_management: state.identity_management.clone(),
    });
    let enrollment = Arc::new(crate::enrollment::http::HttpState {
        service: Arc::new(crate::enrollment::EnrollmentService::new(
            state.access.clone(),
            state.credentials.clone(),
            state.audit_store.clone(),
        )),
        devices: state.devices.clone(),
        apple: state.apple.is_some(),
        windows: state.windows.is_some(),
    });
    let collection_read = Arc::new(CollectionState {
        collection: state.collection.clone(),
    });
    let readiness = Arc::new(ReadinessState {
        readiness: state.readiness.clone(),
        apple: state.apple.clone(),
        clock: state.clock.clone(),
        flow: state.flow.clone(),
    });
    let authentication = state.identity.routes();
    let audit_tenant = state.identity.tenant.to_string();
    let audit_store = state.audit_store.clone();
    let requests = state.requests.clone();
    let protected_v1 = Router::new()
        .merge(
            crate::software_publication::http::routes().with_state(Arc::new(
                crate::software_publication::http::HttpState {
                    publications: state.flow.publications.clone(),
                    access: state.access.clone(),
                },
            )),
        )
        .merge(crate::authorization::routes().with_state(authorization))
        .route(
            "/devices/{id}/collection-runs",
            post(crate::collection::apple::create).with_state(collection),
        )
        .route(
            "/devices/{id}/collection-runs/{run}",
            get(collection_run).with_state(collection_read),
        )
        .route("/devices/{id}/actions", post(action))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    let protected_v2 = Router::new()
        .merge(crate::execution::routes().with_state(execution.clone()))
        .merge(crate::planning::routes_v2().with_state(planning.clone()))
        .merge(crate::assets::routes().with_state(assets))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    let protected_v3 = crate::resource_catalog::http::routes()
        .with_state(Arc::new(crate::resource_catalog::http::HttpState {
            catalog: state.flow.catalog.clone(),
        }))
        .merge(crate::execution::actions::http::routes().with_state(execution.clone()))
        .merge(
            crate::flow::actions_http::routes()
                .with_state(Arc::new(crate::flow::actions_http::HttpState { plans })),
        )
        .merge(crate::software_catalog::routes().with_state(Arc::new(
            crate::software_catalog::HttpState {
                runtime: state.flow.runtime.clone(),
                audit: state.audit_store.clone(),
                tenant: state.execution.tenant,
                catalog: rss_mdm_software_service::catalog::Catalog::new(
                    state.flow.runtime.clone(),
                    state.execution.tenant,
                    Arc::new(crate::software_publication::host::Audit(
                        state.audit_store.clone(),
                    )),
                ),
                content: state.content_writer.clone(),
            },
        )))
        .merge(crate::content::http::routes().with_state(Arc::new(
            crate::content::http::HttpState {
                runtime: state.flow.runtime.clone(),
                audit_store: state.audit_store.clone(),
                tenant: state.execution.tenant,
                content: state.content_writer.clone(),
                clock: state.clock.clone(),
            },
        )))
        .merge(crate::enrollment::http::routes().with_state(enrollment))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    let mut listeners = Vec::new();
    if let Some((enrollment, planning)) = crate::windows::routers(windows_state, monotonic.clone())
    {
        listeners.push((
            crate::native::NativeListenerKind::WindowsEnrollment,
            enrollment,
        ));
        listeners.push((
            crate::native::NativeListenerKind::WindowsManagement,
            planning,
        ));
    }
    if let Some(apple) = crate::apple::router(apple_state.clone(), monotonic.clone()) {
        listeners.push((crate::native::NativeListenerKind::AppleManagement, apple));
    }
    let host_context = Router::new()
        .route(
            "/api/identity-host/v1/tenants/{tenant}/context",
            get(identity_context).with_state(identity_context_state),
        )
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::identity_only,
        ));
    let apple = state.apple.clone();
    let browser = Router::new()
        .merge(host_context)
        .merge(crate::apple::browser_routes().with_state(apple_state))
        .nest(
            "/api/agent/v2",
            crate::agent::routes()
                .with_state(agent)
                .merge(crate::execution::actions::http::agent_routes().with_state(execution)),
        )
        .nest("/api/v1", protected_v1)
        .nest("/api/v2", protected_v2)
        .nest("/api/v3", protected_v3)
        .route("/livez", get(|| async { Json(json!({"alive":true})) }))
        .route("/readyz", get(ready).with_state(readiness))
        .merge(authentication)
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn_with_state(
            Envelope {
                admission: Arc::new(tokio::sync::Semaphore::new(32)),
                host,
                clock: monotonic,
                audit_store,
                requests,
                tenant: audit_tenant,
            },
            envelope,
        ));
    crate::native::Routers {
        apple,
        browser,
        listeners,
    }
}

#[derive(Clone)]
pub(crate) struct Envelope {
    pub(crate) admission: Arc<tokio::sync::Semaphore>,
    pub(crate) host: String,
    pub(crate) clock: Arc<dyn rss_observation::Clock>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
    pub(crate) tenant: String,
}
fn route_action(route: &str, native_identity: bool) -> &'static str {
    match route {
        "/api/v1/authorization" => "authorization_effective_read",
        "/api/v1/authorization/rules" => "authorization_rules_read",
        "/api/v1/authorization/user-groups" => "authorization_groups_read",
        "/api/v1/authorization/user-groups/{id}/members" => "authorization_members_read",
        "/api/v1/authorization/departments" => "authorization_departments_read",
        "/api/v1/authorization/rules/{id}" | "/api/v1/authorization/user-groups/{id}" => {
            "authorization_write"
        }
        "/api/v3/enrollments" => "enrollment_create",
        "/api/v3/enrollments/{id}" => "enrollment_read",
        "/api/v3/devices/{device}/registrations" => "registration_read",
        "/api/v3/enrollments/{id}/resume" => "enrollment_resume",
        "/api/v3/enrollments/{id}/cancel" => "enrollment_cancel",
        "/api/v3/devices/{device}/registrations/{registration}/revoke" => "credential_revoke",
        "/api/agent/v2/registrations" => "agent_registration",
        "/api/agent/v2/reports" => "agent_report",
        "/api/agent/v2/reports/{id}" => "agent_report_read",
        "/api/v2/devices/{id}/inventory" => "inventory_read",
        "/api/v1/devices/{id}/collection-runs" => "collection_start",
        "/api/v1/devices/{id}/collection-runs/{run}" => "collection_read",
        "/api/v1/devices/{id}/actions" => "device_action",
        _ if native_identity => "authentication",
        "/EnrollmentServer/Discovery.svc" => "windows_discovery",
        "/EnrollmentServer/Policy.svc" => "windows_policy",
        "/EnrollmentServer/Enrollment.svc" => "enrollment_issue",
        "/ManagementServer/MDM.svc" => "windows_management",
        "/checkin" => "apple_checkin",
        "/mdm" => "apple_management",
        "/native/apple/scep/challenge" | "/native/apple/scep/notify" => "apple_scep",
        p if p.starts_with("/api/v3/enrollments/") && p.ends_with("/profile") => "apple_profile",
        _ => "protected_request",
    }
}
pub(crate) async fn envelope(
    State(envelope): State<Envelope>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = envelope.clock.now();
    let host = &envelope.host;
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let native_identity =
        route.starts_with("/api/v2/tenants/") || route.starts_with("/api/v2/oidc/");
    let action = route_action(route, native_identity);
    let soap = route.starts_with("/EnrollmentServer/");
    let agent_route = route.starts_with("/api/agent/v2/");
    let audit = RequestAudit::new(envelope.tenant.clone(), action);
    let request_id = audit.request_id();
    // Native authentication commits its own atomic security event. A second product
    // audit must not replace that settled response (including rotated credentials).
    let audited = !matches!(request.uri().path(), "/livez" | "/readyz") && !native_identity;
    // Transport capacity is admitted before handlers and durable denial auditing.
    // Keep this separate from the existing cryptographic/Agent permit to avoid nested acquisition.
    let _audit_permit = if audited {
        match envelope.admission.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                audit.finalize(None);
                return capacity_response(
                    request.uri().path().starts_with("/api/agent/v2/"),
                    request_id,
                );
            }
        }
    } else {
        None
    };
    request.extensions_mut().insert(audit.clone());
    let mut response = if request.headers().get_all(header::HOST).iter().count() != 1
        || request.uri().to_string().len() > 8192
        || request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(host.as_str())
    {
        Error::Malformed.into_response()
    } else {
        bounded_body(request, next, agent_route, envelope.requests.clone()).await
    };
    let snapshot = audit.snapshot();
    if matches!(
        response.extensions().get::<Error>(),
        Some(Error::Unavailable(Failure::RequestDeadline))
    ) {
        response = crate::error_projection::audit_deadline(snapshot.write_outcome).into_response();
    }
    let mut audit_failure = match response.extensions().get::<Error>() {
        Some(
            error @ Error::Unavailable(
                Failure::AuditIntegrity
                | Failure::AuditIsolation
                | Failure::AuditContract
                | Failure::AuditAdmission,
            ),
        ) => Some(crate::error_projection::audit_failure_reason(error)),
        Some(Error::Unavailable(Failure::Audit)) => Some(FailureReason::Transaction),
        _ => None,
    };
    if audited
        && (snapshot.settle_request
            || snapshot.write_outcome != WriteOutcome::Committed
            || matches!(
                snapshot.management_result,
                Some(rss_mdm_audit_integration::ManagementResult::Replayed)
            ))
    {
        let status = response.status().as_u16();
        let result = audit_result(&response, &snapshot);
        let budget = crate::audit_budget::AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        if let Err(error) = envelope
            .audit_store
            .settle_request(&audit, status, result, &control)
            .await
        {
            let error = Error::from(error);
            audit_failure = Some(crate::error_projection::audit_failure_reason(&error));
            response = crate::error_projection::audit_settlement(
                response.extensions().get::<Error>(),
                snapshot.write_outcome,
                error,
            )
            .into_response();
        }
    }

    if soap
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"application/soap+xml"))
        && let Some(error) = response.extensions().get::<Error>().cloned()
    {
        response = crate::windows::fault(None, error);
    }
    if let Some(key) = snapshot.operation_id {
        response.headers_mut().insert(
            "idempotency-key",
            HeaderValue::from_str(&key.to_string()).expect("UUID"),
        );
    }
    audit.finalize(audit_failure);
    eprintln!(
        "{}",
        json!({"event":"mdm_request","request_id":request_id,"operation_id":snapshot.operation_id,"status":response.status().as_u16(),"latency_ms":envelope.clock.now().saturating_duration_since(started).as_millis(),"error":response.extensions().get::<Error>()})
    );
    secure_response(response, request_id)
}
fn capacity_response(agent: bool, request_id: uuid::Uuid) -> Response {
    let mut response = if agent {
        crate::agent::ingress_error(rss_mdm_agent_wire::ErrorCode::ServiceUnavailable)
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"code":"request_limited"})),
        )
            .into_response()
    };
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    secure_response(response, request_id)
}

pub(crate) fn secure_response(mut response: Response, request_id: uuid::Uuid) -> Response {
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("UUID header"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
async fn bounded_body(
    request: Request,
    next: Next,
    agent: bool,
    requests: Arc<tokio::sync::Semaphore>,
) -> Response {
    // Bound ingress before starting any transaction. Component operations then settle
    // within their own budgets; product operations are bounded after authentication.
    let _agent_permit = if agent {
        match requests.try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return crate::agent::ingress_error(
                    rss_mdm_agent_wire::ErrorCode::ServiceUnavailable,
                );
            }
        }
    } else {
        None
    };
    let streaming = match request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
    {
        Some("/api/v3/resources/{id}/content") => request.method() == axum::http::Method::POST,
        Some("/api/v3/resources/{id}/uploads/{upload}") => {
            request.method() == axum::http::Method::PATCH
        }
        _ => false,
    };
    if streaming {
        return next.run(request).await;
    }
    let limit = match request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
    {
        Some("/api/v3/resources/{id}") => 8 * 1024 * 1024,
        Some("/api/agent/v2/tasks/{id}/events") => rss_mdm_agent_wire::MAX_TASK_REQUEST_BYTES,
        _ if agent => rss_mdm_agent_wire::MAX_REQUEST_BYTES,
        _ => 2 * 1024 * 1024,
    };
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(Duration::from_secs(8), axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
                .await
        }
        Ok(Err(_)) if agent => {
            crate::agent::ingress_error(rss_mdm_agent_wire::ErrorCode::MalformedRequest)
        }
        Ok(Err(_)) => axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(_) if agent => {
            crate::agent::ingress_error(rss_mdm_agent_wire::ErrorCode::ServiceUnavailable)
        }
        Err(_) => Error::Unavailable(Failure::RequestDeadline).into_response(),
    }
}

fn audit_result(
    response: &Response,
    snapshot: &rss_mdm_audit_integration::Snapshot,
) -> &'static str {
    let status = response.status().as_u16();
    if matches!(
        response.extensions().get::<Error>(),
        Some(Error::CommitUnknown | Error::RollbackFailed)
    ) || snapshot.write_outcome == WriteOutcome::Unknown && status >= 500
    {
        "unknown"
    } else if status == 401
        || status == 403
        || matches!(
            response.extensions().get::<Error>(),
            Some(Error::Unauthorized | Error::Forbidden)
        )
    {
        "denied"
    } else if status >= 400 {
        "failed"
    } else if let Some(result) = snapshot.management_result {
        result.audit_tag()
    } else {
        "success"
    }
}
pub(crate) async fn authenticate(
    identity: &Identity,
    access: &Database,
    secret: SessionSecret,
) -> Result<AuthorizedPrincipal, Error> {
    AuthorizedPrincipal::from_identity(identity.authenticate(secret).await?)
        .load_authorization(access)
        .await
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityHostContext {
    tenant_id: String,
    principal_id: String,
    session_id: String,
    navigation: crate::authorization::identity_management::IdentityNavigation,
}
async fn identity_context(
    State(app): State<Arc<IdentityContextState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(tenant): Path<String>,
) -> Result<Json<IdentityHostContext>, Error> {
    let proof = &auth.proof;
    if tenant != proof.tenant_id() {
        return Err(Error::Unauthorized);
    }
    Ok(Json(IdentityHostContext {
        tenant_id: proof.tenant_id().to_owned(),
        principal_id: proof.principal_id().to_owned(),
        session_id: proof.session_id(),
        navigation: app.identity_management.identity_navigation(proof)?,
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    action: String,
}
async fn action(
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    if rss_observation::Id::new(&id).is_ok() {
        audit.target(&id);
    }
    audit.set_action("device_action");
    let _grant = auth.proof.dangerous(&id)?;
    if input.map_err(|_| Error::Malformed)?.0.action != "wipe" {
        return Err(Error::Malformed);
    }
    Err(Error::Unsupported)
}

fn operation_key(headers: &HeaderMap) -> Result<uuid::Uuid, Error> {
    if headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(Error::Malformed);
    }
    let id = uuid::Uuid::parse_str(
        headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Malformed)?,
    )
    .map_err(|_| Error::Malformed)?;
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    Ok(id)
}
pub(crate) fn write_key(
    headers: &HeaderMap,
    audit: &RequestAudit,
    action: &'static str,
) -> Result<uuid::Uuid, Error> {
    let key = operation_key(headers)?;
    audit.operation(key, action);
    Ok(key)
}

async fn ready(State(app): State<Arc<ReadinessState>>) -> Response {
    if app.readiness.ready()
        && app
            .apple
            .as_ref()
            .is_none_or(|apple| app.clock.unix_seconds().is_ok_and(|now| apple.ready(now)))
        && app
            .flow
            .planning
            .automation_task
            .get()
            .is_some_and(rss_runtime::TaskStatus::is_running)
        && app.flow.planning.ingress_ready().await
    {
        Json(json!({"ready":true})).into_response()
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ready":false})),
        )
            .into_response()
    }
}
async fn collection_run(
    State(app): State<Arc<CollectionState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<(String, uuid::Uuid)>, axum::extract::rejection::PathRejection>,
    query: Result<Query<Coordinates>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<crate::assets::collection::CollectionResponse>, Error> {
    let Path((device, run)) = path.map_err(|_| Error::Malformed)?;
    let Query(coordinates) = query.map_err(|_| Error::Malformed)?;
    audit.target(&device);
    audit.set_action("collection_read");
    let grant = auth.proof.inventory(&device, coordinates)?;
    Ok(Json(app.collection.run(grant, run).await?))
}

struct IdentityContextState {
    identity_management: Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
}

struct CollectionState {
    collection: Arc<crate::assets::collection::CollectionService>,
}

struct ReadinessState {
    readiness: Arc<crate::inventory_runtime::Readiness>,
    apple: Option<Arc<crate::apple::Apple>>,
    clock: Arc<dyn crate::clock::Clock>,
    flow: Arc<crate::flow::Flow>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn registration_routes_keep_audit_identity_before_handler_rejections() {
        for (route, action) in [
            (
                "/api/v3/devices/{device}/registrations",
                "registration_read",
            ),
            (
                "/api/v3/devices/{device}/registrations/{registration}/revoke",
                "credential_revoke",
            ),
            ("/api/agent/v2/registrations", "agent_registration"),
        ] {
            assert_eq!(route_action(route, false), action);
        }
    }

    use super::*;
    #[test]
    fn collection_creation_has_a_business_action_before_authorization() {
        assert_eq!(
            route_action("/api/v1/devices/{id}/collection-runs", false),
            "collection_start"
        );
    }

    #[tokio::test]
    #[ignore = "make t2: close an admitted Audit pool before protected response settlement"]
    async fn audit_failure_logs_preserve_action_and_origin() {
        use tower::ServiceExt;
        const CHILD: &str = "MDM_AUDIT_LOG_TEST";
        if let Ok(mode) = std::env::var(CHILD) {
            let (pool, audit_store) = crate::audit_integration_tests::request_store()
                .await
                .unwrap();
            pool.close().await;
            let router = Router::new()
                .route(
                    "/api/v2/devices/{id}/inventory",
                    get(move || async move {
                        if mode == "transaction" {
                            Error::Unavailable(Failure::Audit).into_response()
                        } else {
                            Json(json!({"sensitive":"inventory-result"})).into_response()
                        }
                    }),
                )
                .layer(middleware::from_fn_with_state(
                    Envelope {
                        admission: Arc::new(tokio::sync::Semaphore::new(32)),
                        host: "mdm.example.test".into(),
                        clock: monotonic(),
                        audit_store,
                        requests: Arc::new(tokio::sync::Semaphore::new(4)),
                        tenant: "11111111-1111-4111-8111-111111111111".into(),
                    },
                    envelope,
                ));
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/api/v2/devices/sensitive-target/inventory")
                        .header("host", "mdm.example.test")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            return;
        }
        for mode in ["read", "transaction"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "api::tests::audit_failure_logs_preserve_action_and_origin",
                    "--ignored",
                    "--exact",
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            let events: Vec<Value> = stderr
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|event| event["event"] == "audit_failure")
                .collect();
            assert_eq!(events.len(), 1, "{mode}: {stderr}");
            assert_eq!(events[0]["reason"], "persistent_audit_unavailable");
            assert_eq!(events[0]["action"], "inventory_read");
            assert!(!stderr.contains("sensitive-target"));
            assert!(!stderr.contains("inventory-result"));
        }
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "test fixture selects the monotonic provider outside request handling"
    )]
    fn monotonic() -> Arc<dyn rss_observation::Clock> {
        Arc::new(crate::Monotonic(std::time::Instant::now))
    }
    #[tokio::test]
    #[ignore = "make t2: production envelope has an admitted Audit capability"]
    async fn request_diagnostics_keep_causes_internal_and_issue_request_ids() {
        use tower::ServiceExt;
        let (pool, audit_store) = crate::audit_integration_tests::request_store()
            .await
            .unwrap();
        for reason in [
            Failure::RequestDeadline,
            Failure::IdentityStorage,
            Failure::InventoryPool,
            Failure::InventoryQuery,
            Failure::ManualQuery,
            Failure::CollectionQuery,
            Failure::AssetObjectLimit,
            Failure::AssetSourceLimit,
            Failure::AssetBytesLimit,
            Failure::Clock,
            Failure::Capacity,
        ] {
            let router = Router::new()
                .route(
                    "/livez",
                    get(move || async move { Error::Unavailable(reason) }),
                )
                .layer(middleware::from_fn_with_state(
                    Envelope {
                        admission: Arc::new(tokio::sync::Semaphore::new(32)),
                        host: "mdm.example.test".to_owned(),
                        clock: monotonic(),
                        audit_store: audit_store.clone(),
                        requests: Arc::new(tokio::sync::Semaphore::new(4)),
                        tenant: "11111111-1111-4111-8111-111111111111".into(),
                    },
                    envelope,
                ));
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/livez")
                        .header("host", "mdm.example.test")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(
                uuid::Uuid::parse_str(response.headers()["x-request-id"].to_str().unwrap()).is_ok()
            );
            assert!(matches!(
                response.extensions().get::<Error>(),
                Some(Error::Unavailable(_))
            ));
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap(),
                json!({"code":"service_unavailable"})
            );
        }
        pool.close().await;
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler = entered.clone();
        let router = Router::new()
            .route(
                "/api/protected",
                get(move || {
                    let handler = handler.clone();
                    async move {
                        handler.store(true, std::sync::atomic::Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            )
            .layer(middleware::from_fn_with_state(
                Envelope {
                    admission: Arc::new(tokio::sync::Semaphore::new(0)),
                    host: "mdm.example.test".into(),
                    clock: monotonic(),
                    audit_store,
                    requests: Arc::new(tokio::sync::Semaphore::new(4)),
                    tenant: "11111111-1111-4111-8111-111111111111".into(),
                },
                envelope,
            ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/protected")
                    .header("host", "mdm.example.test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));
    }
    #[test]
    fn operation_coordinate_does_not_claim_request_replay() {
        let audit = RequestAudit::new(
            "11111111-1111-4111-8111-111111111111".into(),
            "command_read",
        );
        audit.operation(uuid::Uuid::new_v4(), "command_read");
        let response = StatusCode::OK.into_response();
        assert_eq!(audit_result(&response, &audit.snapshot()), "success");
        audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
        assert_eq!(audit_result(&response, &audit.snapshot()), "replay");
        audit.finalize(None);
    }
}
