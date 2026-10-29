//! Account-driven Device Enrollment. Identity owns people; registration owns devices.
//! ref: Apple implementing-the-simple-authentication-account-driven-enrollment-flow;
//! apple/device-management mdm/checkin/gettoken.yaml@09f249a06e7e3289930bf6d05f38fb562f748ebf.
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
mod authority;
pub use authority::authority;
mod bridge;
pub(crate) mod management;

mod protocol;
mod store;
use crate::{Error, Failure, HttpState};
use axum::http::HeaderMap;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_http_contract::Router;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

pub struct Authentication {
    pub authority: rss_identity_postgres::Authority,
    pub http: rss_identity_http_axum::HttpConfig,
    pub origin: String,
}
pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    use rss_mdm_http_contract::routing::{get, post};
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { external_get_discover, external_post_enroll, get_start, get_resume, post_finish, get_script } }
        RoutesModule1 {
            external_get_discover: rss_mdm_http_contract::module::Route::new(
                "/.well-known/com.apple.remotemanagement",
                rss_mdm_http_contract::routing::external_get(
                    protocol::discover,
                    rss_mdm_http_contract::ExternalProtocol::AppleMdm,
                    &contracts::PROTOCOL_APPLE_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_enroll: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/account-enrollment/enroll/{organization}",
                rss_mdm_http_contract::routing::external_post(
                    protocol::enroll,
                    rss_mdm_http_contract::ExternalProtocol::AppleMdm,
                    &contracts::PROTOCOL_APPLE_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_start: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/account-enrollment/authenticate/{flow}",
                get(
                    bridge::start,
                    &contracts::PROTOCOL_APPLE_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_resume: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/account-enrollment/authenticate",
                get(
                    bridge::resume,
                    &contracts::PROTOCOL_APPLE_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            post_finish: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/account-enrollment/finish",
                post(
                    bridge::finish,
                    &contracts::PROTOCOL_APPLE_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_script: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/account-enrollment/bridge.js",
                get(
                    bridge::script,
                    &contracts::PROTOCOL_APPLE_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
}
pub(crate) fn management_routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    use rss_mdm_http_contract::routing::get;
    {
        rss_mdm_http_contract::route_module! { struct ManagementRoutesModule1 for [Browser] { get_list, get_organization_detail, put_organization, get_accounts, get_account_detail, put_account } }
        ManagementRoutesModule1 {
            get_list: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations",
                get(
                    management::list,
                    &contracts::APPLE_ORGANIZATIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_organization_detail: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/account-enrollment",
                rss_mdm_http_contract::routing::get(
                    management::organization_detail,
                    &contracts::APPLE_ACCOUNT_CONFIGURATION,
                    &[RouteOperation::Get],
                ),
            ),
            put_organization: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/account-enrollment",
                rss_mdm_http_contract::routing::put(
                    management::organization,
                    &contracts::APPLE_ACCOUNT_CONFIGURATION,
                    &[RouteOperation::Update],
                ),
            ),
            get_accounts: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/account-enrollment/accounts",
                get(
                    management::accounts,
                    &contracts::APPLE_ACCOUNTS,
                    &[RouteOperation::List],
                ),
            ),
            get_account_detail: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/account-enrollment/accounts/{account}",
                rss_mdm_http_contract::routing::get(
                    management::account_detail,
                    &contracts::APPLE_ACCOUNT_BINDINGS,
                    &[RouteOperation::Get],
                ),
            ),
            put_account: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/account-enrollment/accounts/{account}",
                rss_mdm_http_contract::routing::put(
                    management::account,
                    &contracts::APPLE_ACCOUNT_BINDINGS,
                    &[RouteOperation::Update],
                ),
            ),
        }
        .assemble()
    }
}
pub(crate) async fn authenticate(
    app: &HttpState,
    headers: &HeaderMap,
    active: bool,
) -> Result<AuthorizedPrincipal, Error> {
    let (session, _secret) = rss_identity_http_axum::authenticate_request(
        &app.authentication.authority,
        &app.authentication.http,
        app.identity.tenant(),
        headers,
        if active {
            rss_identity_http_axum::SessionActivity::Active
        } else {
            rss_identity_http_axum::SessionActivity::Passive
        },
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            std::time::Duration::from_secs(10),
        ),
    )
    .await
    .map_err(
        |r| match r.extensions().get::<rss_identity_http_axum::HttpFailure>() {
            Some(rss_identity_http_axum::HttpFailure::Authority(
                rss_identity_postgres::AuthorityError::CommitUnknown(_),
            )) => Error::CommitUnknown,
            Some(rss_identity_http_axum::HttpFailure::Authority(
                rss_identity_postgres::AuthorityError::RollbackFailed(_),
            )) => Error::RollbackFailed,
            _ if r.status().is_server_error() => Error::Unavailable(Failure::Database),
            _ => Error::Unauthorized,
        },
    )?;
    AuthorizedPrincipal::new(session)?
        .load_authorization(&app.access.authorization)
        .await
        .map_err(Into::into)
}
fn domain(value: &str) -> Result<String, Error> {
    let value = value.to_ascii_lowercase();
    if value.len() > 253
        || !value.contains('.')
        || value.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::Malformed);
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Err(Error::Malformed);
    }
    Ok(value)
}
fn account_name(value: &str) -> Result<String, Error> {
    if value.len() > 320 || value.matches('@').count() != 1 {
        return Err(Error::Malformed);
    }
    let (local, host) = value.rsplit_once('@').ok_or(Error::Malformed)?;
    if local.is_empty()
        || local.len() > 64
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        return Err(Error::Malformed);
    }
    Ok(format!("{}@{}", local.to_ascii_lowercase(), domain(host)?))
}
/// All post-authentication entry points require the current server-selected binding revision.
pub(crate) async fn require_binding(app: &HttpState, enrollment: Uuid) -> Result<(), Error> {
    let mut tx = app.access.begin(&app.identity.tenant().to_string()).await?;
    store::binding(&mut tx, &app.identity.tenant().to_string(), enrollment).await?;
    tx.rollback().await.map_err(crate::database::db)?;
    Ok(())
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Material {
    token: zeroize::Zeroizing<String>,
    challenge: zeroize::Zeroizing<String>,
}
pub(crate) fn aad(
    tenant: &str,
    flow: Uuid,
    part: &str,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    crate::material::aad(tenant, flow, 1, "", 1, part)
}
fn token_hash(tenant: &str, token: &str) -> String {
    rss_mdm_registration_service::enrollment::digest(&("apple.account.access/v1", tenant, token))
}
fn cookie_hash(tenant: &str, flow: Uuid, secret: &str) -> String {
    rss_mdm_registration_service::enrollment::digest(&(
        "apple.account.flow/v1",
        tenant,
        flow,
        secret,
    ))
}
/// Retained user proof accompanies the request into its existing protocol transaction.
pub struct UserAccess {
    admission: rss_mdm_registration_service::enrollment::native::Admission,
    flow: Uuid,
    hash: String,
}
impl UserAccess {
    pub(crate) async fn current_in(&self, c: &mut sqlx::PgConnection) -> Result<(), Error> {
        self.admission.revalidate_account_in(c).await?;
        let d = self.admission.coordinates();
        let current: bool =
            sqlx::query_scalar("SELECT mdm_apple.account_current($1::uuid,$2,$3,$4,$5)")
                .bind(&d.tenant)
                .bind(d.id)
                .bind(d.version)
                .bind(self.flow)
                .bind(&self.hash)
                .fetch_one(c)
                .await
                .map_err(crate::database::db)?;
        if !current {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
/// A user-channel bearer supplements the current device certificate.
pub(crate) async fn authorize_user(
    app: &HttpState,
    enrollment: Uuid,
    headers: &HeaderMap,
) -> Result<Option<UserAccess>, Error> {
    let tenant = app.identity.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let account:bool=sqlx::query_scalar("SELECT authority_kind='apple_account' FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2")
        .bind(&tenant).bind(enrollment).fetch_one(&mut *tx).await.map_err(crate::database::db)?;
    if !account {
        return Ok(None);
    }
    let token = protocol::bearer(headers)?.ok_or(Error::Unauthorized)?;
    let row = store::token(&mut tx, &tenant, token).await?;
    if row
        .try_get::<Uuid, _>("enrollment")
        .map_err(crate::database::db)?
        != enrollment
    {
        return Err(Error::Unauthorized);
    }
    let flow = row.try_get("id").map_err(crate::database::db)?;
    tx.rollback().await.map_err(crate::database::db)?;
    let admission = rss_mdm_registration_service::enrollment::native::account(
        &app.access.registration(),
        &app.identity,
        enrollment,
        app.account_authority.clone(),
        None,
    )
    .await?;
    if admission.coordinates().version
        != row
            .try_get::<i64, _>("authorization_version")
            .map_err(crate::database::db)?
    {
        return Err(Error::Unauthorized);
    }
    admission.check_live()?;
    Ok(Some(UserAccess {
        admission,
        flow,
        hash: token_hash(&tenant, token),
    }))
}
pub(crate) async fn reauthentication(
    app: &HttpState,
    enrollment: Uuid,
    audit: &rss_mdm_audit_integration::RequestAudit,
) -> Result<axum::response::Response, Error> {
    let tenant = app.identity.tenant().to_string();
    let flow = Uuid::new_v4();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &budget.source_control(),
            (app, &tenant, enrollment, flow, audit),
            |(app, tenant, enrollment, flow, audit), tx| {
                Box::pin(async move {
                    tx.with_connection_context(
                        &mut (*tenant, *enrollment, *flow),
                        |(tenant, enrollment, flow), c| {
                            Box::pin(async move {
                                let previous = store::recovery(c, tenant, *enrollment).await?;
                                store::new_flow(
                                    c,
                                    tenant,
                                    store::NewFlow {
                                        id: *flow,
                                        organization: previous
                                            .try_get("organization")
                                            .map_err(crate::database::db)?,
                                        revision: previous
                                            .try_get("current_organization_revision")
                                            .map_err(crate::database::db)?,
                                        target: *enrollment,
                                        request_digest: previous
                                            .try_get("request_digest")
                                            .map_err(crate::database::db)?,
                                        expected_account: Some(
                                            previous
                                                .try_get("account")
                                                .map_err(crate::database::db)?,
                                        ),
                                    },
                                )
                                .await
                            })
                        },
                    )
                    .await?;

                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-account-reauthentication:{flow}"),
                        401,
                        "success",
                        Some(*enrollment),
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact)
                        .await
                        .map_err(Error::from)?;
                    audit.mark_commit_started();
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(outcome, audit)?;
    protocol::challenge(app, flow)
}
pub(crate) async fn require_binding_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    enrollment: Uuid,
) -> Result<(), Error> {
    store::binding(c, tenant, enrollment).await?;
    Ok(())
}
pub(crate) async fn maid(
    app: &HttpState,
    principal: &crate::device::DevicePrincipal,
    enrollment: Uuid,
    udid: &str,
    access: Option<&UserAccess>,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    let tenant = app.identity.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    crate::device::store::revalidate_source(
        &mut tx,
        principal,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?;
    let row = store::binding(&mut tx, &tenant, enrollment).await?;
    let expected:String=sqlx::query_scalar("SELECT udid FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state<>'retired'").bind(&tenant).bind(principal.registration()).fetch_one(&mut *tx).await.map_err(crate::database::db)?;
    if expected != udid {
        return Err(Error::Unauthorized);
    }
    if let Some(access) = access {
        access.current_in(&mut tx).await?;
    }
    let org: Uuid = row.try_get("organization").map_err(crate::database::db)?;
    let organization=sqlx::query("SELECT server_uuid,signing_key FROM mdm_apple.account_configuration WHERE tenant_id=$1::uuid AND id=$2 AND enabled").bind(&tenant).bind(org).fetch_one(&mut *tx).await.map_err(crate::database::db)?;
    let key: String = organization
        .try_get("signing_key")
        .map_err(crate::database::db)?;
    let signer = app.apple()?.account_keys.get(&key).ok_or(Error::Conflict)?;
    let token = signer.sign(
        organization
            .try_get("server_uuid")
            .map_err(crate::database::db)?,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let bytes = rss_mdm_apple_mdm::protocol::xml(rss_mdm_apple_mdm::protocol::dictionary([(
        "TokenData",
        plist::Value::Data(token.into_bytes()),
    )]))?;
    Ok(([("content-type", "application/xml")], bytes).into_response())
}

/// Current account instructions and Identity validity are observations, never a new grant.
pub async fn progress_in(
    c: &mut sqlx::PgConnection,
    sessions: &rss_mdm_authorization_service::session::SessionAuthority,
    context: &rss_mdm_registration_service::enrollment::read::Context,
) -> Result<(String, bool), Error> {
    let name:String=sqlx::query_scalar("SELECT account FROM mdm_apple.account_flows WHERE tenant_id=$1::uuid AND enrollment=$2 ORDER BY authorization_version DESC LIMIT 1")
        .bind(&context.tenant).bind(context.enrollment).fetch_one(&mut *c).await.map_err(crate::database::db)?;
    match store::binding_read(c, &context.tenant, context.enrollment, false).await {
        Err(Error::Unauthorized) => return Ok((name, true)),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let reference=sqlx::query_scalar::<_,serde_json::Value>("SELECT account_reference FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2 AND account_version=$3")
        .bind(&context.tenant).bind(context.enrollment).bind(context.authorization_version).fetch_one(c).await.map_err(crate::database::db)?;
    let reference =
        serde_json::from_value(reference).map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let required = match sessions.recheck(&reference).await {
        Ok(_) => false,
        Err(rss_mdm_authorization_service::Error::Unauthorized) => true,
        Err(error) => return Err(error.into()),
    };
    Ok((name, required))
}
