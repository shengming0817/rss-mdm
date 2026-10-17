use super::*;
use crate::{database::db, profile};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::RequestAudit;
use serde::Deserialize;
#[derive(Deserialize)]
pub struct Discovery {
    #[serde(rename = "user-identifier")]
    user_identifier: String,
    #[serde(rename = "model-family")]
    model_family: String,
}
pub(super) async fn discover(
    State(app): State<Arc<HttpState>>,
    Query(input): Query<Discovery>,
) -> Result<Json<serde_json::Value>, Error> {
    if input.model_family != "Mac" {
        return Err(Error::Malformed);
    }
    let name = account_name(&input.user_identifier)?;
    let host = name.rsplit_once('@').ok_or(Error::Malformed)?.1;
    let tenant = app.identity.tenant().to_string();
    let mut tx = app.access.begin_read(&tenant).await?;
    let row=sqlx::query("SELECT id,signing_key FROM mdm_apple.account_configuration WHERE tenant_id=$1::uuid AND domain=$2 AND enabled")
        .bind(&tenant).bind(host).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::NotFound)?;
    let key: String = row.try_get("signing_key").map_err(db)?;
    let signer = app.apple()?.account_keys.get(&key).ok_or(Error::Conflict)?;
    if signer.expires()
        <= app
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))? as u64
    {
        return Err(Error::Conflict);
    }
    Ok(Json(
        serde_json::json!({"Servers":[{"Version":"mdm-adde","BaseURL":format!("{}/api/v1/apple/account-enrollment/enroll/{}",app.authentication.origin,row.try_get::<Uuid,_>("id").map_err(db)?)}]}),
    ))
}
pub(super) fn bearer(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    let values = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(Error::Unauthorized);
    }
    values
        .first()
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.strip_prefix("Bearer "))
                .filter(|s| {
                    s.len() == 43
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                })
                .ok_or(Error::Unauthorized)
        })
        .transpose()
}
pub(super) fn challenge(app: &HttpState, flow: Uuid) -> Result<Response, Error> {
    let value = format!(
        "Bearer method=\"apple-as-web\", url=\"{}/api/v1/apple/account-enrollment/authenticate/{flow}\"",
        app.authentication.origin
    );
    Ok((
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, value)],
    )
        .into_response())
}
pub(super) async fn enroll(
    State(app): State<Arc<HttpState>>,
    Path(organization): Path<Uuid>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Result<Response, Error> {
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    let request = rss_mdm_certificate::apple::enrollment_request(&bytes, now)?;
    let body = rss_mdm_apple_mdm::protocol::decode(&request.payload)?;
    validate_platform(&body)?;
    let digest = rss_mdm_registration_service::enrollment::digest(&(
        "apple.account.request/v1",
        request.signer,
        request.payload,
    ));
    if let Some(token) = bearer(&headers)? {
        return profile(&app, organization, token, &digest, &audit).await;
    }
    audit.identify_service("service:apple-account-bootstrap");
    let flow = Uuid::new_v4();
    let tenant = app.identity.tenant().to_string();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &control,
            (&app, &tenant, organization, flow, &digest, &audit),
            |(app, tenant, organization, flow, digest, audit), tx| {
                Box::pin(async move {
                    tx.with_connection_context(
                        &mut (*app, *tenant, *organization, *flow, *digest),
                        |(app, tenant, organization, flow, digest), c| {
                            Box::pin(bootstrap_on(
                                c,
                                Bootstrap {
                                    app,
                                    tenant,
                                    organization: *organization,
                                    flow: *flow,
                                    digest,
                                },
                            ))
                        },
                    )
                    .await?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-account-flow:{flow}"),
                        digest.as_bytes(),
                        401,
                        "success",
                        Some(*flow),
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact, false)
                        .await
                        .map_err(Error::from)?;
                    audit.mark_commit_started();
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(outcome, &audit)?;
    challenge(&app, flow)
}
async fn profile(
    app: &HttpState,
    organization: Uuid,
    token: &str,
    digest: &str,
    audit: &RequestAudit,
) -> Result<Response, Error> {
    let tenant = app.identity.tenant().to_string();
    let mut read = app.access.begin(&tenant).await?;
    let flow = store::token(&mut read, &tenant, token).await?;
    if flow.try_get::<Uuid, _>("organization").map_err(db)? != organization
        || flow.try_get::<String, _>("request_digest").map_err(db)? != digest
    {
        return Err(Error::Unauthorized);
    }
    let id: Uuid = flow.try_get("enrollment").map_err(db)?;
    let flow_id: Uuid = flow.try_get("id").map_err(db)?;
    read.rollback().await.map_err(db)?;
    let admission = rss_mdm_registration_service::enrollment::native::account(
        &app.access.registration(),
        &app.identity,
        id,
        app.account_authority.clone(),
        None,
    )
    .await?;
    admission.bind_audit(audit)?;
    audit.target(&admission.coordinates().device);
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &control,
            (app, &tenant, token, digest, &admission, flow_id, audit),
            |(app, tenant, token, digest, admission, flow_id, audit), tx| {
                Box::pin(async move {
                    let (bytes, replayed) = tx
                        .with_connection_context(
                            &mut (*app, *tenant, *token, *digest, *admission, *flow_id),
                            |(app, tenant, token, digest, admission, flow_id), c| {
                                Box::pin(profile_on(
                                    c,
                                    Profile {
                                        app,
                                        tenant,
                                        token,
                                        digest,
                                        admission,
                                        flow_id: *flow_id,
                                    },
                                ))
                            },
                        )
                        .await?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!(
                            "apple-account-profile:{}:{}",
                            admission.coordinates().id,
                            admission.coordinates().version
                        ),
                        digest.as_bytes(),
                        200,
                        "success",
                        Some(admission.coordinates().id),
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        )
                    }
                    audit.mark_commit_started();
                    Ok(bytes)
                })
            },
        )
        .await;
    Ok((
        [("content-type", "application/x-apple-aspen-config")],
        crate::operations::settle(outcome, audit)?,
    )
        .into_response())
}

struct Bootstrap<'a> {
    app: &'a HttpState,
    tenant: &'a String,
    organization: Uuid,
    flow: Uuid,
    digest: &'a str,
}
async fn bootstrap_on(c: &mut sqlx::PgConnection, input: Bootstrap<'_>) -> Result<(), Error> {
    let Bootstrap {
        app,
        tenant,
        organization,
        flow,
        digest,
    } = input;
    let row=sqlx::query("SELECT revision,signing_key FROM mdm_apple.account_configuration WHERE tenant_id=$1::uuid AND id=$2 AND enabled FOR SHARE").bind(tenant).bind(organization).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let key: String = row.try_get("signing_key").map_err(db)?;
    if !app.apple()?.account_keys.get(&key).is_some_and(|s| {
        app.clock
            .unix_seconds()
            .is_some_and(|now| s.expires() > now as u64)
    }) {
        return Err(Error::Conflict);
    }
    store::new_flow(
        c,
        tenant,
        store::NewFlow {
            id: flow,
            organization,
            revision: row.try_get("revision").map_err(db)?,
            target: flow,
            request_digest: digest.to_string(),
            expected_account: None,
        },
    )
    .await
}

struct Profile<'a> {
    app: &'a HttpState,
    tenant: &'a String,
    token: &'a str,
    digest: &'a str,
    admission: &'a rss_mdm_registration_service::enrollment::native::Admission,
    flow_id: Uuid,
}
async fn profile_on(
    c: &mut sqlx::PgConnection,
    input: Profile<'_>,
) -> Result<(Vec<u8>, bool), Error> {
    let Profile {
        app,
        tenant,
        token,
        digest,
        admission,
        flow_id,
    } = input;
    let current = admission.current(c).await?;
    let row = store::token(c, tenant, token).await?;
    // Hold the same configuration locks used by bridge completion.
    let row = store::flow(c, tenant, row.try_get("id").map_err(db)?).await?;
    let binding = store::bound_account(
        c,
        tenant,
        row.try_get("organization").map_err(db)?,
        &row.try_get::<String, _>("account").map_err(db)?,
    )
    .await?;
    if row.try_get::<i64, _>("binding_revision").map_err(db)?
        != binding.try_get::<i64, _>("revision").map_err(db)?
        || row.try_get::<i64, _>("authorization_version").map_err(db)?
            != admission.coordinates().version
        || row.try_get::<String, _>("request_digest").map_err(db)? != digest
    {
        return Err(Error::Unauthorized);
    }
    if let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("profile").map_err(db)? {
        let bytes = app
            .protection
            .open_bytes(&sealed, &aad(tenant, flow_id, "apple.account.profile")?)
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
        return Ok::<_, Error>((bytes.expose().to_vec(), true));
    }
    let material: Vec<u8> = row.try_get("material").map_err(db)?;
    let plain = app
        .protection
        .open_bytes(&material, &aad(tenant, flow_id, "apple.account.material")?)
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let material: Material = serde_json::from_slice(plain.expose())
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let apple = app.apple()?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND enrollment=$2 AND authorization_version<>$3 AND state<>'superseded'").bind(tenant).bind(admission.coordinates().id).bind(admission.coordinates().version).execute(&mut *c).await.map_err(db)?;
    let (attempt, _, scep_url, scep_provisioner) = crate::enrollment::prepared(
        c,
        apple,
        admission.coordinates(),
        tenant,
        &current.try_get::<String, _>("deadline").map_err(db)?,
    )
    .await?;
    let name: String = row.try_get("account").map_err(db)?;
    let bytes = apple.signer.sign(
        &profile::enrollment(
            &profile::EnrollmentProfile {
                mode: profile::EnrollmentMode::Account {
                    managed_account: &name,
                },
                access_rights: apple.access_rights() as u16,
                scep_url: &scep_url,
                scep_provisioner: &scep_provisioner,
                apns_topic: &apple.config.apns_topic,
                management_origin: &apple.config.management.origin,
                subject: &rss_mdm_certificate::apple::subject(admission.coordinates().id, attempt),
            },
            admission.coordinates().id,
            attempt,
            &material.challenge,
        )?,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let sealed = app
        .protection
        .seal_bytes(&bytes, &aad(tenant, flow_id, "apple.account.profile")?)
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    sqlx::query("UPDATE mdm_apple.account_flows SET profile=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant)
        .bind(flow_id)
        .bind(sealed)
        .execute(c)
        .await
        .map_err(db)?;
    admission.check_live()?;
    Ok((bytes, false))
}

fn validate_platform(body: &plist::Dictionary) -> Result<(), Error> {
    let product = rss_mdm_apple_mdm::protocol::text(body, "PRODUCT")?;
    let build = rss_mdm_apple_mdm::protocol::text(body, "VERSION")?;
    rss_mdm_apple_mdm::protocol::text(body, "LANGUAGE")?;
    let major = build
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    let major = std::str::from_utf8(&major)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or(Error::Malformed)?;
    if !(product.starts_with("Mac") || product.starts_with("iMac")) || major < 23 {
        return Err(Error::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_platform_requires_supported_mac_build() {
        for (product, build, accepted) in [
            ("Mac14,2", "23A344", true),
            ("iMac20,1", "23A344", true),
            ("iPhone15,2", "23A344", false),
            ("Mac14,2", "22A344", false),
            ("Mac14,2", "A344", false),
            ("Mac14,2", "4294967296A", false),
        ] {
            let body = rss_mdm_apple_mdm::protocol::dictionary([
                ("PRODUCT", product.into()),
                ("VERSION", build.into()),
                ("LANGUAGE", "en".into()),
            ]);
            assert_eq!(validate_platform(&body).is_ok(), accepted);
        }
    }
}
