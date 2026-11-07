//! Native registration writes settle with the existing Audit transaction owner.
use super::*;
use crate::database::db;
use crate::device_access::{Binding, storage as bindings};
use rss_identity_postgres::platform::{
    PlatformBinding, PlatformSubjectVersion, admit_platform_subject_on,
};
use rss_mdm_agent_wire::platform_sso::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::DevicePrincipal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ceremony {
    principal_registration: Uuid,
    principal_generation: i64,
    source: store::Source,
    previous_version: i64,
}
#[derive(Serialize)]
pub enum Action {
    Bootstrap(Bootstrap),
    Register(Registration),
    Nonce,
    Login(String),
    Revoke(Uuid, Revocation),
}
pub async fn mutate(
    app: &Context,
    principal: Option<&DevicePrincipal>,
    audit: &RequestAudit,
    action: Action,
) -> Result<Outcome, Error> {
    app.runtime()?;
    let operation = match &action {
        Action::Bootstrap(v) => v.operation_id,
        Action::Register(v) => v.operation_id,
        _ => Uuid::new_v4(),
    };
    if operation.is_nil() {
        return Err(Error::Malformed);
    }
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::DeviceAccess,
        operation,
        "apple_platform_sso",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let outcome = app
        .audit_store
        .write(
            app.tenant,
            &budget.source_control(),
            (app, principal, audit, &action, operation),
            |(app, principal, audit, action, operation), tx| {
                Box::pin(async move {
                    let value = tx
                        .with_connection_context(
                            &mut (*app, *principal, *action),
                            |(app, principal, action), c| {
                                Box::pin(apply(app, c, *principal, action))
                            },
                        )
                        .await?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        rss_mdm_audit_integration::operation::OperationOwner::DeviceAccess,
                        &format!("apple-platform-sso:{operation}"),
                        200,
                        "success",
                        None,
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact)
                        .await
                        .map_err(Error::from)?;
                    audit.mark_commit_started();
                    Ok(value)
                })
            },
        )
        .await;
    crate::service::settle(outcome, audit)
}
pub fn subject(
    app: &Context,
    b: &Binding,
    source: Uuid,
    version: i64,
) -> Result<PlatformBinding, Error> {
    Ok(PlatformBinding {
        instance: rss_identity_core::InstanceId::parse(&b.person.instance.to_string())
            .map_err(|_| Error::Unauthorized)?,
        account: rss_identity_core::account::AccountKey {
            tenant: app.tenant,
            principal: rss_identity_core::PrincipalId::parse(&b.person.principal.to_string())
                .map_err(|_| Error::Unauthorized)?,
        },
        binding_id: b.id,
        binding_epoch: b.generation,
        source_id: source,
        source_version: version,
        external_identity: None,
    })
}
pub async fn admit(
    app: &Context,
    c: &mut PgConnection,
    s: &store::Source,
) -> Result<PlatformSubjectVersion, Error> {
    let binding = s.subject.as_ref().ok_or(Error::Unauthorized)?;
    let instance = app.instance;
    admit_platform_subject_on(c, instance, binding, s.subject_version)
        .await
        .map_err(|e| match e {
            rss_identity_postgres::platform::PlatformSubjectAdmissionError::Rejected => {
                Error::Unauthorized
            }
            _ => Error::Storage,
        })
}
async fn apply(
    app: &Context,
    c: &mut PgConnection,
    p: Option<&DevicePrincipal>,
    a: &Action,
) -> Result<Outcome, Error> {
    let now = store::now(c).await?;
    match a {
        Action::Bootstrap(v) => bootstrap(app, c, p.ok_or(Error::Unauthorized)?, v, now)
            .await
            .map(Outcome::Bootstrap),
        Action::Register(v) => register(app, c, p.ok_or(Error::Unauthorized)?, v, now)
            .await
            .map(Outcome::Registration),
        Action::Nonce => {
            let tenant = app.tenant.to_string();
            // Serialized bounded capacity; never hold this lock before the Identity guard.
            store::fence(c, &tenant).await?;
            challenge(app, c, "login", &json!({}), now)
                .await
                .map(Outcome::Nonce)
        }
        Action::Login(token) => login(app, c, token, now).await.map(Outcome::Login),
        Action::Revoke(id, input) => revoke(
            app,
            c,
            p.ok_or(Error::Unauthorized)?,
            *id,
            input.source_version,
        )
        .await
        .map(Outcome::Revocation),
    }
}
async fn challenge(
    app: &Context,
    c: &mut PgConnection,
    purpose: &str,
    context: &Value,
    now: i64,
) -> Result<Nonce, Error> {
    let tenant = app.tenant.to_string();
    store::cleanup(c, &tenant, now).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_da.psso_challenges WHERE tenant_id=$1::uuid AND (purpose='login')=$2",
    )
    .bind(&tenant)
    .bind(purpose == "login")
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if count >= 4096 {
        return Err(Error::Capacity);
    }
    let id = Uuid::new_v4();
    let nonce = crypto::random()?;
    sqlx::query("INSERT INTO rss_da.psso_challenges(tenant_id,id,purpose,nonce_digest,expires_at,context) VALUES($1::uuid,$2,$3,$4,$5,$6)").bind(tenant).bind(id).bind(purpose).bind(crypto::digest(&nonce)).bind(now+NONCE_SECONDS).bind(context).execute(c).await.map_err(db)?;
    Ok(Nonce {
        id,
        nonce,
        expires_at: now + NONCE_SECONDS,
    })
}
async fn bootstrap(
    app: &Context,
    c: &mut PgConnection,
    p: &DevicePrincipal,
    input: &Bootstrap,
    now: i64,
) -> Result<BootstrapResponse, Error> {
    if p.tenant() != app.tenant {
        return Err(Error::Unauthorized);
    }
    let tenant = p.tenant().to_string();
    let rt = app.runtime()?;
    let candidate = if input.kind == Kind::User {
        Some(
            bindings::get_in(
                c,
                Uuid::parse_str(&p.tenant().to_string()).map_err(|_| Error::Unauthorized)?,
                input.binding_id.ok_or(Error::Malformed)?,
            )
            .await?,
        )
    } else {
        if input.binding_id.is_some() || input.binding_generation.is_some() {
            return Err(Error::Malformed);
        }
        None
    };
    let existing: Option<Value> = if let Some(b) = &candidate {
        sqlx::query_scalar("SELECT document FROM rss_da.psso_sources WHERE tenant_id=$1::uuid AND binding=$2 AND kind='user'").bind(&tenant).bind(b.id).fetch_optional(&mut *c).await.map_err(db)?
    } else {
        None
    };
    let previous: Option<store::Source> = existing
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error::Storage)?;
    let id = previous.as_ref().map_or_else(Uuid::new_v4, |s| s.id);
    let version = previous
        .as_ref()
        .map_or(Ok(1), |s| s.version.checked_add(1).ok_or(Error::Conflict))?;
    let subject = candidate
        .as_ref()
        .map(|b| subject(app, b, id, version))
        .transpose()?;
    let epochs = if let Some(binding) = &subject {
        Some(
            admit_platform_subject_on(c, app.instance, binding, None)
                .await
                .map_err(|e| match e {
                    rss_identity_postgres::platform::PlatformSubjectAdmissionError::Rejected => {
                        Error::Unauthorized
                    }
                    _ => Error::Storage,
                })?,
        )
    } else {
        None
    };
    let resolved = crate::delivery::resolve_on(c, p).await?;
    store::fence(c, &tenant).await?;
    let object = rss_mdm_registration_service::device::endpoints::DaRegistration {
        device: resolved.device().into(),
        registration_id: resolved.registration(),
        generation: resolved.generation(),
    };
    super::deployment::ready(app, c, &object, now).await?;
    let registration = object.registration_id;
    let binding = if let Some(b) = candidate {
        let current = app
            .registration_binding_on(
                c,
                p,
                b.id,
                input.binding_generation.ok_or(Error::Malformed)?,
            )
            .await?;
        if current.person != b.person
            || current.generation != b.generation
            || current.intent.platform() != rss_mdm_agent_wire::runtime::TaskPlatform::Macos
        {
            return Err(Error::Unauthorized);
        }
        Some(current)
    } else {
        None
    };
    let (id, version, old) = if input.kind == Kind::Device {
        let old:Option<Value>=sqlx::query_scalar("SELECT document FROM rss_da.psso_sources WHERE tenant_id=$1::uuid AND registration=$2 AND kind='device'").bind(&tenant).bind(registration).fetch_optional(&mut *c).await.map_err(db)?;
        let old: Option<store::Source> = old
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| Error::Storage)?;
        match old {
            Some(s) => (
                s.id,
                s.version.checked_add(1).ok_or(Error::Conflict)?,
                s.version,
            ),
            None => (id, 1, 0),
        }
    } else {
        (id, version, version - 1)
    };
    let parent: Option<(Uuid, i64)> = if input.kind == Kind::User {
        Some(sqlx::query_as("SELECT id,version FROM rss_da.psso_sources WHERE tenant_id=$1::uuid AND registration=$2 AND kind='device' AND NOT revoked").bind(&tenant).bind(registration).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?)
    } else {
        None
    };
    // Keys are supplied and proved at completion; these placeholders never enter source storage.
    let empty = PublicKey {
        kty: String::new(),
        crv: String::new(),
        x: String::new(),
        y: String::new(),
    };
    let login_configuration =
        super::deployment::configuration_for_object(c, app.tenant, &object).await?;
    let mut password_identity = None;
    let mut password_provider_revision = None;
    let mut password_provider_fingerprint = None;
    if login_configuration.authentication == AuthenticationMode::Password {
        let provider = rt.password_provider(&login_configuration)?;
        provider.admit_on(c, app.tenant).await?;
        password_provider_revision = Some(provider.configuration.revision);
        password_provider_fingerprint = Some(provider.fingerprint()?);
        if let Some(binding) = &binding {
            password_identity = Some(
                crate::enterprise::subject_on(
                    c,
                    binding.tenant,
                    provider.configuration.id,
                    &binding.person,
                )
                .await?,
            );
        }
    }
    let profile_uuid = rt.profile(&login_configuration)?.uuid;
    let source = store::Source {
        login_configuration,
        profile_uuid,
        password_identity,
        password_provider_revision,
        password_provider_fingerprint,
        id,
        kind: input.kind,
        registration,
        object,
        binding: binding.as_ref().map(|b| b.id),
        binding_generation: binding.as_ref().map_or(0, |b| b.generation),
        parent: parent.map(|p| p.0),
        parent_version: parent.map_or(0, |p| p.1),
        version,
        revoked: false,
        configuration: rt.fingerprint()?,
        signing: None,
        encryption: empty,
        subject,
        subject_version: epochs,
    };
    store::current_object(app, c, &source.object, registration).await?;
    let context = serde_json::to_value(Ceremony {
        principal_registration: p.registration(),
        principal_generation: p.generation(),
        source,
        previous_version: old,
    })
    .map_err(|_| Error::Malformed)?;
    let challenge = challenge(app, c, input.kind.as_str(), &context, now).await?;
    Ok(BootstrapResponse {
        id: challenge.id,
        nonce: challenge.nonce,
        expires_at: challenge.expires_at,
        source_id: id,
        source_version: version,
        endpoints: rt.endpoints.clone(),
        client_id: rt.configuration.client_id,
        login_user_name: id.to_string(),
    })
}

async fn register(
    app: &Context,
    c: &mut PgConnection,
    p: &DevicePrincipal,
    input: &Registration,
    now: i64,
) -> Result<RegistrationReceipt, Error> {
    if p.tenant() != app.tenant {
        return Err(Error::Unauthorized);
    }
    let tenant = p.tenant().to_string();
    let row=sqlx::query("SELECT context,nonce_digest,expires_at,consumed FROM rss_da.psso_challenges WHERE tenant_id=$1::uuid AND id=$2 AND purpose IN('device','user')")
        .bind(&tenant).bind(input.challenge_id).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let mut ceremony: Ceremony =
        serde_json::from_value(row.try_get("context").map_err(db)?).map_err(|_| Error::Storage)?;
    if ceremony.principal_registration != p.registration()
        || ceremony.principal_generation != p.generation()
        || row.try_get::<bool, _>("consumed").map_err(db)?
        || row.try_get::<i64, _>("expires_at").map_err(db)? <= now
    {
        return Err(Error::Unauthorized);
    }
    let s = &mut ceremony.source;
    if s.kind == Kind::User {
        admit(app, c, s).await?;
    }
    let resolved = crate::delivery::resolve_on(c, p).await?;
    if s.object.registration_id != resolved.registration()
        || s.object.generation != resolved.generation()
    {
        return Err(Error::Unauthorized);
    }
    store::fence(c, &tenant).await?;
    store::current_object(app, c, &s.object, s.registration).await?;
    super::deployment::ready(app, c, &s.object, now).await?;
    let current_login =
        super::deployment::configuration_for_object(c, app.tenant, &s.object).await?;
    if s.configuration != app.runtime()?.fingerprint()?
        || s.login_configuration != current_login
        || s.profile_uuid != app.runtime()?.profile(&current_login)?.uuid
    {
        return Err(Error::Unauthorized);
    }
    if let Some(id) = s.binding {
        let b = app
            .registration_binding_on(c, p, id, s.binding_generation)
            .await?;
        if s.login_configuration.authentication == AuthenticationMode::Password {
            let identity = crate::enterprise::subject_on(
                c,
                b.tenant,
                s.login_configuration
                    .password_provider
                    .ok_or(Error::Unauthorized)?,
                &b.person,
            )
            .await?;
            if s.password_identity.as_ref() != Some(&identity) {
                return Err(Error::Unauthorized);
            }
        }
        if Some(subject(app, &b, s.id, s.version)?) != s.subject {
            return Err(Error::Unauthorized);
        }
        let parent = store::source(c, &tenant, s.parent.ok_or(Error::Unauthorized)?).await?;
        if parent.revoked
            || parent.version != s.parent_version
            || parent.object != s.object
            || parent.configuration != s.configuration
        {
            return Err(Error::Unauthorized);
        }
    }
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM rss_da.psso_sources WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE",
    )
    .bind(&tenant)
    .bind(s.id)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?;
    if current.unwrap_or(0) != ceremony.previous_version {
        return Err(Error::Conflict);
    }
    let signing = if s.kind == Kind::User
        && s.login_configuration.authentication == AuthenticationMode::Password
    {
        if input.signing_key.is_some() {
            return Err(Error::Malformed);
        }
        let parent = store::source(c, &tenant, s.parent.ok_or(Error::Unauthorized)?).await?;
        parent.signing.ok_or(Error::Unauthorized)?
    } else {
        input.signing_key.clone().ok_or(Error::Malformed)?
    };
    let proof = crypto::verify(&input.proof, &signing, REGISTRATION_TYPE)?;
    crypto::times(&proof, now)?;
    let proof: RegistrationClaims =
        serde_json::from_value(proof).map_err(|_| Error::Unauthorized)?;
    if proof.aud != format!("{}/register", app.runtime()?.endpoints.base)
        || proof.iss != p.registration()
        || proof.challenge_id != input.challenge_id
        || proof.source_id != s.id
        || proof.source_version != s.version
        || proof.encryption_key_id != crypto::kid(&input.encryption_key)?
        || crypto::digest(&proof.nonce) != row.try_get::<Vec<u8>, _>("nonce_digest").map_err(db)?
    {
        return Err(Error::Unauthorized);
    }
    let accepted=sqlx::query("UPDATE rss_da.psso_challenges SET consumed=true WHERE tenant_id=$1::uuid AND id=$2 AND NOT consumed AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint").bind(&tenant).bind(input.challenge_id).execute(&mut *c).await.map_err(db)?;
    if accepted.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    s.signing = input.signing_key.clone();
    s.encryption = input.encryption_key.clone();
    store::put(c, &tenant, s).await?;
    sqlx::query("DELETE FROM rss_da.psso_tokens WHERE tenant_id=$1::uuid AND source=$2")
        .bind(&tenant)
        .bind(s.id)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(RegistrationReceipt {
        source_id: s.id,
        source_version: s.version,
        kind: s.kind,
        registered: true,
        hardware_attested: false,
        registration_trust: if p.kind()
            == rss_mdm_registration_service::device::RegistrationKind::DaDevice
        {
            RegistrationTrust::DaDevicePop
        } else {
            RegistrationTrust::MdmBootstrapPop
        },
    })
}
async fn login(app: &Context, c: &mut PgConnection, token: &str, now: i64) -> Result<Value, Error> {
    let (_, untrusted) = crypto::unverified(token)?;
    let (_, inner) = crypto::unverified(crypto::text(&untrusted, "assertion")?)?;
    let id = Uuid::parse_str(crypto::text(&inner, "sub")?).map_err(|_| Error::Unauthorized)?;
    // Read a candidate without locks, acquire Identity first, then recheck all host state.
    let candidate = store::read(c, &app.tenant.to_string(), id).await?;
    admit(app, c, &candidate).await?;
    let (user, device, binding) = store::current_user(app, c, id, true).await?;
    if user.subject != candidate.subject
        || user.subject_version != candidate.subject_version
        || Some(subject(app, &binding, user.id, user.version)?) != user.subject
    {
        return Err(Error::Unauthorized);
    }
    let nonce = crypto::text(&untrusted, "request_nonce")?;
    if nonce.len() != 43 {
        return Err(Error::Unauthorized);
    }
    let (client_nonce, apv) = super::native::verify(
        app.runtime()?,
        device.signing.as_ref().ok_or(Error::Unauthorized)?,
        user.signing.as_ref().ok_or(Error::Unauthorized)?,
        user.id,
        token,
        nonce,
        now,
    )?;
    let tenant = app.tenant.to_string();
    let accepted=sqlx::query("UPDATE rss_da.psso_challenges SET consumed=true WHERE tenant_id=$1::uuid AND purpose='login' AND nonce_digest=$2 AND NOT consumed AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint")
        .bind(&tenant).bind(crypto::digest(nonce)).execute(&mut *c).await.map_err(db)?;
    if accepted.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    let access = crypto::random()?;
    let refresh = crypto::random()?;
    sqlx::query("DELETE FROM rss_da.psso_tokens WHERE tenant_id=$1::uuid AND source=$2")
        .bind(&tenant)
        .bind(id)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query("INSERT INTO rss_da.psso_tokens(tenant_id,digest,source,version,expires_at) VALUES($1::uuid,$2,$3,$4,$5)")
        .bind(&tenant).bind(crypto::digest(&access)).bind(id).bind(user.version).bind(now+TOKEN_SECONDS).execute(&mut *c).await.map_err(db)?;
    super::native::response(
        app.runtime()?,
        &user,
        &client_nonce,
        &apv,
        now,
        &access,
        &refresh,
    )
}
async fn revoke(
    app: &Context,
    c: &mut PgConnection,
    p: &DevicePrincipal,
    id: Uuid,
    expected_version: i64,
) -> Result<RevocationReceipt, Error> {
    if expected_version < 1 {
        return Err(Error::Malformed);
    }
    if p.tenant() != app.tenant {
        return Err(Error::Unauthorized);
    }
    let tenant = p.tenant().to_string();
    let resolved = crate::delivery::resolve_on(c, p).await?;
    store::fence(c, &tenant).await?;
    let mut source = store::source(c, &tenant, id).await?;
    if source.object.registration_id != resolved.registration()
        || source.object.generation != resolved.generation()
        || source.object.device != resolved.device()
    {
        return Err(Error::Unauthorized);
    }
    store::current_object(app, c, &source.object, source.registration).await?;
    // The source row is locked by store::source in the same transaction as replacement.
    // Replaying the exact already-completed revocation is allowed; a replacement is not.
    if source.version != expected_version
        && !(source.revoked && expected_version.checked_add(1) == Some(source.version))
    {
        return Err(Error::Conflict);
    }
    if !source.revoked {
        source.revoked = true;
        source.version = source.version.checked_add(1).ok_or(Error::Conflict)?;
        store::put(c, &tenant, &source).await?;
    }
    sqlx::query("DELETE FROM rss_da.psso_tokens WHERE tenant_id=$1::uuid AND (source=$2 OR source IN(SELECT id FROM rss_da.psso_sources WHERE tenant_id=$1::uuid AND parent=$2))")
        .bind(&tenant).bind(id).execute(c).await.map_err(db)?;
    Ok(RevocationReceipt {
        source_id: id,
        source_version: source.version,
        revoked: true,
    })
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Nonce {
    id: Uuid,
    nonce: String,
    expires_at: i64,
}
pub enum Outcome {
    Bootstrap(BootstrapResponse),
    Registration(RegistrationReceipt),
    Nonce(Nonce),
    Login(Value),
    Revocation(RevocationReceipt),
}
impl Outcome {
    pub fn bootstrap(self) -> Result<BootstrapResponse, Error> {
        match self {
            Self::Bootstrap(value) => Ok(value),
            _ => Err(Error::Storage),
        }
    }
}
impl Outcome {
    pub fn registration(self) -> Result<RegistrationReceipt, Error> {
        match self {
            Self::Registration(value) => Ok(value),
            _ => Err(Error::Storage),
        }
    }
}
impl Outcome {
    pub fn nonce(self) -> Result<Nonce, Error> {
        match self {
            Self::Nonce(value) => Ok(value),
            _ => Err(Error::Storage),
        }
    }
}
impl Outcome {
    pub fn login(self) -> Result<Value, Error> {
        match self {
            Self::Login(value) => Ok(value),
            _ => Err(Error::Storage),
        }
    }
}
impl Outcome {
    pub fn revocation(self) -> Result<RevocationReceipt, Error> {
        match self {
            Self::Revocation(value) => Ok(value),
            _ => Err(Error::Storage),
        }
    }
}
