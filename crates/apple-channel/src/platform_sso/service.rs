//! Native registration writes settle with the existing Audit transaction owner.
use super::*;
use crate::database::db;
use rss_identity_postgres::platform::{
    PlatformBinding, PlatformSubjectVersion, admit_platform_subject_on,
};
use rss_mdm_apple_mdm::platform_sso::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::{
    DevicePrincipal,
    device_access::{Binding, storage as bindings},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Device,
    User,
}
impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::User => "user",
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Bootstrap {
    pub operation_id: Uuid,
    pub kind: Kind,
    pub binding_id: Option<Uuid>,
    pub binding_generation: Option<i64>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ceremony {
    principal_registration: Uuid,
    principal_generation: i64,
    source: store::Source,
    previous_version: i64,
}
#[derive(Serialize)]
pub(super) enum Action {
    Bootstrap(Bootstrap),
    Register(Registration),
    Nonce,
    Login(String),
    Revoke(Uuid),
}
pub(super) async fn mutate(
    app: &Context,
    principal: Option<&DevicePrincipal>,
    audit: &RequestAudit,
    action: Action,
) -> Result<Value, Error> {
    app.runtime()?;
    let operation = match &action {
        Action::Bootstrap(v) => v.operation_id,
        Action::Register(v) => v.operation_id,
        _ => Uuid::new_v4(),
    };
    if operation.is_nil() {
        return Err(Error::Malformed);
    }
    audit.operation(operation, "apple_platform_sso");
    let fingerprint =
        crypto::digest(&serde_json::to_string(&action).map_err(|_| Error::Malformed)?);
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let outcome = app
        .audit_store
        .write(
            app.tenant,
            &budget.control(),
            (app, principal, audit, &action, &fingerprint, operation),
            |(app, principal, audit, action, fingerprint, operation), tx| {
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
                        &format!("apple-platform-sso:{operation}"),
                        fingerprint,
                        200,
                        "success",
                        None,
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact, false)
                        .await
                        .map_err(Error::from)?;
                    audit.mark_commit_started();
                    Ok(value)
                })
            },
        )
        .await;
    crate::operations::settle(outcome, audit)
}
pub(super) fn subject(
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
pub(super) async fn admit(
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
            _ => Error::Unavailable(crate::Failure::Database),
        })
}
async fn apply(
    app: &Context,
    c: &mut PgConnection,
    p: Option<&DevicePrincipal>,
    a: &Action,
) -> Result<Value, Error> {
    let now = store::now(c).await?;
    match a {
        Action::Bootstrap(v) => bootstrap(app, c, p.ok_or(Error::Unauthorized)?, v, now).await,
        Action::Register(v) => register(app, c, p.ok_or(Error::Unauthorized)?, v, now).await,
        Action::Nonce => {
            let tenant = app.tenant.to_string();
            // Serialized bounded capacity; never hold this lock before the Identity guard.
            store::fence(c, &tenant).await?;
            challenge(app, c, "login", &json!({}), now).await
        }
        Action::Login(token) => login(app, c, token, now).await,
        Action::Revoke(id) => revoke(app, c, p.ok_or(Error::Unauthorized)?, *id).await,
    }
}
async fn challenge(
    app: &Context,
    c: &mut PgConnection,
    purpose: &str,
    context: &Value,
    now: i64,
) -> Result<Value, Error> {
    let tenant = app.tenant.to_string();
    store::cleanup(c, &tenant, now).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_apple.psso_challenges WHERE tenant_id=$1::uuid AND (purpose='login')=$2",
    )
    .bind(&tenant)
    .bind(purpose == "login")
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if count >= 4096 {
        return Err(Error::Unavailable(crate::Failure::Capacity));
    }
    let id = Uuid::new_v4();
    let nonce = crypto::random()?;
    sqlx::query("INSERT INTO mdm_apple.psso_challenges(tenant_id,id,purpose,nonce_digest,expires_at,context) VALUES($1::uuid,$2,$3,$4,$5,$6)").bind(tenant).bind(id).bind(purpose).bind(crypto::digest(&nonce)).bind(now+NONCE_SECONDS).bind(context).execute(c).await.map_err(db)?;
    Ok(json!({"id":id,"nonce":nonce,"expiresAt":now+NONCE_SECONDS}))
}
async fn bootstrap(
    app: &Context,
    c: &mut PgConnection,
    p: &DevicePrincipal,
    input: &Bootstrap,
    now: i64,
) -> Result<Value, Error> {
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
        sqlx::query_scalar("SELECT document FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND binding=$2 AND kind='user'").bind(&tenant).bind(b.id).fetch_optional(&mut *c).await.map_err(db)?
    } else {
        None
    };
    let previous: Option<store::Source> = existing
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
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
                    _ => Error::Unavailable(crate::Failure::Database),
                })?,
        )
    } else {
        None
    };
    store::fence(c, &tenant).await?;
    let object = app
        .platform_objects
        .paired_in(c, p.tenant(), p.device())
        .await
        .map_err(db)?;
    super::deployment::ready(app, c, &object, now).await?;
    let apple = object
        .members
        .iter()
        .find(|m| m.channel == rss_mdm_inventory::Channel::Mdm)
        .ok_or(Error::Unauthorized)?
        .registration_id;
    if !object
        .members
        .iter()
        .any(|m| m.registration_id == p.registration() && m.generation == p.generation())
    {
        return Err(Error::Unauthorized);
    }
    let binding = if let Some(b) = candidate {
        let current = app
            .execution
            .registration_access_binding_on(
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
        let old:Option<Value>=sqlx::query_scalar("SELECT document FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND registration=$2 AND kind='device'").bind(&tenant).bind(apple).fetch_optional(&mut *c).await.map_err(db)?;
        let old: Option<store::Source> = old
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
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
        Some(sqlx::query_as("SELECT id,version FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND registration=$2 AND kind='device' AND NOT revoked").bind(&tenant).bind(apple).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?)
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
    let source = store::Source {
        id,
        kind: input.kind,
        registration: apple,
        object,
        binding: binding.as_ref().map(|b| b.id),
        binding_generation: binding.as_ref().map_or(0, |b| b.generation),
        parent: parent.map(|p| p.0),
        parent_version: parent.map_or(0, |p| p.1),
        version,
        revoked: false,
        configuration: rt.fingerprint()?,
        signing: empty.clone(),
        encryption: empty,
        subject,
        subject_version: epochs,
    };
    store::current_object(app, c, &source.object, apple).await?;
    let context = serde_json::to_value(Ceremony {
        principal_registration: p.registration(),
        principal_generation: p.generation(),
        source,
        previous_version: old,
    })
    .map_err(|_| Error::Malformed)?;
    let mut value = challenge(app, c, input.kind.as_str(), &context, now).await?;
    value["sourceId"] = json!(id);
    value["sourceVersion"] = json!(version);
    value["endpoints"] = serde_json::to_value(&rt.endpoints).map_err(|_| Error::Malformed)?;
    value["clientId"] = json!(rt.configuration.client_id);
    value["loginUserName"] = json!(id);
    Ok(value)
}

async fn register(
    app: &Context,
    c: &mut PgConnection,
    p: &DevicePrincipal,
    input: &Registration,
    now: i64,
) -> Result<Value, Error> {
    if p.tenant() != app.tenant {
        return Err(Error::Unauthorized);
    }
    let tenant = p.tenant().to_string();
    let row=sqlx::query("SELECT context,nonce_digest,expires_at,consumed FROM mdm_apple.psso_challenges WHERE tenant_id=$1::uuid AND id=$2 AND purpose IN('device','user')")
        .bind(&tenant).bind(input.challenge_id).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let mut ceremony: Ceremony = serde_json::from_value(row.try_get("context").map_err(db)?)
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
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
    store::fence(c, &tenant).await?;
    store::current_object(app, c, &s.object, s.registration).await?;
    super::deployment::ready(app, c, &s.object, now).await?;
    if s.configuration != app.runtime()?.fingerprint()? {
        return Err(Error::Unauthorized);
    }
    if let Some(id) = s.binding {
        let b = app
            .execution
            .registration_access_binding_on(c, p, id, s.binding_generation)
            .await?;
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
        "SELECT version FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE",
    )
    .bind(&tenant)
    .bind(s.id)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?;
    if current.unwrap_or(0) != ceremony.previous_version {
        return Err(Error::Conflict);
    }
    let proof = crypto::verify(
        &input.proof,
        &input.signing_key,
        "rss-mdm-platform-sso-registration+jwt",
    )?;
    crypto::times(&proof, now)?;
    if crypto::text(&proof, "aud")? != format!("{}/register", app.runtime()?.endpoints.base)
        || crypto::text(&proof, "iss")? != p.registration().to_string()
        || crypto::text(&proof, "challengeId")? != input.challenge_id.to_string()
        || crypto::text(&proof, "sourceId")? != s.id.to_string()
        || proof.get("sourceVersion").and_then(Value::as_i64) != Some(s.version)
        || crypto::text(&proof, "encryptionKeyId")? != crypto::kid(&input.encryption_key)?
        || crypto::digest(crypto::text(&proof, "nonce")?)
            != row.try_get::<Vec<u8>, _>("nonce_digest").map_err(db)?
    {
        return Err(Error::Unauthorized);
    }
    let accepted=sqlx::query("UPDATE mdm_apple.psso_challenges SET consumed=true WHERE tenant_id=$1::uuid AND id=$2 AND NOT consumed AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint").bind(&tenant).bind(input.challenge_id).execute(&mut *c).await.map_err(db)?;
    if accepted.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    s.signing = input.signing_key.clone();
    s.encryption = input.encryption_key.clone();
    store::put(c, &tenant, s).await?;
    sqlx::query("DELETE FROM mdm_apple.psso_tokens WHERE tenant_id=$1::uuid AND source=$2")
        .bind(&tenant)
        .bind(s.id)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(
        json!({"sourceId":s.id,"sourceVersion":s.version,"kind":s.kind,"registered":true,"hardwareAttested":false,"registrationTrust":"mdm_bootstrap_pop"}),
    )
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
        &device.signing,
        &user.signing,
        user.id,
        token,
        nonce,
        now,
    )?;
    let tenant = app.tenant.to_string();
    let accepted=sqlx::query("UPDATE mdm_apple.psso_challenges SET consumed=true WHERE tenant_id=$1::uuid AND purpose='login' AND nonce_digest=$2 AND NOT consumed AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint")
        .bind(&tenant).bind(crypto::digest(nonce)).execute(&mut *c).await.map_err(db)?;
    if accepted.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    let access = crypto::random()?;
    let refresh = crypto::random()?;
    sqlx::query("DELETE FROM mdm_apple.psso_tokens WHERE tenant_id=$1::uuid AND source=$2")
        .bind(&tenant)
        .bind(id)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query("INSERT INTO mdm_apple.psso_tokens(tenant_id,digest,source,version,expires_at) VALUES($1::uuid,$2,$3,$4,$5)")
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
) -> Result<Value, Error> {
    if p.tenant() != app.tenant {
        return Err(Error::Unauthorized);
    }
    let tenant = p.tenant().to_string();
    store::fence(c, &tenant).await?;
    let mut source = store::source(c, &tenant, id).await?;
    store::current_object(app, c, &source.object, source.registration).await?;
    if !source
        .object
        .members
        .iter()
        .any(|m| m.registration_id == p.registration() && m.generation == p.generation())
    {
        return Err(Error::Unauthorized);
    }
    if !source.revoked {
        source.revoked = true;
        source.version = source.version.checked_add(1).ok_or(Error::Conflict)?;
        store::put(c, &tenant, &source).await?;
    }
    sqlx::query("DELETE FROM mdm_apple.psso_tokens WHERE tenant_id=$1::uuid AND (source=$2 OR source IN(SELECT id FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND parent=$2))")
        .bind(&tenant).bind(id).execute(c).await.map_err(db)?;
    Ok(json!({"sourceId":id,"sourceVersion":source.version,"revoked":true}))
}
