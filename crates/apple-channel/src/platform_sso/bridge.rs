//! P2 adapter: native token plus a purpose-specific PoP, bound to Identity's browser challenge.
use super::*;
use rss_identity_postgres::platform::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin, sync::OnceLock};
use uuid::Uuid;
type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, PlatformError>> + Send + 'a>>;

pub struct Verifier {
    audience: String,
    app: OnceLock<super::context::Binding>,
}
impl Verifier {
    pub fn new(origin: &str) -> Self {
        Self {
            audience: format!("{origin}/login"),
            app: OnceLock::new(),
        }
    }
    pub fn bind(&self, app: &Arc<HttpState>) -> Result<(), Error> {
        let candidate = Context::new(app);
        if let Some(bound) = self.app.get() {
            return if bound.matches(&candidate) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.app
            .set(super::context::Binding::new(candidate))
            .map_err(|_| Error::Conflict)
    }
    fn app(&self) -> Result<Context, PlatformError> {
        self.app
            .get()
            .and_then(super::context::Binding::get)
            .ok_or(PlatformError::Unavailable)
    }
}
fn failure(error: Error) -> PlatformError {
    match error {
        Error::Unavailable(_)
        | Error::Configuration(_)
        | Error::CommitUnknown
        | Error::RollbackFailed => PlatformError::Unavailable,
        _ => PlatformError::Rejected,
    }
}
async fn current(
    app: &Context,
    c: &mut PgConnection,
    id: Uuid,
) -> Result<PlatformBinding, PlatformError> {
    let candidate = store::read(c, &app.tenant.to_string(), id)
        .await
        .map_err(failure)?;
    service::admit(app, c, &candidate).await.map_err(failure)?;
    let (user, _, binding) = store::current_user(app, c, id, true)
        .await
        .map_err(failure)?;
    let subject = service::subject(app, &binding, id, user.version).map_err(failure)?;
    if user.subject.as_ref() != Some(&subject)
        || candidate.subject != user.subject
        || candidate.subject_version != user.subject_version
    {
        return Err(PlatformError::Rejected);
    }
    Ok(subject)
}
impl PlatformVerifier for Verifier {
    fn audience(&self) -> &str {
        &self.audience
    }
    fn resolve<'a>(
        &'a self,
        instance: rss_identity_core::InstanceId,
        tenant: TenantId,
        binding: Uuid,
        c: &'a mut PgConnection,
    ) -> Pending<'a, PlatformBinding> {
        Box::pin(async move {
            let app = self.app()?;
            if tenant != app.tenant || instance != app.instance {
                return Err(PlatformError::Rejected);
            }
            let id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND binding=$2 AND kind='user' AND NOT revoked")
            .bind(tenant.to_string()).bind(binding).fetch_optional(&mut *c).await.map_err(|_|PlatformError::Unavailable)?;
            current(&app, c, id.ok_or(PlatformError::Rejected)?).await
        })
    }
    fn verify<'a>(
        &'a self,
        challenge: &'a PlatformChallengeContext,
        evidence: &'a [u8],
    ) -> Pending<'a, PlatformEvidence> {
        Box::pin(async move {
            let app = self.app()?;
            if challenge.binding.account.tenant != app.tenant || challenge.audience != self.audience
            {
                return Err(PlatformError::Rejected);
            }
            let token = std::str::from_utf8(evidence).map_err(|_| PlatformError::Rejected)?;
            let mut tx = app
                .access
                .begin(&app.tenant.to_string())
                .await
                .map_err(|_| PlatformError::Unavailable)?;
            // No host authority lock is taken before Identity's guard.
            let subject = current(&app, &mut tx, challenge.binding.source_id).await?;
            if subject != challenge.binding {
                return Err(PlatformError::Rejected);
            }
            let user = store::read(&mut tx, &app.tenant.to_string(), subject.source_id)
                .await
                .map_err(failure)?;
            let claims = crypto::verify(
                token,
                &user.signing,
                rss_mdm_apple_mdm::platform_sso::BRIDGE_TYPE,
            )
            .map_err(failure)?;
            let now = store::now(&mut tx).await.map_err(failure)?;
            crypto::times(&claims, now).map_err(failure)?;
            if crypto::text(&claims, "iss").map_err(failure)? != user.id.to_string()
                || crypto::text(&claims, "aud").map_err(failure)? != challenge.audience
                || crypto::text(&claims, "nonce").map_err(failure)? != challenge.nonce
                || claims
                    .get("sourceVersion")
                    .and_then(serde_json::Value::as_i64)
                    != Some(user.version)
            {
                return Err(PlatformError::Rejected);
            }
            let access = crypto::text(&claims, "accessToken").map_err(failure)?;
            if access.len() != 43 {
                return Err(PlatformError::Rejected);
            }
            let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_apple.psso_tokens WHERE tenant_id=$1::uuid AND digest=$2 AND source=$3 AND version=$4 AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint)")
            .bind(app.tenant.to_string()).bind(crypto::digest(access)).bind(user.id).bind(user.version).fetch_one(&mut *tx).await.map_err(|_|PlatformError::Unavailable)?;
            if !valid {
                return Err(PlatformError::Rejected);
            }
            Ok(PlatformEvidence {
                key_possession: true,
                hardware_key: false,
                user_presence: false,
                user_verification: false,
                authenticated_at: None,
                profile: PlatformProfile::Unavailable,
            })
        })
    }
    fn recheck<'a>(
        &'a self,
        binding: &'a PlatformBinding,
        c: &'a mut PgConnection,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let app = self.app()?;
            if binding.account.tenant != app.tenant
                || current(&app, c, binding.source_id).await? != *binding
            {
                return Err(PlatformError::Rejected);
            }
            Ok(())
        })
    }
}
