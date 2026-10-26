//! RP interactions are business contexts, not a second authentication/session authority.
use super::*;
use crate::device_access::{Admission, Binding};
use rss_identity_postgres::{AuthenticatedSession, RevalidatedSession, SessionReference};
use rss_mdm_agent_wire::{
    enterprise as wire,
    runtime::{AccessLocalSession, Secret},
};
use rss_mdm_native_protection::ProtectionContext;
use std::{future::Future, pin::Pin};
use zeroize::Zeroizing;

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
/// Configured backend client. No browser input chooses its issuer, credentials or scopes.
pub trait Client: Send + Sync {
    fn target(&self) -> &rss_identity_core::enterprise::EnterpriseTarget;
    fn provider(&self) -> Uuid;
    fn fingerprint(&self) -> &str;
    fn authenticate(&self, credential: &str) -> bool;
    fn exchange<'a>(
        &'a self,
        assertion: &'a str,
        expires: i64,
        subject: &'a str,
    ) -> Pending<'a, ExchangeToken>;
}
pub struct ExchangeToken {
    pub token: Zeroizing<String>,
    pub subject: String,
    pub expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    pub id: Uuid,
    pub binding: Binding,
    pub digest: [u8; 32],
    pub local_session: AccessLocalSession,
    pub relying_party: RelyingParty,
    pub subject: Subject,
    pub phase: wire::Phase,
    pub expires_at: i64,
    pub challenge: Option<wire::Challenge>,
    pub attempt: Option<Uuid>,
    pub reference: Option<SessionReference>,
    pub identity_session: Option<Uuid>,
    pub consume_operation: Option<Uuid>,
    browser_digest: [u8; 32],
    continuation_digest: Option<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
struct Handoff {
    #[serde(deserialize_with = "secret_text")]
    access_token: Zeroizing<String>,
    continuation: Secret,
    subject: String,
    expires_at: i64,
}
fn secret_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Consumed {
    pub session: Uuid,
    #[schemars(with = "String")]
    pub access_token: Zeroizing<String>,
    pub subject: String,
    pub expires_at: i64,
}
fn hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn random() -> Result<Secret, Error> {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .map_err(|_| Error::Runtime)?;
    Secret::parse(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| Error::Corrupt)
}
fn browser_matches(context: &Context, browser: &Secret) -> Result<(), Error> {
    use subtle::ConstantTimeEq;
    if bool::from(context.browser_digest.ct_eq(&hash(browser.expose()))) {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}
fn continuation_matches(context: &Context, continuation: &Secret) -> Result<(), Error> {
    use subtle::ConstantTimeEq;
    if context
        .continuation_digest
        .is_some_and(|d| bool::from(d.ct_eq(&hash(continuation.expose()))))
    {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}
fn aad(
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    ProtectionContext::new(tenant, &id.to_string(), "enterprise.broker.handoff", 1)
        .map(|v| v.derive())
        .map_err(|_| Error::Configuration)
}
async fn load(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    locked: bool,
) -> Result<(Context, Option<Vec<u8>>), Error> {
    use sqlx::Row;
    let sql = if locked {
        "SELECT document,sealed FROM mdm_enterprise.brokers WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
    } else {
        "SELECT document,sealed FROM mdm_enterprise.brokers WHERE tenant_id=$1 AND id=$2"
    };
    let row = sqlx::query(sql)
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
        .map_err(db)?
        .ok_or(Error::NotFound)?;
    let context: Context =
        serde_json::from_value(row.try_get("document").map_err(db)?).map_err(|_| Error::Corrupt)?;
    if context.id != id
        || context.binding.tenant != tenant
        || context.subject.person != context.binding.person
    {
        return Err(Error::Corrupt);
    }
    context.binding.validate()?;
    Ok((context, row.try_get("sealed").map_err(db)?))
}
async fn save(c: &mut PgConnection, value: &Context, sealed: Option<&[u8]>) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_enterprise.brokers SET document=$3,sealed=$4,expires_at=$5,phase=$6 WHERE tenant_id=$1 AND id=$2")
        .bind(value.binding.tenant).bind(value.id).bind(serde_json::to_value(value).map_err(|_|Error::Corrupt)?).bind(sealed).bind(value.expires_at)
        .bind(serde_json::to_value(value.phase).map_err(|_|Error::Corrupt)?.as_str().ok_or(Error::Corrupt)?).execute(c).await.map_err(db)?;
    Ok(())
}
async fn qualify(
    c: &mut PgConnection,
    context: &Context,
    admission: &dyn Admission,
) -> Result<(), Error> {
    let b = crate::device_access::storage::require_active_in(
        c,
        context.binding.tenant,
        context.binding.id,
        context.binding.generation,
    )
    .await?;
    crate::device_access::lifecycle::require_subject_on(c, b.tenant, &b.person).await?;
    if b.definition_digest()? != context.digest
        || admission.binding_session(c, b.tenant, &b).await? != context.local_session
    {
        return Err(Error::Forbidden);
    }
    let policy = admission.policy(c, b.tenant, &b.device, b.policy).await?;
    if policy.version != b.policy_version || policy.configuration != b.configuration {
        return Err(Error::Forbidden);
    }
    let rp = relying_party_on(c, b.tenant, &context.relying_party.id).await?;
    if !rp.enabled
        || rp.revision != context.relying_party.revision
        || rp.callback != context.relying_party.callback
        || rp.target_fingerprint != context.relying_party.target_fingerprint
    {
        return Err(Error::Forbidden);
    }
    let subject = subject_on(c, b.tenant, context.subject.provider, &b.person).await?;
    if subject != context.subject {
        return Err(Error::Forbidden);
    }
    Ok(())
}

fn tenant(service: &Service) -> Result<Uuid, Error> {
    Uuid::parse_str(&service.tenant.to_string()).map_err(|_| Error::Configuration)
}
fn terminal_phase(context: &Context, now: i64) -> wire::Phase {
    if context.phase == wire::Phase::Consumed || context.phase == wire::Phase::Cancelled {
        context.phase
    } else if now >= context.expires_at {
        if context.phase == wire::Phase::Completing {
            wire::Phase::Unknown
        } else {
            wire::Phase::Expired
        }
    } else {
        context.phase
    }
}
impl Service {
    pub async fn broker_prepare(
        &self,
        input: &wire::Begin,
        browser: &Secret,
        client: &dyn Client,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<(Context, bool), Error> {
        if input.operation_id.is_nil()
            || input.binding_id.is_nil()
            || input.relying_party != client.target().id
        {
            return Err(Error::Malformed);
        }
        audit.operation(
            input.operation_id,
            "enterprise_broker_prepare",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(audit,(self,input,browser,client,admission),|ctx,c|Box::pin(async move{
            let (service,input,browser,client,admission)=ctx;let tenant=tenant(service)?;
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_enterprise.brokers WHERE tenant_id=$1 AND id=$2)").bind(tenant).bind(input.operation_id).fetch_one(&mut *c).await.map_err(db)?;
            if exists {
                let (old,_)=load(c,tenant,input.operation_id,true).await?;browser_matches(&old,browser)?;
                if old.binding.id!=input.binding_id||old.relying_party.id!=input.relying_party||old.relying_party.target_fingerprint!=client.fingerprint(){return Err(Error::Conflict);}
                return Ok(AuditedChange{value:(old,false), replay:true});
            }
            let now=rss_mdm_webhook_service::events::now_on(c).await.map_err(|_|Error::Storage)?;
            // Preserve operation receipts; expired backend tokens are the only material discarded here.
            sqlx::query("UPDATE mdm_enterprise.brokers SET sealed=NULL WHERE tenant_id=$1 AND id IN(SELECT id FROM mdm_enterprise.brokers WHERE tenant_id=$1 AND expires_at<=$2 AND sealed IS NOT NULL LIMIT 128)").bind(tenant).bind(now).execute(&mut *c).await.map_err(db)?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_enterprise.brokers WHERE tenant_id=$1 AND expires_at>$2 AND phase NOT IN('consumed','cancelled','failed','expired')").bind(tenant).bind(now).fetch_one(&mut *c).await.map_err(db)?;
            if count>=1024{return Err(Error::Capacity);}
            let candidate=crate::device_access::storage::get_in(c,tenant,input.binding_id).await?;
            let binding=crate::device_access::storage::require_active_in(c,tenant,input.binding_id,candidate.generation).await?;
            crate::device_access::lifecycle::require_subject_on(c,tenant,&binding.person).await?;
            let rp=relying_party_on(c,tenant,&input.relying_party).await?;
            if !rp.enabled||rp.target_fingerprint!=client.fingerprint(){return Err(Error::Forbidden);}
            let local_session=admission.binding_session(c,tenant,&binding).await?;
            let subject=subject_on(c,tenant,client.provider(),&binding.person).await?;
            let value=Context{id:input.operation_id,digest:binding.definition_digest()?,binding,local_session,relying_party:rp,subject,phase:wire::Phase::Preparing,expires_at:now+120,challenge:None,attempt:None,reference:None,identity_session:None,consume_operation:None,browser_digest:hash(browser.expose()),continuation_digest:None};
            qualify(c,&value,*admission).await?;
            sqlx::query("INSERT INTO mdm_enterprise.brokers(tenant_id,id,document,expires_at,phase) VALUES($1,$2,$3,$4,'preparing')")
                .bind(tenant).bind(value.id).bind(serde_json::to_value(&value).map_err(|_|Error::Malformed)?).bind(value.expires_at).execute(c).await.map_err(db)?;
            Ok(AuditedChange{value:(value,true), replay:false})
        })).await
    }
    pub async fn broker_attach_challenge(
        &self,
        id: Uuid,
        browser: &Secret,
        challenge: rss_identity_postgres::platform::PlatformChallenge,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<wire::Challenge, Error> {
        audit.operation(
            id,
            "enterprise_broker_challenge",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(
            audit,
            (self, id, browser, challenge, admission),
            |ctx, c| {
                Box::pin(async move {
                    let (service, id, browser, challenge, admission) = ctx;
                    let (mut value, _) = load(c, tenant(service)?, *id, true).await?;
                    browser_matches(&value, browser)?;
                    if value.phase != wire::Phase::Preparing {
                        return Err(Error::Conflict);
                    }
                    qualify(c, &value, *admission).await?;
                    value.expires_at = value.expires_at.min(challenge.expires_at);
                    let response = wire::Challenge {
                        operation_id: *id,
                        challenge_id: challenge.id,
                        nonce: challenge.nonce.clone(),
                        signing_payload: challenge.signing_payload.clone(),
                        local_session: value.local_session.clone(),
                        expires_at: value.expires_at,
                    };
                    value.challenge = Some(response.clone());
                    value.phase = wire::Phase::AwaitingProof;
                    save(c, &value, None).await?;
                    Ok(AuditedChange {
                        value: response,
                        replay: false,
                    })
                })
            },
        )
        .await
    }
    pub async fn broker_claim(
        &self,
        input: &wire::Complete,
        browser: &Secret,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<Context, Error> {
        audit.operation(
            input.operation_id,
            "enterprise_broker_claim",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(audit, (self, input, browser, admission), |ctx, c| {
            Box::pin(async move {
                let (service, input, browser, admission) = ctx;
                let (mut value, _) = load(c, tenant(service)?, input.operation_id, true).await?;
                browser_matches(&value, browser)?;
                let now = rss_mdm_webhook_service::events::now_on(c)
                    .await
                    .map_err(|_| Error::Storage)?;
                if terminal_phase(&value, now) != wire::Phase::AwaitingProof {
                    return Err(Error::Conflict);
                }
                let challenge = value.challenge.as_ref().ok_or(Error::Corrupt)?;
                if challenge.challenge_id != input.challenge_id || challenge.nonce != input.nonce {
                    return Err(Error::Forbidden);
                }
                qualify(c, &value, *admission).await?;
                value.phase = wire::Phase::Completing;
                value.attempt = Some(Uuid::new_v4());
                save(c, &value, None).await?;
                Ok(AuditedChange {
                    value,
                    replay: false,
                })
            })
        })
        .await
    }
    pub async fn broker_fail(
        &self,
        id: Uuid,
        attempt: Uuid,
        browser: &Secret,
        unknown: bool,
        audit: &RequestAudit,
    ) -> Result<(), Error> {
        audit.operation(
            id,
            "enterprise_broker_failure",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(audit, (self, id, attempt, browser, unknown), |ctx, c| {
            Box::pin(async move {
                let (service, id, attempt, browser, unknown) = ctx;
                let (mut value, sealed) = load(c, tenant(service)?, *id, true).await?;
                browser_matches(&value, browser)?;
                if value.attempt != Some(*attempt) {
                    return Err(Error::Conflict);
                }
                if value.phase == wire::Phase::Completing {
                    value.phase = if *unknown {
                        wire::Phase::Unknown
                    } else {
                        wire::Phase::Failed
                    };
                    save(c, &value, sealed.as_deref()).await?;
                }
                Ok(AuditedChange {
                    value: (),
                    replay: false,
                })
            })
        })
        .await
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Identity or RP authority, browser proof and frozen operation coordinates are independently validated"
    )]
    pub async fn broker_finish(
        &self,
        id: Uuid,
        attempt: Uuid,
        browser: &Secret,
        actor: &AuthenticatedSession,
        token: ExchangeToken,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<wire::Status, Error> {
        audit.operation(
            id,
            "enterprise_broker_ready",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write_admitted(
            &self.access_audit,
            audit,
            (self, id, attempt, browser, actor, token, admission),
            |ctx, c| {
                Box::pin(async move {
                    rss_identity_postgres::recheck_authenticated_session_on(c, ctx.4)
                        .await
                        .map_err(|_| Error::Unauthorized)
                })
            },
            |ctx, c| {
                Box::pin(async move {
                    let (service, id, attempt, browser, actor, token, admission) = ctx;
                    let (mut value, _) = load(c, tenant(service)?, *id, true).await?;
                    browser_matches(&value, browser)?;
                    let now = rss_mdm_webhook_service::events::now_on(c)
                        .await
                        .map_err(|_| Error::Storage)?;
                    if terminal_phase(&value, now) != wire::Phase::Completing
                        || value.attempt != Some(*attempt)
                        || token.expires_at <= now
                        || token.expires_at > now + 30
                        || token.subject != value.subject.subject
                    {
                        return Err(Error::Conflict);
                    }
                    if actor.account().tenant != service.tenant
                        || actor.instance().as_uuid() != value.binding.person.instance
                        || actor.account().principal.as_uuid() != value.binding.person.principal
                    {
                        return Err(Error::Forbidden);
                    }
                    qualify(c, &value, *admission).await?;
                    value.reference = Some(actor.reference().map_err(|_| Error::Unauthorized)?);
                    value.identity_session = Some(actor.view().id.as_uuid());
                    let continuation = random()?;
                    value.continuation_digest = Some(hash(continuation.expose()));
                    value.phase = wire::Phase::Ready;
                    value.expires_at = value.expires_at.min(token.expires_at);
                    let handoff = Handoff {
                        access_token: Zeroizing::new(token.token.to_string()),
                        continuation: continuation.clone(),
                        subject: token.subject.clone(),
                        expires_at: token.expires_at,
                    };
                    let plain =
                        Zeroizing::new(serde_json::to_vec(&handoff).map_err(|_| Error::Corrupt)?);
                    let sealed = service
                        .protection
                        .seal_bytes(&plain, &aad(service.tenant, *id)?)
                        .map_err(|_| Error::Configuration)?;
                    save(c, &value, Some(&sealed)).await?;
                    let status = wire::Status {
                        operation_id: *id,
                        phase: value.phase,
                        expires_at: value.expires_at,
                        callback: Some(value.relying_party.callback.clone()),
                        continuation: Some(continuation),
                    };
                    Ok(AuditedChange {
                        value: status,
                        replay: false,
                    })
                })
            },
        )
        .await
    }
    pub async fn broker_status(
        &self,
        id: Uuid,
        browser: &Secret,
        admission: &dyn Admission,
    ) -> Result<wire::Status, Error> {
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        let (value, sealed) = load(&mut tx, tenant(self)?, id, false).await?;
        browser_matches(&value, browser)?;
        let now = rss_mdm_webhook_service::events::now_on(&mut tx)
            .await
            .map_err(|_| Error::Storage)?;
        let phase = terminal_phase(&value, now);
        let (callback, continuation) = if phase == wire::Phase::Ready {
            qualify(&mut tx, &value, admission).await?;
            let plain = self
                .protection
                .open_bytes(&sealed.ok_or(Error::Corrupt)?, &aad(self.tenant, id)?)
                .map_err(|_| Error::Corrupt)?;
            let handoff: Handoff =
                serde_json::from_slice(plain.expose()).map_err(|_| Error::Corrupt)?;
            (
                Some(value.relying_party.callback.clone()),
                Some(handoff.continuation),
            )
        } else {
            (None, None)
        };
        tx.rollback().await.map_err(db)?;
        Ok(wire::Status {
            operation_id: id,
            phase,
            expires_at: value.expires_at,
            callback,
            continuation,
        })
    }
    pub async fn broker_cancel(
        &self,
        id: Uuid,
        browser: &Secret,
        audit: &RequestAudit,
    ) -> Result<(), Error> {
        audit.operation(
            id,
            "enterprise_broker_cancel",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(audit, (self, id, browser), |ctx, c| {
            Box::pin(async move {
                let (service, id, browser) = ctx;
                let (mut value, _) = load(c, tenant(service)?, *id, true).await?;
                browser_matches(&value, browser)?;
                let replay = value.phase == wire::Phase::Cancelled;
                value.phase = wire::Phase::Cancelled;
                save(c, &value, None).await?;
                Ok(AuditedChange { value: (), replay })
            })
        })
        .await
    }
    pub async fn broker_reference(
        &self,
        client: &dyn Client,
        id: Uuid,
        continuation: Option<&Secret>,
        admission: &dyn Admission,
    ) -> Result<SessionReference, Error> {
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        let (value, _) = load(&mut tx, tenant(self)?, id, false).await?;
        if value.relying_party.id != client.target().id
            || value.relying_party.target_fingerprint != client.fingerprint()
            || value.subject.provider != client.provider()
        {
            return Err(Error::Forbidden);
        }
        if let Some(continuation) = continuation {
            continuation_matches(&value, continuation)?;
            if !matches!(value.phase, wire::Phase::Ready | wire::Phase::Consumed) {
                return Err(Error::Conflict);
            }
        } else if value.phase != wire::Phase::Consumed {
            return Err(Error::Forbidden);
        }
        qualify(&mut tx, &value, admission).await?;
        let reference = value.reference.ok_or(Error::Conflict)?;
        tx.rollback().await.map_err(db)?;
        Ok(reference)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Identity or RP authority, browser proof and frozen operation coordinates are independently validated"
    )]
    pub async fn broker_consume(
        &self,
        client: &dyn Client,
        id: Uuid,
        operation: Uuid,
        continuation: &Secret,
        facts: &RevalidatedSession,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<(), Error> {
        if operation.is_nil() {
            return Err(Error::Malformed);
        }
        audit.operation(
            operation,
            "enterprise_broker_consume",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(
            audit,
            (self, client, id, operation, continuation, facts, admission),
            |ctx, c| {
                Box::pin(async move {
                    let (service, client, id, operation, continuation, facts, admission) = ctx;
                    facts.check_live().map_err(|_| Error::Unauthorized)?;
                    let (mut value, sealed) = load(c, tenant(service)?, *id, true).await?;
                    continuation_matches(&value, continuation)?;
                    if value.relying_party.id != client.target().id
                        || value.relying_party.target_fingerprint != client.fingerprint()
                        || value.subject.provider != client.provider()
                        || facts.account().tenant != service.tenant
                        || facts.instance().as_uuid() != value.binding.person.instance
                        || Some(facts.view().id.as_uuid()) != value.identity_session
                        || facts.account().principal.as_uuid() != value.binding.person.principal
                    {
                        return Err(Error::Forbidden);
                    }
                    let now = rss_mdm_webhook_service::events::now_on(c)
                        .await
                        .map_err(|_| Error::Storage)?;
                    if now >= value.expires_at
                        || !matches!(value.phase, wire::Phase::Ready | wire::Phase::Consumed)
                    {
                        return Err(Error::Conflict);
                    }
                    if value.consume_operation.is_some_and(|op| op != *operation) {
                        return Err(Error::Conflict);
                    }
                    qualify(c, &value, *admission).await?;
                    let sealed = sealed.ok_or(Error::Corrupt)?;
                    let replay = value.phase == wire::Phase::Consumed;
                    value.phase = wire::Phase::Consumed;
                    value.consume_operation = Some(*operation);
                    save(c, &value, Some(&sealed)).await?;
                    Ok(AuditedChange { value: (), replay })
                })
            },
        )
        .await
    }
}

impl Service {
    async fn broker_authorized_snapshot(
        &self,
        authority: &rss_identity_postgres::Authority,
        client: &dyn Client,
        id: Uuid,
        operation: Option<Uuid>,
        continuation: Option<&Secret>,
        platform: serde_json::Value,
    ) -> Result<(Context, Option<Vec<u8>>), Error> {
        use sqlx::{Arguments, Row};
        let mut arguments = sqlx::postgres::PgArguments::default();
        arguments.add(tenant(self)?).map_err(|_| Error::Malformed)?;
        arguments
            .add(client.target().id.clone())
            .map_err(|_| Error::Malformed)?;
        arguments
            .add(client.fingerprint().to_owned())
            .map_err(|_| Error::Malformed)?;
        arguments
            .add(client.provider())
            .map_err(|_| Error::Malformed)?;
        arguments.add(id).map_err(|_| Error::Malformed)?;
        arguments.add(platform).map_err(|_| Error::Malformed)?;
        arguments.add(operation).map_err(|_| Error::Malformed)?;
        arguments
            .add(continuation.map(|v| serde_json::json!(hash(v.expose()))))
            .map_err(|_| Error::Malformed)?;
        let rows = authority
            .with_session_references_read(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    std::time::Duration::from_secs(5),
                ),
                move |mut read| {
                    Box::pin(async move {
                        read.query(include_str!("broker-release.sql"), arguments, 1)
                            .await
                    })
                },
            )
            .await
            .map_err(|e| match e {
                rss_identity_postgres::AuthorityError::Rejected => Error::Unauthorized,
                _ => Error::Storage,
            })?;
        if rows.len() != 1 {
            return Err(Error::Forbidden);
        }
        let row = &rows[0];
        let context: Context = serde_json::from_value(row.try_get("document").map_err(db)?)
            .map_err(|_| Error::Corrupt)?;
        Ok((context, row.try_get("sealed").map_err(db)?))
    }
    /// Receipt settlement alone is not authorization. Release uses one current Identity/product snapshot.
    pub async fn broker_release(
        &self,
        authority: &rss_identity_postgres::Authority,
        client: &dyn Client,
        id: Uuid,
        operation: Uuid,
        continuation: &Secret,
        platform: serde_json::Value,
    ) -> Result<Consumed, Error> {
        let (context, sealed) = self
            .broker_authorized_snapshot(
                authority,
                client,
                id,
                Some(operation),
                Some(continuation),
                platform,
            )
            .await?;
        let plain = self
            .protection
            .open_bytes(&sealed.ok_or(Error::Conflict)?, &aad(self.tenant, id)?)
            .map_err(|_| Error::Corrupt)?;
        let handoff: Handoff =
            serde_json::from_slice(plain.expose()).map_err(|_| Error::Corrupt)?;
        let now = self.now()?;
        if handoff.expires_at <= now || context.expires_at <= now {
            return Err(Error::Conflict);
        }
        Ok(Consumed {
            session: id,
            access_token: handoff.access_token,
            subject: handoff.subject,
            expires_at: handoff.expires_at,
        })
    }
    pub async fn broker_current(
        &self,
        authority: &rss_identity_postgres::Authority,
        client: &dyn Client,
        id: Uuid,
        platform: serde_json::Value,
    ) -> Result<Uuid, Error> {
        let (context, _) = self
            .broker_authorized_snapshot(authority, client, id, None, None, platform)
            .await?;
        Ok(context.binding.person.principal)
    }
}
