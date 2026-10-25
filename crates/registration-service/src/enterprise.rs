//! Product RP registry and stable IdP coordinates; Identity owns all authentication sessions.
//! ref: Keycloak 26.7.3 OIDC JWT authorization grant (fixed target issuer/client binding).
use crate::device_access::Person;
use crate::{
    Error,
    agent::{Change as AuditedChange, Service},
    database::db,
    operations::{Actor, Operation},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

pub mod broker;
pub mod directory;
pub mod keycloak;
pub mod platform;

pub const INSTALL_SQL: &str = include_str!("../schema/enterprise.sql");
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    NativeKey,
    Password,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelyingParty {
    pub id: String,
    pub revision: i64,
    pub enabled: bool,
    pub callback: String,
    pub target_fingerprint: String,
    pub capabilities: Vec<ProofKind>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Subject {
    pub provider: Uuid,
    pub person: Person,
    pub revision: i64,
    pub enabled: bool,
    pub subject: String,
    pub username: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Configuration {
    WindowsKey {
        registration: rss_mdm_agent_wire::enterprise::KeyRegistration,
    },
    RelyingParty {
        id: String,
        enabled: bool,
        callback: String,
        capabilities: Vec<ProofKind>,
    },
    Subject {
        provider: Uuid,
        person: Person,
        enabled: bool,
        subject: String,
        username: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub configuration: Configuration,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Record {
    RelyingParty(RelyingParty),
    Subject(Subject),
    WindowsKey(WindowsSource),
}
fn text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control)
}
impl Change {
    pub fn context(
        &self,
        actor: &AuthorizedPrincipal,
        target_fingerprint: Option<&str>,
    ) -> Result<rss_identity_core::step_up::StepUpContext, Error> {
        actor.require(Permission::EnterpriseApplicationsWrite, None)?;
        actor.session()?;
        if self.operation_id.is_nil() || self.expected_revision < 0 {
            return Err(Error::Malformed);
        }
        match &self.configuration {
            Configuration::WindowsKey { registration } => {
                if registration.binding_id.is_nil() || registration.signature.len() != 86 {
                    return Err(Error::Malformed);
                }
            }
            Configuration::RelyingParty {
                id,
                callback,
                capabilities,
                ..
            } => {
                let url = url::Url::parse(callback).map_err(|_| Error::Malformed)?;
                if id.is_empty()
                    || id.len() > 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    || url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                    || url.query().is_some()
                    || url.as_str() != callback
                    || capabilities.is_empty()
                    || capabilities.len() > 2
                    || capabilities.len() == 2 && capabilities[0] == capabilities[1]
                {
                    return Err(Error::Malformed);
                }
            }
            Configuration::Subject {
                provider,
                person,
                subject,
                username,
                ..
            } => {
                person.validate()?;
                if provider.is_nil()
                    || person.instance.to_string() != actor.instance_id()
                    || !text(subject)
                    || !text(username)
                {
                    return Err(Error::Malformed);
                }
            }
        }
        let bytes = serde_json::to_vec(&(
            "mdm.enterprise.configuration.v1",
            actor.tenant_id(),
            actor.instance_id(),
            actor.principal_id(),
            self,
            target_fingerprint,
        ))
        .map_err(|_| Error::Malformed)?;
        rss_identity_core::step_up::StepUpContext::new(
            "mdm.enterprise.configuration".into(),
            Sha256::digest(bytes).into(),
        )
        .map_err(|_| Error::Malformed)
    }
}
pub async fn subject_on(
    c: &mut PgConnection,
    tenant: Uuid,
    provider: Uuid,
    person: &Person,
) -> Result<Subject, Error> {
    let doc:serde_json::Value=sqlx::query_scalar("SELECT document FROM mdm_enterprise.subjects WHERE tenant_id=$1 AND provider=$2 AND principal=$3")
        .bind(tenant).bind(provider).bind(person.principal).fetch_optional(c).await.map_err(db)?.ok_or(Error::NotFound)?;
    let value: Subject = serde_json::from_value(doc).map_err(|_| Error::Corrupt)?;
    if value.provider != provider || value.person != *person || !value.enabled || value.revision < 1
    {
        return Err(Error::Forbidden);
    }
    Ok(value)
}
pub async fn relying_party_on(
    c: &mut PgConnection,
    tenant: Uuid,
    id: &str,
) -> Result<RelyingParty, Error> {
    let doc: serde_json::Value = sqlx::query_scalar(
        "SELECT document FROM mdm_enterprise.relying_parties WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(c)
    .await
    .map_err(db)?
    .ok_or(Error::NotFound)?;
    let value: RelyingParty = serde_json::from_value(doc).map_err(|_| Error::Corrupt)?;
    if value.id != id || value.revision < 1 {
        return Err(Error::Corrupt);
    }
    Ok(value)
}
async fn authorize(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
    permission: Permission,
) -> Result<(), Error> {
    actor.check_live()?;
    rss_mdm_authorization_service::lock_on(c, actor.tenant_id(), actor.instance_id()).await?;
    rss_mdm_authorization_service::snapshot_on(c, actor.tenant_id(), actor.instance_id())
        .await?
        .require(actor, permission, None)
        .map_err(|_| Error::Forbidden)
}
impl Service {
    pub async fn change_enterprise_configuration(
        &self,
        actor: &AuthorizedPrincipal,
        input: &Change,
        target_fingerprint: Option<&str>,
        proof: Option<&rss_mdm_agent_wire::runtime::Secret>,
        audit: &RequestAudit,
    ) -> Result<Record, Error> {
        audit.intent(rss_mdm_audit_integration::AuditIntent::Management);
        self.proof(actor, audit)?;
        let context = input.context(actor, target_fingerprint)?;
        if matches!(input.configuration, Configuration::RelyingParty { .. })
            && !target_fingerprint
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Error::Configuration);
        }
        let digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(input, target_fingerprint)).map_err(|_| Error::Malformed)?
            )
        );
        audit.operation(
            input.operation_id,
            "enterprise_configuration",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        if let Some(value) = self
            .enterprise_replay(actor, input.operation_id, &digest)
            .await?
        {
            return Ok(value);
        }
        let outcome=self.write_admitted(&self.access_audit,audit,(actor,input,target_fingerprint,proof,&context,&digest,audit),
            |ctx,c|Box::pin(async move {
                rss_identity_postgres::consume_step_up_on(c,ctx.0.session()?,ctx.4,ctx.3.ok_or(Error::Unauthorized)?.expose()).await
                    .map_err(|e|if e.kind()==rss_transactional_messaging::error::MessagingErrorKind::Conflict {Error::Unauthorized}else{Error::Storage})?;Ok(())
            }),|ctx,c|Box::pin(async move {
                let (actor,input,fingerprint,_,_,digest,audit)=ctx;
                authorize(c,actor,Permission::EnterpriseApplicationsWrite).await?;
                let op=Operation{actor:Actor::from_authorized(actor),key:input.operation_id,digest};
                if crate::operations::replay(c,&op).await?.is_some(){return Err(Error::Conflict);}
                let revision=input.expected_revision.checked_add(1).ok_or(Error::Capacity)?;
                let record=match &input.configuration {
                    Configuration::WindowsKey{registration}=>Record::WindowsKey(register_key_on(c,actor,input.operation_id,input.expected_revision,registration).await?),
                    Configuration::RelyingParty{id,enabled,callback,capabilities}=>{
                        let current:Option<i64>=sqlx::query_scalar("SELECT revision FROM mdm_enterprise.relying_parties WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(actor.tenant_id()).bind(id).fetch_optional(&mut *c).await.map_err(db)?;
                        if current.unwrap_or(0)!=input.expected_revision{return Err(Error::Conflict);}
                        let value=RelyingParty{id:id.clone(),revision,enabled:*enabled,callback:callback.clone(),target_fingerprint:fingerprint.ok_or(Error::Configuration)?.into(),capabilities:capabilities.clone()};
                        sqlx::query("INSERT INTO mdm_enterprise.relying_parties(tenant_id,id,revision,document) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,document=excluded.document")
                            .bind(actor.tenant_id()).bind(id).bind(revision).bind(serde_json::to_value(&value).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
                        Record::RelyingParty(value)
                    }
                    Configuration::Subject{provider,person,enabled,subject,username}=>{
                        let current:Option<i64>=sqlx::query_scalar("SELECT revision FROM mdm_enterprise.subjects WHERE tenant_id=$1::uuid AND provider=$2 AND principal=$3 FOR UPDATE").bind(actor.tenant_id()).bind(provider).bind(person.principal).fetch_optional(&mut *c).await.map_err(db)?;
                        if current.unwrap_or(0)!=input.expected_revision{return Err(Error::Conflict);}
                        sqlx::query("INSERT INTO mdm_enterprise.subject_owners(tenant_id,provider,subject,principal) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,provider,subject) DO NOTHING")
                            .bind(actor.tenant_id()).bind(provider).bind(subject).bind(person.principal).execute(&mut *c).await.map_err(db)?;
                        let owner:Uuid=sqlx::query_scalar("SELECT principal FROM mdm_enterprise.subject_owners WHERE tenant_id=$1::uuid AND provider=$2 AND subject=$3")
                            .bind(actor.tenant_id()).bind(provider).bind(subject).fetch_one(&mut *c).await.map_err(db)?;
                        if owner!=person.principal{return Err(Error::Conflict);}
                        let known:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_enterprise.subject_versions WHERE tenant_id=$1::uuid AND principal=$2 AND provider=$3 AND document->>'subject'=$4)")
                            .bind(actor.tenant_id()).bind(person.principal).bind(provider).bind(subject).fetch_one(&mut *c).await.map_err(db)?;
                        if !known {
                            let count:i64=sqlx::query_scalar("SELECT count(*) FROM (SELECT DISTINCT provider,document->>'subject' FROM mdm_enterprise.subject_versions WHERE tenant_id=$1::uuid AND principal=$2) subjects")
                                .bind(actor.tenant_id()).bind(person.principal).fetch_one(&mut *c).await.map_err(db)?;
                            if count>=64 {return Err(Error::Capacity);}
                        }
                        let value=Subject{provider:*provider,person:person.clone(),revision,enabled:*enabled,subject:subject.clone(),username:username.clone()};
                        sqlx::query("INSERT INTO mdm_enterprise.subjects(tenant_id,provider,principal,revision,document) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,provider,principal) DO UPDATE SET revision=excluded.revision,document=excluded.document")
                            .bind(actor.tenant_id()).bind(provider).bind(person.principal).bind(revision).bind(serde_json::to_value(&value).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
                        sqlx::query("INSERT INTO mdm_enterprise.subject_versions(tenant_id,provider,principal,revision,document) VALUES($1::uuid,$2,$3,$4,$5)")
                            .bind(actor.tenant_id()).bind(provider).bind(person.principal).bind(revision).bind(serde_json::to_value(&value).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
                        Record::Subject(value)
                    }
                };
                crate::operations::save(c,&op,&serde_json::to_string(&record).map_err(|_|Error::Corrupt)?,audit).await?;
                Ok(AuditedChange{value:record, replay:false})
            })).await;
        match outcome {
            Ok(value) => Ok(value),
            Err(error) => match self
                .enterprise_replay(actor, input.operation_id, &digest)
                .await
            {
                Ok(Some(value)) => Ok(value),
                _ => Err(error),
            },
        }
    }
    async fn enterprise_replay(
        &self,
        actor: &AuthorizedPrincipal,
        id: Uuid,
        digest: &str,
    ) -> Result<Option<Record>, Error> {
        let mut tx = self.store.begin(actor.tenant_id()).await?;
        authorize(&mut tx, actor, Permission::EnterpriseApplicationsRead).await?;
        let value = crate::operations::read(
            &mut tx,
            &Operation {
                actor: Actor::from_authorized(actor),
                key: id,
                digest,
            },
        )
        .await?;
        let record = value
            .map(|value| serde_json::from_str(&value).map_err(|_| Error::Corrupt))
            .transpose()?;
        tx.rollback().await.map_err(db)?;
        Ok(record)
    }
}

pub fn target_fingerprint(
    target: &rss_identity_core::enterprise::EnterpriseTarget,
) -> Result<String, Error> {
    target.validate().map_err(|_| Error::Configuration)?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(target).map_err(|_| Error::Configuration)?)
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSource {
    pub id: Uuid,
    pub version: i64,
    pub binding_id: Uuid,
    pub binding_generation: i64,
    pub factor_generation: i64,
    pub binding_revision: i64,
    pub person: Person,
    pub public_key: rss_mdm_agent_wire::platform_sso::PublicKey,
}
async fn register_key_on(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
    operation: Uuid,
    expected: i64,
    key: &rss_mdm_agent_wire::enterprise::KeyRegistration,
) -> Result<WindowsSource, Error> {
    let tenant = Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Malformed)?;
    let binding = crate::device_access::storage::require_active_in(
        c,
        tenant,
        key.binding_id,
        key.binding_generation,
    )
    .await?;
    if binding.intent.platform() != rss_mdm_agent_wire::runtime::TaskPlatform::Windows
        || binding.factor_generation != key.factor_generation
        || binding.revision != key.binding_revision
    {
        return Err(Error::Conflict);
    }
    rss_mdm_authorization_service::snapshot_on(c, actor.tenant_id(), actor.instance_id())
        .await?
        .require(actor, Permission::AccountWrite, Some(&binding.device))
        .map_err(|_| Error::Forbidden)?;
    let bytes = key
        .signing_bytes(
            tenant,
            binding.person.instance,
            binding.person.principal,
            operation,
        )
        .map_err(|_| Error::Malformed)?;
    verify_signature(&key.public_key, &key.signature, &bytes)?;
    let previous:Option<serde_json::Value>=sqlx::query_scalar("SELECT document FROM mdm_enterprise.windows_sources WHERE tenant_id=$1 AND binding=$2 FOR UPDATE")
        .bind(tenant).bind(binding.id).fetch_optional(&mut *c).await.map_err(db)?;
    let previous: Option<WindowsSource> = previous
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error::Corrupt)?;
    if previous.as_ref().map_or(0, |s| s.version) != expected {
        return Err(Error::Conflict);
    }
    let source = WindowsSource {
        id: previous.map_or_else(Uuid::new_v4, |s| s.id),
        version: expected.checked_add(1).ok_or(Error::Capacity)?,
        binding_id: binding.id,
        binding_generation: binding.generation,
        factor_generation: binding.factor_generation,
        binding_revision: binding.revision,
        person: binding.person,
        public_key: key.public_key.clone(),
    };
    sqlx::query("INSERT INTO mdm_enterprise.windows_sources(tenant_id,binding,id,version,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,binding) DO UPDATE SET version=excluded.version,document=excluded.document")
        .bind(tenant).bind(source.binding_id).bind(source.id).bind(source.version).bind(serde_json::to_value(&source).map_err(|_|Error::Malformed)?).execute(c).await.map_err(db)?;
    Ok(source)
}
pub fn verify_signature(
    key: &rss_mdm_agent_wire::platform_sso::PublicKey,
    signature: &str,
    payload: &[u8],
) -> Result<(), Error> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    if signature.len() != 86 || payload.len() > 16384 {
        return Err(Error::Malformed);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Error::Malformed)?;
    if bytes.len() != 64 || URL_SAFE_NO_PAD.encode(&bytes) != signature {
        return Err(Error::Malformed);
    }
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        key.x963().map_err(|_| Error::Malformed)?,
    )
    .verify(payload, &bytes)
    .map_err(|_| Error::Unauthorized)
}
