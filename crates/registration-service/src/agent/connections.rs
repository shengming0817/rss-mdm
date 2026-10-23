//! Registration-owned connection configuration, key material and installation receipts.
//! ref: ring src/ec/curve25519/ed25519/signing.rs; sqlx-core/src/transaction.rs.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rss_mdm_agent_wire::connections as w;
use rss_mdm_authorization_service::Permission;
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use std::collections::BTreeMap;

/// Public draft; saving does not deploy a gateway or publish a trusted destination.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Draft {
    pub configuration: w::Configuration,
}
/// Management writes are recoverable by their original operation, never by making a new ID.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Save {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub preferred_origin: String,
    pub origins: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publish {
    pub operation_id: Uuid,
    pub expected_revision: u64,
}
/// Read projection, not a claim that an offline device has applied a revision.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub service_id: Uuid,
    pub draft: Option<Draft>,
    pub published: Option<w::SignedConfiguration>,
    pub verification_keys: BTreeMap<String, String>,
    pub deployments: Vec<Deployment>,
    pub convergence: Convergence,
    pub retirement_blockers: RetirementBlockers,
}
/// Live installation materials that cannot learn any proposed remaining location.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetirementBlockers {
    pub configurations: u64,
    pub installations: u64,
}
async fn retirement_blockers_on(
    c: &mut PgConnection,
    tenant: &str,
    remaining: &[String],
) -> Result<RetirementBlockers, Error> {
    let configurations:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.agent_configurations f WHERE f.tenant_id=$1::uuid AND NOT ((f.document#>'{connections,configuration,origins}') ?| $2::text[]) AND ((f.state='available' AND f.expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM mdm_access.agent_grants g WHERE g.tenant_id=f.tenant_id AND g.configuration_id=f.id AND g.state='available' AND g.expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id)))")
        .bind(tenant).bind(remaining).fetch_one(&mut *c).await.map_err(db)?;
    let installations:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.agent_bootstraps b WHERE b.tenant_id=$1::uuid AND b.active AND NOT b.cleanup_complete AND b.state<>'revoked' AND b.deadline>floor(extract(epoch FROM clock_timestamp()))::bigint AND NOT(b.download_origin=ANY($2::text[])) AND NOT EXISTS(SELECT 1 FROM mdm_access.agent_grants g JOIN mdm_access.registrations r ON(r.tenant_id,r.agent_grant_id)=(g.tenant_id,g.id) WHERE g.tenant_id=b.tenant_id AND g.native_authority->>'installation'=b.installation::text AND r.state='active')")
        .bind(tenant).bind(remaining).fetch_one(c).await.map_err(db)?;
    Ok(RetirementBlockers {
        configurations: u64::try_from(configurations).map_err(|_| Error::Corrupt)?,
        installations: u64::try_from(installations).map_err(|_| Error::Corrupt)?,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub origin: String,
    pub host_id: Uuid,
    pub revision: u64,
    pub observed_at: i64,
    pub configuration_revision: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Convergence {
    pub target_revision: Option<u64>,
    pub active_devices: u64,
    pub confirmed_devices: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceQuery {
    pub revision: u64,
    pub after: Option<Uuid>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnconfirmedDevices {
    pub target_revision: u64,
    pub items: Vec<DeviceStatus>,
    pub next: Option<Uuid>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStatus {
    pub device: String,
    pub registration: Uuid,
    pub generation: u64,
    pub installed_revision: Option<u64>,
    pub origin: Option<String>,
    pub received_at: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub target_revision: Option<u64>,
    pub registration: Uuid,
    pub generation: u64,
    pub acknowledgement: Option<w::Acknowledgement>,
    pub received_at: Option<i64>,
    pub failure: Option<FailureObservation>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureObservation {
    pub report: w::FailureReport,
    pub origin: String,
    pub received_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Receipt {
    Saved {
        draft: Draft,
    },
    Published {
        configuration: w::SignedConfiguration,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum StoredReceipt {
    Save { revision: u64 },
    Publish { revision: u64 },
}

fn key_aad(tenant: &str, key_id: &str) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Configuration)?,
        key_id,
        "agent-configuration.private-key",
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| Error::Configuration)
}

/// Read existing configuration keys only. Task-key state cannot replace this trust root.
pub(super) async fn signer_on(
    c: &mut PgConnection,
    tenant: &str,
    protection: &Protector,
) -> Result<configurations::Signer, Error> {
    let row = sqlx::query("SELECT key_id,public_key,private_key FROM mdm_access.agent_configuration_keys WHERE tenant_id=$1::uuid")
        .bind(tenant).fetch_optional(c).await.map_err(db)?.ok_or(Error::Conflict)?;
    let id: String = row.try_get("key_id").map_err(db)?;
    let public: String = row.try_get("public_key").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
    let private = protection
        .open_bytes(&sealed, &key_aad(tenant, &id)?)
        .map_err(|_| Error::Corrupt)?;
    configurations::Signer::new(
        private.expose(),
        &id,
        &BTreeMap::from([(id.clone(), public)]),
    )
}

async fn ensure_signer_on(
    c: &mut PgConnection,
    tenant: &str,
    protection: &Protector,
) -> Result<configurations::Signer, Error> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mdm_access.agent_configuration_keys WHERE tenant_id=$1::uuid)",
    )
    .bind(tenant)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if !exists {
        let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| Error::Configuration)?;
        let key = Ed25519KeyPair::from_pkcs8(private.as_ref()).map_err(|_| Error::Configuration)?;
        let id = Uuid::new_v4().to_string();
        let sealed = protection
            .seal_bytes(private.as_ref(), &key_aad(tenant, &id)?)
            .map_err(|_| Error::Configuration)?;
        sqlx::query("INSERT INTO mdm_access.agent_configuration_keys(tenant_id,key_id,public_key,private_key) VALUES($1::uuid,$2,$3,$4)")
            .bind(tenant).bind(id).bind(URL_SAFE_NO_PAD.encode(key.public_key().as_ref())).bind(sealed)
            .execute(&mut *c).await.map_err(db)?;
    }
    signer_on(c, tenant, protection).await
}

async fn service_id_on(c: &mut PgConnection) -> Result<Uuid, Error> {
    sqlx::query_scalar("SELECT instance_id FROM public.mdm_installation")
        .fetch_one(c)
        .await
        .map_err(db)
}
pub(super) async fn lock(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2894))")
        .bind(tenant)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
async fn draft_on(
    c: &mut PgConnection,
    tenant: &str,
    revision: Option<u64>,
) -> Result<Option<Draft>, Error> {
    let raw: Option<serde_json::Value> = sqlx::query_scalar("SELECT document FROM mdm_access.agent_connection_drafts WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision=$2) ORDER BY revision DESC LIMIT 1")
        .bind(tenant).bind(revision.map(i64::try_from).transpose().map_err(|_| Error::Malformed)?)
        .fetch_optional(c).await.map_err(db)?;
    raw.map(|v| serde_json::from_value(v).map_err(|_| Error::Corrupt))
        .transpose()
}
async fn published_on(
    c: &mut PgConnection,
    tenant: &str,
    revision: Option<u64>,
) -> Result<Option<w::SignedConfiguration>, Error> {
    let row = sqlx::query("SELECT document,k.public_key FROM mdm_access.agent_connection_versions v JOIN mdm_access.agent_configuration_keys k USING(tenant_id) WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision=$2) ORDER BY revision DESC LIMIT 1")
        .bind(tenant).bind(revision.map(i64::try_from).transpose().map_err(|_| Error::Malformed)?)
        .fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let value: w::SignedConfiguration =
        serde_json::from_value(row.try_get("document").map_err(db)?).map_err(|_| Error::Corrupt)?;
    value.validate().map_err(|_| Error::Corrupt)?;
    let key: String = row.try_get("public_key").map_err(db)?;
    let key = URL_SAFE_NO_PAD.decode(key).map_err(|_| Error::Corrupt)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&value.signature)
        .map_err(|_| Error::Corrupt)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(
            &value
                .configuration
                .signing_bytes()
                .map_err(|_| Error::Corrupt)?,
            &signature,
        )
        .map_err(|_| Error::Corrupt)?;
    if value.configuration.service_id != service_id_on(c).await?
        || value.configuration.tenant_id.to_string() != tenant
    {
        return Err(Error::Corrupt);
    }
    Ok(Some(value))
}
pub(super) async fn current_on(
    c: &mut PgConnection,
    tenant: &str,
) -> Result<w::SignedConfiguration, Error> {
    published_on(c, tenant, None).await?.ok_or(Error::Conflict)
}

/// Freeze a new native installation locator while fencing publication/retirement.
/// The command runtime can read the public configuration and never its private key.
pub async fn installation_configuration_on(
    c: &mut PgConnection,
    tenant: &str,
) -> Result<w::SignedConfiguration, Error> {
    lock(c, tenant).await?;
    current_on(c, tenant).await
}

/// Installation owner records a successful real HTTPS host observation in its own transaction.
/// There is deliberately no management HTTP endpoint capable of inventing this observation.
pub async fn record_deployment_on(
    c: &mut PgConnection,
    tenant: Uuid,
    origin: &str,
    service_id: Uuid,
    host_id: Uuid,
    revision: u64,
) -> Result<(), Error> {
    w::validate_origin(origin).map_err(|_| Error::Malformed)?;
    if service_id != service_id_on(c).await? || host_id.is_nil() || revision == 0 {
        return Err(Error::Conflict);
    }
    lock(c, &tenant.to_string()).await?;
    let configuration_revision:i64=sqlx::query_scalar("SELECT coalesce(max(revision),0) FROM mdm_access.agent_connection_drafts WHERE tenant_id=$1")
        .bind(tenant).fetch_one(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.agent_connection_deployments(tenant_id,origin,service_id,host_id,revision,configuration_revision,observed_at) VALUES($1,$2,$3,$4,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(tenant_id,origin) DO UPDATE SET service_id=excluded.service_id,host_id=excluded.host_id,revision=excluded.revision,configuration_revision=excluded.configuration_revision,observed_at=excluded.observed_at")
        .bind(tenant).bind(origin).bind(service_id).bind(host_id).bind(i64::try_from(revision).map_err(|_| Error::Malformed)?).bind(configuration_revision)
        .execute(c).await.map_err(db)?;
    Ok(())
}

impl Service {
    pub async fn connection_configuration(&self) -> Result<w::SignedConfiguration, Failure> {
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        let out = current_on(&mut tx, &self.tenant.to_string()).await?;
        if out.configuration.service_id != self.service_id()? {
            return Err(Error::Configuration.into());
        }
        tx.rollback().await.map_err(db)?;
        Ok(out)
    }
    pub async fn connection_state(&self, p: &AuthorizedPrincipal) -> Result<State, Failure> {
        p.manage(Permission::RegistrationConfigurationRead)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        super::authorize_on(&mut tx, p, Permission::RegistrationConfigurationRead).await?;
        let published = published_on(&mut tx, p.tenant_id(), None).await?;
        let revision = published.as_ref().map(|v| v.configuration.revision);
        let rows = sqlx::query("SELECT origin,host_id,revision,configuration_revision,observed_at FROM mdm_access.agent_connection_deployments WHERE tenant_id=$1::uuid AND service_id=$2 ORDER BY origin")
            .bind(p.tenant_id()).bind(self.service_id()?).fetch_all(&mut *tx).await.map_err(db)?;
        let deployments = rows
            .into_iter()
            .map(|r| {
                Ok(Deployment {
                    origin: r.try_get("origin").map_err(db)?,
                    host_id: r.try_get("host_id").map_err(db)?,
                    revision: u64::try_from(r.try_get::<i64, _>("revision").map_err(db)?)
                        .map_err(|_| Error::Corrupt)?,
                    observed_at: r.try_get("observed_at").map_err(db)?,
                    configuration_revision: u64::try_from(
                        r.try_get::<i64, _>("configuration_revision").map_err(db)?,
                    )
                    .map_err(|_| Error::Corrupt)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let (active, confirmed): (i64,i64) = sqlx::query_as("SELECT count(*),count(*) FILTER(WHERE EXISTS(SELECT 1 FROM mdm_access.agent_connection_observations o WHERE o.tenant_id=r.tenant_id AND o.registration=r.id AND o.generation=r.generation AND o.revision=$2)) FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active'")
            .bind(p.tenant_id()).bind(revision.map(i64::try_from).transpose().map_err(|_| Error::Corrupt)?).fetch_one(&mut *tx).await.map_err(db)?;
        let keys: Vec<(String,String)> = sqlx::query_as("SELECT key_id,public_key FROM mdm_access.agent_configuration_keys WHERE tenant_id=$1::uuid")
            .bind(p.tenant_id()).fetch_all(&mut *tx).await.map_err(db)?;
        let draft = draft_on(&mut tx, p.tenant_id(), None).await?;
        let retirement_blockers = if let Some(ref d) = draft {
            retirement_blockers_on(&mut tx, p.tenant_id(), &d.configuration.origins).await?
        } else {
            RetirementBlockers::default()
        };
        let state = State {
            service_id: self.service_id()?,
            draft,
            retirement_blockers,
            published,
            verification_keys: keys.into_iter().collect(),
            deployments,
            convergence: Convergence {
                target_revision: revision,
                active_devices: u64::try_from(active).map_err(|_| Error::Corrupt)?,
                confirmed_devices: u64::try_from(confirmed).map_err(|_| Error::Corrupt)?,
            },
        };
        tx.rollback().await.map_err(db)?;
        Ok(state)
    }
    pub async fn save_connections(
        &self,
        p: &AuthorizedPrincipal,
        input: &Save,
        audit: &RequestAudit,
    ) -> Result<Draft, Failure> {
        self.proof(p, audit)?;
        p.session()?;
        if input.operation_id.is_nil() {
            return Err(Error::Malformed.into());
        }
        audit.operation(input.operation_id, "agent_connections_save");
        let d = digest(&("save", input))?;
        self.write(audit,(self,p,input,audit,d),|ctx,c|Box::pin(async move {
            let (service,p,input,audit,d)=ctx;
            authorize_write(c,p).await?;
            lock(c,p.tenant_id()).await?;
            let op=crate::operations::Operation{actor:crate::operations::Actor::from_authorized(p),key:input.operation_id,digest:d};
            if let Some(old)=crate::operations::replay(c,&op).await? {
                let StoredReceipt::Save { revision } = serde_json::from_str(&old).map_err(|_|Error::Corrupt)? else { return Err(Error::Conflict) };
                return Ok(Change{value:draft_on(c,p.tenant_id(),Some(revision)).await?.ok_or(Error::Corrupt)?,replay:true,digest:d.clone()});
            }
            let old=draft_on(c,p.tenant_id(),None).await?;
            let current=old.map_or(0,|v|v.configuration.revision);
            if current!=input.expected_revision || current>=i64::MAX as u64 {return Err(Error::Conflict)}
            if service.service_id()? != service_id_on(c).await? { return Err(Error::Configuration); }
            let signer=ensure_signer_on(c,p.tenant_id(),&service.protection).await?;
            let out=Draft{configuration:w::Configuration{wire_version:1,service_id:service.service_id()?,tenant_id:Uuid::parse_str(p.tenant_id()).map_err(|_|Error::Configuration)?,revision:current+1,preferred_origin:input.preferred_origin.clone(),origins:input.origins.clone(),key_id:signer.key_id.clone()}};
            out.configuration.validate().map_err(|_|Error::Malformed)?;
            sqlx::query("INSERT INTO mdm_access.agent_connection_drafts(tenant_id,revision,document) VALUES($1::uuid,$2,$3)")
                .bind(p.tenant_id()).bind((current+1) as i64).bind(serde_json::to_value(&out).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
            crate::operations::save(c,&op,&serde_json::to_string(&StoredReceipt::Save { revision: current+1 }).map_err(|_|Error::Corrupt)?,audit).await?;
            Ok(Change{value:out,replay:false,digest:d.clone()})
        })).await.map_err(Into::into)
    }
    pub async fn publish_connections(
        &self,
        p: &AuthorizedPrincipal,
        input: &Publish,
        audit: &RequestAudit,
    ) -> Result<w::SignedConfiguration, Failure> {
        self.proof(p, audit)?;
        p.session()?;
        if input.operation_id.is_nil() {
            return Err(Error::Malformed.into());
        }
        audit.operation(input.operation_id, "agent_connections_publish");
        let d = digest(&("publish", input))?;
        self.write(audit,(self,p,input,audit,d),|ctx,c|Box::pin(async move{
            let(service,p,input,audit,d)=ctx;
            authorize_write(c,p).await?;lock(c,p.tenant_id()).await?;
            let op=crate::operations::Operation{actor:crate::operations::Actor::from_authorized(p),key:input.operation_id,digest:d};
            if let Some(old)=crate::operations::replay(c,&op).await?{
                let StoredReceipt::Publish { revision } = serde_json::from_str(&old).map_err(|_|Error::Corrupt)? else { return Err(Error::Conflict) };
                return Ok(Change{value:published_on(c,p.tenant_id(),Some(revision)).await?.ok_or(Error::Corrupt)?,replay:true,digest:d.clone()});
            }
            let draft=draft_on(c,p.tenant_id(),None).await?.ok_or(Error::Conflict)?;
            if draft.configuration.revision!=input.expected_revision{return Err(Error::Conflict)}
            if let Some(previous)=published_on(c,p.tenant_id(),None).await?{
                if draft.configuration.revision<=previous.configuration.revision{return Err(Error::Conflict)}
                draft.configuration.validate_successor(&previous.configuration).map_err(|_|Error::Conflict)?;
                if previous.configuration.origins.iter().any(|o|!draft.configuration.origins.contains(o)) {
                    let blocked=retirement_blockers_on(c,p.tenant_id(),&draft.configuration.origins).await?;
                    if blocked.configurations>0 || blocked.installations>0 { return Err(Error::Agent(wire::ErrorCode::ConnectionRetirementBlocked)); }
                }
                // A device that has only removed locations cannot discover this update.
                let stranded:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND NOT EXISTS(SELECT 1 FROM mdm_access.agent_connection_observations o WHERE o.tenant_id=r.tenant_id AND o.registration=r.id AND o.generation=r.generation AND o.operation_id=(SELECT n.operation_id FROM mdm_access.agent_connection_observations n WHERE n.tenant_id=r.tenant_id AND n.registration=r.id AND n.generation=r.generation ORDER BY n.revision DESC,n.recorded_at DESC LIMIT 1) AND o.document->>'origin'=ANY($2::text[])))")
                    .bind(p.tenant_id()).bind(&draft.configuration.origins).fetch_one(&mut *c).await.map_err(db)?;
                if stranded && !previous.configuration.origins.iter().any(|o|draft.configuration.origins.contains(o)){return Err(Error::Agent(wire::ErrorCode::ConnectionRetirementBlocked))}
                if stranded && previous.configuration.origins.iter().any(|o|!draft.configuration.origins.contains(o)){return Err(Error::Agent(wire::ErrorCode::ConnectionRetirementBlocked))}
            }
            for origin in &draft.configuration.origins{
                let verified:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_connection_deployments WHERE tenant_id=$1::uuid AND origin=$2 AND service_id=$3 AND configuration_revision=$4 AND observed_at>=floor(extract(epoch FROM clock_timestamp()))::bigint-300)")
                    .bind(p.tenant_id()).bind(origin).bind(service.service_id()?).bind(draft.configuration.revision as i64).fetch_one(&mut *c).await.map_err(db)?;
                if !verified{return Err(Error::Agent(wire::ErrorCode::ConnectionDeploymentUnobserved))}
            }
            let signer=signer_on(c,p.tenant_id(),&service.protection).await?;
            let out=signer.sign_connections(draft.configuration)?;
            sqlx::query("INSERT INTO mdm_access.agent_connection_versions(tenant_id,revision,document) VALUES($1::uuid,$2,$3)")
                .bind(p.tenant_id()).bind(input.expected_revision as i64).bind(serde_json::to_value(&out).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
            crate::operations::save(c,&op,&serde_json::to_string(&StoredReceipt::Publish { revision: input.expected_revision }).map_err(|_|Error::Corrupt)?,audit).await?;
            Ok(Change{value:out,replay:false,digest:d.clone()})
        })).await.map_err(Into::into)
    }
    pub async fn connection_operation(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<Option<Receipt>, Failure> {
        p.manage(Permission::RegistrationConfigurationRead)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        super::authorize_on(&mut tx, p, Permission::RegistrationConfigurationRead).await?;
        let revision:Option<String>=sqlx::query_scalar("SELECT result FROM mdm_access.registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND instance=$3 AND operation_id=$4")
            .bind(p.tenant_id()).bind(p.principal_id()).bind(p.instance_id()).bind(id).fetch_optional(&mut *tx).await.map_err(db)?;
        let Some(revision) = revision else {
            tx.rollback().await.map_err(db)?;
            return Ok(None);
        };
        let receipt: StoredReceipt =
            serde_json::from_str(&revision).map_err(|_| Error::Conflict)?;
        let out = match receipt {
            StoredReceipt::Save { revision } => Receipt::Saved {
                draft: draft_on(&mut tx, p.tenant_id(), Some(revision))
                    .await?
                    .ok_or(Error::NotFound)?,
            },
            StoredReceipt::Publish { revision } => Receipt::Published {
                configuration: published_on(&mut tx, p.tenant_id(), Some(revision))
                    .await?
                    .ok_or(Error::NotFound)?,
            },
        };
        tx.rollback().await.map_err(db)?;
        Ok(Some(out))
    }
    pub async fn acknowledge_connections(
        &self,
        peer: &rss_mdm_certificate::ClientCertificateEvidence,
        input: &w::Acknowledgement,
        origin: &rss_mdm_certificate::GatewayOrigin,
        audit: &RequestAudit,
    ) -> Result<(), Failure> {
        if input.origin != origin.as_str() {
            return Err(Error::Forbidden.into());
        }
        let p = self.authenticate(peer).await?;
        audit.identify_device(p.registration());
        audit.target(p.device());
        audit.operation(input.operation_id, "agent_connections_ack");
        let d = digest(&(p.registration(), p.generation(), input))?;
        self.write(audit,(self,p,input,d),|ctx,c|Box::pin(async move{
            let(service,p,input,d)=ctx;
            lock(c,&service.tenant.to_string()).await?;
            let current=current_on(c,&service.tenant.to_string()).await?;
            if !current.configuration.origins.contains(&input.origin) {return Err(Error::Conflict)}
            crate::device::store::revalidate_source(c,p,rss_mdm_inventory::ReportSource::AgentBuiltin).await?;
            let configuration=published_on(c,&service.tenant.to_string(),Some(input.revision)).await?.ok_or(Error::Conflict)?;
            input.validate_for(&configuration.configuration).map_err(|_|Error::Conflict)?;
            let old:Option<serde_json::Value>=sqlx::query_scalar("SELECT document FROM mdm_access.agent_connection_observations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND operation_id=$4")
                .bind(service.tenant.to_string()).bind(p.registration()).bind(p.generation()).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)?;
            if let Some(old)=old{
                if old!=serde_json::to_value(input).map_err(|_|Error::Malformed)?{return Err(Error::Conflict)}
                return Ok(Change{value:(),replay:true,digest:d.clone()});
            }
            let latest:Option<i64>=sqlx::query_scalar("SELECT max(revision) FROM mdm_access.agent_connection_observations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
                .bind(service.tenant.to_string()).bind(p.registration()).bind(p.generation()).fetch_one(&mut *c).await.map_err(db)?;
            if latest.is_some_and(|v|v>input.revision as i64){return Err(Error::Conflict)}
            sqlx::query("INSERT INTO mdm_access.agent_connection_observations(tenant_id,registration,generation,operation_id,revision,document,received_at) VALUES($1::uuid,$2,$3,$4,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint)")
                .bind(service.tenant.to_string()).bind(p.registration()).bind(p.generation()).bind(input.operation_id).bind(input.revision as i64).bind(serde_json::to_value(input).map_err(|_|Error::Malformed)?).execute(c).await.map_err(db)?;
            Ok(Change{value:(),replay:false,digest:d.clone()})
        })).await.map_err(Into::into)
    }
    pub async fn report_connection_failure(
        &self,
        peer: &rss_mdm_certificate::ClientCertificateEvidence,
        input: &w::FailureReport,
        origin: &rss_mdm_certificate::GatewayOrigin,
        audit: &RequestAudit,
    ) -> Result<(), Failure> {
        if input.operation_id.is_nil() || !(1..=i64::MAX as u64).contains(&input.revision) {
            return Err(Error::Malformed.into());
        }
        let principal = self.authenticate(peer).await?;
        audit.identify_device(principal.registration());
        audit.target(principal.device());
        audit.operation(input.operation_id, "agent_connections_failure");
        let fingerprint = digest(&(principal.registration(), principal.generation(), input))?;
        self.write(audit,(self,principal,input,origin,fingerprint),|ctx,c|Box::pin(async move{
            let(service,p,input,origin,digest)=ctx;
            crate::device::store::revalidate_source(c,p,rss_mdm_inventory::ReportSource::AgentBuiltin).await?;
            published_on(c,&service.tenant.to_string(),Some(input.revision)).await?.ok_or(Error::Conflict)?;
            let previous=sqlx::query("SELECT document FROM mdm_access.agent_connection_failures WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND operation_id=$4")
                .bind(service.tenant.to_string()).bind(p.registration()).bind(p.generation()).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)?;
            let document=serde_json::to_value(&**input).map_err(|_|Error::Malformed)?;
            if let Some(previous)=previous {
                if previous.try_get::<serde_json::Value,_>("document").map_err(db)?!=document {return Err(Error::Conflict)}
                return Ok(Change{value:(),replay:true,digest:digest.clone()});
            }
            sqlx::query("INSERT INTO mdm_access.agent_connection_failures(tenant_id,registration,generation,operation_id,revision,document,origin,received_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,floor(extract(epoch FROM clock_timestamp()))::bigint)")
                .bind(service.tenant.to_string()).bind(p.registration()).bind(p.generation()).bind(input.operation_id).bind(input.revision as i64).bind(document).bind(origin.as_str()).execute(c).await.map_err(db)?;
            Ok(Change{value:(),replay:false,digest:digest.clone()})
        })).await.map_err(Into::into)
    }
    /// Bounded keyset page of active devices that have not confirmed this exact target.
    pub async fn unconfirmed_connection_devices(
        &self,
        p: &AuthorizedPrincipal,
        input: &DeviceQuery,
    ) -> Result<UnconfirmedDevices, Failure> {
        p.manage(Permission::RegistrationConfigurationRead)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        super::authorize_on(&mut tx, p, Permission::RegistrationConfigurationRead).await?;
        let published = current_on(&mut tx, p.tenant_id()).await?;
        if published.configuration.revision != input.revision {
            return Err(Error::Conflict.into());
        }
        let snapshot =
            rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id())
                .await?;
        let mut rows=sqlx::query("SELECT r.id,r.device,r.generation,a.revision,a.document->>'origin' AS origin,a.received_at FROM mdm_access.registrations r LEFT JOIN LATERAL(SELECT revision,document,received_at FROM mdm_access.agent_connection_observations WHERE tenant_id=r.tenant_id AND registration=r.id AND generation=r.generation ORDER BY revision DESC,recorded_at DESC LIMIT 1) a ON true WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND ($2::uuid IS NULL OR r.id>$2) AND (a.revision IS NULL OR a.revision<>$3) ORDER BY r.id LIMIT 101")
            .bind(p.tenant_id()).bind(input.after).bind(input.revision as i64).fetch_all(&mut *tx).await.map_err(db)?;
        let more = rows.len() > 100;
        if more {
            rows.pop();
        }
        let next = if more {
            rows.last()
                .map(|r| r.try_get("id").map_err(db))
                .transpose()?
        } else {
            None
        };
        let mut items = Vec::new();
        for row in rows {
            let device: String = row.try_get("device").map_err(db)?;
            match snapshot.require(p, Permission::InventoryRead, Some(&device)) {
                Ok(()) => {}
                Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => {
                    continue;
                }
                Err(error) => {
                    return Err(
                        Error::from(rss_mdm_authorization_service::Error::from(error)).into(),
                    );
                }
            }
            items.push(DeviceStatus {
                device,
                registration: row.try_get("id").map_err(db)?,
                generation: u64::try_from(row.try_get::<i64, _>("generation").map_err(db)?)
                    .map_err(|_| Error::Corrupt)?,
                installed_revision: row
                    .try_get::<Option<i64>, _>("revision")
                    .map_err(db)?
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| Error::Corrupt)?,
                origin: row.try_get("origin").map_err(db)?,
                received_at: row.try_get("received_at").map_err(db)?,
            });
        }
        p.check_live()?;
        tx.rollback().await.map_err(db)?;
        Ok(UnconfirmedDevices {
            target_revision: input.revision,
            items,
            next,
        })
    }
    pub async fn connection_observation(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<Option<Observation>, Failure> {
        p.check_live()?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        rss_mdm_authorization_service::lock_on(&mut tx, p.tenant_id(), p.instance_id()).await?;
        rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id())
            .await?
            .require(p, Permission::InventoryRead, Some(device))
            .map_err(|_| Error::Forbidden)?;
        let row=sqlx::query("SELECT (SELECT max(revision) FROM mdm_access.agent_connection_versions WHERE tenant_id=r.tenant_id) AS target_revision,r.id AS registration,r.generation,a.document,a.received_at,f.document AS failure_document,f.origin AS failure_origin,f.received_at AS failure_received_at FROM mdm_access.registrations r LEFT JOIN LATERAL(SELECT revision,document,received_at,recorded_at FROM mdm_access.agent_connection_observations WHERE tenant_id=r.tenant_id AND registration=r.id AND generation=r.generation ORDER BY revision DESC,recorded_at DESC LIMIT 1) a ON true LEFT JOIN LATERAL(SELECT document,origin,received_at FROM mdm_access.agent_connection_failures WHERE tenant_id=r.tenant_id AND registration=r.id AND generation=r.generation AND (revision>coalesce(a.revision,0) OR (revision=a.revision AND recorded_at>a.recorded_at)) ORDER BY revision DESC,recorded_at DESC LIMIT 1) f ON true WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.state='active'")
            .bind(p.tenant_id()).bind(device).fetch_optional(&mut *tx).await.map_err(db)?;
        let out = row
            .map(|r| {
                Ok::<_, Error>(Observation {
                    target_revision: r
                        .try_get::<Option<i64>, _>("target_revision")
                        .map_err(db)?
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|_| Error::Corrupt)?,
                    registration: r.try_get("registration").map_err(db)?,
                    generation: u64::try_from(r.try_get::<i64, _>("generation").map_err(db)?)
                        .map_err(|_| Error::Corrupt)?,
                    acknowledgement: r
                        .try_get::<Option<serde_json::Value>, _>("document")
                        .map_err(db)?
                        .map(|v| serde_json::from_value(v).map_err(|_| Error::Corrupt))
                        .transpose()?,
                    received_at: r.try_get("received_at").map_err(db)?,
                    failure: r
                        .try_get::<Option<serde_json::Value>, _>("failure_document")
                        .map_err(db)?
                        .map(|v| {
                            Ok::<_, Error>(FailureObservation {
                                report: serde_json::from_value(v).map_err(|_| Error::Corrupt)?,
                                origin: r.try_get("failure_origin").map_err(db)?,
                                received_at: r.try_get("failure_received_at").map_err(db)?,
                            })
                        })
                        .transpose()?,
                })
            })
            .transpose()?;
        tx.rollback().await.map_err(db)?;
        Ok(out)
    }
}

async fn authorize_write(c: &mut PgConnection, p: &AuthorizedPrincipal) -> Result<(), Error> {
    super::authorize_on(c, p, Permission::RegistrationConfigurationWrite).await?;
    if !p.recently_authenticated(now(c).await?, 300)? {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

/// Ordinary consumer fixtures start from one valid current signed configuration.
/// This does not fabricate deployment observations or stand in for publication acceptance.
#[cfg(feature = "integration")]
pub async fn fixture_configuration_on(
    c: &mut PgConnection,
    tenant: Uuid,
    protection: &Protector,
    origin: &str,
) -> Result<(), Error> {
    let tenant = tenant.to_string();
    lock(c, &tenant).await?;
    if published_on(c, &tenant, None).await?.is_some() {
        return Ok(());
    }
    let signer = ensure_signer_on(c, &tenant, protection).await?;
    let draft = Draft {
        configuration: w::Configuration {
            wire_version: 1,
            service_id: service_id_on(c).await?,
            tenant_id: Uuid::parse_str(&tenant).map_err(|_| Error::Configuration)?,
            revision: 1,
            preferred_origin: origin.into(),
            origins: vec![origin.into()],
            key_id: signer.key_id.clone(),
        },
    };
    let published = signer.sign_connections(draft.configuration.clone())?;
    sqlx::query("INSERT INTO mdm_access.agent_connection_drafts(tenant_id,revision,document) VALUES($1::uuid,1,$2)").bind(&tenant).bind(serde_json::to_value(draft).map_err(|_|Error::Corrupt)?).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.agent_connection_versions(tenant_id,revision,document) VALUES($1::uuid,1,$2)").bind(tenant).bind(serde_json::to_value(published).map_err(|_|Error::Corrupt)?).execute(c).await.map_err(db)?;
    Ok(())
}

/// Re-encrypt only the configuration private key under the existing Native protection rotation.
/// Signed public history, key identity and every connection revision remain unchanged.
pub async fn rewrap(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    protection: &Protector,
) -> Result<u64, Error> {
    let prefix = protection.ciphertext_prefix();
    let rows=sqlx::query("SELECT key_id,private_key FROM mdm_access.agent_configuration_keys WHERE tenant_id=$1::uuid AND substring(private_key FROM 1 FOR $2)<>$3 FOR UPDATE")
        .bind(tenant.to_string()).bind(prefix.len() as i32).bind(prefix).fetch_all(&mut *c).await.map_err(db)?;
    for row in &rows {
        let id: String = row.try_get("key_id").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
        let next = protection
            .rewrap_bytes(&sealed, &key_aad(&tenant.to_string(), &id)?)
            .map_err(|_| Error::Corrupt)?;
        sqlx::query("UPDATE mdm_access.agent_configuration_keys SET private_key=$3 WHERE tenant_id=$1::uuid AND key_id=$2")
            .bind(tenant.to_string()).bind(id).bind(next).execute(&mut *c).await.map_err(db)?;
    }
    Ok(rows.len() as u64)
}
