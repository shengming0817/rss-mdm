//! Reusable administrator authority; grants and durable issuance facts own its allocations.
//! ref: ring src/ec/curve25519/ed25519/signing.rs; sqlx-core/src/transaction.rs.
pub mod directory;
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rss_mdm_agent_wire::enroll::configuration as wire_config;
use rss_mdm_authorization_service::Permission;
use std::collections::BTreeMap;
/// Configuration-specific signer; no dependency on the execution/task owner.
pub struct Signer {
    pub(super) key_id: String,
    key: Ed25519KeyPair,
    trusted_keys: BTreeMap<String, String>,
}
impl Signer {
    pub fn new(
        private: &[u8],
        key_id: &str,
        trusted_keys: &BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let key = Ed25519KeyPair::from_pkcs8(private).map_err(|_| Error::Configuration)?;
        let expected = trusted_keys.get(key_id).ok_or(Error::Configuration)?;
        if key_id.is_empty()
            || key_id.len() > 128
            || trusted_keys.len() > 16
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || URL_SAFE_NO_PAD
                .decode(expected)
                .map_err(|_| Error::Configuration)?
                != key.public_key().as_ref()
        {
            return Err(Error::Configuration);
        }
        for (id, key) in trusted_keys {
            if id.is_empty()
                || id.len() > 128
                || URL_SAFE_NO_PAD.decode(key).map_or(true, |v| v.len() != 32)
            {
                return Err(Error::Configuration);
            }
        }
        Ok(Self {
            key_id: key_id.into(),
            key,
            trusted_keys: trusted_keys.clone(),
        })
    }
    fn sign(
        &self,
        configuration: wire_config::Configuration,
        secret: runtime::Secret,
    ) -> Result<wire_config::ConfigurationFile, Error> {
        if configuration.key_id != self.key_id {
            return Err(Error::Configuration);
        }
        let bytes = configuration
            .signing_bytes(&secret)
            .map_err(|_| Error::Malformed)?;
        let signature = URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).as_ref());
        Ok(wire_config::ConfigurationFile {
            configuration,
            secret,
            signature,
        })
    }
    pub(super) fn sign_connections(
        &self,
        configuration: rss_mdm_agent_wire::connections::Configuration,
    ) -> Result<rss_mdm_agent_wire::connections::SignedConfiguration, Error> {
        if configuration.key_id != self.key_id {
            return Err(Error::Configuration);
        }
        let bytes = configuration
            .signing_bytes()
            .map_err(|_| Error::Malformed)?;
        Ok(rss_mdm_agent_wire::connections::SignedConfiguration {
            configuration,
            signature: URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).as_ref()),
        })
    }
    pub(super) fn verify(&self, file: &wire_config::ConfigurationFile) -> Result<(), Error> {
        let key = self
            .trusted_keys
            .get(&file.configuration.key_id)
            .ok_or(Error::Unauthorized)?;
        let key = URL_SAFE_NO_PAD
            .decode(key)
            .map_err(|_| Error::Configuration)?;
        let bytes = file
            .configuration
            .signing_bytes(&file.secret)
            .map_err(|_| Error::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&file.signature)
            .map_err(|_| Error::Unauthorized)?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&bytes, &signature)
            .map_err(|_| Error::Unauthorized)
    }
}
/// Publication owner checks the exact current release in this same tenant transaction.
pub trait InstallationAdmission: Send + Sync {
    fn verify<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        installation: &'a wire_config::Installation,
    ) -> Pending<'a, wire_config::Package>;
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub operation_id: Uuid,
    /// Management client retains this for exact recovery; the database holds only its digest.
    pub secret: runtime::Secret,
    pub lifetime_seconds: Option<u32>,
    pub quantity: wire_config::Quantity,
    pub targets: Vec<wire_config::Target>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Read {
    pub configuration: wire_config::Configuration,
    pub state: String,
    pub created_by: String,
    /// Nullable business responsibility is unrelated to management audit identity.
    pub responsible_user: Option<rss_mdm_authorization_service::User>,
    pub reserved: u64,
    pub consumed: u64,
    /// Quantity authority only; expiry and revocation remain separate admission checks.
    pub remaining: Option<u64>,
}
async fn read_on(c: &mut PgConnection, tenant: &str, row: &PgRow) -> Result<Read, Error> {
    let configuration = document(row)?;
    let (reserved, consumed) = usage(c, tenant, configuration.configuration_id).await?;
    let state = if row.try_get::<String, _>("state").map_err(db)? == "revoked" {
        "revoked"
    } else if configuration.expires_at <= now(c).await? {
        "expired"
    } else {
        "available"
    }
    .into();
    let remaining = match &configuration.quantity {
        wire_config::Quantity::Finite { count } => Some(
            u64::from(count.get())
                .checked_sub(reserved)
                .and_then(|n| n.checked_sub(consumed))
                .ok_or(Error::Corrupt)?,
        ),
        wire_config::Quantity::Unlimited => None,
    };
    Ok(Read {
        configuration,
        state,
        created_by: row.try_get("creator").map_err(db)?,
        responsible_user: None,
        reserved,
        consumed,
        remaining,
    })
}
fn configuration_secret(tenant: &str, id: Uuid, secret: &runtime::Secret) -> String {
    let mut h = Sha256::new();
    h.update(b"rss-mdm-agent-configuration-secret/v1\0");
    h.update(tenant.as_bytes());
    h.update(id.as_bytes());
    h.update(secret.expose().as_bytes());
    hex(h.finalize())
}
fn check_configuration_secret(
    tenant: &str,
    row: &PgRow,
    secret: &runtime::Secret,
) -> Result<(), Error> {
    use subtle::ConstantTimeEq;
    let expected: String = row.try_get("secret_digest").map_err(db)?;
    let actual = configuration_secret(tenant, row.try_get("id").map_err(db)?, secret);
    if !bool::from(expected.as_bytes().ct_eq(actual.as_bytes())) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
async fn row(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<PgRow, Error> {
    sqlx::query("SELECT * FROM mdm_access.agent_configurations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(tenant).bind(id).fetch_optional(c).await.map_err(db)?.ok_or(Error::Unauthorized)
}
fn document(row: &PgRow) -> Result<wire_config::Configuration, Error> {
    serde_json::from_value(row.try_get("document").map_err(db)?).map_err(|_| Error::Corrupt)
}
async fn usage(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<(u64, u64), Error> {
    let counts:(i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM mdm_access.agent_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id)) AND g.state='available' AND g.expires_at>clock_timestamp()),count(*) FILTER(WHERE EXISTS(SELECT 1 FROM mdm_access.agent_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id))) FROM mdm_access.agent_grants g WHERE g.tenant_id=$1::uuid AND g.configuration_id=$2")
        .bind(tenant).bind(id).fetch_one(c).await.map_err(db)?;
    Ok((
        u64::try_from(counts.0).map_err(|_| Error::Corrupt)?,
        u64::try_from(counts.1).map_err(|_| Error::Corrupt)?,
    ))
}
/// Acquire configuration before grant; hold until the durable issuance claim settles.
/// Never call after taking a grant lock: expiry/claim/exchange must serialize together.
pub(super) async fn lock_for_grant(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<(), Error> {
    let config: Option<Uuid> = sqlx::query_scalar(
        "SELECT configuration_id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .ok_or(Error::Unauthorized)?;
    if let Some(config) = config {
        row(c, tenant, config).await?;
    }
    Ok(())
}
impl Service {
    pub async fn create_configuration(
        &self,
        p: &AuthorizedPrincipal,
        input: &Create,
        a: &RequestAudit,
    ) -> Result<wire_config::ConfigurationFile, Failure> {
        self.proof(p, a)?;
        p.manage(Permission::AgentEnrollmentWrite)?;
        version(wire::API_VERSION, input.operation_id)?;
        wire_config::validate_scope(&input.targets).map_err(|_| Error::Malformed)?;
        let d = digest(&(
            "agent_configuration.v1",
            input.operation_id,
            &input.secret,
            input.lifetime_seconds,
            &input.quantity,
            &input.targets,
        ))?;
        a.operation(
            input.operation_id,
            "agent_configuration_create",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let config=self.write(a,(self,p,input,d),|ctx,c|Box::pin(async move {
            let (service,p,input,d)=ctx;let tenant=service.tenant.to_string();
            authorize_on(c,p,Permission::AgentEnrollmentWrite).await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2674))")
                .bind(format!("{tenant}:configuration:{}",input.operation_id)).execute(&mut *c).await.map_err(db)?;
            if let Some(id)=sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_access.agent_configurations WHERE tenant_id=$1::uuid AND operation_id=$2")
                .bind(&tenant).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)?{
                let old=row(c,&tenant,id).await?;check_configuration_secret(&tenant,&old,&input.secret)?;
                if old.try_get::<String,_>("request_digest").map_err(db)?!=*d || old.try_get::<String,_>("creator").map_err(db)?!=p.principal_id() || old.try_get::<String,_>("instance").map_err(db)?!=p.instance_id(){return Err(Error::Conflict);}
                return Ok(Change{value:(document(&old)?,old.try_get::<String,_>("signature").map_err(db)?),replay:true,digest:d.clone()});
            }
            crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::Agent).await?;
            let mut defaults=None;
            for target in &input.targets {defaults=Some(settings::admit_on(c,&tenant,target.platform).await?);}
            let seconds=input.lifetime_seconds.unwrap_or(defaults.ok_or(Error::Malformed)?.configuration_default_seconds);
            if !(1..=settings::CONFIGURATION_MAX_SECONDS).contains(&seconds){return Err(Error::Malformed);}
            super::connections::lock(c, &tenant).await?;
            let signer = super::connections::signer_on(c, &tenant, &service.protection).await?;
            let connections = super::connections::current_on(c, &tenant).await?;
            let id=Uuid::new_v4();let expires_at=now(c).await?+i64::from(seconds);
            let config=wire_config::Configuration{wire_version:1,configuration_id:id,tenant_id:Uuid::parse_str(&tenant).map_err(|_|Error::Configuration)?,connections,targets:input.targets.clone(),expires_at,quantity:input.quantity.clone(),key_id:signer.key_id.clone()};
            config.signing_bytes(&input.secret).map_err(|_|Error::Configuration)?;
            let signature=signer.sign(config.clone(),input.secret.clone())?.signature;
            let quantity=match input.quantity{wire_config::Quantity::Finite{count}=>Some(i64::from(count.get())),wire_config::Quantity::Unlimited=>None};
            sqlx::query("INSERT INTO mdm_access.agent_configurations(tenant_id,id,operation_id,creator,instance,secret_digest,request_digest,signature,document,quantity,state,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',to_timestamp($11))")
                .bind(&tenant).bind(id).bind(input.operation_id).bind(p.principal_id()).bind(p.instance_id()).bind(configuration_secret(&tenant,id,&input.secret)).bind(&*d).bind(&signature).bind(serde_json::to_value(&config).map_err(|_|Error::Malformed)?).bind(quantity).bind(expires_at as f64).execute(&mut *c).await.map_err(db)?;
            p.manage(Permission::AgentEnrollmentWrite)?;
            Ok(Change{value:(config,signature),replay:false,digest:d.clone()})
        })).await?;
        Ok(wire_config::ConfigurationFile {
            configuration: config.0,
            signature: config.1,
            secret: input.secret.clone(),
        })
    }
    pub async fn read_configuration(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<Read, Failure> {
        p.manage(Permission::AgentEnrollmentRead)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        authorize_on(&mut tx, p, Permission::AgentEnrollmentRead).await?;
        let row = row(&mut tx, p.tenant_id(), id).await?;
        let out = read_on(&mut tx, p.tenant_id(), &row).await?;
        p.check_live()?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
    /// Resolve a possibly committed create without recovering its transferable secret.
    /// Absence is an unknown outcome: a concurrent create can still commit later.
    pub async fn configuration_operation(
        &self,
        p: &AuthorizedPrincipal,
        operation: Uuid,
    ) -> Result<Option<Read>, Failure> {
        p.manage(Permission::AgentEnrollmentRead)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        if operation.is_nil() {
            return Err(Error::Malformed.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        authorize_on(&mut tx, p, Permission::AgentEnrollmentRead).await?;
        let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM mdm_access.agent_configurations WHERE tenant_id=$1::uuid AND operation_id=$2 AND creator=$3 AND instance=$4")
            .bind(p.tenant_id()).bind(operation).bind(p.principal_id()).bind(p.instance_id())
            .fetch_optional(&mut *tx).await.map_err(db)?;
        let out = if let Some(id) = id {
            let row = row(&mut tx, p.tenant_id(), id).await?;
            Some(read_on(&mut tx, p.tenant_id(), &row).await?)
        } else {
            None
        };
        p.check_live()?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
    pub async fn revoke_configuration(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<(), Failure> {
        self.proof(p, a)?;
        p.manage(Permission::AgentEnrollmentWrite)?;
        version(1, operation)?;
        a.operation(
            operation,
            "agent_configuration_revoke",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let d = digest(&("configuration_revoke", id, operation))?;
        self.write(a,(self,p,id,d,operation,a),|ctx,c|Box::pin(async move {
            let (service,p,id,d,operation,a)=ctx;let tenant=service.tenant.to_string();
            authorize_on(c,p,Permission::AgentEnrollmentWrite).await?;
            let op=crate::operations::Operation{actor:crate::operations::Actor::from_authorized(p),key:*operation,digest:d};
            if crate::operations::replay(c,&op).await?.is_some(){return Ok(Change{value:(),replay:true,digest:d.clone()});}
            row(c,&tenant,*id).await?;
            sqlx::query("UPDATE mdm_access.agent_configurations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(*id).execute(&mut *c).await.map_err(db)?;
            crate::operations::save(c,&op,"null",a).await?;
            Ok(Change{value:(),replay:false,digest:d.clone()})
        })).await.map_err(Into::into)
    }
    pub async fn exchange_configuration(
        &self,
        input: &wire_config::Exchange,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        version(input.file.configuration.wire_version, input.operation_id)?;
        let mut verification = self.store.begin(&self.tenant.to_string()).await?;
        let signer = super::connections::signer_on(
            &mut verification,
            &self.tenant.to_string(),
            &self.protection,
        )
        .await?;
        signer.verify(&input.file)?;
        verification.rollback().await.map_err(db)?;
        if input.secret.expose() == input.file.secret.expose() {
            return Err(Error::Malformed.into());
        }
        input.runtime.validate().map_err(|_| Error::Malformed)?;
        let spki = hex(csr(&input.csr)?.spki());
        let d = digest(input)?;
        a.operation(
            input.operation_id,
            "agent_configuration_exchange",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(a,(self,input,spki,d),|ctx,c|Box::pin(async move {
            let (service,input,spki,d)=ctx;let tenant=service.tenant.to_string();let cfg=&input.file.configuration;
            if cfg.tenant_id.to_string()!=tenant || cfg.connections.configuration.service_id!=service.service_id()?{return Err(Error::Forbidden);}
            let config=row(c,&tenant,cfg.configuration_id).await?;check_configuration_secret(&tenant,&config,&input.file.secret)?;
            if serde_json::to_value(cfg).map_err(|_|Error::Malformed)?!=config.try_get::<serde_json::Value,_>("document").map_err(db)?{return Err(Error::Unauthorized);}
            if let Some(id)=sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='configuration' AND operation_id=$2")
                .bind(&tenant).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)?{
                let old=grant_row(c,&tenant,id).await?;check_secret(&tenant,&old,&input.secret)?;
                if old.try_get::<String,_>("request_digest").map_err(db)?!=*d || old.try_get::<Option<Uuid>,_>("configuration_id").map_err(db)?!=Some(cfg.configuration_id){return Err(Error::Conflict);}
                return Ok(Change{value:receipt(&old)?,replay:true,digest:d.clone()});
            }
            if config.try_get::<String,_>("state").map_err(db)?!="available"{return Err(Error::Agent(wire::ErrorCode::GrantRevoked));}
            if cfg.expires_at<=now(c).await?{return Err(Error::Agent(wire::ErrorCode::GrantExpired));}
            crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::Agent).await?;
            let values=settings::admit_on(c,&tenant,input.runtime.platform).await?;
            let package=service.installations.verify(c,&tenant,&input.installation).await?;
            let target=wire_config::Target{platform:input.runtime.platform,architecture:input.runtime.architecture};
            if package.tenant_id!=cfg.tenant_id || package.target!=target || !cfg.targets.contains(&target){return Err(Error::Forbidden);}
            let reused:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND configuration_id=$2 AND spki=$3)").bind(&tenant).bind(cfg.configuration_id).bind(&*spki).fetch_one(&mut *c).await.map_err(db)?;
            if reused{return Err(Error::Conflict);}
            if let wire_config::Quantity::Finite{count}=cfg.quantity {
                let (reserved,consumed)=usage(c,&tenant,cfg.configuration_id).await?;
                if reserved+consumed>=u64::from(count.get()){return Err(Error::RegistrationLimit);}
            }
            let id=Uuid::new_v4();
            let binding=serde_json::json!({"runtime":input.runtime,"installation":input.installation});
            sqlx::query("INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,created_at,expires_at,configuration_id,configuration_binding) VALUES($1::uuid,$2,$3,'configuration',$4,$5,$6,$7,$8,$9,$10,'available',statement_timestamp(),statement_timestamp()+make_interval(secs=>$11),$12,$13)")
                .bind(&tenant).bind(id).bind(input.operation_id).bind(config.try_get::<String,_>("creator").map_err(db)?).bind(config.try_get::<String,_>("instance").map_err(db)?).bind(Uuid::new_v4().to_string()).bind(platform(input.runtime.platform))
                .bind(secret_digest(&tenant,id,&input.secret)).bind(&*d).bind(&*spki).bind(f64::from(values.grant_seconds)).bind(cfg.configuration_id).bind(binding).execute(&mut *c).await.map_err(db)?;
            Ok(Change{value:receipt(&grant_row(c,&tenant,id).await?)?,replay:false,digest:d.clone()})
        })).await.map_err(Into::into)
    }
    pub async fn configuration_exchange_status(
        &self,
        input: &wire_config::ExchangeStatus,
    ) -> Result<wire::GrantReceipt, Failure> {
        version(input.wire_version, input.operation_id)?;
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let row=sqlx::query("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>clock_timestamp() AS live FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND configuration_id=$2 AND operation_id=$3 AND source='configuration'")
            .bind(&tenant).bind(input.configuration_id).bind(input.operation_id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
        check_secret(&tenant, &row, &input.secret)?;
        let out = receipt(&row)?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
    pub async fn cancel_reservation(
        &self,
        input: &wire_config::Cancel,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        version(input.wire_version, input.operation_id)?;
        a.operation(
            input.operation_id,
            "agent_reservation_cancel",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let d = digest(input)?;
        self.write(a,(self,input,d),|ctx,c|Box::pin(async move {
            let (service,input,d)=ctx;let tenant=service.tenant.to_string();let row=grant_row(c,&tenant,input.grant_id).await?;
            check_secret(&tenant,&row,&input.secret)?;
            if row.try_get::<Uuid,_>("operation_id").map_err(db)?!=input.creation_operation_id{return Err(Error::Conflict);}
            let issued:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND grant_id=$2)").bind(&tenant).bind(input.grant_id).fetch_one(&mut *c).await.map_err(db)?;
            if issued{return Err(Error::Conflict);}
            let replay=row.try_get::<String,_>("state").map_err(db)?=="revoked";
            sqlx::query("UPDATE mdm_access.agent_grants SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(input.grant_id).execute(&mut *c).await.map_err(db)?;
            Ok(Change{value:receipt(&grant_row(c,&tenant,input.grant_id).await?)?,replay,digest:d.clone()})
        })).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_bind_every_field_and_do_not_trust_file_keys() {
        let private = include_bytes!("../../tests/fixtures/configuration-signer.pk8");
        let key = Ed25519KeyPair::from_pkcs8(private.as_ref()).unwrap();
        let keys = BTreeMap::from([(
            "current".into(),
            URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        )]);
        let signer = Signer::new(private.as_ref(), "current", &keys).unwrap();
        let tenant_id = Uuid::new_v4();
        let connections = signer
            .sign_connections(rss_mdm_agent_wire::connections::Configuration {
                wire_version: 1,
                service_id: Uuid::new_v4(),
                tenant_id,
                revision: 1,
                preferred_origin: "https://mdm.example.test:9445".into(),
                origins: vec!["https://mdm.example.test:9445".into()],
                key_id: "current".into(),
            })
            .unwrap();
        let config = wire_config::Configuration {
            wire_version: 1,
            configuration_id: Uuid::new_v4(),
            tenant_id,
            connections,
            targets: vec![wire_config::Target {
                platform: runtime::TaskPlatform::Macos,
                architecture: runtime::TaskArchitecture::Aarch64,
            }],
            expires_at: 100,
            quantity: wire_config::Quantity::Unlimited,
            key_id: "current".into(),
        };
        let secret = runtime::Secret::parse(&URL_SAFE_NO_PAD.encode([13; 32])).unwrap();
        let file = signer.sign(config, secret).unwrap();
        signer.verify(&file).unwrap();
        for field in [
            "connections",
            "expiresAt",
            "quantity",
            "tenantId",
            "targets",
            "keyId",
            "secret",
        ] {
            let mut value = serde_json::to_value(&file).unwrap();
            if field == "secret" {
                value[field] = serde_json::json!(URL_SAFE_NO_PAD.encode([14; 32]));
            } else {
                value["configuration"][field] = match field {
                    "connections" => {
                        let mut connections = file.configuration.connections.clone();
                        connections.configuration.preferred_origin =
                            "https://other.example.test".into();
                        serde_json::to_value(connections).unwrap()
                    }
                    "expiresAt" => serde_json::json!(101),
                    "quantity" => serde_json::json!({"kind":"finite","count":1}),
                    "tenantId" => serde_json::json!(Uuid::new_v4()),
                    "targets" => {
                        serde_json::json!([{"platform":"windows","architecture":"x86_64"}])
                    }
                    _ => serde_json::json!("untrusted"),
                };
            }
            let changed: wire_config::ConfigurationFile = serde_json::from_value(value).unwrap();
            assert!(
                signer.verify(&changed).is_err(),
                "unsigned {field} mutation"
            );
        }
        assert!(!format!("{file:?}").contains(file.secret.expose()));
    }
}
