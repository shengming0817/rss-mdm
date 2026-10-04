//! One tenant/purpose registry; trust distribution precedes activation and safe retirement.
use crate::Error;
use rss_mdm_agent_wire::pki::{Acknowledgement, Mode, Purpose, Trust};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_device_trust::{DeviceTrust, decode};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

pub fn purpose(value: Purpose) -> &'static str {
    match value {
        Purpose::Windows => "windows",
        Purpose::Apple => "apple",
        Purpose::Agent => "agent",
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub id: Uuid,
    pub purpose: Purpose,
    pub expected_revision: u64,
    pub candidate: Trust,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub id: Uuid,
    pub expected_revision: u64,
    pub action: Action,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Approve,
    Activate,
    Retire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation: Uuid,
    pub revision: u64,
    pub state: String,
}
pub struct Registry {
    pub(crate) pool: PgPool,
    pub(crate) audit: Arc<AuditStore>,
    bindings: Vec<DeviceTrust>,
    pub(crate) providers: Arc<crate::providers::Providers>,
}
impl Registry {
    pub fn new(
        pool: PgPool,
        audit: Arc<AuditStore>,
        bindings: Vec<DeviceTrust>,
        providers: Arc<crate::providers::Providers>,
    ) -> Self {
        Self {
            pool,
            audit,
            bindings,
            providers,
        }
    }
    pub fn bindings(&self) -> &[DeviceTrust] {
        &self.bindings
    }
    pub(crate) fn binding(&self, purpose: Purpose) -> Result<&DeviceTrust, Error> {
        self.bindings
            .iter()
            .find(|b| b.public().is_ok_and(|t| t.purpose == purpose))
            .ok_or(Error::Configuration)
    }
    /// Bootstrap is audited. Durable revisions win over deployment files after rotation.
    pub async fn admit(&self, tenant: TenantId, now: i64) -> Result<(), Error> {
        for binding in &self.bindings {
            let configured = binding.public().map_err(|_| Error::Configuration)?;
            if configured.tenant.to_string() != tenant.to_string() {
                return Err(Error::Configuration);
            }
            let mut read = self.begin(&tenant.to_string()).await?;
            let stored = sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT body FROM mdm_pki.trust WHERE tenant_id=$1::uuid AND purpose=$2",
            )
            .bind(tenant.to_string())
            .bind(purpose(configured.purpose))
            .fetch_optional(&mut *read)
            .await
            .map_err(|_| Error::Storage)?;
            let archived: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT chain FROM mdm_pki.issuers WHERE tenant_id=$1::uuid AND purpose=$2",
            )
            .bind(tenant.to_string())
            .bind(purpose(configured.purpose))
            .fetch_all(&mut *read)
            .await
            .map_err(|_| Error::Storage)?;
            let archived = archived
                .into_iter()
                .map(|bytes| {
                    serde_json::from_slice::<rss_mdm_agent_wire::pki::Issuer>(&bytes)
                        .map_err(|_| Error::Storage)
                })
                .collect::<Result<Vec<_>, _>>()?;
            read.rollback().await.map_err(|_| Error::Storage)?;
            let mut next = match stored.as_ref() {
                Some(bytes) => {
                    let mut stored: Trust =
                        serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
                    if configured.origin != stored.origin
                        || configured.issuers.iter().any(|g| {
                            !stored.issuers.iter().chain(archived.iter()).any(|s| {
                                s.digest == g.digest
                                    && s.certificate == g.certificate
                                    && s.root == g.root
                                    && s.provisioner == g.provisioner
                                    && s.kid == g.kid
                            })
                        })
                    {
                        return Err(Error::Conflict);
                    }
                    for g in &mut stored.issuers {
                        if let Some(c) = configured.issuers.iter().find(|c| c.digest == g.digest) {
                            let root = x509_cert::Certificate::from_der(
                                &decode(&g.root, 32768).map_err(|_| Error::Configuration)?,
                            )
                            .map_err(|_| Error::Configuration)?;
                            let previous = rss_mdm_device_trust::crl(
                                &decode(&g.root_crl, 16 * 1024 * 1024)
                                    .map_err(|_| Error::Configuration)?,
                                &root,
                                crate::maintenance::publication_time(
                                    &serde_json::from_slice(bytes).map_err(|_| Error::Storage)?,
                                )?,
                            )
                            .map_err(|_| Error::Configuration)?;
                            if let Ok(replacement) = rss_mdm_device_trust::crl(
                                &decode(&c.root_crl, 16 * 1024 * 1024)
                                    .map_err(|_| Error::Configuration)?,
                                &root,
                                now,
                            ) && (replacement.number > previous.number
                                || (replacement.number == previous.number
                                    && replacement.der == previous.der))
                            {
                                g.root_crl = c.root_crl.clone();
                            }
                        }
                    }
                    stored
                }
                None => configured.clone(),
            };
            // Fresh online CRLs are fetched before entering the Audit/business transaction.
            for g in &mut next.issuers {
                if let Ok(provider) = self.providers.get(next.purpose, &g.digest) {
                    g.crl = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        provider.published_crl().await?,
                    );
                } else if g.mode != Mode::VerifyOnly || !g.provisioner.is_empty() {
                    return Err(Error::Configuration);
                }
            }
            DeviceTrust::new(next.clone(), next.purpose, now).map_err(|_| Error::Configuration)?;
            if let Some(bytes) = &stored {
                let old: Trust = serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
                let previous = DeviceTrust::new(
                    old.clone(),
                    old.purpose,
                    crate::maintenance::publication_time(&old)?,
                )
                .map_err(|_| Error::Storage)?;
                previous
                    .update(next.clone(), now)
                    .map_err(|_| Error::Conflict)?;
            }
            let hash =
                sha2::Sha256::digest(serde_json::to_vec(&next).map_err(|_| Error::Configuration)?)
                    .to_vec();
            let id = Uuid::from_bytes(hash[..16].try_into().map_err(|_| Error::Storage)?);
            let a = RequestAudit::new(tenant.to_string(), "device_pki_admit");
            a.identify_service("service:device-pki");
            a.operation(id, "device_pki_admit");
            let result=self.mutation(tenant,&a,(next.clone(),stored,hash,id),|ctx,c|Box::pin(async move {
                let (next,observed,hash,id)=ctx;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))").bind(next.tenant.to_string()).execute(&mut *c).await.map_err(|_|Error::Storage)?;
                let current=sqlx::query_scalar::<_,Vec<u8>>("SELECT body FROM mdm_pki.trust WHERE tenant_id=$1 AND purpose=$2 FOR UPDATE")
                    .bind(next.tenant).bind(purpose(next.purpose)).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)?;
                if current!=*observed {return Err(Error::Conflict);}
                let replay=crate::mutation::replay(c,&next.tenant.to_string(),"service:device-pki","",*id,"admit",hash).await?.is_some();
                persist(c,next).await?;
                if !replay {crate::mutation::save(c,(&next.tenant.to_string(),"service:device-pki",""),*id,"admit",hash,b"null").await?;}
                Ok(crate::mutation::Change{value:(),replay,key:format!("pki:{id}:admit"),fingerprint:hash.clone()})
            })).await;
            a.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            result?;
            binding.update(next, now).map_err(|_| Error::Conflict)?;
        }
        Ok(())
    }
    pub async fn begin(
        &self,
        tenant: &str,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
        Ok(tx)
    }
    /// Durable approval and publications are shared across app processes.
    pub async fn synchronize(&self, now: i64) -> Result<(), Error> {
        for binding in &self.bindings {
            let current = binding.public().map_err(|_| Error::Storage)?;
            let mut tx = self.begin(&current.tenant.to_string()).await?;
            let bytes: Vec<u8> = sqlx::query_scalar(
                "SELECT body FROM mdm_pki.trust WHERE tenant_id=$1 AND purpose=$2",
            )
            .bind(current.tenant)
            .bind(purpose(current.purpose))
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
            tx.rollback().await.map_err(|_| Error::Storage)?;
            let stored: Trust = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            DeviceTrust::restore(stored.clone(), stored.purpose, now)
                .map_err(|_| Error::Storage)?;
            binding
                .update(
                    stored.clone(),
                    crate::maintenance::publication_time(&stored)?,
                )
                .map_err(|_| Error::Conflict)?;
        }
        Ok(())
    }
    pub fn trust(&self, purpose: Purpose) -> Result<Trust, Error> {
        self.binding(purpose)?.public().map_err(|_| Error::Storage)
    }
    pub async fn prepare(
        &self,
        p: &AuthorizedPrincipal,
        input: &Rotation,
        a: &RequestAudit,
        now: i64,
    ) -> Result<Receipt, Error> {
        p.require_all_devices(Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        self.synchronize(now).await?;
        let request =
            sha2::Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Request)?).to_vec();
        if let Some(old) = self
            .rotation_replay(p, a, input.id, "distributing", &request)
            .await?
        {
            return Ok(old);
        }
        let old = self.trust(input.purpose)?;
        if input.id.is_nil()
            || old.tenant.to_string() != p.tenant_id()
            || input.expected_revision != old.revision
            || input.candidate.revision != old.revision + 1
            || input.candidate.origin != old.origin
            || input.candidate.tenant != old.tenant
            || input.candidate.purpose != old.purpose
        {
            return Err(Error::Conflict);
        }
        let mut candidate_trust = input.candidate.clone();
        for previous in &old.issuers {
            let next = candidate_trust
                .issuers
                .iter_mut()
                .find(|g| g.digest == previous.digest)
                .ok_or(Error::Conflict)?;
            if next.mode != previous.mode
                || next.certificate != previous.certificate
                || next.root != previous.root
                || next.provisioner != previous.provisioner
                || next.kid != previous.kid
            {
                return Err(Error::Conflict);
            }
            // Concurrent CRL refresh must not invalidate an otherwise exact rotation proposal.
            *next = previous.clone();
        }
        DeviceTrust::new(candidate_trust.clone(), input.purpose, now)
            .map_err(|_| Error::Request)?;
        let added = input
            .candidate
            .issuers
            .iter()
            .filter(|g| !old.issuers.iter().any(|p| p.digest == g.digest))
            .collect::<Vec<_>>();
        if added.len() != 1 || added[0].mode != Mode::Prepared {
            return Err(Error::Request);
        }
        self.providers
            .get(input.purpose, &added[0].digest)?
            .verify_issuer(&added[0].digest)
            .await?;
        let previous = old
            .issuers
            .iter()
            .find(|g| g.mode == Mode::Active)
            .ok_or(Error::Configuration)?
            .digest
            .clone();
        let candidate = added[0].digest.clone();
        let state = "distributing";
        let receipt = self
            .write(
                p,
                a,
                (input.id, input.expected_revision),
                (&candidate_trust, state, Some((&previous, &candidate))),
                now,
                &request,
            )
            .await?;
        self.binding(input.purpose)?
            .update(candidate_trust, now)
            .map_err(|_| Error::Storage)?;
        Ok(receipt)
    }
    pub async fn transition(
        &self,
        p: &AuthorizedPrincipal,
        purpose_value: Purpose,
        input: &Transition,
        a: &RequestAudit,
        now: i64,
    ) -> Result<Receipt, Error> {
        p.require_all_devices(Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        self.synchronize(now).await?;
        let phase = match input.action {
            Action::Approve => "approved",
            Action::Activate => "activated",
            Action::Retire => "retired",
        };
        let request = sha2::Sha256::digest(
            serde_json::to_vec(&(purpose_value, input)).map_err(|_| Error::Request)?,
        )
        .to_vec();
        if let Some(old) = self
            .rotation_replay(p, a, input.id, phase, &request)
            .await?
        {
            return Ok(old);
        }
        let mut trust = self.trust(purpose_value)?;
        if trust.tenant.to_string() != p.tenant_id() || trust.revision != input.expected_revision {
            return Err(Error::Conflict);
        }
        let mut tx = self.begin(p.tenant_id()).await?;
        let row=sqlx::query("SELECT previous,candidate,revision,state FROM mdm_pki.rotations WHERE tenant_id=$1::uuid AND id=$2 AND purpose=$3")
            .bind(p.tenant_id()).bind(input.id).bind(purpose(purpose_value)).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
        let previous: String = row.try_get("previous").map_err(|_| Error::Storage)?;
        let candidate: String = row.try_get("candidate").map_err(|_| Error::Storage)?;
        let old_state: String = row.try_get("state").map_err(|_| Error::Storage)?;
        let state = match input.action {
            Action::Approve if old_state == "distributing" => "approved",
            Action::Activate if old_state == "approved" => "activated",
            Action::Retire if old_state == "activated" => "retired",
            _ => return Err(Error::Conflict),
        };
        tx.rollback().await.map_err(|_| Error::Storage)?;
        if matches!(input.action, Action::Activate) {
            self.providers
                .get(purpose_value, &candidate)?
                .verify_issuer(&candidate)
                .await?;
            for g in &mut trust.issuers {
                if g.digest == previous {
                    g.mode = Mode::VerifyOnly;
                } else if g.digest == candidate {
                    g.mode = Mode::Active;
                }
            }
        }
        if matches!(input.action, Action::Retire) {
            trust.issuers.retain(|g| g.digest != previous);
        }
        trust.revision = trust.revision.checked_add(1).ok_or(Error::Conflict)?;
        DeviceTrust::new(trust.clone(), purpose_value, now).map_err(|_| Error::Request)?;
        let receipt = self
            .write(
                p,
                a,
                (input.id, input.expected_revision),
                (&trust, state, None),
                now,
                &request,
            )
            .await?;
        self.binding(purpose_value)?
            .update(trust, now)
            .map_err(|_| Error::Storage)?;
        Ok(receipt)
    }
    pub async fn acknowledge_in(
        c: &mut sqlx::PgConnection,
        tenant: &str,
        registration: Uuid,
        trust: &Trust,
        input: &Acknowledgement,
    ) -> Result<(), Error> {
        if input.operation.is_nil()
            || input.version != 1
            || input.revision != trust.revision
            || input.digest != trust.installation_digest()
        {
            return Err(Error::Conflict);
        }
        if trust.tenant.to_string() != tenant {
            return Err(Error::Forbidden);
        }
        let prior:Option<(i64,String)>=sqlx::query_as("SELECT revision,digest FROM mdm_pki.installations WHERE tenant_id=$1::uuid AND purpose=$2 AND registration=$3 FOR UPDATE")
            .bind(tenant).bind(purpose(trust.purpose)).bind(registration).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)?;
        if prior.is_some_and(|(r, d)| {
            r > input.revision as i64 || (r == input.revision as i64 && d != input.digest)
        }) {
            return Err(Error::Conflict);
        }
        sqlx::query("INSERT INTO mdm_pki.installations(tenant_id,purpose,registration,revision,digest,body) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,purpose,registration) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,body=excluded.body,confirmed_at=clock_timestamp()")
            .bind(tenant).bind(purpose(trust.purpose)).bind(registration).bind(input.revision as i64).bind(&input.digest).bind(serde_json::to_vec(trust).map_err(|_|Error::Storage)?)
            .execute(&mut *c).await.map_err(|_|Error::Storage)?;
        sqlx::query("INSERT INTO mdm_pki.acknowledgements(tenant_id,rotation,registration,revision,digest) SELECT $1::uuid,id,$2,$3,$4 FROM mdm_pki.rotations WHERE tenant_id=$1::uuid AND purpose=$5 AND state IN ('distributing','approved') ON CONFLICT(tenant_id,rotation,registration) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,confirmed_at=clock_timestamp()")
            .bind(tenant).bind(registration).bind(input.revision as i64).bind(input.digest.as_bytes()).bind(purpose(trust.purpose))
            .execute(c).await.map_err(|_|Error::Storage)?;
        Ok(())
    }
    async fn rotation_replay(
        &self,
        p: &AuthorizedPrincipal,
        a: &RequestAudit,
        id: Uuid,
        phase: &str,
        hash: &[u8],
    ) -> Result<Option<Receipt>, Error> {
        p.bind_audit(a).map_err(|_| Error::Forbidden)?;
        let mut tx = self.begin(p.tenant_id()).await?;
        let found=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_pki.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation=$3 AND phase=$4)")
            .bind(p.tenant_id()).bind(p.principal_id()).bind(id).bind(phase).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
        tx.rollback().await.map_err(|_| Error::Storage)?;
        if !found {
            return Ok(None);
        }
        a.operation(id, "device_pki_rotation");
        self.mutation(
            TenantId::parse(p.tenant_id()).map_err(|_| Error::Request)?,
            a,
            (p, id, phase, hash),
            |ctx, c| {
                Box::pin(async move {
                    let (p, id, phase, hash) = ctx;
                    live(c, p).await?;
                    let bytes = crate::mutation::replay(
                        c,
                        p.tenant_id(),
                        p.principal_id(),
                        p.instance_id(),
                        *id,
                        phase,
                        hash,
                    )
                    .await?
                    .ok_or(Error::Conflict)?;
                    let receipt = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
                    Ok(crate::mutation::Change {
                        value: Some(receipt),
                        replay: true,
                        key: format!("pki:{id}:{phase}"),
                        fingerprint: hash.to_vec(),
                    })
                })
            },
        )
        .await
    }
    async fn write(
        &self,
        p: &AuthorizedPrincipal,
        a: &RequestAudit,
        request: (Uuid, u64),
        change: (&Trust, &str, Option<(&str, &str)>),
        now: i64,
        hash: &[u8],
    ) -> Result<Receipt, Error> {
        let (id, expected) = request;
        let (trust, state, added) = change;
        p.bind_audit(a).map_err(|_| Error::Forbidden)?;
        a.operation(id, "device_pki_rotation");
        self.mutation(TenantId::parse(p.tenant_id()).map_err(|_|Error::Request)?,a,
            (p,id,expected,trust,state,added,now,hash),|ctx,c|Box::pin(async move {
                let (p,id,expected,trust,state,added,now,hash)=ctx;
                live(c,p).await?;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))").bind(p.tenant_id()).execute(&mut *c).await.map_err(|_|Error::Storage)?;
                if let Some(bytes)=crate::mutation::replay(c,p.tenant_id(),p.principal_id(),p.instance_id(),*id,state,hash).await? {
                    return Ok(crate::mutation::Change{value:serde_json::from_slice(&bytes).map_err(|_|Error::Storage)?,replay:true,
                        key:format!("pki:{id}:{state}"),fingerprint:hash.to_vec()});
                }
                    let revision:i64=sqlx::query_scalar("SELECT revision FROM mdm_pki.trust WHERE tenant_id=$1::uuid AND purpose=$2 FOR UPDATE")
                        .bind(p.tenant_id()).bind(purpose(trust.purpose)).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                    if revision!=*expected as i64 {return Err(Error::Conflict);}
                    if *state=="approved" || *state=="activated" {
                        let missing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.state='active' AND ((r.channel='agent' AND $3='agent') OR (r.channel='mdm' AND EXISTS(SELECT 1 FROM mdm_access.requests q WHERE q.tenant_id=r.tenant_id AND q.id=r.request_id AND q.source=$3))) AND NOT EXISTS(SELECT 1 FROM mdm_pki.acknowledgements a WHERE a.tenant_id=r.tenant_id AND a.registration=r.id AND a.rotation=$2 AND a.revision>=(SELECT revision FROM mdm_pki.rotations WHERE tenant_id=r.tenant_id AND id=$2)))")
                            .bind(p.tenant_id()).bind(*id).bind(match trust.purpose {Purpose::Windows=>"mdm.windows",Purpose::Apple=>"mdm.apple",Purpose::Agent=>"agent"})
                            .fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                        if missing {return Err(Error::Conflict);}
                    }
                    if *state=="retired" {
                        let unknown:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_pki.signing s JOIN mdm_pki.rotations r ON r.tenant_id=s.tenant_id AND r.purpose=s.purpose AND r.previous=s.issuer WHERE r.tenant_id=$1::uuid AND r.id=$2 AND (s.state IN ('signing','unknown') OR (s.state='prepared' AND s.deadline>$3)))")
                            .bind(p.tenant_id()).bind(*id).bind(*now).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                        if unknown {return Err(Error::Conflict);}
                        if trust.purpose==Purpose::Apple {
                            let unsettled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts s JOIN mdm_pki.rotations r ON r.tenant_id=s.tenant_id AND r.previous=encode(s.issuer,'hex') WHERE r.tenant_id=$1::uuid AND r.id=$2 AND ((s.state='consumed' AND s.certificate IS NULL) OR (s.state='prepared' AND s.expires_at>clock_timestamp())))")
                                .bind(p.tenant_id()).bind(*id).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                            if unsettled{return Err(Error::Conflict);}
                        }


                        let outstanding:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_pki.certificates cert JOIN mdm_pki.rotations r ON r.tenant_id=cert.tenant_id AND r.previous=cert.issuer AND r.purpose=cert.purpose WHERE r.tenant_id=$1::uuid AND r.id=$2 AND cert.not_after>$3 AND NOT EXISTS(SELECT 1 FROM mdm_pki.revocations v WHERE (v.tenant_id,v.purpose,v.issuer,v.serial)=(cert.tenant_id,cert.purpose,cert.issuer,cert.serial) AND v.state='published'))")
                            .bind(p.tenant_id()).bind(*id).bind(*now).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                        if outstanding {return Err(Error::Conflict);}
                    }
                    if let Some((previous,candidate))=added {
                        sqlx::query("INSERT INTO mdm_pki.rotations(tenant_id,id,purpose,previous,candidate,revision,state) VALUES($1::uuid,$2,$3,$4,$5,$6,'distributing')")
                            .bind(p.tenant_id()).bind(*id).bind(purpose(trust.purpose)).bind(*previous).bind(*candidate).bind(trust.revision as i64).execute(&mut *c).await.map_err(|_|Error::Storage)?;
                    } else {
                        sqlx::query("UPDATE mdm_pki.rotations SET state=$3 WHERE tenant_id=$1::uuid AND id=$2")
                            .bind(p.tenant_id()).bind(*id).bind(*state).execute(&mut *c).await.map_err(|_|Error::Storage)?;
                    }
                    persist(c,trust).await?;
                    let receipt=Receipt{operation:*id,revision:trust.revision,state:state.to_string()};
                    crate::mutation::save(c,(p.tenant_id(),p.principal_id(),p.instance_id()),*id,state,hash,
                        &serde_json::to_vec(&receipt).map_err(|_|Error::Storage)?).await?;

                Ok(crate::mutation::Change{value:receipt,replay:false,key:format!("pki:{id}:{state}"),fingerprint:hash.to_vec()})
            })).await
    }
}
async fn live(c: &mut sqlx::PgConnection, p: &AuthorizedPrincipal) -> Result<(), Error> {
    p.check_live().map_err(|_| Error::Forbidden)?;
    rss_mdm_authorization_service::lock_on(c, p.tenant_id(), p.instance_id())
        .await
        .map_err(|_| Error::Storage)?;
    rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await
        .map_err(|_| Error::Storage)?
        .require_all_devices(p, Permission::Credentials)
        .map_err(|_| Error::Forbidden)
}

pub async fn persist(c: &mut sqlx::PgConnection, trust: &Trust) -> Result<(), Error> {
    let bytes = serde_json::to_vec(trust).map_err(|_| Error::Request)?;
    sqlx::query("INSERT INTO mdm_pki.trust(tenant_id,purpose,revision,body) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,purpose) DO UPDATE SET revision=excluded.revision,body=excluded.body")
        .bind(trust.tenant).bind(purpose(trust.purpose)).bind(trust.revision as i64).bind(bytes).execute(&mut *c).await.map_err(|_|Error::Storage)?;
    sqlx::query("UPDATE mdm_pki.issuers SET state='retired' WHERE tenant_id=$1 AND purpose=$2 AND digest<>ALL($3)")
        .bind(trust.tenant).bind(purpose(trust.purpose)).bind(trust.issuers.iter().map(|g|g.digest.clone()).collect::<Vec<_>>())
        .execute(&mut *c).await.map_err(|_|Error::Storage)?;
    // Retire the previous active row before promoting another generation under the unique fence.
    sqlx::query("UPDATE mdm_pki.issuers SET state='verify_only' WHERE tenant_id=$1 AND purpose=$2 AND state='active' AND digest<>$3")
        .bind(trust.tenant).bind(purpose(trust.purpose)).bind(trust.issuers.iter().find(|g|g.mode==Mode::Active).ok_or(Error::Request)?.digest.as_str())
        .execute(&mut *c).await.map_err(|_|Error::Storage)?;
    for g in &trust.issuers {
        for (encoded, list) in [(&g.certificate, &g.crl), (&g.root, &g.root_crl)] {
            let cert_der = decode(encoded, 32768).map_err(|_| Error::Request)?;
            let digest = rss_mdm_device_trust::digest(&cert_der);
            let certificate =
                x509_cert::Certificate::from_der(&cert_der).map_err(|_| Error::Request)?;
            let der = decode(list, 16 * 1024 * 1024).map_err(|_| Error::Request)?;
            let parsed =
                x509_cert::crl::CertificateList::from_der(&der).map_err(|_| Error::Request)?;
            let at = parsed
                .tbs_cert_list
                .this_update
                .to_unix_duration()
                .as_secs() as i64;
            let checked =
                rss_mdm_device_trust::crl(&der, &certificate, at).map_err(|_| Error::Request)?;
            if let Some(old)=sqlx::query("SELECT number,this_update,der FROM mdm_pki.crls WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 FOR UPDATE")
                .bind(trust.tenant).bind(purpose(trust.purpose)).bind(&digest).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)? {
                let number:i64=old.try_get("number").map_err(|_|Error::Storage)?;
                let previous:i64=old.try_get("this_update").map_err(|_|Error::Storage)?;
                if checked.number<number as u64 || checked.this_update<previous
                    || (checked.number==number as u64 && checked.der!=old.try_get::<Vec<u8>,_>("der").map_err(|_|Error::Storage)?) {return Err(Error::Conflict);}
            }
            sqlx::query("INSERT INTO mdm_pki.crls(tenant_id,purpose,issuer,number,this_update,next_update,der) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,purpose,issuer) DO UPDATE SET number=excluded.number,this_update=excluded.this_update,next_update=excluded.next_update,der=excluded.der")
                .bind(trust.tenant).bind(purpose(trust.purpose)).bind(&digest).bind(i64::try_from(checked.number).map_err(|_|Error::Request)?)
                .bind(checked.this_update).bind(checked.next_update).bind(&checked.der).execute(&mut *c).await.map_err(|_|Error::Storage)?;
        }
        let certificate = x509_cert::Certificate::from_der(
            &decode(&g.certificate, 32768).map_err(|_| Error::Request)?,
        )
        .map_err(|_| Error::Request)?;
        sqlx::query("INSERT INTO mdm_pki.issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1,$2,$3,$4,$5,$6,$8,$7) ON CONFLICT(tenant_id,purpose,digest) DO UPDATE SET state=excluded.state")
            .bind(trust.tenant).bind(purpose(trust.purpose)).bind(&g.digest).bind(trust.revision as i64)
            .bind(match g.mode {Mode::Active=>"active",Mode::Prepared=>"prepared",Mode::VerifyOnly=>"verify_only"})
            .bind(serde_json::to_vec(g).map_err(|_|Error::Request)?).bind(certificate.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64).bind(if g.provisioner.is_empty(){"legacy"}else{"step_ca"})
            .execute(&mut *c).await.map_err(|_|Error::Storage)?;
    }
    Ok(())
}
use sha2::Digest;
use x509_cert::der::Decode;
