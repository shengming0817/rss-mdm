//! Durable CA dispatch: one network invocation, immutable response, explicit unknown recovery.
use crate::{Error, Sign, StepCa};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frozen {
    pub version: u8,
    pub purpose: String,
    pub issuer: String,
    pub provider: String,
    pub csr: String,
    pub csr_digest: [u8; 32],
    pub subject: String,
    pub sans: Vec<String>,
    pub start: i64,
    pub end: i64,
    pub deadline: i64,
}
impl Frozen {
    fn matches(&self, purpose: &str, issuer: &str, i: Sign<'_>) -> bool {
        self.version == 1
            && self.purpose == purpose
            && self.issuer == issuer
            && self.csr == i.csr_pem
            && self.csr_digest == *i.csr_digest
            && self.subject == i.subject
            && self.sans == i.sans
            && self.start == i.start
            && self.end == i.end
            && self.deadline == i.deadline
    }
}
pub struct SigningStore {
    audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
}
enum Claim {
    New,
    Cached(Vec<Vec<u8>>),
}
impl SigningStore {
    pub fn new(audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>) -> Self {
        Self { audit }
    }
    pub async fn issue<F>(
        &self,
        tenant: Uuid,
        purpose: &str,
        issuer: &str,
        provider: &StepCa,
        intent: Sign<'_>,
        now: i64,
        validate: F,
    ) -> Result<Vec<Vec<u8>>, Error>
    where
        F: FnOnce(&[Vec<u8>]) -> bool,
    {
        if !matches!(purpose, "windows" | "agent") || issuer.len() != 64 || intent.attempt.is_nil()
        {
            return Err(Error::Request);
        }
        let unknown = || Error::Unknown {
            attempt: intent.attempt,
        };
        let binding = serde_json::to_vec(&Frozen {
            version: 1,
            purpose: purpose.into(),
            issuer: issuer.into(),
            provider: provider.authority_digest(issuer),
            csr: intent.csr_pem.into(),
            csr_digest: *intent.csr_digest,
            subject: intent.subject.into(),
            sans: intent.sans.to_vec(),
            start: intent.start,
            end: intent.end,
            deadline: intent.deadline,
        })
        .map_err(|_| Error::Request)?;
        let hash = Sha256::digest(&binding).to_vec();
        let a = rss_mdm_audit_integration::RequestAudit::new(
            tenant.to_string(),
            "device_pki_signing_claim",
        );
        a.identify_service("service:device-pki-signing");
        a.operation(intent.attempt, "device_pki_signing_claim");
        let claim=crate::mutation::run(&self.audit,rss_request_context::TenantId::parse(&tenant.to_string()).map_err(|_|Error::Request)?,&a,
            (tenant,purpose,issuer,intent,&binding,&hash,now),|ctx,c|Box::pin(async move {
                let (tenant,purpose,issuer,intent,binding,hash,now)=ctx;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))").bind(tenant.to_string()).execute(&mut *c).await.map_err(|_|Error::Storage)?;
                if let Some(row)=sqlx::query("SELECT binding,state,chain FROM mdm_pki.signing WHERE tenant_id=$1 AND attempt=$2 FOR UPDATE")
                    .bind(*tenant).bind(intent.attempt).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)? {
                    let frozen:Frozen=serde_json::from_slice(&row.try_get::<Vec<u8>,_>("binding").map_err(|_|Error::Storage)?).map_err(|_|Error::Storage)?;
                    if !frozen.matches(purpose,issuer,*intent){return Err(Error::Conflict);}
                    if row.try_get::<String,_>("state").map_err(|_|Error::Storage)?!="issued" {return Err(Error::Unknown{attempt:intent.attempt});}
                    let chain=serde_json::from_slice(&row.try_get::<Vec<u8>,_>("chain").map_err(|_|Error::Storage)?).map_err(|_|Error::Storage)?;
                    return Ok(crate::mutation::Change{value:Claim::Cached(chain),replay:false,key:String::new(),fingerprint:vec![]});
                }
                let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_pki.issuers WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='active')")
                    .bind(*tenant).bind(*purpose).bind(*issuer).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                if !active || *now<intent.start || *now>=intent.deadline || *now-intent.start>=60 {return Err(Error::Request);}
                sqlx::query("INSERT INTO mdm_pki.signing(tenant_id,attempt,purpose,issuer,binding,digest,state) VALUES($1,$2,$3,$4,$5,$6,'signing')")
                    .bind(*tenant).bind(intent.attempt).bind(*purpose).bind(*issuer).bind(*binding).bind(*hash).execute(c).await.map_err(|_|Error::Storage)?;
                Ok(crate::mutation::Change{value:Claim::New,replay:false,key:format!("pki:{}:claim",intent.attempt),fingerprint:hash.to_vec()})
            })).await;
        a.finalize(
            claim
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        match claim? {
            Claim::Cached(chain) => {
                if !validate(&chain) {
                    return Err(unknown());
                }
                return Ok(chain);
            }
            Claim::New => {}
        }
        // Audit and the immutable dispatch claim are committed before the single network call.
        let chain = match provider.sign(intent, now).await {
            Ok(chain) if validate(&chain) => chain,
            _ => {
                let _ = self.settle(tenant, intent.attempt, &hash, None).await;
                return Err(unknown());
            }
        };
        self.settle(tenant, intent.attempt, &hash, Some(&chain))
            .await?;
        Ok(chain)
    }
    async fn settle(
        &self,
        tenant: Uuid,
        attempt: Uuid,
        hash: &[u8],
        chain: Option<&[Vec<u8>]>,
    ) -> Result<(), Error> {
        let bytes = chain
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| Error::Storage)?;
        let a = rss_mdm_audit_integration::RequestAudit::new(
            tenant.to_string(),
            "device_pki_signing_result",
        );
        a.identify_service("service:device-pki-signing");
        a.operation(attempt, "device_pki_signing_result");
        let result=crate::mutation::run(&self.audit,rss_request_context::TenantId::parse(&tenant.to_string()).map_err(|_|Error::Request)?,&a,
            (tenant,attempt,hash,chain,bytes),|ctx,c|Box::pin(async move {
                let (tenant,attempt,hash,chain,bytes)=ctx;
                let row=sqlx::query("SELECT binding,digest,state,chain FROM mdm_pki.signing WHERE tenant_id=$1 AND attempt=$2 FOR UPDATE")
                    .bind(*tenant).bind(*attempt).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                if row.try_get::<Vec<u8>,_>("digest").map_err(|_|Error::Storage)?!=*hash {return Err(Error::Conflict);}
                if row.try_get::<String,_>("state").map_err(|_|Error::Storage)?!="signing" {
                    if row.try_get::<Option<Vec<u8>>,_>("chain").map_err(|_|Error::Storage)?==*bytes {
                        return Ok(crate::mutation::Change{value:(),replay:false,key:String::new(),fingerprint:vec![]});
                    }
                    return Err(Error::Conflict);
                }
                let state=if chain.is_some(){"issued"}else{"unknown"};
                if let Some(chain)=chain {
                    let frozen:Frozen=serde_json::from_slice(&row.try_get::<Vec<u8>,_>("binding").map_err(|_|Error::Storage)?).map_err(|_|Error::Storage)?;
                    crate::certificates::record_candidate_in(c,&tenant.to_string(),&frozen.purpose,None,&frozen.issuer,chain.first().ok_or(Error::Request)?).await?;
                }
                sqlx::query("UPDATE mdm_pki.signing SET state=$3,chain=$4 WHERE tenant_id=$1 AND attempt=$2")
                    .bind(*tenant).bind(*attempt).bind(state).bind(&*bytes).execute(c).await.map_err(|_|Error::Storage)?;
                let fingerprint=Sha256::digest(serde_json::to_vec(&(hash,&bytes)).map_err(|_|Error::Storage)?).to_vec();
                Ok(crate::mutation::Change{value:(),replay:false,key:format!("pki:{attempt}:{state}"),fingerprint})
            })).await;
        a.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
